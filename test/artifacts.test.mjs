import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { makeArtifactTools } from '../src/artifacts.mjs';
import { HarnessError, canonical } from '../src/value.mjs';
import { runPlan, replayPlan } from '../src/engine.mjs';

const inspect = new Map(makeArtifactTools().map((t) => [t.name, t])).get('artifact.inspect');
const policy = { maxOutputBytes: 1048576 };

function tempWorkspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'concord-artifacts-'));
}

function writeFixture(temp, name, bytes) {
  fs.writeFileSync(path.join(temp, name), bytes);
  return name;
}

function minimalElf(is64) {
  const size = is64 ? 64 : 52;
  const buffer = Buffer.alloc(size);
  buffer.write('\x7fELF', 0, 'latin1');
  buffer[4] = is64 ? 2 : 1;
  buffer[5] = 1; // little-endian
  buffer[6] = 1;
  buffer.writeUInt16LE(2, 16); // e_type = ET_EXEC
  buffer.writeUInt16LE(is64 ? 0x3e : 3, 18); // e_machine
  buffer.writeUInt32LE(1, 20); // e_version
  if (is64) { buffer.writeBigUInt64LE(0x400000n, 24); buffer.writeUInt16LE(11, 60); }
  else { buffer.writeUInt32LE(0x8048000, 24); buffer.writeUInt16LE(11, 48); }
  return buffer;
}

function minimalPe() {
  const buffer = Buffer.alloc(112);
  buffer.write('MZ', 0, 'latin1');
  buffer.writeInt32LE(64, 0x3c); // e_lfanew -> PE signature at offset 64
  buffer.write('PE\0\0', 64, 'latin1');
  buffer.writeUInt16LE(0x8664, 68); // Machine
  buffer.writeUInt16LE(7, 70); // NumberOfSections
  buffer.writeUInt32LE(1700000000, 72); // TimeDateStamp
  buffer.writeUInt16LE(240, 84); // SizeOfOptionalHeader
  buffer.writeUInt32LE(0x1000, 64 + 24 + 16); // AddressOfEntryPoint within optional header
  return buffer;
}

// `entries` may carry optional `extra`/`comment` buffers (the variable-length central-directory
// fields real writers populate with timestamps/UIDs); `options.zip64Gap` inserts a spec-legal
// ZIP64 EOCD record + locator between the central directory and the EOCD, which is exactly what
// a real third-party-written archive was found to contain.
function buildZipFixture(entries, options = {}) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const { name, data, extra, comment } of entries) {
    let crc = 0xffffffff;
    for (const byte of data) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
    crc = (crc ^ 0xffffffff) >>> 0;
    const nameBuf = Buffer.from(name, 'utf-8');
    const localHeader = Buffer.alloc(30);
    localHeader.write('PK\x03\x04', 0, 'latin1');
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(data.length, 18); // compressed size (method 0 = stored)
    localHeader.writeUInt32LE(data.length, 22); // uncompressed size
    localHeader.writeUInt16LE(nameBuf.length, 26); // name length
    localParts.push(localHeader, nameBuf, data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.write('PK\x01\x02', 0, 'latin1');
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(data.length, 20); // compressed size
    centralHeader.writeUInt32LE(data.length, 24); // uncompressed size
    const extraBuf = extra ?? Buffer.alloc(0);
    const commentBuf = comment ?? Buffer.alloc(0);
    centralHeader.writeUInt16LE(nameBuf.length, 28); // name length
    centralHeader.writeUInt16LE(extraBuf.length, 30); // extra field length
    centralHeader.writeUInt16LE(commentBuf.length, 32); // file comment length
    centralHeader.writeUInt32LE(offset, 42); // offset of this entry's local header
    centralParts.push(centralHeader, nameBuf, extraBuf, commentBuf);

    offset += localHeader.length + nameBuf.length + data.length;
  }
  const localSection = Buffer.concat(localParts);
  const centralSection = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.write('PK\x05\x06', 0, 'latin1');
  eocd.writeUInt16LE(entries.length, 8); // entries on this disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(centralSection.length, 12); // central directory size
  eocd.writeUInt32LE(localSection.length, 16); // central directory offset
  const gap = [];
  if (options.zip64Gap) {
    const zip64Eocd = Buffer.alloc(56);
    zip64Eocd.write('PK\x06\x06', 0, 'latin1');
    zip64Eocd.writeBigUInt64LE(44n, 4); // size of this record, excluding the 12-byte prefix
    zip64Eocd.writeBigUInt64LE(BigInt(entries.length), 24); // entries on this disk
    zip64Eocd.writeBigUInt64LE(BigInt(entries.length), 32); // total entries
    zip64Eocd.writeBigUInt64LE(BigInt(centralSection.length), 40); // central directory size
    zip64Eocd.writeBigUInt64LE(BigInt(localSection.length), 48); // central directory offset
    const locator = Buffer.alloc(20);
    locator.write('PK\x06\x07', 0, 'latin1');
    locator.writeBigUInt64LE(BigInt(localSection.length + centralSection.length), 8); // offset of the ZIP64 EOCD
    locator.writeUInt32LE(1, 16); // total number of disks
    gap.push(zip64Eocd, locator);
  }
  return Buffer.concat([localSection, centralSection, ...gap, eocd]);
}

function buildMachoFixture() {
  const dylibPathBuf = Buffer.from('/usr/lib/libSystem.B.dylib\0', 'latin1');
  const dylibCmdFixed = 24; // cmd+cmdsize+name_offset+timestamp+current_version+compat_version
  const dylibCmd = Buffer.alloc(Math.ceil((dylibCmdFixed + dylibPathBuf.length) / 8) * 8);
  dylibCmd.writeUInt32LE(0xc, 0); // LC_LOAD_DYLIB
  dylibCmd.writeUInt32LE(dylibCmd.length, 4);
  dylibCmd.writeUInt32LE(dylibCmdFixed, 8); // name offset within this command
  dylibPathBuf.copy(dylibCmd, dylibCmdFixed);

  const uuidCmd = Buffer.alloc(24);
  uuidCmd.writeUInt32LE(0x1b, 0); // LC_UUID
  uuidCmd.writeUInt32LE(24, 4);
  Buffer.from('918c0eaa36f33d9698139bc0a18a8670', 'hex').copy(uuidCmd, 8);

  const segCmd = Buffer.alloc(72);
  segCmd.writeUInt32LE(0x19, 0); // LC_SEGMENT_64
  segCmd.writeUInt32LE(72, 4);
  segCmd.write('__TEXT', 8, 'latin1');

  const commands = Buffer.concat([dylibCmd, uuidCmd, segCmd]);
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0); // mach-o-64-le magic
  header.writeUInt32LE(0x01000007, 4); // CPU_TYPE_X86_64
  header.writeUInt32LE(0x80000003, 8); // cpusubtype, arbitrary nonzero
  header.writeUInt32LE(0x8, 12); // MH_BUNDLE
  header.writeUInt32LE(3, 16); // ncmds
  header.writeUInt32LE(commands.length, 20); // sizeofcmds
  return Buffer.concat([header, commands]);
}

function encodeLeb128(value) {
  const bytes = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (value !== 0);
  return Buffer.from(bytes);
}

function buildWasmFixture(sections) {
  const header = Buffer.alloc(8);
  header.write('\0asm', 0, 'latin1');
  header.writeUInt32LE(1, 4);
  const parts = [header];
  for (const { id, payload } of sections) parts.push(Buffer.from([id]), encodeLeb128(payload.length), payload);
  return Buffer.concat(parts);
}

test('rejects an absolute path and a traversal path identically to other read-effect tools', () => {
  const temp = tempWorkspace();
  assert.throws(() => inspect.execute({ path: path.join(temp, 'x') }, { workspaceRoot: temp, policy }), (e) => e instanceof HarnessError && e.code === 'PATH_DENIED');
  assert.throws(() => inspect.execute({ path: '../escape' }, { workspaceRoot: temp, policy }), (e) => e instanceof HarnessError && e.code === 'PATH_DENIED');
});

test('computes the correct SHA-256 of the inspected bytes', () => {
  const temp = tempWorkspace();
  const content = Buffer.from('hello concord artifact');
  const name = writeFixture(temp, 'plain.bin', content);
  const result = inspect.execute({ path: name }, { workspaceRoot: temp, policy });
  assert.equal(result.sha256, createHash('sha256').update(content).digest('hex'));
  assert.equal(result.bytes, content.length);
  assert.equal(result.format, 'unknown');
});

test('identifies ELF, PE (via MZ+PE signature), ZIP, and PNG by magic bytes', () => {
  const temp = tempWorkspace();
  assert.equal(inspect.execute({ path: writeFixture(temp, 'a.elf', minimalElf(false)) }, { workspaceRoot: temp, policy }).format, 'elf');
  assert.equal(inspect.execute({ path: writeFixture(temp, 'a.exe', minimalPe()) }, { workspaceRoot: temp, policy }).format, 'pe');
  assert.equal(inspect.execute({ path: writeFixture(temp, 'a.zip', Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0])) }, { workspaceRoot: temp, policy }).format, 'zip');
  assert.equal(inspect.execute({ path: writeFixture(temp, 'a.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0])) }, { workspaceRoot: temp, policy }).format, 'png');
});

test('extracts correct ELF32 header fields', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'a32.elf', minimalElf(false)) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.elf, { class: '32-bit', dataEncoding: 'little-endian', type: 2, machine: 3, entryPoint: 0x8048000, sectionCount: 11, neededLibraries: [] });
});

test('extracts correct ELF64 header fields, including a 64-bit entry point', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'a64.elf', minimalElf(true)) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.elf, { class: '64-bit', dataEncoding: 'little-endian', type: 2, machine: 0x3e, entryPoint: 0x400000, sectionCount: 11, neededLibraries: [] });
});

test('extracts correct PE header fields', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'a.exe', minimalPe()) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.pe, { machine: 0x8664, sectionCount: 7, timestamp: 1700000000, entryPoint: 0x1000, imports: [] });
});

test('a huge section count is only ever reported, never used to drive a parsing loop', () => {
  const temp = tempWorkspace();
  const elf = minimalElf(false);
  elf.writeUInt16LE(0xffff, 48);
  const result = inspect.execute({ path: writeFixture(temp, 'many-sections.elf', elf) }, { workspaceRoot: temp, policy });
  assert.equal(result.elf.sectionCount, 0xffff);
});

test('an ELF file truncated right after its magic bytes degrades to a partial result, not a crash', () => {
  const temp = tempWorkspace();
  const truncated = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1, 1]);
  const result = inspect.execute({ path: writeFixture(temp, 'short.elf', truncated) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'elf');
  assert.deepEqual(result.elf, { class: '32-bit', dataEncoding: 'little-endian', truncatedHeader: true });
});

test('an MZ file whose e_lfanew points past end of file is identified as mz-dos, not pe, with no crash', () => {
  const temp = tempWorkspace();
  const buffer = Buffer.alloc(64);
  buffer.write('MZ', 0, 'latin1');
  buffer.writeUInt32LE(0xffffffff, 0x3c); // e_lfanew far beyond the file
  const result = inspect.execute({ path: writeFixture(temp, 'bad.exe', buffer) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'mz-dos');
  assert.equal(result.pe, undefined);
});

test('an unrecognized format returns identification and hash as a success, not an error', () => {
  const temp = tempWorkspace();
  const content = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]);
  const result = inspect.execute({ path: writeFixture(temp, 'random.bin', content) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'unknown');
  assert.equal(result.sha256, createHash('sha256').update(content).digest('hex'));
});

test('an empty file is handled without an out-of-bounds slice', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'empty.bin', Buffer.alloc(0)) }, { workspaceRoot: temp, policy });
  assert.equal(result.bytes, 0);
  assert.equal(result.format, 'unknown');
  assert.equal(result.sha256, createHash('sha256').update(Buffer.alloc(0)).digest('hex'));
});

test('a file past the read budget fails closed rather than silently truncating (and hashing the wrong bytes)', () => {
  const temp = tempWorkspace();
  const tightPolicy = { maxOutputBytes: 16 };
  writeFixture(temp, 'big.bin', Buffer.alloc(1000));
  assert.throws(() => inspect.execute({ path: 'big.bin' }, { workspaceRoot: temp, policy: tightPolicy }), (e) => e instanceof HarnessError && e.code === 'OUTPUT_LIMIT');
});

test('arbitrary non-UTF-8 binary content succeeds, proving this tool never attempts text decoding', () => {
  const temp = tempWorkspace();
  const invalidUtf8 = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0x81, 0xc0]);
  const result = inspect.execute({ path: writeFixture(temp, 'binary.bin', invalidUtf8) }, { workspaceRoot: temp, policy });
  assert.equal(result.bytes, invalidUtf8.length);
  assert.equal(result.sha256, createHash('sha256').update(invalidUtf8).digest('hex'));
});

test('a real small PE executable yields its actual imported DLL names', (t) => {
  const source = 'C:/Windows/System32/attrib.exe';
  if (!fs.existsSync(source)) return t.skip('attrib.exe not present on this host');
  const temp = tempWorkspace();
  const bytes = fs.readFileSync(source);
  const name = writeFixture(temp, 'attrib.exe', bytes);
  const result = inspect.execute({ path: name }, { workspaceRoot: temp, policy: { maxOutputBytes: bytes.length * 8 + 1024 } });
  assert.equal(result.format, 'pe');
  assert.ok(result.pe.imports.includes('ntdll.dll'));
  assert.ok(result.pe.imports.includes('msvcrt.dll'));
  assert.ok(result.pe.imports.length >= 5);
});

test('a real ELF shared library yields its actual DT_NEEDED library names', (t) => {
  const source = 'C:/Windows/System32/DriverStore/FileRepository/nv_dispi.inf_amd64_436833bbb0f00476/libcuda_loader.so';
  if (!fs.existsSync(source)) return t.skip('no real local ELF shared library found on this host');
  const temp = tempWorkspace();
  const bytes = fs.readFileSync(source);
  const name = writeFixture(temp, 'lib.so', bytes);
  const result = inspect.execute({ path: name }, { workspaceRoot: temp, policy: { maxOutputBytes: bytes.length * 8 + 1024 } });
  assert.equal(result.format, 'elf');
  assert.deepEqual(result.elf.neededLibraries, ['libc.so.6', 'libdl.so.2', 'libpthread.so.0']);
});

function elfWithUnterminatedNeeded() {
  const buffer = Buffer.alloc(225); // byte 224 (the real last byte) is a lone non-NUL character
  buffer.write('\x7fELF', 0, 'latin1');
  buffer[4] = 2; buffer[5] = 1; buffer[6] = 1; // 64-bit, little-endian, version 1
  buffer.writeUInt16LE(2, 16); // e_type
  buffer.writeUInt16LE(0x3e, 18); // e_machine
  buffer.writeUInt32LE(1, 20); // e_version
  buffer.writeBigUInt64LE(64n, 32); // e_phoff
  buffer.writeUInt16LE(56, 54); // e_phentsize
  buffer.writeUInt16LE(2, 56); // e_phnum
  // PH[0]: PT_LOAD, identity-maps the whole file at vaddr 0x1000
  buffer.writeUInt32LE(1, 64); // p_type
  buffer.writeBigUInt64LE(0n, 64 + 8); // p_offset
  buffer.writeBigUInt64LE(0x1000n, 64 + 16); // p_vaddr
  buffer.writeBigUInt64LE(225n, 64 + 32); // p_filesz
  // PH[1]: PT_DYNAMIC
  buffer.writeUInt32LE(2, 120); // p_type
  buffer.writeBigUInt64LE(176n, 120 + 8); // p_offset
  // Dynamic entries at file offset 176: DT_NEEDED(val=0), DT_STRTAB(val=0x10E0), DT_NULL
  buffer.writeBigUInt64LE(1n, 176); buffer.writeBigUInt64LE(0n, 176 + 8);
  buffer.writeBigUInt64LE(5n, 192); buffer.writeBigUInt64LE(0x10e0n, 192 + 8);
  buffer.writeBigUInt64LE(0n, 208); buffer.writeBigUInt64LE(0n, 208 + 8);
  buffer[224] = 0x41; // 'A' — no NUL terminator anywhere in the file
  return buffer;
}

test('a DT_NEEDED string with no terminator before the real end of the file is rejected, not fabricated', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'unterminated.elf', elfWithUnterminatedNeeded()) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.elf.neededLibraries, []);
});

test('a huge ELF program-header count is bounded, never an unbounded parsing loop', () => {
  const temp = tempWorkspace();
  const elf = minimalElf(true);
  elf.writeUInt16LE(0xffff, 56); // e_phnum, absurdly large, with no real program headers present
  const result = inspect.execute({ path: writeFixture(temp, 'many-phdrs.elf', elf) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.elf.neededLibraries, []);
});

test('a huge PE section count is bounded, never an unbounded parsing loop', () => {
  const temp = tempWorkspace();
  const pe = minimalPe();
  pe.writeUInt16LE(0xffff, 70); // NumberOfSections, absurdly large, with no real section table present
  const result = inspect.execute({ path: writeFixture(temp, 'many-pe-sections.exe', pe) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.pe.imports, []);
});

test('identifies WASM and Mach-O by magic bytes', () => {
  const temp = tempWorkspace();
  assert.equal(inspect.execute({ path: writeFixture(temp, 'a.wasm', Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])) }, { workspaceRoot: temp, policy }).format, 'wasm');
  assert.equal(inspect.execute({ path: writeFixture(temp, 'a.dylib', Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.alloc(28)])) }, { workspaceRoot: temp, policy }).format, 'mach-o-64-le');
});

test('extracts correct ZIP central-directory entries from a freshly built archive', () => {
  const temp = tempWorkspace();
  const files = [
    { name: 'readme.txt', data: Buffer.from('hello world!!') },
    { name: 'nested/deep.txt', data: Buffer.from('deep') },
  ];
  const result = inspect.execute({ path: writeFixture(temp, 'a.zip', buildZipFixture(files)) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'zip');
  assert.deepEqual(result.zip.entries, files.map((f) => ({ name: f.name, compressedSize: f.data.length, uncompressedSize: f.data.length, compressionMethod: 0 })));
});

test('a ZIP whose EOCD claims far more entries than actually exist is bounded, never an unbounded parsing loop', () => {
  const temp = tempWorkspace();
  const fixture = buildZipFixture([{ name: 'only.txt', data: Buffer.from('x') }]);
  fixture.writeUInt16LE(0xfffe, fixture.length - 22 + 8); // high ordinary count; 0xffff is a ZIP64 sentinel
  fixture.writeUInt16LE(0xfffe, fixture.length - 22 + 10);
  const result = inspect.execute({ path: writeFixture(temp, 'lying.zip', fixture) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.zip.entries, [{ name: 'only.txt', compressedSize: 1, uncompressedSize: 1, compressionMethod: 0 }]);
});

test('a ZIP-identified file with no locatable EOCD returns an empty entry list, not a crash', () => {
  const temp = tempWorkspace();
  const fixture = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(50)]);
  const result = inspect.execute({ path: writeFixture(temp, 'no-eocd.zip', fixture) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'zip');
  assert.deepEqual(result.zip.entries, []);
});

// Named to be precise: this archive is hand-built in-process, NOT produced by a real zip tool.
// Unlike the ELF/PE/Mach-O/WASM tests, no on-disk archive of known provenance backs this format,
// so the shapes a real writer emits are covered explicitly by the two tests further below.
test('a multi-entry, multi-directory ZIP built in-process yields its full entry listing', () => {
  const temp = tempWorkspace();
  const files = [
    { name: 'a.txt', data: Buffer.from('first file contents') },
    { name: 'dir/b.json', data: Buffer.from('{"k":"v"}') },
    { name: 'dir/sub/c.bin', data: Buffer.from([1, 2, 3, 4, 5]) },
  ];
  const result = inspect.execute({ path: writeFixture(temp, 'real.zip', buildZipFixture(files)) }, { workspaceRoot: temp, policy });
  assert.equal(result.zip.entries.length, 3);
  assert.ok(result.zip.entries.some((e) => e.name === 'dir/sub/c.bin' && e.uncompressedSize === 5));
});

test('extracts correct Mach-O 64-bit header, dylib, UUID, and segment fields from a freshly built bundle', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'a.dylib', buildMachoFixture()) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'mach-o-64-le');
  assert.equal(result.machO.cpuType, 0x01000007);
  assert.equal(result.machO.fileType, 0x8);
  assert.equal(result.machO.loadCommandCount, 3);
  assert.deepEqual(result.machO.dylibs, ['/usr/lib/libSystem.B.dylib']);
  assert.equal(result.machO.uuid, '918c0eaa36f33d9698139bc0a18a8670');
  assert.deepEqual(result.machO.segments, ['__TEXT']);
});

test('a Mach-O file truncated right after its magic bytes degrades to a partial result, not a crash', () => {
  const temp = tempWorkspace();
  const truncated = Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 1, 2]);
  const result = inspect.execute({ path: writeFixture(temp, 'short.dylib', truncated) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'mach-o-64-le');
  assert.deepEqual(result.machO, { truncatedHeader: true });
});

test('a huge Mach-O load-command count is bounded, never an unbounded parsing loop', () => {
  const temp = tempWorkspace();
  const fixture = buildMachoFixture();
  fixture.writeUInt32LE(0xffffffff, 16); // ncmds, absurdly large, with no real commands beyond the three present
  const result = inspect.execute({ path: writeFixture(temp, 'many-cmds.dylib', fixture) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.machO.dylibs, ['/usr/lib/libSystem.B.dylib']);
  assert.deepEqual(result.machO.segments, ['__TEXT']);
});

test('a real Mach-O bundle (node-pty prebuild) yields its actual dylibs, UUID, and segments', (t) => {
  const source = 'C:/Users/Dough/AppData/Local/hermes/hermes-agent/node_modules/node-pty/prebuilds/darwin-x64/pty.node';
  if (!fs.existsSync(source)) return t.skip('no real local Mach-O bundle found on this host');
  const temp = tempWorkspace();
  const bytes = fs.readFileSync(source);
  const name = writeFixture(temp, 'pty.node', bytes);
  const result = inspect.execute({ path: name }, { workspaceRoot: temp, policy: { maxOutputBytes: bytes.length * 8 + 1024 } });
  assert.equal(result.format, 'mach-o-64-le');
  assert.ok(result.machO.dylibs.some((d) => d.endsWith('libSystem.B.dylib')));
  assert.equal(result.machO.uuid.length, 32);
  assert.ok(result.machO.segments.includes('__TEXT'));
});

test('extracts correct WASM section id/size sequence, including a multi-byte LEB128 size', () => {
  const temp = tempWorkspace();
  const fixture = buildWasmFixture([
    { id: 1, payload: Buffer.alloc(5) },
    { id: 7, payload: Buffer.alloc(200) }, // size 200 requires a 2-byte LEB128 varint
  ]);
  const result = inspect.execute({ path: writeFixture(temp, 'a.wasm', fixture) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'wasm');
  assert.equal(result.wasm.version, 1);
  assert.deepEqual(result.wasm.sections, [{ id: 1, size: 5 }, { id: 7, size: 200 }]);
});

test('a WASM section with a truncated (unterminated) LEB128 size is rejected, not read out of bounds', () => {
  const temp = tempWorkspace();
  const header = Buffer.alloc(8);
  header.write('\0asm', 0, 'latin1');
  header.writeUInt32LE(1, 4);
  const truncated = Buffer.concat([header, Buffer.from([1, 0x80])]); // section id 1, continuation bit set with no following byte
  const result = inspect.execute({ path: writeFixture(temp, 'bad.wasm', truncated) }, { workspaceRoot: temp, policy });
  assert.equal(result.format, 'wasm');
  assert.deepEqual(result.wasm.sections, []);
  assert.equal(result.wasm.truncated, true);
});

test('a WASM module with more sections than the bound is capped, not an unbounded parsing loop', () => {
  const temp = tempWorkspace();
  const sections = Array.from({ length: 200 }, () => ({ id: 0, payload: Buffer.alloc(0) }));
  const result = inspect.execute({ path: writeFixture(temp, 'many-sections.wasm', buildWasmFixture(sections)) }, { workspaceRoot: temp, policy });
  assert.equal(result.wasm.sections.length, 128); // MAX_WASM_SECTIONS
});

test('a real WASM module (tesseract-core-lstm.wasm) yields its actual section sequence', (t) => {
  const source = 'C:/Users/Dough/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/tesseract.js-core/tesseract-core-lstm.wasm';
  if (!fs.existsSync(source)) return t.skip('no real local WASM module found on this host');
  const temp = tempWorkspace();
  const bytes = fs.readFileSync(source);
  const name = writeFixture(temp, 'core.wasm', bytes);
  const result = inspect.execute({ path: name }, { workspaceRoot: temp, policy: { maxOutputBytes: bytes.length * 8 + 1024 } });
  assert.equal(result.format, 'wasm');
  assert.equal(result.wasm.version, 1);
  assert.ok(result.wasm.sections.map((s) => s.id).includes(10)); // Code section
  assert.ok(!result.wasm.truncated);
});

test('ZIP comment signatures cannot replace the actual central directory', () => {
  const temp = tempWorkspace();
  const archive = buildZipFixture([{ name: 'real.txt', data: Buffer.from('contents') }]);
  for (const [fakeOffset, sentinel] of [[0, false], [12, false], [12, true]]) {
    const comment = Buffer.alloc(34);
    comment.write('PK\x05\x06', fakeOffset, 'latin1');
    if (sentinel) comment.writeUInt16LE(65535, fakeOffset + 10);
    const fixture = Buffer.from(archive);
    fixture.writeUInt16LE(comment.length, fixture.length - 2);
    const result = inspect.execute({ path: writeFixture(temp, `comment-${fakeOffset}-${sentinel}.zip`, Buffer.concat([fixture, comment])) }, { workspaceRoot: temp, policy });
    assert.deepEqual(result.zip.entries.map(e => e.name), ['real.txt']);
  }
});

test('ZIP entry fields cannot borrow bytes from outside the declared central directory', () => {
  const temp = tempWorkspace();
  for (const field of [28, 30, 32]) {
    const fixture = buildZipFixture([{ name: 'real.txt', data: Buffer.from('x') }]);
    const cd = fixture.readUInt32LE(fixture.length - 22 + 16);
    fixture.writeUInt16LE(65535, cd + field);
    const result = inspect.execute({ path: writeFixture(temp, `length-${field}.zip`, fixture) }, { workspaceRoot: temp, policy });
    assert.deepEqual(result.zip.entries, []);
    assert.equal(result.zip.truncated, true);
  }
});

// Regression: a real third-party-written .zip (a game crash report, 5 entries, real deflate)
// carried a ZIP64 EOCD record + locator in the 76-byte gap between its central directory and
// its EOCD, with every 32-bit field still valid. findEocd required the central directory to end
// flush against the EOCD and so rejected the archive outright, reporting zero entries with
// truncated:true. Neither the flushness assumption nor the gap was reachable from any synthetic
// fixture, which is precisely why only a real archive exposed it.
test('a ZIP carrying ZIP64 records between its central directory and EOCD still lists its entries', () => {
  const temp = tempWorkspace();
  const files = [
    { name: 'info.json', data: Buffer.from('{"a":1}') },
    { name: 'dump.dmp', data: Buffer.from('binary-ish') },
  ];
  const fixture = buildZipFixture(files, { zip64Gap: true });
  // The gap really is present and really is a ZIP64 EOCD record followed by its locator.
  const eocdStart = fixture.length - 22;
  assert.equal(fixture.subarray(eocdStart - 76, eocdStart - 72).toString('hex'), '504b0606');
  assert.equal(fixture.subarray(eocdStart - 20, eocdStart - 16).toString('hex'), '504b0607');
  const result = inspect.execute({ path: writeFixture(temp, 'zip64-gap.zip', fixture) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.zip.entries.map((e) => e.name), ['info.json', 'dump.dmp']);
  assert.equal(result.zip.truncated, undefined);
  assert.equal(result.zip.unsupported, undefined);
});

test('ZIP entries with nonzero extra fields and comments are walked to the next entry correctly', () => {
  const temp = tempWorkspace();
  const files = [
    { name: 'first.txt', data: Buffer.from('one'), extra: Buffer.alloc(9, 0x55), comment: Buffer.from('c1') },
    { name: 'second.txt', data: Buffer.from('two'), extra: Buffer.alloc(4, 0x66) },
    { name: 'third.txt', data: Buffer.from('three'), comment: Buffer.from('a longer comment') },
  ];
  const result = inspect.execute({ path: writeFixture(temp, 'variable-fields.zip', buildZipFixture(files)) }, { workspaceRoot: temp, policy });
  // Every entry is found, in order, with its own name — only correct
  // 46+nameLength+extraLength+commentLength skip arithmetic can produce this.
  assert.deepEqual(result.zip.entries.map((e) => e.name), ['first.txt', 'second.txt', 'third.txt']);
  assert.deepEqual(result.zip.entries.map((e) => e.uncompressedSize), [3, 3, 5]);
  assert.equal(result.zip.truncated, undefined);
});

test('ZIP64 and multi-disk structures are disclosed rather than reported as ordinary sizes', () => {
  const temp = tempWorkspace();
  for (const [field, size, value, unsupported] of [[10, 2, 65535, 'zip64'], [12, 4, 0xffffffff, 'zip64'], [4, 2, 1, 'multi-disk']]) {
    const fixture = buildZipFixture([{ name: 'a', data: Buffer.from('x') }]);
    fixture[`writeUInt${size * 8}LE`](value, fixture.length - 22 + field);
    const result = inspect.execute({ path: writeFixture(temp, `unsupported-${field}.zip`, fixture) }, { workspaceRoot: temp, policy });
    assert.deepEqual(result.zip, { entries: [], unsupported });
  }
});

test('Mach-O weak dylib constants match the loader format', () => {
  const temp = tempWorkspace();
  for (const [cmd, names] of [[0x80000018, ['/usr/lib/libSystem.B.dylib']], [0x8000000c, []]]) {
    const fixture = buildMachoFixture(); fixture.writeUInt32LE(cmd, 32);
    const result = inspect.execute({ path: writeFixture(temp, `weak-${cmd}.dylib`, fixture) }, { workspaceRoot: temp, policy });
    assert.deepEqual(result.machO.dylibs, names);
  }
});

test('Mach-O metadata stays inside sizeofcmds and each command record', () => {
  const temp = tempWorkspace();
  const outsideTable = buildMachoFixture(); outsideTable.writeUInt32LE(0, 20);
  const empty = inspect.execute({ path: writeFixture(temp, 'outside-table.dylib', outsideTable) }, { workspaceRoot: temp, policy });
  assert.deepEqual(empty.machO.dylibs, []); assert.equal(empty.machO.uuid, undefined); assert.deepEqual(empty.machO.segments, []);
  for (const [command, size] of [[0x1b, 8], [0x19, 24], [0xc, 24]]) {
    const fixture = Buffer.alloc(80, 0x61);
    fixture.fill(0, 0, 32); fixture.writeUInt32LE(0xfeedfacf, 0);
    fixture.writeUInt32LE(1, 16); fixture.writeUInt32LE(size, 20);
    fixture.writeUInt32LE(command, 32); fixture.writeUInt32LE(size, 36);
    if (command === 0xc) { fixture.writeUInt32LE(24, 40); fixture.write('fake.dylib\0', 56, 'latin1'); }
    const result = inspect.execute({ path: writeFixture(temp, `command-${command}.dylib`, fixture) }, { workspaceRoot: temp, policy });
    assert.deepEqual(result.machO.dylibs, []); assert.equal(result.machO.uuid, undefined); assert.deepEqual(result.machO.segments, []);
    assert.equal(result.machO.malformed, true);
    assert.doesNotThrow(() => canonical(result));
  }
});

test('WASM u32 section sizes reject fifth-byte overflow but allow valid padded encodings', () => {
  const temp = tempWorkspace();
  const header = buildWasmFixture([]);
  const bad = Buffer.concat([header, Buffer.from([0, 0x80, 0x80, 0x80, 0x80, 0x10])]);
  const overflow = inspect.execute({ path: writeFixture(temp, 'overflow.wasm', bad) }, { workspaceRoot: temp, policy });
  assert.deepEqual(overflow.wasm.sections, []); assert.equal(overflow.wasm.malformed, true);
  const padded = Buffer.concat([header, Buffer.from([0, 0x80, 0x80, 0x80, 0x80, 0x00])]);
  const valid = inspect.execute({ path: writeFixture(temp, 'padded.wasm', padded) }, { workspaceRoot: temp, policy });
  assert.deepEqual(valid.wasm.sections, [{ id: 0, size: 0 }]); assert.equal(valid.wasm.truncated, undefined);
});

test('header-only and partial artifacts satisfy the real harness JSON and replay contracts', async () => {
  const temp = tempWorkspace();
  const macho = Buffer.alloc(32); macho.writeUInt32LE(0xfeedfacf, 0);
  const futureWasm = buildWasmFixture([]); futureWasm.writeUInt32LE(2, 4);
  const inputs = [['no-uuid.dylib', macho], ['partial.wasm', Buffer.from([0, 0x61, 0x73, 0x6d])], ['future.wasm', futureWasm]];
  for (const [name, bytes] of inputs) {
    writeFixture(temp, name, bytes);
    const options = { plan: { version: 1, tasks: [{ id: 'inspect', tool: 'artifact.inspect', input: { path: name } }] }, policy: { version: 1, allowedTools: ['artifact.inspect'], allowedEffects: ['read'] }, registry: new Map([[inspect.name, inspect]]), sourceLock: {}, workspaceRoot: fs.realpathSync(temp) };
    const journal = await runPlan(options);
    assert.equal(journal.outcome.status, 'completed', name);
    assert.doesNotThrow(() => canonical(journal.results));
    assert.equal(replayPlan({ ...options, journal, expectedRoot: journal.root }).replayed, true);
  }
});

test('a symlinked artifact is rejected, matching files.read\'s discipline', (t) => {
  const temp = tempWorkspace();
  const real = writeFixture(temp, 'real.bin', Buffer.from('x'));
  try { fs.symlinkSync(path.join(temp, real), path.join(temp, 'link.bin')); }
  catch (e) { if (e.code === 'EPERM') return t.skip('Host disallows link creation'); throw e; }
  assert.throws(() => inspect.execute({ path: 'link.bin' }, { workspaceRoot: temp, policy }), (e) => e instanceof HarnessError && e.code === 'PATH_DENIED');
});
