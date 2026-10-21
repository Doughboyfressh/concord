import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { makeArtifactTools } from '../src/artifacts.mjs';
import { HarnessError, canonical, validateSchema } from '../src/value.mjs';
import { runPlan, replayPlan } from '../src/engine.mjs';
import { tempDir } from './temp-workspace.mjs';

const inspect = new Map(makeArtifactTools().map((t) => [t.name, t])).get('artifact.inspect');
const policy = { maxOutputBytes: 1048576 };

function tempWorkspace() {
  return tempDir('concord-artifacts-');
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
  assert.deepEqual(result.elf, { class: '32-bit', dataEncoding: 'little-endian', type: 2, machine: 3, entryPoint: 0x8048000, sectionCount: 11, segments: [], neededLibraries: [] });
});

test('extracts correct ELF64 header fields, including a 64-bit entry point', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'a64.elf', minimalElf(true)) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.elf, { class: '64-bit', dataEncoding: 'little-endian', type: 2, machine: 0x3e, entryPoint: 0x400000, sectionCount: 11, segments: [], neededLibraries: [] });
});

test('extracts correct PE header fields', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'a.exe', minimalPe()) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.pe, { machine: 0x8664, sectionCount: 7, timestamp: 1700000000, entryPoint: 0x1000, sections: [], imports: [] });
});

/**
 * A PE whose section table really maps the entry point somewhere other than its RVA.
 *
 * The gap matters: AddressOfEntryPoint is an RVA, every disassembler input is a file offset, and the
 * two differ by exactly the distance between a section virtual address and where its bytes sit in
 * the file. A fixture where the two happen to be equal would pass with the conversion deleted.
 */
function peWithSections() {
  const buffer = Buffer.alloc(512);
  buffer.write('MZ', 0, 'latin1');
  buffer.writeInt32LE(64, 0x3c);
  buffer.write('PE\u0000\u0000', 64, 'latin1');
  buffer.writeUInt16LE(0x8664, 68);
  buffer.writeUInt16LE(1, 70); // one section
  buffer.writeUInt32LE(1700000000, 72);
  buffer.writeUInt16LE(240, 84); // SizeOfOptionalHeader
  buffer.writeUInt16LE(0x20b, 88); // PE32+ magic, which moves ImageBase and the data directories
  buffer.writeUInt32LE(0x1234, 104); // AddressOfEntryPoint, an RVA
  buffer.writeBigUInt64LE(0x140000000n, 112); // ImageBase
  const section = 64 + 24 + 240;
  buffer.write('.text', section, 'latin1');
  buffer.writeUInt32LE(0x2000, section + 8); // VirtualSize
  buffer.writeUInt32LE(0x1000, section + 12); // VirtualAddress
  buffer.writeUInt32LE(0x2000, section + 16); // SizeOfRawData
  buffer.writeUInt32LE(0x400, section + 20); // PointerToRawData
  return buffer;
}

test('a PE entry point RVA is converted to the file offset its section table implies', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'sections.exe', peWithSections()) }, { workspaceRoot: temp, policy });
  assert.equal(result.pe.entryPoint, 0x1234);
  // 0x1234 - 0x1000 + 0x400. The point of the assertion is that it is not 0x1234.
  assert.equal(result.pe.entryPointOffset, 0x634);
  assert.notEqual(result.pe.entryPointOffset, result.pe.entryPoint);
  assert.equal(result.pe.imageBase, 0x140000000);
  assert.equal(result.pe.entryPointAddress, 0x140001234);
  assert.deepEqual(result.pe.sections, [{ name: '.text', virtualAddress: 0x1000, virtualSize: 0x2000, fileOffset: 0x400, fileSize: 0x2000 }]);
});

test('an entry point RVA no section covers reports no file offset rather than a wrong one', () => {
  const temp = tempWorkspace();
  const buffer = peWithSections();
  buffer.writeUInt32LE(0x900000, 104); // an RVA past every section
  const result = inspect.execute({ path: writeFixture(temp, 'unmapped.exe', buffer) }, { workspaceRoot: temp, policy });
  assert.equal(result.pe.entryPoint, 0x900000);
  assert.ok(!('entryPointOffset' in result.pe), 'an unmappable RVA must not produce an offset key');
  // The loaded address is still known, because it needs only the image base.
  assert.equal(result.pe.entryPointAddress, 0x140900000);
});

/** A 64-bit ELF with one PT_LOAD, so the entry virtual address maps to a different file offset. */
function elfWithSegment() {
  const buffer = Buffer.alloc(256);
  buffer.write('\u007fELF', 0, 'latin1');
  buffer[4] = 2;
  buffer[5] = 1;
  buffer[6] = 1;
  buffer.writeUInt16LE(2, 16);
  buffer.writeUInt16LE(0x3e, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x400500n, 24); // e_entry
  buffer.writeBigUInt64LE(64n, 32); // e_phoff
  buffer.writeUInt16LE(56, 54); // e_phentsize
  buffer.writeUInt16LE(1, 56); // e_phnum
  buffer.writeUInt16LE(11, 60); // e_shnum
  buffer.writeUInt32LE(1, 64); // p_type = PT_LOAD
  buffer.writeBigUInt64LE(0x200n, 64 + 8); // p_offset
  buffer.writeBigUInt64LE(0x400000n, 64 + 16); // p_vaddr
  buffer.writeBigUInt64LE(0x1000n, 64 + 32); // p_filesz
  return buffer;
}

test('an ELF entry point virtual address is converted through its PT_LOAD segment', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'seg.elf', elfWithSegment()) }, { workspaceRoot: temp, policy });
  assert.equal(result.elf.entryPoint, 0x400500);
  assert.equal(result.elf.entryPointOffset, 0x700); // 0x400500 - 0x400000 + 0x200
  assert.notEqual(result.elf.entryPointOffset, result.elf.entryPoint);
  assert.deepEqual(result.elf.segments, [{ vaddr: 0x400000, fileOffset: 0x200, fileSize: 0x1000 }]);
});

test('an ELF entry point outside every loaded segment reports no file offset', () => {
  const temp = tempWorkspace();
  const buffer = elfWithSegment();
  buffer.writeBigUInt64LE(0x900000n, 24);
  const result = inspect.execute({ path: writeFixture(temp, 'unmapped.elf', buffer) }, { workspaceRoot: temp, policy });
  assert.equal(result.elf.entryPoint, 0x900000);
  assert.ok(!('entryPointOffset' in result.elf), 'an unmappable virtual address must not produce an offset key');
});

test('no header field is ever reported as undefined, which canonical refuses', () => {
  const temp = tempWorkspace();
  for (const [name, bytes] of [['sections.exe', peWithSections()], ['a.exe', minimalPe()],
    ['seg.elf', elfWithSegment()], ['a64.elf', minimalElf(true)], ['a32.elf', minimalElf(false)]]) {
    const result = inspect.execute({ path: writeFixture(temp, name, bytes) }, { workspaceRoot: temp, policy });
    const header = result.pe ?? result.elf;
    const undefinedKeys = Object.entries(header).filter(([, value]) => value === undefined).map(([key]) => key);
    assert.deepEqual(undefinedKeys, [], `${name} reported undefined for ${undefinedKeys.join(', ')}`);
  }
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
  // The PE and ELF entries carry the optional entry-point-offset keys, which is the case that
  // breaks if an unknown field is reported as undefined instead of omitted: canonical() refuses
  // undefined, so the whole journal would fail to serialise rather than the field being missing.
  const inputs = [['no-uuid.dylib', macho], ['partial.wasm', Buffer.from([0, 0x61, 0x73, 0x6d])], ['future.wasm', futureWasm],
    ['sections.exe', peWithSections()], ['seg.elf', elfWithSegment()], ['a.exe', minimalPe()], ['a64.elf', minimalElf(true)]];
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

// REA recovers a WASM interface through WABT, an external toolkit. Concord decodes it from the
// bytes instead, so the check that matters is agreement with an independent implementation rather
// than with an expectation written here: Node's own WebAssembly reports the real names and kinds.
const artifactTools = new Map(makeArtifactTools().map((t) => [t.name, t]));
const wasmInterface = artifactTools.get('artifact.wasmInterface');
const compareWasmInterfaces = artifactTools.get('artifact.compareWasmInterfaces');

const leb = (n) => { const out = []; do { let b = n & 0x7f; n >>>= 7; if (n !== 0) b |= 0x80; out.push(b); } while (n !== 0); return out; };
const wasmStr = (s) => { const b = [...Buffer.from(s, 'utf8')]; return [...leb(b.length), ...b]; };
const wasmVec = (items) => [...leb(items.length), ...items.flat()];
const wasmSection = (id, payload) => [id, ...leb(payload.length), ...payload];
const wasmModule = (...sections) => Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...sections.flat()]);
const wasmBody = (bytes) => [...leb(bytes.length), ...bytes];

function wasmFixture(resultType, exportNames) {
  const types = wasmSection(1, wasmVec([
    [0x60, ...wasmVec([[0x7f]]), ...wasmVec([[0x7f]])],
    [0x60, ...wasmVec([]), ...wasmVec([])],
    [0x60, ...wasmVec([[0x7e], [0x7e]]), ...wasmVec([[resultType]])],
  ]));
  const imports = wasmSection(2, wasmVec([
    [...wasmStr('env'), ...wasmStr('imported_func'), 0x00, ...leb(0)],
    [...wasmStr('env'), ...wasmStr('mem'), 0x02, 0x00, ...leb(1)],
    [...wasmStr('host'), ...wasmStr('tbl'), 0x01, 0x70, 0x01, ...leb(1), ...leb(10)],
  ]));
  const funcs = wasmSection(3, wasmVec([[...leb(1)], [...leb(2)]]));
  const exported = wasmSection(7, wasmVec(exportNames));
  // A function section is legal only with a matching code section.
  const value = resultType === 0x7c ? [0x44, 0, 0, 0, 0, 0, 0, 0, 0] : [0x42, 0x00];
  const code = wasmSection(10, wasmVec([wasmBody([0x00, 0x0b]), wasmBody([0x00, ...value, 0x0b])]));
  return wasmModule(types, imports, funcs, exported, code);
}

test('WASM interface decoding agrees with Node WebAssembly, and resolves the function index space', () => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };
  const base = wasmFixture(0x7c, [
    [...wasmStr('exported_void'), 0x00, ...leb(1)],
    [...wasmStr('exported_math'), 0x00, ...leb(2)],
    [...wasmStr('exported_mem'), 0x02, ...leb(0)],
  ]);
  const variant = wasmFixture(0x7e, [
    [...wasmStr('exported_void'), 0x00, ...leb(1)],
    [...wasmStr('exported_math'), 0x00, ...leb(2)],
    [...wasmStr('added_export'), 0x00, ...leb(1)],
  ]);
  const cases = { 'full.wasm': base, 'variant.wasm': variant, 'empty.wasm': wasmModule() };

  for (const [name, bytes] of Object.entries(cases)) {
    writeFixture(temp, name, bytes);
    // A fixture the real implementation rejects would make any agreement below vacuous.
    assert.equal(WebAssembly.validate(bytes), true, name);
    const module = new WebAssembly.Module(bytes);
    const mine = wasmInterface.execute({ path: name }, context);
    const kindOf = (k) => (k === 'func' ? 'function' : k);
    const mineIn = mine.entries.filter((e) => e.direction === 'import').map((e) => [e.module, e.name, kindOf(e.kind)]).sort();
    const mineOut = mine.entries.filter((e) => e.direction === 'export').map((e) => [e.name, kindOf(e.kind)]).sort();
    assert.deepEqual(mineIn, WebAssembly.Module.imports(module).map((x) => [x.module, x.name, x.kind]).sort(), name);
    assert.deepEqual(mineOut, WebAssembly.Module.exports(module).map((x) => [x.name, x.kind]).sort(), name);
    assert.equal(mine.state, 'complete', name);
  }

  // Signatures are the part the oracle cannot report. exported_math is the second DEFINED
  // function, so a parser that ignored the imported function would resolve the wrong type.
  const full = wasmInterface.execute({ path: 'full.wasm' }, context);
  const math = full.entries.find((e) => e.name === 'exported_math');
  assert.deepEqual(math.signature, { kind: 'func', params: ['i64', 'i64'], results: ['f64'] });
  assert.equal(math.wat_form, '(export "exported_math" (func (param i64 i64) (result f64)))');
  const imported = full.entries.find((e) => e.name === 'imported_func');
  assert.deepEqual(imported.signature, { kind: 'func', params: ['i32'], results: ['i32'] });
  assert.equal(full.entries.find((e) => e.name === 'tbl').signature.element, 'funcref');
  // Identical bytes decode identically, which replay depends on.
  assert.deepEqual(wasmInterface.execute({ path: 'full.wasm' }, context), full);

  const diff = compareWasmInterfaces.execute({ left: full, right: wasmInterface.execute({ path: 'variant.wasm' }, context), select: 'exports' });
  assert.deepEqual(diff.summary, { added: 1, removed: 1, changed: 1, unchanged: 1, unknown: 0 });
  assert.equal(diff.changes.find((c) => c.name === 'exported_math').state, 'changed');
  assert.equal(diff.changes.find((c) => c.name === 'exported_mem').state, 'removed');
  assert.equal(diff.changes.find((c) => c.name === 'added_export').state, 'added');
  assert.equal(diff.changes.find((c) => c.name === 'exported_void').state, 'unchanged');

  // The declaration has to accept what this test just passed. Calling execute() directly skips
  // schema validation, which the kernel performs for a plan — so until a training round composed
  // these two tools in a plan, this test passed whole reader results while the declared schema
  // rejected them, and the disagreement was invisible from either side. A reference is resolved
  // while running, so the cost was a failed task rather than a refused plan.
  assert.doesNotThrow(() => validateSchema({ left: full, right: full, select: 'exports' }, compareWasmInterfaces.inputSchema));
  fs.rmSync(temp, { recursive: true, force: true });
});

test('WASM interface reports what it could not decode instead of an empty interface', () => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };
  const base = wasmFixture(0x7c, [[...wasmStr('only'), 0x00, ...leb(1)]]);

  writeFixture(temp, 'cut.wasm', base.subarray(0, 24));
  const cut = wasmInterface.execute({ path: 'cut.wasm' }, context);
  assert.equal(cut.state, 'partial');
  assert.ok(cut.limitations.length > 0);

  // Not a module at all is an answer about the bytes, not a thrown error.
  writeFixture(temp, 'plain.txt', Buffer.from('definitely not a wasm module'));
  const plain = wasmInterface.execute({ path: 'plain.txt' }, context);
  assert.equal(plain.state, 'partial');
  assert.deepEqual(plain.entries, []);
  assert.match(plain.limitations[0], /not a WASM module/);

  // A duplicated name has no established correspondence, so equality is never claimed.
  const left = { state: 'complete', entries: [
    { direction: 'export', module: null, name: 'dup', kind: 'func', signature: { kind: 'func', params: [], results: [] } },
    { direction: 'export', module: null, name: 'dup', kind: 'func', signature: { kind: 'func', params: ['i32'], results: [] } },
  ] };
  const right = { state: 'complete', entries: [
    { direction: 'export', module: null, name: 'dup', kind: 'func', signature: { kind: 'func', params: [], results: [] } },
  ] };
  const dup = compareWasmInterfaces.execute({ left, right, select: 'exports' });
  assert.equal(dup.summary.unknown, 1);
  assert.equal(dup.summary.unchanged, 0);
  assert.match(dup.changes[0].reason, /occurs more than once/);

  // A partial side cannot be read as evidence of removal.
  const partial = compareWasmInterfaces.execute({ left, right: { state: 'partial', entries: [] }, select: 'exports' });
  assert.ok(partial.limitations.some((l) => /right interface is partial/.test(l)));
  fs.rmSync(temp, { recursive: true, force: true });
});

// REA recovers EVM selectors with bundled EVMole plus a host prlimit. That dataflow analysis is
// not reproduced here, so these tests check the two things that are actually determinate from the
// bytes: that the opcode sweep skips PUSH immediates by width, and that a Solidity metadata
// trailer is only accepted when its length prefix addresses a real CBOR root map.
const evmInterface = artifactTools.get('artifact.evmInterface');

test('EVM selector candidates agree with REAs own fixture and never read PUSH data as code', () => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };

  // Verbatim from REA scripts/verify-evm-interface.mjs, where EVMole is expected to report
  // exactly 0x00000000: PUSH1 0, CALLDATALOAD, PUSH1 0xe0, SHR, PUSH4 0, EQ, PUSH1 0x10, JUMPI.
  writeFixture(temp, 'zero-selector.hex', Buffer.from('60003560e01c630000000014601057005b00', 'utf8'));
  const zero = evmInterface.execute({ path: 'zero-selector.hex', encoding: 'hex' }, context);
  assert.equal(zero.supported, true);
  assert.deepEqual(zero.selectorCandidates.map((s) => s.selector), ['00000000']);
  assert.equal(zero.opcodes.jumpdests, 1);

  // The property that separates a sweep from a substring search: a PUSH32 immediate containing
  // the byte pattern of PUSH4 followed by a plausible selector must NOT yield that selector.
  const hidden = Buffer.concat([
    Buffer.from([0x7f]), // PUSH32
    Buffer.from([0x63, 0xde, 0xad, 0xbe, 0xef]), // looks like PUSH4 deadbeef, but it is data
    Buffer.alloc(27, 0x11),
    Buffer.from([0x50]), // POP
    Buffer.from([0x63, 0xa9, 0x05, 0x9c, 0xbb]), // a real PUSH4, in code position
    Buffer.from([0x14, 0x00]), // EQ, STOP
  ]);
  writeFixture(temp, 'hidden.bin', hidden);
  const swept = evmInterface.execute({ path: 'hidden.bin', encoding: 'raw' }, context);
  assert.deepEqual(swept.selectorCandidates.map((s) => s.selector), ['a9059cbb']);
  assert.equal(swept.selectorCandidates.some((s) => s.selector === 'deadbeef'), false);
  assert.equal(swept.opcodes.pushes, 2);

  // Candidates are labelled as candidates rather than asserted to be the interface.
  assert.ok(swept.limitations.some((l) => /PUSH4 sweep/.test(l)));
  fs.rmSync(temp, { recursive: true, force: true });
});

test('EVM carrier digests stay distinct, hex rules are strict, and EOF is refused by name', () => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };

  // The carrier digest covers the file as written; the bytecode digest covers the decoded bytes.
  // Two carriers differing only in prefix and casing decode to identical bytecode.
  writeFixture(temp, 'a.hex', Buffer.from('0x6000', 'utf8'));
  writeFixture(temp, 'b.hex', Buffer.from('6000\n', 'utf8'));
  const a = evmInterface.execute({ path: 'a.hex', encoding: 'hex' }, context);
  const b = evmInterface.execute({ path: 'b.hex', encoding: 'hex' }, context);
  assert.notEqual(a.carrierSha256, b.carrierSha256);
  assert.equal(a.bytecodeSha256, b.bytecodeSha256);
  assert.equal(a.bytecodeBytes, 2);

  for (const [name, text, why] of [
    ['odd.hex', '600', /odd number/],
    ['sep.hex', '60 00', /interior separators/],
    ['stray.hex', '60x00', /interior separators|stray x/],
  ]) {
    writeFixture(temp, name, Buffer.from(text, 'utf8'));
    const bad = evmInterface.execute({ path: name, encoding: 'hex' }, context);
    assert.equal(bad.supported, false, name);
    assert.equal(bad.reason, 'carrier_invalid', name);
    assert.match(bad.detail, why, name);
    assert.equal(bad.bytecodeSha256, null, name);
  }

  // An EOF container is named as unsupported rather than decoded as legacy bytecode.
  writeFixture(temp, 'eof.bin', Buffer.from([0xef, 0x00, 0x01, 0x01, 0x00]));
  const eof = evmInterface.execute({ path: 'eof.bin', encoding: 'raw' }, context);
  assert.equal(eof.supported, false);
  assert.equal(eof.reason, 'unsupported_target');
  assert.match(eof.detail, /EOF/);

  // Empty bytecode is a valid carrier with nothing to report, not an error.
  writeFixture(temp, 'empty.bin', Buffer.alloc(0));
  const empty = evmInterface.execute({ path: 'empty.bin', encoding: 'raw' }, context);
  assert.equal(empty.supported, true);
  assert.deepEqual(empty.selectorCandidates, []);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('a Solidity metadata trailer is read only when its length prefix addresses a CBOR map', () => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };
  const code = Buffer.from([0x60, 0x01, 0x50, 0x00]);
  // CBOR: {"solc": h'00081e'} is 10 bytes, followed by its big-endian length.
  const cbor = Buffer.from([0xa1, 0x64, 0x73, 0x6f, 0x6c, 0x63, 0x43, 0x00, 0x08, 0x1e]);
  writeFixture(temp, 'meta.bin', Buffer.concat([code, cbor, Buffer.from([0x00, 0x0a])]));
  const withMeta = evmInterface.execute({ path: 'meta.bin', encoding: 'raw' }, context);
  assert.deepEqual(withMeta.metadata.root, { solc: '00081e' });
  assert.equal(withMeta.metadata.length, 10);
  assert.equal(withMeta.metadata.offset, code.length);
  // The trailer is excluded from the code region, so it is never swept as opcodes.
  assert.equal(withMeta.opcodes.codeBytes, code.length);

  // A length prefix pointing at something that is not a CBOR root map is reported, not believed.
  // 0xfb is genuinely unassigned; 0xff would not be, since it is SELFDESTRUCT.
  writeFixture(temp, 'lying.bin', Buffer.concat([code, Buffer.alloc(10, 0xfb), Buffer.from([0x00, 0x0a])]));
  const lying = evmInterface.execute({ path: 'lying.bin', encoding: 'raw' }, context);
  assert.equal(lying.metadata, null);
  assert.ok(lying.limitations.some((l) => /did not address a CBOR root map/.test(l)));
  assert.equal(lying.opcodes.codeBytes, lying.bytecodeBytes);

  // Undefined opcodes are surfaced rather than skipped: the 0xfb bytes above are unassigned.
  assert.ok(lying.opcodes.undefinedCount > 0);
  // Cancun opcodes must NOT count as undefined, which a split 0x50-0x5b / 0x5f-0x9f table got wrong.
  writeFixture(temp, 'cancun.bin', Buffer.from([0x5c, 0x5d, 0x5e, 0x5f]));
  assert.deepEqual(evmInterface.execute({ path: 'cancun.bin', encoding: 'raw' }, context).opcodes.undefined, []);
  // Identical bytes read identically, which replay depends on.
  assert.deepEqual(evmInterface.execute({ path: 'meta.bin', encoding: 'raw' }, context), withMeta);
  fs.rmSync(temp, { recursive: true, force: true });
});

// REA reads SQLite structure through the sqlite3 library. Concord reads the documented file
// format directly, so the check is agreement with SQLite itself via Node's built-in node:sqlite,
// not agreement with an expectation written here.
const sqliteTool = artifactTools.get('artifact.sqlite');

test('SQLite structure agrees with the engines own sqlite_master and header pragmas', async () => {
  const { DatabaseSync } = await import('node:sqlite');
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };
  const file = path.join(temp, 'app.db');
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA user_version = 42;
    CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT NOT NULL, balance REAL);
    CREATE TABLE sessions (token TEXT PRIMARY KEY, account_id INTEGER REFERENCES accounts(id));
    CREATE INDEX accounts_by_email ON accounts(email);
    CREATE VIEW rich AS SELECT id FROM accounts WHERE balance > 1000;
    CREATE TRIGGER touch AFTER UPDATE ON accounts BEGIN UPDATE accounts SET balance = balance; END;
    INSERT INTO accounts (email, balance) VALUES ('a@example.com', 10.5), ('b@example.com', 2000);
  `);
  const oracle = db.prepare('SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY name').all();
  const pragma = (sql) => Object.values(db.prepare(sql).get())[0];
  const expected = {
    pageSize: pragma('PRAGMA page_size'), encoding: pragma('PRAGMA encoding'),
    userVersion: pragma('PRAGMA user_version'), pageCount: pragma('PRAGMA page_count'),
    schemaCookie: pragma('PRAGMA schema_version'),
  };
  db.close();

  const mine = sqliteTool.execute({ path: 'app.db' }, context);
  assert.equal(mine.supported, true);
  assert.equal(mine.header.pageSize, expected.pageSize);
  assert.equal(mine.header.textEncoding, expected.encoding);
  assert.equal(mine.header.userVersion, expected.userVersion);
  assert.equal(mine.header.pageCount, expected.pageCount);
  assert.equal(mine.header.schemaCookie, expected.schemaCookie);

  // rootPage is the assertion that matters most: it comes from a 1-byte signed serial type, and
  // reading it with the 8-byte helper silently produced a string for every table.
  const shape = (rows) => rows.map((r) => [r.type, r.name, r.tbl_name ?? r.tableName,
    r.rootpage ?? r.rootPage, (r.sql ?? '').replace(/\s+/g, ' ').trim()]).sort((a, b) => (a[1] < b[1] ? -1 : 1));
  assert.deepEqual(shape(mine.objects), shape(oracle));
  assert.equal(mine.objects.length, 6);
  assert.deepEqual(mine.counts, { table: 2, index: 2, view: 1, trigger: 1 });
  assert.deepEqual(mine.limitations, []);
  for (const object of mine.objects) {
    if (object.type === 'table') assert.equal(typeof object.rootPage, 'number');
  }
  // Identical bytes read identically, which replay depends on.
  assert.deepEqual(sqliteTool.execute({ path: 'app.db' }, context), mine);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('SQLite reading reports a non-database, a WAL journal and a truncated file honestly', async () => {
  const { DatabaseSync } = await import('node:sqlite');
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };

  // Not a database at all is an answer about the bytes, not a thrown error.
  writeFixture(temp, 'plain.txt', Buffer.from('definitely not a database'));
  const plain = sqliteTool.execute({ path: 'plain.txt' }, context);
  assert.equal(plain.supported, false);
  assert.equal(plain.reason, 'not_sqlite');
  assert.deepEqual(plain.objects, []);

  const walPath = path.join(temp, 'wal.db');
  const wal = new DatabaseSync(walPath);
  wal.exec('PRAGMA journal_mode = WAL; CREATE TABLE t (x);');
  wal.close();
  const walRead = sqliteTool.execute({ path: 'wal.db' }, context);
  assert.equal(walRead.header.writeVersion, 'wal');
  assert.deepEqual(walRead.objects.map((o) => o.name), ['t']);

  // A header-only file declares pages it does not contain: said plainly, not implied by a count.
  writeFixture(temp, 'cut.db', fs.readFileSync(walPath).subarray(0, 100));
  const cut = sqliteTool.execute({ path: 'cut.db' }, context);
  assert.equal(cut.supported, true);
  assert.deepEqual(cut.objects, []);
  assert.ok(cut.limitations.some((l) => /truncated or sparse/.test(l)));

  // A 65536-byte page size is encoded as 1, the one value that does not fit the 16-bit field.
  const odd = Buffer.alloc(200);
  odd.write('SQLite format 3\0', 0, 'latin1');
  odd.writeUInt16BE(1, 16);
  odd.writeUInt32BE(1, 28);
  odd.writeUInt32BE(1, 56);
  writeFixture(temp, 'big-page.db', odd);
  const big = sqliteTool.execute({ path: 'big-page.db' }, context);
  assert.equal(big.header.pageSize, 65536);
  assert.equal(big.header.pageSizeValid, true);

  // A page size that is not a power of two is refused rather than used to walk the file.
  const bad = Buffer.from(odd);
  bad.writeUInt16BE(1000, 16);
  writeFixture(temp, 'bad-page.db', bad);
  const badRead = sqliteTool.execute({ path: 'bad-page.db' }, context);
  assert.equal(badRead.header.pageSizeValid, false);
  assert.deepEqual(badRead.objects, []);
  assert.ok(badRead.limitations.some((l) => /power of two/.test(l)));
  fs.rmSync(temp, { recursive: true, force: true });
});

// REA reads captures, PE resources and Go metadata through external tooling. Concord reads the
// documented layouts directly. Each fixture below encodes a distinctive value at a known offset,
// so the assertion is that the reader returns exactly what was written there: an offset,
// endianness or layer-walk error cannot pass.
const pcapTool = artifactTools.get('artifact.pcap');
const packetFieldsTool = artifactTools.get('artifact.packetFields');
const peResourcesTool = artifactTools.get('artifact.peResources');
const goBuildInfoTool = artifactTools.get('artifact.goBuildInfo');

function ethernetTcpFrame() {
  const ether = Buffer.concat([
    Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    Buffer.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    Buffer.from([0x08, 0x00]),
  ]);
  const ipv4 = Buffer.alloc(20);
  ipv4[0] = 0x45;
  ipv4.writeUInt16BE(40, 2);
  ipv4[8] = 64;
  ipv4[9] = 6;
  Buffer.from([10, 0, 0, 1]).copy(ipv4, 12);
  Buffer.from([192, 168, 7, 9]).copy(ipv4, 16);
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(43210, 0);
  tcp.writeUInt16BE(443, 2);
  tcp.writeUInt32BE(305419896, 4);
  tcp[12] = 5 << 4;
  tcp[13] = 0x02 | 0x10;
  tcp.writeUInt16BE(64240, 14);
  return Buffer.concat([ether, ipv4, tcp]);
}

function classicPcap({ bigEndian = false, records = [] } = {}) {
  const global = Buffer.alloc(24);
  (bigEndian ? Buffer.from([0xa1, 0xb2, 0xc3, 0xd4]) : Buffer.from([0xd4, 0xc3, 0xb2, 0xa1])).copy(global, 0);
  const u16 = (v, o) => (bigEndian ? global.writeUInt16BE(v, o) : global.writeUInt16LE(v, o));
  const u32 = (v, o) => (bigEndian ? global.writeUInt32BE(v, o) : global.writeUInt32LE(v, o));
  u16(2, 4); u16(4, 6); u32(262144, 16); u32(1, 20);
  const parts = [global];
  for (const { seconds, sub, payload, originalLength } of records) {
    const head = Buffer.alloc(16);
    const w = (v, o) => (bigEndian ? head.writeUInt32BE(v, o) : head.writeUInt32LE(v, o));
    w(seconds, 0); w(sub, 4); w(payload.length, 8); w(originalLength ?? payload.length, 12);
    parts.push(head, payload);
  }
  return Buffer.concat(parts);
}

test('pcap reading recovers the global header, records and slicing in both byte orders', (t) => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };
  const frame = ethernetTcpFrame();
  const records = [
    { seconds: 1700000000, sub: 123456, payload: frame },
    { seconds: 1700000005, sub: 654321, payload: frame, originalLength: 9999 },
  ];
  writeFixture(temp, 'two.pcap', classicPcap({ records }));
  const cap = pcapTool.execute({ path: 'two.pcap' }, context);
  assert.equal(cap.format, 'pcap');
  assert.equal(cap.supported, true);
  assert.equal(cap.header.byteOrder, 'little');
  assert.equal(cap.header.timestampUnit, 'microseconds');
  assert.equal(cap.header.linkType, 1);
  assert.equal(cap.header.linkTypeName, 'ethernet');
  assert.equal(cap.header.snapLength, 262144);
  assert.deepEqual(cap.summary, {
    packetCount: 2, capturedBytes: frame.length * 2, originalBytes: frame.length + 9999, slicedPackets: 1,
    firstTimestamp: { seconds: 1700000000, sub: 123456 },
    lastTimestamp: { seconds: 1700000005, sub: 654321 },
  });
  // A sliced packet is one whose wire length exceeds what was captured.
  assert.deepEqual(cap.packets.map((p) => p.sliced), [false, true]);
  assert.deepEqual(cap.limitations, []);

  // The stored byte order decides how every field is read, so a big-endian file of the same
  // capture must yield identical values rather than byte-swapped ones.
  writeFixture(temp, 'be.pcap', classicPcap({ bigEndian: true, records: [records[0]] }));
  const be = pcapTool.execute({ path: 'be.pcap' }, context);
  assert.equal(be.header.byteOrder, 'big');
  assert.equal(be.header.snapLength, cap.header.snapLength);
  assert.equal(be.packets[0].timestampSeconds, cap.packets[0].timestampSeconds);
  assert.equal(be.packets[0].timestampSub, cap.packets[0].timestampSub);

  // Nanosecond captures are a different magic, and the unit rides along with it.
  const nanos = classicPcap({ records: [records[0]] });
  Buffer.from([0x4d, 0x3c, 0xb2, 0xa1]).copy(nanos, 0);
  writeFixture(temp, 'nanos.pcap', nanos);
  assert.equal(pcapTool.execute({ path: 'nanos.pcap' }, context).header.timestampUnit, 'nanoseconds');

  // A record claiming more captured bytes than the file holds must stop the sweep.
  const lying = classicPcap({ records: [records[0]] });
  lying.writeUInt32LE(100000, 24 + 8);
  writeFixture(temp, 'lying.pcap', lying);
  const lyingRead = pcapTool.execute({ path: 'lying.pcap' }, context);
  assert.deepEqual(lyingRead.packets, []);
  assert.ok(lyingRead.limitations.some((l) => /more captured bytes/.test(l)));

  // pcapng is a different container: recognised structurally, not mis-read as classic pcap.
  const shb = Buffer.alloc(28);
  shb.writeUInt32LE(0x0a0d0d0a, 0); shb.writeUInt32LE(28, 4); shb.writeUInt32LE(0x1a2b3c4d, 8);
  shb.writeUInt16LE(1, 12); shb.writeUInt32LE(28, 24);
  writeFixture(temp, 'cap.pcapng', shb);
  const ng = pcapTool.execute({ path: 'cap.pcapng' }, context);
  assert.equal(ng.format, 'pcapng');
  assert.equal(ng.byteOrder, 'little');
  assert.equal(ng.blocks.length, 1);
  assert.ok(ng.limitations.some((l) => /block level/.test(l)));

  writeFixture(temp, 'plain.txt', Buffer.from('not a capture at all'));
  const plain = pcapTool.execute({ path: 'plain.txt' }, context);
  assert.equal(plain.supported, false);
  assert.equal(plain.reason, 'not_a_capture');
  assert.deepEqual(pcapTool.execute({ path: 'two.pcap' }, context), cap);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('packet field decoding returns exactly the values encoded at each header offset', () => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };
  const frame = ethernetTcpFrame();
  writeFixture(temp, 'one.pcap', classicPcap({ records: [{ seconds: 1, sub: 2, payload: frame }] }));
  const decoded = packetFieldsTool.execute({ path: 'one.pcap' }, context);
  assert.equal(decoded.supported, true);
  assert.equal(decoded.linkTypeName, 'ethernet');
  assert.equal(decoded.decoded, 1);
  const layers = Object.fromEntries(decoded.frames[0].layers.map((l) => [l.layer, l]));
  assert.equal(layers.ethernet.destination, 'aa:bb:cc:dd:ee:ff');
  assert.equal(layers.ethernet.source, '11:22:33:44:55:66');
  assert.equal(layers.ipv4.source, '10.0.0.1');
  assert.equal(layers.ipv4.destination, '192.168.7.9');
  assert.equal(layers.ipv4.ttl, 64);
  assert.equal(layers.ipv4.protocolName, 'tcp');
  assert.equal(layers.tcp.sourcePort, 43210);
  assert.equal(layers.tcp.destinationPort, 443);
  assert.equal(layers.tcp.sequence, 305419896);
  assert.equal(layers.tcp.window, 64240);
  assert.deepEqual(layers.tcp.flags, ['syn', 'ack']);

  // A VLAN tag shifts every later layer by four bytes, so an unwrapped tag would misread the IP.
  const tagged = Buffer.concat([
    frame.subarray(0, 12), Buffer.from([0x81, 0x00]),
    Buffer.from([0x20, 0x64]), Buffer.from([0x08, 0x00]), frame.subarray(14),
  ]);
  writeFixture(temp, 'vlan.pcap', classicPcap({ records: [{ seconds: 1, sub: 0, payload: tagged }] }));
  const vlan = packetFieldsTool.execute({ path: 'vlan.pcap' }, context);
  const vlanLayers = Object.fromEntries(vlan.frames[0].layers.map((l) => [l.layer, l]));
  assert.equal(vlanLayers.vlan.id, 100);
  assert.equal(vlanLayers.ipv4.source, '10.0.0.1');
  assert.equal(vlanLayers.tcp.destinationPort, 443);

  // A UDP frame takes the other transport branch.
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(53, 0); udp.writeUInt16BE(5353, 2); udp.writeUInt16BE(8, 4);
  const udpFrame = Buffer.concat([frame.subarray(0, 14), (() => {
    const ip = Buffer.from(frame.subarray(14, 34)); ip[9] = 17; return ip;
  })(), udp]);
  writeFixture(temp, 'udp.pcap', classicPcap({ records: [{ seconds: 1, sub: 0, payload: udpFrame }] }));
  const udpLayers = Object.fromEntries(packetFieldsTool.execute({ path: 'udp.pcap' }, context).frames[0].layers.map((l) => [l.layer, l]));
  assert.equal(udpLayers.ipv4.protocolName, 'udp');
  assert.equal(udpLayers.udp.sourcePort, 53);
  assert.equal(udpLayers.udp.destinationPort, 5353);

  // A truncated frame reports truncation rather than reading past what was captured.
  writeFixture(temp, 'cut.pcap', classicPcap({ records: [{ seconds: 1, sub: 0, payload: frame.subarray(0, 20), originalLength: frame.length }] }));
  const cut = packetFieldsTool.execute({ path: 'cut.pcap' }, context);
  assert.equal(cut.frames[0].truncated, true);
  assert.ok(cut.limitations.some((l) => /sliced packet/.test(l)));

  // Fields come from classic pcap only; pcapng says so rather than returning empty frames.
  const shb = Buffer.alloc(28);
  shb.writeUInt32LE(0x0a0d0d0a, 0); shb.writeUInt32LE(28, 4); shb.writeUInt32LE(0x1a2b3c4d, 8);
  shb.writeUInt32LE(28, 24);
  writeFixture(temp, 'x.pcapng', shb);
  const ng = packetFieldsTool.execute({ path: 'x.pcapng' }, context);
  assert.equal(ng.supported, false);
  assert.deepEqual(ng.frames, []);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('PE resource reading walks the three-level tree and names the standard types', () => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };
  const buffer = Buffer.alloc(0x800);
  buffer.write('MZ', 0, 'latin1');
  buffer.writeInt32LE(64, 0x3c);
  buffer.write('PE\0\0', 64, 'latin1');
  buffer.writeUInt16LE(0x8664, 68);
  buffer.writeUInt16LE(1, 70);           // one section
  buffer.writeUInt16LE(240, 84);         // SizeOfOptionalHeader
  const optionalAt = 88;
  buffer.writeUInt16LE(0x20b, optionalAt); // PE32+
  buffer.writeUInt32LE(16, optionalAt + 108); // NumberOfRvaAndSizes
  const directoriesAt = optionalAt + 112;
  buffer.writeUInt32LE(0x2000, directoriesAt + 16); // resource RVA
  buffer.writeUInt32LE(0x400, directoriesAt + 20);  // resource size
  const sectionAt = optionalAt + 240;
  buffer.write('.rsrc\0\0\0', sectionAt, 'latin1');
  buffer.writeUInt32LE(0x400, sectionAt + 8);   // VirtualSize
  buffer.writeUInt32LE(0x2000, sectionAt + 12); // VirtualAddress
  buffer.writeUInt32LE(0x400, sectionAt + 16);  // SizeOfRawData
  buffer.writeUInt32LE(0x400, sectionAt + 20);  // PointerToRawData

  // Resource bytes live at file 0x400, addressed as RVA 0x2000. Child offsets are relative to it.
  const base = 0x400;
  const dir = (at, named, ids) => {
    buffer.writeUInt16LE(named.length, at + 12);
    buffer.writeUInt16LE(ids.length, at + 14);
    [...named, ...ids].forEach((entry, i) => {
      // JS bitwise OR yields a signed 32-bit value, which writeUInt32LE refuses; the high bit
      // that marks a name string or a subdirectory needs the unsigned coercion.
      buffer.writeUInt32LE(entry.name >>> 0, at + 16 + i * 8);
      buffer.writeUInt32LE(entry.data >>> 0, at + 20 + i * 8);
    });
  };
  // Level 1: MANIFEST (24) and VERSION (16).
  dir(base, [], [{ name: 24, data: 0x80 | 0x80000000 }, { name: 16, data: 0xc0 | 0x80000000 }]);
  dir(base + 0x80, [], [{ name: 1, data: 0x100 | 0x80000000 }]);      // MANIFEST name id 1
  dir(base + 0x100, [], [{ name: 1033, data: 0x180 }]);               // language 1033 -> leaf
  dir(base + 0xc0, [{ name: 0x200 | 0x80000000, data: 0x140 | 0x80000000 }], []); // VERSION, named
  dir(base + 0x140, [], [{ name: 1033, data: 0x1a0 }]);
  // Leaves: IMAGE_RESOURCE_DATA_ENTRY is RVA, size, code page, reserved.
  buffer.writeUInt32LE(0x2200, base + 0x180);
  buffer.writeUInt32LE(42, base + 0x184);
  buffer.writeUInt32LE(65001, base + 0x188);
  buffer.writeUInt32LE(0x2300, base + 0x1a0);
  buffer.writeUInt32LE(100, base + 0x1a4);
  // A named entry points at a UTF-16LE counted string.
  buffer.writeUInt16LE(7, base + 0x200);
  buffer.write('MYENTRY', base + 0x202, 'utf16le');

  writeFixture(temp, 'res.exe', buffer);
  const read = peResourcesTool.execute({ path: 'res.exe' }, context);
  assert.equal(read.supported, true);
  assert.equal(read.pe32Plus, true);
  assert.deepEqual(read.directory, { rva: 0x2000, bytes: 0x400 });
  assert.equal(read.entryCount, 2);
  assert.deepEqual(read.byType, { MANIFEST: 1, VERSION: 1 });

  const manifest = read.resources.find((r) => r.id === 24);
  assert.equal(manifest.typeName, 'MANIFEST');
  const leaf = manifest.children[0].children[0];
  assert.equal(leaf.id, 1033);
  // The leaf's own RVA must map back through the section table to a real file offset.
  assert.deepEqual(leaf.data, { rva: 0x2200, bytes: 42, codePage: 65001, fileOffset: 0x600 });

  // The named entry proves the UTF-16LE counted string is decoded rather than skipped.
  const version = read.resources.find((r) => r.id === 16);
  assert.equal(version.typeName, 'VERSION');
  assert.equal(version.children[0].named, true);
  assert.equal(version.children[0].name, 'MYENTRY');

  // A PE with no resource directory is reported as such, not as a failure.
  const bare = minimalPe();
  writeFixture(temp, 'bare.exe', bare);
  const bareRead = peResourcesTool.execute({ path: 'bare.exe' }, context);
  assert.equal(bareRead.supported, true);
  assert.deepEqual(bareRead.resources, []);
  assert.ok(bareRead.limitations.length > 0);

  writeFixture(temp, 'notpe.bin', Buffer.from('MZ and nothing more'));
  assert.equal(peResourcesTool.execute({ path: 'notpe.bin' }, context).reason, 'not_pe');
  assert.deepEqual(peResourcesTool.execute({ path: 'res.exe' }, context), read);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('Go build information is read inline, and the pointer layout is reported unresolved', () => {
  const temp = tempWorkspace();
  const context = { workspaceRoot: temp, policy };
  const magic = Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]);
  const leb = (n) => { const out = []; do { let b = n & 0x7f; n >>>= 7; if (n !== 0) b |= 0x80; out.push(b); } while (n !== 0); return Buffer.from(out); };
  const counted = (s) => { const b = Buffer.from(s, 'utf8'); return Buffer.concat([leb(b.length), b]); };
  const modInfo = 'path\texample.com/app\nmod\texample.com/app\t(devel)\t\nbuild\t-ldflags=-s -w\nbuild\tGOOS=windows\ndep\tgithub.com/x/y\tv1.2.3\th1:abc\n';
  // Flag bit 1 selects the inline layout; the blob's strings begin 32 bytes in.
  const blob = Buffer.concat([magic, Buffer.from([8, 0x02]), Buffer.alloc(16), counted('go1.24.2'), counted(modInfo)]);
  writeFixture(temp, 'app.bin', Buffer.concat([Buffer.alloc(64, 0x90), blob, Buffer.alloc(32, 0)]));

  const go = goBuildInfoTool.execute({ path: 'app.bin' }, context);
  assert.equal(go.supported, true);
  assert.equal(go.layout, 'inline');
  assert.equal(go.pointerSize, 8);
  assert.equal(go.endianness, 'little');
  assert.equal(go.offset, 64);
  assert.equal(go.version, 'go1.24.2');
  const settings = Object.fromEntries(go.settings.map((s) => [s.key, s.value]));
  assert.equal(settings.GOOS, 'windows');
  assert.equal(settings['-ldflags'], '-s -w');
  assert.equal(settings.dep, 'github.com/x/y v1.2.3');
  assert.deepEqual(go.limitations, []);

  // The pointer layout stores its strings in the data section: reported as present, not guessed.
  writeFixture(temp, 'old.bin', Buffer.concat([magic, Buffer.from([4, 0x00]), Buffer.alloc(16)]));
  const old = goBuildInfoTool.execute({ path: 'old.bin' }, context);
  assert.equal(old.supported, true);
  assert.equal(old.layout, 'pointer');
  assert.equal(old.pointerSize, 4);
  assert.equal(old.version, null);
  assert.ok(old.limitations.some((l) => /not dereferenced/.test(l)));

  writeFixture(temp, 'plain.bin', Buffer.from('no build info in here'));
  const plain = goBuildInfoTool.execute({ path: 'plain.bin' }, context);
  assert.equal(plain.supported, false);
  assert.equal(plain.reason, 'no_build_info');
  assert.deepEqual(goBuildInfoTool.execute({ path: 'app.bin' }, context), go);
  fs.rmSync(temp, { recursive: true, force: true });
});
