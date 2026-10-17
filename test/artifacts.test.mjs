import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { makeArtifactTools } from '../src/artifacts.mjs';
import { HarnessError } from '../src/value.mjs';

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

test('a symlinked artifact is rejected, matching files.read\'s discipline', (t) => {
  const temp = tempWorkspace();
  const real = writeFixture(temp, 'real.bin', Buffer.from('x'));
  try { fs.symlinkSync(path.join(temp, real), path.join(temp, 'link.bin')); }
  catch (e) { if (e.code === 'EPERM') return t.skip('Host disallows link creation'); throw e; }
  assert.throws(() => inspect.execute({ path: 'link.bin' }, { workspaceRoot: temp, policy }), (e) => e instanceof HarnessError && e.code === 'PATH_DENIED');
});
