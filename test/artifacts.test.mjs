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
  assert.deepEqual(result.elf, { class: '32-bit', dataEncoding: 'little-endian', type: 2, machine: 3, entryPoint: 0x8048000, sectionCount: 11 });
});

test('extracts correct ELF64 header fields, including a 64-bit entry point', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'a64.elf', minimalElf(true)) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.elf, { class: '64-bit', dataEncoding: 'little-endian', type: 2, machine: 0x3e, entryPoint: 0x400000, sectionCount: 11 });
});

test('extracts correct PE header fields', () => {
  const temp = tempWorkspace();
  const result = inspect.execute({ path: writeFixture(temp, 'a.exe', minimalPe()) }, { workspaceRoot: temp, policy });
  assert.deepEqual(result.pe, { machine: 0x8664, sectionCount: 7, timestamp: 1700000000, entryPoint: 0x1000 });
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

test('a symlinked artifact is rejected, matching files.read\'s discipline', (t) => {
  const temp = tempWorkspace();
  const real = writeFixture(temp, 'real.bin', Buffer.from('x'));
  try { fs.symlinkSync(path.join(temp, real), path.join(temp, 'link.bin')); }
  catch (e) { if (e.code === 'EPERM') return t.skip('Host disallows link creation'); throw e; }
  assert.throws(() => inspect.execute({ path: 'link.bin' }, { workspaceRoot: temp, policy }), (e) => e instanceof HarnessError && e.code === 'PATH_DENIED');
});
