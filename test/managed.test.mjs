import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeManagedTools } from '../src/managed.mjs';
import { realTempDir } from './temp-workspace.mjs';

const tools = new Map(makeManagedTools().map((t) => [t.name, t]));
const policy = { maxOutputBytes: 4 * 1024 * 1024 };

function workspace(t) {
  const dir = realTempDir('concord-managed-');
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });
  return { dir, context: { workspaceRoot: dir, policy } };
}
const write = (dir, name, bytes) => { fs.writeFileSync(path.join(dir, name), bytes); return name; };

/**
 * A managed PE assembled byte by byte: PE headers, one section, a CLI header, a BSJB metadata
 * root and a `#~` table stream carrying ten tables.
 *
 * Every row count is small and `HeapSizes` is zero, so every heap and table index is two bytes
 * wide. That is deliberate: it makes the expected row offsets computable here, so a width or
 * stepping error in the reader shows up as a wrong name rather than passing silently.
 *
 * The assembly declares `Fixture.MyType` with a nested `Inner`, a private field, a normal method
 * and a P/Invoke method forwarded to `kernel32.dll`.
 */
function buildAssembly() {
  const names = ['', '<Module>', 'Fixture.dll', 'MyType', 'Inner', 'count', 'Run', 'NativeCall',
    'kernel32.dll', 'CreateEventW', 'MyAssembly', 'mscorlib', 'System', 'Object', 'Fixture'];
  const stringOffsets = new Map();
  let stringCursor = 0;
  const stringParts = [];
  for (const name of names) {
    stringOffsets.set(name, stringCursor);
    const blob = Buffer.concat([Buffer.from(name, 'utf8'), Buffer.from([0])]);
    stringParts.push(blob);
    stringCursor += blob.length;
  }
  const stringsHeap = Buffer.concat(stringParts);
  const str = (name) => stringOffsets.get(name);

  // Present tables, each with a small row count so every index stays two bytes wide.
  const rowCounts = [[0x00, 1], [0x01, 1], [0x02, 3], [0x04, 1], [0x06, 2],
    [0x1a, 1], [0x1c, 1], [0x20, 1], [0x23, 1], [0x29, 1]];
  let valid = 0n;
  for (const [table] of rowCounts) valid |= 1n << BigInt(table);

  const rows = [];
  const u16v = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v, 0); return b; };
  const u32v = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v, 0); return b; };
  // Coded index: value is (rowIndex << tagBits) | tag.
  const coded = (rowIndex, tag, bits) => u16v((rowIndex << bits) | tag);

  // Module: generation, name, three GUID indices.
  rows.push(Buffer.concat([u16v(0), u16v(str('Fixture.dll')), u16v(0), u16v(0), u16v(0)]));
  // TypeRef: ResolutionScope -> AssemblyRef row 1 (tag 2 of [Module, ModuleRef, AssemblyRef, TypeRef]).
  rows.push(Buffer.concat([coded(1, 2, 2), u16v(str('Object')), u16v(str('System'))]));
  // TypeDef 1: <Module>, no members.
  rows.push(Buffer.concat([u32v(0), u16v(str('<Module>')), u16v(str('')), u16v(0), u16v(1), u16v(1)]));
  // TypeDef 2: Fixture.MyType, public + sealed, extends TypeRef row 1 (tag 1 of TypeDefOrRef).
  rows.push(Buffer.concat([u32v(0x101), u16v(str('MyType')), u16v(str('Fixture')), coded(1, 1, 2), u16v(1), u16v(1)]));
  // TypeDef 3: Inner, nested-public, no namespace, its member ranges start past MyType's.
  rows.push(Buffer.concat([u32v(0x02), u16v(str('Inner')), u16v(str('')), u16v(0), u16v(2), u16v(3)]));
  // Field 1: private count.
  rows.push(Buffer.concat([u16v(0x01), u16v(str('count')), u16v(0)]));
  // MethodDef 1: public Run with a body.
  rows.push(Buffer.concat([u32v(0x2500), u16v(0), u16v(0x06), u16v(str('Run')), u16v(0), u16v(1)]));
  // MethodDef 2: public NativeCall, pinvoke-impl, no body.
  rows.push(Buffer.concat([u32v(0), u16v(0), u16v(0x2006), u16v(str('NativeCall')), u16v(0), u16v(1)]));
  // ModuleRef 1: kernel32.dll.
  rows.push(u16v(str('kernel32.dll')));
  // ImplMap 1: unicode charset, forwards MethodDef row 2 (tag 1 of [Field, MethodDef]).
  rows.push(Buffer.concat([u16v(0x04), coded(2, 1, 1), u16v(str('CreateEventW')), u16v(1)]));
  // Assembly 1: version 1.2.3.4.
  rows.push(Buffer.concat([u32v(0x8004), u16v(1), u16v(2), u16v(3), u16v(4), u32v(0), u16v(0), u16v(str('MyAssembly')), u16v(str(''))]));
  // AssemblyRef 1: mscorlib 4.0.0.0.
  rows.push(Buffer.concat([u16v(4), u16v(0), u16v(0), u16v(0), u32v(0), u16v(0), u16v(str('mscorlib')), u16v(str('')), u16v(0)]));
  // NestedClass 1: TypeDef 3 (Inner) is enclosed by TypeDef 2 (MyType).
  rows.push(Buffer.concat([u16v(3), u16v(2)]));

  const tableHeader = Buffer.concat([
    u32v(0), Buffer.from([2, 0, 0, 1]),           // reserved, major, minor, HeapSizes = 0, reserved
    (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(valid, 0); return b; })(),
    Buffer.alloc(8),                               // sorted mask
    ...rowCounts.map(([, count]) => u32v(count)),
  ]);
  const tablesStream = Buffer.concat([tableHeader, ...rows]);

  // Metadata root. The version string is padded to a four-byte boundary.
  const versionText = Buffer.from('v4.0.30319\0\0', 'latin1');
  const streamsAt = 16 + versionText.length + 4;
  const tablesOffset = streamsAt + 12 + 20;
  const root = Buffer.concat([
    u32v(0x424a5342), u16v(1), u16v(1), u32v(0), u32v(versionText.length), versionText,
    u16v(0), u16v(2),
    u32v(tablesOffset), u32v(tablesStream.length), Buffer.from('#~\0\0', 'latin1'),
    u32v(tablesOffset + tablesStream.length), u32v(stringsHeap.length), Buffer.from('#Strings\0\0\0\0', 'latin1'),
    tablesStream, stringsHeap,
  ]);

  const sectionRva = 0x2000;
  const cliRva = sectionRva;
  const metadataRva = sectionRva + 0x100;
  const cli = Buffer.alloc(72);
  cli.writeUInt32LE(72, 0);
  cli.writeUInt16LE(2, 4); cli.writeUInt16LE(5, 6);
  cli.writeUInt32LE(metadataRva, 8); cli.writeUInt32LE(root.length, 12);
  cli.writeUInt32LE(0x01, 16);                     // ILONLY

  const sectionRaw = Buffer.alloc(Math.max(0x1000, 0x100 + root.length + 16));
  cli.copy(sectionRaw, 0);
  root.copy(sectionRaw, 0x100);

  const headerSize = 0x400;
  const buffer = Buffer.alloc(headerSize + sectionRaw.length);
  buffer.write('MZ', 0, 'latin1');
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.write('PE\0\0', 0x80, 'latin1');
  buffer.writeUInt16LE(0x14c, 0x84);               // i386
  buffer.writeUInt16LE(1, 0x86);                   // one section
  buffer.writeUInt16LE(224, 0x94);                 // SizeOfOptionalHeader (PE32)
  const optionalAt = 0x98;
  buffer.writeUInt16LE(0x10b, optionalAt);         // PE32
  buffer.writeUInt32LE(16, optionalAt + 92);       // NumberOfRvaAndSizes
  const directoriesAt = optionalAt + 96;
  buffer.writeUInt32LE(cliRva, directoriesAt + 14 * 8);
  buffer.writeUInt32LE(72, directoriesAt + 14 * 8 + 4);
  const sectionAt = optionalAt + 224;
  buffer.write('.text\0\0\0', sectionAt, 'latin1');
  buffer.writeUInt32LE(sectionRaw.length, sectionAt + 8);
  buffer.writeUInt32LE(sectionRva, sectionAt + 12);
  buffer.writeUInt32LE(sectionRaw.length, sectionAt + 16);
  buffer.writeUInt32LE(headerSize, sectionAt + 20);
  sectionRaw.copy(buffer, headerSize);
  return buffer;
}

test('managed metadata yields the CLI header, assembly identity and present tables', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'asm.dll', buildAssembly());
  const read = tools.get('artifact.managed').execute({ path: 'asm.dll' }, context);
  assert.equal(read.supported, true);
  assert.equal(read.reason, null);
  assert.equal(read.cli.ilOnly, true);
  assert.equal(read.cli.runtimeVersion, '2.5');
  assert.equal(read.metadataVersion, 'v4.0.30319');
  assert.deepEqual(read.streams, ['#~', '#Strings']);
  assert.deepEqual(read.heapSizes, { stringWide: false, guidWide: false, blobWide: false });
  assert.equal(read.module, 'Fixture.dll');
  assert.deepEqual(read.assembly, { name: 'MyAssembly', version: '1.2.3.4', culture: null, hashAlgorithm: 0x8004 });
  assert.deepEqual(read.assemblyReferences, [{ name: 'mscorlib', version: '4.0.0.0', culture: null }]);
  // Row counts come from the header's Valid bitmask, so a mis-stepped table shows up here first.
  const byName = Object.fromEntries(read.tables.map((entry) => [entry.name ?? entry.table, entry.rows]));
  assert.deepEqual(byName, { Module: 1, TypeRef: 1, TypeDef: 3, Field: 1, MethodDef: 2,
    ModuleRef: 1, ImplMap: 1, Assembly: 1, AssemblyRef: 1, NestedClass: 1 });
  assert.deepEqual(read.limitations, []);
  assert.deepEqual(tools.get('artifact.managed').execute({ path: 'asm.dll' }, context), read);
});

test('types resolve their namespace, their nesting and their base type', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'asm.dll', buildAssembly());
  const read = tools.get('artifact.managedMembers').execute({ path: 'asm.dll' }, context);
  assert.equal(read.supported, true);
  assert.deepEqual(read.types.map((entry) => entry.fullName), ['<Module>', 'Fixture.MyType', 'Fixture.MyType.Inner']);

  const myType = read.types.find((entry) => entry.fullName === 'Fixture.MyType');
  assert.deepEqual(myType.attributes, ['public', 'sealed']);
  // The base type is a TypeRef, so resolving it requires following the coded index into TypeRef
  // and reading its namespace and name from the string heap.
  assert.equal(myType.extends, 'System.Object');
  assert.equal(myType.nested, false);

  // A nested type carries an empty namespace; its name comes from the NestedClass table, so
  // without that join it would be reported as a top-level `Inner`.
  const inner = read.types.find((entry) => entry.nested);
  assert.equal(inner.fullName, 'Fixture.MyType.Inner');
  assert.equal(inner.enclosing, 'Fixture.MyType');
  assert.deepEqual(inner.attributes, ['nested-public']);

  // Member ranges run to the next type's start, so a type with no members must report none.
  const mine = read.members.filter((member) => member.declaringType === 'Fixture.MyType');
  assert.deepEqual(mine.map((member) => member.name).sort(), ['NativeCall', 'Run', 'count']);
  assert.deepEqual(read.members.filter((member) => member.declaringType === '<Module>'), []);
  assert.deepEqual(read.members.filter((member) => member.declaringType === 'Fixture.MyType.Inner'), []);

  const field = mine.find((member) => member.name === 'count');
  assert.equal(field.kind, 'field');
  assert.deepEqual(field.attributes, ['private']);
  const run = mine.find((member) => member.name === 'Run');
  assert.equal(run.hasBody, true);
  assert.deepEqual(run.attributes, ['public']);
  const native = mine.find((member) => member.name === 'NativeCall');
  assert.equal(native.hasBody, false);
  assert.deepEqual(native.attributes, ['public', 'pinvoke-impl']);
  assert.ok(read.limitations.some((l) => /overloads share a name/.test(l)));

  const absent = tools.get('artifact.managedMembers').execute({ path: 'asm.dll', type: 'Nope.Missing' }, context);
  assert.equal(absent.reason, 'type_absent');
  assert.deepEqual(absent.members, []);
});

test('P/Invoke boundaries resolve their module, forwarded member and character set', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'asm.dll', buildAssembly());
  const read = tools.get('artifact.managedNativeBoundaries').execute({ path: 'asm.dll' }, context);
  assert.equal(read.supported, true);
  assert.deepEqual(read.modules, ['kernel32.dll']);
  assert.equal(read.boundaries.length, 1);
  // The forwarded member arrives as a MemberForwarded coded index, and the declaring type is
  // recovered by finding which type's method range contains that row.
  assert.deepEqual(read.boundaries[0], {
    importName: 'CreateEventW', module: 'kernel32.dll', moduleResolved: true,
    managedMember: 'NativeCall', declaringType: 'Fixture.MyType', forwardedKind: 'method',
    charSet: 'unicode', exactSpelling: false,
  });
  assert.ok(read.limitations.some((l) => /function pointer or a runtime import/.test(l)));

  const verify = tools.get('artifact.verifyManagedNativeBoundaries');
  const satisfied = verify.execute({ boundaries: read.boundaries, available: ['KERNEL32'] });
  // Matching ignores case and a platform extension, so kernel32.dll and KERNEL32 are one name.
  assert.equal(satisfied.summary.satisfied, 1);
  assert.equal(satisfied.findings[0].state, 'satisfied');
  const missing = verify.execute({ boundaries: read.boundaries, available: ['user32'] });
  assert.equal(missing.summary.missing, 1);
  // With no list supplied, presence is unknown rather than assumed either way.
  const unknown = verify.execute({ boundaries: read.boundaries });
  assert.equal(unknown.summary.unknown, 1);
  assert.match(unknown.findings[0].reason, /No available module list/);
  const unresolved = verify.execute({ boundaries: [{ importName: 'X', module: 'x.dll', moduleResolved: false }] });
  assert.equal(unresolved.summary.unresolvedScope, 1);
});

test('the type graph separates internal edges from referenced-assembly ones', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'asm.dll', buildAssembly());
  const graph = tools.get('artifact.managedGraph').execute({ path: 'asm.dll' }, context);
  assert.equal(graph.supported, true);
  assert.deepEqual(graph.edges, [
    { from: 'Fixture.MyType', to: 'System.Object', kind: 'extends', resolved: false },
  ]);
  // System.Object lives in mscorlib: external, which is not the same as a gap in the graph.
  assert.equal(graph.unresolvedEdges, 1);
  assert.ok(graph.limitations.some((l) => /external rather than gaps/.test(l)));
  assert.ok(graph.roots.includes('<Module>'));
  assert.equal(tools.get('artifact.managedGraph').execute({ path: 'asm.dll', namespace: 'Nope' }, context).edges.length, 0);
});

test('a native PE and a non-PE are refused by name rather than part-read', (t) => {
  const { dir, context } = workspace(t);
  // A PE whose CLI data directory is empty is a native binary, not a broken managed one.
  const native = buildAssembly();
  native.writeUInt32LE(0, 0x98 + 96 + 14 * 8);
  write(dir, 'native.dll', native);
  const read = tools.get('artifact.managed').execute({ path: 'native.dll' }, context);
  assert.equal(read.supported, false);
  assert.equal(read.reason, 'not_managed');
  assert.deepEqual(read.tables, []);
  assert.equal(read.assembly, null);

  write(dir, 'plain.bin', Buffer.from('not a portable executable'));
  assert.equal(tools.get('artifact.managed').execute({ path: 'plain.bin' }, context).reason, 'not_pe');

  // A CLI header that does not address a BSJB root is named as such.
  const noRoot = buildAssembly();
  noRoot.writeUInt32LE(0x424a5341, 0x400 + 0x100);
  write(dir, 'noroot.dll', noRoot);
  assert.equal(tools.get('artifact.managed').execute({ path: 'noroot.dll' }, context).reason, 'metadata_absent');
});

test('member comparison and reconstruction import never invent a correspondence', () => {
  const compare = tools.get('artifact.compareManagedMembers');
  const left = { members: [
    { declaringType: 'T', name: 'Kept', kind: 'method', attributes: ['public'] },
    { declaringType: 'T', name: 'Changed', kind: 'method', attributes: ['public'] },
    { declaringType: 'T', name: 'Gone', kind: 'field', attributes: ['private'] },
    { declaringType: 'T', name: 'Dup', kind: 'method', attributes: ['public'] },
    { declaringType: 'T', name: 'Dup', kind: 'method', attributes: ['private'] },
  ] };
  const right = { members: [
    { declaringType: 'T', name: 'Kept', kind: 'method', attributes: ['public'] },
    { declaringType: 'T', name: 'Changed', kind: 'method', attributes: ['private'] },
    { declaringType: 'T', name: 'New', kind: 'method', attributes: ['public'] },
    { declaringType: 'T', name: 'Dup', kind: 'method', attributes: ['public'] },
  ] };
  const diff = compare.execute({ left, right });
  assert.deepEqual(diff.summary, { added: 1, removed: 1, changed: 1, unchanged: 1, unknown: 1 });
  // Overloads collapse to one key because signatures are not decoded, so the duplicate is
  // reported unknown instead of being paired arbitrarily.
  const dup = diff.changes.find((change) => change.member.includes('Dup'));
  assert.equal(dup.state, 'unknown');
  assert.match(dup.reason, /occurs more than once/);

  const importer = tools.get('artifact.importManagedReconstruction');
  const imported = importer.execute({
    observed: { members: [
      { declaringType: 'T', name: 'A', kind: 'method' },
      { declaringType: 'T', name: 'B', kind: 'method' },
    ] },
    reconstruction: [
      { declaringType: 'T', name: 'A', kind: 'method', source: 'void A() {}' },
      { declaringType: 'T', name: 'A', kind: 'method', source: 'duplicate' },
      { declaringType: 'T', name: 'Invented', kind: 'method', source: 'void Invented() {}' },
    ],
  });
  // A reconstruction cannot introduce a member the artifact does not declare.
  assert.deepEqual(imported.accepted, [{ member: 'T::A(method)', hasSource: true }]);
  assert.equal(imported.rejected.length, 2);
  assert.ok(imported.rejected.some((entry) => /declares no such member/.test(entry.reason)));
  assert.ok(imported.rejected.some((entry) => /more than once/.test(entry.reason)));
  assert.deepEqual(imported.summary, { observed: 2, accepted: 1, rejected: 2, uncovered: 1, coverage: 0.5 });
});
