import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeDexTools } from '../src/dex.mjs';
import { realTempDir } from './temp-workspace.mjs';

const tools = new Map(makeDexTools().map((t) => [t.name, t]));
const policy = { maxOutputBytes: 4 * 1024 * 1024 };

function workspace(t) {
  const dir = realTempDir('concord-dex-');
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });
  return { dir, context: { workspaceRoot: dir, policy } };
}
const write = (dir, name, bytes) => { fs.writeFileSync(path.join(dir, name), bytes); return name; };
const uleb = (n) => { const out = []; do { let b = n & 0x7f; n >>>= 7; if (n !== 0) b |= 0x80; out.push(b); } while (n !== 0); return Buffer.from(out); };

/**
 * A DEX file assembled byte by byte. Every value the assertions check is written here at a known
 * offset, so an index, delta or offset error in the reader cannot pass. The class declares one
 * private instance field, a constructor and one virtual method taking an int and returning String.
 */
function buildDex() {
  const strings = ['Foo.java', 'I', 'Lcom/example/Foo;', 'Lcom/example/Iface;',
    'Ljava/lang/Object;', 'Ljava/lang/String;', 'V', 'count', 'doThing', '<init>'];
  const typeToString = [2, 3, 4, 5, 1, 6]; // Foo, Iface, Object, String, I, V
  const stringIdsOff = 112;
  const typeIdsOff = stringIdsOff + strings.length * 4;
  const protoIdsOff = typeIdsOff + typeToString.length * 4;
  const fieldIdsOff = protoIdsOff + 2 * 12;
  const methodIdsOff = fieldIdsOff + 8;
  const classDefsOff = methodIdsOff + 2 * 8;
  const dataOff = classDefsOff + 32;

  const parts = [];
  let cursor = dataOff;
  const stringOffsets = [];
  for (const text of strings) {
    stringOffsets.push(cursor);
    const blob = Buffer.concat([uleb(text.length), Buffer.from(text, 'utf8'), Buffer.from([0])]);
    parts.push(blob);
    cursor += blob.length;
  }
  const pad = (4 - (cursor % 4)) % 4;
  if (pad) { parts.push(Buffer.alloc(pad)); cursor += pad; }

  const typeList = (typeIndex) => { const list = Buffer.alloc(8); list.writeUInt32LE(1, 0); list.writeUInt16LE(typeIndex, 4); return list; };
  const interfacesOff = cursor;
  parts.push(typeList(1)); cursor += 8;   // implements Iface
  const paramsOff = cursor;
  parts.push(typeList(4)); cursor += 8;   // one int parameter

  const classDataOff = cursor;
  const classData = Buffer.concat([
    uleb(0), uleb(1), uleb(1), uleb(1),             // static, instance, direct, virtual counts
    uleb(0), uleb(0x0002),                           // instance field 0, private
    uleb(0), uleb(0x0001 | 0x10000), uleb(0),        // direct method 0, public + constructor
    uleb(1), uleb(0x0001), uleb(0),                  // virtual method index 0+1, public
  ]);
  parts.push(classData);
  cursor += classData.length;

  const total = cursor;
  const buffer = Buffer.alloc(total);
  Buffer.from('dex\n035\0', 'latin1').copy(buffer, 0);
  buffer.writeUInt32LE(total, 32);
  buffer.writeUInt32LE(112, 36);
  buffer.writeUInt32LE(0x12345678, 40);
  buffer.writeUInt32LE(strings.length, 56); buffer.writeUInt32LE(stringIdsOff, 60);
  buffer.writeUInt32LE(typeToString.length, 64); buffer.writeUInt32LE(typeIdsOff, 68);
  buffer.writeUInt32LE(2, 72); buffer.writeUInt32LE(protoIdsOff, 76);
  buffer.writeUInt32LE(1, 80); buffer.writeUInt32LE(fieldIdsOff, 84);
  buffer.writeUInt32LE(2, 88); buffer.writeUInt32LE(methodIdsOff, 92);
  buffer.writeUInt32LE(1, 96); buffer.writeUInt32LE(classDefsOff, 100);
  buffer.writeUInt32LE(total - dataOff, 104); buffer.writeUInt32LE(dataOff, 108);

  stringOffsets.forEach((off, i) => buffer.writeUInt32LE(off, stringIdsOff + i * 4));
  typeToString.forEach((s, i) => buffer.writeUInt32LE(s, typeIdsOff + i * 4));
  buffer.writeUInt32LE(6, protoIdsOff); buffer.writeUInt32LE(5, protoIdsOff + 4);     // ()V
  buffer.writeUInt32LE(5, protoIdsOff + 12); buffer.writeUInt32LE(3, protoIdsOff + 16);
  buffer.writeUInt32LE(paramsOff, protoIdsOff + 20);                                   // (I)String
  buffer.writeUInt16LE(0, fieldIdsOff); buffer.writeUInt16LE(4, fieldIdsOff + 2);
  buffer.writeUInt32LE(7, fieldIdsOff + 4);                                            // Foo.count : I
  buffer.writeUInt16LE(0, methodIdsOff); buffer.writeUInt16LE(0, methodIdsOff + 2);
  buffer.writeUInt32LE(9, methodIdsOff + 4);                                           // Foo.<init>
  buffer.writeUInt16LE(0, methodIdsOff + 8); buffer.writeUInt16LE(1, methodIdsOff + 10);
  buffer.writeUInt32LE(8, methodIdsOff + 12);                                          // Foo.doThing
  buffer.writeUInt32LE(0, classDefsOff);
  buffer.writeUInt32LE(0x0001, classDefsOff + 4);
  buffer.writeUInt32LE(2, classDefsOff + 8);
  buffer.writeUInt32LE(interfacesOff, classDefsOff + 12);
  buffer.writeUInt32LE(0, classDefsOff + 16);
  buffer.writeUInt32LE(classDataOff, classDefsOff + 24);
  Buffer.concat(parts).copy(buffer, dataOff);
  return buffer;
}

test('DEX index tables decode to exactly the entries written into them', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'classes.dex', buildDex());
  const dex = tools.get('artifact.dex').execute({ path: 'classes.dex' }, context);
  assert.equal(dex.supported, true);
  assert.equal(dex.version, 35);
  assert.deepEqual(dex.counts, { strings: 10, types: 6, protos: 2, fields: 1, methods: 2, classes: 1 });
  assert.deepEqual(dex.limitations, []);
  assert.deepEqual(dex.classes, [{
    index: 0, descriptor: 'Lcom/example/Foo;', readable: 'com.example.Foo', access: ['public'],
    superclass: 'Ljava/lang/Object;', interfaces: ['Lcom/example/Iface;'], sourceFile: 'Foo.java',
  }]);
  assert.deepEqual(tools.get('artifact.dex').execute({ path: 'classes.dex' }, context), dex);
});

test('class members come from delta-encoded indices, with access flags and prototypes resolved', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'classes.dex', buildDex());
  const read = tools.get('artifact.dexClass').execute({ path: 'classes.dex', descriptor: 'Lcom/example/Foo;' }, context);
  assert.equal(read.supported, true);
  const declared = read.class;
  assert.equal(declared.readable, 'com.example.Foo');
  assert.deepEqual(declared.staticFields, []);
  assert.deepEqual(declared.instanceFields, [{
    index: 0, name: 'count', type: 'I', declaringClass: 'Lcom/example/Foo;', access: ['private'],
  }]);
  // The constructor carries both flags, which is what the two-bit access value encodes.
  assert.deepEqual(declared.directMethods[0].access, ['public', 'constructor']);
  assert.equal(declared.directMethods[0].name, '<init>');
  assert.equal(declared.directMethods[0].returnType, 'V');
  assert.deepEqual(declared.directMethods[0].parameters, []);
  // The virtual method's index is 0 + a delta of 1, so a reader ignoring the delta would
  // report the constructor's prototype here instead.
  assert.equal(declared.virtualMethods[0].index, 1);
  assert.equal(declared.virtualMethods[0].name, 'doThing');
  assert.equal(declared.virtualMethods[0].returnType, 'Ljava/lang/String;');
  assert.deepEqual(declared.virtualMethods[0].parameters, ['I']);
  assert.equal(declared.virtualMethods[0].hasCode, false);

  const methods = tools.get('artifact.dexMethod').execute({ path: 'classes.dex', descriptor: 'Lcom/example/Foo;', name: 'doThing' }, context);
  assert.equal(methods.methods.length, 1);
  assert.equal(methods.methods[0].kind, 'virtual');
  const all = tools.get('artifact.dexMethod').execute({ path: 'classes.dex', descriptor: 'Lcom/example/Foo;' }, context);
  assert.deepEqual(all.methods.map((m) => m.name).sort(), ['<init>', 'doThing']);
});

test('DEX search, references and the type graph report only what the file declares', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'classes.dex', buildDex());
  const search = tools.get('artifact.dexSearch').execute({ path: 'classes.dex', query: 'EXAMPLE' }, context);
  assert.equal(search.totalMatches, 1);
  assert.equal(search.matches[0].readable, 'com.example.Foo');
  assert.equal(tools.get('artifact.dexSearch').execute({ path: 'classes.dex', query: 'absent' }, context).totalMatches, 0);

  const refs = tools.get('artifact.dexReferences').execute({ path: 'classes.dex', type: 'Lcom/example/Foo;' }, context);
  assert.equal(refs.totalMethods, 2);
  assert.equal(refs.totalFields, 1);
  // A reference is a declared relationship, not a call site, and the output says so.
  assert.ok(refs.limitations.some((l) => /call sites inside bytecode are not decoded/.test(l)));
  // String is referenced only as a return type, which the prototype scan must still find.
  const byType = tools.get('artifact.dexReferences').execute({ path: 'classes.dex', type: 'Ljava/lang/String;' }, context);
  assert.equal(byType.totalMethods, 1);
  assert.equal(byType.methods[0].name, 'doThing');

  const graph = tools.get('artifact.dexGraph').execute({ path: 'classes.dex' }, context);
  assert.deepEqual(graph.edges, [
    { from: 'Lcom/example/Foo;', to: 'Ljava/lang/Object;', kind: 'extends', resolved: false },
    { from: 'Lcom/example/Foo;', to: 'Lcom/example/Iface;', kind: 'implements', resolved: false },
  ]);
  // Object and Iface are framework or other-DEX types: unresolved is not the same as missing.
  assert.equal(graph.unresolvedEdges, 2);
  assert.ok(graph.limitations.some((l) => /rather than gaps/.test(l)));
  assert.deepEqual(graph.roots, ['Lcom/example/Foo;']);
  assert.equal(tools.get('artifact.dexGraph').execute({ path: 'classes.dex', prefix: 'Lzz/' }, context).edges.length, 0);
});

test('DEX reading refuses a non-DEX file, a reverse-endian file and an absent class by name', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'plain.bin', Buffer.from('not a dex file at all'));
  const plain = tools.get('artifact.dex').execute({ path: 'plain.bin' }, context);
  assert.equal(plain.supported, false);
  assert.equal(plain.reason, 'not_dex');
  assert.deepEqual(plain.classes, []);

  const swapped = buildDex();
  swapped.writeUInt32LE(0x78563412, 40);
  write(dir, 'swapped.dex', swapped);
  assert.equal(tools.get('artifact.dex').execute({ path: 'swapped.dex' }, context).reason, 'byte_order_unsupported');

  const truncated = buildDex();
  truncated.writeUInt32LE(truncated.length + 1000, 32);
  write(dir, 'short.dex', truncated);
  const short = tools.get('artifact.dex').execute({ path: 'short.dex' }, context);
  assert.equal(short.supported, true);
  assert.ok(short.limitations.some((l) => /truncated or padded/.test(l)));

  write(dir, 'classes.dex', buildDex());
  assert.equal(tools.get('artifact.dexClass').execute({ path: 'classes.dex', descriptor: 'Lnope/Absent;' }, context).reason, 'class_absent');
});

/** Binary XML carrying one manifest element with a string and a boolean attribute. */
function buildAxml() {
  const strings = ['manifest', 'package', 'com.example.app', 'application', 'debuggable', 'android'];
  const poolOffsets = [];
  const poolParts = [];
  let poolCursor = 0;
  for (const text of strings) {
    poolOffsets.push(poolCursor);
    const body = Buffer.alloc(2 + text.length * 2 + 2);
    body.writeUInt16LE(text.length, 0);
    body.write(text, 2, 'utf16le');
    poolParts.push(body);
    poolCursor += body.length;
  }
  const stringsStart = 28 + strings.length * 4;
  const poolBody = Buffer.concat(poolParts);
  const poolSize = stringsStart + poolBody.length;
  const pool = Buffer.alloc(poolSize);
  pool.writeUInt16LE(0x0001, 0);
  pool.writeUInt16LE(28, 2);
  pool.writeUInt32LE(poolSize, 4);
  pool.writeUInt32LE(strings.length, 8);
  pool.writeUInt32LE(0, 12);
  pool.writeUInt32LE(0, 16);          // flags: UTF-16LE
  pool.writeUInt32LE(stringsStart, 20);
  poolOffsets.forEach((off, i) => pool.writeUInt32LE(off, 28 + i * 4));
  poolBody.copy(pool, stringsStart);

  // A start tag: 16-byte node header, attrExt, then 20-byte attributes.
  const startTag = (nameIndex, attributes) => {
    const size = 36 + attributes.length * 20;
    const chunk = Buffer.alloc(size);
    chunk.writeUInt16LE(0x0102, 0);
    chunk.writeUInt16LE(16, 2);
    chunk.writeUInt32LE(size, 4);
    chunk.writeUInt32LE(1, 8);
    chunk.writeUInt32LE(0xffffffff, 12);
    chunk.writeUInt32LE(0xffffffff, 16); // namespace
    chunk.writeUInt32LE(nameIndex, 20);
    chunk.writeUInt16LE(20, 24);         // attributeStart, measured from attrExt
    chunk.writeUInt16LE(20, 26);
    chunk.writeUInt16LE(attributes.length, 28);
    attributes.forEach((attribute, i) => {
      const at = 36 + i * 20;
      chunk.writeUInt32LE(0xffffffff, at);
      chunk.writeUInt32LE(attribute.name, at + 4);
      chunk.writeUInt32LE(attribute.type === 0x03 ? attribute.data : 0xffffffff, at + 8);
      chunk.writeUInt16LE(8, at + 12);
      chunk.writeUInt8(attribute.type, at + 15);
      chunk.writeUInt32LE(attribute.data, at + 16);
    });
    return chunk;
  };
  const endTag = (nameIndex) => {
    const chunk = Buffer.alloc(24);
    chunk.writeUInt16LE(0x0103, 0);
    chunk.writeUInt16LE(16, 2);
    chunk.writeUInt32LE(24, 4);
    chunk.writeUInt32LE(0xffffffff, 16);
    chunk.writeUInt32LE(nameIndex, 20);
    return chunk;
  };
  const body = Buffer.concat([
    pool,
    startTag(0, [{ name: 1, type: 0x03, data: 2 }]),  // <manifest package="com.example.app">
    startTag(3, [{ name: 4, type: 0x12, data: 1 }]),  //   <application debuggable="true">
    endTag(3), endTag(0),
  ]);
  const file = Buffer.alloc(8 + body.length);
  file.writeUInt16LE(0x0003, 0);
  file.writeUInt16LE(8, 2);
  file.writeUInt32LE(file.length, 4);
  body.copy(file, 8);
  return file;
}

test('binary XML decodes its string pool, nesting and typed attributes', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'AndroidManifest.xml', buildAxml());
  const read = tools.get('artifact.androidManifest').execute({ path: 'AndroidManifest.xml' }, context);
  assert.equal(read.supported, true);
  assert.equal(read.stringCount, 6);
  assert.deepEqual(read.limitations, []);
  assert.equal(read.elements.length, 1);

  const manifest = read.elements[0];
  assert.equal(manifest.name, 'manifest');
  // A string attribute resolves through the pool; the index lives in the value word, and reading
  // the packed size/type word instead would return the wrong string or none.
  assert.deepEqual(manifest.attributes, [{ namespace: null, name: 'package', type: 'string', value: 'com.example.app' }]);
  // Nesting comes from matching start and end tags, so a mis-sized chunk would flatten the tree.
  assert.equal(manifest.children.length, 1);
  assert.equal(manifest.children[0].name, 'application');
  assert.deepEqual(manifest.children[0].attributes, [{ namespace: null, name: 'debuggable', type: 'boolean', value: true }]);

  assert.equal(read.summary.package, 'com.example.app');
  assert.equal(read.summary.debuggable, true);
  assert.deepEqual(read.summary.permissions, []);
  assert.deepEqual(read.summary.activities, []);

  write(dir, 'plain.xml', Buffer.from('<manifest package="x"/>'));
  const plain = tools.get('artifact.androidManifest').execute({ path: 'plain.xml' }, context);
  assert.equal(plain.supported, false);
  assert.equal(plain.reason, 'not_axml');
  assert.deepEqual(tools.get('artifact.androidManifest').execute({ path: 'AndroidManifest.xml' }, context), read);
});

test('APK structure is read from the central directory, including ABIs and signature entries', (t) => {
  const { dir, context } = workspace(t);
  // A ZIP built from stored entries, so the central directory is the only thing walked.
  const names = ['AndroidManifest.xml', 'classes.dex', 'classes2.dex', 'resources.arsc',
    'lib/arm64-v8a/libnative.so', 'lib/x86_64/libnative.so', 'META-INF/CERT.RSA'];
  const locals = [];
  const central = [];
  let offset = 0;
  for (const name of names) {
    const nameBytes = Buffer.from(name, 'utf8');
    const content = Buffer.from('x'.repeat(10));
    const local = Buffer.alloc(30 + nameBytes.length + content.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);
    content.copy(local, 30 + nameBytes.length);
    locals.push(local);
    const entry = Buffer.alloc(46 + nameBytes.length);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(0, 10);                      // stored
    entry.writeUInt32LE(0x12345678, 16);             // crc32
    entry.writeUInt32LE(content.length, 20);
    entry.writeUInt32LE(content.length, 24);
    entry.writeUInt16LE(nameBytes.length, 28);
    entry.writeUInt32LE(offset, 42);
    nameBytes.copy(entry, 46);
    central.push(entry);
    offset += local.length;
  }
  const localBytes = Buffer.concat(locals);
  const centralBytes = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(names.length, 8);
  eocd.writeUInt16LE(names.length, 10);
  eocd.writeUInt32LE(centralBytes.length, 12);
  eocd.writeUInt32LE(localBytes.length, 16);
  write(dir, 'app.apk', Buffer.concat([localBytes, centralBytes, eocd]));

  const apk = tools.get('artifact.apk').execute({ path: 'app.apk' }, context);
  assert.equal(apk.supported, true);
  assert.equal(apk.entries.length, names.length);
  assert.deepEqual(apk.summary.dexFiles, ['classes.dex', 'classes2.dex']);
  assert.equal(apk.summary.hasManifest, true);
  assert.equal(apk.summary.hasResources, true);
  assert.deepEqual(apk.summary.nativeAbis, ['arm64-v8a', 'x86_64']);
  assert.equal(apk.summary.nativeLibraryCount, 2);
  assert.deepEqual(apk.summary.signatureSchemes, ['META-INF/CERT.RSA']);
  assert.deepEqual(apk.limitations, []);
  assert.equal(apk.entries[0].crc32, 0x12345678);

  write(dir, 'notzip.bin', Buffer.from('definitely not an archive'));
  const notZip = tools.get('artifact.apk').execute({ path: 'notzip.bin' }, context);
  assert.equal(notZip.supported, false);
  assert.equal(notZip.reason, 'not_a_zip');
  assert.deepEqual(tools.get('artifact.apk').execute({ path: 'app.apk' }, context), apk);
});
