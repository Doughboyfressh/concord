import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makePlatformTools } from '../src/platform.mjs';
import { realTempDir } from './temp-workspace.mjs';

const tools = new Map(makePlatformTools().map((t) => [t.name, t]));
const policy = { maxOutputBytes: 8 * 1024 * 1024 };

function workspace(t) {
  const dir = realTempDir('concord-platform-');
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });
  return { dir, context: { workspaceRoot: dir, policy } };
}
const write = (dir, name, bytes) => {
  fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
  fs.writeFileSync(path.join(dir, name), bytes);
  return name;
};
/** A buffer with given byte sequences placed at given offsets, zero elsewhere. */
const placed = (size, entries) => {
  const buffer = Buffer.alloc(size);
  for (const [offset, bytes] of entries) Buffer.from(bytes).copy(buffer, offset);
  return buffer;
};
const nulJoined = (strings) => Buffer.from(strings.join('\0') + '\0', 'latin1');

test('firmware signatures are located, bounded and labelled as evidence rather than proof', (t) => {
  const { dir, context } = workspace(t);
  // Three signatures at offsets chosen here, so the expected offsets are not a guess.
  write(dir, 'image.bin', placed(0x2000, [
    [0x000, [0x27, 0x05, 0x19, 0x56]],              // U-Boot header
    [0x100, [0x68, 0x73, 0x71, 0x73]],              // SquashFS
    [0x800, [0x1f, 0x8b, 0x08]],                    // gzip
    [0x438, [0x53, 0xef]],                          // ext superblock, at its anchored offset
  ]));
  const read = tools.get('artifact.firmware').execute({ path: 'image.bin' }, context);
  assert.equal(read.supported, true);
  const byKind = Object.fromEntries(read.regions.map((region) => [region.kind, region]));
  assert.equal(byKind.uimage.offset, 0x000);
  assert.equal(byKind['squashfs-le'].offset, 0x100);
  assert.equal(byKind.gzip.offset, 0x800);
  // A two-byte magic is only trusted where the format pins it to a fixed offset.
  assert.equal(byKind['ext-superblock'].offset, 0x438);
  assert.equal(byKind['ext-superblock'].anchored, true);
  assert.equal(byKind.uimage.anchored, false);
  // A region's length is the distance to the next signature, which is an upper bound.
  assert.equal(byKind.uimage.boundedLength, 0x100);
  assert.equal(byKind.gzip.boundedLength, 0x2000 - 0x800);
  assert.ok(read.limitations.some((l) => /evidence of a format, not proof/.test(l)));
  assert.ok(read.limitations.some((l) => /upper bound/.test(l)));

  // An anchored magic placed somewhere else must not be reported.
  write(dir, 'noext.bin', placed(0x1000, [[0x200, [0x53, 0xef]]]));
  const noext = tools.get('artifact.firmware').execute({ path: 'noext.bin' }, context);
  assert.equal(noext.regions.some((region) => region.kind === 'ext-superblock'), false);

  const region = tools.get('artifact.firmwareRegion').execute({ path: 'image.bin', offset: 0x100, length: 64 }, context);
  assert.equal(region.region.offset, 0x100);
  assert.equal(region.region.length, 64);
  assert.equal(region.region.kind, 'squashfs-le');
  assert.equal(region.region.sha256.length, 64);
  assert.equal(region.preview.startsWith('68737173'), true);
  // Reading is not extracting: this tool holds a read grant and writes nothing.
  assert.ok(region.limitations.some((l) => /reads and does not extract to disk/.test(l)));
  const past = tools.get('artifact.firmwareRegion').execute({ path: 'image.bin', offset: 0x99999 }, context);
  assert.equal(past.supported, false);
  assert.equal(past.reason, 'offset_past_end');
});

test('Rust evidence is recovered from toolchain paths and symbol mangling, and labelled as such', (t) => {
  const { dir, context } = workspace(t);
  const commit = 'a'.repeat(40);
  write(dir, 'app.exe', nulJoined([
    'rustc-1.78.0-x86_64-pc-windows-msvc',
    '/rustc/' + commit + '/library/core/src/panicking.rs',
    '/home/u/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.197/src/lib.rs',
    '_ZN4core3fmt9Formatter3pad17h0123456789abcdefE',
    'some unrelated string padding the image out',
  ]));
  const read = tools.get('artifact.rustBinary').execute({ path: 'app.exe' }, context);
  assert.equal(read.supported, true);
  assert.deepEqual(read.rustcVersions, ['1.78.0']);
  assert.deepEqual(read.rustcCommits, [commit]);
  assert.deepEqual(read.cargoCrates, ['serde-1.0.197']);
  assert.equal(read.mangling.legacy, 1);
  assert.equal(read.mangling.scheme, 'legacy');
  assert.ok(read.panicPaths.some((entry) => entry.path.endsWith('panicking.rs')));
  // Every conclusion rests on a string, so a stripped binary can be Rust and show none of this.
  assert.ok(read.limitations.some((l) => /stripped binary can be Rust and show none of it/.test(l)));

  write(dir, 'v0.exe', nulJoined(['_RNvCs1234_7mycrate4main', 'rustc-1.80.0 padding here']));
  assert.equal(tools.get('artifact.rustBinary').execute({ path: 'v0.exe' }, context).mangling.scheme, 'v0');

  write(dir, 'plain.exe', nulJoined(['nothing to see here at all', 'just some ordinary strings']));
  const plain = tools.get('artifact.rustBinary').execute({ path: 'plain.exe' }, context);
  assert.equal(plain.supported, false);
  assert.equal(plain.reason, 'no_rust_evidence');
});

test('a Dart snapshot header yields its version hash, build mode and architecture', (t) => {
  const { dir, context } = workspace(t);
  const versionHash = 'b'.repeat(32);
  const snapshot = (prefixBytes, features) => Buffer.concat([
    Buffer.alloc(prefixBytes),
    Buffer.from([0xdc, 0xdc, 0xf5, 0xf5]),
    Buffer.alloc(8),
    Buffer.from(versionHash, 'latin1'),
    Buffer.from(features + '\0', 'latin1'),
  ]);
  write(dir, 'app.aot', snapshot(0, 'product no-causal_async_stacks arm64 null-safety'));
  const read = tools.get('artifact.dartSnapshot').execute({ path: 'app.aot' }, context);
  assert.equal(read.supported, true);
  assert.equal(read.offset, 0);
  assert.equal(read.embedded, false);
  assert.equal(read.byteOrder, 'little');
  assert.equal(read.versionHash, versionHash);
  assert.equal(read.buildMode, 'release');
  assert.equal(read.architecture, 'arm64');
  assert.equal(read.nullSafety, true);
  assert.deepEqual(read.limitations, []);

  // An AOT snapshot usually sits inside a host image, which is a different fact about it.
  write(dir, 'embedded.so', snapshot(512, 'debug x64 no-null-safety'));
  const embedded = tools.get('artifact.dartSnapshot').execute({ path: 'embedded.so' }, context);
  assert.equal(embedded.offset, 512);
  assert.equal(embedded.embedded, true);
  assert.equal(embedded.buildMode, 'debug');
  assert.equal(embedded.architecture, 'x64');
  assert.equal(embedded.nullSafety, false);
  assert.ok(embedded.limitations.some((l) => /embedded in a host image/.test(l)));

  write(dir, 'none.bin', Buffer.alloc(256, 0x41));
  assert.equal(tools.get('artifact.dartSnapshot').execute({ path: 'none.bin' }, context).reason, 'no_snapshot_magic');
});

test('Flutter identification combines marker strings with the snapshot header', (t) => {
  const { dir, context } = workspace(t);
  const revision = 'c'.repeat(40);
  write(dir, 'libapp.so', Buffer.concat([
    nulJoined([
      'libflutter.so loaded here',
      'flutter/engine/src/' + revision,
      'kDartVmSnapshotData',
      'Dart_SetMessageNotifyCallback',
      'Dart VM version: 3.4.1 padding',
    ]),
    Buffer.from([0xdc, 0xdc, 0xf5, 0xf5]), Buffer.alloc(8),
    Buffer.from('d'.repeat(32), 'latin1'), Buffer.from('product arm64 null-safety\0', 'latin1'),
  ]));
  const read = tools.get('artifact.flutterBuild').execute({ path: 'libapp.so' }, context);
  assert.equal(read.supported, true);
  assert.ok(read.markers.includes('engine-reference'));
  assert.ok(read.markers.includes('snapshot-symbol'));
  assert.ok(read.markers.includes('dart-api-symbol'));
  assert.deepEqual(read.engineRevisions, [revision]);
  assert.deepEqual(read.dartVersions, ['3.4.1']);
  assert.equal(read.snapshot.embedded, true);
  assert.equal(read.buildMode, 'release');
  assert.ok(read.limitations.some((l) => /stripped or renamed build can show less/.test(l)));

  write(dir, 'notflutter.so', nulJoined(['an ordinary shared object string']));
  assert.equal(tools.get('artifact.flutterBuild').execute({ path: 'notflutter.so' }, context).reason, 'no_flutter_evidence');
});

test('Electron fuses decode by wire position, and the security-relevant pair is derived', (t) => {
  const { dir, context } = workspace(t);
  const sentinel = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX';
  // Position is the only thing that identifies a fuse, so the order written here is the contract.
  const states = ['0', '1', '0', '0', '1', '1', '0', '0'];
  write(dir, 'app.exe', Buffer.concat([
    Buffer.alloc(64, 0x90),
    Buffer.from(sentinel, 'latin1'),
    Buffer.from([1, states.length]),
    Buffer.from(states.join(''), 'latin1'),
    Buffer.alloc(16),
  ]));
  const read = tools.get('artifact.electronFuses').execute({ path: 'app.exe' }, context);
  assert.equal(read.supported, true);
  assert.equal(read.offset, 64);
  assert.equal(read.wireVersion, 1);
  assert.equal(read.declaredCount, 8);
  assert.equal(read.fuses.length, 8);
  assert.equal(read.byName.runAsNode, 'disabled');
  assert.equal(read.byName.enableCookieEncryption, 'enabled');
  assert.equal(read.byName.onlyLoadAppFromAsar, 'enabled');
  assert.equal(read.byName.grantFileProtocolExtraPrivileges, 'disabled');
  assert.equal(read.runAsNodeEnabled, false);
  // Integrity is only enforced when both of the two fuses are enabled.
  assert.equal(read.asarIntegrityEnforced, true);
  assert.ok(read.fuses.every((fuse) => fuse.recognised));
  assert.ok(read.limitations.some((l) => /depends on the Electron build reading it/.test(l)));

  // A wire longer than the published list has fuses this reader cannot name.
  write(dir, 'future.exe', Buffer.concat([
    Buffer.from(sentinel, 'latin1'), Buffer.from([1, 9]), Buffer.from('011001001', 'latin1'),
  ]));
  const future = tools.get('artifact.electronFuses').execute({ path: 'future.exe' }, context);
  assert.equal(future.fuses.length, 9);
  assert.equal(future.fuses[8].recognised, false);
  assert.equal(future.fuses[8].name, null);

  // A declared length longer than the wire is reported rather than padded.
  write(dir, 'short.exe', Buffer.concat([Buffer.from(sentinel, 'latin1'), Buffer.from([1, 8]), Buffer.from('01', 'latin1')]));
  const short = tools.get('artifact.electronFuses').execute({ path: 'short.exe' }, context);
  assert.equal(short.fuses.length, 2);
  assert.ok(short.limitations.some((l) => /shorter than its declared length/.test(l)));

  write(dir, 'plain.exe', Buffer.alloc(256, 0x41));
  assert.equal(tools.get('artifact.electronFuses').execute({ path: 'plain.exe' }, context).reason, 'no_fuse_wire');
});

/** A binary plist with one dictionary of two string keys, laid out by hand. */
function buildBinaryPlist() {
  const ascii = (text) => (text.length < 15
    ? Buffer.concat([Buffer.from([0x50 | text.length]), Buffer.from(text, 'latin1')])
    : Buffer.concat([Buffer.from([0x5f, 0x10, text.length]), Buffer.from(text, 'latin1')]));
  const objects = [
    Buffer.from([0xd2, 0x01, 0x03, 0x02, 0x04]),  // dict: keys 1,3 -> values 2,4
    ascii('CFBundleIdentifier'),
    ascii('com.example.app'),
    ascii('CFBundleName'),
    ascii('Fixture'),
  ];
  const offsets = [];
  let cursor = 8;
  for (const object of objects) { offsets.push(cursor); cursor += object.length; }
  const table = Buffer.from(offsets);
  const trailer = Buffer.alloc(32);
  trailer[6] = 1;  // offsetSize
  trailer[7] = 1;  // refSize
  trailer.writeBigUInt64BE(BigInt(objects.length), 8);
  trailer.writeBigUInt64BE(0n, 16);
  trailer.writeBigUInt64BE(BigInt(cursor), 24);
  return Buffer.concat([Buffer.from('bplist00', 'latin1'), ...objects, table, trailer]);
}

test('property lists are read in both the binary and the XML form', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'Info.plist', buildBinaryPlist());
  const binary = tools.get('artifact.plist').execute({ path: 'Info.plist' }, context);
  assert.equal(binary.supported, true);
  assert.equal(binary.format, 'binary');
  assert.equal(binary.version, '00');
  assert.equal(binary.objectCount, 5);
  assert.deepEqual(binary.root, { CFBundleIdentifier: 'com.example.app', CFBundleName: 'Fixture' });

  write(dir, 'xml.plist', Buffer.from([
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<plist version="1.0"><dict>',
    '<key>CFBundleIdentifier</key><string>com.example.xml</string>',
    '<key>MinimumOSVersion</key><string>14.0</string>',
    '<key>UIFileSharingEnabled</key><true/>',
    '<key>CFBundleURLTypes</key><array><dict/></array>',
    '</dict></plist>',
  ].join('\n'), 'utf8'));
  const xml = tools.get('artifact.plist').execute({ path: 'xml.plist' }, context);
  assert.equal(xml.format, 'xml');
  assert.equal(xml.root.CFBundleIdentifier, 'com.example.xml');
  assert.equal(xml.root.UIFileSharingEnabled, true);
  // A nested container is reported as present rather than reconstructed.
  assert.deepEqual(xml.root.CFBundleURLTypes, { nested: 'array' });
  assert.ok(xml.limitations.some((l) => /flat listing of its top-level keys/.test(l)));

  write(dir, 'plain.txt', Buffer.from('not a plist at all', 'utf8'));
  assert.equal(tools.get('artifact.plist').execute({ path: 'plain.txt' }, context).reason, 'not_a_plist');
  write(dir, 'stub.plist', Buffer.from('bplist00', 'latin1'));
  assert.equal(tools.get('artifact.plist').execute({ path: 'stub.plist' }, context).reason, 'plist_truncated');
});

test('an Apple application graph reports bundle identity and separates system links', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'Info.plist', buildBinaryPlist());
  write(dir, 'Fixture', nulJoined([
    '/usr/lib/libSystem.B.dylib',
    '/System/Library/Frameworks/Foundation.framework/Foundation',
    '@rpath/MyPrivate.framework/MyPrivate',
    '@executable_path/../Frameworks/libthird.dylib',
    'unrelated string content here',
  ]));
  const read = tools.get('artifact.appleGraph').execute({ plist: 'Info.plist', binary: 'Fixture' }, context);
  assert.equal(read.supported, true);
  assert.equal(read.bundle.identifier, 'com.example.app');
  assert.equal(read.bundle.name, 'Fixture');
  assert.equal(read.bundle.plistFormat, 'binary');
  const targets = read.edges.map((edge) => edge.to);
  assert.ok(targets.includes('/usr/lib/libSystem.B.dylib'));
  assert.ok(targets.includes('@rpath/MyPrivate.framework/MyPrivate'));
  // A system framework is a different kind of dependency from a bundled one.
  assert.equal(read.edges.find((edge) => edge.to === '/usr/lib/libSystem.B.dylib').system, true);
  assert.equal(read.edges.find((edge) => edge.to.startsWith('@rpath')).system, false);
  assert.equal(read.externalFrameworks, 2);
  assert.ok(read.limitations.some((l) => /rather than from decoded load commands/.test(l)));

  // Without a binary there are no link edges, which is distinct from there being none.
  const plistOnly = tools.get('artifact.appleGraph').execute({ plist: 'Info.plist' }, context);
  assert.deepEqual(plistOnly.edges, []);
  assert.equal(plistOnly.bundle.identifier, 'com.example.app');
  const missing = tools.get('artifact.appleGraph').execute({ plist: 'Info.plist', binary: 'nope' }, context);
  assert.ok(missing.limitations.some((l) => /could not be read/.test(l)));
});

/** A stored-entry ZIP, which is what a HarmonyOS package is underneath. */
function buildZip(names) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const name of names) {
    const nameBytes = Buffer.from(name, 'utf8');
    const content = Buffer.from('x');
    const local = Buffer.alloc(30 + nameBytes.length + content.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);
    content.copy(local, 30 + nameBytes.length);
    locals.push(local);
    const entry = Buffer.alloc(46 + nameBytes.length);
    entry.writeUInt32LE(0x02014b50, 0);
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
  return Buffer.concat([localBytes, centralBytes, eocd]);
}

test('a HarmonyOS package graph is built from its layout, with contents left undecompressed', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'entry.hap', buildZip([
    'module.json', 'pack.info', 'resources.index',
    'ets/modules.abc', 'ets/widget.abc',
    'libs/arm64-v8a/libnative.so', 'libs/x86_64/libnative.so',
  ]));
  const read = tools.get('artifact.harmonyGraph').execute({ path: 'entry.hap' }, context);
  assert.equal(read.supported, true);
  assert.equal(read.module.hasModuleJson, true);
  assert.equal(read.module.hasPackInfo, true);
  assert.equal(read.module.resourceIndex, true);
  assert.deepEqual(read.module.arkTsBytecode, ['ets/modules.abc', 'ets/widget.abc']);
  assert.deepEqual(read.module.abis, ['arm64-v8a', 'x86_64']);
  assert.equal(read.module.entryCount, 7);
  assert.equal(read.edges.filter((edge) => edge.kind === 'contains-bytecode').length, 2);
  assert.equal(read.edges.filter((edge) => edge.kind === 'contains-native').length, 2);
  // Abilities live inside module.json, which is compressed and not read: said plainly.
  assert.ok(read.limitations.some((l) => /not decompressed/.test(l)));

  // A ZIP without the descriptors may not be a HarmonyOS package at all.
  write(dir, 'other.zip', buildZip(['readme.txt']));
  const other = tools.get('artifact.harmonyGraph').execute({ path: 'other.zip' }, context);
  assert.equal(other.supported, true);
  assert.ok(other.limitations.some((l) => /may be a ZIP that is not a HarmonyOS package/.test(l)));

  write(dir, 'notzip.bin', Buffer.from('definitely not an archive'));
  const notZip = tools.get('artifact.harmonyGraph').execute({ path: 'notzip.bin' }, context);
  assert.equal(notZip.supported, false);
  assert.equal(notZip.reason, 'not_a_hap');
});
