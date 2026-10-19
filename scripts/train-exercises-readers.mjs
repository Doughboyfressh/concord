import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

/**
 * The reader family, which is most of Concord's tool surface.
 *
 * Fifty-two artifact tools, and what they share matters more than what any one of them parses.
 * Every prediction below was probed first rather than guessed: a reader handed a file that is not
 * its format answers with supported:false, a reason, and the digest of exactly what it examined.
 * None of them throws. That uniformity is the lesson worth having — a reader that cannot parse
 * something still tells you what it looked at, so a negative result is evidence rather than an
 * absence of evidence.
 *
 * The exception is as informative as the rule. A lexical scanner reports supported:true for any
 * text at all, because any text can be scanned. There, supported means "I could read this", never
 * "this is what you hoped it was", and conflating the two is how a scan gets mistaken for a parse.
 *
 * These predictions deliberately do not check that every declared output key is present. That is a
 * universal contract and the harness enforces it for every exercise in one place, so it cannot be
 * forgotten by the next exercise written. It briefly lived here instead, and that was a mistake
 * worth recording: touching all seven of a reader's keys to confirm they existed scored identically
 * to checking what the values meant, which pushed reported key coverage to 317/418 when most of it
 * was presence rather than content. What is asserted below is meaning: the digest equals the hash
 * of the exact bytes the fixture wrote, the path is the one that was asked for, a reader that
 * parsed nothing returns an empty list or an explicit null where findings would go, and a region
 * read reports back the bytes it actually took.
 */

const write = (dir, name, body) => fs.writeFileSync(path.join(dir, name), Buffer.isBuffer(body) ? body : Buffer.from(body));
const digestOf = (bytes) => createHash('sha256').update(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)).digest('hex');

/** Plain text, which is not the format any binary reader here is looking for. */
const NOT_MINE = 'this is plain text, not the format this reader parses';

/**
 * The digest the fixture must hash to, computed here rather than asserted loosely.
 *
 * Checking that sha256 merely looks like hex says almost nothing: it would pass for the digest of
 * a different file, or of a truncated read. Comparing against the digest of the exact bytes the
 * fixture wrote is the assertion actually worth making, because the claim a reader makes is "this
 * is the hash of what I examined" — and that claim is only testable if the test knows the answer.
 */
const NOT_MINE_DIGEST = digestOf(NOT_MINE);

/** Binary readers: a non-matching file is reported, not thrown. */
const BINARY_READERS = [
  'artifact.androidManifest', 'artifact.apk', 'artifact.coreDump', 'artifact.dartSnapshot',
  'artifact.dex', 'artifact.dexGraph', 'artifact.electronFuses', 'artifact.flutterBuild',
  'artifact.goBuildInfo', 'artifact.harmonyGraph', 'artifact.managed', 'artifact.managedGraph',
  'artifact.managedMembers', 'artifact.managedNativeBoundaries', 'artifact.packetFields',
  'artifact.pcap', 'artifact.peResources', 'artifact.plist', 'artifact.recoverSources',
  'artifact.rustBinary', 'artifact.sqlite',
];

/**
 * The same contract, for readers that need an argument beyond the path.
 *
 * `empty` names what each one returns in place of findings when it could not parse: an empty list
 * or an explicit null, never a partial or absent answer. Measured for each, because "it returns
 * nothing useful" has several possible shapes and only one of them is what these actually do.
 */
const NARROWED_READERS = [
  { tool: 'artifact.dexClass', extra: { descriptor: 'La/B;' }, empty: (r) => r.class === null },
  { tool: 'artifact.dexMethod', extra: { descriptor: 'La/B;' }, empty: (r) => Array.isArray(r.methods) && r.methods.length === 0 },
  { tool: 'artifact.dexReferences', extra: { type: 'La/B;' }, empty: (r) => r.methods.length === 0 && r.fields.length === 0 },
  { tool: 'artifact.dexSearch', extra: { query: 'anything' }, empty: (r) => r.matches.length === 0 && r.totalMatches === 0 },
  { tool: 'artifact.sourceLocation', extra: { line: 1, column: 1 }, empty: (r) => r.entry === null },
];

/** Lexical scanners, with text that really does contain what they look for. */
const SCANNERS = [
  {
    tool: 'artifact.jsExports', name: 'code.js', key: 'exports',
    body: 'export const a = 1;\nexport function go() { return 2; }\n',
  },
  {
    tool: 'artifact.moduleImports', name: 'imports.js', key: 'imports',
    body: 'import x from "./b.js";\nimport { y } from "./c.js";\nexport const a = 1;\n',
  },
  {
    tool: 'artifact.htmlScripts', name: 'page.html', key: 'scripts',
    body: '<html><body><script src="a.js"></script><script>var n = 1;</script></body></html>',
  },
];

export function readerExercises() {
  return [
    ...BINARY_READERS.map((tool) => ({
      family: 'readers', tool, workspace: 'temp',
      fixture: (dir) => write(dir, 'notmine.bin', NOT_MINE),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool, input: { path: 'notmine.bin' } }] },
      expect: (r) => r.results.a.supported === false && typeof r.results.a.reason === 'string'
        && r.results.a.sha256 === NOT_MINE_DIGEST && r.results.a.untrusted === true
        && r.results.a.path === 'notmine.bin' && Array.isArray(r.results.a.limitations),
      lesson: `${tool} answers a file that is not its format with supported:false and a stated reason, never by throwing, and the SHA-256 it reports is the digest of exactly the bytes the fixture wrote — compared against a value computed independently, so it cannot be the hash of a different or partial read. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more.`,
    })),

    ...NARROWED_READERS.map((entry) => ({
      family: 'readers', tool: entry.tool, workspace: 'temp',
      fixture: (dir) => write(dir, 'notmine.bin', NOT_MINE),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: entry.tool, input: { path: 'notmine.bin', ...entry.extra } }] },
      expect: (r) => r.results.a.supported === false && typeof r.results.a.reason === 'string'
        && r.results.a.untrusted === true && Array.isArray(r.results.a.limitations)
        && r.results.a.path === 'notmine.bin' && r.results.a.sha256 === NOT_MINE_DIGEST
        && entry.empty(r.results.a),
      lesson: `${entry.tool} takes an argument beyond the path, and still refuses a file that is not its format with supported:false, a reason, and the digest of exactly the bytes it read. Where findings would go it returns an empty list or an explicit null rather than omitting the key or guessing — so a caller reading the result cannot tell a parse that found nothing from a parse that failed, except by the field that says which. The extra argument narrows what is being asked; it never loosens what is accepted.`,
    })),

    ...SCANNERS.map((entry) => ({
      family: 'readers', tool: entry.tool, workspace: 'temp',
      fixture: (dir) => write(dir, entry.name, entry.body),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: entry.tool, input: { path: entry.name } }] },
      expect: (r) => r.results.a.supported === true && Array.isArray(r.results.a[entry.key])
        && r.results.a[entry.key].length > 0 && r.results.a.untrusted === true
        && Array.isArray(r.results.a.limitations),
      lesson: `${entry.tool} is a lexical scan, so supported:true means only that the text could be scanned and never that the file is what you hoped. It blanks comments, strings, template literals and regular expressions first while preserving every byte offset, so a match cannot fire on a keyword inside a comment and a reported position still refers to the real file.`,
    })),

    {
      family: 'readers', tool: 'artifact.jsSemantics', workspace: 'temp',
      fixture: (dir) => write(dir, 'sem.js', 'export async function go() { await fetch("/x"); }\n'),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.jsSemantics', input: { path: 'sem.js' } }] },
      expect: (r) => r.results.a.supported === true && /^[0-9a-f]{64}$/.test(r.results.a.sha256)
        && Array.isArray(r.results.a.findings) && r.results.a.untrusted === true,
      lesson: 'artifact.jsSemantics reports constructs it recognised by scanning and says plainly that it is a scan rather than a parse: it describes what the text contains, not what the program does when it runs.',
    },
    {
      family: 'readers', tool: 'artifact.webBundle', workspace: 'temp',
      fixture: (dir) => write(dir, 'bundle.js', '/*! bundled */\nvar __webpack_require__ = 1;\nexport const a = 2;\n'),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.webBundle', input: { path: 'bundle.js' } }] },
      expect: (r) => r.results.a.supported === true && Array.isArray(r.results.a.bundlers)
        && r.results.a.untrusted === true && Array.isArray(r.results.a.limitations),
      lesson: 'artifact.webBundle looks for bundler markers in text and reports which it saw. A marker is evidence that a bundler touched the file, not proof of which one or of what it did.',
    },
    {
      family: 'readers', tool: 'artifact.firmware', workspace: 'temp',
      fixture: (dir) => write(dir, 'fw.bin', Buffer.concat([Buffer.from('UBI#'), Buffer.alloc(64)])),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.firmware', input: { path: 'fw.bin' } }] },
      expect: (r) => r.results.a.supported === true && r.results.a.regions.length === 1
        && r.results.a.untrusted === true && r.results.a.path === 'fw.bin'
        && r.results.a.sha256 === digestOf(Buffer.concat([Buffer.from('UBI#'), Buffer.alloc(64)]))
        && r.results.a.bytes === 68 && r.results.a.counts && Array.isArray(r.results.a.limitations),
      lesson: 'artifact.firmware scans for known magics and reports exactly what it found and where: one region for one UBI signature, a tally beside it, the byte length it examined, and the digest of those same bytes. Some signatures are only meaningful at a fixed offset, so an anchored magic appearing elsewhere is deliberately not treated as a hit — which is why the region count is worth asserting rather than just the presence of a list.',
    },
    {
      family: 'readers', tool: 'artifact.wasmInterface', workspace: 'temp',
      fixture: (dir) => write(dir, 'm.wasm', Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.wasmInterface', input: { path: 'm.wasm' } }] },
      expect: (r) => r.results.a.entries.length === 0 && r.results.a.state === 'complete'
        && r.results.a.path === 'm.wasm' && r.results.a.format === 'wasm'
        && r.results.a.counts && Array.isArray(r.results.a.limitations)
        && r.results.a.sha256 === digestOf(Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])),
      lesson: 'artifact.wasmInterface reads a module header and its section table directly rather than instantiating anything, so a module is described without ever being run. It reports its own state, because a module it could only partly decode must not read as one it decoded fully.',
    },
    {
      family: 'readers', tool: 'artifact.evmInterface', workspace: 'temp',
      fixture: (dir) => write(dir, 'c.evm', '6080604052'),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.evmInterface', input: { path: 'c.evm', encoding: 'hex' } }] },
      expect: (r) => r.results.a.supported === true
        && /^[0-9a-f]{64}$/.test(r.results.a.bytecodeSha256)
        && /^[0-9a-f]{64}$/.test(r.results.a.carrierSha256)
        && r.results.a.bytecodeSha256 !== r.results.a.carrierSha256
        && r.results.a.encoding === 'hex'
        && r.results.a.carrierSha256 === digestOf('6080604052')
        && r.results.a.bytecodeBytes === 5
        && r.results.a.opcodes.codeBytes === 5 && r.results.a.opcodes.instructions === 3
        && r.results.a.opcodes.pushes === 2 && r.results.a.opcodes.undefinedCount === 0
        && r.results.a.selectorCandidates.length === 0 && r.results.a.metadata === null
        && Array.isArray(r.results.a.limitations),
      lesson: 'artifact.evmInterface digests the carrier file and the decoded bytecode separately, and the two genuinely differ for hex input: the same contract delivered as hex text and as raw bytes is one bytecode in two different files, and only the bytecode digest identifies the contract. The opcode tally is a scan rather than a disassembly — five bytes decode to three instructions of which two are pushes — and its `undefined` and `undefinedCount` fields are named for undefined EVM opcodes, not for a missing value. Absent trailing metadata is null rather than an empty object, so "there was none" and "there was some and it was empty" stay distinguishable.',
    },
    {
      family: 'readers', tool: 'artifact.firmwareRegion', workspace: 'temp',
      fixture: (dir) => write(dir, 'blob.bin', '0123456789abcdef'),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.firmwareRegion', input: { path: 'blob.bin', offset: 4, length: 4 } }] },
      expect: (r) => r.results.a.supported === true && r.results.a.region.offset === 4
        && r.results.a.region.length === 4 && r.results.a.preview === '34353637'
        && r.results.a.path === 'blob.bin' && r.results.a.sha256 === digestOf('0123456789abcdef')
        && Array.isArray(r.results.a.limitations) && r.results.a.untrusted === true,
      lesson: 'artifact.firmwareRegion reads a declared window of a file rather than the whole of it, and echoes back the offset and length it actually read, so an unknown blob can be examined in bounded pieces without ever loading it entirely.',
    },
    {
      family: 'readers', tool: 'artifact.jsApplication', workspace: 'temp',
      fixture: (dir) => {
        write(dir, 'entry.js', 'import helper from "./helper.js";\nexport const main = helper;\n');
        write(dir, 'helper.js', 'export default 1;\n');
      },
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.jsApplication', input: { entry: 'entry.js' } }] },
      expect: (r) => r.results.a.supported === true && r.results.a.modules.length === 2
        && Array.isArray(r.results.a.limitations),
      lesson: 'artifact.jsApplication walks a module graph from a single entry and resolves the files it reaches, reporting resolved modules, external packages and unresolved specifiers as separate lists, so a dependency it could not find is never quietly counted as one that was not there.',
    },
  ];
}
