import fs from 'node:fs';
import path from 'node:path';

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
 * was presence rather than content. What is asserted below is meaning — the digest is hex of the
 * right length, the path is the one that was asked for, limitations is a list, untrusted is true.
 */

const write = (dir, name, body) => fs.writeFileSync(path.join(dir, name), Buffer.isBuffer(body) ? body : Buffer.from(body));

/** Plain text, which is not the format any binary reader here is looking for. */
const NOT_MINE = 'this is plain text, not the format this reader parses';

/** Binary readers: a non-matching file is reported, not thrown. */
const BINARY_READERS = [
  'artifact.androidManifest', 'artifact.apk', 'artifact.coreDump', 'artifact.dartSnapshot',
  'artifact.dex', 'artifact.dexGraph', 'artifact.electronFuses', 'artifact.flutterBuild',
  'artifact.goBuildInfo', 'artifact.harmonyGraph', 'artifact.managed', 'artifact.managedGraph',
  'artifact.managedMembers', 'artifact.managedNativeBoundaries', 'artifact.packetFields',
  'artifact.pcap', 'artifact.peResources', 'artifact.plist', 'artifact.recoverSources',
  'artifact.rustBinary', 'artifact.sqlite',
];

/** The same contract, for readers that need an argument beyond the path. */
const NARROWED_READERS = [
  { tool: 'artifact.dexClass', extra: { descriptor: 'La/B;' } },
  { tool: 'artifact.dexMethod', extra: { descriptor: 'La/B;' } },
  { tool: 'artifact.dexReferences', extra: { type: 'La/B;' } },
  { tool: 'artifact.dexSearch', extra: { query: 'anything' } },
  { tool: 'artifact.sourceLocation', extra: { line: 1, column: 1 } },
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
        && /^[0-9a-f]{64}$/.test(r.results.a.sha256) && r.results.a.untrusted === true
        && r.results.a.path === 'notmine.bin' && Array.isArray(r.results.a.limitations),
      lesson: `${tool} answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more.`,
    })),

    ...NARROWED_READERS.map((entry) => ({
      family: 'readers', tool: entry.tool, workspace: 'temp',
      fixture: (dir) => write(dir, 'notmine.bin', NOT_MINE),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: entry.tool, input: { path: 'notmine.bin', ...entry.extra } }] },
      expect: (r) => r.results.a.supported === false && typeof r.results.a.reason === 'string'
        && r.results.a.untrusted === true && Array.isArray(r.results.a.limitations),
      lesson: `${entry.tool} takes an argument beyond the path, and still refuses a file that is not its format with supported:false, a reason, and its full declared output shape. The extra argument narrows what is being asked; it never loosens what is accepted.`,
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
      expect: (r) => r.results.a.supported === true && Array.isArray(r.results.a.regions)
        && r.results.a.untrusted === true,
      lesson: 'artifact.firmware scans for known magics and reports what it found and where. Some signatures are only meaningful at a fixed offset, so an anchored magic appearing elsewhere is deliberately not treated as a hit.',
    },
    {
      family: 'readers', tool: 'artifact.wasmInterface', workspace: 'temp',
      fixture: (dir) => write(dir, 'm.wasm', Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.wasmInterface', input: { path: 'm.wasm' } }] },
      expect: (r) => Array.isArray(r.results.a.entries) && typeof r.results.a.state === 'string'
        && r.results.a.path === 'm.wasm',
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
        && r.results.a.encoding === 'hex',
      lesson: 'artifact.evmInterface digests the carrier file and the decoded bytecode separately, and the two digests genuinely differ for hex input: the same contract delivered as hex text and as raw bytes is one bytecode in two different files, and only the bytecode digest identifies the contract.',
    },
    {
      family: 'readers', tool: 'artifact.firmwareRegion', workspace: 'temp',
      fixture: (dir) => write(dir, 'blob.bin', '0123456789abcdef'),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.firmwareRegion', input: { path: 'blob.bin', offset: 4, length: 4 } }] },
      expect: (r) => r.results.a.supported === true && r.results.a.region.offset === 4
        && r.results.a.region.length === 4,
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
