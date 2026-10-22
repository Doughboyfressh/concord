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

/**
 * Binary readers: a non-matching file is reported, not thrown.
 *
 * `empty` names what each returns in place of findings, for the same reason NARROWED_READERS
 * below carries one: "it returns nothing useful" has several shapes and only one of them is what
 * a given reader actually does. Measured, and they genuinely differ - a list, an explicit null,
 * one of each, and an empty object. A reader that returned undefined for its own subject would
 * make a caller branch on whether a key exists, which is the thing every envelope here prevents.
 *
 * The readers with no predicate are the ones that now have a fixture of their own format, where
 * the success path is asserted in full; this exercise is only about the refusal path.
 */
const BINARY_READERS = [
  { tool: 'artifact.androidManifest', empty: (r) => r.elements.length === 0 },
  { tool: 'artifact.apk', empty: (r) => r.entries.length === 0 && r.summary === null },
  { tool: 'artifact.coreDump', empty: (r) => r.thread === null && r.process === null },
  { tool: 'artifact.dartSnapshot', empty: (r) => r.versionHash === null && r.buildMode === null },
  { tool: 'artifact.dex', empty: (r) => r.classes.length === 0 && r.counts === null },
  { tool: 'artifact.dexGraph', empty: (r) => r.edges.length === 0 && r.roots.length === 0 },
  { tool: 'artifact.electronFuses', empty: (r) => r.fuses.length === 0 && Object.keys(r.byName).length === 0 },
  { tool: 'artifact.flutterBuild', empty: (r) => r.markers.length === 0 && r.buildMode === null },
  { tool: 'artifact.goBuildInfo', empty: (r) => r.version === null && r.settings.length === 0 },
  { tool: 'artifact.harmonyGraph', empty: (r) => r.module === null && r.edges.length === 0 },
  { tool: 'artifact.rustBinary', empty: (r) => r.rustcVersions.length === 0 && r.mangling === null },
  { tool: 'artifact.managed' },
  { tool: 'artifact.managedGraph' },
  { tool: 'artifact.managedMembers' },
  { tool: 'artifact.managedNativeBoundaries' },
  { tool: 'artifact.packetFields' },
  { tool: 'artifact.pcap' },
  { tool: 'artifact.peResources' },
  { tool: 'artifact.plist' },
  { tool: 'artifact.recoverSources' },
  { tool: 'artifact.sqlite' },
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
    /**
     * Every one of those readers, in one plan, refusing the same wrong file.
     *
     * The per-reader exercises below prove each one individually. This proves the uniformity: the
     * same file handed to twenty-three readers produces twenty-three answers of one shape, with
     * one digest, inside a single run. That is the claim a caller depends on when a directory
     * arrives and the format is unknown, and it is the claim the kernel exists to let a plan
     * make — the composition axis this round keeps naming, over the widest set available.
     */
    {
      family: 'composition', tool: 'artifact.dex', workspace: 'temp',
      fixture: (dir) => write(dir, 'notmine.bin', NOT_MINE),
      plan: { version: 1, name: 'one-wrong-file-and-every-reader', tasks: [
        ...BINARY_READERS.map((entry, index) => ({ id: `b${index}`, tool: entry.tool, input: { path: 'notmine.bin' } })),
        ...NARROWED_READERS.map((entry, index) => ({ id: `n${index}`, tool: entry.tool, input: { path: 'notmine.bin', ...entry.extra } })),
      ] },
      expect: (r) => {
        const values = Object.values(r.results);
        return values.length === BINARY_READERS.length + NARROWED_READERS.length
          && values.every((value) => value.supported === false && typeof value.reason === 'string'
            && value.sha256 === NOT_MINE_DIGEST && value.untrusted === true
            && value.path === 'notmine.bin' && Array.isArray(value.limitations))
          // Each reason is that reader's own, not one shared string.
          && new Set(values.map((value) => value.reason)).size > 1
          && BINARY_READERS.every((entry, index) => !entry.empty || entry.empty(r.results[`b${index}`]))
          && NARROWED_READERS.every((entry, index) => entry.empty(r.results[`n${index}`]));
      },
      lesson: 'Twenty-three readers, one file none of them can parse, one plan. Every answer has the same shape — supported:false, a reason, the digest of exactly those bytes, the untrusted flag, the path asked for, and a limitations list — while the reasons differ from one another, so a caller learns both that nothing parsed the file and what each reader was looking for. The readers taking an extra argument still return an empty list or an explicit null where findings would go. Proven together rather than only one at a time because the uniformity is itself the property: a caller meeting an unknown file writes one branch for twenty-three formats, and a reader that broke the shape would show up here rather than at whichever call site happened to depend on it.',
    },

    ...BINARY_READERS.map(({ tool, empty }) => ({
      family: 'readers', tool, workspace: 'temp',
      fixture: (dir) => write(dir, 'notmine.bin', NOT_MINE),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool, input: { path: 'notmine.bin' } }] },
      expect: (r) => r.results.a.supported === false && typeof r.results.a.reason === 'string'
        && r.results.a.sha256 === NOT_MINE_DIGEST && r.results.a.untrusted === true
        && r.results.a.path === 'notmine.bin' && Array.isArray(r.results.a.limitations)
        // And what this particular reader puts where its findings would go.
        && (!empty || empty(r.results.a)),
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
    {
      family: 'readers', tool: 'artifact.inspect', workspace: 'temp',
      // A PE whose section table puts the entry point at a file offset 0xC00 below its RVA, which
      // is the same shape as a real Windows binary: .text at virtual 0x1000, raw at 0x400.
      fixture: (dir) => {
        const pe = Buffer.alloc(512);
        pe.write('MZ', 0, 'latin1');
        pe.writeInt32LE(64, 0x3c);
        pe.write('PE\u0000\u0000', 64, 'latin1');
        pe.writeUInt16LE(0x8664, 68);
        pe.writeUInt16LE(1, 70);
        pe.writeUInt16LE(240, 84);
        pe.writeUInt16LE(0x20b, 88);
        pe.writeUInt32LE(0x1234, 104);
        pe.writeBigUInt64LE(0x140000000n, 112);
        const section = 64 + 24 + 240;
        pe.write('.text', section, 'latin1');
        pe.writeUInt32LE(0x2000, section + 8);
        pe.writeUInt32LE(0x1000, section + 12);
        pe.writeUInt32LE(0x2000, section + 16);
        pe.writeUInt32LE(0x400, section + 20);
        write(dir, 'prog.exe', pe);
      },
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.inspect', input: { path: 'prog.exe' } }] },
      expect: (r) => r.results.a.format === 'pe' && r.results.a.path === 'prog.exe'
        && r.results.a.pe.entryPoint === 0x1234
        && r.results.a.pe.entryPointOffset === 0x634
        && r.results.a.pe.entryPointOffset !== r.results.a.pe.entryPoint
        && r.results.a.pe.entryPointAddress === 0x140001234
        && r.results.a.pe.sections[0].name === '.text',
      lesson: 'artifact.inspect reports a PE entry point three ways because they are three different numbers, and confusing them is the most direct route to confidently wrong disassembly. AddressOfEntryPoint is a relative virtual address; the bytes live at a file offset that differs by the gap between a section virtual address and its PointerToRawData; and the address the code believes it runs at is the image base plus the RVA. On a real Windows binary that gap is 0xC00, so handing the RVA to a disassembler as an offset decodes bytes three kilobytes away and reports success on every one of them, because a stream of x86 bytes is almost always decodable as something. The conversion needs the section table, so the section table is reported too, and when no section covers the RVA the offset key is absent rather than null or zero: canonical refuses undefined, and a guessed offset is worse than a stated gap. The same distinction applies to ELF, where the mapping comes from the PT_LOAD segments instead.',
    },
  ];
}
