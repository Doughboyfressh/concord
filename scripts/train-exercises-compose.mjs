import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical } from '../src/value.mjs';

const harDigest = (text) => createHash('sha256').update(Buffer.from(text)).digest('hex');

/**
 * Composition: the thing the kernel is actually for, and the thing nothing was testing.
 *
 * Ninety-four exercises reached every tool in the registry and every one of them was a single-task
 * plan. So the suite had never touched the reference mechanism at all — a tool count of 79/79 was
 * measuring the wrong axis and reading as complete while the centre was bare.
 *
 * A task reads a previous task's output as `{$task: 'id', path: '/rfc6901/pointer'}`, placed
 * unquoted as the value, and only where `dependsOn` already declares that edge. Two properties are
 * worth more than the syntax. The declared edge means the dependency graph is readable without
 * executing anything, so a plan can be refused before it runs rather than discovered mid-flight.
 * And the approval hash binds the *resolved* input, which is what makes a referenced write safe:
 * granting it approves the bytes that were actually derived, not the shape of a plan that promised
 * to derive something.
 *
 * The guards divide cleanly, and the division is the lesson. A malformed reference is refused while
 * compiling, before any task runs, because it is a defect in the plan. A reference that is well
 * formed but does not fit the data it points at fails as a task, because only the data could reveal
 * it. Nothing here was assumed: each code and reason below was raised by a real run first.
 */

const write = (dir, name, body) => fs.writeFileSync(path.join(dir, name), body);

/**
 * A minimal but real WebAssembly module: type, import, function, export and code sections.
 *
 * Hand-encoded because the only wasm fixture in this suite was the eight-byte header, against
 * which every one of the reader's outputs is an empty list — a parser that read nothing at all
 * would have scored the same. Each export points at function index 0; the signature is () -> ().
 */
function wasmModule(exportNames) {
  const bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  const section = (id, body) => { bytes.push(id, body.length, ...body); };
  const str = (text) => [text.length, ...[...text].map((character) => character.charCodeAt(0))];
  section(0x01, [0x01, 0x60, 0x00, 0x00]);                                  // one signature, () -> ()
  section(0x02, [0x01, ...str('env'), ...str('log'), 0x00, 0x00]);          // one imported function
  section(0x03, [0x01, 0x00]);                                             // one local function
  section(0x07, [exportNames.length, ...exportNames.flatMap((name) => [...str(name), 0x00, 0x00])]);
  section(0x0a, [0x01, 0x02, 0x00, 0x0b]);                                 // one empty body
  return Buffer.from(bytes);
}

/** Two captures of the same page, differing by one failure and one new request. */
const har = (entries) => JSON.stringify({ log: { version: '1.2', creator: { name: 'training', version: '1' }, entries } });
const capture = (method, url, status, mimeType, size) => ({
  request: { method, url }, response: { status, content: { mimeType, size }, bodySize: size },
});
const BEFORE_HAR = har([
  capture('GET', 'https://app.example/index.html', 200, 'text/html', 1200),
  capture('GET', 'https://app.example/app.js', 200, 'application/javascript', 8400),
]);
const AFTER_HAR = har([
  capture('GET', 'https://app.example/index.html', 200, 'text/html', 1300),
  capture('GET', 'https://app.example/app.js', 500, 'application/javascript', 0),
  capture('POST', 'https://telemetry.example/collect', 204, 'application/json', 0),
]);

/** One tree holding a file for every reader in the batch below. */
const READER_FILES = {
  'sem.js': 'export async function go() { await fetch("/x"); }\n',
  'bundle.js': '/*! bundled */\nvar __webpack_require__ = 1;\nexport const a = 2;\n',
  'code.js': 'export const a = 1;\nexport function b() {}\n',
  'imports.js': 'import x from "./code.js";\nimport "./side-effect.js";\n',
  'page.html': '<html><body><script src="/a.js"></script><script>var inline = 1;</script></body></html>',
  'c.evm': '6080604052',
  'blob.bin': '0123456789abcdef',
  'entry.js': 'import helper from "./helper.js";\nexport const main = helper;\n',
  'helper.js': 'export default 1;\n',
};
const readerFixture = (dir) => {
  for (const [name, body] of Object.entries(READER_FILES)) write(dir, name, body);
  write(dir, 'fw.bin', Buffer.concat([Buffer.from('UBI#'), Buffer.alloc(64)]));
  write(dir, 'm.wasm', Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]));
};
const bodyDigest = (name) => (name in READER_FILES
  ? createHash('sha256').update(Buffer.from(READER_FILES[name])).digest('hex')
  : null);

export function composeExercises() {
  return [
    {
      family: 'composition', tool: 'artifact.jsSemantics', workspace: 'temp', fixture: readerFixture,
      plan: { version: 1, name: 'ten-readers-over-one-tree', tasks: [
        { id: 'semantics', tool: 'artifact.jsSemantics', input: { path: 'sem.js' } },
        { id: 'bundle', tool: 'artifact.webBundle', input: { path: 'bundle.js' } },
        { id: 'exports', tool: 'artifact.jsExports', input: { path: 'code.js' } },
        { id: 'imports', tool: 'artifact.moduleImports', input: { path: 'imports.js' } },
        { id: 'scripts', tool: 'artifact.htmlScripts', input: { path: 'page.html' } },
        { id: 'firmware', tool: 'artifact.firmware', input: { path: 'fw.bin' } },
        { id: 'wasm', tool: 'artifact.wasmInterface', input: { path: 'm.wasm' } },
        { id: 'evm', tool: 'artifact.evmInterface', input: { path: 'c.evm', encoding: 'hex' } },
        { id: 'region', tool: 'artifact.firmwareRegion', input: { path: 'blob.bin', offset: 4, length: 4 } },
        { id: 'application', tool: 'artifact.jsApplication', input: { entry: 'entry.js' } },
      ] },
      expect: (r) => {
        // The envelope every path-taking reader shares, over ten readers and one tree.
        const envelope = [
          ['semantics', 'sem.js'], ['bundle', 'bundle.js'], ['exports', 'code.js'],
          ['imports', 'imports.js'], ['scripts', 'page.html'], ['region', 'blob.bin'],
        ].every(([id, file]) => {
          const value = r.results[id];
          return value.path === file && value.sha256 === bodyDigest(file) && value.untrusted === true;
        });
        return envelope
          && r.results.firmware.untrusted === true && r.results.wasm.untrusted === true
          // And one fact from each, so the envelope is not the only thing being claimed.
          && r.results.exports.exports.length === 2
          && r.results.imports.imports.length === 2
          && r.results.imports.counts.import === 2
          && r.results.scripts.scripts.length === 2
          && r.results.firmware.regions.length === 1
          && r.results.wasm.entries.length === 0 && r.results.wasm.state === 'complete'
          // A region reports the digest of the slice as well as of the file it came from.
          && r.results.region.region.length === 4 && r.results.region.preview === '34353637'
          && r.results.region.region.sha256 !== r.results.region.sha256
          // The carrier and the bytecode are two different things with two different digests.
          && r.results.evm.carrierSha256 === bodyDigest('c.evm')
          && r.results.evm.bytecodeSha256 !== r.results.evm.carrierSha256
          && r.results.evm.bytecodeBytes === 5 && r.results.evm.untrusted === true
          // And an application is a module graph rather than a file.
          && r.results.application.entry === 'entry.js'
          && r.results.application.modules.length === 2
          && r.results.application.modules.every((module) => module.readable === true);
      },
      lesson: 'Ten readers over one tree in a single plan, which is how a caller actually meets them: a directory arrives and several formats are in it. The envelope holds across all of them — each reports the path it was asked for, the digest of exactly those bytes computed independently here, and the untrusted flag — and each still answers its own question: two exports, two imports, two scripts in the page, one firmware region, an empty but complete WebAssembly interface, four bytes of a region whose slice carries its own digest beside the one for the whole file, five bytes of EVM bytecode whose digest differs from that of the hex text carrying it, and two readable modules reached from one entry. The uniformity is the useful part. A caller handling ten formats writes one result-shaped branch rather than ten, and a reader that broke its envelope would be visible immediately instead of at whichever call site happened to depend on it.',
    },
    // ---- compositions that do real work ----------------------------------------------
    {
      family: 'composition', tool: 'artifact.compareHar', workspace: 'temp',
      fixture: (dir) => {
        write(dir, 'before.har', BEFORE_HAR);
        write(dir, 'after.har', AFTER_HAR);
      },
      plan: { version: 1, name: 'compare-two-captures', tasks: [
        { id: 'before', tool: 'artifact.harCapture', input: { path: 'before.har' } },
        { id: 'after', tool: 'artifact.harCapture', input: { path: 'after.har' } },
        { id: 'diff', tool: 'artifact.compareHar', dependsOn: ['before', 'after'],
          input: { left: { $task: 'before' }, right: { $task: 'after' } } },
      ] },
      expect: (r) => r.results.before.summary.entryCount === 2 && r.results.after.summary.entryCount === 3
        && r.results.before.summary.byStatus['2xx'] === 2 && r.results.after.summary.byStatus['5xx'] === 1
        && r.results.after.summary.origins.length === 2
        && canonical(r.results.diff.summary) === canonical({ added: 1, removed: 0, changed: 1, unchanged: 1, countDiffers: 0 })
        && r.results.diff.changes.find((change) => change.state === 'added').request === 'POST https://telemetry.example/collect'
        && r.results.diff.changes.find((change) => change.state === 'changed').right.status === 500
        && r.results.before.untrusted === true && r.results.diff.limitations.length === 1
        // The reader's own envelope, checked against digests computed here.
        && r.results.before.path === 'before.har' && r.results.after.path === 'after.har'
        && r.results.before.sha256 === harDigest(BEFORE_HAR) && r.results.after.sha256 === harDigest(AFTER_HAR)
        && r.results.before.supported === true && Array.isArray(r.results.before.limitations),
      lesson: 'Two HTTP archives read by artifact.harCapture feed artifact.compareHar by reference, and the comparison is the point of both: it reports one request added, one changed and one unchanged, keying requests by method, origin and path so that a query string or a timing difference is not mistaken for a different request. It names the unchanged request explicitly rather than omitting it, which is what lets a reader tell "the same request still succeeds" from "the request is no longer in the capture". The reason this tool takes two reader results rather than two paths is that comparison is pure: nothing is read twice, and the same two captures can be compared again from the journal without touching the files. Its single stated limitation is the key itself, which a caller has to know in order to read the result correctly.',
    },
    {
      family: 'composition', tool: 'peer.inbox', grant: true, expectApprovals: 1,
      plan: { version: 1, name: 'file-a-message-and-read-the-box', tasks: [
        { id: 'sent', tool: 'peer.post', input: {
          message: 'Filed by a composed training exercise to prove the mailbox reports back the sequence it assigned. No reply is needed.',
          subject: 'training composition', for: 'operator',
        } },
        { id: 'box', tool: 'peer.inbox', dependsOn: ['sent'], input: {} },
      ] },
      expect: (r) => Number.isInteger(r.results.sent.seq) && r.results.sent.seq >= 1
        && r.results.sent.replyTo === null && r.results.sent.for === 'operator'
        && r.results.sent.id.includes('-')
        && r.results.sent.limitations.some((note) => note.includes('notifies nobody'))
        && r.results.box.latestSeq === r.results.sent.seq
        && r.results.box.total >= 1 && r.results.box.returned >= 1
        && r.results.box.returned <= r.results.box.total
        && r.results.box.openQuestions >= 1
        // The default page is the OLDEST messages, so the message just filed appears only when
        // the whole box fits in one page. Stated as an equivalence so it holds for a mailbox of
        // one and for this one, which holds three hundred and eleven.
        && (r.results.box.total <= r.results.box.returned)
          === r.results.box.messages.some((entry) => entry.seq === r.results.sent.seq && entry.answered === false && entry.for === 'operator')
        && r.results.box.messages[0].seq < r.results.sent.seq
        && r.results.box.limitations.some((note) => note.includes('leaves the mailbox unchanged')),
      lesson: 'A message filed by peer.post and read back by peer.inbox in the same plan shows what the mailbox is and is not. The write is approved on its own and returns the sequence number it assigned; the read reports that same number as latestSeq, so the two halves agree without the plan restating it. The trap is which messages come back: the default page is the oldest, not the newest, so in a mailbox of three hundred and eleven the message just filed is not in the result at all, and a caller reading the inbox to find what just arrived gets the opposite end of the history. latestSeq is the handle for that — the stated way to page is with `after` using it — and the box reports what it returned separately from what it holds precisely so the difference is visible rather than assumed. Open questions are counted separately again, because an unanswered message is usually what a caller is looking for. Both tools also say what they do not do: posting notifies nobody, so a record is evidence that a message was filed and not that anyone read it, and reading leaves the mailbox unchanged, so an inbox is not a queue that drains.',
    },
    {
      family: 'composition', tool: 'experiment.compare',
      plan: { version: 1, name: 'judge-two-real-measurements', tasks: [
        { id: 'first', tool: 'json.hash', input: { reading: 1 } },
        { id: 'again', tool: 'json.hash', input: { reading: 1 } },
        { id: 'other', tool: 'json.hash', input: { reading: 2 } },
        { id: 'verdict', tool: 'experiment.compare', dependsOn: ['first', 'again', 'other'], input: {
          hypothesis: 'The digest of a value depends only on the value.',
          conditions: [
            { name: 'same-value', varied: 'nothing', expected: { $task: 'first', path: '/digest' }, actual: { $task: 'again', path: '/digest' } },
            { name: 'different-value', varied: 'the reading', expected: { $task: 'first', path: '/digest' }, actual: { $task: 'other', path: '/digest' } },
          ],
        } },
      ] },
      expect: (r) => r.results.verdict.confirmed.join(',') === 'same-value'
        && r.results.verdict.refuted.join(',') === 'different-value'
        && r.results.verdict.untestable.length === 0
        && r.results.verdict.verdicts.length === 2
        && r.results.verdict.verdicts.find((entry) => entry.name === 'different-value').why.includes('differs from the declared expectation')
        // The experiment this plan describes is itself flawed, and the tool says so.
        && r.results.verdict.discriminating === false
        && r.results.verdict.warnings.length === 1
        && r.results.verdict.warnings[0].code === 'NONDISCRIMINATING_EXPECTATION',
      lesson: 'experiment.compare judges real measurements when its conditions are references: two digests computed by actual tasks, compared against each other rather than against numbers someone typed into the plan. It names which conditions were confirmed and which refuted and emits no aggregate score, because "one of two" hides which one. The sharper half is that it audits the experiment as well as the result — this plan declares the same expectation in both conditions, so a pass could not have distinguished the varied factor from a test that would pass regardless, and the result says so with NONDISCRIMINATING_EXPECTATION and discriminating:false even though both verdicts are correct. The probe that was written to measure this tool built exactly that flaw by accident and was told about it, which is the whole reason the check exists in a harness rather than in advice.',
    },
    {
      family: 'composition', tool: 'artifact.compareWasmInterfaces', workspace: 'temp',
      fixture: (dir) => {
        write(dir, 'before.wasm', wasmModule(['run', 'version']));
        write(dir, 'after.wasm', wasmModule(['run']));
      },
      plan: { version: 1, name: 'did-the-module-keep-its-surface', tasks: [
        { id: 'before', tool: 'artifact.wasmInterface', input: { path: 'before.wasm' } },
        { id: 'after', tool: 'artifact.wasmInterface', input: { path: 'after.wasm' } },
        { id: 'surface', tool: 'artifact.compareWasmInterfaces', dependsOn: ['before', 'after'],
          input: { left: { $task: 'before' }, right: { $task: 'after' }, select: 'exports' } },
      ] },
      expect: (r) => r.results.before.state === 'complete' && r.results.before.entries.length === 3
        && r.results.before.entries[0].direction === 'import' && r.results.before.entries[0].module === 'env'
        && r.results.before.entries[0].wat_form === '(import "env" "log" (func))'
        && r.results.before.entries.filter((entry) => entry.direction === 'export').length === 2
        && r.results.after.entries.filter((entry) => entry.direction === 'export').length === 1
        && r.results.surface.select === 'exports'
        && canonical(r.results.surface.summary) === canonical({ added: 0, removed: 1, changed: 0, unchanged: 1, unknown: 0 })
        && r.results.surface.changes.find((change) => change.name === 'version').state === 'removed'
        && r.results.surface.changes.every((change) => change.direction === 'export'),
      lesson: 'A real WebAssembly module — type, import, function, export and code sections, hand-encoded — proves artifact.wasmInterface reads the module\'s actual surface rather than only recognising its magic bytes: one import from env, two exported functions, each with its decoded signature and a WAT form beside it. Feeding two of those to artifact.compareWasmInterfaces answers whether a module kept the surface its callers depend on, and select narrows the question to imports, exports or both, so "we stopped exporting something" is distinguishable from "we started depending on something new" rather than being averaged into one diff. Until this exercise the reader had only ever been run against an eight-byte header, where every output was an empty list and a parser that read nothing at all would have scored identically.',
    },
    {
      family: 'composition', tool: 'artifact.compareSourceToBundle', workspace: 'temp',
      fixture: (dir) => {
        write(dir, 'authored.js', 'export const keep = 1;\nexport function alsoKeep() {}\nexport class Dropped {}\n');
        write(dir, 'shipped.js', 'export const keep = 1;\nexport function alsoKeep() {}\nexport const extra = 2;\n');
      },
      plan: { version: 1, name: 'did-the-build-keep-what-was-written', tasks: [
        { id: 'authored', tool: 'artifact.jsExports', input: { path: 'authored.js' } },
        { id: 'shipped', tool: 'artifact.jsExports', input: { path: 'shipped.js' } },
        { id: 'verdict', tool: 'artifact.compareSourceToBundle', dependsOn: ['authored', 'shipped'],
          input: { source: { $task: 'authored' }, bundle: { $task: 'shipped' } } },
      ] },
      expect: (r) => canonical(r.results.verdict.summary) === canonical({ present: 2, absent: 1, bundleOnly: 1 })
        && r.results.verdict.findings.find((entry) => entry.name === 'Dropped').state === 'absent'
        && r.results.verdict.findings.find((entry) => entry.name === 'Dropped').reason.includes('minifier')
        && r.results.verdict.findings.find((entry) => entry.name === 'extra').state === 'bundle-only'
        && r.results.verdict.findings.filter((entry) => entry.state === 'present').length === 2
        && r.results.verdict.limitations.some((note) => note.includes('not evidence of removal')),
      lesson: 'artifact.compareSourceToBundle is deliberately asymmetric where artifact.compareJsExports is symmetric: it answers "did the build keep what the source declared", so an export missing from the bundle is absent, one the bundle adds is bundle-only, and those are different findings rather than two directions of one diff. The valuable part is what it refuses to conclude - an absent export carries the reason that a minifier renaming it would look identical, and the result repeats as a limitation that absence is not evidence of removal. A tool reporting "one export was removed" would be more satisfying and would be making a claim the evidence does not support. Both sides come from the same reader over different files, composed by reference, so the comparison is pure and replays without reading either file again.',
    },
    {
      family: 'composition', tool: 'artifact.compareJsExports', workspace: 'temp',
      fixture: (dir) => {
        write(dir, 'left.js', 'export const keep = 1;\nexport function drop() {}\n');
        write(dir, 'right.js', 'export const keep = 1;\nexport class fresh {}\n');
      },
      plan: { version: 1, name: 'compose', tasks: [
        { id: 'l', tool: 'artifact.jsExports', input: { path: 'left.js' } },
        { id: 'r', tool: 'artifact.jsExports', input: { path: 'right.js' } },
        { id: 'c', tool: 'artifact.compareJsExports', dependsOn: ['l', 'r'],
          input: { left: { exports: { $task: 'l', path: '/exports' } }, right: { exports: { $task: 'r', path: '/exports' } } } },
      ] },
      expect: (r) => r.results.c.summary.added === 1 && r.results.c.summary.removed === 1
        && r.results.c.summary.unchanged === 1
        && r.results.l.exports.length === 2 && r.results.c.changes.length === 3,
      lesson: 'Two artifact.jsExports scans feed artifact.compareJsExports through /exports pointers in one plan, so the comparison is computed from bytes this run actually read rather than from a summary someone typed in. A JSON pointer selects part of an upstream output, which is what lets a tool expecting a narrow shape consume a tool that returns a wide one.',
    },
    {
      family: 'composition', tool: 'json.value', workspace: 'temp',
      plan: { version: 1, name: 'whole', tasks: [
        { id: 'h', tool: 'json.hash', input: { value: { a: 1 } } },
        { id: 'v', tool: 'json.value', dependsOn: ['h'], input: { value: { $task: 'h' } } },
      ] },
      expect: (r) => typeof r.results.v.value.digest === 'string'
        && r.results.v.value.digest === r.results.h.digest,
      lesson: 'A reference with no path resolves to the whole upstream output, so a task can take another task entire. The resolved value is a clone: a downstream task cannot reach back and mutate the output a receipt was already written for.',
    },
    {
      family: 'composition', tool: 'memory.promote', grant: true, workspace: 'temp', expectApprovals: 1,
      plan: { version: 1, name: 'learn', tasks: [
        { id: 'c', tool: 'memory.candidate', input: { lesson: 'A single plan can earn a lesson and commit it, under a grant bound to what it actually derived.', evidence: [{ exercise: 'composition', proven: true }] } },
        { id: 'p', tool: 'memory.promote', dependsOn: ['c'], input: { $task: 'c' } },
      ] },
      expect: (r, ctx) => r.results.p.promoted === true
        && r.results.p.candidateHash === r.results.c.candidateHash
        && fs.existsSync(path.join(ctx.workspaceRoot, r.results.p.path)),
      lesson: 'memory.candidate derives a lesson and memory.promote commits it inside one plan, the whole candidate passed by a single reference. This is the self-improvement primitive, and it is still gated: the write blocks for an approval whose hash binds the resolved candidate, so granting it approves the lesson that was actually derived rather than a plan that promised to derive one.',
    },
    {
      family: 'composition', tool: 'files.read', grant: true, workspace: 'temp', expectApprovals: 1,
      plan: { version: 1, name: 'roundtrip', tasks: [
        { id: 'h', tool: 'json.hash', input: { value: { round: 'trip' } } },
        { id: 'w', tool: 'files.write', dependsOn: ['h'], input: { path: 'derived.json', content: { $task: 'h' } } },
        { id: 'r', tool: 'files.read', dependsOn: ['w'], input: { path: 'derived.json' } },
      ] },
      expect: (r) => r.results.r.text.includes(r.results.h.digest)
        && typeof r.results.r.sha256 === 'string' && r.results.r.untrusted === true
        && r.results.r.bytes > 0,
      lesson: 'A pure result can be written and read back within one plan, and the file that comes back is still marked untrusted with its own digest reported. Content this run computed itself is given no more standing than content found on disk, because the tool that reads a file cannot know who wrote it.',
    },

    // ---- a malformed reference is a defect in the plan, refused before anything runs ----
    {
      family: 'composition', tool: 'json.value', expectThrow: 'INVALID_REFERENCE', workspace: 'temp',
      plan: { version: 1, name: 'strref', tasks: [
        { id: 'h', tool: 'json.hash', input: { value: 1 } },
        { id: 'v', tool: 'json.value', dependsOn: ['h'], input: { value: '{"$task":"h"}' } },
      ] },
      lesson: 'A reference written as a quoted string is refused with INVALID_REFERENCE rather than passed through as text, and the message says to place the object unquoted as the value. Silently treating it as a literal string is the failure mode this guard exists to prevent: the plan would run, do the wrong thing, and look successful.',
    },
    {
      family: 'composition', tool: 'json.value', expectThrow: 'INVALID_REFERENCE', workspace: 'temp',
      plan: { version: 1, name: 'nodep', tasks: [
        { id: 'h', tool: 'json.hash', input: { value: 1 } },
        { id: 'v', tool: 'json.value', input: { value: { $task: 'h' } } },
      ] },
      lesson: 'A reference to a task that dependsOn does not declare is refused with INVALID_REFERENCE even though the task exists and would have run first. The edge has to be declared, so the dependency graph can be read off the plan without executing it, and an ordering that only happened to work is never mistaken for one that was stated.',
    },
    {
      family: 'composition', tool: 'json.value', expectThrow: 'INVALID_REFERENCE', workspace: 'temp',
      plan: { version: 1, name: 'badptr', tasks: [
        { id: 'h', tool: 'json.hash', input: { value: 1 } },
        { id: 'v', tool: 'json.value', dependsOn: ['h'], input: { value: { $task: 'h', path: 'digest' } } },
      ] },
      lesson: 'A path that is not an RFC 6901 JSON pointer is refused with INVALID_REFERENCE while compiling: a bare key like "digest" is rejected where "/digest" is accepted. Guessing that a bare key meant a top-level one would make the pointer syntax ambiguous exactly where it has to be exact.',
    },
    {
      family: 'composition', tool: 'json.hash', expectThrow: 'INVALID_PLAN', workspace: 'temp',
      plan: { version: 1, name: 'selfdep', tasks: [
        { id: 'h', tool: 'json.hash', dependsOn: ['h'], input: { value: 1 } },
      ] },
      lesson: 'A task declaring itself as its own dependency is refused with INVALID_PLAN at compile time, so a cycle is caught by reading the plan rather than by hanging while running it.',
    },
    {
      family: 'composition', tool: 'json.value', expectThrow: 'INVALID_PLAN', workspace: 'temp',
      plan: { version: 1, name: 'dupdep', tasks: [
        { id: 'h', tool: 'json.hash', input: { value: 1 } },
        { id: 'v', tool: 'json.value', dependsOn: ['h', 'h'], input: { value: { $task: 'h' } } },
      ] },
      lesson: 'The same dependency declared twice is refused with INVALID_PLAN rather than quietly deduplicated. A duplicated edge means the plan was assembled by something that lost track of what it had already written, and accepting it would hide that.',
    },

    // ---- a well-formed reference that does not fit the data fails as a task -------------
    {
      family: 'composition', tool: 'json.value', expectCode: 'INPUT_INVALID',
      expectReason: 'Reference path does not exist', workspace: 'temp',
      plan: { version: 1, name: 'nokey', tasks: [
        { id: 'h', tool: 'json.hash', input: { value: 1 } },
        { id: 'v', tool: 'json.value', dependsOn: ['h'], input: { value: { $task: 'h', path: '/nope' } } },
      ] },
      lesson: 'A well-formed pointer into a key the upstream output does not have fails the task with INPUT_INVALID and the reason that the reference path does not exist. It cannot be caught while compiling, because only the output can say which keys it has; so the plan is legal and the task is the thing that fails.',
    },
    {
      family: 'composition', tool: 'json.value', expectCode: 'INPUT_INVALID',
      expectReason: 'Unsafe reference key', workspace: 'temp',
      plan: { version: 1, name: 'proto', tasks: [
        { id: 'h', tool: 'json.hash', input: { value: 1 } },
        { id: 'v', tool: 'json.value', dependsOn: ['h'], input: { value: { $task: 'h', path: '/__proto__' } } },
      ] },
      lesson: 'A pointer naming __proto__, prototype or constructor is refused as an unsafe reference key rather than resolved. A pointer is attacker-reachable input in a plan Concord did not write, and without this a reference would be a route to the prototype chain; it shares INPUT_INVALID with a merely absent key, so only the reason distinguishes a typo from an attempt.',
    },
  ];
}
