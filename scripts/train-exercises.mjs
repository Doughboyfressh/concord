import fs from 'node:fs';
import path from 'node:path';
import { canonical, digest } from '../src/value.mjs';
import { readerExercises } from './train-exercises-readers.mjs';
import { ghidraExercises } from './train-exercises-ghidra.mjs';
import { evidenceExercises } from './train-exercises-evidence.mjs';
import { writeExercises } from './train-exercises-writes.mjs';
import { webExercises } from './train-exercises-web.mjs';
import { horizonExercises } from './train-exercises-horizon.mjs';
import { hubExercises } from './train-exercises-hub.mjs';
import { serverExercises } from './train-exercises-server.mjs';
import { buildExercises } from './train-exercises-build.mjs';
import { composeExercises } from './train-exercises-compose.mjs';

import { derivedExercises } from './train-exercises-derived.mjs';
import { kernelExercises } from './train-exercises-kernel.mjs';
import { sessionExercises } from './train-exercises-session.mjs';
import { processExercises } from './train-exercises-process.mjs';

/**
 * What Concord is trained on: one entry per thing worth proving.
 *
 * Separated from the harness because widening coverage should mean adding to a list, not editing
 * a runner. Each entry is a real plan plus the prediction it must satisfy, and the lesson that
 * becomes memory only if the run behaved exactly as predicted and then replayed.
 *
 *   family        what part of the system this exercises
 *   plan          a real plan, run through the real kernel
 *   expect        the prediction; false means a finding, not a lesson
 *   expectCode    for refusals: the exact tool code that must be raised
 *   grant         re-attempt once with the precise request hash a block reports
 *   fixture       write real bytes first, because a reader proves nothing against nothing
 *   lesson        what the run demonstrated, in a form worth recalling later
 */

const bytes = (...values) => Buffer.from(values);
const write = (dir, name, content) => fs.writeFileSync(path.join(dir, name), content);

export function exercises(inventory, registry) {
  const skill = (inventory.capabilities ?? []).find((entry) => entry.kind === 'skill' && typeof entry.sourceSha256 === 'string');

  return [
    ...readerExercises(),
    ...ghidraExercises(),
    ...evidenceExercises(),
    ...writeExercises(),
    ...webExercises(registry),
    ...horizonExercises(),
    ...hubExercises(),
    ...serverExercises(),
    ...buildExercises(),
    ...composeExercises(),
    ...derivedExercises(registry),
    ...kernelExercises(),
    ...sessionExercises(),
    ...processExercises(),

    // ---- determinism -----------------------------------------------------------------
    {
      family: 'determinism', tool: 'json.hash',
      // Round 021 learned this the hard way: passing { value: ... } hashed the wrapper, because
      // in a plan json.hash's input IS the value. That wrapper is an MCP-surface artefact.
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'json.hash', input: { b: 2, a: 1 } }] },
      expect: (r) => r.results.a.digest === digest({ a: 1, b: 2 }),
      lesson: 'json.hash hashes its entire input and, in a plan, that input IS the value: the {value: ...} wrapper exists only on the MCP surface, where a tool whose schema is not an object schema gets wrapped. A plan passing {value: X} hashes the wrapper, not X. Key order never matters either way, because canonicalisation happens first.',
    },
    {
      family: 'determinism', tool: 'json.assert',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'json.assert', input: { value: { n: 5 }, schema: { type: 'object', properties: { n: { type: 'number', minimum: 0 } }, required: ['n'] } } }] },
      expect: (r) => r.results.a.passed === true,
      lesson: 'json.assert returns a verdict carrying an evidence hash rather than a bare boolean, so a validation result can be cited later by that hash.',
    },
    {
      family: 'refusal', tool: 'json.assert',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'json.assert', input: { value: { n: -1 }, schema: { type: 'object', properties: { n: { type: 'number', minimum: 0 } }, required: ['n'] } } }] },
      expect: (r) => r.outcome.status === 'failed',
      lesson: 'A failing json.assert fails the task rather than returning passed:false, so a plan cannot continue past a violated invariant by ignoring a boolean.',
    },

    // ---- values ----------------------------------------------------------------------
    {
      family: 'values', tool: 'json.value',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'json.value', input: { n: 1 } }] },
      expect: (r) => canonical(r.results.a) === canonical({ n: 1 }),
      lesson: 'json.value returns its input unchanged after canonical validation, which makes it the way to pin a literal into a plan that later tasks can depend on.',
    },
    {
      family: 'values', tool: 'json.mergeShallow',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'json.mergeShallow', input: { values: [{ a: 1 }, { b: 2 }] } }] },
      expect: (r) => canonical(r.results.a.value) === canonical({ a: 1, b: 2 }),
      lesson: 'json.mergeShallow takes a values array and merges it as a disjoint union, not as a patch applied over a base: there is no last-writer-wins, which is why it needs no notion of order.',
    },
    {
      family: 'values', tool: 'text.concat',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'text.concat', input: { values: ['a', 'b', 'c'], separator: '-' } }] },
      expect: (r) => (r.results.a.value ?? r.results.a.text) === 'a-b-c',
      lesson: 'text.concat is bounded at 1000 values of 65536 characters each, so building a string inside a plan cannot become an unbounded allocation.',
    },

    // ---- knowledge and provenance ----------------------------------------------------
    {
      family: 'sources', tool: 'sources.catalog',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'sources.catalog', input: {} }] },
      // The count is asserted deliberately rather than read from the lock, so pinning a source
      // without reviewed instructions for it is a finding here. The kernel enforces the same
      // bijection at CHAT_CONTEXT, and this exercise is the cheaper place to notice.
      expect: (r) => Array.isArray(r.results.a.sources) && r.results.a.sources.length === 14,
      lesson: 'sources.catalog reports 14 pinned upstream sources as inert provenance: listing a source is not a claim that its runtime is installed or that its tools exist here. Eleven are Git repositories pinned by commit, two are explicitly unpinned website observations, and one is a release archive pinned by its release identifier rather than by a revision.',
    },
    {
      family: 'knowledge', tool: 'capabilities.search',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'capabilities.search', input: { query: 'deterministic replay', limit: 5 } }] },
      expect: (r) => r.results.a.grantsCapabilities === false,
      lesson: 'capabilities.search answers from an inert index and states grantsCapabilities:false on every reply: finding a capability is never the same as acquiring one.',
    },
    {
      family: 'ranking', tool: 'skills.rank',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'skills.rank', input: { query: 'hello there', skills: [{ id: 'greet', text: 'say hello politely' }, { id: 'apk', text: 'inspect android packages' }] } }] },
      expect: (r) => r.results.a.ranked[0].id === 'greet' && r.results.a.strategy === 'lexical-overlap-v1',
      lesson: 'skills.rank is lexical-overlap-v1, not semantic: it scores shared tokens, so a corpus entry matching on one common word can outrank a relevant entry sharing none. Near-duplicate entries therefore crowd the top of a result list.',
    },
    {
      family: 'catalog', tool: 'rea.catalog',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'rea.catalog', input: {} }] },
      expect: (r) => r.results.a.total === 117,
      lesson: 'rea.catalog reports all 117 REA tools with the realization route of each, keeping visible the difference between a reader Concord wrote and a bounded call to an operator-reviewed binary.',
    },
    {
      family: 'foreign', tool: 'foreign.catalog',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'foreign.catalog', input: {} }] },
      expect: (r) => r.results.a.grantsCapabilities === false && r.results.a.availableNow === 0,
      lesson: 'foreign.catalog reports availableNow:0 until an operator both configures a server and allow-lists a tool: importing a capability manifest grants nothing by itself.',
    },

    // ---- formats, against real bytes -------------------------------------------------
    ...[
      { format: 'zip', name: 'a.zip', content: bytes(0x50, 0x4b, 0x03, 0x04, 0, 0) },
      { format: 'png', name: 'a.png', content: bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0) },
      { format: 'wasm', name: 'a.wasm', content: bytes(0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0) },
    ].map((entry) => ({
      family: 'formats', tool: 'artifact.inspect', workspace: 'temp',
      fixture: (dir) => write(dir, entry.name, entry.content),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.inspect', input: { path: entry.name } }] },
      expect: (r) => r.results.a.format === entry.format,
      lesson: `artifact.inspect identifies ${entry.format} from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read.`,
    })),
    {
      family: 'formats', tool: 'artifact.inspect', workspace: 'temp',
      // An extension that lies is the ordinary case this has to survive.
      fixture: (dir) => write(dir, 'lies.png', bytes(0x50, 0x4b, 0x03, 0x04, 0, 0)),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.inspect', input: { path: 'lies.png' } }] },
      expect: (r) => r.results.a.format === 'zip',
      lesson: 'A file named .png whose bytes are a zip is reported as a zip: artifact.inspect reads content, so a wrong extension cannot mislead anything downstream of it.',
    },
    {
      family: 'evidence', tool: 'artifact.inspect',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.inspect', input: { path: 'package.json' } }] },
      expect: (r) => typeof r.results.a.sha256 === 'string',
      lesson: 'artifact.inspect binds every claim to a digest of the bytes it read, so a later statement about a file can be checked against the exact content that produced it.',
    },

    // ---- readers ---------------------------------------------------------------------
    {
      family: 'readers', tool: 'artifact.sourceMap', workspace: 'temp',
      fixture: (dir) => write(dir, 'a.map', JSON.stringify({ version: 3, sources: ['a.ts'], names: [], mappings: 'AAAA' })),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.sourceMap', input: { path: 'a.map' } }] },
      expect: (r) => Array.isArray(r.results.a.sources) && r.results.a.sources.length === 1,
      lesson: 'artifact.sourceMap decodes VLQ mappings field by field rather than trusting a library: only generatedColumn resets per line, so a decoder resetting the others would report plausible wrong origins.',
    },
    {
      family: 'readers', tool: 'artifact.harCapture', workspace: 'temp',
      fixture: (dir) => write(dir, 'a.har', JSON.stringify({ log: { version: '1.2', entries: [{ request: { method: 'GET', url: 'https://example.test/x' }, response: { status: 200 } }] } })),
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'artifact.harCapture', input: { path: 'a.har' } }] },
      expect: (r) => Array.isArray(r.results.a.entries) && r.results.a.entries.length === 1 && r.results.a.untrusted === true,
      lesson: 'artifact.harCapture reports a capture structurally and copies no headers, cookies or bodies out of it: a HAR is full of credentials, so the reader withholds them by construction rather than by redaction.',
    },

    // ---- governance ------------------------------------------------------------------
    {
      family: 'governance', tool: 'hooks.evaluate',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'hooks.evaluate', input: { rules: [{ id: 'ok', decision: 'allow' }, { id: 'no', decision: 'deny', when: { effect: 'write' } }], event: { tool: 'files.write', effect: 'write' } } }] },
      expect: (r) => r.results.a.decision === 'deny',
      lesson: 'hooks.evaluate returns the strictest matching decision, so an allow rule never cancels a deny that also matched. It reports a decision and enforces nothing.',
    },
    {
      family: 'delegation', tool: 'agent.delegate',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'agent.delegate', input: { plan: { version: 1, tasks: [{ id: 'w', tool: 'files.write', input: { path: 'nope.json', content: { a: 1 } } }] } } }] },
      expect: (r) => r.results.a.status === 'blocked' && r.results.a.blocked[0].tool === 'files.write',
      lesson: 'agent.delegate hands its sub-plan no approvals, so a write inside returns a recorded blocked event naming the tool rather than failing to compile or running on borrowed authority.',
    },
    {
      family: 'scheduling', tool: 'schedule.due',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'schedule.due', input: { now: '2000-01-01T00:00:00Z' } }] },
      expect: (r) => Array.isArray(r.results.a.due),
      lesson: 'schedule.due answers against a time the caller supplies, never a clock the kernel reads, which is what keeps a scheduling answer reproducible on replay.',
    },
    {
      family: 'scheduling', tool: 'schedule.declare', grant: true, workspace: 'temp', expectApprovals: 1,
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'schedule.declare', input: { id: 'trained-sweep', dueAt: '2027-01-01T00:00:00Z', plan: { version: 1, tasks: [] } } }] },
      expect: (r) => r.results.a.replaced === false && typeof r.results.a.planHash === 'string',
      lesson: 'schedule.declare is a write and takes a grant like any other, and it stores the plan hash: re-declaring the same id replaces it, which is how a finished schedule is advanced.',
    },

    // ---- judgment, comparison, memory, exchange --------------------------------------
    {
      family: 'judgment', tool: 'judgment.gate',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'judgment.gate', input: { score: 0.9, threshold: 0.8, evidence: { why: 'training' } } }] },
      expect: (r) => r.results.a.accepted === true && r.results.a.grantsCapabilities === false,
      lesson: 'judgment.gate reports accepted rather than passed, and states grantsCapabilities:false on the way out: clearing a quality bar is a judgement about a score, never permission to do anything.',
    },
    {
      family: 'comparison', tool: 'experiment.compare',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'experiment.compare', input: { hypothesis: 'a bound below the input length refuses it', conditions: [{ name: 'roomy', varied: { bound: 10 }, expected: 'accepted', actual: 'accepted' }, { name: 'tight', varied: { bound: 1 }, expected: 'refused', actual: 'refused' }] } }] },
      expect: (r) => r.results.a.discriminating === true && canonical(r.results.a.confirmed) === canonical(['roomy', 'tight']) && r.results.a.warnings.length === 0,
      lesson: 'experiment.compare is a hypothesis test across named conditions, not a diff. confirmed, refuted and untestable are arrays of condition names rather than booleans, so an untested condition can never read as a passing one.',
    },
    {
      family: 'comparison', tool: 'experiment.compare',
      // Round 022 found this rather than predicting it, and it is the better lesson of the two.
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'experiment.compare', input: { hypothesis: 'the bound matters', conditions: [{ name: 'small', varied: { bound: 10 }, expected: 'accepted', actual: 'accepted' }, { name: 'large', varied: { bound: 1 }, expected: 'accepted', actual: 'refused' }] } }] },
      expect: (r) => r.results.a.discriminating === false && r.results.a.warnings[0].code === 'NONDISCRIMINATING_EXPECTATION',
      lesson: 'experiment.compare warns NONDISCRIMINATING_EXPECTATION and reports discriminating:false when every condition declares the same expectation: an experiment whose conditions all expect the same outcome cannot distinguish the factor it varied from one that would pass regardless, so a green result there proves nothing.',
    },
    {
      family: 'memory', tool: 'memory.candidate',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'memory.candidate', input: { lesson: 'A candidate is not yet memory.', evidence: [{ note: 'training' }] } }] },
      expect: (r) => typeof r.results.a.candidateHash === 'string',
      lesson: 'memory.candidate is pure and yields only a content hash: nothing is remembered until memory.promote writes it under its own exact grant, so drafting a lesson costs no authority.',
    },
    {
      family: 'memory', tool: 'memory.recall',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'memory.recall', input: { query: 'approval grant hash', limit: 3 } }] },
      expect: (r) => r.results.a.strategy === 'lexical-overlap-v1' && r.results.a.corruptedEntries === 0,
      lesson: 'memory.recall is lexical, and it counts stored entries it could not parse rather than skipping them silently: a corrupted lesson is reported, not hidden.',
    },
    {
      family: 'exchange', tool: 'peer.inbox',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'peer.inbox', input: { unanswered: true } }] },
      expect: (r) => typeof r.results.a.openQuestions === 'number',
      lesson: 'peer.inbox reports open questions without consuming them: reading never removes a letter, because a tool that quietly drained the mailbox would make a lost message look like one that was never sent.',
    },

    // ---- skills ----------------------------------------------------------------------
    {
      family: 'skills', tool: 'skills.snapshot', needsCorpus: skill ? skill.path : 'nothing',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'skills.snapshot', input: skill ? { path: skill.path, sourceId: skill.sourceId } : { path: 'x', sourceId: 'x' } }] },
      expect: (r) => r.results.a !== undefined,
      lesson: 'skills.snapshot reads one named file and requires both its path and its sourceId: it is a read of a specific reviewed artefact rather than a browse, so a snapshot always says which source it came from.',
    },
    {
      family: 'skills', tool: 'skills.installed', workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'skills.installed', input: {} }] },
      expect: (r) => r.results.a.count === 0 && Array.isArray(r.results.a.installed),
      lesson: 'skills.installed reads an empty store as empty rather than failing, and separates a changed local copy from a changed upstream so a local edit is never reported as an update.',
    },

    // ---- the approval loop itself ----------------------------------------------------
    {
      family: 'approval', tool: 'files.write', grant: true, workspace: 'temp', expectApprovals: 1,
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'files.write', input: { path: 'trained.json', content: { ok: true } } }] },
      expect: (r, ctx) => r.outcome.status === 'completed' && fs.existsSync(path.join(ctx.workspaceRoot, 'trained.json')),
      lesson: 'A write blocks once with an exact request hash and runs only when that same hash is granted; the hash binds the resolved input, so an approval can never be reused for a different write.',
    },
    ...(skill ? [{
      family: 'skills', tool: 'skills.install', grant: true, workspace: 'temp', expectApprovals: 1, needsCorpus: skill.path,
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'skills.install', input: { id: skill.id } }] },
      expect: (r) => r.outcome.status === 'completed' && r.results.a.sha256 === skill.sourceSha256,
      lesson: 'skills.install verifies a file against the digest the inventory recorded before copying it, so an adopted skill is provably the reviewed bytes rather than whatever happens to be on disk now.',
    }, {
      family: 'composition', tool: 'judgment.gate', workspace: 'temp', needsCorpus: skill.path,
      fixture: (dir) => write(dir, 'a.map', JSON.stringify({ version: 3, file: 'out.js', sources: ['a.js'], names: [], mappings: 'AAAA' })),
      plan: { version: 1, name: 'six-reads-and-judgements-together', tasks: [
        { id: 'gate', tool: 'judgment.gate', input: { score: 0.9, threshold: 0.8, evidence: { why: 'a composed training exercise' } } },
        { id: 'hooks', tool: 'hooks.evaluate', input: {
          rules: [{ id: 'warn-reads', decision: 'warn', reason: 'a read still sees untrusted bytes', when: { effect: 'read' } }],
          event: { tool: 'artifact.sourceMap', effect: 'read', input: { path: 'a.map' } },
        } },
        { id: 'lessons', tool: 'instructions.lesson', input: { ids: ['nothing:such-lesson'] } },
        { id: 'foreign', tool: 'foreign.catalog', input: {} },
        { id: 'map', tool: 'artifact.sourceMap', input: { path: 'a.map' } },
        { id: 'snapshot', tool: 'skills.snapshot', input: { path: skill.path, sourceId: skill.sourceId } },
      ] },
      expect: (r) => r.results.gate.accepted === true && r.results.gate.grantsCapabilities === false
        && r.results.hooks.decision === 'warn' && r.results.hooks.matched.length === 1
        && r.results.lessons.requested === 1 && r.results.lessons.returned === 0
        && r.results.lessons.missing.length === 1
        && r.results.foreign.grantsCapabilities === false && r.results.foreign.availableNow === 0
        && r.results.map.supported === true && r.results.map.path === 'a.map'
        && r.results.map.sources.length === 1 && r.results.map.mappingCount >= 1
        && r.results.map.untrusted === true
        && r.results.snapshot !== undefined,
      lesson: 'Six reads and judgements in one plan, which is the turn a session actually takes before proposing anything: a score checked against a threshold, a rule set consulted about the read that is about to happen, a lesson looked up by id, a catalogue of tools that are not installed here, a source map parsed, and a reviewed skill snapshotted. Not one of them needs an approval and not one of them grants anything — the gate says grantsCapabilities:false in the same breath as accepting, the catalogue says it while listing, and the hook warns without stopping. That is the shape of everything a plan can establish before it asks for authority, and establishing it first is what makes a later blocked effect cheap to review: the evidence behind the request already exists and is already hashed.',
    }, {
      family: 'composition', tool: 'skills.installed', grant: true, workspace: 'temp', expectApprovals: 2, needsCorpus: skill.path,
      plan: { version: 1, name: 'adopt-list-and-drop-a-skill', tasks: [
        { id: 'adopt', tool: 'skills.install', input: { id: skill.id } },
        { id: 'listed', tool: 'skills.installed', dependsOn: ['adopt'], input: {} },
        // The id the removal acts on comes from the installation's own result, not restated here.
        { id: 'drop', tool: 'skills.remove', dependsOn: ['adopt', 'listed'], input: { id: { $task: 'adopt', path: '/id' } } },
        { id: 'after', tool: 'skills.installed', dependsOn: ['drop'], input: {} },
      ] },
      expect: (r) => r.results.adopt.sha256 === skill.sourceSha256
        && r.results.adopt.status === 'source-available-unreviewed'
        && r.results.adopt.installedAs.startsWith('skills/')
        && r.results.adopt.bytes > 0
        && r.results.adopt.limitations.some((note) => note.includes('grants nothing'))
        && r.results.listed.count === 1 && r.results.listed.installed.length === 1
        && r.results.listed.changed === 0 && r.results.listed.missing === 0 && r.results.listed.upstreamChanged === 0
        && r.results.listed.installed[0].id === r.results.adopt.id
        && r.results.listed.installed[0].lockedSha256 === skill.sourceSha256
        && r.results.listed.installed[0].present === true && r.results.listed.installed[0].localChanged === false
        && r.results.listed.installed[0].status === r.results.adopt.status
        && r.results.drop.removed === true && r.results.drop.fileRemoved === true
        && r.results.drop.id === r.results.adopt.id && r.results.drop.remaining === 0
        && r.results.after.count === 0 && r.results.after.installed.length === 0,
      lesson: 'The whole skill lifecycle composes in one plan: adopt a reviewed skill, list what is installed, remove it by the id the installation itself reported, and list again. Two writes mean two approval hashes, each bound to its own resolved input, and the removal takes its id by reference rather than by restating it — so the plan cannot drift into removing something other than what it installed. The lock records the digest the inventory declared and the listing reports the installed copy against it, so localChanged distinguishes a skill someone edited in the workspace from one still matching its source, and upstreamChanged distinguishes a source that has moved on. Every stage repeats that an installed skill is inert text: installing it executes nothing and grants nothing, and the status the inventory recorded travels with it, so an unreviewed source stays unreviewed after adoption. Removal reports both that the lock entry went and that the file went, which are two different facts — a lock entry without its file, or a file without its entry, is the state worth being able to name.',
    }] : []),

    {
      family: 'composition', tool: 'json.mergeShallow',
      plan: { version: 1, name: 'nine-kernel-tools-in-one-chain', tasks: [
        { id: 'pinned', tool: 'json.value', input: { reading: 1 } },
        { id: 'hashed', tool: 'json.hash', dependsOn: ['pinned'], input: { $task: 'pinned' } },
        { id: 'merged', tool: 'json.mergeShallow', input: { values: [{ a: 1 }, { b: 2 }] } },
        { id: 'joined', tool: 'text.concat', dependsOn: ['hashed'], input: {
          values: ['digest', { $task: 'hashed', path: '/digest' }], separator: ':',
        } },
        { id: 'checked', tool: 'json.assert', dependsOn: ['merged'], input: {
          value: { $task: 'merged', path: '/value/a' }, schema: { const: 1 },
        } },
        { id: 'ranked', tool: 'skills.rank', input: { query: 'deterministic replay', skills: [
          { id: 'replay', text: 'deterministic replay of a recorded run' },
          { id: 'unrelated', text: 'something else entirely' },
        ] } },
        { id: 'searched', tool: 'capabilities.search', input: { query: 'deterministic replay', limit: 3 } },
        { id: 'sources', tool: 'sources.catalog', input: {} },
        { id: 'drafted', tool: 'memory.candidate', dependsOn: ['hashed', 'ranked'], input: {
          lesson: 'A chain of pure and read tools can carry one value from end to end without any effect.',
          evidence: [{ $task: 'hashed' }, { $task: 'ranked', path: '/strategy' }],
        } },
      ] },
      expect: (r) => canonical(r.results.pinned) === canonical({ reading: 1 })
        && r.results.hashed.digest === digest({ reading: 1 })
        && canonical(r.results.merged.value) === canonical({ a: 1, b: 2 })
        // The reference resolved to the digest string and the join used it verbatim.
        && (r.results.joined.value ?? r.results.joined.text) === `digest:${r.results.hashed.digest}`
        && r.results.checked.passed === true
        && r.results.ranked.ranked[0].id === 'replay'
        && r.results.ranked.strategy === 'lexical-overlap-v1'
        && r.results.searched.grantsCapabilities === false
        && r.results.sources.sources.length === 14
        && r.results.drafted.evidenceHashes.length === 2
        && r.results.drafted.status === 'proposed' && r.results.drafted.executable === false,
      lesson: 'Nine pure and read tools in one plan, with a single value carried from end to end: a literal pinned into the plan, hashed, the digest spliced into a string by reference, and that same digest filed as one of two pieces of evidence on a memory candidate. Nothing in the chain requires an approval, because nothing in it leaves the process — which is what makes this the shape to reach for first: everything a plan can establish without an effect should be established before an effect is proposed, since a blocked write is cheaper to review when the evidence behind it already exists and is hashed. The candidate at the end is still marked proposed and not executable, so a chain of nine verified steps produces a claim rather than a permission.',
    },

    // ---- the strictest rule wins, and nothing is enforced ------------------------------
    {
      family: 'governance', tool: 'hooks.evaluate',
      plan: { version: 1, name: 'one-allow-one-deny', tasks: [
        { id: 'verdict', tool: 'hooks.evaluate', input: {
          rules: [
            { id: 'allow-reads', decision: 'allow', when: { effect: 'read' } },
            { id: 'warn-artifacts', decision: 'warn', reason: 'artifact readers see untrusted bytes', when: { toolPrefix: 'artifact.' } },
            { id: 'deny-secrets', decision: 'deny', reason: 'that path holds credentials', when: { pathPrefix: 'secrets/' } },
            { id: 'never-matches', decision: 'deny', reason: 'unrelated', when: { tool: 'files.write' } },
          ],
          event: { tool: 'artifact.inspect', effect: 'read', input: { path: 'secrets/key.pem' } },
        } },
      ] },
      expect: (r) => r.results.verdict.decision === 'deny'
        && r.results.verdict.evaluated === 4
        && r.results.verdict.matched.map((entry) => entry.id).join(',') === 'allow-reads,warn-artifacts,deny-secrets'
        && r.results.verdict.matched.find((entry) => entry.id === 'allow-reads').reason === null
        && r.results.verdict.reasons.length === 2
        && r.results.verdict.limitations.some((note) => note.includes('does not enforce'))
        && r.results.verdict.limitations.some((note) => note.includes('hidden control flow')),
      lesson: 'hooks.evaluate is a pure verdict about an event, and three of its properties are deliberate. The strictest matching decision wins, so a rule set where one rule allows and another denies has not expressed a preference and the deny stands — treating deny as the weaker side would make the safer rule the easiest to cancel by accident. Every matching rule is listed with its own decision and reason even though only one decides, because an operator reading a deny needs to know what else fired. And it enforces nothing: it reports, a caller that ignores a deny is not stopped, and no host command runs on any tool-call boundary, because hidden control flow at effect boundaries is the thing this kernel exists to remove. A matched rule with no reason reports null rather than being dropped from the list.',
    },
    {
      family: 'catalog', tool: 'rea.catalog',
      plan: { version: 1, name: 'ask-a-catalog-what-it-holds', tasks: [
        { id: 'all', tool: 'rea.catalog', input: {} },
        { id: 'matched', tool: 'rea.catalog', input: { query: 'disassemble' } },
      ] },
      expect: (r) => r.results.all.total === 117 && r.results.all.schemaVersion >= 1
        && typeof r.results.all.revision === 'string'
        && r.results.all.grantsCapabilities === false
        && r.results.all.availableNow <= r.results.all.total
        && r.results.all.matched === r.results.all.total
        && r.results.matched.matched < r.results.all.matched
        && r.results.matched.matched === r.results.matched.tools.length
        && r.results.matched.total === r.results.all.total,
      lesson: 'A catalog answers three different counts and keeping them apart is the point: total is everything the pinned table declares, availableNow is how much of it this machine could actually reach, and matched is how much of it answered the query. A query narrows matched while leaving total alone, so "there are 117 of these" and "I found 4 of them" and "I could run n of them here" never collapse into one number. grantsCapabilities is false on every reply, which is the same statement sources.catalog makes: finding a capability in a catalogue is not acquiring it, and the revision travels with the answer so a count can be rechecked against the table it came from.',
    },
    {
      family: 'catalog', tool: 'foreign.catalog',
      plan: { version: 1, name: 'a-catalog-of-things-not-installed', tasks: [
        { id: 'all', tool: 'foreign.catalog', input: {} },
      ] },
      expect: (r) => r.results.all.grantsCapabilities === false
        && r.results.all.availableNow === 0
        && r.results.all.schemaVersion >= 1
        && Array.isArray(r.results.all.sources)
        && r.results.all.matched === r.results.all.total
        && r.results.all.tools.length === r.results.all.matched,
      lesson: 'The foreign catalogue reports availableNow as zero while still listing what it knows, which is exactly the distinction a reader needs: the manifest describes tools belonging to other projects, and nothing in this workspace is configured to run any of them. A catalogue that hid unavailable entries would answer "there is no such tool" to a question whose true answer is "that tool exists and is not wired up here", and those lead to different next steps. Listing the sources beside the tools is what makes the second answer actionable.',
    },
    {
      family: 'instructions', tool: 'instructions.lesson',
      plan: { version: 1, name: 'fetch-a-lesson-that-is-not-there', tasks: [
        { id: 'asked', tool: 'instructions.lesson', input: { ids: ['nothing:such-lesson', 'also:absent'] } },
      ] },
      expect: (r) => r.results.asked.requested === 2 && r.results.asked.returned === 0
        && r.results.asked.lessons.length === 0 && r.results.asked.missing.length === 2
        && r.results.asked.missing.join(',') === 'also:absent,nothing:such-lesson'
        && Array.isArray(r.results.asked.limitations),
      lesson: 'Asking for lessons that do not exist returns a result rather than a refusal: requested two, returned none, and both ids named in missing. A batch fetch that failed on the first unknown id would be the wrong shape for its actual caller, which is usually working from an omission record a turn or two old and needs the lessons that are still there plus an honest list of the ones that went stale. The missing ids come back sorted, so the answer is the same whatever order they were asked in.',
    },

    // ---- delegation: a sub-plan that runs on no authority of its own --------------------
    {
      family: 'authority', tool: 'agent.delegate',
      plan: { version: 1, name: 'delegate-something-harmless', tasks: [
        { id: 'sub', tool: 'agent.delegate', input: {
          plan: { version: 1, name: 'inner', tasks: [{ id: 's', tool: 'json.hash', input: { delegated: true } }] },
          note: 'a pure sub-plan',
        } },
        { id: 'checked', tool: 'json.assert', dependsOn: ['sub'], input: {
          value: { $task: 'sub', path: '/authority/approvals' }, schema: { const: 0 },
        } },
      ] },
      expect: (r) => r.results.sub.status === 'completed'
        && r.results.sub.taskCount === 1 && typeof r.results.sub.root === 'string'
        && r.results.sub.rejection === null && r.results.sub.blocked.length === 0
        && r.results.sub.results.s.digest === digest({ delegated: true })
        && r.results.sub.authority.approvals === 0
        // Exactly one tool fewer than the caller holds, and the missing one is itself.
        && r.results.sub.authority.allowedTools === registry.size - 1
        && r.results.sub.limitations.length === 2
        && r.results.checked.passed === true,
      lesson: 'agent.delegate runs a sub-plan and reports its whole outcome as data: the status, each task result, the Merkle root of the delegated run, and the authority it was given. It is a read effect, so delegating costs no approval of its own, and the authority it reports is the point — zero approvals, and a registry one tool smaller than the caller\'s, because the delegate cannot delegate. The sub-plan\'s results are recorded rather than adopted: nothing it produced has authority over the caller, and a later task that wants to rely on a delegated value has to read it by reference and say so, which is what the json.assert here does with the approval count itself.',
    },
    {
      family: 'authority', tool: 'agent.delegate', workspace: 'temp',
      plan: { version: 1, name: 'delegate-a-write-and-watch-it-not-happen', tasks: [
        { id: 'sub', tool: 'agent.delegate', input: {
          plan: { version: 1, name: 'inner', tasks: [{ id: 's', tool: 'files.write', input: { path: 'delegated-write.json', content: { n: 1 } } }] },
        } },
      ] },
      expect: (r, ctx) => r.outcome.status === 'completed'
        // The *caller's* task completed; the delegated plan is the thing that blocked.
        && r.results.sub.status === 'blocked'
        && r.results.sub.blocked.length === 1
        && r.results.sub.blocked[0].tool === 'files.write'
        && r.results.sub.blocked[0].effect === 'write'
        && r.results.sub.blocked[0].taskId === 's'
        && Object.keys(r.results.sub.results).length === 0
        && r.results.sub.authority.approvals === 0
        && r.results.sub.limitations.some((note) => note.includes('comes back blocked rather than performed'))
        // The guarantee, checked against the filesystem rather than taken from the report.
        && !fs.existsSync(path.join(ctx.workspaceRoot, 'delegated-write.json')),
      lesson: 'A delegated write does not happen. The delegate is handed an empty approvals list, so the write reaches the approval gate and comes back as a recorded blocked event naming the task, the tool and the effect — and the file is not on disk, which this exercise checks directly rather than believing the report. The caller\'s own task still completes, because "the sub-plan was blocked" is an answer and not a failure. Worth knowing why the effect list is left alone instead of being attenuated to pure and read: that would make the write fail to compile as POLICY_DENIED, which is equally unable to run but says nothing about what was attempted. Both refuse; only one leaves a record of the request, and a record is what an operator needs in order to grant it deliberately later.',
    },
    {
      family: 'authority', tool: 'agent.delegate',
      plan: { version: 1, name: 'a-delegate-cannot-delegate', tasks: [
        { id: 'sub', tool: 'agent.delegate', input: {
          plan: { version: 1, name: 'inner', tasks: [{ id: 's', tool: 'agent.delegate', input: {
            plan: { version: 1, name: 'deeper', tasks: [{ id: 'i', tool: 'json.hash', input: { deep: true } }] },
          } }] },
        } },
      ] },
      expect: (r) => r.outcome.status === 'completed'
        && r.results.sub.status === 'rejected'
        && r.results.sub.rejection.code === 'UNKNOWN_TOOL'
        && r.results.sub.root === null
        && r.results.sub.blocked.length === 0
        && Object.keys(r.results.sub.results).length === 0
        && r.results.sub.limitations.length === 1
        && r.results.sub.limitations[0].includes('refused before anything ran'),
      lesson: 'A delegated plan naming agent.delegate is rejected UNKNOWN_TOOL, because the registry handed to a delegate has that tool removed — recursion there would let a caller spend its whole budget on bookkeeping, and nothing needs it. The rejection is reported rather than thrown: status rejected, a root of null since no run happened, and a single limitation saying the plan was refused before anything ran, so a caller gets the same shape of answer whether the sub-plan ran, blocked or would not compile. A plan naming any other unregistered tool comes back identically, which is the honest reading — from inside a delegate, a tool that was taken away and a tool that never existed are the same fact.',
    },

    // ---- refusals, each naming its own code ------------------------------------------
    {
      family: 'refusal', tool: 'json.mergeShallow', expectCode: 'MERGE_COLLISION',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'json.mergeShallow', input: { values: [{ a: 1 }, { a: 2 }] } }] },
      lesson: 'json.mergeShallow refuses a key appearing in two inputs with MERGE_COLLISION rather than letting one silently win. A merge that picks a winner hides the disagreement that made two values exist.',
    },
    {
      family: 'refusal', tool: 'files.read', expectCode: 'PATH_DENIED',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'files.read', input: { path: '../escape.json' } }] },
      lesson: 'files.read refuses a path climbing out of the workspace with PATH_DENIED, checked segment by segment, so containment never depends on the caller having normalised anything.',
    },
    {
      family: 'refusal', tool: 'files.read', expectCode: 'PATH_DENIED',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'files.read', input: { path: 'C:/Windows/win.ini' } }] },
      lesson: 'An absolute path is refused as PATH_DENIED rather than read: only unambiguous relative workspace paths are accepted, which is what makes the workspace boundary mean anything.',
    },
    {
      family: 'refusal', tool: 'skills.install', expectCode: 'SKILL_UNKNOWN', grant: true, workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'skills.install', input: { id: 'nobody:such/skill.md' } }] },
      lesson: 'skills.install refuses an unknown id with SKILL_UNKNOWN, but only once the write is granted: the approval gate sits in front of the tool, so a write tool blocks before it can tell you the request was nonsense. Round 022 learned this by predicting the refusal and getting a block instead.',
    },
    {
      family: 'refusal', tool: 'schedule.declare', expectCode: 'SCHEDULE_TIME', grant: true, workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'schedule.declare', input: { id: 'bad-time', dueAt: 'next tuesday', plan: { version: 1, tasks: [] } } }] },
      lesson: 'schedule.declare refuses a time it cannot parse as an instant with SCHEDULE_TIME, because a schedule compared as text rather than as an instant would come due at the wrong moment.',
    },
    {
      family: 'refusal', tool: 'agent.delegate', expectCode: 'DELEGATE_PLAN',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'agent.delegate', input: { plan: { version: 1, tasks: [] } } }] },
      lesson: 'agent.delegate refuses an empty sub-plan with DELEGATE_PLAN rather than returning a vacuous success, so a delegation that would have done nothing is reported as the mistake it is.',
    },
  ];
}
