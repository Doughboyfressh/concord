import fs from 'node:fs';
import path from 'node:path';
import { canonical, digest } from '../src/value.mjs';

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

export function exercises(inventory) {
  const skill = (inventory.capabilities ?? []).find((entry) => entry.kind === 'skill' && typeof entry.sourceSha256 === 'string');

  return [
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
      expect: (r) => Array.isArray(r.results.a.sources) && r.results.a.sources.length === 13,
      lesson: 'sources.catalog reports 13 pinned upstream sources as inert provenance: listing a source is not a claim that its runtime is installed or that its tools exist here.',
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
    }] : []),

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
