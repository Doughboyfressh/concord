import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { buildChatContext } from '../src/chat-context.mjs';
import { createChatHarness } from '../src/chat.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';
import { makeCapabilityTools } from '../src/capabilities.mjs';
import { loadSourceLock, makeSourceTools } from '../src/sources.mjs';
import { parseJson, digest } from '../src/value.mjs';
import { tempDir } from './temp-workspace.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
const inventory = parseJson(fs.readFileSync(path.join(root, 'capabilities.lock.json'), 'utf8'));
function setup(workspaceRoot, additional = []) {
  const descriptors = [...makeBuiltinTools(), ...makeCapabilityTools(inventory), ...makeSourceTools(catalog), ...additional];
  const registry = new Map(descriptors.map(t => [t.name, t]));
  const context = ({message,history,observations,proposedPlan,policy}) => buildChatContext({message,history,observations,proposedPlan,policy,sourceLock:catalog,inventory,registry,instructionRoot:path.join(root,'instructions')});
  return createChatHarness({registry,policy:{version:1,allowedTools:[...registry.keys()],allowedEffects:['pure','read','write','network'],maxTasks:32,maxOutputBytes:1048576,maxJournalBytes:16777216,timeoutMs:10000},sourceLock:catalog,workspaceRoot,buildContext:context});
}

test('chat uses all thirteen reviewed instruction modules and executes/replays its evidence plan', async () => {
  const temp = tempDir('concord-chat-flow-');
  try {
    const harness = setup(temp);
    const turn = await harness.send('Combine deterministic replay, browser tools, security review and memory in this chat harness.');
    assert.equal(turn.mode, 'offline-demo');
    assert.equal(turn.sourceCoverage.length, 13);
    assert.ok(turn.history.some(m => m.role === 'assistant' && m.content.length));
    assert.ok(turn.proposedPlan?.tasks.length);
    const state = await harness.executePlan();
    assert.ok(state.runs.some(r => r.status === 'completed'));
    const last = state.runs.at(-1);
    const replay = await harness.replay(last.id);
    assert.equal(replay.replayed, true);
  } finally { fs.rmSync(temp, {recursive:true,force:true}); }
});

test('live chat proposal and file effect have separate exact grants; replay repeats neither', async () => {
  const temp = tempDir('concord-chat-live-');
  let calls = 0;
  try {
    const model = {name:'model.propose',version:'fixture-1',effect:'network',inputSchema:{type:'object'},config:{fixture:true},execute(){calls++;return{model:'fixture-1',proposal:{reply:'I propose saving this reviewed memory.',plan:{version:1,tasks:[{id:'save',tool:'files.write',input:{path:'memory.json',content:{lesson:'Recorded evidence precedes promotion.'}}}]}}};}};
    const harness = setup(temp,[model]);
    let state = await harness.send('Propose a memory update.');
    assert.equal(calls,0); assert.equal(state.pending.effect,'network');
    state = await harness.approve(state.pending.requestHash);
    assert.equal(calls,1); assert.ok(state.proposedPlan);
    state = await harness.executePlan();
    assert.equal(state.pending.effect,'write'); assert.equal(fs.existsSync(path.join(temp,'memory.json')),false);
    state = await harness.approve(state.pending.requestHash);
    assert.equal(fs.existsSync(path.join(temp,'memory.json')),true);
    const prior = fs.readFileSync(path.join(temp,'memory.json'),'utf8');
    const run = state.runs.at(-1);
    assert.equal((await harness.replay(run.id)).replayed,true);
    assert.equal(calls,1); assert.equal(fs.readFileSync(path.join(temp,'memory.json'),'utf8'),prior);
  } finally { fs.rmSync(temp, {recursive:true,force:true}); }
});

const SKILL_QUERY = 'Review this change for security vulnerabilities before shipping it.';

test('selected retains the capability path needed to fetch a skill body', async () => {
  const temp = tempDir('concord-chat-flow-');
  try {
    const harness = setup(temp);
    const turn = await harness.send(SKILL_QUERY);
    const skillMatch = turn.selected.find((s) => s.kind === 'skill');
    assert.ok(skillMatch, 'expected at least one skill-kind match for a security-review query');
    assert.equal(typeof skillMatch.path, 'string');
    assert.ok(skillMatch.path.endsWith('SKILL.md'));
  } finally { fs.rmSync(temp, {recursive:true,force:true}); }
});

test('a resolvable skill match enriches the offline memory-candidate lesson with its untrusted excerpt, recorded as its own run', async () => {
  const harness = setup(root); // the real repo root, where upstream/ is actually acquired
  const turn = await harness.send(SKILL_QUERY);
  assert.equal(turn.runs.length, 3, 'expected a skill-enrichment attempt, a memory-enrichment attempt, and the primary offline-demo attempt');
  assert.ok(turn.runs.every((r) => r.status === 'completed'));
  const memoryTask = turn.proposedPlan.tasks.find((t) => t.id === 'memory');
  assert.match(memoryTask.input.lesson, /Untrusted reference skill \(ecc\)/);
  assert.match(memoryTask.input.lesson, /Security Review Skill/);
});

test('an unresolvable skill path (the default fresh-clone state) soft-fails without breaking the primary turn', async () => {
  const temp = tempDir('concord-chat-flow-');
  try {
    const harness = setup(temp); // no upstream/ under this fresh workspace, and no memory/ directory yet either
    const turn = await harness.send(SKILL_QUERY);
    assert.equal(turn.mode, 'offline-demo');
    assert.ok(turn.history.some((m) => m.role === 'assistant' && m.content.length), 'the primary turn still produced a reply');
    const memoryTask = turn.proposedPlan.tasks.find((t) => t.id === 'memory');
    assert.doesNotMatch(memoryTask.input.lesson, /Untrusted reference skill/);
    assert.doesNotMatch(memoryTask.input.lesson, /Relevant past memory/);
    assert.ok(turn.runs.some((r) => r.status === 'completed'), 'the primary plan still completed');
  } finally { fs.rmSync(temp, {recursive:true,force:true}); }
});

test('a prior promoted memory surfaces as a relevant-past-memory excerpt in a later turn', async () => {
  const temp = tempDir('concord-chat-flow-');
  try {
    const lesson = 'When reviewing changes for security vulnerabilities, check authentication boundaries first.';
    const candidate = { version: 1, lesson, evidenceHashes: [digest('reviewed-evidence')], status: 'proposed', executable: false };
    const candidateHash = digest(candidate);
    fs.mkdirSync(path.join(temp, 'memory'), { recursive: true });
    fs.writeFileSync(path.join(temp, 'memory', `${candidateHash}.json`), JSON.stringify({ ...candidate, candidateHash }) + '\n');

    const harness = setup(temp);
    const turn = await harness.send(SKILL_QUERY); // shares "security"/"vulnerabilities" tokens with the stored lesson
    const memoryTask = turn.proposedPlan.tasks.find((t) => t.id === 'memory');
    assert.match(memoryTask.input.lesson, /Relevant past memory/);
    assert.match(memoryTask.input.lesson, /authentication boundaries/);
  } finally { fs.rmSync(temp, {recursive:true,force:true}); }
});

test('the skill-enrichment and memory-recall read effects never produce a pending approval', async () => {
  const harness = setup(root);
  const turn = await harness.send(SKILL_QUERY);
  assert.equal(turn.pending, null);
});

test('live mode supplies acquired skills as untrusted reference data outside the system prompt', async () => {
  let receivedSystem, receivedPrompt;
  const model = { name: 'model.propose', version: 'fixture-1', effect: 'network', inputSchema: { type: 'object' }, config: { fixture: true },
    execute(input) { receivedSystem = input.system; receivedPrompt = JSON.parse(input.prompt); return { model: 'fixture-1', proposal: { reply: 'ok' } }; } };

  const resolvable = setup(root, [model]);
  let state = await resolvable.send(SKILL_QUERY);
  await resolvable.approve(state.pending.requestHash); // unblocks the network effect so execute() actually runs
  assert.equal(receivedPrompt.references.trust, 'untrusted-data');
  assert.equal(receivedPrompt.references.skill.sourceId, 'ecc');
  assert.equal(receivedPrompt.references.skill.title, 'Security Review Skill');
  assert.doesNotMatch(receivedSystem, /Untrusted reference skill \(ecc\)/);

  const temp = tempDir('concord-chat-flow-');
  try {
    const unresolvable = setup(temp, [model]);
    state = await unresolvable.send(SKILL_QUERY);
    await unresolvable.approve(state.pending.requestHash);
    assert.doesNotMatch(receivedSystem, /Untrusted reference skill/);
    assert.equal(receivedPrompt.references.skill, null);
  } finally { fs.rmSync(temp, {recursive:true,force:true}); }
});

test('replay reproduces the skill-enrichment, memory-enrichment, and primary runs byte-identically', async () => {
  const harness = setup(root);
  const turn = await harness.send(SKILL_QUERY);
  assert.equal(turn.runs.length, 3);
  for (const run of turn.runs) {
    const replay = await harness.replay(run.id);
    assert.equal(replay.replayed, true);
  }
});

test('a turn attenuated for untrusted input narrows the whole turn and still replays', async () => {
  // hermes serves untrusted webhook payloads from a reduced toolset. The same shape here: the
  // caller declares the turn untrusted and the turn loses authority before the model plans.
  const temp = tempDir('concord-attenuate-');
  try {
    const harness = setup(temp);
    const open = await harness.send('Summarise what this harness does.');
    assert.equal(open.authority.allowedEffects.includes('write'), true);

    const narrowed = await harness.send('Summarise what this harness does.', {
      attenuate: { allowedEffects: ['pure', 'read'], maxOutputBytes: 65536 },
    });
    assert.deepEqual(narrowed.authority.allowedEffects, ['pure', 'read']);
    assert.equal(narrowed.authority.maxOutputBytes, 65536);
    // The context the model is given describes the reduced authority, not the base policy.
    assert.equal(narrowed.authority.allowedEffects.includes('write'), false);

    // Recorded per run, so an attenuated turn replays against the authority it actually had.
    for (const run of narrowed.runs) assert.equal((await harness.replay(run.id)).replayed, true);

    // A later unattenuated turn is not permanently reduced by an earlier narrowed one.
    const restored = await harness.send('And again, without restriction.');
    assert.equal(restored.authority.allowedEffects.includes('write'), true);

    // Attenuation cannot be used to grant authority the base policy withholds.
    await assert.rejects(harness.send('try to widen', { attenuate: { allowedEffects: ['pure', 'process'] } }),
      e => e.code === 'POLICY_NOT_ATTENUATED');
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});
