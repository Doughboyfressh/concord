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
import { parseJson } from '../src/value.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
const inventory = parseJson(fs.readFileSync(path.join(root, 'capabilities.lock.json'), 'utf8'));
function setup(workspaceRoot, additional = []) {
  const descriptors = [...makeBuiltinTools(), ...makeCapabilityTools(inventory), ...makeSourceTools(catalog), ...additional];
  const registry = new Map(descriptors.map(t => [t.name, t]));
  const context = ({message,history}) => buildChatContext({message,history,sourceLock:catalog,inventory,registry,corpusRoot:root,instructionRoot:path.join(root,'instructions')});
  return createChatHarness({registry,policy:{version:1,allowedTools:[...registry.keys()],allowedEffects:['pure','read','write','network'],maxTasks:32,maxOutputBytes:1048576,maxJournalBytes:16777216,timeoutMs:10000},sourceLock:catalog,workspaceRoot,buildContext:context});
}

test('chat uses all twelve reviewed instruction modules and executes/replays its evidence plan', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'concord-chat-flow-'));
  try {
    const harness = setup(temp);
    const turn = await harness.send('Combine deterministic replay, browser tools, security review and memory in this chat harness.');
    assert.equal(turn.mode, 'offline-demo');
    assert.equal(turn.sourceCoverage.length, 12);
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
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'concord-chat-live-'));
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
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'concord-chat-flow-'));
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
  assert.equal(turn.runs.length, 2, 'expected a skill-enrichment attempt plus the primary offline-demo attempt');
  assert.equal(turn.runs[0].status, 'completed');
  assert.equal(turn.runs.at(-1).status, 'completed');
  const memoryTask = turn.proposedPlan.tasks.find((t) => t.id === 'memory');
  assert.match(memoryTask.input.lesson, /Untrusted reference skill \(ecc\)/);
  assert.match(memoryTask.input.lesson, /Security Review Skill/);
});

test('an unresolvable skill path (the default fresh-clone state) soft-fails without breaking the primary turn', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'concord-chat-flow-'));
  try {
    const harness = setup(temp); // no upstream/ under this fresh workspace
    const turn = await harness.send(SKILL_QUERY);
    assert.equal(turn.mode, 'offline-demo');
    assert.ok(turn.history.some((m) => m.role === 'assistant' && m.content.length), 'the primary turn still produced a reply');
    const memoryTask = turn.proposedPlan.tasks.find((t) => t.id === 'memory');
    assert.doesNotMatch(memoryTask.input.lesson, /Untrusted reference skill/);
    assert.ok(turn.runs.some((r) => r.status === 'completed'), 'the primary plan still completed');
  } finally { fs.rmSync(temp, {recursive:true,force:true}); }
});

test('the skill-enrichment read effect never produces a pending approval', async () => {
  const harness = setup(root);
  const turn = await harness.send(SKILL_QUERY);
  assert.equal(turn.pending, null);
});

test('live mode splices the untrusted skill excerpt into the system prompt only when the fetch actually succeeds', async () => {
  let receivedSystem;
  const model = { name: 'model.propose', version: 'fixture-1', effect: 'network', inputSchema: { type: 'object' }, config: { fixture: true },
    execute(input) { receivedSystem = input.system; return { model: 'fixture-1', proposal: { reply: 'ok' } }; } };

  const resolvable = setup(root, [model]);
  let state = await resolvable.send(SKILL_QUERY);
  await resolvable.approve(state.pending.requestHash); // unblocks the network effect so execute() actually runs
  assert.match(receivedSystem, /Untrusted reference skill \(ecc\): Security Review Skill/);

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'concord-chat-flow-'));
  try {
    const unresolvable = setup(temp, [model]);
    state = await unresolvable.send(SKILL_QUERY);
    await unresolvable.approve(state.pending.requestHash);
    assert.doesNotMatch(receivedSystem, /Untrusted reference skill/);
  } finally { fs.rmSync(temp, {recursive:true,force:true}); }
});

test('replay reproduces both the skill-enrichment run and the primary run byte-identically', async () => {
  const harness = setup(root);
  const turn = await harness.send(SKILL_QUERY);
  assert.equal(turn.runs.length, 2);
  for (const run of turn.runs) {
    const replay = await harness.replay(run.id);
    assert.equal(replay.replayed, true);
  }
});
