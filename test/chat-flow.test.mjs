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
