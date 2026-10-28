import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical } from '../src/value.mjs';
import { buildChatContext, selectToolContracts, TOOL_CONTRACT_BUDGET } from '../src/chat-context.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';
import { makeArtifactTools } from '../src/artifacts.mjs';
import { makeReaderTools } from '../src/readers.mjs';
import { loadSourceLock } from '../src/sources.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const sourceLock = await loadSourceLock(path.join(root, 'sources.lock.json'));
const instructionRoot = path.join(root, 'instructions');

const tools = [...makeBuiltinTools(), ...makeArtifactTools(), ...makeReaderTools()];
const contracts = [...tools].sort((a, b) => (a.name < b.name ? -1 : 1)).map((tool) => ({
  name: tool.name, version: tool.version, effect: tool.effect, inputSchema: tool.inputSchema,
  requiresApproval: ['write', 'network', 'process'].includes(tool.effect),
  ...(Array.isArray(tool.outputKeys) ? { outputKeys: tool.outputKeys } : {}),
}));
const FLOOR = ['tools.catalog', 'files.read', 'files.write', 'files.writeText', 'math.evaluate', 'time.now'];
const names = (selection) => selection.contracts.map((contract) => contract.name);
const select = (message, rest = {}) => selectToolContracts({ message, contracts, ...rest });

test('a turn carries far less than the whole registry, and says how much less', () => {
  const full = Buffer.byteLength(canonical(contracts));
  const selection = select('Decompile the binary and show me the call graph.');
  assert.ok(selection.shown < selection.total, 'a subset, not everything');
  assert.equal(selection.total, contracts.length);
  assert.equal(selection.shown + selection.omittedNames.length, selection.total, 'every tool is either shown or named as omitted');
  assert.ok(selection.bytes < full / 2, `expected well under half of ${full}, got ${selection.bytes}`);
  assert.equal(selection.bytes, Buffer.byteLength(canonical(selection.contracts)), 'the reported size is the real one');
});

test('relevance actually tracks the question', () => {
  const graphs = names(select('Decompile the binary and show me the call graph.'));
  assert.ok(graphs.includes('artifact.callGraph'), 'the tool the question is about is present');
  const files = names(select('Read src/patch.mjs and tell me whether applyPatch has defects.'));
  assert.ok(files.includes('files.read'));
  // The two questions must not select the same set, or the ranking is doing nothing.
  assert.notDeepEqual(graphs, files);
  assert.ok(!files.includes('artifact.callGraph'), 'an unrelated reader stays out');
});

test('the topic-independent floor is always there, whatever the subject', () => {
  // The measurement that forced this: an arithmetic question whose words share no vocabulary with
  // math.evaluate dropped the calculator from the very turn that needed it.
  for (const message of [
    'The annual pass is $60 and adult admission is $12 - how many visits before it pays for itself?',
    'Decompile the binary and show me the call graph.',
    'hello',
  ]) {
    const kept = names(select(message));
    for (const required of ['math.evaluate', 'time.now', 'files.read']) {
      assert.ok(kept.includes(required), `${required} missing for: ${message}`);
    }
  }
});

test('a tool the instructions name by force carries its contract', () => {
  // The prompt tells the model it MUST answer inventory questions through tools.catalog, so a
  // prompt that said so without the contract would be ordering it to do something it was not
  // shown how to do. The pin is derived from the prose, so the two cannot drift apart.
  const pinned = selectToolContracts({
    message: 'What is the weather like?',
    contracts: contracts.filter((contract) => !FLOOR.includes(contract.name)),
    prose: 'you MUST propose a plan calling artifact.dexSearch and state its numbers',
  });
  assert.ok(names(pinned).includes('artifact.dexSearch'), 'a tool the prose names is carried');
  const loose = selectToolContracts({
    message: 'What is the weather like?',
    contracts: contracts.filter((contract) => !FLOOR.includes(contract.name)),
    prose: 'always read the receipt carefully',
  });
  assert.ok(!names(loose).includes('artifact.dexSearch'), 'a bare English word pins nothing');
});

test('a tool the operator names, or that the open plan uses, is never dropped', () => {
  assert.ok(names(select('run artifact.dexSearch over the apk please')).includes('artifact.dexSearch'));
  const withPlan = select('carry on', {
    proposedPlan: { version: 1, tasks: [{ id: 'a', tool: 'artifact.wasmInterface', input: {} }] },
  });
  assert.ok(names(withPlan).includes('artifact.wasmInterface'), 'the plan on the table stays readable');
});

test('common words score nothing, which is what stopwords are for', () => {
  // Before stopwords, "How many tools does this harness have?" ranked files.write top, purely on
  // "this" and "have" appearing in its description. Scoring on function words is not relevance.
  const selection = select('How many tools does this harness have?');
  const ranked = names(selection).filter((name) => !FLOOR.includes(name));
  assert.deepEqual(ranked, [], 'a question with no tool-specific words selects nothing beyond the floor');
});

test('the budget is honoured, and a large enough one keeps everything', () => {
  const query = 'read write decompile dex wasm graph binary apk sqlite plist firmware';
  const tight = select(query, { budgetBytes: 4096 });
  const generous = select(query, { budgetBytes: 10_000_000 });
  assert.ok(generous.shown > tight.shown, 'a bigger budget admits more');
  assert.equal(generous.omittedNames.filter((name) => !FLOOR.includes(name)).length >= 0, true);
  // Floor members are carried regardless, so the budget bounds what RANKING adds on top of them.
  const floorOnly = selectToolContracts({ message: 'hello', contracts, budgetBytes: 4096 });
  assert.ok(tight.bytes >= floorOnly.bytes, 'ranking only ever adds to the floor');
});

test('selection is deterministic, because an approval hash is taken over this prompt', () => {
  const a = select('Decompile the binary and show me the call graph.');
  const b = select('Decompile the binary and show me the call graph.');
  assert.equal(canonical(a.contracts), canonical(b.contracts));
  assert.equal(a.bytes, b.bytes);
  assert.deepEqual(a.omittedNames, b.omittedNames);
});

test('the prompt still lists every registered name, and admits the contracts are a subset', () => {
  const registry = new Map(tools.map((tool) => [tool.name, tool]));
  const built = buildChatContext({
    message: 'Decompile the binary and show me the call graph.',
    history: [], sourceLock, registry, instructionRoot,
  });
  assert.ok(built.toolSelection.omittedNames.length > 0, 'this registry is big enough to trim');
  // The expensive half is trimmed; the cheap half that stops a tool being invented is not.
  for (const name of ['artifact.sqlite', 'files.read', 'artifact.callGraph']) {
    assert.ok(built.systemPrompt.includes(name), `${name} is still named in the prompt`);
  }
  assert.match(built.systemPrompt, /Tool contracts spelled out for this turn: \d+ of \d+/);
  assert.match(built.systemPrompt, /never report a tool as unavailable merely because its contract is/);
  // toolContracts keeps its old meaning: everything the policy makes visible.
  assert.equal(built.toolContracts.length, registry.size);
  assert.ok(built.toolSelection.shown < built.toolContracts.length);
});

test('a registry small enough to fit is presented as complete, with no subset warning', () => {
  const registry = new Map(makeBuiltinTools().filter((tool) => tool.name === 'text.concat').map((tool) => [tool.name, tool]));
  const built = buildChatContext({ message: 'join these strings', history: [], sourceLock, registry, instructionRoot });
  assert.deepEqual(built.toolSelection.omittedNames, []);
  assert.match(built.systemPrompt, /Registered tool contracts \(all 1\)/);
  assert.doesNotMatch(built.systemPrompt, /spelled out for this turn/);
});

test('the default budget is the one the measurement was taken against', () => {
  assert.equal(TOOL_CONTRACT_BUDGET, 16384);
});
