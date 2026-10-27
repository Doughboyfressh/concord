import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { makeObservationTools } from '../src/observation.mjs';
import { boundedValue } from '../src/chat-data.mjs';
import { runPlan, registryManifest } from '../src/engine.mjs';
import { digest } from '../src/value.mjs';

/**
 * The failure this undoes, stated once: boundedValue does not shorten an oversized output, it
 * drops it and leaves a hash. A turn that read a 20 KB file was shown a digest where the content
 * should be, and described the file anyway. The content was recorded the whole time.
 */

const reader = {
  name: 't.read', version: '1.0.0', effect: 'read',
  inputSchema: { type: 'object', additionalProperties: true },
  execute: (input) => ({ path: input.path, bytes: input.size, text: 'L'.repeat(input.size) }),
};
const registry = new Map([[reader.name, reader]]);
const policy = { version: 1, allowedTools: ['t.read'], allowedEffects: ['read'], maxOutputBytes: 200000, maxJournalBytes: 2000000 };
const workspaceRoot = path.resolve('/explicit/workspace');
const context = { workspaceRoot, policy };

/** One real recorded run, and the store a session keeps over it. */
async function recorded(size) {
  const plan = { version: 1, name: 'read', tasks: [{ id: 'file', tool: 't.read', input: { path: 'big.txt', size } }] };
  const result = await runPlan({ plan, policy, registry, sourceLock: { version: 1 }, workspaceRoot });
  const event = result.events.find((e) => e.type === 'completed');
  const runId = digest(result).slice(0, 24);
  const store = (wantRun, wantTask) =>
    (wantRun === runId && wantTask === event.data.taskId
      ? { output: event.data.output, outputHash: event.data.outputHash }
      : null);
  return { runId, event, result, store };
}

const toolOver = (store, options = {}) => makeObservationTools({ readOutput: store, ...options })[0];

test('an output the turn was never shown is fetched back in slices', async () => {
  const { runId, event, store } = await recorded(20000);

  // The premise, asserted rather than assumed: this really is dropped, not shortened.
  const shown = boundedValue(event.data.output);
  assert.equal(shown.omitted, true);
  assert.equal(shown.reason, 'byte-limit');
  assert.equal(shown.value, undefined, 'the turn was shown a hash and no content at all');

  const tool = toolOver(store, { maxBytes: 4096 });
  const first = tool.execute({ runId, taskId: 'file', path: '/text' }, context);
  assert.equal(first.found, true);
  assert.equal(first.kind, 'string');
  assert.equal(first.totalLength, 20000);
  assert.equal(first.offset, 0);
  assert.equal(first.hasMore, true);
  assert.ok(first.returned > 0 && first.returned <= 4096);
  assert.equal(first.text, 'L'.repeat(first.returned), 'verbatim, not a description of the text');
  assert.equal(first.outputHash, event.data.outputHash, 'tied to the hash the receipt was shown under');

  // The whole string is reachable by following hasMore, and reassembles exactly.
  let assembled = first.text;
  let cursor = first.returned;
  let guard = 0;
  for (;;) {
    const next = tool.execute({ runId, taskId: 'file', path: '/text', offset: cursor }, context);
    assembled += next.text;
    cursor += next.returned;
    if (!next.hasMore) break;
    assert.ok(++guard < 100, 'it must make progress');
  }
  assert.equal(assembled.length, 20000);
  assert.equal(assembled, 'L'.repeat(20000));
});

test('every declared outputKeys is present whatever the outcome', async () => {
  const { runId, store } = await recorded(20000);
  const tool = toolOver(store);
  const outcomes = [
    tool.execute({ runId, taskId: 'file', path: '/text' }, context),
    tool.execute({ runId, taskId: 'file', path: '/bytes' }, context),
    tool.execute({ runId, taskId: 'file' }, context),
    tool.execute({ runId, taskId: 'nosuch' }, context),
  ];
  assert.deepEqual(outcomes.map((o) => o.kind), ['string', 'value', 'oversized', 'absent']);
  for (const outcome of outcomes) {
    for (const key of tool.outputKeys) assert.ok(key in outcome, `missing ${key} on a ${outcome.kind}`);
  }
});

test('a value too large is withheld entire and names what it holds', async () => {
  const { runId, store } = await recorded(20000);
  const tool = toolOver(store, { maxBytes: 4096 });
  const whole = tool.execute({ runId, taskId: 'file' }, context);

  assert.equal(whole.kind, 'oversized');
  assert.equal(whole.value, null, 'half an object is a different object');
  assert.deepEqual([...whole.keys].sort(), ['bytes', 'path', 'text'], 'so a deeper path can be chosen');
  assert.ok(whole.totalLength > 4096);
  // And the key it named really does lead somewhere. A string arrives as a slice however short
  // it is, because every string is sliceable and one shape for all of them beats two.
  const named = tool.execute({ runId, taskId: 'file', path: '/path' }, context);
  assert.equal(named.kind, 'string');
  assert.equal(named.text, 'big.txt');
  assert.equal(named.hasMore, false);
  assert.equal(named.value, null);
});

test('a small value comes back whole rather than sliced', async () => {
  const { runId, store } = await recorded(100);
  const tool = toolOver(store);
  const whole = tool.execute({ runId, taskId: 'file' }, context);
  assert.equal(whole.kind, 'value');
  assert.deepEqual(whole.value, { path: 'big.txt', bytes: 100, text: 'L'.repeat(100) });
  assert.deepEqual(whole.keys, []);
});

test('a slice never splits a character, and never exceeds the bound', () => {
  // Four-byte characters: a character count is not a byte count, and returning one byte over the
  // bound would have the observation window drop the whole reply.
  const text = '🧪'.repeat(4000);
  const store = () => ({ output: { text }, outputHash: 'f'.repeat(64) });
  const tool = toolOver(store, { maxBytes: 1024 });

  let assembled = '';
  let cursor = 0;
  for (let i = 0; i < 400; i += 1) {
    const part = tool.execute({ runId: 'r', taskId: 't', path: '/text', offset: cursor }, context);
    assert.ok(Buffer.byteLength(part.text) <= 1024, 'the byte bound holds');
    assert.ok(part.returned > 0, 'it must make progress');
    assert.equal(part.text, text.slice(cursor, cursor + part.returned), 'no character was split');
    assembled += part.text;
    cursor += part.returned;
    if (!part.hasMore) break;
  }
  assert.equal(assembled, text);
});

test('reading past the end is empty rather than an error', async () => {
  const { runId, store } = await recorded(100);
  const tool = toolOver(store);
  const past = tool.execute({ runId, taskId: 'file', path: '/text', offset: 500 }, context);
  assert.equal(past.found, true);
  assert.equal(past.text, '');
  assert.equal(past.returned, 0);
  assert.equal(past.hasMore, false);
  assert.equal(past.totalLength, 100);
});

test('an unknown run, task or path is reported rather than invented', async () => {
  const { runId, store } = await recorded(100);
  const tool = toolOver(store);
  for (const probe of [
    { runId: 'nosuchrun', taskId: 'file' },
    { runId, taskId: 'nosuchtask' },
  ]) {
    const result = tool.execute(probe, context);
    assert.equal(result.found, false);
    assert.equal(result.kind, 'absent');
    assert.equal(result.outputHash, null);
  }
  const badPath = tool.execute({ runId, taskId: 'file', path: '/nope' }, context);
  assert.equal(badPath.found, false);
  assert.equal(badPath.value, null);
  assert.equal(badPath.text, null);
});

test('a pointer is the kernel\'s pointer, and an unsafe key is refused', async () => {
  const { runId, store } = await recorded(100);
  const tool = toolOver(store);
  for (const bad of ['text', '/~2bad']) {
    assert.throws(() => tool.execute({ runId, taskId: 'file', path: bad }, context),
      (error) => error.code === 'INPUT_INVALID');
  }
  assert.throws(() => tool.execute({ runId, taskId: 'file', path: '/__proto__' }, context),
    (error) => error.code === 'INPUT_INVALID');
  assert.throws(() => tool.execute({ runId: 'has space', taskId: 'file' }, context),
    (error) => error.code === 'INPUT_INVALID');
});

test('the registry digest does not move when the recorded outputs do', async () => {
  // The reason the store is a closure and not config, same as conversation.turn and variant.
  let outputs = null;
  const tool = toolOver((runId, taskId) => (outputs ? outputs(runId, taskId) : null));
  const manifest = () => digest(registryManifest(new Map([[tool.name, tool]])));
  const before = manifest();

  const { runId, store } = await recorded(20000);
  outputs = store;

  assert.equal(before, manifest());
  assert.equal(tool.execute({ runId, taskId: 'file', path: '/text' }, context).totalLength, 20000);
});

test('the store refuses a configuration it cannot read an output from', () => {
  assert.throws(() => makeObservationTools({}), /OBSERVATION_CONFIG|readOutput/);
  assert.throws(() => makeObservationTools({ readOutput: () => null, maxBytes: 16 }), /OBSERVATION_CONFIG|maxBytes/);
});
