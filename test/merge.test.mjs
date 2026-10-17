import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { runPlan } from '../src/engine.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';

const registry = new Map(makeBuiltinTools().map((t) => [t.name, t]));
const policy = { version: 1, allowedTools: [...registry.keys()], allowedEffects: ['pure'], maxOutputBytes: 10000, maxJournalBytes: 100000 };
const base = (plan) => ({ plan, policy, registry, sourceLock: { version: 1 }, workspaceRoot: path.resolve('/explicit/workspace') });

test('text.concat joins caller-ordered values with an explicit separator', async () => {
  const plan = { version: 1, tasks: [{ id: 'joined', tool: 'text.concat', input: { values: ['A-DONE', 'B-DONE'], separator: '\n' } }] };
  const result = await runPlan(base(plan));
  assert.equal(result.outcome.status, 'completed');
  assert.deepEqual(result.results.joined, { value: 'A-DONE\nB-DONE' });
});

test('text.concat respects caller order and an empty separator', () => {
  const tool = registry.get('text.concat');
  assert.deepEqual(tool.execute({ values: ['b', 'a', 'c'], separator: '' }), { value: 'bac' });
});

test('json.mergeShallow combines disjoint objects', () => {
  const tool = registry.get('json.mergeShallow');
  assert.deepEqual(tool.execute({ values: [{ a: 1 }, { b: 2 }, { c: 3 }] }), { value: { a: 1, b: 2, c: 3 } });
});

test('json.mergeShallow fails closed on a key collision instead of silently picking a winner', async () => {
  const tool = registry.get('json.mergeShallow');
  assert.throws(() => tool.execute({ values: [{ a: 1 }, { a: 2 }] }), (e) => e.code === 'MERGE_COLLISION');

  const plan = { version: 1, tasks: [{ id: 'merged', tool: 'json.mergeShallow', input: { values: [{ a: 1 }, { a: 2 }] } }] };
  const result = await runPlan(base(plan));
  assert.equal(result.outcome.status, 'failed');
  assert.equal(result.outcome.code, 'TOOL_FAILED');
});

test('json.mergeShallow rejects a __proto__ key itself, rather than relying on the kernel\'s gate', () => {
  const tool = registry.get('json.mergeShallow');
  const hostile = JSON.parse('{"__proto__":{"polluted":true}}'); // a real own "__proto__" data key, as JSON.parse produces it
  assert.throws(() => tool.execute({ values: [hostile] }), (e) => e.code === 'INPUT_INVALID');
  const result = (() => { try { return tool.execute({ values: [hostile] }); } catch { return undefined; } })();
  assert.equal(result, undefined); // never silently returns a prototype-swapped object
});

test('text.concat and json.mergeShallow reject malformed values with a clean HarnessError, not a raw exception', () => {
  const concat = registry.get('text.concat');
  const merge = registry.get('json.mergeShallow');
  assert.throws(() => concat.execute({ values: [Symbol('x')], separator: ',' }), (e) => e.code === 'INPUT_INVALID');
  assert.throws(() => concat.execute({ values: [{}], separator: ',' }), (e) => e.code === 'INPUT_INVALID');
  assert.throws(() => merge.execute({ values: [null] }), (e) => e.code === 'INPUT_INVALID');
  assert.throws(() => merge.execute({ values: [[1, 2]] }), (e) => e.code === 'INPUT_INVALID');
});

test('composes with another task\'s output via $task references, mirroring process.runMany result shapes', async () => {
  const plan = {
    version: 1,
    tasks: [
      { id: 'a', tool: 'json.value', input: { name: 'batch.a', stdout: 'A-DONE' } },
      { id: 'b', tool: 'json.value', input: { name: 'batch.b', stdout: 'B-DONE' } },
      {
        id: 'joined', tool: 'text.concat', dependsOn: ['a', 'b'],
        input: { values: [{ $task: 'a', path: '/stdout' }, { $task: 'b', path: '/stdout' }], separator: ', ' },
      },
      {
        id: 'merged', tool: 'json.mergeShallow', dependsOn: ['a', 'b'],
        input: { values: [{ $task: 'a' }, { $task: 'b' }] },
      },
    ],
  };
  const result = await runPlan(base(plan));
  assert.equal(result.outcome.status, 'failed'); // "name" collides across a and b in the merge task
  assert.equal(result.outcome.code, 'TOOL_FAILED');
  assert.deepEqual(result.results.joined, { value: 'A-DONE, B-DONE' });
});
