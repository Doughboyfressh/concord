import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, linkSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { canonical, digest, parseJson, validateSchema, clone } from '../src/value.mjs';
import { runPlan, replayPlan, inspectPlan } from '../src/engine.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';

const registry = new Map(makeBuiltinTools().map(t => [t.name, t]));
const policy = { version: 1, allowedTools: [...registry.keys()], allowedEffects: ['pure', 'read', 'write'], maxOutputBytes: 10000, maxJournalBytes: 100000 };
const base = (plan, overrides = {}) => ({ plan, policy, registry, sourceLock: { version: 1 }, workspaceRoot: path.resolve('/explicit/workspace'), ...overrides });
const task = (id, input = 1) => ({ id, tool: 'json.value', input });
const one = { version: 1, tasks: [task('a')] };

test('canonical identity is independent of key insertion, distinct for order', () => {
  assert.equal(canonical({ z: 1, a: [2, 3] }), '{"a":[2,3],"z":1}');
  assert.equal(digest({ z: 1, a: 2 }), digest({ a: 2, z: 1 }));
  assert.notEqual(digest([1, 2]), digest([2, 1]));
});
test('canonical rejects unsupported, unsafe, cyclic and hidden data without invoking accessors', () => {
  const cycle = {}; cycle.a = cycle;
  const accessor = {}; Object.defineProperty(accessor, 'a', { enumerable: true, get() { throw Error('called'); } });
  for (const bad of [undefined, NaN, Infinity, 9007199254740992, 1n, new Date(), cycle, [, 1], accessor, JSON.parse('{"__proto__":1}'), { a: undefined }]) assert.throws(() => canonical(bad), e => e.code === 'INVALID_JSON');
});
test('strict JSON rejects duplicate keys, unsafe keys and extra content', () => {
  for (const bad of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"constructor":1}', '1 2', '[1,]', '{"a":NaN}', '"unterminated', '{"x":01}']) assert.throws(() => parseJson(bad));
  assert.deepEqual(parseJson(' {"a":"\\\"x", "b":[true, null, -1.5e2]} '), { a: '"x', b: [true, null, -150] });
});
test('schema subset is explicit and fails closed', () => {
  validateSchema({ a: 2 }, { type: 'object', properties: { a: { type: 'integer', minimum: 1 } }, required: ['a'], additionalProperties: false });
  assert.throws(() => validateSchema({ a: 2, b: 3 }, { type: 'object', properties: { a: true }, additionalProperties: false }));
  assert.throws(() => validateSchema('a', { pattern: '.' }), e => e.code === 'INVALID_SCHEMA');
  assert.throws(() => validateSchema('a', { oneOf: [true, true] }));
});
test('equivalent captures have identical roots and stable topological order', async () => {
  const plan = { version: 1, tasks: [task('z'), task('b'), { ...task('a'), dependsOn: ['b'] }] };
  const a = await runPlan(base(plan)), b = await runPlan(base(plan));
  assert.deepEqual(a, b);
  assert.deepEqual(a.events[0].data.order, ['b', 'a', 'z']);
  assert.equal(replayPlan({ ...base(plan), journal: a, expectedRoot: a.root }).replayed, true);
});
test('invalid graph and unknown capabilities fail before tools', async () => {
  for (const tasks of [[task('constructor')], [task('prototype')], [task('a'), task('a')], [{ ...task('a'), dependsOn: ['missing'] }], [{ ...task('a'), dependsOn: ['b'] }, { ...task('b'), dependsOn: ['a'] }], [{ ...task('a'), tool: 'unknown' }], [{ ...task('a'), input: { $task: 'b' } }, task('b')]]) await assert.rejects(runPlan(base({ version: 1, tasks })));
  await assert.rejects(runPlan(base(one, { policy: { ...policy, allowedTools: [] } })), e => e.code === 'POLICY_DENIED');
  await assert.rejects(runPlan(base(one, { policy: { ...policy, allowedEffects: [] } })), e => e.code === 'POLICY_DENIED');
});
test('references use direct dependencies and RFC6901 own-property paths', async () => {
  const plan = { version: 1, tasks: [task('a', { 'x/y': { '~z': [7] } }), { ...task('b', { $task: 'a', path: '/x~1y/~0z/0' }), dependsOn: ['a'] }] };
  const j = await runPlan(base(plan));
  assert.equal(j.results.b, 7);
  replayPlan({ ...base(plan), journal: j });
  for (const pointer of ['/x~1y/~0z/00', '/x~1y/~0z/length', '/constructor', '/missing']) {
    const bad = clone(plan); bad.tasks[1].input.path = pointer;
    const result = await runPlan(base(bad));
    assert.equal(result.outcome.code, 'INPUT_INVALID');
    replayPlan({ ...base(bad), journal: result });
  }
});
test('exact approval binds resolved input, policy, sources, tool config and workspace', async () => {
  let calls = 0;
  const tool = { name: 'write', version: '1', effect: 'write', inputSchema: true, config: { target: 'one' }, execute() { calls++; return true; } };
  const p = { version: 1, allowedTools: ['write'], allowedEffects: ['write'], maxOutputBytes: 10000, maxJournalBytes: 100000 };
  const plan = { version: 1, tasks: [{ id: 'a', tool: 'write', input: { data: 1 } }] };
  const o = base(plan, { policy: p, registry: new Map([['write', tool]]) });
  const blocked = await runPlan(o);
  assert.equal(calls, 0); assert.equal(blocked.outcome.status, 'blocked');
  const approvals = [blocked.outcome.requestHash];
  const done = await runPlan({ ...o, approvals }); assert.equal(calls, 1); assert.equal(done.outcome.status, 'completed');
  replayPlan({ ...o, journal: done }); assert.equal(calls, 1);
  for (const change of [{ sourceLock: { version: 2 } }, { workspaceRoot: path.resolve('/different') }, { policy: { ...p, timeoutMs: 123 } }, { plan: { version: 1, tasks: [{ ...plan.tasks[0], input: { data: 2 } }] } }, { registry: new Map([['write', { ...tool, config: { target: 'two' } }]]) }]) {
    const result = await runPlan({ ...o, ...change, approvals }); assert.equal(result.outcome.status, 'blocked');
  }
});
test('replay rejects changed context, chain, root, truncation and trailing events', async () => {
  const j = await runPlan(base(one));
  for (const mutate of [x => { x.events[1].data.inputHash = '0'.repeat(64); }, x => { x.root = '1'.repeat(64); }, x => { x.events.pop(); }, x => { x.results.a = 2; }, x => { x.outcome.status = 'failed'; }, x => { x.events.push(x.events[0]); }]) {
    const bad = clone(j); mutate(bad);
    assert.throws(() => replayPlan({ ...base(one), journal: bad }));
  }
  assert.throws(() => replayPlan({ ...base(one, { sourceLock: {} }), journal: j }));
  assert.throws(() => replayPlan({ ...base(one), journal: j, expectedRoot: '0'.repeat(64) }));
});
test('rehashing an illegal transition does not make it replayable', async () => {
  const j = clone(await runPlan(base(one)));
  j.events[1].type = 'completed';
  let previous = digest(j.header);
  for (const e of j.events) { e.previous = previous; e.hash = digest({ previous, seq: e.seq, type: e.type, data: e.data }); previous = e.hash; }
  j.root = previous;
  assert.throws(() => replayPlan({ ...base(one), journal: j }), e => e.code === 'REPLAY_TRANSITION');
});
test('postconditions stop dependents and replay records failure without execution', async () => {
  const plan = { version: 1, tasks: [{ ...task('a', 2), outputSchema: { const: 1 } }, { ...task('b'), dependsOn: ['a'] }] };
  const j = await runPlan(base(plan)); assert.equal(j.outcome.status, 'failed'); assert.equal(j.results.b, undefined);
  replayPlan({ ...base(plan), journal: j });
});
test('deadlines and non-JSON outputs fail closed', async () => {
  for (const execute of [() => undefined, () => new Promise(() => {})]) {
    const tool = { name: 'x', version: '1', effect: 'pure', inputSchema: true, execute };
    const options = base({ version: 1, tasks: [{ id: 'a', tool: 'x', input: null }] }, { registry: new Map([['x', tool]]), policy: { ...policy, allowedTools: ['x'], timeoutMs: 10 } });
    const j = await runPlan(options); assert.equal(j.outcome.code, 'TOOL_FAILED'); replayPlan({ ...options, journal: j });
  }
});
test('reserve journal budget before invoking effects', async () => {
  let calls = 0;
  const tool = { name: 'x', version: '1', effect: 'pure', inputSchema: true, execute() { calls++; return 1; } };
  const o = base({ version: 1, tasks: [{ id: 'a', tool: 'x', input: null }] }, { registry: new Map([['x', tool]]), policy: { ...policy, allowedTools: ['x'], maxOutputBytes: 10000, maxJournalBytes: 4000 } });
  const j = await runPlan(o); assert.equal(calls, 0); assert.equal(j.outcome.code, 'BUDGET_EXHAUSTED'); replayPlan({ ...o, journal: j });
});
test('intent is durable before execution and existing journals are refused', async () => {
  const temp = mkdtempSync(path.join(tmpdir(), 'concord-journal-'));
  try {
    const filename = path.join(temp, 'events.jsonl');
    const tool = { name: 'x', version: '1', effect: 'read', inputSchema: true, execute() { const log = readFileSync(filename, 'utf8'); assert.match(log, /"type":"intent"/); return true; } };
    const o = base({ version: 1, tasks: [{ id: 'a', tool: 'x', input: null }] }, { registry: new Map([['x', tool]]), policy: { ...policy, allowedTools: ['x'] }, journalPath: filename });
    const j = await runPlan(o); assert.equal(j.outcome.status, 'completed'); await assert.rejects(runPlan(o), e => e.code === 'EEXIST');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
test('file write requires grant, uses exclusive create, and is not repeated on replay', async () => {
  const temp = mkdtempSync(path.join(tmpdir(), 'concord-write-'));
  try {
    const plan = { version: 1, tasks: [{ id: 'a', tool: 'files.write', input: { path: 'memory.json', content: { lesson: 'x' } } }] };
    const o = base(plan, { workspaceRoot: temp });
    const b = await runPlan(o); assert.equal(existsSync(path.join(temp, 'memory.json')), false);
    const j = await runPlan({ ...o, approvals: [b.outcome.requestHash] });
    assert.equal(j.outcome.status, 'completed'); replayPlan({ ...o, journal: j });
    assert.deepEqual(JSON.parse(readFileSync(path.join(temp, 'memory.json'), 'utf8')), { lesson: 'x' });
    const second = await runPlan({ ...o, approvals: [b.outcome.requestHash] }); assert.equal(second.outcome.code, 'EFFECT_INDETERMINATE');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
test('untrusted inputs cannot mutate downstream evidence', async () => {
  const evil = { name: 'x', version: '1', effect: 'pure', inputSchema: true, execute(input) { input.x = 2; return input; } };
  const options = base({ version: 1, tasks: [{ id: 'a', tool: 'x', input: { x: 1 } }] }, { registry: new Map([['x', evil]]), policy: { ...policy, allowedTools: ['x'] } });
  assert.equal((await runPlan(options)).outcome.status, 'failed');
});
test('file reads reject hardlinks and directories before reading', (t) => {
  const temp = mkdtempSync(path.join(tmpdir(), 'concord-links-'));
  try {
    const workspace = path.join(temp, 'workspace'); mkdirSync(workspace);
    const outside = path.join(temp, 'outside'); writeFileSync(outside, 'secret');
    const tool = registry.get('files.read');
    const context = { workspaceRoot: workspace, policy: { maxOutputBytes: 10000 } };
    assert.throws(() => tool.execute({ path: 'directory' }, context));
    mkdirSync(path.join(workspace, 'directory'));
    assert.throws(() => tool.execute({ path: 'directory' }, context));
    try { linkSync(outside, path.join(workspace, 'alias')); }
    catch (error) { if (['EPERM', 'EACCES'].includes(error.code)) { t.skip('Host disallows link creation'); return; } throw error; }
    assert.throws(() => tool.execute({ path: 'alias' }, context), e => e.code === 'PATH_DENIED');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
test('replay enforces post-intent receipt reserve', async () => {
  const o = base(one, { policy: { ...policy, maxOutputBytes: 10000, maxJournalBytes: 13000 } });
  const j = clone(await runPlan(o));
  const output = 'x'.repeat(9998);
  j.events.find(e => e.type === 'completed').data = { taskId: 'a', output, outputHash: digest(output) };
  j.results.a = output;
  let previous = digest(j.header);
  for (const e of j.events) { e.previous = previous; e.hash = digest({ previous, seq: e.seq, type: e.type, data: e.data }); previous = e.hash; }
  j.root = previous;
  assert.throws(() => replayPlan({ ...o, journal: j }), e => e.code === 'REPLAY_LIMIT');
});
test('ambient working-directory roots cannot enter approval identity', async () => {
  const roots = ['.', '..', 'relative/path', 'C:relative'];
  if (path.sep === '\\') roots.push('/drive-relative', '\\drive-relative');
  for (const workspaceRoot of roots) await assert.rejects(runPlan(base(one, { workspaceRoot })), e => e.code === 'INVALID_WORKSPACE');
});

test('the input-schema gate rejects static inputs before approval and defers references to a clean INPUT_INVALID', async () => {
  let invoked = 0;
  const strict = { name: 'strict.write', version: '1', effect: 'write',
    inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'], additionalProperties: false },
    execute() { invoked++; return true; } };
  const reg = new Map([...makeBuiltinTools(), strict].map(t => [t.name, t]));
  const pol = { ...policy, allowedTools: [...reg.keys()], allowedEffects: ['pure', 'read', 'write'] };
  const ctx = p => ({ plan: p, policy: pol, registry: reg, sourceLock: { version: 1 }, workspaceRoot: path.resolve('/explicit/workspace') });

  // A static input of the wrong type is refused structurally: no execution, no approval hash.
  const staticBad = { version: 1, tasks: [{ id: 'w', tool: 'strict.write', input: { text: 42 } }] };
  await assert.rejects(runPlan(ctx(staticBad)), e => e.code === 'SCHEMA_MISMATCH');
  assert.throws(() => inspectPlan(ctx(staticBad)), e => e.code === 'SCHEMA_MISMATCH');
  assert.equal(invoked, 0);

  // A $task reference cannot be validated until its dependency resolves, which inspectPlan
  // discloses in its own note rather than papering over.
  const referenced = { version: 1, tasks: [
    { id: 'n', tool: 'json.value', input: 42 },
    { id: 'w', tool: 'strict.write', input: { text: { $task: 'n' } }, dependsOn: ['n'] },
  ] };
  assert.match(inspectPlan(ctx(referenced)).note, /resolve when dependency evidence is available/);

  const journal = await runPlan(ctx(referenced));
  assert.equal(journal.outcome.status, 'failed');
  assert.equal(journal.outcome.taskId, 'w');
  // The decisive assertion. A write whose resolved input fails validation reports INPUT_INVALID,
  // never EFFECT_INDETERMINATE: validation provably precedes execute(), so "the effect may have
  // occurred" would be a false indeterminate, and this project's guidance forbids retrying one.
  assert.equal(journal.outcome.code, 'INPUT_INVALID');
  assert.equal(invoked, 0);
  // Nothing was ever offered for approval, because the input could not validate.
  // Scoped to the failing task: its pure dependency legitimately ran and recorded its own intent.
  assert.ok(!journal.events.some(e => e.type === 'blocked' && e.data.taskId === 'w'));
  assert.ok(!journal.events.some(e => e.type === 'intent' && e.data.taskId === 'w'));
  assert.ok(journal.events.some(e => e.type === 'intent' && e.data.taskId === 'n'));
  replayPlan({ ...ctx(referenced), journal });
});

test('a journaled INPUT_INVALID records which rule it broke, and replay reconstructs it', async () => {
  // Measured in round 004: asked to extract a field nested inside a JSON file's text, the model
  // proposed a reference path into files.read's result object, where that field does not exist.
  // The plan was structurally valid (references defer validation by design) and failed only at
  // execution, where a bare INPUT_INVALID gave no way to tell a nonexistent path from a malformed
  // pointer. Both sides of the kernel must record the same diagnostic or replay breaks.
  const plan = { version: 1, tasks: [
    { id: 'a', tool: 'json.value', input: { text: 'flat' } },
    { id: 'b', tool: 'json.value', input: { v: { $task: 'a', path: '/project/topic' } }, dependsOn: ['a'] },
  ] };
  const journal = await runPlan(base(plan));
  assert.equal(journal.outcome.code, 'INPUT_INVALID');
  const failed = journal.events.find(e => e.type === 'failed');
  assert.equal(failed.data.taskId, 'b');
  assert.match(failed.data.reason, /Reference path does not exist/);
  // The outcome stays exactly as before, so the settled envelope is unchanged.
  assert.deepEqual(journal.outcome, { status: 'failed', taskId: 'b', code: 'INPUT_INVALID' });
  // Replay must reconstruct the identical event, including the diagnostic.
  replayPlan({ ...base(plan), journal });

  // The sibling rule is caught earlier still: a pointer that is not RFC 6901 does not depend on
  // any resolved value, so inspectRefs rejects it structurally at compile time and the plan never
  // reaches execution or an approval hash. The two rules share one code but not one stage.
  const badPointer = clone(plan);
  badPointer.tasks[1].input.v.path = 'project/topic';
  await assert.rejects(runPlan(base(badPointer)), e => e.code === 'INVALID_REFERENCE' && /RFC 6901/.test(e.message));
  assert.throws(() => inspectPlan(base(badPointer)), e => e.code === 'INVALID_REFERENCE');
});
