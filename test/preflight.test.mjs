import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { planGrants, assertSinglePass } from '../src/preflight.mjs';
import { runPlan, replayPlan } from '../src/engine.mjs';
import { digest as digestOf } from '../src/value.mjs';

/**
 * The claim under test is narrow and total: a hash computed before the plan runs is the SAME hash
 * the kernel computes when it reaches that task. If it ever differs, approving in advance grants
 * nothing and the run blocks anyway — so the first test here compares the two directly rather than
 * trusting that both call the same function.
 */

const landed = [];
const writer = {
  name: 't.write', version: '1.0.0', effect: 'write',
  inputSchema: { type: 'object', additionalProperties: false, required: ['path'], properties: { path: { type: 'string' }, body: { type: 'string' } } },
  execute: (input) => { landed.push(input.path); return { wrote: input.path }; },
};
const ok = {
  name: 't.ok', version: '1.0.0', effect: 'pure',
  inputSchema: { type: 'object', additionalProperties: true },
  execute: (input) => ({ value: input.value ?? 'done' }),
};
const fetcher = {
  name: 't.net', version: '1.0.0', effect: 'network',
  inputSchema: { type: 'object', additionalProperties: true },
  execute: () => ({ fetched: true }),
};

const registry = new Map([writer, ok, fetcher].map((t) => [t.name, t]));
const policy = {
  version: 1, allowedTools: [...registry.keys()].sort(),
  allowedEffects: ['pure', 'read', 'write', 'network'], maxOutputBytes: 10000, maxJournalBytes: 200000,
};
const sourceLock = { version: 1 };
const workspaceRoot = path.resolve('/explicit/workspace');
const base = (plan, overrides = {}) => ({ plan, policy, registry, sourceLock, workspaceRoot, ...overrides });
const preflight = (plan, overrides = {}) => planGrants({ plan, policy, registry, sourceLock, workspaceRoot, ...overrides });

const write = (id, file) => ({ id, tool: 't.write', input: { path: file, body: 'x' } });
const plan = (name, tasks) => ({ version: 1, name, tasks });

test('a hash computed before the run is the hash the kernel blocks on', async () => {
  // The whole feature in one assertion. Both sides call approvalRequest, but through completely
  // different paths -- one from the literal plan, one from inputFor's resolved and revalidated
  // input -- so agreeing is a real result rather than a tautology.
  const one = plan('one-write', [write('w', 'a.txt')]);
  const computed = preflight(one);
  const blocked = await runPlan(base(one));

  assert.equal(blocked.outcome.status, 'blocked');
  assert.equal(computed.grants.length, 1);
  assert.equal(computed.grants[0].requestHash, blocked.outcome.requestHash);
  assert.equal(computed.grants[0].requestHash, blocked.events.find((e) => e.type === 'blocked').data.requestHash);
});

test('a plan holding every grant runs in one pass, each effect exactly once', async () => {
  landed.length = 0;
  const many = plan('five-writes', ['a', 'b', 'c', 'd', 'e'].map((n) => write(n, n + '.txt')));
  const computed = preflight(many);

  assert.equal(computed.gatedCount, 5);
  assert.equal(computed.singlePass, true);
  assert.deepEqual(computed.grants.map((g) => g.taskId), ['a', 'b', 'c', 'd', 'e'], 'in execution order');

  const result = await runPlan(base(many, { approvals: computed.grants.map((g) => g.requestHash) }));
  assert.equal(result.outcome.status, 'completed');
  assert.equal(result.events.filter((e) => e.type === 'blocked').length, 0, 'never stopped');
  // The measurement that matters: five effects, five executions. Not six, not nine.
  assert.deepEqual(landed, ['a.txt', 'b.txt', 'c.txt', 'd.txt', 'e.txt']);
  replayPlan({ ...base(many), journal: result });
});

test('the round 009 failure this replaces: approving one gate at a time re-runs what already landed', async () => {
  // Kept as a live demonstration rather than a comment, because it is the entire argument for
  // computing grants up front. Approve-then-reattempt is the ONLY way a two-write plan could be
  // run before, and it re-executes the first write every single time.
  landed.length = 0;
  const two = plan('two-writes', [write('a', 'a.txt'), { ...write('b', 'b.txt'), dependsOn: ['a'] }]);

  const first = await runPlan(base(two));
  assert.equal(first.outcome.status, 'blocked');
  const second = await runPlan(base(two, { approvals: [first.outcome.requestHash] }));
  assert.equal(second.outcome.status, 'blocked', 'it lands a.txt, then stops at the second gate');
  const third = await runPlan(base(two, { approvals: [first.outcome.requestHash, second.outcome.requestHash] }));
  assert.equal(third.outcome.status, 'completed');

  // a.txt was written twice. For a non-idempotent effect that is the bug, and no amount of care
  // at the approval surface can prevent it once the plan has already been attempted.
  assert.deepEqual(landed, ['a.txt', 'a.txt', 'b.txt']);

  // Computed up front instead: one pass, one write each.
  landed.length = 0;
  const computed = preflight(two);
  const once = await runPlan(base(two, { approvals: computed.grants.map((g) => g.requestHash) }));
  assert.equal(once.outcome.status, 'completed');
  assert.deepEqual(landed, ['a.txt', 'b.txt']);
});

test('a gated task fed by an earlier result is deferred, never guessed at', () => {
  const chained = plan('chained', [
    { id: 'name', tool: 't.ok', input: { value: 'from-a' } },
    { id: 'w', tool: 't.write', input: { path: { $task: 'name', path: '/value' } }, dependsOn: ['name'] },
  ]);
  const computed = preflight(chained);

  assert.deepEqual(computed.grants, [], 'its resolved input does not exist yet, so neither does its request');
  assert.equal(computed.deferred.length, 1);
  assert.equal(computed.deferred[0].taskId, 'w');
  assert.equal(computed.deferred[0].reason, 'REFERENCE');
  assert.equal(computed.singlePass, false);

  // One gated task is still executable the old way: nothing completed earlier can be repeated.
  assert.doesNotThrow(() => assertSinglePass(computed, chained));
});

test('several gated tasks where one is deferred stays refused, and says which', () => {
  const mixed = plan('mixed', [
    write('literal', 'a.txt'),
    { id: 'name', tool: 't.ok', input: { value: 'b.txt' } },
    { id: 'derived', tool: 't.write', input: { path: { $task: 'name', path: '/value' } }, dependsOn: ['name'] },
  ]);
  const computed = preflight(mixed);
  assert.equal(computed.grants.length, 1);
  assert.equal(computed.deferred.length, 1);

  assert.throws(() => assertSinglePass(computed, mixed), (error) => error.code === 'PLAN_UNEXECUTABLE'
    && /derived/.test(error.message) && /re-attempt/.test(error.message));
});

test('granting everything is still not a grant to anything else', async () => {
  // A hash binds the plan, policy, registry, source lock and workspace. Each change below is one
  // an operator could make between approving and running, and each must stop the grant matching.
  const one = plan('one-write', [write('w', 'z.txt')]);
  const approvals = preflight(one).grants.map((g) => g.requestHash);
  assert.equal((await runPlan(base(one, { approvals }))).outcome.status, 'completed');

  const changes = [
    { label: 'a different workspace', change: { workspaceRoot: path.resolve('/elsewhere') } },
    { label: 'a different source lock', change: { sourceLock: { version: 2 } } },
    { label: 'a tightened policy', change: { policy: { ...policy, timeoutMs: 123 } } },
    { label: 'a changed input', change: { plan: plan('one-write', [{ id: 'w', tool: 't.write', input: { path: 'other.txt', body: 'x' } }]) } },
    { label: 'a changed tool config', change: { registry: new Map([...registry, ['t.write', { ...writer, config: { mode: 'new' } }]]) } },
  ];
  for (const { label, change } of changes) {
    const result = await runPlan(base(one, { approvals, ...change }));
    assert.equal(result.outcome.status, 'blocked', `${label} must invalidate the grant`);
  }
});

test('ungated tasks produce no grants at all', () => {
  const pure = plan('pure', [{ id: 'a', tool: 't.ok', input: { value: 1 } }, { id: 'b', tool: 't.ok', input: { value: 2 } }]);
  const computed = preflight(pure);
  assert.deepEqual(computed.grants, []);
  assert.deepEqual(computed.deferred, []);
  assert.equal(computed.gatedCount, 0);
  assert.equal(computed.singlePass, true);
  assert.doesNotThrow(() => assertSinglePass(computed, pure));
});

test('mixed effects are each recognised for what they are', () => {
  const mixed = plan('mixed-effects', [
    { id: 'p', tool: 't.ok', input: {} },
    { id: 'n', tool: 't.net', input: { url: 'x' } },
    write('w', 'a.txt'),
  ]);
  const computed = preflight(mixed);
  assert.deepEqual(computed.grants.map((g) => [g.taskId, g.effect]), [['n', 'network'], ['w', 'write']]);
  assert.equal(computed.gatedCount, 2);
});

test('an input the tool would reject takes the whole plan down, not just its own task', () => {
  // Stricter than deferring it, and not this module's doing: compile() validates every
  // reference-free input against its tool's schema, so inspectPlan rejects the plan before any
  // hash is computed. Asserted here because it is the reason preflight does NOT re-check schemas.
  const bad = plan('bad', [{ id: 'w', tool: 't.write', input: { path: 42 } }, write('ok', 'a.txt')]);
  assert.throws(() => preflight(bad), (e) => e.code === 'SCHEMA_MISMATCH');
});

test('an input too large to ever run is deferred rather than hashed', () => {
  // The one check inputFor makes that compile does not, so this case is reachable and the only
  // reason a reference-free gated task can still land in `deferred`.
  const huge = plan('huge', [{ id: 'w', tool: 't.write', input: { path: 'a.txt', body: 'x'.repeat(20000) } }, write('ok', 'b.txt')]);
  const computed = preflight(huge);
  assert.equal(computed.grants.length, 1, 'only the one that can actually run is offered');
  assert.equal(computed.grants[0].taskId, 'ok');
  assert.equal(computed.deferred[0].taskId, 'w');
  assert.equal(computed.deferred[0].reason, 'INPUT_LIMIT');
  assert.equal(computed.singlePass, false);
});

test('a plan the kernel would reject yields no hashes at all', () => {
  // Fails closed through inspectPlan rather than producing a hash for a run that cannot happen.
  assert.throws(() => preflight(plan('unknown', [{ id: 'x', tool: 'nope', input: {} }])), (e) => e.code === 'UNKNOWN_TOOL');
  assert.throws(() => preflight(plan('denied', [write('w', 'a.txt')]), { policy: { ...policy, allowedEffects: ['pure'] } }),
    (e) => e.code === 'POLICY_DENIED');
  assert.throws(() => preflight(plan('cycle', [
    { id: 'a', tool: 't.ok', input: {}, dependsOn: ['b'] },
    { id: 'b', tool: 't.ok', input: {}, dependsOn: ['a'] },
  ])), (e) => e.code === 'INVALID_PLAN');
});

test('preflight runs nothing', () => {
  landed.length = 0;
  const many = plan('three-writes', ['a', 'b', 'c'].map((n) => write(n, n + '.txt')));
  const computed = preflight(many);
  assert.equal(computed.grants.length, 3);
  assert.deepEqual(landed, [], 'computing a request is not performing it');
});

test('a four-file build whose last task is wrong is fixed and re-run without repeating the three that landed', async () => {
  // The point of all of this, end to end, with a real workspace.
  //
  // A plan cannot be "resumed" after a failure: correcting the broken task changes the plan hash,
  // hence every approval hash, so the corrected plan is a different run by construction and
  // re-executes the writes that already succeeded. Before writeExclusiveOrIdentical that re-run
  // died on the first of them with EEXIST, and the three good files made the build unrepeatable.
  const { makeBuiltinTools } = await import('../src/builtins.mjs');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const real = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'concord-build-')));
  const builtins = new Map(makeBuiltinTools().map((t) => [t.name, t]));
  const site = new Map([['files.writeText', builtins.get('files.writeText')]]);
  const sitePolicy = { version: 1, allowedTools: ['files.writeText'], allowedEffects: ['write'], maxOutputBytes: 65536, maxJournalBytes: 1048576 };
  const text = (id, file, body) => ({ id, tool: 'files.writeText', input: { path: file, text: body } });
  const run = (plan, approvals = []) => runPlan({ plan, policy: sitePolicy, registry: site, sourceLock: { version: 1 }, workspaceRoot: real, approvals });
  const grantsOf = (plan) => planGrants({ plan, policy: sitePolicy, registry: site, sourceLock: { version: 1 }, workspaceRoot: real })
    .grants.map((g) => g.requestHash);

  const good = [text('a', 'index.html', '<h1>Site</h1>'), text('b', 'style.css', 'body{}'), text('c', 'app.js', 'console.log(1)')];
  // The fourth task writes into a directory that does not exist, so it fails after three succeed.
  const broken = plan('build', [...good, text('d', 'missing/README.md', '# Site')]);

  const first = await run(broken, grantsOf(broken));
  assert.equal(first.outcome.status, 'failed');
  assert.equal(first.outcome.taskId, 'd');
  assert.equal(fs.readFileSync(path.join(real, 'index.html'), 'utf8'), '<h1>Site</h1>', 'the first three landed');

  // Correct the fourth task. Different plan, different hashes, a fresh set of grants.
  const fixed = plan('build', [...good, text('d', 'README.md', '# Site')]);
  assert.notEqual(digestOf(fixed), digestOf(broken));
  const second = await run(fixed, grantsOf(fixed));

  assert.equal(second.outcome.status, 'completed');
  // The three that already existed were accepted rather than rewritten, and say so.
  assert.deepEqual(['a', 'b', 'c'].map((id) => second.results[id].created), [false, false, false]);
  assert.equal(second.results.d.created, true, 'only the corrected task actually wrote');
  assert.equal(fs.readFileSync(path.join(real, 'README.md'), 'utf8'), '# Site');
  fs.rmSync(real, { recursive: true, force: true });
});
