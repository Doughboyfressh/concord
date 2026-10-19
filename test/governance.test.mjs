import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeGovernanceTools } from '../src/governance.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';

// Delegation, scheduling and hook rules: three capabilities Concord described and did not have.
// None needed a dependency; each needed a shape that survives the kernel's contract.

const byName = (tools) => new Map(tools.map((tool) => [tool.name, tool]));
const sourceLock = { catalog: { sources: [] }, inventoryHash: 'x', runtime: { node: 'test', platform: 'test', arch: 'test', files: [] } };
// A real policy always names its allowed tools, and attenuation can only ever narrow that list,
// so the fixture has to carry the whole registry for the delegate to be able to reduce it.
const policyFor = (registry) => ({
  version: 1, allowedTools: [...registry.keys()].sort(),
  allowedEffects: ['pure', 'read', 'write', 'network', 'process'], allowedOrigins: [],
  maxTasks: 32, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 10000,
});
const workspace = () => fs.mkdtempSync(path.join(os.tmpdir(), 'concord-gov-'));

function governance() {
  const registry = new Map(makeBuiltinTools().map((tool) => [tool.name, tool]));
  return { registry, tools: byName(makeGovernanceTools({ registry, sourceLock })) };
}

test('hook rules decide and never execute anything', () => {
  const { tools } = governance();
  const hooks = tools.get('hooks.evaluate');
  assert.equal(hooks.effect, 'pure');

  const rules = [
    { id: 'anything-goes', decision: 'allow' },
    { id: 'no-writes-to-config', decision: 'deny', reason: 'config is reviewed by hand', when: { effect: 'write', pathPrefix: 'config/' } },
    { id: 'watch-the-network', decision: 'warn', reason: 'leaves the machine', when: { effect: 'network' } },
  ];

  const denied = hooks.execute({ rules, event: { tool: 'files.write', effect: 'write', input: { path: 'config/live.json' } } });
  // The strictest matching decision wins: a rule set where one allows and another denies has not
  // expressed a preference, and the safer rule must not be the easiest to cancel by accident.
  assert.equal(denied.decision, 'deny');
  assert.deepEqual(denied.matched.map((match) => match.id), ['anything-goes', 'no-writes-to-config']);
  assert.deepEqual(denied.reasons, ['config is reviewed by hand']);

  assert.equal(hooks.execute({ rules, event: { tool: 'model.propose', effect: 'network' } }).decision, 'warn');
  // A condition that is present must hold; one that is absent is simply not asked.
  assert.equal(hooks.execute({ rules, event: { tool: 'files.write', effect: 'write', input: { path: 'notes/x.md' } } }).decision, 'allow');
  assert.equal(hooks.execute({ rules, event: { tool: 'json.hash', effect: 'pure' } }).decision, 'allow');

  const prefixed = hooks.execute({ rules: [{ id: 'artifacts', decision: 'warn', when: { toolPrefix: 'artifact.' } }], event: { tool: 'artifact.sqlite', effect: 'read' } });
  assert.equal(prefixed.decision, 'warn');
  assert.equal(prefixed.limitations.length, 2);
});

test('a schedule is recorded intent, and being due is a statement about a supplied time', (t) => {
  const root = workspace();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const { registry, tools } = governance();
  const context = { workspaceRoot: root, policy: policyFor(registry) };

  const declare = tools.get('schedule.declare');
  const due = tools.get('schedule.due');
  assert.equal(declare.effect, 'write');
  assert.equal(due.effect, 'read');

  // Nothing declared yet is an empty answer, not a failure.
  assert.deepEqual(due.execute({ now: '2026-10-19T00:00:00Z' }, context).due, []);

  const plan = { version: 1, tasks: [{ id: 'a', tool: 'json.hash', input: { value: 1 } }] };
  const first = declare.execute({ id: 'nightly-review', dueAt: '2026-10-19T02:00:00Z', plan }, context);
  assert.equal(first.replaced, false);
  declare.execute({ id: 'weekly-sweep', dueAt: '2026-10-26T02:00:00Z', plan }, context);

  // The kernel never reads a clock: the caller says what time it is, which is what makes this
  // answer reproducible.
  const early = due.execute({ now: '2026-10-19T01:00:00Z' }, context);
  assert.deepEqual(early.due, []);
  assert.equal(early.pending, 2);

  const later = due.execute({ now: '2026-10-19T03:00:00Z' }, context);
  assert.deepEqual(later.due.map((entry) => entry.id), ['nightly-review']);
  assert.equal(later.pending, 1);
  assert.equal(later.total, 2);

  // Re-declaring the same id replaces it, which is also how a completed schedule is advanced.
  const again = declare.execute({ id: 'nightly-review', dueAt: '2026-10-20T02:00:00Z', plan }, context);
  assert.equal(again.replaced, true);
  assert.deepEqual(due.execute({ now: '2026-10-19T03:00:00Z' }, context).due, []);

  for (const bad of [{ id: 'Nightly', dueAt: '2026-10-19T02:00:00Z', plan }, { id: 'ok-id', dueAt: 'tuesday', plan }]) {
    assert.throws(() => declare.execute(bad, context), (error) => /^SCHEDULE_/.test(error.code));
  }
});

test('a delegate runs with strictly less authority than whoever asked', async (t) => {
  const root = workspace();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const { registry, tools } = governance();
  const delegate = tools.get('agent.delegate');
  const context = { workspaceRoot: root, policy: policyFor(registry) };

  // Read, not write: a delegate can do nothing its caller could not already do without a grant,
  // which is what makes it safe to leave ungated.
  assert.equal(delegate.effect, 'read');

  const done = await delegate.execute({
    plan: { version: 1, name: 'research', tasks: [{ id: 'hash', tool: 'json.hash', input: { value: { a: 1 } } }] },
  }, context);
  assert.equal(done.status, 'completed');
  assert.equal(typeof done.results.hash.digest, 'string');
  assert.deepEqual(done.blocked, []);
  assert.equal(done.authority.approvals, 0);
  assert.equal(done.rejection, null);

  // An effectful step comes back as data for the caller to escalate deliberately, rather than
  // running on borrowed authority.
  const refused = await delegate.execute({
    plan: { version: 1, name: 'overreach', tasks: [{ id: 'w', tool: 'files.write', input: { path: 'x.json', content: { a: 1 } } }] },
  }, context);
  // Blocked, with the attempt recorded: equally unable to run, but it says what was tried.
  assert.equal(refused.status, 'blocked');
  assert.deepEqual(refused.blocked.map((entry) => entry.tool), ['files.write']);
  assert.equal(fs.existsSync(path.join(root, 'x.json')), false);

  // And it cannot delegate again: recursion here would spend a caller's whole budget on
  // bookkeeping, and nothing needs it.
  const recursive = await delegate.execute({
    plan: { version: 1, name: 'again', tasks: [{ id: 'd', tool: 'agent.delegate', input: { plan: { version: 1, tasks: [] } } }] },
  }, context);
  assert.equal(recursive.status, 'rejected');
  assert.equal(recursive.rejection.code, 'UNKNOWN_TOOL');

  for (const bad of [{ plan: { version: 1, tasks: [] } }, { plan: {} }]) {
    await assert.rejects(delegate.execute(bad, context), (error) => error.code === 'DELEGATE_PLAN');
  }
});

test('delegation is not registered when there is nothing to delegate against', () => {
  const names = makeGovernanceTools({}).map((tool) => tool.name);
  // Registered-and-always-failing is worse than absent: a tool that exists implies it can be used.
  assert.equal(names.includes('agent.delegate'), false);
  assert.deepEqual(names, ['hooks.evaluate', 'schedule.declare', 'schedule.due']);
});
