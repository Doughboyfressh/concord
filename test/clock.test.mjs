import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { runPlan, replayPlan } from '../src/engine.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';
import { makeGovernanceTools } from '../src/governance.mjs';
import { tempDir } from './temp-workspace.mjs';

const tools = [...makeBuiltinTools(), ...makeGovernanceTools({})];
const registry = new Map(tools.map(t => [t.name, t]));
const clock = registry.get('time.now');
const policy = {
  version: 1, allowedTools: [...registry.keys()], allowedEffects: ['pure', 'read'],
  maxOutputBytes: 10000, maxJournalBytes: 100000,
};
const base = (plan, workspaceRoot) => ({ plan, policy, registry, sourceLock: { version: 1 }, workspaceRoot });

test('the clock is a read effect, so the kernel records it instead of trusting it twice', () => {
  // Pure would be a lie: a pure tool promises the same output for the same input forever, and a
  // clock cannot. Read is the honest declaration, and it is what gets the instant journalled.
  assert.equal(clock.effect, 'read');
  assert.deepEqual(clock.inputSchema.properties, {});
  assert.equal(clock.inputSchema.additionalProperties, false);
});

test('it reports the host clock as a usable UTC instant', () => {
  const before = Date.now();
  const observed = clock.execute({}, {});
  const after = Date.now();
  assert.match(observed.iso, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.ok(Number.isInteger(observed.epochMs));
  assert.ok(observed.epochMs >= before && observed.epochMs <= after, 'the instant is this moment, not a constant');
  // The two forms must agree, or a plan that reads one and compares the other is quietly wrong.
  assert.equal(Date.parse(observed.iso), observed.epochMs);
});

test('a replay returns the instant that was recorded, not the time of the replay', async () => {
  const workspaceRoot = tempDir('concord-clock-');
  try {
    const plan = { version: 1, tasks: [{ id: 'clock', tool: 'time.now', input: {} }] };
    const journal = await runPlan(base(plan, workspaceRoot));
    const recorded = journal.results.clock.iso;

    // The clock has moved on by the time this replays, and that is the point: replay never
    // invokes a tool, so it reproduces the recorded instant. If it re-read the clock the output
    // hash would not match and this would throw rather than return replayed.
    const replayed = replayPlan({ ...base(plan, workspaceRoot), journal, expectedRoot: journal.root });
    assert.equal(replayed.replayed, true);
    assert.equal(journal.results.clock.iso, recorded, 'the journal still holds the instant it observed');
  } finally {
    const { rmSync } = await import('node:fs');
    rmSync(workspaceRoot, { recursive: true, force: true });
  }
});

test('two live runs of the same plan are different runs, which is what read effects mean', async () => {
  const workspaceRoot = tempDir('concord-clock-live-');
  try {
    const plan = { version: 1, tasks: [{ id: 'clock', tool: 'time.now', input: {} }] };
    const first = await runPlan(base(plan, workspaceRoot));
    // Busy-wait past a millisecond boundary rather than sleeping: this must not be able to pass
    // by accident when two runs land in the same millisecond.
    const until = Date.now() + 2;
    while (Date.now() < until) { /* spin */ }
    const second = await runPlan(base(plan, workspaceRoot));
    assert.notEqual(first.results.clock.epochMs, second.results.clock.epochMs);
    assert.notEqual(first.root, second.root, 'a clock reading makes the run identity differ, as any read does');
  } finally {
    const { rmSync } = await import('node:fs');
    rmSync(workspaceRoot, { recursive: true, force: true });
  }
});

test('the clock feeds schedule.due, which still takes its time from the caller', async () => {
  // This is the composition the clock exists for. schedule.due was written to require `now` from
  // its caller so it stays reproducible, and that is unchanged — what changed is that the caller
  // now has somewhere true to get the answer instead of the model inventing a timestamp.
  const workspaceRoot = tempDir('concord-clock-schedule-');
  try {
    const plan = { version: 1, tasks: [
      { id: 'clock', tool: 'time.now', input: {} },
      { id: 'due', tool: 'schedule.due', input: { now: { $task: 'clock', path: '/iso' } }, dependsOn: ['clock'] },
    ] };
    const journal = await runPlan(base(plan, workspaceRoot));
    // Accepting the reference at all is the assertion: schedule.due parses `now` with Date.parse
    // and refuses SCHEDULE_TIME on anything it cannot read, so reaching a result proves the
    // clock's ISO form is one it accepts.
    assert.equal(journal.results.due.now, journal.results.clock.iso);
    assert.deepEqual(journal.results.due.due, []);
    assert.equal(journal.results.due.total, 0);
    assert.equal(replayPlan({ ...base(plan, workspaceRoot), journal, expectedRoot: journal.root }).replayed, true);
  } finally {
    const { rmSync } = await import('node:fs');
    rmSync(workspaceRoot, { recursive: true, force: true });
  }
});
