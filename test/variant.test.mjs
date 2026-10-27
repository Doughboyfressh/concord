import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { makeVariantTools, runSummary } from '../src/variant.mjs';
import { runPlan, registryManifest } from '../src/engine.mjs';
import { digest } from '../src/value.mjs';

/**
 * Every fixture here is a real journal from runPlan, never a hand-written object.
 *
 * That is not thoroughness for its own sake. The whole claim of variant.contrast is that a run's
 * recorded header already proves what varied, so a contrast built from invented headers would
 * verify the test's idea of a journal rather than the kernel's. The one place a hand-built
 * contrast IS used is the selection test that must prove variant.select refuses evidence no real
 * run could have produced — there, fabricating it is the point.
 */

const ok = {
  name: 't.ok', version: '1.0.0', effect: 'pure',
  inputSchema: { type: 'object', additionalProperties: true },
  execute: (input) => ({ value: input.value }),
};
const boom = {
  name: 't.boom', version: '1.0.0', effect: 'pure',
  inputSchema: { type: 'object', additionalProperties: true },
  execute: () => { throw new Error('always'); },
};
const writer = {
  name: 't.write', version: '1.0.0', effect: 'write',
  inputSchema: { type: 'object', additionalProperties: true },
  execute: () => ({ written: true }),
};
/**
 * A tool whose output differs between calls, which is what `read` exists to declare.
 *
 * Needed because of something this kernel makes true and most harnesses do not: a run id here is
 * `digest(journal)`, so two runs of the same plan over PURE tools produce a byte-identical journal
 * and therefore the same id. They are not two entries that happen to agree, they are one entry.
 * Run-to-run variation is not merely rare in that case, it is unrepresentable. Producing the
 * variation this file needs to test for takes a tool that genuinely varies.
 */
let drifts = 0;
const drift = {
  name: 't.drift', version: '1.0.0', effect: 'read',
  inputSchema: { type: 'object', additionalProperties: true },
  execute: () => ({ seen: (drifts += 1) }),
};

const registry = new Map([ok, boom, writer, drift].map((tool) => [tool.name, tool]));
const policy = {
  version: 1, allowedTools: [...registry.keys()].sort(),
  allowedEffects: ['pure', 'read', 'write'], maxOutputBytes: 10000, maxJournalBytes: 200000,
};
const workspaceRoot = path.resolve('/explicit/workspace');
const base = (plan, overrides = {}) => ({ plan, policy, registry, sourceLock: { version: 1 }, workspaceRoot, ...overrides });

/** One recorded run, projected exactly as a session's ledger would hold it. */
const record = async (plan, overrides = {}) => {
  const result = await runPlan(base(plan, overrides));
  return runSummary({ id: digest(result).slice(0, 24), status: result.outcome.status, plan, planHash: digest(plan), result });
};

const plan = (name, tasks) => ({ version: 1, name, tasks });
const okTask = (id, value) => ({ id, tool: 't.ok', input: { value } });

const toolsOver = (ledger, options = {}) => {
  const [contrast, select] = makeVariantTools({ readRuns: () => ledger, ...options });
  return { contrast, select };
};
const context = { workspaceRoot, policy };

const contrastOf = (ledger, reference, candidates, options = {}) =>
  toolsOver(ledger, options).contrast.execute({ reference, candidates }, context);
const selectOver = (contrast, prefer, tolerance) =>
  toolsOver([]).select.execute({ contrast, prefer, ...(tolerance ? { tolerance } : {}) }, context);

test('a contrast between two plans proves that only the plan differed', async () => {
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2), okTask('c', 3)]));
  const candidate = await record(plan('leaner', [okTask('a', 1)]));
  const result = contrastOf([reference, candidate], reference.runId, [candidate.runId]);

  // The claim Harness²'s probe can only hope for: the policy, registry, source lock and workspace
  // digests matched, so a difference here cannot have come from the harness.
  assert.equal(result.candidates[0].comparable, true);
  assert.equal(result.candidates[0].variant, true);
  assert.equal(result.candidates[0].incomparable, undefined);

  const byField = new Map(result.candidates[0].differences.map((d) => [d.field, d]));
  assert.deepEqual(byField.get('trajectory.toolCalls'), { field: 'trajectory.toolCalls', reference: 3, candidate: 1 });
  assert.deepEqual(byField.get('trajectory.tasks'), { field: 'trajectory.tasks', reference: 3, candidate: 1 });
  assert.equal(byField.has('status'), false, 'both runs completed, so status is not a difference');
  assert.equal(result.candidates[0].deliverable.matchesReference, false);
});

test('a candidate run under a different registry is incomparable, and the contrast names which digest moved', async () => {
  const reference = await record(plan('same', [okTask('a', 1)]));
  // The harness changed under the experiment: one extra descriptor is enough to move registryHash.
  const widened = new Map([...registry, ['t.extra', { ...ok, name: 't.extra' }]]);
  const candidate = await record(plan('variant', [okTask('a', 1), okTask('b', 2)]), {
    registry: widened, policy: { ...policy, allowedTools: [...widened.keys()].sort() },
  });

  const result = contrastOf([reference, candidate], reference.runId, [candidate.runId]);
  assert.equal(result.candidates[0].comparable, false);
  // Both moved: allowedTools grew, so policyHash moved with registryHash. Naming them is the
  // diagnosis -- "incomparable" alone would not say the tools had changed underneath.
  assert.deepEqual(result.candidates[0].incomparable, ['policyHash', 'registryHash']);
  assert.ok(result.warnings.some((w) => w.code === 'INCOMPARABLE_RUN'));

  // And no winner is named while it is in the set. Deciding on the rest would be a confident
  // answer that silently excluded a candidate which might have been the best one.
  const decision = selectOver(result, ['fewerToolCalls']);
  assert.equal(decision.decision, 'undecided');
  assert.equal(decision.declined[0].code, 'INCOMPARABLE');
});

test('the same plan run twice is run-to-run variation, not a variant', async () => {
  // t.drift rather than t.ok, so the two runs really are two ledger entries: see its comment
  // above for why a pure plan cannot produce this case at all.
  const same = plan('same', [{ id: 'a', tool: 't.drift', input: {} }]);
  const reference = await record(same);
  const again = await record(same);
  assert.notEqual(reference.runId, again.runId);
  assert.equal(reference.planHash, again.planHash);

  const result = contrastOf([reference, again], reference.runId, [again.runId]);
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].variant, false);
  assert.ok(result.warnings.some((w) => w.code === 'NOT_A_VARIANT'));

  const decision = selectOver(result, ['fewerToolCalls']);
  assert.equal(decision.decision, 'undecided');
  assert.equal(decision.declined[0].code, 'NOT_A_VARIANT');
});

test('a fault every run shares carries no information about the variants', async () => {
  // Harness² measured incorrect premises propagating from the reference into every candidate at a
  // cost of 2 to 11 points. When the premise is wrong in the reference, every edit inherits it.
  const reference = await record(plan('reference', [{ id: 'x', tool: 't.boom', input: {} }]));
  const first = await record(plan('variant-one', [okTask('a', 1), { id: 'x', tool: 't.boom', input: {} }]));
  const second = await record(plan('variant-two', [okTask('a', 1), okTask('b', 2), { id: 'x', tool: 't.boom', input: {} }]));
  assert.equal(reference.status, 'failed');
  assert.equal(reference.failure.code, 'TOOL_FAILED');

  const result = contrastOf([reference, first, second], reference.runId, [first.runId, second.runId]);
  assert.deepEqual(result.sharedFailure, { code: 'TOOL_FAILED', runs: [reference.runId, first.runId, second.runId] });
  assert.ok(result.warnings.some((w) => w.code === 'SHARED_FAILURE'));

  // The candidates genuinely differ in trajectory -- they completed more tasks before failing --
  // so a selector comparing only call counts would happily name a winner here.
  assert.ok(result.candidates[0].differences.some((d) => d.field === 'trajectory.completed'));
  const decision = selectOver(result, ['completed', 'fewerToolCalls']);
  assert.equal(decision.decision, 'undecided');
  assert.equal(decision.declined[0].code, 'COMMON_MODE_FAILURE');
});

test('a blocked run looks like the cheapest run, and is refused as unfinished', async () => {
  // The trap this exists for: a run that stopped at the approval gate emits no intent at all, so
  // its toolCalls is zero and it beats every real run on any cost criterion. Adopting it would be
  // adopting the plan that did nothing.
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2)]));
  const gated = await record(plan('gated', [{ id: 'w', tool: 't.write', input: { path: 'x' } }]));
  assert.equal(gated.status, 'blocked');
  assert.equal(gated.trajectory.toolCalls, 0);

  const result = contrastOf([reference, gated], reference.runId, [gated.runId]);
  assert.ok(result.warnings.some((w) => w.code === 'INCOMPLETE_RUN'));
  const decision = selectOver(result, ['fewerToolCalls']);
  assert.equal(decision.decision, 'undecided');
  assert.equal(decision.declined[0].code, 'INCOMPLETE_RUN');
});

test('a win bought with a grant the reference never held is refused', async () => {
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2), okTask('c', 3)]));
  const gatedPlan = plan('granted', [{ id: 'w', tool: 't.write', input: { path: 'x' } }]);
  const blocked = await runPlan(base(gatedPlan));
  const approvals = [blocked.events.find((e) => e.type === 'blocked').data.requestHash];
  const candidate = await record(gatedPlan, { approvals });
  assert.equal(candidate.status, 'completed');
  assert.equal(candidate.grantsUsed, 1);

  const result = contrastOf([reference, candidate], reference.runId, [candidate.runId]);
  assert.equal(result.candidates[0].authorityDelta, 1);
  assert.ok(result.warnings.some((w) => w.code === 'UNEQUAL_AUTHORITY'));

  // It really does win on the declared criterion -- one tool call against three -- which is why
  // the refusal has to sit after the comparison rather than instead of it.
  const decision = selectOver(result, ['fewerToolCalls']);
  assert.equal(decision.decision, 'undecided');
  assert.equal(decision.declined[0].code, 'UNEQUAL_AUTHORITY');
});

test('authority is what a run spent, not what the session was holding', async () => {
  // The regression this exists for, found by running the tool live rather than by review.
  // header.approvals is the session's ACCUMULATED grant set and only ever grows, so counting it
  // made every later run look more authorised than every earlier one. Measured in the UI: a pure
  // two-task reference reported 1 and a pure one-task candidate reported 2, purely because a
  // model call had been approved in between, and UNEQUAL_AUTHORITY then refused a contrast
  // between two plans that had exercised no authority whatsoever.
  const unrelated = ['a'.repeat(64), 'b'.repeat(64)];
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2)]), { approvals: unrelated.slice(0, 1) });
  const candidate = await record(plan('candidate', [okTask('a', 1)]), { approvals: unrelated });

  assert.equal(reference.grantsUsed, 0, 'a pure plan spends no grant however many the session holds');
  assert.equal(candidate.grantsUsed, 0);

  const result = contrastOf([reference, candidate], reference.runId, [candidate.runId]);
  assert.equal(result.candidates[0].authorityDelta, 0);
  assert.equal(result.warnings.some((w) => w.code === 'UNEQUAL_AUTHORITY'), false);
  assert.equal(result.candidates[0].differences.some((d) => d.field === 'grantsUsed'), false);

  const decision = selectOver(result, ['fewerToolCalls']);
  assert.equal(decision.decision, 'adopt');
  assert.equal(decision.adopted, candidate.runId);
});

test('a leaner plan that reaches the same answer is visible as exactly that', async () => {
  // The finding worth having: same result, fewer steps. The full-output digest cannot show it --
  // the reference recorded an intermediate the candidate never produced, so every output taken
  // together differs. The terminal output is what "did it produce the same thing" actually asks.
  const reference = await record(plan('stepwise', [okTask('a', 1), okTask('b', 7)]));
  const direct = await record(plan('direct', [okTask('a', 7)]));

  const result = contrastOf([reference, direct], reference.runId, [direct.runId]);
  const candidate = result.candidates[0];
  assert.equal(candidate.deliverable.matchesTerminal, true, 'both runs ended holding the same output');
  assert.equal(candidate.deliverable.matchesReference, false, 'they did not do the same work to get there');
  assert.ok(candidate.differences.some((d) => d.field === 'deliverable.digest'));
  assert.equal(candidate.differences.some((d) => d.field === 'deliverable.terminalHash'), false);

  const decision = selectOver(result, ['fewerToolCalls']);
  assert.equal(decision.decision, 'adopt');
  assert.equal(decision.adopted, direct.runId);
});

test('a plan that changed without changing anything observable is no reason to adopt it', async () => {
  // Same tool, same input, different task id: the plan hash moves and not one measured field does.
  const reference = await record(plan('reference', [okTask('a', 1)]));
  const renamed = await record(plan('renamed', [okTask('b', 1)]));
  assert.notEqual(reference.planHash, renamed.planHash);

  const result = contrastOf([reference, renamed], reference.runId, [renamed.runId]);
  assert.equal(result.candidates[0].variant, true);
  assert.deepEqual(result.candidates[0].differences, []);
  assert.equal(result.candidates[0].deliverable.matchesReference, true);
  assert.ok(result.warnings.some((w) => w.code === 'NO_BEHAVIOURAL_DIFFERENCE'));

  const decision = selectOver(result, ['fewerToolCalls']);
  assert.equal(decision.decision, 'keep');
  assert.equal(decision.adopted, reference.runId);
  assert.equal(decision.declined[0].code, 'NO_IMPROVEMENT');
});

test('one clear improvement is adopted, and cites the observation verbatim', async () => {
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2), okTask('c', 3)]));
  const lean = await record(plan('lean', [okTask('a', 1)]));
  const middle = await record(plan('middle', [okTask('a', 1), okTask('b', 2)]));

  const result = contrastOf([reference, lean, middle], reference.runId, [lean.runId, middle.runId]);
  const decision = selectOver(result, ['completed', 'fewerToolCalls']);

  assert.equal(decision.decision, 'adopt');
  assert.equal(decision.adopted, lean.runId, 'one call beats two, which beats the reference three');
  assert.deepEqual(decision.because, [{
    criterion: 'fewerToolCalls', field: 'trajectory.toolCalls', reference: 3, candidate: 1,
  }]);
  // The cited observation is the contrast's own entry, not a restatement of it.
  const observed = result.candidates.find((c) => c.runId === lean.runId).differences
    .find((d) => d.field === 'trajectory.toolCalls');
  assert.deepEqual({ criterion: 'fewerToolCalls', ...observed }, decision.because[0]);
  // The decision names the exact evidence it was computed from.
  assert.equal(decision.contrastHash, result.contrastHash);
  assert.deepEqual([...decision.considered].sort(), [lean.runId, middle.runId].sort());
});

test('a tie is never broken', async () => {
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2), okTask('c', 3)]));
  // Two variants, each one call cheaper than the reference and indistinguishable from each other
  // on the declared criterion. Breaking this on run id would be reproducible and still arbitrary.
  const first = await record(plan('first', [okTask('a', 1), okTask('b', 9)]));
  const second = await record(plan('second', [okTask('a', 7), okTask('b', 8)]));
  const result = contrastOf([reference, first, second], reference.runId, [first.runId, second.runId]);
  assert.equal(result.candidates[0].trajectory.toolCalls, result.candidates[1].trajectory.toolCalls);

  const decision = selectOver(result, ['fewerToolCalls']);
  assert.equal(decision.decision, 'undecided');
  assert.equal(decision.declined[0].code, 'TIE');
  assert.equal(decision.adopted, null);
});

test('a declared tolerance keeps a one-call difference from reading as a win', async () => {
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2)]));
  const candidate = await record(plan('candidate', [okTask('a', 1)]));
  const result = contrastOf([reference, candidate], reference.runId, [candidate.runId]);

  assert.equal(selectOver(result, ['fewerToolCalls']).decision, 'adopt');
  const tolerant = selectOver(result, ['fewerToolCalls'], { toolCalls: 1 });
  assert.equal(tolerant.decision, 'keep');
  assert.equal(tolerant.rule.tolerance.toolCalls, 1);
});

test('selection cannot cite a field that nothing measured', () => {
  // The structural guarantee, tested with evidence no real run could produce: a candidate that
  // claims a lower call count while reporting no observed difference in it. Harness²'s composer
  // is a model free-forming a judgement, and its appendix reports it selecting 55 over 95. Here
  // the only reasons available are the contrast's own entries, so a missing one is not a weaker
  // decision, it is no decision.
  const summary = (runId, toolCalls) => ({
    runId, planHash: 'hash-' + runId, status: 'completed',
    trajectory: { tasks: toolCalls, toolCalls, completed: toolCalls, tools: ['t.ok'] },
    deliverable: { digest: 'd-' + runId, terminalHash: 't-' + runId, outputCount: toolCalls, matchesReference: false, matchesTerminal: false },
    failure: null, grantsUsed: 0,
  });
  const fabricated = {
    reference: summary('ref', 3),
    candidates: [{ ...summary('cand', 1), comparable: true, variant: true, authorityDelta: 0, differences: [] }],
    missing: [], sharedFailure: null, warnings: [], contrastHash: 'x',
  };
  assert.throws(() => selectOver(fabricated, ['fewerToolCalls']),
    (error) => error.code === 'SELECTION_UNGROUNDED' && /trajectory\.toolCalls/.test(error.message));
});

test('an unknown run is reported rather than thrown, and selection declines on it', async () => {
  const reference = await record(plan('reference', [okTask('a', 1)]));
  const present = contrastOf([reference], reference.runId, ['nosuchrun']);
  assert.deepEqual(present.missing, ['nosuchrun']);
  assert.deepEqual(present.candidates, []);
  assert.ok(present.warnings.some((w) => w.code === 'UNKNOWN_RUN'));
  assert.equal(selectOver(present, ['fewerToolCalls']).declined[0].code, 'NO_CANDIDATES');

  const absent = contrastOf([reference], 'nosuchref', [reference.runId]);
  assert.equal(absent.reference, null);
  assert.ok(absent.warnings.some((w) => w.code === 'UNKNOWN_REFERENCE'));
  assert.equal(selectOver(absent, ['fewerToolCalls']).declined[0].code, 'NO_REFERENCE');

  // A run cannot be a variant of itself, and saying so is better than contrasting it with itself.
  const reflexive = contrastOf([reference], reference.runId, [reference.runId]);
  assert.deepEqual(reflexive.candidates, []);
  assert.ok(reflexive.warnings.some((w) => w.code === 'REFERENCE_AS_CANDIDATE'));
});

test('counts come from the journal, not from the plan', async () => {
  // A plan lists what was asked for; only an intent proves a tool was invoked and only a completed
  // proves an output was recorded. The distinction is the whole of Harness²'s call-count metric.
  // Declared as a dependency chain rather than relying on task ids sorting the way the reader
  // expects: compile() orders ready tasks alphabetically, so a plan whose failing task happens to
  // sort last executes everything before stopping and measures nothing.
  const summary = await record(plan('failing', [
    okTask('a', 1),
    { id: 'b', tool: 't.boom', input: {}, dependsOn: ['a'] },
    { ...okTask('c', 3), dependsOn: ['b'] },
  ]));
  assert.equal(summary.trajectory.tasks, 3, 'three tasks were asked for');
  assert.equal(summary.trajectory.toolCalls, 2, 'two tools were actually invoked');
  assert.equal(summary.trajectory.completed, 1, 'one output was recorded');
  assert.deepEqual(summary.trajectory.tools, ['t.boom', 't.ok']);
  assert.deepEqual(summary.failure, { taskId: 'b', code: 'TOOL_FAILED' });
  assert.equal(summary.deliverable.outputCount, 1);
});

test('the registry digest does not move when the run ledger does', async () => {
  // The reason the ledger is a closure and not config. registryManifest hashes every descriptor's
  // config into the digest that binds approval hashes and replay, so a config carrying the ledger
  // would invalidate the previous run's grants every time a run was recorded.
  let ledger = [];
  const [contrast, select] = makeVariantTools({ readRuns: () => ledger });
  const manifest = () => digest(registryManifest(new Map([[contrast.name, contrast], [select.name, select]])));
  const before = manifest();

  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2)]));
  const candidate = await record(plan('candidate', [okTask('a', 1)]));
  ledger = [reference, candidate];

  assert.equal(before, manifest());
  // And it really is reading the new ledger, so the digest held still for the right reason rather
  // than because the closure was stale.
  const result = contrast.execute({ reference: reference.runId, candidates: [candidate.runId] }, context);
  assert.equal(result.totalRuns, 2);
  assert.equal(result.candidates.length, 1);
});

test('every declared outputKeys is present in each of the three outcomes', async () => {
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2)]));
  const lean = await record(plan('lean', [okTask('a', 1)]));
  const heavy = await record(plan('heavy', [okTask('a', 1), okTask('b', 2), okTask('c', 3)]));
  const { contrast, select } = toolsOver([reference, lean, heavy]);

  const result = contrast.execute({ reference: reference.runId, candidates: [lean.runId] }, context);
  for (const key of contrast.outputKeys) assert.ok(key in result, `contrast is missing ${key}`);

  const outcomes = [
    select.execute({ contrast: result, prefer: ['fewerToolCalls'] }, context),
    select.execute({ contrast: contrast.execute({ reference: reference.runId, candidates: [heavy.runId] }, context), prefer: ['fewerToolCalls'] }, context),
    select.execute({ contrast: { reference: null, candidates: [] }, prefer: ['fewerToolCalls'] }, context),
  ];
  assert.deepEqual(outcomes.map((o) => o.decision), ['adopt', 'keep', 'undecided']);
  for (const outcome of outcomes) {
    for (const key of select.outputKeys) assert.ok(key in outcome, `select is missing ${key} on a ${outcome.decision}`);
  }
});

test('a contrast too large for the observation window fails closed rather than truncating', async () => {
  const reference = await record(plan('reference', [okTask('a', 1), okTask('b', 2)]));
  const candidate = await record(plan('candidate', [okTask('a', 1)]));
  assert.throws(
    () => contrastOf([reference, candidate], reference.runId, [candidate.runId], { maxBytes: 1024 }),
    (error) => error.code === 'CONTRAST_TOO_LARGE');
});

test('the store refuses a configuration it cannot read a ledger from', () => {
  assert.throws(() => makeVariantTools({}), /VARIANT_CONFIG|readRuns/);
  assert.throws(() => makeVariantTools({ readRuns: () => [], maxBytes: 16 }), /VARIANT_CONFIG|maxBytes/);
  const [contrast, select] = makeVariantTools({ readRuns: () => null });
  assert.throws(() => contrast.execute({ reference: 'a', candidates: ['b'] }, context), /VARIANT_LEDGER|unavailable/);
  // Distinct criteria only: a repeated preference would silently do nothing on its second pass.
  assert.throws(() => select.execute({ contrast: { reference: null, candidates: [] }, prefer: ['fewerToolCalls', 'fewerToolCalls'] }, context),
    (error) => error.code === 'INPUT_INVALID');
});
