import fs from 'node:fs';
import path from 'node:path';
import { digest } from '../src/value.mjs';
import { runPlan } from '../src/engine.mjs';

/**
 * Long-horizon work: what holds when a task outlives the run that started it.
 *
 * Everything else in this suite exercises a capability inside one plan. These exercise the parts
 * that only matter once work spans an interruption, an approval someone has to come back to, or a
 * second session days later — and the striking thing about this kernel is that it does not try to
 * solve that with a daemon or a retry loop. It has no clock and no scheduler. What it has instead:
 *
 *   schedule.declare / schedule.due   future work recorded as a plan plus its digest, due only
 *                                     against a time the *caller* supplies
 *   artifact.obligationLedger         what is still owed, and what a verifier has to be before it
 *                                     may close anything
 *   the journal sink                  durable intent written before an effect runs, so an
 *                                     interrupted run leaves evidence rather than ambiguity
 *   the task bound                    a long plan is bounded by policy, at compile time
 *
 * The reason this is trainable at all is that none of it reads the clock. `schedule.due` answers
 * against the instant it was given, so "a month from now" is an argument rather than a wait, and a
 * recorded long-horizon run replays exactly. A scheduler that read the system clock would make
 * every one of these exercises unreproducible, which is the trade that was deliberately not made.
 */

const LATER = { version: 1, name: 'the-work-itself', tasks: [{ id: 'x', tool: 'json.value', input: { note: 'run me later' } }] };
const DUE_AT = '2026-12-01T00:00:00Z';
const BEFORE = '2026-11-01T00:00:00Z';
const AFTER = '2027-01-01T00:00:00Z';

/** A chain where every task consumes the one before it, so the last digest depends on all of them. */
const chainOf = (length) => ({
  version: 1, name: 'long-chain',
  tasks: Array.from({ length }, (unused, index) => (index === 0
    ? { id: 't0', tool: 'json.hash', input: { seed: 'start' } }
    : { id: `t${index}`, tool: 'json.hash', dependsOn: [`t${index - 1}`], input: { previous: { $task: `t${index - 1}`, path: '/digest' } } })),
});

const LEDGER_INPUT = {
  facts: [
    { id: 'o1', subject: 'the decompiled entry point matches the disassembly', kind: 'static', required: true, owner: 'reverse' },
    { id: 'o2', subject: 'the build is reproducible', kind: 'runtime', required: true, owner: 'build' },
    { id: 'o3', subject: 'the page said what we claim', kind: 'runtime', required: true, owner: 'web' },
    { id: 'o4', subject: 'nothing verifies this at all', kind: 'static', required: true, owner: 'reverse' },
  ],
  verifiers: [
    { obligationIds: ['o1'], result: 'pass', authority: 'replay', evidenceIds: ['sha256:abc'] },
    { obligationIds: ['o2'], result: 'pass', authority: 'inferred', evidenceIds: ['sha256:def'] },
    { obligationIds: ['o3'], result: 'fail', authority: 'replay', evidenceIds: [] },
  ],
};

/** Counts invocations of the journal exercise, which the runner calls twice to check determinism. */
let attempt = 0;

export function horizonExercises() {
  return [
    {
      family: 'horizon', tool: 'schedule.due', grant: true, expectApprovals: 1, workspace: 'temp',
      plan: { version: 1, name: 'declare-work-for-later-then-ask-twice', tasks: [
        { id: 'declared', tool: 'schedule.declare', input: { id: 'nightly-report', dueAt: DUE_AT, plan: LATER, note: 'a long-horizon declaration' } },
        { id: 'before', tool: 'schedule.due', dependsOn: ['declared'], input: { now: BEFORE } },
        { id: 'after', tool: 'schedule.due', dependsOn: ['declared'], input: { now: AFTER } },
      ] },
      expect: (r) => r.results.declared.id === 'nightly-report' && r.results.declared.dueAt === DUE_AT
        && r.results.declared.replaced === false
        // The work to do later is carried as a plan and pinned by its digest.
        && r.results.declared.planHash === digest(LATER)
        && r.results.declared.limitations.some((note) => note.includes('starts no timer'))
        && r.results.before.due.length === 0 && r.results.before.pending === 1
        && r.results.before.total === 1 && r.results.before.now === BEFORE
        && r.results.after.due.length === 1 && r.results.after.pending === 0
        && r.results.after.due[0].planHash === r.results.declared.planHash
        && r.results.after.due[0].plan.tasks[0].tool === 'json.value'
        && r.results.after.due[0].note === 'a long-horizon declaration'
        && r.results.after.limitations.some((note) => note.includes('not an event')),
      lesson: 'Future work is declared as a plan plus the digest of that plan, and whether it is due is answered against an instant the caller supplies rather than a clock. The same declaration is pending at one date and due at another inside a single run, which is only possible because nothing here reads the time: Concord has no daemon, declaring a schedule starts no timer, and being due is a statement about the now you passed in rather than an event that fired. That is what makes a long-horizon plan replayable at all — a scheduler reading the system clock would make every recorded run of it unreproducible. The work itself travels with the declaration, so what comes back when it falls due is the plan to run and its hash, not a reminder that something was once intended.',
    },
    {
      family: 'horizon', tool: 'schedule.declare', grant: true, expectApprovals: 2, workspace: 'temp',
      plan: { version: 1, name: 'advance-a-schedule-by-redeclaring-it', tasks: [
        { id: 'first', tool: 'schedule.declare', input: { id: 'rolling-task', dueAt: DUE_AT, plan: LATER } },
        { id: 'again', tool: 'schedule.declare', dependsOn: ['first'], input: { id: 'rolling-task', dueAt: AFTER, plan: LATER } },
        { id: 'state', tool: 'schedule.due', dependsOn: ['again'], input: { now: DUE_AT } },
      ] },
      expect: (r) => r.results.again.replaced === true
        && r.results.again.dueAt === AFTER
        && r.results.first.planHash === r.results.again.planHash
        // Both report replaced:true, and the first one is the finding — see the lesson. In a
        // workspace that has never held this id, the first declaration still says it replaced
        // something, because collecting the second approval re-ran the plan and performed the
        // first write a second time.
        && r.results.first.replaced === true
        // Counted over this id alone: the round shares one scratch workspace and another exercise
        // has already declared a schedule of its own in it, so the store's total is not this
        // exercise's business. What is: this id is now pending rather than due at the date it was
        // first given.
        && r.results.state.due.every((entry) => entry.id !== 'rolling-task')
        && r.results.state.total >= 1 && r.results.state.pending >= 1,
      lesson: 'Re-declaring a schedule under the same id replaces it and says so, which is how a repeating long-horizon task is advanced rather than accumulated: after two declarations one record remains, now due at the later date. The finding is in the first declaration, which reports replaced:true even in a workspace that has never held that id — because a plan with two effects is run three times to collect two approvals, and every already-granted effect is performed again on each pass. A task that blocks does not execute on that run; it executes on the run where its hash is granted, and on every run after it. So the first write here happened twice. There is no way to avoid that by collecting all the hashes first, because a request hash binds the *resolved* input and a later task\'s input can depend on an earlier task\'s output, which only exists once that earlier effect has actually run. For long-horizon work that is the property to design around: an effect reached through a multi-grant plan must be idempotent, as replacing a schedule by id is, or it will be performed once per remaining approval. A plan with a single effect is unaffected: it blocks before executing anything, so the granted run performs it exactly once, which the journal exercise beside this one shows directly. And where an effect is not idempotent the kernel refuses rather than double-applying — the exercise above this one reaches EFFECT_INDETERMINATE by that exact route.',
    },
    {
      family: 'horizon', tool: 'files.write', expectCode: 'EFFECT_INDETERMINATE',
      grant: true, expectApprovals: 2, workspace: 'temp',
      plan: { version: 1, name: 'two-writes-one-grant-at-a-time', tasks: [
        { id: 'a', tool: 'files.write', input: { path: 'horizon-first.json', content: { n: 1 } } },
        { id: 'b', tool: 'files.write', dependsOn: ['a'], input: { path: 'horizon-second.json', content: { n: 2 } } },
      ] },
      lesson: 'A plan with two non-idempotent effects cannot be completed by granting one approval at a time, and the kernel says so with EFFECT_INDETERMINATE rather than quietly applying the first effect twice. The sequence is forced: the first run blocks before executing anything, the second run performs the first write and blocks on the second, and the third run — which now carries both grants — reaches the first write again and finds the world already changed. files.write creates exclusively and never replaces, so its outcome cannot be re-established, and the honest answer is that this effect\'s state is indeterminate. There is no way around it by collecting every hash up front, because a request hash binds the resolved input and a later task\'s input may depend on an earlier task\'s output, which does not exist until that earlier effect has run. So a long-horizon plan either keeps to a single effect per run, or its effects are idempotent by construction — replacing a schedule by id, promoting a lesson to the path its own digest names — and this is the sharpest reason the write tools in this harness are built that way rather than as appends.',
    },
    {
      family: 'horizon', tool: 'artifact.obligationLedger',
      plan: { version: 1, name: 'what-is-still-owed', tasks: [
        { id: 'owed', tool: 'artifact.obligationLedger', input: LEDGER_INPUT },
      ] },
      expect: (r) => {
        const byId = new Map(r.results.owed.obligations.map((entry) => [entry.id, entry]));
        return r.results.owed.obligations.length === 4
          && byId.get('o1').status === 'closed' && byId.get('o1').verifierAuthority === 'replay'
          && byId.get('o1').reason === null
          // A passing verifier is not enough: inferred authority cannot close anything.
          && byId.get('o2').status === 'open' && byId.get('o2').reason.includes('inferred authority')
          && byId.get('o3').status === 'open' && byId.get('o3').reason.includes('did not pass')
          && byId.get('o4').status === 'open' && byId.get('o4').reason.includes('No verifier')
          && r.results.owed.summary.closed === 1 && r.results.owed.summary.open === 3
          && r.results.owed.summary.contradicted === 0
          && r.results.owed.limitations.some((note) => note.includes('behaviourally correct'))
          && r.results.owed.limitations.some((note) => note.includes('raises no obligation'));
      },
      lesson: 'The obligation ledger is the accounting a long task needs: what was claimed, what is still owed, and what a verifier has to be before it may close anything. Only a passing verifier that enumerates the obligation and carries replay authority closes it — a passing verifier with inferred authority leaves the obligation open and says so, because an inference is not comparable to the original observation. Three different reasons for staying open are reported rather than one: the verifier failed, the verifier was not comparable, or nothing enumerated this obligation at all. The ledger also states its own two boundaries: a closed obligation means a replay-authority verifier cited evidence, not that the reconstruction behaves correctly, and an obligation nobody recorded raises nothing, so the ledger is only ever as complete as the facts it was handed.',
    },
    {
      family: 'horizon', tool: 'engine.journal', workspace: 'temp',
      /**
       * A call rather than a plan, because the thing under test is the journal sink itself, which
       * a plan cannot ask for: journalPath is an argument to runPlan, not a tool input.
       */
      call: async ({ registry, policy, sourceLock, workspaceRoot }) => {
        // Every artefact this call touches is named for the attempt. The journal sink is created
        // exclusively so it cannot reuse a path, and the written file has to be a creation each
        // time too — otherwise the runner's second invocation overwrites the first one's file and
        // the two results differ for a reason that has nothing to do with journalling. Found
        // exactly that way: reported as non-deterministic when only the workspace had moved.
        attempt += 1;
        const target = `horizon-journal-${attempt}.json`;
        const plan = { version: 1, name: 'one-write-with-a-journal', tasks: [
          { id: 'w', tool: 'files.write', input: { path: target, content: { recorded: true } } },
        ] };
        const read = (file) => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
        const types = (file) => read(file).map((line) => line.type ?? Object.keys(line).join('+'));
        const blockedLog = path.join(workspaceRoot, `blocked-${attempt}.jsonl`);
        const grantedLog = path.join(workspaceRoot, `granted-${attempt}.jsonl`);
        const first = await runPlan({ plan, policy, registry, sourceLock, approvals: [], workspaceRoot, journalPath: blockedLog });
        const second = await runPlan({ plan, policy, registry, sourceLock, approvals: [first.outcome.requestHash], workspaceRoot, journalPath: grantedLog });
        const granted = read(grantedLog);
        const intent = granted.findIndex((line) => line.type === 'intent');
        const done = granted.findIndex((line) => line.type === 'completed');
        return {
          blockedTypes: types(blockedLog).join('>'),
          grantedTypes: types(grantedLog).join('>'),
          intentBeforeEffect: intent >= 0 && done > intent,
          // What an operator is asked to approve is on disk before they are asked.
          blockedRecordsTheInput: read(blockedLog).some((line) => line.type === 'blocked'
            && line.data?.input?.path === target && typeof line.data?.requestHash === 'string'),
          intentNamesTheInputOnly: Boolean(granted[intent]?.data) && typeof granted[intent].data.inputHash === 'string'
            && granted[intent].data.output === undefined,
          outcomes: `${first.outcome.status}>${second.outcome.status}`,
        };
      },
      expect: (r) => r.outcomes === 'blocked>completed'
        && r.blockedTypes === 'header>started>blocked>settled'
        && r.grantedTypes === 'header>started>intent>completed>settled'
        && r.intentBeforeEffect === true && r.blockedRecordsTheInput === true
        && r.intentNamesTheInputOnly === true,
      lesson: 'With a journal attached, a run leaves a record an interrupted process can be read from. A granted run writes header, started, intent, completed, settled — and the intent line, carrying the resolved input hash and the request hash but no output, is flushed before the effect is invoked. So a crash between those two lines leaves an intent with no outcome, which is exactly the state this kernel refuses to resume automatically: an effect without a committed receipt is indeterminate, and retrying it is a decision an operator makes with the log in front of them rather than something the harness does on their behalf. The blocked run is recorded too, with the full resolved input and the request hash, so what somebody is being asked to approve exists on disk before they are asked. Both logs are forensic rather than resumable, which is the honest shape for work that can stop in the middle.',
    },
    {
      family: 'horizon', tool: 'json.hash',
      plan: chainOf(32),
      expect: (r) => {
        const order = r.events.find((event) => event.type === 'started')?.data?.order ?? [];
        return order.length === 32 && order[0] === 't0' && order[31] === 't31'
          && Object.keys(r.results).length === 32
          // Each link consumed the one before it, so no two digests can coincide.
          && new Set(Object.values(r.results).map((value) => value.digest)).size === 32
          && r.results.t31.digest === digest({ previous: r.results.t30.digest })
          && r.results.t0.digest === digest({ seed: 'start' });
      },
      lesson: 'A plan exactly at the policy task bound runs as one long chain: thirty-two tasks where each consumes the digest of the one before it, so the final value depends transitively on all of them and no two links can collide. The order comes from the declared dependencies rather than from the order the tasks were written in, which is what lets a long plan be read as a graph before any of it executes. The bound is policy and it is enforced while compiling, so the length of a long-horizon plan is something an operator agreed to in advance rather than something discovered when a run stops partway.',
    },
    {
      family: 'horizon', tool: 'json.hash', expectThrow: 'SCHEMA_MISMATCH',
      plan: chainOf(33),
      lesson: 'A plan one task past the policy bound is refused SCHEMA_MISMATCH while compiling, and the refusal names the limit it exceeded. The bound lives in the plan schema rather than in the executor, so an oversized plan cannot run its first thirty-two tasks and then stop: nothing is executed, nothing is journaled, and no effect is left half-applied for somebody to reconcile later. For long-horizon work that is the important half — the failure arrives before any state changed.',
    },
  ];
}
