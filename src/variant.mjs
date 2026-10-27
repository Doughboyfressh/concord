import { canonical, digest, HarnessError } from './value.mjs';

/**
 * Task-level recursion over plans: run a reference, run variants, contrast what was recorded,
 * and select only where the recording separates them.
 *
 * This is Harness² (arXiv:2610.14224) propose/probe/compose, with the one part that cannot sit on
 * this kernel removed and the one part this kernel can do better made mechanical.
 *
 * What was removed. Harness² edits harness COMPONENT FILES mid-task — system prompt, guardrails,
 * scripts, plugins — and probes the edited harness. Every one of those is something `compile()`
 * hashes into a run's identity: guardrails are `policyHash`, a build target or adapter is a
 * descriptor's `config` inside `registryHash`, an instruction module is pinned by digest in
 * `sources.lock.json`. `replayPlan` asserts that identity is unchanged, so a harness that rewrites
 * its own configuration mid-run invalidates the grants it already holds and makes the run
 * unreplayable. So nothing here edits a harness. The variants are PLANS, which the kernel already
 * treats as data, already records, and already replays one by one.
 *
 * What was made mechanical. Harness² probes by behavioural contrast against a reference execution
 * and says so plainly: the contrast informs composition rather than verifying correctness. Its own
 * appendix reports the cost — nine regressions, one of them selecting a candidate scoring 55 over
 * one scoring 95, and premises that were wrong in the reference propagating into every candidate
 * for 2 to 11 points. Both failures have the same shape: a model composer free-forming a judgement
 * over evidence that did not actually separate the candidates.
 *
 * Here the comparison is a pure function of recorded journals, and selection can only cite a field
 * the contrast actually observed — `assertGrounded` below throws rather than let a decision rest on
 * a premise nothing measured. Three outcomes are first-class, and two of them decline: `keep` when
 * nothing beats the reference by more than the declared tolerance (Harness²'s fourth option, which
 * its paper never reports a rate for), and `undecided` when the evidence is confounded or tied. A
 * tie is never broken. Breaking one deterministically would be reproducible and still unjustified,
 * and an unjustified pick is the 55-over-95 failure exactly.
 *
 * The confound Harness² cannot rule out, this kernel rules out by construction. Its probe runs
 * candidates under "the same model and environment" and hopes; a run's header here PINS the policy,
 * registry, source lock and workspace by digest, so `comparable` below is a proof that nothing but
 * the plan differed, not an assurance that nothing else was meant to.
 *
 * The ledger arrives through a closure rather than through `config`, for the reason
 * `conversation.turn` takes the transcript that way: `registryManifest` hashes every descriptor's
 * config into the registry digest that binds every approval hash and every replay check, so a
 * config carrying the ledger would change on each run and invalidate the grants of the one before.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const runIdSchema = { type: 'string', minLength: 1, maxLength: 128 };

/** A reference and at most this many variants. Six contrasts fit the observation window. */
const MAX_CANDIDATES = 6;

/** Below the 8 KiB an observation keeps, so a contrast this tool returns is one the model sees. */
const DEFAULT_MAX_BYTES = 6144;

/** Plans are capped at 32 tasks, so a listing this long cannot be silently partial. */
const MAX_TOOLS_LISTED = 32;

const RUN_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/**
 * The fields a contrast compares, and the ONLY fields a selection may cite.
 *
 * One table, read by both halves. A criterion below names a path from this list, and
 * `assertGrounded` refuses a decision whose deciding path is absent from the observed
 * differences — so "every choice rests on a concrete observation" is enforced by construction
 * rather than asked for in a prompt.
 */
const FIELDS = [
  { path: 'status', get: (run) => run.status },
  { path: 'trajectory.tasks', get: (run) => run.trajectory.tasks },
  { path: 'trajectory.toolCalls', get: (run) => run.trajectory.toolCalls },
  { path: 'trajectory.completed', get: (run) => run.trajectory.completed },
  { path: 'trajectory.tools', get: (run) => run.trajectory.tools },
  { path: 'deliverable.digest', get: (run) => run.deliverable.digest },
  { path: 'deliverable.terminalHash', get: (run) => run.deliverable.terminalHash },
  { path: 'failure.code', get: (run) => (run.failure ? run.failure.code : null) },
  { path: 'grantsUsed', get: (run) => run.grantsUsed },
];

const fieldAt = (path) => {
  const field = FIELDS.find((entry) => entry.path === path);
  if (!field) throw new HarnessError('INPUT_INVALID', 'Unknown comparison field');
  return field;
};

/**
 * Identity components that must match for two runs to be contrastable.
 *
 * `planHash` is deliberately absent: it is the thing allowed — required, in fact — to differ.
 * `approvals` is absent too, and that is not an oversight. An approval hash binds the plan, so
 * two different plans NEVER share one and comparing the hashes would reject every real variant.
 * What is comparable is how much authority each run actually exercised, which travels as
 * `grantsUsed` above and is why `variant.select` refuses a winner that held more of it.
 */
const IDENTITY_KEYS = ['policyHash', 'registryHash', 'sourceHash', 'workspaceRoot'];

const LIMITATIONS = [
  'Adopting a plan says it did better on the declared criteria in the recorded runs; it does not say the plan is correct, and no ground truth was consulted',
  'keep is a real outcome, not a failure to decide: it means nothing beat the reference by more than the declared tolerance',
  'A tie is never broken. An arbitrary pick would be reproducible and still unjustified',
  'Criteria are compared lexicographically in the order declared, so a later criterion only speaks where every earlier one tied',
];

/**
 * Project one recorded run into the bounded shape a contrast compares.
 *
 * Exported because the ledger a session keeps should hold these and not second copies of whole
 * journals: a summary is a few hundred bytes, a journal is up to the policy's journal budget.
 * Counts come from the journal's own events rather than from the plan, because only an `intent`
 * proves a tool was actually invoked and only a `completed` proves an output was recorded. A plan
 * lists what was asked for, which is the number that made Harness²'s call-count metric ambiguous.
 */
export function runSummary(record) {
  if (!record || typeof record !== 'object') throw new HarnessError('INPUT_INVALID', 'A run record is required');
  const result = record.result;
  const header = result && typeof result === 'object' ? result.header : undefined;
  if (!header || typeof header !== 'object' || !Array.isArray(result.events)) {
    throw new HarnessError('INPUT_INVALID', 'A run record needs a journal with a header and events');
  }
  const events = result.events;
  const intents = events.filter((event) => event.type === 'intent');
  const completed = events.filter((event) => event.type === 'completed');
  const failed = events.find((event) => event.type === 'failed');
  const outputHashes = completed.map((event) => event.data.outputHash).sort();
  // Grants this run actually SPENT, not grants the session happened to be holding.
  //
  // `header.approvals` is the session's accumulated approval set, and it only ever grows, so
  // counting it made every later run look more authorised than every earlier one — which made the
  // UNEQUAL_AUTHORITY refusal fire on a contrast between two plans that used no authority at all.
  // Measured live before this was fixed: a two-task pure reference recorded 1 and a one-task pure
  // candidate recorded 2, purely because an unrelated model call had been approved in between.
  //
  // An intent's requestHash binds this plan, this task and this resolved input, so it appears in
  // approvals exactly when the operator granted THAT effect. Counting the intersection therefore
  // counts gated effects this run really executed, and does not move with session history.
  const granted = new Set(Array.isArray(header.approvals) ? header.approvals : []);
  const tools = [...new Set(intents.map((event) => event.data.tool))].sort().slice(0, MAX_TOOLS_LISTED);
  const status = result.outcome && typeof result.outcome.status === 'string' ? result.outcome.status : 'unknown';
  return {
    runId: String(record.id ?? digest(result).slice(0, 24)),
    planHash: String(record.planHash ?? header.planHash ?? ''),
    status,
    root: typeof result.root === 'string' ? result.root : null,
    identity: Object.fromEntries(IDENTITY_KEYS.map((key) => [key, header[key] ?? null])),
    grantsUsed: intents.filter((event) => granted.has(event.data.requestHash)).length,
    trajectory: {
      tasks: Array.isArray(record.plan?.tasks) ? record.plan.tasks.length : intents.length,
      toolCalls: intents.length,
      completed: completed.length,
      tools,
    },
    // Content-addressed and task-id independent, which is the only way two DIFFERENT plans can be
    // asked whether they produced the same thing: their task ids do not correspond, their output
    // hashes do. An identical value across a changed plan is the real finding Harness² reports in
    // prose as "fewer errors but more calls" — a variant that moved the trajectory and not the result.
    //
    // Two of them, because they answer different questions. `digest` covers every recorded output,
    // so it only matches when the runs did the same work; a plan that reaches the same answer in
    // one step instead of three has different intermediate outputs and so a different digest.
    // `terminalHash` is the last output actually recorded, which is what "did it produce the same
    // thing" means — and the only one of the two that can show a leaner plan reaching the same
    // result. It is the LAST COMPLETED task, not a declared deliverable: with independent branches
    // the kernel orders ready tasks alphabetically, so the final completion is the honest reading
    // of what the run ended up holding rather than a claim about which task mattered.
    deliverable: {
      digest: digest(outputHashes),
      terminalHash: completed.length ? completed[completed.length - 1].data.outputHash : null,
      outputCount: outputHashes.length,
    },
    failure: failed
      ? {
        taskId: typeof failed.data.taskId === 'string' ? failed.data.taskId : null,
        code: typeof failed.data.code === 'string' ? failed.data.code : null,
        ...(typeof failed.data.toolCode === 'string' ? { toolCode: failed.data.toolCode } : {}),
      }
      : null,
  };
}

/** A summary that reached a tool through a caller rather than through runSummary. */
function assertSummary(run, label) {
  const ok = run && typeof run === 'object'
    && typeof run.runId === 'string' && typeof run.planHash === 'string' && typeof run.status === 'string'
    && run.identity && typeof run.identity === 'object'
    && run.trajectory && typeof run.trajectory === 'object'
    && Number.isInteger(run.trajectory.tasks) && Number.isInteger(run.trajectory.toolCalls)
    && Number.isInteger(run.trajectory.completed) && Array.isArray(run.trajectory.tools)
    && run.deliverable && typeof run.deliverable === 'object' && typeof run.deliverable.digest === 'string'
    && Number.isInteger(run.grantsUsed)
    && (run.failure === null || (typeof run.failure === 'object' && run.failure !== null));
  if (!ok) throw new HarnessError('INPUT_INVALID', `A ${label} run summary is malformed`);
}

function differencesBetween(reference, candidate) {
  return FIELDS
    .filter((field) => canonical(field.get(reference)) !== canonical(field.get(candidate)))
    .map((field) => ({ field: field.path, reference: field.get(reference), candidate: field.get(candidate) }));
}

function incomparabilityOf(reference, candidate) {
  const reasons = [];
  for (const key of IDENTITY_KEYS) {
    if (canonical(reference.identity[key] ?? null) !== canonical(candidate.identity[key] ?? null)) {
      // Named, not merely counted. Which component moved is the whole diagnosis: a differing
      // registryHash means the tools changed under the experiment, and a differing policyHash
      // means the authority did. Either way the contrast is measuring the harness, not the plan.
      reasons.push(key);
    }
  }
  return reasons;
}

/**
 * The criteria a selection may be ordered by.
 *
 * Each names a path from FIELDS, so a decision it reaches is always backed by an observed
 * difference. `compare` returns 1 when the candidate is better, -1 when worse, 0 when the
 * difference is within the declared tolerance — which is what keeps ordinary run-to-run
 * variation from reading as a win.
 */
const CRITERIA = {
  // A completed run beats one that did not complete. Nothing finer: ranking `failed` against
  // `blocked` would invent an ordering between "it broke" and "it is waiting for a grant".
  completed: {
    field: 'status',
    compare: (reference, candidate) => {
      const rank = (run) => (run.status === 'completed' ? 1 : 0);
      return rank(candidate) - rank(reference);
    },
  },
  fewerToolCalls: {
    field: 'trajectory.toolCalls',
    compare: (reference, candidate, tolerance) => {
      const delta = reference.trajectory.toolCalls - candidate.trajectory.toolCalls;
      return Math.abs(delta) <= (tolerance.toolCalls ?? 0) ? 0 : Math.sign(delta);
    },
  },
  fewerTasks: {
    field: 'trajectory.tasks',
    compare: (reference, candidate, tolerance) => {
      const delta = reference.trajectory.tasks - candidate.trajectory.tasks;
      return Math.abs(delta) <= (tolerance.tasks ?? 0) ? 0 : Math.sign(delta);
    },
  },
};

/**
 * The structural guarantee, as an assertion rather than an instruction.
 *
 * A criterion decided, so a difference in that exact field must have been observed. If it was
 * not, the selection is resting on a premise nothing measured, which is the failure mode
 * Harness²'s own appendix reports costing it 2 to 11 points. Throwing is the only honest
 * response: the alternative is a confident decision with no evidence behind it.
 */
function assertGrounded(differences, path, candidateId) {
  const observed = differences.find((difference) => difference.field === path);
  if (!observed) {
    throw new HarnessError('SELECTION_UNGROUNDED',
      `A selection over ${path} decided for ${candidateId}, but no difference in that field was observed`);
  }
  return observed;
}

/** Lexicographic over the declared order: the first criterion that is not a tie decides. */
function rankAgainst(reference, candidate, prefer, tolerance) {
  for (const name of prefer) {
    const verdict = CRITERIA[name].compare(reference, candidate, tolerance);
    if (verdict !== 0) return { verdict, by: name, field: CRITERIA[name].field };
  }
  return { verdict: 0, by: null, field: null };
}

const select = Object.freeze({
  name: 'variant.select', version: '1.0.0', effect: 'pure',
  outputKeys: ['decision', 'adopted', 'because', 'declined', 'considered', 'rule', 'contrastHash', 'limitations'],
  inputSchema: object({
    contrast: { type: 'object', additionalProperties: true },
    prefer: { type: 'array', minItems: 1, maxItems: 3, items: { enum: Object.keys(CRITERIA) } },
    tolerance: object({
      toolCalls: { type: 'integer', minimum: 0, maximum: 1000 },
      tasks: { type: 'integer', minimum: 0, maximum: 1000 },
    }, []),
  }, ['contrast', 'prefer']),
  execute(input) {
    // Self-validating rather than trusting the declared schema alone, for the reason text.concat
    // and json.mergeShallow are: a pure tool's execute() is called directly elsewhere in this
    // codebase, and `contrast` arrives here as an opaque object by task reference.
    const contrast = input.contrast;
    const prefer = [...input.prefer];
    if (new Set(prefer).size !== prefer.length) throw new HarnessError('INPUT_INVALID', 'Preference criteria must be distinct');
    const tolerance = input.tolerance ?? {};
    for (const name of prefer) fieldAt(CRITERIA[name].field);
    const rule = { prefer, tolerance: { toolCalls: tolerance.toolCalls ?? 0, tasks: tolerance.tasks ?? 0 } };
    const contrastHash = typeof contrast.contrastHash === 'string' ? contrast.contrastHash : null;

    const decline = (code, detail, considered = []) => ({
      decision: 'undecided', adopted: null, because: [],
      declined: [{ code, detail }], considered, rule, contrastHash,
      limitations: LIMITATIONS,
    });

    if (!contrast.reference) return decline('NO_REFERENCE', 'The contrast has no reference run, so there is nothing to improve on.');
    if (!Array.isArray(contrast.candidates) || contrast.candidates.length === 0) {
      return decline('NO_CANDIDATES', 'The contrast lists no candidates, so there is nothing to choose between.');
    }
    // identity is absent from a contrast's published reference and candidates by design: the
    // contrast has already compared it and published the verdict as `comparable`. Supplying an
    // empty one keeps the shared shape check usable without re-asserting what was already checked.
    assertSummary({ ...contrast.reference, identity: {} }, 'reference');

    const candidates = contrast.candidates;
    for (const candidate of candidates) {
      assertSummary({ ...candidate, identity: {} }, 'candidate');
      if (!Array.isArray(candidate.differences)) throw new HarnessError('INPUT_INVALID', 'Each candidate needs its observed differences');
    }
    const considered = candidates.map((candidate) => candidate.runId);

    // Refusals before comparisons, each because the evidence is confounded rather than close.
    if (contrast.sharedFailure) {
      return decline('COMMON_MODE_FAILURE',
        `Every run failed with ${contrast.sharedFailure.code}; a fault they all share says nothing about the variants.`, considered);
    }
    const uncomparable = candidates.filter((candidate) => candidate.comparable === false).map((candidate) => candidate.runId);
    if (uncomparable.length) {
      // Not "ignore them and decide on the rest": a candidate that cannot be compared might be the
      // best one, so declaring a winner without it is the 55-over-95 failure with extra steps.
      return decline('INCOMPARABLE',
        `These candidates ran under a different harness identity, so no winner can be named while they are in the set: ${uncomparable.join(', ')}.`, considered);
    }
    const notVariants = candidates.filter((candidate) => candidate.variant === false).map((candidate) => candidate.runId);
    if (notVariants.length) {
      return decline('NOT_A_VARIANT',
        `These candidates ran the reference's own plan, so the set measures variability rather than variants: ${notVariants.join(', ')}.`, considered);
    }
    const unfinished = [contrast.reference, ...candidates].filter((run) => run.status === 'blocked').map((run) => run.runId);
    if (unfinished.length) {
      return decline('INCOMPLETE_RUN',
        `These runs stopped at an approval gate, so their trajectories are truncated and not comparable as finished work: ${unfinished.join(', ')}.`, considered);
    }

    const better = [];
    for (const candidate of candidates) {
      const ranked = rankAgainst(contrast.reference, candidate, prefer, rule.tolerance);
      if (ranked.verdict > 0) better.push({ candidate, ranked });
    }

    if (better.length === 0) {
      // Harness²'s fourth composition option, and the one its paper never reports a rate for.
      // Nothing beat the reference by more than the declared tolerance, so the reference stands.
      return {
        decision: 'keep', adopted: contrast.reference.runId, because: [],
        declined: [{ code: 'NO_IMPROVEMENT', detail: 'No candidate beat the reference on the declared criteria by more than the declared tolerance.' }],
        considered, rule, contrastHash, limitations: LIMITATIONS,
      };
    }

    // A winner that held more authority than the reference may have won on the grant rather than
    // on the plan. The contrast already warns; refusing to ADOPT is the part that matters.
    const overAuthorised = better.filter(({ candidate }) => (candidate.authorityDelta ?? 0) > 0).map(({ candidate }) => candidate.runId);
    if (overAuthorised.length) {
      return decline('UNEQUAL_AUTHORITY',
        `These candidates won while holding more approval grants than the reference, so the win may be authority rather than plan: ${overAuthorised.join(', ')}.`, considered);
    }

    // A winner must beat every other improver, not merely the reference. Any pair this ordering
    // cannot separate ends the selection: see the TIE reasoning in the module header.
    let winner = better[0];
    for (const contender of better.slice(1)) {
      const against = rankAgainst(winner.candidate, contender.candidate, prefer, rule.tolerance);
      if (against.verdict > 0) winner = contender;
      else if (against.verdict === 0) {
        return decline('TIE',
          `${winner.candidate.runId} and ${contender.candidate.runId} are indistinguishable under the declared criteria; add a criterion that separates them or accept neither.`, considered);
      }
    }
    for (const contender of better) {
      if (contender === winner) continue;
      const against = rankAgainst(winner.candidate, contender.candidate, prefer, rule.tolerance);
      if (against.verdict === 0) {
        return decline('TIE',
          `${winner.candidate.runId} and ${contender.candidate.runId} are indistinguishable under the declared criteria; add a criterion that separates them or accept neither.`, considered);
      }
    }

    const deciding = rankAgainst(contrast.reference, winner.candidate, prefer, rule.tolerance);
    const observed = assertGrounded(winner.candidate.differences, deciding.field, winner.candidate.runId);
    return {
      decision: 'adopt', adopted: winner.candidate.runId,
      // Verbatim from the contrast's own differences. A reason this tool cannot produce is a
      // reason it cannot give, which is the enforceable half of "rest each choice on an observation".
      because: [{ criterion: deciding.by, ...observed }],
      declined: [], considered, rule, contrastHash, limitations: LIMITATIONS,
    };
  },
});

export function makeVariantTools({ readRuns, maxBytes = DEFAULT_MAX_BYTES } = {}) {
  if (typeof readRuns !== 'function') {
    throw new HarnessError('VARIANT_CONFIG', 'The variant store needs a readRuns function');
  }
  if (!Number.isInteger(maxBytes) || maxBytes < 1024) {
    throw new HarnessError('VARIANT_CONFIG', 'maxBytes must be an integer of at least 1024');
  }

  const contrast = Object.freeze({
    name: 'variant.contrast', version: '1.0.0', effect: 'read',
    outputKeys: ['reference', 'candidates', 'missing', 'sharedFailure', 'warnings', 'contrastHash', 'totalRuns', 'limitations'],
    inputSchema: object({
      reference: runIdSchema,
      candidates: { type: 'array', minItems: 1, maxItems: MAX_CANDIDATES, items: runIdSchema },
    }),
    // Stable across every run, so the registry digest is too. The byte bound belongs here because
    // it is an operator's choice about this build, not something a plan may vary per call.
    config: { source: 'session-run-ledger-v1', maxBytes },
    execute(input) {
      const ledger = readRuns();
      if (!Array.isArray(ledger)) throw new HarnessError('VARIANT_LEDGER', 'The run ledger is unavailable');
      for (const id of [input.reference, ...input.candidates]) {
        if (!RUN_ID_PATTERN.test(id)) throw new HarnessError('INPUT_INVALID', 'A run id must be a bare identifier');
      }
      const byId = new Map();
      for (const entry of ledger) {
        assertSummary(entry, 'ledger');
        if (!byId.has(entry.runId)) byId.set(entry.runId, entry);
      }

      const warnings = [];
      const missing = [];
      const reference = byId.get(input.reference) ?? null;
      if (!reference) {
        missing.push(input.reference);
        warnings.push({ code: 'UNKNOWN_REFERENCE', detail: 'The reference run is not in this ledger, so there is nothing to contrast against.' });
      }

      // De-duplicated: the same run named twice is one candidate, not two data points. Ordered by
      // the caller, because a caller's order is the only order a variant list has.
      const unique = [...new Set(input.candidates)];
      const requested = unique.filter((id) => id !== input.reference);
      if (requested.length !== unique.length) {
        warnings.push({ code: 'REFERENCE_AS_CANDIDATE', detail: 'The reference was also listed as a candidate; a run cannot be a variant of itself.' });
      }

      const candidates = [];
      for (const id of requested) {
        const run = byId.get(id);
        if (!run) { missing.push(id); continue; }
        if (!reference) continue;
        const incomparable = incomparabilityOf(reference, run);
        candidates.push({
          runId: run.runId,
          planHash: run.planHash,
          status: run.status,
          comparable: incomparable.length === 0,
          ...(incomparable.length ? { incomparable } : {}),
          // A variant whose plan hashes the same as the reference is the same plan run twice. That
          // is a measurement of run-to-run variation, which is worth having and is not a variant,
          // so it is labelled rather than quietly counted as one.
          variant: run.planHash !== reference.planHash,
          trajectory: run.trajectory,
          deliverable: {
            ...run.deliverable,
            matchesReference: run.deliverable.digest === reference.deliverable.digest,
            // The finding worth surfacing on its own: same answer, different route.
            matchesTerminal: run.deliverable.terminalHash !== null
              && run.deliverable.terminalHash === reference.deliverable.terminalHash,
          },
          failure: run.failure,
          grantsUsed: run.grantsUsed,
          authorityDelta: run.grantsUsed - reference.grantsUsed,
          differences: differencesBetween(reference, run),
        });
      }

      if (missing.length) {
        warnings.push({ code: 'UNKNOWN_RUN', detail: `These run ids are not in this ledger: ${missing.join(', ')}.` });
      }
      if (reference && candidates.length === 1) {
        warnings.push({ code: 'SINGLE_CANDIDATE', detail: 'One candidate cannot separate a variant effect from ordinary run-to-run variation; run the same variant twice, or contrast two.' });
      }
      for (const candidate of candidates) {
        if (!candidate.variant) {
          warnings.push({ code: 'NOT_A_VARIANT', detail: `${candidate.runId} ran the reference's own plan, so any difference from it measures variability rather than a variant.` });
        } else if (candidate.differences.length === 0) {
          warnings.push({ code: 'NO_BEHAVIOURAL_DIFFERENCE', detail: `${candidate.runId} changed the plan and changed nothing observable, so there is no evidence to prefer it.` });
        }
        if (candidate.incomparable) {
          warnings.push({ code: 'INCOMPARABLE_RUN', detail: `${candidate.runId} ran under a different ${candidate.incomparable.join(' and ')}, so a difference from the reference may come from the harness rather than the plan.` });
        }
        if (candidate.authorityDelta > 0) {
          warnings.push({ code: 'UNEQUAL_AUTHORITY', detail: `${candidate.runId} held ${candidate.authorityDelta} more approval grant(s) than the reference, so a difference may come from authority rather than the plan.` });
        }
        if (candidate.status === 'blocked') {
          warnings.push({ code: 'INCOMPLETE_RUN', detail: `${candidate.runId} stopped at an approval gate, so its trajectory is truncated rather than finished.` });
        }
      }

      // A fault the reference shares with every candidate says nothing about the variants. This is
      // Harness²'s measured "incorrect premises propagating across candidates" stated mechanically:
      // when the premise is wrong in the reference, every edit inherits it, and the contrast between
      // them is uninformative however large it looks.
      let sharedFailure = null;
      if (reference && candidates.length && reference.failure && reference.failure.code) {
        const code = reference.failure.code;
        if (candidates.every((candidate) => candidate.failure && candidate.failure.code === code)) {
          sharedFailure = { code, runs: [reference.runId, ...candidates.map((candidate) => candidate.runId)] };
          warnings.push({ code: 'SHARED_FAILURE', detail: `Every run failed with ${code}, so the contrast between them carries no information about the variants; fix the common cause first.` });
        }
      }

      const body = {
        reference: reference
          ? {
            runId: reference.runId, planHash: reference.planHash, status: reference.status,
            trajectory: reference.trajectory, deliverable: reference.deliverable,
            failure: reference.failure, grantsUsed: reference.grantsUsed,
          }
          : null,
        candidates, missing, sharedFailure, warnings,
      };
      const result = {
        ...body,
        // Pins a decision to the evidence it was computed from, the way judgment.gate pins a
        // verdict to its evidence. variant.select echoes this, so a recorded adoption names the
        // exact contrast that justified it rather than merely asserting one existed.
        contrastHash: digest(body),
        totalRuns: ledger.length,
        limitations: [
          'This contrasts what was recorded; it does not judge correctness. No ground truth is consulted, and a candidate that differs is different rather than better',
          'A difference between two runs of the SAME plan is run-to-run variation, not evidence about a variant; such a candidate is reported with variant:false',
          'comparable means the policy, registry, source lock and workspace digests matched, so only the plan differed; it does not mean the runs are equally good',
          'An identical deliverable digest means every recorded output hashed the same, not that the task was accomplished',
          'matchesTerminal compares the LAST output each run recorded, which is what a leaner plan reaching the same answer looks like; it is the final completion, not a declared deliverable',
        ],
      };
      // Fails closed rather than truncating, for the reason the system prompt's contract list
      // does: half a contrast is a misreading waiting to happen, and the caller can ask for fewer
      // candidates. The bound is below the observation window, so what this returns is seen.
      if (Buffer.byteLength(canonical(result)) > maxBytes) {
        throw new HarnessError('CONTRAST_TOO_LARGE', 'The contrast exceeds its byte bound; contrast fewer candidates');
      }
      return result;
    },
  });

  return [contrast, select];
}
