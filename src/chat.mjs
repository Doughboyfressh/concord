import { canonical, digest, clone, validateSchema, HarnessError } from './value.mjs';
import { runPlan, replayPlan, inspectPlan, attenuatePolicy } from './engine.mjs';
import { planGrants, assertSinglePass } from './preflight.mjs';
import { boundedRecords, boundedValue } from './chat-data.mjs';

const MODEL_TOOL = 'model.propose';
// The tool that can falsify a claim about code by running it. Named here rather than discovered,
// because a check this harness cannot identify is one it cannot report as unrun.
const VERIFY_TOOL = 'build.run';
const MAX_SKILL_EXCERPT_CHARS = 1500;
const MAX_SETTLED_ATTEMPTS = 8;
// How much learned knowledge one turn may carry. Bounded by bytes rather than by count so the
// cost stays fixed as the memory store grows, in the same spirit as every other context bound.
const MAX_RECALLED_LESSONS = 6;
const MAX_MEMORY_EXCERPT_BYTES = 6000;
// A reply anchors a bounded number of claims; more than this is narration, not citation.
const MAX_CITATIONS = 12;
const MAX_CITATION_QUOTE_CHARS = 512;
// Self-distilled lesson candidates kept from measured failures. Bounded like every other
// context record, newest retained, because a session should not grow an unbounded teaching log.
const MAX_LESSON_CANDIDATES = 16;
/**
 * How far one operator instruction may carry an unattended run. Small on purpose: the grant it
 * authorises is a budget rather than an exact request hash, so it should run out while someone is
 * still paying attention rather than drift on.
 */
const MAX_ADVANCE_STEPS = 8;
/**
 * What an unattended step asks. Deliberately a continuation rather than a goal: the objective is
 * already in the conversation, and restating it here would let this string quietly become the
 * instruction instead of the operator's own words.
 */
const ADVANCE_REQUEST = 'Continue the work already under way in this conversation. '
  + 'Take the next step that the recorded receipts show is actually needed, propose a plan for it, '
  + 'and say plainly if the work is finished or if you need a decision rather than another step.';

const PRINCIPLES = {
  INVALID_REFERENCE: 'A reference must be an unquoted {"$task":...} object placed where the value belongs, with a direct declared dependsOn, and any path built only from the declared outputKeys of that tool.',
  SCHEMA_MISMATCH: 'Check each input against the declared schema of the tool, including bounds like minItems and required fields, before proposing; a refusal that names the constraint beats a rejected plan.',
  PLAN_UNEXECUTABLE: 'A plan may contain as many approval-requiring effects as it needs, provided each of their inputs is literal: those are all granted before the first one runs, so nothing is ever re-attempted. What is refused is several gated effects where one takes its input from another task\'s output, since that one cannot be granted until the earlier effects have already run. Give the gated tasks literal inputs, or split off the dependent effect as its own plan.',
  OUTPUT_REJECTED: 'The tool completed, so for a write, network or process tool the effect DID occur and only its output was unusable; never describe it as not having happened and never retry it.',
  EFFECT_INDETERMINATE: 'The tool threw, so the effect may or may not have occurred; do not claim it failed safely and do not retry it automatically.',
  INPUT_INVALID: 'Input validation precedes execution, so no effect occurred; correct the named field and propose again.',
  CITATION_UNVERIFIED: 'Anchor a claim only to an outputHash copied from an observed receipt, and quote only text that appears in that recorded output.',
  POLICY_DENIED: 'The policy does not permit that tool or effect; propose within the allowed set rather than naming an unavailable capability.',
  OUTPUT_LIMIT: 'This is a bound rather than a defect; request less output or split the work across fewer tasks.',
  INPUT_LIMIT: 'This is a bound rather than a defect; reduce the resolved input instead of retrying it unchanged.',
  PATH_DENIED: 'Workspace paths must be relative and inside the workspace, and symlinks and hard links are refused.',
  MEMORY_INVALID: 'A stored candidate must match its own content digest, so promote the candidate exactly as produced.',
  TIMEOUT: 'The tool exceeded the policy deadline; the work needs to be smaller rather than reattempted identically.',
  MERGE_COLLISION: 'Shallow merge fails closed on a duplicate key rather than silently preferring one; disambiguate the inputs.',
  TOOL_FAILED: 'A pure or read tool raised a condition it anticipated and changed nothing, so it is safe to correct the input and try again; read its code for the cause.',
  UNKNOWN_TOOL: 'That tool is not registered. Only the names in the supplied contracts exist; source documentation is not an installed capability.',
  INVALID_PLAN: 'Task ids must be distinct, non-reserved identifiers, and every dependsOn must name a task in the same plan.',
  INVALID_JSON: 'Every value must be plain JSON: no undefined, NaN, Infinity, dates, cycles, sparse arrays or prototype keys.',
  INVALID_SCHEMA: 'A declared outputSchema may use only the supported keyword subset; an unsupported keyword is refused rather than ignored.',
  INVALID_WORKSPACE: 'The workspace root is supplied by the operator, not the plan; reference files by workspace-relative path only.',
  JUDGMENT_REJECTED: 'The evidence scored below the declared threshold, so the gate refused it; raise the evidence rather than lowering the threshold.',
  BUDGET_EXHAUSTED: 'The journal had no room left to record the next receipt, so execution stopped before the effect rather than after it; propose fewer or smaller tasks.',
  JOURNAL_LIMIT: 'The recorded journal cannot hold this output, so the effect was not attempted; reduce the expected output size.',
  CHAT_PLAN: 'No plan is currently proposed, so there is nothing to execute; propose one in the same response.',
  TIMEOUT_WORKER: 'A worker exceeded its deadline; the work needs to be smaller rather than reattempted unchanged.',
  WORKER_TIMEOUT: 'A worker exceeded its deadline; the work needs to be smaller rather than reattempted unchanged.',
  WORKER_EXIT: 'A worker exited before completing its protocol, so its effect is indeterminate; do not assume it finished.',
  WORKER_OUTPUT_LIMIT: 'A worker produced more output than the policy permits; narrow the request rather than retrying it.',
  BROWSER_TIMEOUT: 'The page did not reach the expected state within the deadline; a hostile or slow page cannot be waited out by retrying.',
  BROWSER_ABORTED: 'The browser session was torn down before the action list completed, so later actions did not run.',
  INTEGRATION_EXIT: 'The configured process exited non-zero, so its effect is indeterminate; read its own code rather than assuming failure.',
  INTEGRATION_OUTPUT: 'The configured process produced output the adapter could not parse, so nothing was recorded from it.',
  INTEGRATION_TRUNCATED: 'The model used its whole token budget reasoning and never began an answer, so nothing was proposed; the step being asked for is too large to think through in one call, so ask for a smaller one rather than repeating it.',
};

// Codes a model's proposal cannot cause — operator configuration, CLI usage, registry validity,
// replay verification — are deliberately absent rather than padded in. A principle is advice to
// whoever can act on it, and for these that is the operator, not the model.

// The harness's own infrastructure plans. Excluded from success lessons because they run every
// turn and teach nothing about the work the operator asked for.
const INFRASTRUCTURE_PLANS = new Set(['live-proposal', 'memory-enrichment', 'skill-enrichment']);

function livePlan(message, context, skillExcerpt, memoryExcerpt) {
  const input = { prompt: canonical({
    currentRequest: message,
    conversation: context.conversation ?? boundedRecords([]),
    observations: context.observations ?? boundedRecords([]),
    proposal: context.proposal ?? null,
    // Supervisor-computed, like observations and unlike references: what checks this session has
    // and whether they have been run is a fact about the record, not untrusted material.
    verification: context.verification ?? null,
    references: { trust: 'untrusted-data', capabilities: context.selected ?? [], skill: skillExcerpt, memory: memoryExcerpt },
  }) };
  const system = context.systemPrompt ?? '';
  if (system) input.system = system;
  return { version: 1, name: 'live-proposal', tasks: [{ id: 'propose', tool: MODEL_TOOL, input }] };
}

/** The top kind:'skill' entry in `selected`, if any, with the path/sourceId skills.snapshot needs. */
function topSkillMatch(selected) {
  return (selected ?? []).find((s) => s && s.kind === 'skill' && typeof s.path === 'string' && typeof s.sourceId === 'string');
}

function blockedDetail(result) {
  const event = result.events.find(e => e.type === 'blocked');
  return event ? { effect: event.data.effect, tool: event.data.tool, input: event.data.input } : {};
}

/**
 * The chat session broker. Each turn assembles context, proposes exactly one plan,
 * and runs it through the deterministic kernel. A plan with an ungranted write,
 * network, or process effect blocks; the caller must approve its exact request hash
 * before that effect, or anything depending on it, executes. A model's returned
 * proposal is structurally validated before it can become the next proposed plan —
 * it is data, never an instruction the supervisor obeys automatically.
 */
export function createChatHarness({ registry, policy, sourceLock, workspaceRoot, buildContext, persistRun, onProgress }) {
  if (!(registry instanceof Map)) throw new HarnessError('CHAT_CONFIG', 'A tool registry Map is required');
  if (typeof buildContext !== 'function') throw new HarnessError('CHAT_CONFIG', 'A context builder is required');

  const history = [];
  const approvals = new Set();
  const runs = [];
  const observations = [];
  const lessonCandidates = [];
  let lastError = null;
  let proposedPlan = null;
  let lastAttemptedPlan = null;
  let pending = null;
  // The AbortController of the attempt currently executing, or null. A turn can run for the whole
  // policy deadline, so there has to be a way to stop one without killing the process.
  let inflight = null;
  let mode = null;
  let sourceCoverage = [];
  let selected = [];

  const isLive = () => registry.has(MODEL_TOOL);

  // Verified citations. The harness already makes effects verifiable — an approval hash binds the
  // resolved input, replay re-checks a recorded run, provenance records what executed. Narration
  // was the one thing still taken on trust: round 012 measured this model reporting receipts
  // faithfully six times out of six, but nothing PREVENTED a misreport, which is why round 002
  // called the gap irreducible. A citation closes the enforceable part of it. The model may anchor
  // a factual claim to the exact output hash of a recorded task; the supervisor verifies every
  // anchor against the durable run ledger before committing the reply, and rejects the whole
  // response if any anchor does not exist. This cannot verify that prose MEANS the right thing —
  // that part really is irreducible — but a fabricated digest or a citation of a task that never
  // ran is now caught mechanically rather than merely being auditable afterwards.
  function verifyCitations(citations) {
    return citations.map((citation) => {
      const { taskId, outputHash, runId } = citation;
      const candidates = runs.filter((record) => (runId === undefined || record.id === runId));
      // An outputHash is a SHA-256 over the recorded output, so a citation cannot be fabricated
      // without finding a preimage; matching one proves the cited result really was produced.
      const match = candidates.find((record) => record.result.events.some((event) =>
        event.type === 'completed' && event.data.taskId === taskId && event.data.outputHash === outputHash));
      if (!match) {
        throw new HarnessError('CITATION_UNVERIFIED',
          `No recorded completed task "${taskId}" has output hash ${outputHash.slice(0, 16)}…; cite a hash from an observed receipt or omit the citation`);
      }
      const task = match.plan.tasks.find((t) => t.id === taskId);
      // A quote is checked against the recorded output itself, not against the reply. Anchoring
      // proves the receipt exists; quoting proves the asserted fragment is really in it, which is
      // a strictly stronger claim and the furthest a harness can go without judging meaning.
      if (citation.quote !== undefined) {
        const event = match.result.events.find((e) =>
          e.type === 'completed' && e.data.taskId === taskId && e.data.outputHash === outputHash);
        const recorded = canonical(event.data.output);
        if (!recorded.includes(citation.quote)) {
          throw new HarnessError('CITATION_UNVERIFIED',
            `The quoted text does not appear in the recorded output of task "${taskId}"; quote it verbatim from the receipt or omit the quote`);
        }
      }
      return { taskId, outputHash, runId: match.id, tool: task ? task.tool : null,
        ...(citation.quote === undefined ? {} : { quote: citation.quote }) };
    });
  }

  function classifyEvidence(evidenceHashes) {
    const grounded = [];
    for (const hash of evidenceHashes) {
      for (const record of runs) {
        const event = record.result.events.find((e) => e.type === 'completed' && e.data.outputHash === hash);
        if (event) { grounded.push({ evidenceHash: hash, runId: record.id, taskId: event.data.taskId }); break; }
        // A run root is a content-addressed commitment to the whole recorded run, so evidence that
        // digests to a known root proves that run happened — which is the only grounding available
        // for a lesson about a FAILURE, where the failing task has no completed output to cite.
        if (digest(record.result.root) === hash) { grounded.push({ evidenceHash: hash, runId: record.id, taskId: null }); break; }
      }
    }
    const groundedHashes = new Set(grounded.map((g) => g.evidenceHash));
    return {
      groundedCount: grounded.length,
      // Not "false": an item can be real evidence from an earlier session whose runs are not in
      // this ledger. Unverifiable here is the honest label, and the distinction matters because
      // calling it fabricated would be a claim the harness cannot support.
      unverifiedHereCount: evidenceHashes.filter((h) => !groundedHashes.has(h)).length,
      grounded,
    };
  }

  // Surfaced at the approval gate, where it is decision-relevant: an operator about to persist a
  // lesson is told whether its evidence is recorded execution or merely asserted text.
  function promotionEvidence(detail) {
    if (detail.tool !== 'memory.promote') return {};
    const hashes = detail.input && Array.isArray(detail.input.evidenceHashes) ? detail.input.evidenceHashes : null;
    return hashes ? { evidenceProvenance: classifyEvidence(hashes) } : {};
  }

  // Self-distillation. Rounds 002-014 each turned one measured failure into a durable improvement,
  // by hand. The diagnostic that made that possible is already machine-readable — round 003 added
  // the rejection reason, round 006 the failing schema path, round 010 the post-return distinction
  // — so the harness can derive the same lesson itself, from its own experience, for failures
  // nobody anticipated. The text is composed by the supervisor from recorded facts, never by the
  // model, and a candidate is NEVER promoted automatically: learned text becoming authority
  // without review is precisely the hazard this project refuses. It is a suggestion carrying its
  // own verifiable provenance, for an operator to accept or ignore.
  function pushCandidate(candidate) {
    lessonCandidates.push(candidate);
    if (lessonCandidates.length > MAX_LESSON_CANDIDATES) lessonCandidates.shift();
  }

  // Grounded by the run's own root, a content-addressed commitment to the whole recorded run. This
  // is the only grounding available for a lesson about a failure, where the failing task produced
  // no completed output to cite.
  function groundIn(root) {
    return { suggestedEvidence: [root], evidenceGrounded: classifyEvidence([digest(root)]).groundedCount === 1 };
  }

  function recordLessonCandidate({ code, reasonCode, reason, toolCode, taskId, tool, runId, root }) {
    const subject = tool ? `${tool} (task "${taskId}")` : (taskId ? `task "${taskId}"` : 'this turn');
    // The tool's own code is often the real cause where the outer code is only a category: a
    // thrown pure tool reports TOOL_FAILED, which says nothing, while its own code says what
    // condition it hit. Round 015 recorded "no diagnostic was recorded" for exactly this gap.
    const cause = reasonCode && reasonCode !== code ? reasonCode : toolCode;
    const principle = PRINCIPLES[cause] ?? PRINCIPLES[code] ?? null;
    // Recurrence is insight only the harness can supply: a human-written lesson cannot know that
    // this is the third time the same cause has appeared in this session.
    const key = `${code}:${cause ?? ''}`;
    const occurrence = lessonCandidates.filter((c) => c.key === key).length + 1;
    const parts = [`Observed ${code}${cause && cause !== code ? ' / ' + cause : ''} on ${subject}.`];
    if (reason) parts.push(`Diagnostic: ${reason}`);
    else if (toolCode) parts.push(`The tool raised ${toolCode}.`);
    else parts.push('No diagnostic was recorded, which indicates an unhandled exception rather than an anticipated condition.');
    if (principle) parts.push(`Principle: ${principle}`);
    if (occurrence > 1) parts.push(`This is occurrence ${occurrence} of this cause in this session, so the correction has not held; treat it as a pattern rather than an incident.`);
    pushCandidate({ lesson: parts.join(' '), kind: 'failure', key, code,
      ...(cause && cause !== code ? { cause } : {}), occurrence, runId, ...groundIn(root) });
  }

  // Successes teach composition. Round 008 established by hand that a working topology — which
  // tools in which order, joined by which reference shapes — is exactly the transferable fact, and
  // nothing recorded it. Infrastructure plans are excluded: they run every turn and teach nothing
  // about the work that was asked for.
  function recordSuccessCandidate(record) {
    const plan = record.plan;
    if (INFRASTRUCTURE_PLANS.has(plan.name) || (plan.tasks ?? []).length < 2) return;
    const sequence = plan.tasks.map((t) => t.tool);
    const referenced = plan.tasks.filter((t) => canonical(t.input).includes('"$task"'));
    const paths = [...new Set(referenced.flatMap((t) => (canonical(t.input).match(/"path":"[^"]*"/g) ?? [])
      .map((m) => m.slice(8, -1))))];
    const key = `success:${sequence.join('>')}`;
    const occurrence = lessonCandidates.filter((c) => c.key === key).length + 1;
    const parts = [`A ${plan.tasks.length}-task composition completed: ${sequence.join(' then ')}.`];
    if (referenced.length) {
      parts.push(`${referenced.length} task${referenced.length === 1 ? '' : 's'} consumed an earlier result by reference` +
        (paths.length ? ` using ${paths.map((x) => '"' + x + '"').join(', ')}` : '') + '.');
      parts.push('Principle: this topology and these reference paths are known to work, so reuse them for a request of the same shape rather than deriving them again.');
    } else {
      parts.push('No task consumed the result of another, so the tasks were independent rather than composed.');
    }
    if (occurrence > 1) parts.push(`This composition has now succeeded ${occurrence} times, which is corroboration rather than a new finding.`);
    pushCandidate({ lesson: parts.join(' '), kind: 'success', key, tools: sequence, occurrence,
      runId: record.id, ...groundIn(record.result.root) });
  }

  // Every grant this plan needs, computed once and reused. Memoised on the plan AND the turn's
  // policy, because a request hash binds both: an attenuated turn produces different hashes for
  // the same plan, and serving a cached one would offer an approval that could never match.
  let grantCache = null;
  function grantsFor(plan) {
    const key = digest({ plan, policy: turnPolicy });
    if (grantCache && grantCache.key === key) return grantCache.preflight;
    const preflight = planGrants({ plan, policy: turnPolicy, registry, sourceLock, workspaceRoot });
    grantCache = { key, preflight };
    return preflight;
  }

  /**
   * A plan is executable here when every effect it needs can be granted before the first one runs.
   *
   * This used to refuse any plan with more than one gated task, and that refusal was correct for
   * the mechanism it was defending: approving a blocked gate re-attempts the plan from its first
   * task, so a second write would repeat the first. Round 009 measured exactly that. But the
   * premise -- that a gate can only be discovered by running into it -- is false for a task whose
   * input holds no reference, because its request hash is computable from the plan alone. Granting
   * all of them up front means the run never blocks, so nothing is ever re-attempted.
   *
   * What remains refused is the case the mechanism actually cannot handle: several gated tasks
   * where one of them resolves its input from an earlier result. Its hash cannot exist yet, so it
   * would block, and that approval would re-run the effects already granted.
   */
  function assertExecutable(plan) {
    assertSinglePass(grantsFor(plan), plan);
  }

  /**
   * What this session can check, and whether it has.
   *
   * Given four unattended steps to survey a module, Concord read the files, reasoned, and asserted
   * a specific defect with a worked example. The defect was not real — its example described a
   * patch whose header disagreed with its own body, which a well-formed diff cannot do — and one
   * run of the reviewed test target would have refuted it against six existing cases. The target
   * was registered the whole time. Nothing told it so, and nothing noticed it had not looked.
   *
   * Declaring it is the intervention, which is the move this harness keeps reaching for: an
   * omitted turn is named so it can be fetched, an omitted lesson likewise, an oversized output
   * likewise. A check that exists and has not been run is the same kind of absence, and saying so
   * is both mechanical and true. It is not an enforcement — a model may still conclude without
   * checking — but it removes the excuse that it did not know.
   *
   * `runsAgo` matters as much as whether it ran at all: a pass recorded before the files changed
   * is evidence about code that no longer exists, which is the staler and more misleading case.
   */
  function verificationState() {
    const tool = registry.get(VERIFY_TOOL);
    if (!tool) return null;
    const targets = Array.isArray(tool.config?.targets) ? tool.config.targets.map((t) => t.name).filter(Boolean) : [];
    let last = null;
    runs.forEach((record, index) => {
      if (record.status !== 'completed') return;
      const task = (record.plan.tasks ?? []).find((t) => t.tool === VERIFY_TOOL);
      if (!task) return;
      const output = record.result.results[task.id];
      last = { target: task.input?.target ?? null, exitCode: output?.exitCode ?? null,
        ok: output?.ok === true, runsAgo: runs.length - 1 - index };
    });
    return { tool: VERIFY_TOOL, targets, lastRun: last, neverRun: last === null };
  }

  // The authority in force for the turn being processed. It equals `policy` unless the caller
  // attenuated this turn, and attenuation can only narrow (see attenuatePolicy). It is recorded
  // per run because the request hash binds the policy: replaying an attenuated turn against the
  // base policy would not reproduce it.
  let turnPolicy = policy;

  function adoptPlan(plan) {
    inspectPlan({ plan, policy: turnPolicy, registry, sourceLock, workspaceRoot });
    assertExecutable(plan);
    proposedPlan = plan;
  }

  async function attempt(plan) {
    // One controller per attempt, so cancel() can reach whatever is actually in flight. Cleared
    // in the finally below rather than on success, because a failed attempt must not leave a
    // stale controller that a later cancel would abort to no effect.
    const controller = new AbortController();
    inflight = controller;
    let result;
    try {
      result = await runPlan({ plan, policy: turnPolicy, registry, sourceLock, approvals: [...approvals], workspaceRoot, signal: controller.signal, onProgress });
    } finally {
      if (inflight === controller) inflight = null;
    }
    const id = digest(result).slice(0, 24);
    // planHash makes `runs` a durable, content-addressed execution ledger. Unlike the bounded
    // observation window fed to the model, `runs` is never truncated, so "did this proposed plan
    // ever actually run" stays answerable for the whole session.
    const record = { id, status: result.outcome.status, plan, planHash: digest(plan), result, policy: turnPolicy };
    runs.push(record);
    const tasks = result.events.filter(e => ['completed', 'failed', 'blocked'].includes(e.type)).map(e => {
      const task = plan.tasks.find(t => t.id === e.data.taskId);
      const receipt = { taskId: e.data.taskId, tool: task.tool, status: e.type };
      if (e.type === 'completed') {
        receipt.outputHash = e.data.outputHash;
        // Model replies already belong in history. Do not recursively duplicate prompts/proposals.
        if (task.tool !== MODEL_TOOL) {
          const bounded = boundedValue(e.data.output);
          if (!bounded.omitted) receipt.output = bounded.value;
          else receipt.outputOmitted = bounded;
        }
      } else if (e.type === 'failed') {
        receipt.code = e.data.code;
        // The tool's own code, when it raised one. Safe to carry: an identifier, never a message.
        if (typeof e.data.toolCode === 'string') receipt.toolCode = e.data.toolCode;
        // Carry the supervisor's diagnostic through to the model, for the same reason a rejected
        // proposal now carries one: INPUT_INVALID alone does not say which rule was broken.
        if (typeof e.data.reason === 'string') receipt.reason = e.data.reason;
      }
      else receipt.requestHash = e.data.requestHash;
      return receipt;
    });
    observations.push({ runId: id, root: result.root, status: record.status, tasks });
    lastAttemptedPlan = plan;
    if (persistRun) await persistRun(record);
    return record;
  }

  function applyOutcome(record) {
    if (record.status === 'blocked') {
      const detail = blockedDetail(record.result);
      pending = { taskId: record.result.outcome.taskId, requestHash: record.result.outcome.requestHash,
        ...detail, ...promotionEvidence(detail) };
      return;
    }
    pending = null;
    if (record.status !== 'completed') {
      lastError = { runId: record.id, code: record.result.outcome.code, taskId: record.result.outcome.taskId };
      const failed = record.result.events.find((e) => e.type === 'failed');
      const failedTask = failed ? record.plan.tasks.find((t) => t.id === failed.data.taskId) : null;
      recordLessonCandidate({ code: record.result.outcome.code, reason: failed ? failed.data.reason : null,
        toolCode: failed ? failed.data.toolCode : null,
        taskId: record.result.outcome.taskId, tool: failedTask ? failedTask.tool : null,
        runId: record.id, root: record.result.root });
      return;
    }
    lastError = null;
    recordSuccessCandidate(record);
    const lastTaskId = record.plan.tasks.map(t => t.id).at(-1);
    // Untrusted data from any other tool must never impersonate a model proposal.
    if (record.plan.tasks.at(-1).tool !== MODEL_TOOL) return;
    const output = record.result.results[lastTaskId];
    const proposal = output && typeof output === 'object' && !Array.isArray(output) ? output.proposal : undefined;
    let verifiedCitations = null;
    try {
      validateSchema(proposal, { type: 'object', properties: {
        reply: { type: 'string', minLength: 1, maxLength: 65536 },
        // An explicit `"plan": null` is a cooperative way to say "this turn acts on nothing".
        // Accepting only `{type:'object'}` rejected it as SCHEMA_MISMATCH, punishing the model
        // for being explicit while silently accepting a bare omission.
        plan: { anyOf: [{ type: 'object' }, { type: 'null' }] },
        // Anchors for factual claims drawn from tool results. Optional, because a turn that
        // reports nothing has nothing to cite; verified exactly when present.
        citations: { type: 'array', maxItems: MAX_CITATIONS, items: { type: 'object', properties: {
          taskId: { type: 'string', minLength: 1, maxLength: 128 },
          outputHash: { type: 'string', minLength: 64, maxLength: 64 },
          runId: { type: 'string', minLength: 1, maxLength: 128 },
          // The claimed fragment. Optional, and verified verbatim against the cited output when
          // present, so a citation can assert content rather than merely point at a receipt.
          quote: { type: 'string', minLength: 1, maxLength: MAX_CITATION_QUOTE_CHARS },
        }, required: ['taskId', 'outputHash'], additionalProperties: false } },
      }, required: ['reply'], additionalProperties: false });
      if (!proposal.reply.trim()) throw new HarnessError('SCHEMA_MISMATCH', 'Reply must be nonempty');
      // Validate the whole response before committing its narrative or proposed actions.
      // The proposal path validates and assigns directly rather than through adoptPlan, so the
      // single-approval rule has to be applied here too or a model-proposed plan bypasses it.
      if (proposal.plan) {
        inspectPlan({ plan: proposal.plan, policy: turnPolicy, registry, sourceLock, workspaceRoot });
        assertExecutable(proposal.plan);
      }
      // Verified before the reply is committed: an unverifiable anchor rejects the whole response,
      // matching how an invalid plan already rejects the narrative that accompanied it.
      verifiedCitations = proposal.citations ? verifyCitations(proposal.citations) : null;
    } catch (error) {
      // `reason` carries the supervisor's own diagnostic text, which is what makes a rejection
      // correctable: a bare reasonCode like INVALID_REFERENCE does not say which rule was broken,
      // so neither the caller nor the next turn can tell a missing dependsOn from a malformed
      // JSON pointer. These messages are harness-authored string literals, not model or file
      // content, so surfacing them opens no untrusted channel. `details` is deliberately NOT
      // included: it can carry input-derived values, and that would be a new content path.
      lastError = { runId: record.id, code: 'MODEL_PROPOSAL_INVALID',
        reasonCode: error instanceof HarnessError ? error.code : 'INVALID_PROPOSAL',
        reason: error instanceof HarnessError ? error.message : 'The proposal could not be validated' };
      observations.push({ ...lastError, status: 'rejected', source: 'supervisor' });
      recordLessonCandidate({ code: 'MODEL_PROPOSAL_INVALID', reasonCode: lastError.reasonCode,
        reason: lastError.reason, taskId: null, tool: null, runId: record.id, root: record.result.root });
      proposedPlan = null;
      return;
    }
    proposedPlan = proposal.plan ? clone(proposal.plan) : null;
    // Supervisor-minted provenance, stored INSIDE the same record as the reply it describes.
    // That co-location is load-bearing: `conversation` and `observations` are bounded
    // independently (24 vs 8 items), so a receipt kept only in the observation stream can be
    // evicted while the reply asserting the work survives -- which is exactly how a turn that
    // executed nothing stayed quotable as evidence of completed work. boundedRecords drops whole
    // records, so a receipt carried by its own reply can never be separated from it.
    // A model cannot forge this: additionalProperties:false above forbids an `execution` key.
    // runsAtCommit is this turn's position in the run ledger, which is what lets a later
    // execution be attributed to the turn that actually proposed it rather than to any turn
    // that happened to propose identical bytes. A count, not a clock: deterministic.
    history.push({ role: 'assistant', content: proposal.reply,
      execution: proposal.plan
        ? { kind: 'plan-proposed', planHash: digest(proposal.plan), runsAtCommit: runs.length }
        : { kind: 'reply-only', planHash: null, runsAtCommit: runs.length },
      // Present only when the turn anchored a claim, and only ever after verification, so a
      // citation in history is a checked fact rather than a model assertion about itself.
      ...(verifiedCitations && verifiedCitations.length ? { citations: verifiedCitations } : {}) });
  }

  /**
   * A pure projection of (history, runs). Resolves each committed reply's proposed plan against
   * the durable run ledger by content hash, so the model is handed `ran: true/false` rather than
   * being asked to infer execution from the absence of a receipt in a window that may already
   * have dropped it. Reports every attempt with its real status, and lists tools only from runs
   * that actually completed -- it never asserts the converse (that an unlisted tool did not run),
   * because a partially-failed run can execute tools without completing.
   */
  function settleHistory(entries) {
    // Attribute every run to exactly one proposing turn: the latest matching commit at or before
    // that run, which is the turn whose plan `executePlan` would actually have been holding.
    // Matching on plan hash alone over-credits -- two turns proposing byte-identical plans would
    // both claim one execution, reporting ran:true for a turn whose plan never ran. That is the
    // wrong direction for a fix about false assurance, so it is ruled out by construction here.
    const proposers = entries
      .map((entry, index) => ({ entry, index }))
      .filter(({ entry }) => entry.role === 'assistant' && entry.execution
        && entry.execution.kind === 'plan-proposed' && typeof entry.execution.runsAtCommit === 'number');
    const claimed = new Map();
    runs.forEach((run, runIndex) => {
      // `.at(-1)`: proposers are in history order, so the last eligible one is the latest commit.
      const owner = proposers.filter(p => p.entry.execution.planHash === run.planHash
        && p.entry.execution.runsAtCommit <= runIndex).at(-1);
      if (!owner) return;
      if (!claimed.has(owner.index)) claimed.set(owner.index, []);
      claimed.get(owner.index).push(run);
    });
    return entries.map((entry, index) => {
      if (entry.role !== 'assistant' || !entry.execution || entry.execution.kind !== 'plan-proposed') return entry;
      const attempts = claimed.get(index) ?? [];
      const completed = attempts.filter(r => r.status === 'completed');
      return { ...entry, execution: { ...entry.execution,
        ran: completed.length > 0,
        // Bounded like every other context record: a pathological re-attempt loop must not grow
        // an unbounded array inside a history entry. Newest attempts are the informative ones.
        attempts: attempts.slice(-MAX_SETTLED_ATTEMPTS).map(r => ({ runId: r.id, status: r.status })),
        attemptCount: attempts.length,
        toolsCompleted: [...new Set(completed.flatMap(r => r.plan.tasks.map(t => t.tool)))].sort() } };
    });
  }

  async function fetchSkillExcerpt() {
    const match = topSkillMatch(selected);
    if (!match || !registry.has('skills.snapshot')) return null;
    try {
      const plan = { version: 1, name: 'skill-enrichment', tasks: [{ id: 'skill', tool: 'skills.snapshot', input: { path: match.path, sourceId: match.sourceId } }] };
      const record = await attempt(plan);
      if (record.status !== 'completed') return null;
      const snapshotResult = record.result.results.skill;
      const entrypoint = snapshotResult?.files?.find((f) => f.path === 'SKILL.md');
      if (!entrypoint || typeof entrypoint.content !== 'string') return null;
      // Prefer the capability index's human-readable title over the SKILL.md frontmatter's machine slug.
      return { sourceId: match.sourceId, title: match.title ?? snapshotResult.metadata?.name,
        path: match.path, snapshotDigest: snapshotResult.snapshotDigest ?? null,
        text: entrypoint.content.slice(0, MAX_SKILL_EXCERPT_CHARS), truncated: entrypoint.content.length > MAX_SKILL_EXCERPT_CHARS };
    } catch { return null; } // Imported source skill text is untrusted reference material; a failed fetch never breaks the turn.
  }

  /** The best-scoring stored lesson for this message, if any registered memory.recall has one. */
  async function fetchMemoryExcerpt(message) {
    if (!registry.has('memory.recall')) return null;
    try {
      const plan = { version: 1, name: 'memory-enrichment', tasks: [{ id: 'recall', tool: 'memory.recall', input: { query: message, limit: MAX_RECALLED_LESSONS * 2 } }] };
      const record = await attempt(plan);
      if (record.status !== 'completed') return null;
      // Previously only results[0] was kept, discarding matches the recall had already scored and
      // returned. One lesson per turn was a hard ceiling on how much learned knowledge could reach
      // the model, for no benefit: the work was done and thrown away. The primary match keeps its
      // place and shape, and further scoring matches ride alongside under `related`, bounded by a
      // total byte budget so the context cost stays fixed rather than growing with the store.
      const scored = (record.result.results.recall?.results ?? [])
        .filter((r) => r && typeof r.lesson === 'string' && r.score > 0);
      if (!scored.length) return null;
      const kept = [];
      let bytes = 0;
      for (const match of scored.slice(0, MAX_RECALLED_LESSONS)) {
        const lesson = match.lesson.slice(0, MAX_SKILL_EXCERPT_CHARS);
        const size = Buffer.byteLength(lesson);
        // The primary match is always kept, so this never returns less than it used to.
        if (kept.length && bytes + size > MAX_MEMORY_EXCERPT_BYTES) break;
        kept.push({ candidateHash: match.candidateHash, lesson, score: match.score,
          truncated: match.lesson.length > MAX_SKILL_EXCERPT_CHARS,
          ...(Array.isArray(match.evidenceHashes)
            ? { evidence: (({ groundedCount, unverifiedHereCount }) => ({ groundedCount, unverifiedHereCount }))(classifyEvidence(match.evidenceHashes)) }
            : {}) });
        bytes += size;
      }
      const [primary, ...related] = kept;
      return { ...primary, ...(related.length ? { related } : {}) };
    } catch { return null; } // A fresh workspace with no memory/ directory, or any other recall failure, never breaks the turn.
  }

  async function send(message, options = {}) {
    if (typeof message !== 'string' || !message.trim()) throw new HarnessError('CHAT_INPUT', 'A nonempty chat message is required');
    // A model is required to propose. There is no demonstration path: a harness that answers from
    // its own pure tools when nothing is configured looks like it is working and is not, which is
    // precisely the confusion this project exists to refuse. Checked before anything is mutated,
    // so a refused turn leaves no orphaned user message in the history, and raised per-turn rather
    // than at startup so an operator with no model can still read state, runs and receipts.
    if (!isLive()) throw new HarnessError('CHAT_NO_MODEL', 'No model adapter is registered, so no plan can be proposed; start with --integrations naming a model.propose configuration');
    // Least authority derived per request, after hermes's webhook-safe toolset: a caller that knows
    // this turn's input is untrusted narrows the turn before the model is asked to plan. Computed
    // first so the context the model receives describes the authority it will actually get.
    turnPolicy = options && options.attenuate ? attenuatePolicy(policy, options.attenuate) : policy;
    history.push({ role: 'user', content: message });
    const context = await buildContext({ message, verification: verificationState(), history: settleHistory(clone(history)), observations: clone(observations),
      proposedPlan: proposedPlan ? clone(proposedPlan) : null, policy: turnPolicy });
    sourceCoverage = Array.isArray(context.sourceCoverage) ? [...context.sourceCoverage] : [];
    selected = Array.isArray(context.selected) ? [...context.selected] : [];
    const skillExcerpt = await fetchSkillExcerpt();
    const memoryExcerpt = await fetchMemoryExcerpt(message);
    mode = 'live';
    adoptPlan(livePlan(message, context, skillExcerpt, memoryExcerpt));
    applyOutcome(await attempt(proposedPlan));
    return snapshot();
  }

  async function approve(requestHash) {
    if (typeof requestHash !== 'string' || !/^[a-f0-9]{64}$/.test(requestHash)) throw new HarnessError('CHAT_INPUT', 'A SHA-256 request hash is required');

    // Granting a gate the run has already stopped at. Unchanged: the plan is mid-flight, so the
    // grant is immediately useful and re-attempting is what the operator is asking for.
    if (pending && pending.requestHash === requestHash) {
      approvals.add(requestHash);
      applyOutcome(await attempt(proposedPlan));
      return snapshot();
    }

    // Granting ahead of the run. The hash must be one this very plan computed, so an operator can
    // approve no effect that the proposed plan does not already contain, and a hash left over
    // from a plan that has since changed matches nothing.
    const planned = proposedPlan ? grantsFor(proposedPlan).grants : [];
    if (!planned.some(grant => grant.requestHash === requestHash)) {
      throw new HarnessError('CHAT_APPROVAL', 'No pending or planned approval matches that request');
    }
    approvals.add(requestHash);
    // Deliberately does NOT execute. Attempting here would start a run that stops at the next
    // ungranted effect, which is precisely the block-and-re-attempt this mechanism exists to
    // remove: approving five effects one at a time would re-run the first four. The operator
    // grants the set, then executes once.
    return snapshot();
  }

  async function executePlan(plan) {
    if (plan) adoptPlan(plan);
    if (!proposedPlan) throw new HarnessError('CHAT_PLAN', 'No plan is proposed');
    if (proposedPlan === lastAttemptedPlan && pending === null) return snapshot();
    applyOutcome(await attempt(proposedPlan));
    return snapshot();
  }

  async function replay(runId) {
    const record = runs.find(r => r.id === runId);
    if (!record) throw new HarnessError('CHAT_REPLAY', 'Unknown run id');
    // record.policy is the authority the run actually executed under, which is what its request
    // hashes bind. Falling back to `policy` keeps runs recorded before attenuation replayable.
    return replayPlan({ journal: record.result, plan: record.plan, policy: record.policy ?? policy, registry, sourceLock, workspaceRoot });
  }

  function snapshot() {
    return {
      mode,
      // clone, not a spread: entries now carry a nested `execution` object, which a shallow
      // copy would hand to callers by reference. Settled so a caller sees the same resolved
      // provenance the model does.
      history: settleHistory(history).map(m => clone(m)),
      sourceCoverage: [...sourceCoverage],
      selected: [...selected],
      pending: pending ? { ...pending } : null,
      lastError: lastError ? { ...lastError } : null,
      observations: boundedRecords(observations, { maxItems: 8, maxBytes: 16384 }),
      proposedPlan: proposedPlan ? clone(proposedPlan) : null,
      // Every effect this plan will ask for, with the exact request binding each one, before any
      // of them runs. An operator can grant the set and the run then completes in a single pass;
      // granting none is still a valid outcome and nothing here has executed. `granted` reflects
      // what this session already holds, so re-proposing an identical plan does not ask twice.
      plannedGrants: proposedPlan ? (() => {
        const preflight = grantsFor(proposedPlan);
        return {
          singlePass: preflight.singlePass,
          gatedCount: preflight.gatedCount,
          grants: preflight.grants.map(g => ({
            taskId: g.taskId, tool: g.tool, effect: g.effect, requestHash: g.requestHash,
            granted: approvals.has(g.requestHash),
            // Bounded like every other value a surface renders: an operator approving an effect
            // must see what it will do, and a large input must not break the view that shows it.
            input: boundedValue(g.input),
          })),
          deferred: preflight.deferred.map(d => ({ ...d })),
        };
      })() : null,
      runs: runs.map(r => ({ id: r.id, status: r.status })),
      // Suggestions, never authority: an operator may promote one, ignore it, or edit it first.
      lessonCandidates: lessonCandidates.map(c => clone(c)),
      // The authority actually in force for the latest turn: the base policy unless the caller
      // attenuated the turn. Surfaced so a client can show what is permitted instead of inferring it.
      authority: clone(turnPolicy),
    };
  }

  /**
   * Stop whatever is executing. The in-flight tool raises its own abort code, so the run is
   * recorded as failed with a real diagnostic rather than vanishing: a cancelled turn is still a
   * turn that happened, and for a gated effect the receipt says EFFECT_INDETERMINATE, which is
   * the truth. Returns the snapshot as of now; the caller whose send() was cancelled receives
   * the settled failure on its own response.
   */
  function cancel() {
    if (!inflight) throw new HarnessError('CHAT_NOTHING_RUNNING', 'No turn is currently running');
    inflight.abort();
    return snapshot();
  }

  /**
   * Carry a turn across several plans without a human message between them.
   *
   * Until now one turn meant one model call meant one plan. A ninety-line module with its tests
   * took about twenty interactions, nearly all of it turn overhead rather than thinking, because
   * every step needed a person to type something before the harness would reason again.
   *
   * The thing in the way is not the plan, it is the reasoning call. `model.propose` is a network
   * effect and gates like any other, so continuing without a person means authorising model calls
   * that do not exist yet — and their request hashes cannot be precomputed, because each prompt
   * depends on results the previous step has not produced. `planGrants` already names this exact
   * case `deferred`. An exact hash per call is therefore not available here, and pretending
   * otherwise would be the dishonest move.
   *
   * So the grant is coarser and is labelled as such: calling this IS the authorisation, bounded by
   * `maxSteps`, for model calls only. That is strictly weaker than an exact request hash and an
   * operator should read it that way. What it is not is a general loosening — every other effect
   * still needs its own exact grant, and reaching one stops the loop and hands it back. The
   * narrowest true statement: this lets Concord keep THINKING on its own; it never lets Concord
   * act on the world on its own.
   *
   * Each step is an ordinary recorded run and replays exactly as a hand-driven one does. Nothing
   * about the kernel changes here; this is orchestration over it.
   */
  // One positional field, matching send, approve, executePlan and replay. An options object read
  // a bare number as `{}` and silently fell back to a one-step budget: the button asked for four
  // and the journal recorded one, and nothing failed loudly enough to notice. There is no default
  // for the same reason the route has none - the budget is the authorisation, so it is stated.
  async function advance(maxSteps) {
    if (!Number.isInteger(maxSteps) || maxSteps < 1 || maxSteps > MAX_ADVANCE_STEPS) {
      throw new HarnessError('CHAT_INPUT', `maxSteps must be an integer from 1 to ${MAX_ADVANCE_STEPS}`);
    }
    if (!isLive()) throw new HarnessError('CHAT_NO_MODEL', 'No model adapter is registered, so no plan can be proposed');
    if (!history.length) throw new HarnessError('CHAT_PLAN', 'There is nothing to continue; send a message first');

    const stop = (reason, detail) => {
      // Recorded rather than only returned: how far an unattended run got, and why it handed back,
      // is evidence about the session and belongs where the rest of the evidence is.
      observations.push({ source: 'supervisor', status: 'advance', reason, steps: taken, maxSteps, ...(detail ?? {}) });
      return { ...snapshot(), advanced: { steps: taken, reason, ...(detail ?? {}) } };
    };
    let taken = 0;

    for (; taken < maxSteps; taken += 1) {
      // No fabricated user message. The continuation instruction is this turn's currentRequest,
      // which the payload already supplies separately from the conversation; writing it into
      // history would put words the operator never said into the transcript.
      const context = await buildContext({ message: ADVANCE_REQUEST, verification: verificationState(), history: settleHistory(clone(history)),
        observations: clone(observations), proposedPlan: proposedPlan ? clone(proposedPlan) : null, policy: turnPolicy });
      sourceCoverage = Array.isArray(context.sourceCoverage) ? [...context.sourceCoverage] : [];
      selected = Array.isArray(context.selected) ? [...context.selected] : [];
      mode = 'live';
      adoptPlan(livePlan(ADVANCE_REQUEST, context, await fetchSkillExcerpt(), await fetchMemoryExcerpt(ADVANCE_REQUEST)));

      let reasoning = await attempt(proposedPlan);
      if (reasoning.status === 'blocked') {
        const blocked = reasoning.result.events.find((e) => e.type === 'blocked');
        // The one effect this budget covers, checked by tool name on the recorded event rather
        // than inferred from the plan: anything else blocking here is a bug, not a model call.
        if (!blocked || blocked.data.tool !== MODEL_TOOL) {
          applyOutcome(reasoning);
          return stop('UNEXPECTED_GATE', { tool: blocked ? blocked.data.tool : null });
        }
        approvals.add(blocked.data.requestHash);
        reasoning = await attempt(proposedPlan);
      }
      applyOutcome(reasoning);
      if (reasoning.status !== 'completed') return stop('REASONING_FAILED', { code: reasoning.result.outcome.code });
      if (!proposedPlan) return stop('NOTHING_PROPOSED');

      // A plan touching the world stops the loop with the plan proposed and its grants computed,
      // so the operator returns to a decision rather than to a mess.
      const preflight = grantsFor(proposedPlan);
      if (preflight.gatedCount > 0) {
        return stop('AWAITING_APPROVAL', { gatedCount: preflight.gatedCount, singlePass: preflight.singlePass });
      }

      const run = await attempt(proposedPlan);
      applyOutcome(run);
      if (run.status !== 'completed') return stop('PLAN_FAILED', { code: run.result.outcome.code, taskId: run.result.outcome.taskId });
    }
    return stop('BUDGET_SPENT');
  }

  return { send, approve, executePlan, advance, replay, cancel, snapshot };
}
