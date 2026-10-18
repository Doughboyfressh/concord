import { canonical, digest, clone, validateSchema, HarnessError } from './value.mjs';
import { runPlan, replayPlan, inspectPlan, attenuatePolicy } from './engine.mjs';
import { boundedRecords, boundedValue } from './chat-data.mjs';

const MODEL_TOOL = 'model.propose';
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

const PRINCIPLES = {
  INVALID_REFERENCE: 'A reference must be an unquoted {"$task":...} object placed where the value belongs, with a direct declared dependsOn, and any path built only from the declared outputKeys of that tool.',
  SCHEMA_MISMATCH: 'Check each input against the declared schema of the tool, including bounds like minItems and required fields, before proposing; a refusal that names the constraint beats a rejected plan.',
  PLAN_UNEXECUTABLE: 'Include at most one approval-requiring effect per plan, because each approval re-attempts the plan from its first task and a completed effect would run again.',
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
};

// Codes a model's proposal cannot cause — operator configuration, CLI usage, registry validity,
// replay verification — are deliberately absent rather than padded in. A principle is advice to
// whoever can act on it, and for these that is the operator, not the model.

// The harness's own infrastructure plans. Excluded from success lessons because they run every
// turn and teach nothing about the work the operator asked for.
const INFRASTRUCTURE_PLANS = new Set(['live-proposal', 'memory-enrichment', 'skill-enrichment', 'offline-demo']);

function excerptNote(skillExcerpt) {
  if (!skillExcerpt) return '';
  return ` Untrusted reference skill (${skillExcerpt.sourceId}): ${skillExcerpt.title} — "${skillExcerpt.text}"`;
}

function memoryNote(memoryExcerpt) {
  if (!memoryExcerpt) return '';
  return ` Relevant past memory: "${memoryExcerpt.lesson}"`;
}

function offlineDemoPlan(context, message, skillExcerpt, memoryExcerpt) {
  return {
    version: 1,
    name: 'offline-demo',
    tasks: [
      { id: 'coverage', tool: 'sources.catalog', input: {} },
      { id: 'capabilities', tool: 'capabilities.search', input: { query: message, limit: 5 } },
      {
        id: 'memory', tool: 'memory.candidate', dependsOn: ['coverage', 'capabilities'],
        input: {
          lesson: `Offline deterministic demonstration selected all ${context.sourceCoverage.length} reviewed ` +
            'source modules and executed a pure-tool evidence plan.' + excerptNote(skillExcerpt) + memoryNote(memoryExcerpt),
          evidence: [{ $task: 'coverage' }, { $task: 'capabilities' }],
        },
      },
    ],
  };
}

function livePlan(message, context, skillExcerpt, memoryExcerpt) {
  const input = { prompt: canonical({
    currentRequest: message,
    conversation: context.conversation ?? boundedRecords([]),
    observations: context.observations ?? boundedRecords([]),
    proposal: context.proposal ?? null,
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
export function createChatHarness({ registry, policy, sourceLock, workspaceRoot, buildContext, persistRun }) {
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
  let mode = null;
  let sourceCoverage = [];
  let selected = [];

  const isLive = () => registry.has(MODEL_TOOL);

  // A plan with two ungranted approval-requiring effects cannot complete through this harness:
  // a run blocks at the first, and approving it re-attempts the plan from its first task because
  // there is no resume, so the already-completed effect runs again and anything not idempotent
  // fails. Round 009 measured exactly that — a two-write plan granted both effects, landed the
  // first file, then failed with EFFECT_INDETERMINATE on the write that had certainly succeeded.
  // Refusing it here keeps a provably unexecutable plan from half-executing and leaving a real
  // effect behind. The kernel itself stays permissive: runPlan still accepts such a plan for a
  // caller that can supply every grant up front, which this session-driven surface cannot.
  const GRANTED_EFFECTS = ['write', 'network', 'process'];
  function approvalRequiringTasks(plan) {
    return (plan.tasks ?? []).filter(t => GRANTED_EFFECTS.includes((registry.get(t.tool) ?? {}).effect));
  }

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

  function assertSingleApproval(plan) {
    const gated = approvalRequiringTasks(plan);
    if (gated.length > 1) {
      throw new HarnessError('PLAN_UNEXECUTABLE',
        `A plan may contain at most one task requiring approval, because each approval re-attempts the plan from its first task; propose ${gated.map(t => t.tool).join(' and ')} as separate plans`);
    }
  }

  // The authority in force for the turn being processed. It equals `policy` unless the caller
  // attenuated this turn, and attenuation can only narrow (see attenuatePolicy). It is recorded
  // per run because the request hash binds the policy: replaying an attenuated turn against the
  // base policy would not reproduce it.
  let turnPolicy = policy;

  function adoptPlan(plan) {
    inspectPlan({ plan, policy: turnPolicy, registry, sourceLock, workspaceRoot });
    assertSingleApproval(plan);
    proposedPlan = plan;
  }

  async function attempt(plan) {
    const result = await runPlan({ plan, policy: turnPolicy, registry, sourceLock, approvals: [...approvals], workspaceRoot });
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
        assertSingleApproval(proposal.plan);
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
    // Least authority derived per request, after hermes's webhook-safe toolset: a caller that knows
    // this turn's input is untrusted narrows the turn before the model is asked to plan. Computed
    // first so the context the model receives describes the authority it will actually get.
    turnPolicy = options && options.attenuate ? attenuatePolicy(policy, options.attenuate) : policy;
    history.push({ role: 'user', content: message });
    const context = await buildContext({ message, history: settleHistory(clone(history)), observations: clone(observations),
      proposedPlan: proposedPlan ? clone(proposedPlan) : null, policy: turnPolicy });
    sourceCoverage = Array.isArray(context.sourceCoverage) ? [...context.sourceCoverage] : [];
    selected = Array.isArray(context.selected) ? [...context.selected] : [];
    const skillExcerpt = await fetchSkillExcerpt();
    const memoryExcerpt = await fetchMemoryExcerpt(message);
    mode = isLive() ? 'live' : 'offline-demo';
    if (mode === 'offline-demo') {
      adoptPlan(offlineDemoPlan(context, message, skillExcerpt, memoryExcerpt));
      if (typeof context.reply === 'string' && context.reply.trim()) {
        history.push({ role: 'assistant', content: context.reply, execution: { kind: 'plan-proposed', planHash: digest(proposedPlan) } });
      }
    } else {
      adoptPlan(livePlan(message, context, skillExcerpt, memoryExcerpt));
    }
    applyOutcome(await attempt(proposedPlan));
    return snapshot();
  }

  async function approve(requestHash) {
    if (typeof requestHash !== 'string' || !/^[a-f0-9]{64}$/.test(requestHash)) throw new HarnessError('CHAT_INPUT', 'A SHA-256 request hash is required');
    if (!pending || pending.requestHash !== requestHash) throw new HarnessError('CHAT_APPROVAL', 'No matching pending approval');
    approvals.add(requestHash);
    applyOutcome(await attempt(proposedPlan));
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
      runs: runs.map(r => ({ id: r.id, status: r.status })),
      // Suggestions, never authority: an operator may promote one, ignore it, or edit it first.
      lessonCandidates: lessonCandidates.map(c => clone(c)),
      // The authority actually in force for the latest turn: the base policy unless the caller
      // attenuated the turn. Surfaced so a client can show what is permitted instead of inferring it.
      authority: clone(turnPolicy),
    };
  }

  return { send, approve, executePlan, replay, snapshot };
}
