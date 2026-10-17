import { canonical, digest, clone, validateSchema, HarnessError } from './value.mjs';
import { runPlan, replayPlan, inspectPlan } from './engine.mjs';
import { boundedRecords, boundedValue } from './chat-data.mjs';

const MODEL_TOOL = 'model.propose';
const MAX_SKILL_EXCERPT_CHARS = 1500;
const MAX_SETTLED_ATTEMPTS = 8;

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
  let lastError = null;
  let proposedPlan = null;
  let lastAttemptedPlan = null;
  let pending = null;
  let mode = null;
  let sourceCoverage = [];
  let selected = [];

  const isLive = () => registry.has(MODEL_TOOL);

  function adoptPlan(plan) {
    inspectPlan({ plan, policy, registry, sourceLock, workspaceRoot });
    proposedPlan = plan;
  }

  async function attempt(plan) {
    const result = await runPlan({ plan, policy, registry, sourceLock, approvals: [...approvals], workspaceRoot });
    const id = digest(result).slice(0, 24);
    // planHash makes `runs` a durable, content-addressed execution ledger. Unlike the bounded
    // observation window fed to the model, `runs` is never truncated, so "did this proposed plan
    // ever actually run" stays answerable for the whole session.
    const record = { id, status: result.outcome.status, plan, planHash: digest(plan), result };
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
      pending = { taskId: record.result.outcome.taskId, requestHash: record.result.outcome.requestHash, ...blockedDetail(record.result) };
      return;
    }
    pending = null;
    if (record.status !== 'completed') {
      lastError = { runId: record.id, code: record.result.outcome.code, taskId: record.result.outcome.taskId };
      return;
    }
    lastError = null;
    const lastTaskId = record.plan.tasks.map(t => t.id).at(-1);
    // Untrusted data from any other tool must never impersonate a model proposal.
    if (record.plan.tasks.at(-1).tool !== MODEL_TOOL) return;
    const output = record.result.results[lastTaskId];
    const proposal = output && typeof output === 'object' && !Array.isArray(output) ? output.proposal : undefined;
    try {
      validateSchema(proposal, { type: 'object', properties: {
        reply: { type: 'string', minLength: 1, maxLength: 65536 },
        // An explicit `"plan": null` is a cooperative way to say "this turn acts on nothing".
        // Accepting only `{type:'object'}` rejected it as SCHEMA_MISMATCH, punishing the model
        // for being explicit while silently accepting a bare omission.
        plan: { anyOf: [{ type: 'object' }, { type: 'null' }] },
      }, required: ['reply'], additionalProperties: false });
      if (!proposal.reply.trim()) throw new HarnessError('SCHEMA_MISMATCH', 'Reply must be nonempty');
      // Validate the whole response before committing its narrative or proposed actions.
      if (proposal.plan) inspectPlan({ plan: proposal.plan, policy, registry, sourceLock, workspaceRoot });
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
        : { kind: 'reply-only', planHash: null, runsAtCommit: runs.length } });
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
      const plan = { version: 1, name: 'memory-enrichment', tasks: [{ id: 'recall', tool: 'memory.recall', input: { query: message, limit: 3 } }] };
      const record = await attempt(plan);
      if (record.status !== 'completed') return null;
      const top = record.result.results.recall?.results?.[0];
      if (!top || typeof top.lesson !== 'string' || !(top.score > 0)) return null;
      return { candidateHash: top.candidateHash, lesson: top.lesson.slice(0, MAX_SKILL_EXCERPT_CHARS),
        truncated: top.lesson.length > MAX_SKILL_EXCERPT_CHARS };
    } catch { return null; } // A fresh workspace with no memory/ directory, or any other recall failure, never breaks the turn.
  }

  async function send(message) {
    if (typeof message !== 'string' || !message.trim()) throw new HarnessError('CHAT_INPUT', 'A nonempty chat message is required');
    history.push({ role: 'user', content: message });
    const context = await buildContext({ message, history: settleHistory(clone(history)), observations: clone(observations),
      proposedPlan: proposedPlan ? clone(proposedPlan) : null, policy });
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
    return replayPlan({ journal: record.result, plan: record.plan, policy, registry, sourceLock, workspaceRoot });
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
    };
  }

  return { send, approve, executePlan, replay, snapshot };
}
