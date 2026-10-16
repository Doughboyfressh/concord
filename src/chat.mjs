import { digest, clone, HarnessError } from './value.mjs';
import { runPlan, replayPlan, inspectPlan } from './engine.mjs';

const MODEL_TOOL = 'model.propose';
const MAX_SKILL_EXCERPT_CHARS = 1500;

function excerptNote(skillExcerpt) {
  if (!skillExcerpt) return '';
  return ` Untrusted reference skill (${skillExcerpt.sourceId}): ${skillExcerpt.title} — "${skillExcerpt.text}"`;
}

function offlineDemoPlan(context, message, skillExcerpt) {
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
            'source modules and executed a pure-tool evidence plan.' + excerptNote(skillExcerpt),
          evidence: [{ $task: 'coverage' }, { $task: 'capabilities' }],
        },
      },
    ],
  };
}

function livePlan(message, context, skillExcerpt) {
  const input = { prompt: message };
  const system = (context.systemPrompt ?? '') + excerptNote(skillExcerpt);
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
    const record = { id, status: result.outcome.status, plan, result };
    runs.push(record);
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
    if (record.status !== 'completed') return;
    const lastTaskId = record.plan.tasks.map(t => t.id).at(-1);
    const output = record.result.results[lastTaskId];
    const proposal = output && typeof output === 'object' && !Array.isArray(output) ? output.proposal : undefined;
    if (!proposal || typeof proposal !== 'object' || Array.isArray(proposal)) return;
    if (typeof proposal.reply === 'string' && proposal.reply.trim()) {
      history.push({ role: 'assistant', content: proposal.reply });
    }
    if (proposal.plan && typeof proposal.plan === 'object') {
      // Untrusted model output: validated structurally before it can replace the proposed plan.
      adoptPlan(clone(proposal.plan));
    }
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
      return { sourceId: match.sourceId, title: match.title ?? snapshotResult.metadata?.name, text: entrypoint.content.slice(0, MAX_SKILL_EXCERPT_CHARS) };
    } catch { return null; } // Imported source skill text is untrusted reference material; a failed fetch never breaks the turn.
  }

  async function send(message) {
    if (typeof message !== 'string' || !message.trim()) throw new HarnessError('CHAT_INPUT', 'A nonempty chat message is required');
    history.push({ role: 'user', content: message });
    const context = await buildContext({ message, history: [...history] });
    sourceCoverage = Array.isArray(context.sourceCoverage) ? [...context.sourceCoverage] : [];
    selected = Array.isArray(context.selected) ? [...context.selected] : [];
    const skillExcerpt = await fetchSkillExcerpt();
    mode = isLive() ? 'live' : 'offline-demo';
    if (mode === 'offline-demo') {
      adoptPlan(offlineDemoPlan(context, message, skillExcerpt));
      if (typeof context.reply === 'string' && context.reply.trim()) history.push({ role: 'assistant', content: context.reply });
    } else {
      adoptPlan(livePlan(message, context, skillExcerpt));
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
      history: history.map(m => ({ ...m })),
      sourceCoverage: [...sourceCoverage],
      selected: [...selected],
      pending: pending ? { ...pending } : null,
      proposedPlan: proposedPlan ? clone(proposedPlan) : null,
      runs: runs.map(r => ({ id: r.id, status: r.status })),
    };
  }

  return { send, approve, executePlan, replay, snapshot };
}
