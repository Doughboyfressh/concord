import { inspectPlan, approvalRequest, normalizePolicy } from './engine.mjs';
import { canonical, digest, HarnessError } from './value.mjs';

/**
 * Every grant a plan will need, computed before any of it runs.
 *
 * The limitation this removes was real and measured. A plan may block only once per attempt, and
 * approving that one gate re-attempts the plan from its first task, because the kernel has no
 * resume. Round 009 measured the consequence: a two-write plan granted both effects, landed the
 * first file, then failed with EFFECT_INDETERMINATE on the write that had certainly succeeded. The
 * defensive answer was to refuse any plan with more than one gated task, which is correct and
 * which also means a harness that writes ten files does it as ten plans, ten model calls and ten
 * separate approvals — each one asked for after nine effects have already landed.
 *
 * The observation that dissolves it: a request hash binds the plan, the policy, the registry, the
 * source lock, the workspace and the task's RESOLVED input. Every one of those is known before
 * execution for a task whose input contains no reference to another task's output. So the gate
 * does not have to be discovered by running into it. The hashes can be computed up front, approved
 * as a set, and handed to runPlan together — and a run holding every grant it needs never blocks,
 * so nothing is ever re-attempted and the round 009 failure cannot occur.
 *
 * What stays refused, and why it must. A gated task whose input references an earlier task's
 * output has no resolved input until that task has run, so its hash cannot exist yet. Such a task
 * is reported in `deferred` rather than guessed at. A plan with one gated task is still fine
 * however it is written, because there is nothing earlier to re-execute; a plan with several,
 * where any of them is deferred, is still refused, because approving the computable ones and then
 * blocking on the deferred one is exactly the re-attempt this avoids.
 *
 * This computes and discloses. It grants nothing: approving is the operator's act, and runPlan
 * still checks every hash itself.
 */

const GRANTED_EFFECTS = ['write', 'network', 'process'];

/**
 * Does this input depend on a result that does not exist yet?
 *
 * Mirrors the kernel's own rule in engine.mjs: a non-array object carrying `$task` is a reference.
 * compile() has already rejected malformed and stringified references by the time this runs, since
 * inspectPlan below performs the same compilation — so this only has to recognise the real ones.
 */
function hasReference(value) {
  if (!value || typeof value !== 'object') return false;
  if (!Array.isArray(value) && Object.hasOwn(value, '$task')) return true;
  return Object.values(value).some(hasReference);
}

/**
 * @returns {{identity: object, order: string[], grants: Array, deferred: Array, gatedCount: number,
 *            singlePass: boolean}}
 *   `grants` are the exact request hashes an operator can approve now, in execution order.
 *   `deferred` names each gated task whose hash cannot exist yet, with the reason.
 *   `singlePass` is true when granting everything in `grants` lets the plan run without blocking.
 */
export function planGrants({ plan, policy, registry, sourceLock, workspaceRoot }) {
  // Full structural validation first, and deliberately not a lighter check of our own: a hash
  // computed from a plan the kernel would reject is a hash for a run that can never happen.
  const inspected = inspectPlan({ plan, policy, registry, sourceLock, workspaceRoot });
  const normalized = normalizePolicy(policy);
  const byId = new Map((plan.tasks ?? []).map((task) => [task.id, task]));

  const grants = [];
  const deferred = [];
  for (const taskId of inspected.order) {
    const task = byId.get(taskId);
    const tool = registry.get(task.tool);
    if (!tool || !GRANTED_EFFECTS.includes(tool.effect)) continue;

    if (hasReference(task.input)) {
      deferred.push({ taskId, tool: task.tool, effect: tool.effect, reason: 'REFERENCE',
        detail: 'This input resolves from an earlier task\'s output, so its exact request cannot exist until that task has run' });
      continue;
    }
    // Schema validation is deliberately absent here. compile() already validated every
    // reference-free task input against its tool's schema (engine.mjs, in the same loop that
    // checks dependencies), so inspectPlan above has rejected the whole plan before this line can
    // be reached. A second check would be unreachable code that merely looked like care. The byte
    // budget is different: inputFor enforces it at execution and compile does not, so a literal
    // input can be structurally valid and still too large to ever run.
    if (Buffer.byteLength(canonical(task.input)) > normalized.maxOutputBytes) {
      deferred.push({ taskId, tool: task.tool, effect: tool.effect, reason: 'INPUT_LIMIT',
        detail: 'This input exceeds the policy byte budget, so the task cannot run however it is approved' });
      continue;
    }
    grants.push({
      taskId, tool: task.tool, effect: tool.effect,
      requestHash: approvalRequest(inspected.identity, task, tool, task.input),
      inputHash: digest(task.input),
      input: task.input,
    });
  }

  return {
    identity: inspected.identity,
    order: [...inspected.order],
    grants,
    deferred,
    gatedCount: grants.length + deferred.length,
    // One pass means: hold these grants and the run never stops, so nothing is ever re-executed.
    singlePass: deferred.length === 0,
    limitations: [
      'These are exact requests, not grants. Nothing is approved by computing it, and runPlan checks every hash itself',
      'A hash binds this plan, this policy, this registry, this source lock and this workspace; change any of them and it stops matching, which is the point',
      'A deferred task is not a rejected one: its input resolves from an earlier result, so its request exists only once that result does',
    ],
  };
}

/**
 * May this plan be attempted by a surface that approves between attempts?
 *
 * One gated task is always fine: it blocks at most once and there is nothing completed to repeat.
 * Several are fine when every one of them can be approved before the first runs. Several where any
 * is deferred is the case that must stay refused — the computable ones would execute, the deferred
 * one would block, and the approval would re-attempt the plan over effects that already landed.
 */
export function assertSinglePass(preflight, plan) {
  if (preflight.gatedCount <= 1 || preflight.singlePass) return;
  const names = preflight.deferred.map((entry) => `${entry.taskId} (${entry.tool})`).join(', ');
  throw new HarnessError('PLAN_UNEXECUTABLE',
    `This plan has ${preflight.gatedCount} approval-requiring tasks and ${preflight.deferred.length} of them cannot be approved in advance: ${names}. `
    + 'Each one resolves its input from an earlier task, so approving it would re-attempt the plan over effects that already ran. '
    + 'Give the gated tasks literal inputs, or propose the dependent effect as its own plan.',
    { deferred: preflight.deferred.map((entry) => entry.taskId), plan: plan?.name ?? null });
}
