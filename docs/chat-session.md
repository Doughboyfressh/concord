# Chat sessions

`createChatHarness({ registry, policy, sourceLock, workspaceRoot, buildContext, persistRun? })` in `src/chat.mjs`
is the session broker. It holds no clock, randomness, or ambient state; everything it produces is a function of
the registry, policy, source lock, workspace root, the context builder's output, and the approvals granted so
far. It returns five methods: `send`, `approve`, `executePlan`, `replay`, `snapshot`.

## The turn cycle

1. **`send(message)`** appends the message to history, calls `buildContext({message, history})` (see
   [source-derived instructions](chat-instructions.md)), and proposes exactly one plan: a deterministic
   pure-tool demonstration plan when no `model.propose` tool is registered, or a single-task plan that calls
   `model.propose` when one is. The proposed plan is validated structurally (`inspectPlan`) before it is
   accepted, then attempted immediately.
2. **Attempting a plan** means calling the kernel's `runPlan` with the currently granted approvals. Tasks whose
   tool has a `pure` or `read` effect always run; `write`, `network`, and `process` tasks run only if their
   exact request hash has already been approved. A plan built entirely from `pure`/`read` tools therefore
   completes in the same call that proposed it — that is the offline demonstration's "executable pure tool
   plan." A plan with an ungranted effect stops there; its `requestHash`, `tool`, `effect`, and resolved `input`
   surface as `pending` on the returned state, and nothing beyond that point in the plan has executed.
3. **`approve(requestHash)`** accepts only the hash currently in `pending`; anything else throws. On match, the
   hash joins the harness's accumulated approval set and the current proposed plan is attempted again. If that
   attempt completes and its last task's output carries a `{reply?, plan?}` shape (the contract `model.propose`
   returns), the reply is appended to history and the plan — after its own structural validation — replaces the
   proposed plan. A model's returned plan is data until that validation passes; it cannot execute anything by
   being returned.
4. **`executePlan(plan?)`** attempts the given plan, or the current proposed plan if none is given, and is a
   no-op if that exact plan object was already the last one attempted and nothing is pending (so a caller that
   calls `executePlan()` right after a `send()` that already completed does not re-run the same pure tools for
   no reason).
5. **`replay(runId)`** looks up the run's recorded `{plan, result}` by its content-derived id and calls the
   kernel's `replayPlan` against the harness's own policy/registry/sourceLock/workspaceRoot. Replay never calls
   `tool.execute`; it only verifies the recorded hash chain reproduces the same transitions.

## Run identity and evidence

Each attempt's run id is `digest(result).slice(0, 24)` — a function of the plan, policy, source lock, registry,
workspace, approvals, and the resulting events, not of wall-clock time. Two attempts with identical inputs
produce the identical id and identical bytes. `persistRun`, when supplied, is expected to treat a collision on
that id as an idempotent no-op if the bytes match, and as a real error otherwise — `scripts/chat.mjs`'s own
`persistRun` does exactly this (see [validation evidence](validation.md) for the regression test).

## What this module does not do

It does not retry a blocked or failed attempt automatically, does not resume an interrupted effect across
process restarts, and does not clear or rotate the approval set — approvals accumulate for the life of the
harness instance, which is safe only because a request hash is specific to one exact plan/task/input/identity
combination.
