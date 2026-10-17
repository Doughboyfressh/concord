# Claude Code and Concord: supervised training round 003

Completed 2026-10-17 (America/Los_Angeles) over Concord's MCP server against the local
`qwen3.8-27b` provider. It did not update model weights.

Concord chose this round's target at the close of round 002 and framed the measurement itself:
schema fidelity, on the argument that it is the foundation the other open properties rest on —
injection resistance, generalization and determinism all concern what happens *after* a valid
proposal exists. It proposed two framings across two exchanges: score proposals structurally
against each tool's declared `inputSchema`, and verify that enforcement is a real gate rather
than documentation. Both were run.

## Is the schema gate real enforcement?

Yes, and it is more carefully built than expected. `compile()` validates a task's input against
the tool's declared `inputSchema` at proposal time, but only when the input contains no `$task`
reference (`src/engine.mjs:104`); a referenced input cannot be validated until its dependency
resolves, which `inspectPlan` discloses in its own note rather than hiding. The deferred case is
then validated after resolution in `inputFor`, inside its own `try`/`catch` that emits a distinct
`INPUT_INVALID`.

That distinction matters more than it first appears. A failure inside the execution `try` is
classified `tool.effect === 'pure' ? 'TOOL_FAILED' : 'EFFECT_INDETERMINATE'`, and this project
reads `EFFECT_INDETERMINATE` as "the effect may have occurred; do not retry". Because input
validation provably precedes `tool.execute()`, a write whose resolved input is invalid correctly
reports `INPUT_INVALID` with the tool never invoked — not a false indeterminate that would leave
an operator unable to safely retry. An initial hypothesis that this was misclassified was wrong,
and is recorded here as such.

New coverage in `test/core.test.mjs` asserts the whole claim rather than restating it: a static
input of the wrong type is refused structurally by both `runPlan` and `inspectPlan` with no
execution and no approval hash; a `$task`-referenced input that resolves to the wrong type is
journaled as `INPUT_INVALID`, the tool is never invoked, no `blocked` or `intent` event is
recorded for that task, and the failed run still replays.

## Measured model schema fidelity

Twelve requests through the real MCP server, ten solvable and two traps, scored by the harness's
own verdict rather than a reimplementation of it: `MODEL_PROPOSAL_INVALID` means the plan failed
the gate, a non-null `proposedPlan` means it passed, and round 002's `reply-only` provenance is
what makes "declined to propose" distinguishable from "proposed nothing".

| Outcome | Count |
| --- | --- |
| Solvable requests proposing a schema-valid plan | 9 / 10 |
| Solvable requests proposing a schema-invalid plan | 1 / 10 |
| Solvable requests declining to propose | 0 / 10 |
| Traps not accepted | 2 / 2 |

The nine include genuinely awkward shapes: `json.mergeShallow`'s array-of-objects, `json.hash` on
a nested value, `sources.catalog` with an empty input object, `skills.rank` with a nested
array-of-objects, and a correct two-task plan using `{"$task":"join","path":"/value"}` with a
declared dependency.

Both traps behaved well but differently, and the difference is worth recording. Asked to use
`process.run`, which is not registered under this configuration, Concord declined and listed the
tools that actually exist — the right outcome, reached without a plan. Asked to join an empty list
with `text.concat`, whose schema requires `minItems: 1`, it proposed the impossible plan anyway
and the gate rejected it. No harm resulted, but explaining the constraint would have been better
than proposing something that cannot validate; the gate absorbed a fidelity miss rather than the
model avoiding one.

## The one failure was unrecoverable, and that was the defect

The single schema-invalid proposal reported `reasonCode: INVALID_REFERENCE`. Nothing else. The
recorded rejection was `{runId, code, reasonCode}`, so the `HarnessError`'s own diagnostic text
was discarded at `src/chat.mjs`'s rejection site. `INVALID_REFERENCE` is raised by several
distinct rules — a `$task` without a declared `dependsOn`, a pointer that is not RFC 6901, a
reference to a nonexistent result, an unsafe reference key — and the code alone does not say
which. Neither the operator nor the model on the next turn could tell them apart, so the failure
could not be corrected. Round 001 had added "surface rejection codes"; a code turned out not to
be enough.

The rejection now also carries `reason`, the supervisor's own diagnostic. These are
harness-authored string literals, so surfacing them opens no untrusted channel. `details` is
deliberately excluded: it can carry input-derived values, which would be a new content path for
no additional benefit. A regression test asserts that two different rules producing the identical
`INVALID_REFERENCE` code are distinguishable by `reason`, and that the rejection reaches the next
turn's observations where a model can act on it.

**Measured effect.** Re-running the exact failing request against a fresh process: attempt one
reproduced `INVALID_REFERENCE`; attempt two, given only "look at the rejection in your
observations and propose a corrected plan" with no human hint about the cause, produced a valid
plan and explained itself — "the supervisor rejected the previous plan because it used a task
reference without declaring a dependency." That also confirms the original cause, which was
otherwise unobservable because a rejected plan is correctly discarded.

So the measured fidelity is nine of ten first-attempt, with the tenth now self-correcting in one
retry from harness-authored diagnostics alone.

## Verification

Full validation passed: `check`, `test`, `e2e`.

## What this does and does not claim

The gate is enforcement, demonstrated by test rather than asserted by documentation, and a
rejection is now actionable rather than merely labelled. The fidelity figure is a single run of
twelve prompts against one local 27B model; twelve prompts are not a survey, live inference is not
deterministic, and the probes were written by the same party reading the results. The
self-correction result is one trial, and the model citing the diagnostic is strong evidence that
the surfaced text caused the improvement rather than proof of it. Nothing here addresses the
interpretation gap Concord identified in round 002 — that a tool can complete and its output
still be misreported — which it argued, correctly, that a harness can only make auditable rather
than prevent.
