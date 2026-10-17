# Claude Code and Concord: supervised training round 009

Completed 2026-10-17 (America/Los_Angeles) over Concord's MCP server against the local
`qwen3.8-27b` provider. It did not update model weights.

Round 008 measured generalization but refused to execute anything outside a read/pure set, so
approval-gated effects — the ones where a mistake costs something — had no evidence at all. This
round closes that gap and found a real architectural limitation in the process: **a plan containing
more than one ungranted approval-requiring effect can never complete, and until this round it would
half-execute before failing.**

## How it was measured

Seven probes over `files.write` and `memory.promote`, each naming the dimension it varies: literal
content, referenced content, approval withheld, two gated effects, write-then-read ordering,
candidate-to-promotion chaining, and a write followed by a failing task.

The probe is deliberately stricter than round 008's:

- every write lands in a disposable sandbox workspace, never the repository;
- approval is per effect and never blanket — only `model.propose` and a write whose resolved input
  has been inspected are approved, and one probe withholds approval on purpose;
- verification reads the **real filesystem**, not the receipts, because a receipt describing a write
  that did not happen is exactly the false assurance these rounds exist to remove.

## What held

| Condition | Result |
| --- | --- |
| single write, literal content | correct, verified on disk |
| write whose content comes from a reference | correct; the grant showed the **resolved** value |
| approval withheld | correct: nothing on disk, directory unchanged |
| write then read back in one plan | correct: the dependent read saw the written bytes |
| `memory.candidate` chained into `memory.promote` | correct: one grant, one file in `memory/` |
| completed write followed by a failing task | correct: file kept, failure recorded |

The referenced-content case is worth calling out. The approval hash binds the *resolved* input, so
the operator is shown `{"content":"referred","path":"out2.txt"}` rather than an unresolved
reference. An approval gate that showed a reference would be asking for consent to something
unknowable; this one does not.

## What broke: two gated effects in one plan

The two-write probe required two grants, landed the first file, and then failed. The plan was
correct and both grants carried the right resolved inputs:

```
write-a {content:"A", path:"two-a.txt"}   approved, landed
write-b {content:"B", path:"two-b.txt"}   approved
final: failed   statuses: ["files.write:failed"]
lastError: { code: "EFFECT_INDETERMINATE", taskId: "write-a" }
```

The mechanism is the composition of two deliberate decisions, neither of which is wrong on its own:

1. A run blocks at the **first** ungranted effect.
2. Approving it **re-attempts the plan from its first task**, because there is no resume
   (`docs/architecture.md` and `docs/chat-session.md` both state the no-resume policy).
3. So the already-completed `write-a` executes again. `files.write` creates exclusively
   (`flag: 'wx'`) *specifically* so an approval cannot overwrite existing data, so the retry fails
   `EEXIST`.
4. Being a non-pure effect, that failure is classified `EFFECT_INDETERMINATE` — "the effect may
   have occurred" — when in fact it certainly occurred, on the previous attempt. The one
   classification that should never be wrong in this project was wrong here.

The no-resume policy was documented. This *consequence* was not, and the partial effect it leaves
behind is the part that matters: a file on disk from a plan that can never finish.

## The fix, and what was deliberately not done

A prompt rule was tried first — instruct the model to propose at most one gated effect per plan —
and measured as ineffective: it proposed two writes anyway. Per round 007's lesson, rather than
treating that as evidence against prompt text in general, the question became whether the harness
was at fault. It was.

`src/chat.mjs` now refuses, at proposal time, any plan containing more than one
approval-requiring task, with `PLAN_UNEXECUTABLE` naming the offending tools. Three properties of
that choice:

- **It prevents the partial effect.** Measured: the refused plan now leaves the sandbox
  byte-identical, with no `two-a.txt`. Previously the first write landed.
- **The kernel stays permissive.** `runPlan` still accepts such a plan, because a caller able to
  supply every grant up front can execute it in a single pass. Only the session-driven surface,
  which cannot do that, declines to drive it.
- **It applies on both paths.** The first implementation only guarded `adoptPlan`, and a
  model-proposed plan bypassed it entirely, because the proposal path calls `inspectPlan` and
  assigns `proposedPlan` directly. Found by the regression test failing, not by review.

Resume was **not** implemented. `docs/architecture.md` already names the prerequisite — idempotency
keys and reconciliation — and retrofitting it would make a run's outcome depend on a prior journal
rather than on its declared input. Consistent with round 006, where Concord argued the kernel
should stay strict rather than absorb a weakness, the limitation is now enforced and documented
instead of worked around.

After the fix: seven of seven correct, reproduced across two runs.

## A probe that was asserting something impossible

The two-write probe originally expected both files to land. That expectation was wrong, not
optimistic — the behaviour it demanded cannot happen. It is corrected to expect a refusal with no
effect, and noted here for the same reason round 008 noted its own probe bug: a measuring
instrument that encodes a false premise produces findings that look like model failures.

## What this does and does not claim

Seven conditions over the two native write tools, filesystem-verified, reproduced twice. It says
nothing about `process` or `network` effects beyond `model.propose`, nothing about concurrent
writes, and nothing about crash recovery mid-effect — `docs/architecture.md` is explicit that
partial journals are forensic evidence and that automatic retry is absent.

The `EFFECT_INDETERMINATE` misclassification is now unreachable through this surface, because the
plan that produced it is refused earlier. It is not *fixed*: a caller using `runPlan` directly, with
one grant and a re-attempt, can still reach it. Narrowing that classification so a pre-execution
failure is never reported as a possibly-occurred effect is a candidate for a later round.
