# Claude Code and Concord: supervised training round 010

Completed 2026-10-17 (America/Los_Angeles). It did not update model weights. Most of this round is
a kernel change verified by test rather than by live probing; the live write sweep from round 009
was rerun to confirm nothing regressed.

Round 009 named one candidate: narrowing `EFFECT_INDETERMINATE` so a failure that provably precedes
or follows an effect is not reported as a possibly-occurred one. Investigating it corrected round
009's own wording and then found a sharper, unambiguous version of the defect.

## Correcting round 009

Round 009 said the misclassification was "the one classification that should never be wrong in this
project, and it was wrong here". That overstated it. In round 009's case the tool itself threw
(`EEXIST` from an exclusive-create retry), and a throw out of `tool.execute` genuinely **is**
indeterminate for a non-pure tool: the effect may have landed before the throw and the kernel
cannot know. `EFFECT_INDETERMINATE` was the defensible report for that run, even though the file
existed from a previous attempt.

The real defect is adjacent and not arguable. Measured directly:

| Case | Tool returned? | File written? | Reported |
| --- | --- | --- | --- |
| output rejected by the task's `outputSchema` | yes | **yes** | `EFFECT_INDETERMINATE` |
| output exceeds the byte budget | yes | **yes** | `EFFECT_INDETERMINATE` |
| `tool.execute` threw | no | — | `EFFECT_INDETERMINATE` |

In the first two the engine is holding the returned output, so the effect **certainly** occurred,
and "may have occurred" understates it. The practical hazard is specific: this project's guidance
on `EFFECT_INDETERMINATE` is not to retry, but an operator or model told "may have occurred" can
reasonably retry — duplicating a non-idempotent effect that had already succeeded.

## The change

`runPlan` now separates the two stages. A throw out of `tool.execute` keeps its existing
classification (`EFFECT_INDETERMINATE` for effectful tools, `TOOL_FAILED` for pure). A failure
*after* the tool returned — unserialisable output, byte budget, declared `outputSchema`, journal
reserve — is recorded as **`OUTPUT_REJECTED`**, carrying the supervisor's own `reason`, which
composes with round 006's schema diagnostic: "the value does not equal the required constant",
"Tool output exceeds byte budget".

The model-facing contract states the distinction in the terms that matter: `OUTPUT_REJECTED` means
the tool completed, so for a write, network or process tool **its effect did occur** and only its
output was unusable; never describe it as not having happened, and never retry it.

## Replay, and a deliberate trade

Replay previously re-derived the failure code from the tool's effect and asserted an exact match.
It cannot re-derive *which* failure occurred without re-executing, so it now takes the recorded
failure and checks its legality instead: the code must be one of the codes permitted for that
tool's effect, the field set must be exactly `{taskId, code}` or `{taskId, code, reason}`, and
`reason` must be text.

This is the same shape as the `completed` receipt immediately below it, which already takes an
output it cannot reproduce and then asserts properties of it (`outputHash === digest(output)`).
The check that matters survives, and is tested: a journal rehashed to claim a pure tool's
`TOOL_FAILED` for an effectful tool is still refused with `REPLAY_TRANSITION`.

Older journals recording `EFFECT_INDETERMINATE` for a post-return failure still replay, because
that code remains permitted for an effectful tool. The narrowing applies to new runs; it does not
invalidate recorded history.

## An existing test changed meaning, intentionally

`deadlines and non-JSON outputs fail closed` asserted `TOOL_FAILED` for two cases. One of them —
a tool returning `undefined` — is a post-return failure, and now reports `OUTPUT_REJECTED`. The
test asserts per case and is renamed, because both still fail closed and the point is that they
now fail with distinct, more informative codes. This is a behaviour change to a passing test
rather than a regression, and is recorded as such.

## Verification

Full validation passed: `check`, `test`, `e2e`. A new `test/core.test.mjs` case covers all three
stages against a tool that really writes a file: both post-return failures report
`OUTPUT_REJECTED` with the file present on disk and a matching reason, a throw stays
`EFFECT_INDETERMINATE`, every journal replays, and a forged code is refused.

Round 009's live write sweep was rerun: seven of seven correct, nothing regressed.

## A third probe that scored the better outcome as a failure

The two-write probe expected the harness to refuse the plan. This run the model **declined to
propose one at all**, which is the better outcome, and the probe scored it `no-plan`. Corrected to
score the invariant that actually matters — no effect landed — and to accept either a harness
refusal or a model refusal. Noted because it is the third measuring-instrument fault in three
rounds, after round 008's `json.assert` expectation and round 009's impossible two-write
expectation; the pattern is that probes encode an assumption about *how* a thing should be right.

Whether the round 009 contract rule is what produced the refusal is not claimed: that rule was
measured ineffective when added, this is one run, and live inference is not deterministic.

## What this does and does not claim

The distinction is real, implemented, and tested at all three stages, and the narrowing is now in
the kernel rather than merely unreachable through one surface — which is what round 009 left open.
It does not make `EFFECT_INDETERMINATE` rare: a genuine throw mid-effect still produces it, and
still means what it says. Nothing here addresses crash recovery, where `docs/architecture.md`
remains explicit that partial journals are forensic evidence and automatic retry is absent.
