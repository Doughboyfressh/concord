# Claude Code and Concord: supervised training round 019

Completed 2026-10-18 (America/Los_Angeles). It did not update model weights.

Round 018 generated 629 compositions in half a second and closed with two stated limits: it
probed **shape rather than semantics**, and it said **nothing about what the model can produce**.
Both are answered here, and both became answerable because round 018 produced something no earlier
round had — **ground truth**: 170 compositions proven to run.

## Semantics: accepting is not computing

Rounds 004 and 005 are the standing warning. Both had plans that passed the gate, executed
cleanly, and produced the wrong value. So "the kernel accepted it" was never the interesting claim.

A reference resolves correctly exactly when the resolved input equals the source output at the
cited key — and the kernel already commits to what it passed the tool: the `intent` event records
`inputHash = digest(resolved input)`. So the check is **exact rather than approximate**: rebuild
the resolved input independently, digest it, and compare against the kernel's own commitment.

Where a tool's semantics are small enough to restate without copying the implementation
(`text.concat`, `json.value`, `json.hash`, `json.mergeShallow`), the final output is additionally
compared against an independent computation.

| Check | Result |
| --- | --- |
| reference resolution against the kernel's own `inputHash` | **170 / 170** |
| final output against an independent restatement | **30 / 30** |
| divergences | **0** |

Identical across two runs. Reference resolution is semantically correct, not merely accepted.

## Capability: measured against verified targets

Every prior capability measurement compared the model against expectations *written by the same
party reading the results* — and rounds 008, 009, 010, 012, 013 and 015 each had an instrument
fault for exactly that reason. The matrix removes it: a verified composition is a target nobody
had to guess at, because the kernel already proved it computes.

Eight targets were sampled across distinct source tools, each described in words, with the model
asked to propose the plan. Scoring compares the tool sequence, the presence of a reference, and
the reference path against the shape already known to work.

| Verdict | Count |
| --- | --- |
| matched the verified shape | **8 / 8** |

Identical across two runs. Four of the eight were mixed-array positions — a literal and a
reference in the same array — which is the exact shape rounds 004 through 007 spent four rounds
failing to produce. It now produces them reliably, with the correct path, against targets it had
no way to know in advance.

## What makes this measurement better than the earlier ones

The expectation was not authored by the measurer. Round 018's matrix established which
compositions compute, by execution; round 019 asks the model for those and compares. The only
judgement left in the loop is the natural-language description, and a wrong description shows up
as the model producing a *different* composition rather than as a silently vacuous pass.

That removes the failure mode this project kept hitting. It does not remove every one.

## What this does and does not claim

Semantic correctness of reference resolution is established across the whole working matrix,
exactly, against the kernel's own commitment — not sampled, not approximated. Output semantics are
established for the 30 compositions whose consumer tool could be independently restated; the
remaining 140 verify resolution only, because restating a tool's semantics by reading its
implementation would prove nothing.

Capability is eight targets, one local model, two runs. It says the model reliably produces
two-task compositions with correct reference paths when told precisely what to build. It does not
show it would choose those compositions unprompted, nor that it handles topologies the matrix does
not generate — fan-in, diamonds, and anything requiring a grant are all outside this sweep, since
write, network and process effects need an approval per effect and cannot be swept.
