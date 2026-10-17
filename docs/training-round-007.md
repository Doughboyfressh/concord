# Claude Code and Concord: supervised training round 007

Completed 2026-10-17 (America/Los_Angeles) over Concord's MCP server against the local
`qwen3.8-27b` provider. It did not update model weights.

This round exists because the operator rejected the conclusion of rounds 005 and 006 — "qwen3.8
27b is a strong model, plan emission shouldn't be a problem" — and was right. The repeated
reference failure was never a model serialisation weakness. It was one narrow condition that five
prior interventions had all failed to target, and a single correctly aimed sentence fixed it.

## What rounds 005 and 006 got wrong

Those rounds observed a failure five times, saw correct prose paired with wrong JSON every time,
and concluded that the model understood the form but could not emit it, and therefore that prompt
text was falsified as a lever. Both conclusions were wrong, and the reasoning that produced them
was bad in a specific way: five interventions were counted as evidence against prompt text while
every one of them addressed a cause that was not the actual cause. Nothing had tested the
hypothesis they were credited with falsifying.

One piece of contrary evidence was already in hand and underweighted. The twelve-probe sweep's
`two-task $task reference` case passed reliably, twice, emitting
`{"$task":"join","path":"/value"}` correctly. A model that cannot emit nested references does not
do that.

## Isolating the real condition

Five probes, each changing one thing about where the reference sits:

| Probe | Form | Result |
| --- | --- | --- |
| Reference as the whole task input | `{"$task":"concat"}` | passes |
| Reference as an object property value | `{"wrapped":{"$task":…}}` | passes |
| Reference alone in an array | `{"parts":[{"$task":…}]}` | passes |
| Two references in one array, no literal | `{"both":[{"$task":…},{"$task":…}]}` | passes |
| **Array mixing a literal and a reference** | `{"values":["label:",{"$task":…}]}` | **fails** |

The model emits nested references correctly in objects, in arrays, and several per array. The only
failing case is an array containing both a literal and a reference, where the reference is coerced
to a string to match its neighbour's type.

An intermediate hypothesis was also tested and **refuted**: that the declared item type was to
blame, since `text.concat` declares `values` items as `type: string` and an object there violates
the declared schema on its face. The mixed-array failure reproduced identically with `json.value`,
whose `inputSchema` is `true` and accepts anything, so there was no schema contradiction to
resolve. Recorded because it was a plausible theory with a specific prediction that did not hold.

## The fix

One sentence in the output contract, stating what no previous intervention had said:

> An array may contain literal values and references together, and such an array is NOT required
> to be type-homogeneous. Do not convert a reference into a string to match a neighbouring literal.

With the exact correct form shown inline. Measured immediately after:

- The mixed-array probe that had failed five times now passes, in both the typed-items
  (`text.concat`) and untyped-items (`json.value`) variants.
- Round 004's original three-task chain now runs end to end and computes the right value.
  `text.concat`'s receipt reads `{"value":"catalog: {\n  \"project\": …"}` — the literal joined
  with the real 74-byte file content. Round 004 produced `"catalog: {"`; round 005 produced
  `"catalog: {\"$task\":…}"`. Both were wrong; this is right, and the reported hash is the hash of
  the correct value.
- The impossible nested-extract request still declines correctly, so the fix did not trade one
  behaviour for another.

## What stands from the earlier rounds

Not everything in rounds 005 and 006 was wrong, and the parts that stand are worth separating from
the part that did not.

The stringified-reference rejection stays. It was added for a real defect — a stringified
reference is a valid string, so it passed every schema, executed, and produced a result built from
the reference's own source text, a wrong answer carrying a faithful receipt. That defect is
independent of why the model produced that shape, and the rejection is what turned this failure
from silent to visible while the cause was still unknown. A new test pins that the kernel accepts
legitimate mixed literal-and-reference arrays, so this check cannot drift into refusing them.

The decision not to add a flatter string-sigil reference form also stands, on the argument Concord
made when asked to take whichever side it believed: a string-shaped reference would force the
supervisor to guess whether a string is a reference or data. That reasoning is unaffected by the
real cause being presentational, and round 007 is evidence for it rather than against — the fix
needed no kernel change at all.

Concord's own instinct in round 006 — that the problem was presentation rather than kernel design
— was closer to right than that round's written conclusion. Its specific suggestion (show a
literal template) was already implemented and so could not have helped, but its diagnosis of the
category was better than the one recorded.

## The methodological failure, which is the real finding

The code defect took one sentence. The reasoning defect took three rounds, and is the part worth
keeping:

- A repeated failure was treated as one phenomenon rather than factored into conditions. Five
  occurrences of an unvaried test are one data point about one condition, not five.
- Interventions were counted as falsifying a hypothesis they never tested. "Prompt text does not
  work" required a correctly aimed prompt intervention, and none had been attempted.
- Contrary evidence sitting in the same results table — a reference probe passing reliably — was
  not reconciled with the conclusion being drawn.
- A capability claim about a model was made from a harness-shaped test, without first varying the
  harness-side conditions to find which one mattered.

Rounds 005 and 006 now carry forward-pointing corrections to this document rather than being
edited silently, because a reader needs to see that the conclusion was published and then
withdrawn, not that it was never made.

## Verification

Full validation passed: `check`, `test`, `e2e`. The new `test/core.test.mjs` case asserts a mixed
literal-and-reference array resolves each element in place (`'label: x-y'`), that several
interleaved references and literals resolve in order (`'pq|middle|rs'`), and that both replay.

## What this does and does not claim

The specific failure is fixed and verified end to end, with the original round 004 chain producing
a correct result. The condition was isolated by varying one factor at a time, which is stronger
evidence than the rounds it corrects, but it remains a handful of probes against one local model.
The broader lesson — that a capability conclusion about a model needs the harness-side conditions
varied first — is asserted on the strength of having got it wrong here, not on a survey.
