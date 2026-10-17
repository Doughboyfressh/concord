# Claude Code and Concord: supervised training round 008

Completed 2026-10-17 (America/Los_Angeles) over Concord's MCP server against the local
`qwen3.8-27b` provider. It did not update model weights.

Round 007's finding was methodological: a repeated unvaried test is one data point, an aggregate
score hides which condition failed, and a capability claim about a model needs the harness-side
conditions varied first. This round is the first generalization measurement built that way, and it
caught a defect that round 007's own "verified end to end" claim had missed.

## How it was measured

Eight probes, each naming the dimension it varies — reference topology (chain, fan-in, diamond),
data type in flight (string, object, number), reference form (whole result versus a path into it),
and failure propagation. Results are reported per condition rather than totalled.

Crucially, every plan is **executed** and the computed value compared against an expected one. A
schema-valid plan that computes the wrong thing counts as a failure. That is exactly what rounds
004 and 005 missed when a plan passed the gate, ran cleanly, and hashed the wrong string.

## First run: three failures, one cause

| Condition | Result |
| --- | --- |
| chain (two tasks) | correct |
| chain + literal and reference in one array | **execution-failed** |
| fan-in, two sources into one consumer | **execution-failed** |
| diamond, one source, two consumers, recombined | **execution-failed** |
| object value through a reference | correct |
| number value through a reference | correct (see probe bug below) |
| path into a nested tool output | correct |
| failure stops dependents | correct |

All three failures were the same thing, and round 006's diagnostic named it immediately:

```
Value does not satisfy the declared schema: /values/1 expected type string but found object
```

The round 007 fix had worked: the model now emits a mixed literal-and-reference array correctly.
But it emitted `{"$task":"t1"}` **without `path`**, which resolves to the task's entire result
object — `{value: "x-y"}` — where `text.concat` requires a string. The contract's examples all
showed a path; no rule stated what omitting one means.

This is also the round 007 error repeated in miniature, and worth recording as such. Round 007
claimed the reference failure "verified end to end" on the strength of the catalog chain, which
happened to include a path. Varying the topology exposed the adjacent case immediately. The error
class was the same; the detection was three rounds faster.

One result in that table was a bug in the probe, not the model. The number-through-reference case
was scored `wrong-value` because the expectation was written as `undefined` without knowing that
`json.assert` returns `{passed, value, evidenceHash}`. The actual output was correct. The probe now
asserts the checkable subset, and this is noted rather than quietly corrected, because a measuring
instrument that miscounts is the same category of problem as the harness defects these rounds exist
to find.

## The fix and the second measurement

One addition to the output contract, targeted at the actual cause:

> A reference WITHOUT "path" resolves to that task's entire result object, not to a value inside
> it. Wherever a string, number or other scalar is required, include a path naming the key:
> `text.concat` returns `{"value": ...}`, so use `{"$task":"join","path":"/value"}`.

With `files.read` given as a second concrete instance and a pointer to each tool's `outputKeys`,
which round 005 had already made available.

Re-run, twice, with identical results:

| Condition | Run 1 | Run 2 |
| --- | --- | --- |
| chain (two tasks) | correct | correct |
| chain + literal and reference in one array | correct | correct |
| fan-in | correct | correct |
| diamond | correct | correct |
| object value through a reference | correct | correct |
| number value through a reference | correct | correct |
| path into a nested tool output | correct | correct |
| failure stops dependents | correct | correct |

Eight of eight, twice, every value verified against execution. The diamond case is the strongest
single result: four tasks, one source consumed by two independent branches and recombined, with
literals and references interleaved and every path correct.

## What this says about the earlier rounds

The improvements compose, and this round is the first evidence of that rather than an assertion:

- Round 006's schema diagnostic is what made round 008's failure diagnosable in one line. Before
  it, the same three failures would have read "Value does not satisfy the declared schema" and the
  cause would have been guesswork — which is precisely how rounds 004 and 005 went wrong.
- Round 005's `outputKeys` is what makes the new rule actionable: naming a key is only useful if
  the model can see which keys exist.
- Round 002's provenance and round 003's `reason` are why an execution failure arrives as a
  located, attributable fact rather than a narrative.

## What this does and does not claim

Eight conditions across four dimensions, executed and value-checked, reproduced across two runs.
That is a materially stronger basis than any previous round's generalization claim, and it is still
eight conditions against one local model — not a benchmark, and not evidence about topologies,
types or tools that were not tried. Write effects were deliberately excluded: the probe refuses to
execute any plan containing a tool outside a fixed read/pure set, so nothing here measures
generalization over approval-gated effects.

The interpretation gap Concord named in round 002 is untouched. Every value here was checked by the
harness against an expected result, which is a property of the *test*, not of the harness: in
ordinary use a tool can still complete and have its output misreported, and nothing in this round
changes that.
