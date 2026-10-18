# Claude Code and Concord: supervised training round 018

Completed 2026-10-18 (America/Los_Angeles). It did not update model weights.

The operator's objection was about pace: seventeen rounds, roughly one mechanism each, every probe
hand-written. That is a fair criticism, and the bottleneck was identifiable — **learning ran at the
speed of the operator's attention**, because every finding required someone to design a probe,
read the result and derive a lesson.

This round removes that bottleneck for one large class of knowledge.

## The composition matrix generates itself

The harness already declares everything a probe needs. Each tool publishes its `inputSchema`, so a
valid input can be synthesised. Round 005 made each tool publish `outputKeys`, which is exactly
what a reference path must be built from. And pure and read tools need no model call and no
approval, so nothing throttles the rate.

So the probes are now generated rather than written: for every ordered pair of exercisable tools,
through every declared output key of the source, at every reference slot of the consumer, in both
the direct and mixed-array shapes that rounds 004 to 007 spent four rounds on.

**629 compositions from 12 tools, zero hand-written, in 0.575 seconds.**

| Outcome | Count |
| --- | --- |
| completed — a composition proven to work | 170 |
| `INPUT_INVALID` — type-incompatible reference, correctly refused | 314 |
| `INVALID_SCHEMA` — a synthesised value used where a schema is required | 115 |
| `EFFECT_INDETERMINATE` | 26 |
| `JUDGMENT_REJECTED` — score below threshold, correct | 3 |
| `SCHEMA_MISMATCH` | 1 |

Most failures are the generator proposing type-incompatible joins, which is the schema gate working
rather than a defect. The 170 successes are each a round 016 success lesson: a topology and
reference path proven to work.

## What the matrix found that seventeen rounds missed

The 26 `EFFECT_INDETERMINATE` results were all reads — `files.read`, `artifact.inspect`,
`memory.recall` — failing on an incompatible input.

A read **cannot** leave a partial mutation. It requires no approval; `grantedEffects` is
`['write', 'network', 'process']` and read is deliberately not among them. Yet a failed read
reported "the effect may have occurred", and round 016's own principle for that code says *do not
retry it automatically* — advice that is simply wrong for an observation, which is always safe to
repeat.

Round 010 split pure from non-pure and left read on the wrong side of the line. The correct line is
the one the effect taxonomy already draws: indeterminacy belongs to effects that can change the
world.

```
failure = { code: grantedEffects.includes(tool.effect) ? 'EFFECT_INDETERMINATE' : 'TOOL_FAILED' }
```

A write that throws stays indeterminate, because it genuinely may have landed. Replay stays
**permissive for read** — accepting both codes — so journals recorded before this narrowing keep
verifying, the same compatibility stance round 010 took for its own.

This is the first defect in this project found by generation rather than by someone noticing.

## Verification, stated precisely

`check` and `e2e` pass. The test suite is 255 tests; everything passes except
`test/browser.test.mjs`, which is **flaky in this environment for reasons unrelated to this
change**: failures oscillate between none, one and two across identical runs, always as
`connect ETIMEDOUT` against the test's own localhost fixture, with 37 live Chrome processes on the
machine.

That was not assumed. The classification line was temporarily reverted and the browser tests failed
**identically** — two failures either way — which rules this change out as the cause. The Chrome
processes were left alone rather than killed, because they are not this project's to reclaim.

New coverage in `test/core.test.mjs`: a failed read reports `TOOL_FAILED` and replays; a throwing
write still reports `EFFECT_INDETERMINATE` and replays; and a legacy read journal recording the old
code still verifies.

## What this does and does not claim

Learning is no longer bounded by hand-written probes for compositional knowledge: a generated
matrix covers more of the composition space in half a second than seventeen rounds of probes
covered in total, and it found a real misclassification on its first run.

It is not a general learning accelerator. It exercises **pure and read** tools only, because those
need no approval — write, network and process compositions still require a grant per effect and
cannot be swept this way. It synthesises *minimal valid* inputs, so it probes shape rather than
semantics. And it says nothing about whether the model can produce these compositions; it measures
what the kernel accepts, which is a different question from what round 008 measured.
