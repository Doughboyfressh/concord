# Claude Code and Concord: supervised training round 017

Completed 2026-10-17 (America/Los_Angeles). It did not update model weights.

Sixteen rounds transferred facts (round 011's lessons), principles (round 016's table), and
mechanisms (guards, diagnostics, provenance, citations). One category had only ever been
transferred as prose: **method**. How to measure something. That was the most valuable thing the
assisting model contributed, and it existed nowhere in the harness.

## The transferable method, and why it is worth encoding

Across sixteen rounds this project produced one finding more reliable than any other: **the
instrument was usually wrong before the system under test was.**

- Round 007 treated five runs of an **unvaried** test as five data points, concluded a model
  limitation, published it, and had to withdraw it. One correctly aimed change then fixed the
  thing in a sentence.
- Rounds 008 through 015 each shipped a probe with its own fault: an impossible expectation, a
  better outcome scored as failure, a conflated field, a corrupt seed, a bucket that silently
  absorbed an unanticipated case, a path defaulted to somewhere real.
- Rounds 004 and 005 drew wrong conclusions from aggregates — "nine of ten" concealed *which*
  condition failed.

Every one of those faults is mechanically detectable from the data the experiment itself holds. So
they are now checked rather than hoped for.

## `experiment.compare`

A new pure tool. It takes a hypothesis and a set of named conditions, each with the factor it
varies, its declared expectation, and the recorded outcome. It returns a verdict per condition and
four methodological checks:

| Check | What it catches | Round it comes from |
| --- | --- | --- |
| `UNVARIED_CONDITIONS` | conditions that vary nothing between them, so they are one data point repeated | 007 |
| `NONDISCRIMINATING_EXPECTATION` | every condition expects the same thing, so a pass cannot show the factor mattered | 012 |
| `SINGLE_CONDITION` | one condition cannot isolate a cause | 007, 008 |
| `untestable` verdict | an expectation or outcome that was never recorded, reported as neither pass nor failure | 008, 012 |

Two design choices carry most of the weight.

**It emits no aggregate.** There is no rate, score, total or summary field. "Nine of ten" is
exactly how rounds 004 and 005 went wrong, so the output shape makes that reading unavailable
rather than merely discouraged. Results are three name lists — confirmed, refuted, untestable.

**`untestable` is a first-class verdict.** A missing expectation is not a failure and not a pass.
Collapsing it either way is how a probe invents a finding, which round 012 did.

Posed round 007's own error, the tool answers correctly from the data alone:

> `UNVARIED_CONDITIONS`: "These conditions vary nothing between them, so they are one data point
> rather than 3: attempt 1, attempt 2, attempt 3." — and `discriminating: false`.

Posed round 008's properly varied sweep, it returns three confirmed conditions and no warnings.

## The principle table completed, with a deliberate exclusion

Round 016 flagged its table as covering fifteen of forty-four codes. It now covers the conditions a
**model's proposal can actually cause** — unregistered tools, invalid plans, values outside the
JSON domain, unsupported schema keywords, judgment thresholds, journal exhaustion, worker and
browser and integration conditions — thirty-two in total.

Codes a model cannot cause are **deliberately absent** rather than padded in: operator
configuration, CLI usage, registry validity, replay verification. A principle is advice to whoever
can act on it, and for those that is the operator. Completing the table to forty-four for
symmetry would have made it longer and less true.

## Round 005's discipline caught this round's own mistake

`experiment.compare` declares `outputKeys`. On the first full validation the suite failed, because
`test/core.test.mjs` asserts that **every** tool declaring an output shape is exercised against
real execution — a rule added in round 005 precisely so a declaration cannot drift from reality.
The new tool was unexercised, and the test said so before anything shipped.

That is the clearest evidence so far that these mechanisms compose rather than accumulate: a rule
written eleven rounds earlier caught a gap in work that did not exist when it was written.

## Verification

Full validation passed: `check`, `test`, `e2e`. One new case in `test/core.test.mjs` poses four
real historical faults to the tool — round 007's unvaried conditions, round 012's
nondiscriminating expectation, round 008's and 012's missing expectation, and round 008's sound
sweep — and asserts no aggregate field of any name exists in the output.

## What this does and does not claim

Method is now a capability rather than advice: the harness can check an experiment's structure for
the specific faults this project kept committing, including faults a model would have no other way
to notice. It does not make any particular experiment correct — a well-formed comparison can still
test the wrong thing, and the tool cannot tell whether a hypothesis is worth testing. It checks
structure, not judgement. And the checks are drawn from faults that actually happened here, so
there will be classes of instrument error it does not catch.
