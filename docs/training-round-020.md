# Claude Code and Concord: supervised training round 020

Completed 2026-10-17 (America/Los_Angeles). It did not update model weights.

Round 019 closed with two stated limits: the sweep covered only two-task pairs, and capability was
measured by telling the model exactly which tools to use, which is compliance rather than choice.
Both are answered here.

## Composability is transitive

Round 018's matrix proved 170 two-task compositions compute. Chaining them tests a real hypothesis
rather than a formality: references resolve against a growing result set, and three-task ordering
was never exercised by the pair sweep.

Wherever A then B was verified and B then C was verified, A then B then C was built and run.

**400 of 400 chains held. None broke.** Identical across two runs.

## Goals instead of specifications

Round 019 named the tools. This round states a goal, names no tool, executes whatever plan the
model proposes, and compares the final value against an answer computed independently here.

First run: **0 of 4 correct.** Two of the four were this instrument's fault. One was a real defect.

### The real defect: an invented shorthand

Asked to join a literal with a file's text, the model emitted the string `$task:read/text` — its
own shorthand, not JSON. Round 005's check could not see it, because that check matches a JSON
object inside a string. So the kernel accepted it as an ordinary string, concatenated it literally,
and produced `body=$task:read/text`: a wrong answer carrying a faithful receipt. That is precisely
the class round 005 exists to prevent, in a form it missed.

`assertNotStringifiedRef` now also rejects a value that **begins** with `$task`. Anchoring matters,
and the anchor is tested: `use {"$task":"x"} here`, `the $task field` and `cost is $task-free` all
still pass, because prose that merely mentions the form is not a mis-serialised reference.

### Where it actually goes wrong

With coherent goals the failures localised precisely. The four goals that place a reference as a
whole input or a direct field succeeded. Both failures put a reference **inside an array beside a
literal** — `['body=', <ref>]` and `['digest=', <ref>]`.

That is the same position rounds 004 through 007 spent four rounds on. Round 007 fixed the
JSON-encoding mistake there; the model now reaches for shorthand in the same slot. **The position
is the weak spot, not the syntax.** Two different wrong serialisations, one position.

So the diagnostic was made position-specific. It now spells out the array form,
`["<your literal>", {"$task": "<task id>", "path": "<pointer>"}]`. The repaired **shape** is shown
and never the offending value, because a proposal may contain content copied from an untrusted
source and echoing it back would reopen the channel round 006 closed.

After that change: **6 of 6 correct, identical across two runs.** Both mixed-array goals recover
after rejection rather than succeeding outright, and one recovery is worth recording in detail — on
retry the model moved from shorthand to the JSON-encoded form, which the round 005 detector then
caught, and only then produced the object. Two independent detectors, each catching a different
mis-serialisation, with the model converging through both.

## The instrument was wrong twice more

Two of the first run's four failures were bad expectations, not model errors:

- `join then hash` and `merge then hash` expected the hash of the wrapper object, while the goal
  asked for the hash of the joined string and of the merged object. Computing `digest('red-blue')`
  independently matched the model's output exactly. The model was right and the expectation was
  wrong.
- `concat then assert` asked the model to assert the joined result is an object while expecting the
  joined string. That is contradictory: a string is not an object, so `json.assert` correctly
  failed. The model behaved correctly on an incoherent request.

Those are the eighth and ninth instrument faults across rounds 008 to 020, and the shape has not
varied once: an expectation asserting *how* the answer should look rather than testing whether it
is correct.

## Verification

`check` and `e2e` pass. All non-browser suites pass: 134 passing, 2 skipped. `test/browser.test.mjs`
remains environmentally flaky, unchanged from round 018 and demonstrated there to be unrelated to
these changes.

A new case in `test/core.test.mjs` covers the shorthand forms and a bare `$task`, the four benign
strings that must still pass, and the genuine object form still computing `body=contents`.

## What this does and does not claim

Composition is transitive across 400 chains built from verified pairs. Given a goal with no tool
named, the model chooses a correct composition and computes the right value in all six cases, two
of them requiring one rejection-driven correction first.

Six goals, one local model, two runs. Recovery depended on the diagnostic naming the position:
before that change the same goals failed *without* recovering, so this result measures the kernel
and the model together rather than the model alone. And the mixed-array position still fails on
first attempt. What changed is that it now fails loudly and recovers, instead of computing a wrong
answer behind a valid receipt.
