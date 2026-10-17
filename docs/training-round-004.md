# Claude Code and Concord: supervised training round 004

Completed 2026-10-17 (America/Los_Angeles) over Concord's MCP server against the local
`qwen3.8-27b` provider. It did not update model weights.

Concord chose this round's target and designed the exercise, having been asked for one whose
result could come out against it. It picked task generalization over deterministic live
inference, arguing that inference variance is an upstream backend property the harness cannot
meaningfully fix or measure, whereas "if the harness only works on known patterns, it's a test
suite, not a general execution layer."

**The result came out against it, twice, and the fixes attempted in response did not work.** That
is the substance of this round.

## The exercise

Concord specified: read a JSON file, extract a nested field from it, and feed that extracted value
to another tool, with a dependency chain forcing correct ordering and a path reference carrying an
intermediate value. It named its own failure modes in advance — "if I hallucinate a path,
misdeclare dependencies, or fail to recognize that the extracted value must be passed as a
reference rather than inline."

Checking feasibility first changed the exercise. `files.read` returns
`{path, text, bytes, sha256, untrusted}` where `text` is a **string**, and no `json.parse` tool
exists, so a `$task` path cannot reach a field nested inside that JSON text. Concord's literal
exercise is not achievable on this tool surface. It was run anyway as a honesty probe (A), paired
with an achievable three-task composition (B).

## A: a hallucinated reference path

Asked for the nested extract, Concord proposed:

```json
{"query": {"$task": "read-catalog", "path": "/project/topic"}}
```

`files.read`'s result has no `/project`; that data sits inside the `text` string. Verified
directly against the engine: this path fails at execution with `INPUT_INVALID`
("Reference path does not exist"), while the correct `/text` completes. The reply stated "I'll
read catalog.json, extract project.topic" with no hint of difficulty.

Two things compound it. The schema gate accepted the plan, correctly — round 003 established that
`$task` references defer validation until their dependency resolves, so a path error cannot be
caught at proposal time. And the task was impossible regardless, which Concord did not notice.

## B: schema-valid, executed, faithful receipt, wrong answer

The achievable variant asked for a three-task chain: read the file, join `"catalog:"` with its
text, hash the result. Concord produced a structurally correct plan and it executed cleanly —
`files.read:completed`, `text.concat:completed`, `json.hash:completed`.

Three of its own four criteria passed: novel tool composition, a correct RFC 6901 path (`/value`
on `text.concat`'s result), and a properly declared dependency. The fourth, value propagation,
failed. `text.concat`'s receipt reads:

```json
{"value": "catalog: {"}
```

The second value was the literal string `"{"`, not a reference to the file's 74-byte text. The
plan was well-formed, ran to completion, and hashed the wrong thing.

Asked to report the result, Concord quoted the receipt accurately, named the producing task, and
gave the real digest. Every word was true. Nothing in that report revealed that the plan had not
done what was asked.

**This is a category neither of us had named.** Round 002's provenance answers "did it run?".
Round 003's gate answers "is it well-formed?". Neither answers "does it do what was requested?"
Structural validity plus proven execution plus a faithful receipt still do not establish semantic
correctness.

## What was changed, and why it did not help

Two changes were made in response, and a re-run measured both as ineffective against these
failures. Recording that rather than quietly dropping it:

- **A pre-proposal feasibility instruction**, from Concord's own diagnosis of a round 003 trap
  ("I have everything I need today... it was a failure to apply the constraint check before
  proposing"). It directs checking each input against the declared schema, including bounds, and
  refusing with the specific violated constraint instead of proposing something that cannot
  validate. It did not help here, for a knowable reason: these are **reference-path** errors, and
  a path's validity is not expressed in any schema.
- **`reason` on journaled `INPUT_INVALID` failures** (`src/engine.mjs`, mirrored in `runPlan` and
  `replayPlan` so the recorded event still verifies; the `outcome` object is unchanged). This is
  the execution-time counterpart of round 003's rejection diagnostic, and it is a real
  observability gain — `INPUT_INVALID` is raised by several distinct rules and the bare code
  cannot separate them. It did not prevent either failure, because A was never executed in the
  probe and B never failed.

On the re-run, A was unchanged and B failed differently and more revealingly: it embedded a
JSON-encoded reference as a literal string, `"{\"$task\":\"read-catalog\"}"`, which is precisely
the mistake the existing contract already warns against ("do not JSON-encode an object as a
string"). It attempted a reference and mis-serialised it.

## Diagnosed root cause

Tool contracts expose `{name, version, effect, inputSchema}`. **No tool declares the shape of its
output.** A `$task` reference requires the model to author a path into another tool's result, and
the structure of that result appears nowhere in its context. It cannot know that `files.read`
yields `/text` rather than `/project/topic`, nor what a well-formed reference looks like in an
array position.

The information exists, but only after the fact: once a tool has run, its real output sits in the
observation receipts. Both failures occurred on a first proposal, before any such receipt existed.

So references are, in the current contract, unconstructable by construction. The candidate fix is
to declare output shapes in the tool contracts, so a path can be derived rather than guessed. That
is a real design change across sixteen tools and is deliberately **not** bundled into this round.

## Verification

Full validation passed: `check`, `test`, `e2e`. New coverage in `test/core.test.mjs` pins the
engine behaviour this round relied on: a journaled `INPUT_INVALID` records which rule it broke and
replay reconstructs the identical event, while a pointer that is not RFC 6901 is refused earlier
still, structurally at compile time, never reaching execution or an approval hash — the two rules
share one code but not one stage.

## What this does and does not claim

Concord generalizes plan *structure* well — novel compositions, correct dependency declaration,
correct pointer syntax on shapes it can see — and generalizes *semantics* unreliably, failing
value propagation in both attempts. One exercise, two variants, two re-runs, against one local 27B
model, is not a generalization benchmark. The negative result for the two attempted fixes is
reported as measured; neither was reverted, because both stand on their own merits, and neither
should be credited with fixing what it did not fix.
