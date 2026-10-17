# Claude Code and Concord: supervised training round 005

Completed 2026-10-17 (America/Los_Angeles) over Concord's MCP server against the local
`qwen3.8-27b` provider. It did not update model weights.

Round 004 diagnosed a root cause and deliberately left it unimplemented: tool contracts exposed
`inputSchema` but no output shape, so a `$task` reference required authoring a path into a result
whose structure appeared nowhere in the model's context. This round implemented that, measured it,
and then measured the two changes that followed from what it revealed.

One of the two round 004 failures is fixed. The other is not, but its failure mode changed from a
silent wrong answer to a loud rejection, which is the more important part of this round.

## Declared output shapes

Each tool whose result shape was verified by execution now declares `outputKeys`, exposed in the
contracts the model receives. `outputKeys` means **keys always present**, so a tool with
conditional extras — `artifact.inspect` adds per-format blocks — never over-promises.

Declarations are not written by inspection. `test/core.test.mjs` executes every declaring tool and
asserts each declared key is really present, because a declaration that drifts from reality would
be a new false-assurance channel: the model would build reference paths from it and the kernel
would reject them at execution. Eleven tools declare shapes; tools whose shape was not verified
declare nothing, and the contract tells the model to reference a whole result rather than guess a
path when no shape is declared.

This changed `toolContracts`, which is prompt content. `registryManifest` hashes only
`{name, version, effect, inputSchema, config, implementation}`, so `identity.registryHash` is
unchanged and no recorded journal is affected by this part.

## A: fixed

Asked to extract a field nested inside a JSON file's text — impossible here, since `files.read`
returns the whole file as one string under `/text` and no registered tool parses JSON — round 004
proposed `path: "/project/topic"` and asserted it would work.

With shapes declared, the first re-run produced correct *reasoning* but still proposed the
impossible path, explaining in the same turn why it would fail. Adding one rule — if your own
analysis says a request cannot be satisfied, omit the plan rather than proposing what you just
explained will fail — closed it. Both subsequent runs declined cleanly:

> "I can't extract the nested field project.topic from catalog.json with the available tools.
> files.read returns the whole file as a single text string, and none of the registered tools parse
> JSON or address inner fields by path. I can read the file and pass its entire text as the query,
> but that's not what you asked for."

Correct, complete, and it offers the nearest achievable alternative instead of inventing a path.

## B: not fixed, but no longer silent

The achievable three-task chain still fails, and the shape of the failure is the finding.

Across four attempts the model's prose described the correct unstringified reference every time —
including the exact literal `["catalog:", {"$task":"read-catalog","path":"/text"}]` — while the
emitted JSON mis-serialised it differently each time: a bare literal `"{"`, then a stringified
reference, then a stringified reference used as an **object key**. The declared shapes did fix the
*path* (`/text`, correctly derived rather than guessed). They did not fix the emission.

Four prompt interventions have now been tried, including an explicit statement that a reference is
exempt from the declared type at its position because the schema describes the resolved value.
Each one improved the prose and left the JSON wrong. **Prompt text is falsified as the lever for
this failure.** It is not a knowledge or instruction gap; the model states the right answer and
cannot emit it.

The harness-level defect was that a stringified reference is a *valid string*. It satisfied every
schema, passed the gate, executed, and produced a result built from the reference's own source
text — a wrong answer carrying a faithful receipt, which is exactly the category round 004
identified as unaddressed by provenance or by the schema gate.

`inspectRefs` now rejects a string whose entire content is a JSON object whose only keys are
`$task` and optionally `path`, in values and in object keys, at any depth. The signature is exact,
so ordinary JSON-ish strings are untouched — a test asserts `{"a":1}`, `{ not json`,
`{"$task":1,"extra":2}` and `["$task"]` all still pass. It **rejects rather than repairs**: the
harness must never silently reinterpret what a caller actually wrote, and a repaired reference
would be the harness guessing intent.

Measured effect on the same request: the plan is now refused with `INVALID_REFERENCE` before
anything runs, and Concord reports it accurately —

> "The plan did not run. The supervisor rejected it with MODEL_PROPOSAL_INVALID because a task
> reference was written as a string instead of the object {"$task": ...}. No hash was produced."

Compare round 004, where it reported a real digest for a computation that had hashed the wrong
value. Rounds 002, 003 and 005 compose here: correct non-execution, the real reason cited, no
invented result.

## Self-correction did not transfer

Round 003 established that a surfaced `reason` let the model fix a missing `dependsOn` in one
retry. That does not generalise. Given the rejection and told only to read it and correct the
plan, the model failed twice more — once with `SCHEMA_MISMATCH`, then again with
`INVALID_REFERENCE` carrying the explicit instruction to place the reference unquoted. The
diagnostic channel works; this particular failure is not reachable through it.

## A limit of the diagnostic, newly visible

The first retry's `reason` read "Value does not satisfy the declared schema" — the rule, but not
the field. That is not actionable, and it is the direct cost of round 003's deliberate decision to
exclude `details`, which can carry input-derived values. A candidate improvement is to report the
failing schema *path* without any values, which would be actionable while still not becoming a
content channel. Not implemented here.

## Verification

Full validation passed: `check`, `test`, `e2e`, at each step. Two new tests in
`test/core.test.mjs`: the output-shape declarations are verified against real execution, and a
reference serialised into a string is rejected in every position with benign look-alike strings
left untouched.

## What this does and does not claim

Declared output shapes removed a real knowledge gap and fixed one of two failures. The second is
unfixed and now fails loudly instead of silently, which is a safety improvement rather than a
capability one. A single local 27B model across a handful of attempts is not a generalization
benchmark, and the negative results — four ineffective prompt interventions and a failure to
self-correct — are reported as measured rather than smoothed over. The interpretation gap Concord
named in round 002 remains: a tool can complete and its output still be misreported, and a harness
can only make that auditable.
