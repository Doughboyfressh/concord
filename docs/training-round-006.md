# Claude Code and Concord: supervised training round 006

Completed 2026-10-17 (America/Los_Angeles) over Concord's MCP server against the local
`qwen3.8-27b` provider. It did not update model weights.

Round 005 ended with two candidates flagged and deliberately unbundled. This round implemented the
first — actionable schema diagnostics — and put the second, a kernel reference-form change, to
Concord as a design question. Concord argued against changing the kernel for its own benefit, and
its argument was correct.

## Schema rejections now say where and which rule

`validateSchema` previously threw one message for every failure: "Value does not satisfy the
declared schema". That named the rule but not the field, so a rejection could not be acted on —
the direct cost of round 003's deliberate decision to exclude `details`, which can carry
input-derived values.

Rejections now carry an RFC 6901 path and the specific rule, for example:

- `/values/1 expected type string but found number`
- `/values needs at least 1 item but has 0`
- `the value missing required property values`
- `/outer/inner/0/k expected type number but found string`

Three properties of the implementation matter more than the text itself:

- **Location and rule only, never a value.** This string reaches model context and journaled
  failure reasons, so it must not become a channel for the data being validated. A test asserts a
  sentinel value never appears in any diagnostic.
- **Declared property names are schema-derived; undeclared keys are not named.** The first
  implementation echoed the key of an undeclared property, and the no-echo test caught it: a key
  can itself be caller data, such as an email address. Undeclared keys are now unnamed and the
  schema's permitted names are listed instead, which is both leak-free and more useful.
- **Deterministic.** Object traversal is sorted by key, so the reported path is a pure function of
  content rather than of key insertion order. This is required, not cosmetic: round 004 records
  these reasons in journals, and `replayPlan` must reconstruct the identical event.

A failure inside an `anyOf`/`oneOf` alternative is speculative rather than diagnostic, so it is
not reported; the message stays at the alternative that failed to match.

The diagnostic immediately explained a failure that was opaque in round 005. That round's retry had
failed with a bare `SCHEMA_MISMATCH`; the same request now reads "the value has an undeclared
property; permitted properties are plan, reply" — the model had emitted a third top-level key
alongside `reply` and `plan`, which no previous round could see.

## Measured effect

The same twelve-probe sweep as round 003, scored by the harness's own verdict, run twice:

| Outcome | Round 003 | Round 006 (two runs) |
| --- | --- | --- |
| Solvable requests proposing a schema-valid plan | 9 / 10 | **10 / 10** |
| Traps not accepted | 2 / 2 | 2 / 2 |
| Traps *declined* rather than caught by the gate | 1 / 2 | **2 / 2** |

Both runs were identical, so this is reproducible rather than a lucky sample. The probe that was
round 003's single failure — `artifact.inspect` with a reference — now passes. The
schema-impossible `text.concat` trap, which round 003 proposed anyway and left the gate to reject,
is now declined with an explanation.

## The reference-emission failure, and why the kernel did not change

One specific failure is now five for five across rounds 004 to 006. Asked for a three-task chain
where `text.concat` joins a literal with a file's text, the model's prose describes the correct
unstringified reference every time — including the exact literal
`["catalog:", {"$task":"read","path":"/text"}]` — and the emitted JSON mis-serialises it every
time: a bare `"{"`, a stringified reference, a stringified reference used as an object key. Round
005's kernel check makes this fail loudly rather than silently computing the wrong answer, but it
still does not succeed, and round 003's self-correction does not reach it.

Concord was asked to argue whichever side it believed, explicitly including telling the harness not
to change for its benefit. It did:

> "A string-shaped reference reintroduces the exact ambiguity the current rejection exists to
> eliminate... A sigil like `@read:/text` would require the supervisor to guess whether a string is
> a reference or data, which is exactly the failure mode you are trying to avoid. The kernel should
> remain strict and reject stringified references, because that forces the model to learn the
> correct form rather than papering over the weakness with a compatibility shim."

That is right, and it is the reason no reference-form change was made. A second expressible form
would add ambiguity to a kernel whose value is that it has none.

Concord's proposed alternative was to show the reference structure as a literal template rather
than describing it in prose. **That was already implemented when it proposed it**: the contract
contains five literal exemplars, including the exact form `{"$task":"read","path":"/text"}` twice.
No sixth prose intervention was added. The exemplar has been present through all five failures,
which strengthens rather than weakens the round 005 conclusion that prompt text is not the lever
for this one.

## A critique recorded, and partly disputed

Asked for the weakest remaining property, Concord said the harness cannot distinguish a model that
understands a task from one that can serialise the answer, and so "is measuring serialisation skill
rather than reasoning skill".

Half of that is a fair hit: the measurement does conflate them, and this round's own evidence —
correct prose, wrong JSON, five times — is the clearest demonstration of it. The other half is
disputed and recorded as such. For an execution harness the serialised plan *is* the deliverable:
an intention that emits the wrong plan produces the wrong effect, or in round 004's case a wrong
answer carrying a faithful receipt. Comprehension that cannot be emitted is not a capability the
harness can act on, and treating it as success would be exactly the false assurance rounds 002
through 005 were spent removing.

## Verification

Full validation passed: `check`, `test`, `e2e`, after each change. One new test in
`test/core.test.mjs` pins the diagnostic paths, the RFC 6901 escaping, the undeclared-key
redaction, the anyOf suppression, the never-echo-a-value invariant, and determinism across key
insertion order.

## What this does and does not claim

Diagnostics are now actionable, which is a real and reproducible improvement on the sweep — 10/10
twice, both traps declined. It did not fix the reference-emission failure, and did not enable
self-correction for it. The sweep is twelve prompts against one local 27B model: reproducible
across two runs, but not a benchmark. The kernel was deliberately left unchanged on Concord's own
architectural argument, which means this round closes a diagnostic gap and leaves a capability gap
open.
