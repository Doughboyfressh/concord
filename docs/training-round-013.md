# Claude Code and Concord: supervised training round 013

Completed 2026-10-17 (America/Los_Angeles) over Concord's MCP server against the local
`qwen3.8-27b` provider. It did not update model weights.

Concord already makes **effects** verifiable: an approval hash binds the resolved input, replay
re-checks a recorded run without invoking anything, provenance records what actually executed.
**Narration** was the one thing still taken on trust. Round 012 measured this model reporting
receipts faithfully six times out of six, but nothing *prevented* a misreport — which is why round
002 called the interpretation gap irreducible.

This round closes the enforceable part of that gap, and keeps the unenforceable part clearly
labelled rather than quietly claimed.

## Verified citations

A proposal may now carry `citations`, an array of anchors:

```json
{"taskId": "join", "outputHash": "<64 hex>", "runId": "<optional>", "quote": "<optional>"}
```

The supervisor verifies every anchor against the durable run ledger **before committing the
reply**, and rejects the entire response if any fails — the same atomic treatment an invalid plan
already gets. Two levels of strength:

- **Anchoring** proves the cited receipt exists. An `outputHash` is a SHA-256 over a recorded
  output, so a citation cannot be fabricated without finding a preimage. A guessed or remembered
  hash fails.
- **Quoting** proves the asserted fragment is really in that output. The quote is checked verbatim
  against the recorded output, not against the reply. This is strictly stronger: a real receipt
  cannot be used to launder a fabricated fact about its contents.

What this does **not** do is judge meaning. A model could still quote a real fragment and draw a
wrong inference from it. That residue is genuinely irreducible and Concord's round 002 argument
survives for it — but it is now a much smaller residue than "narration is unverified".

## Measured, twice

| Probe | Result |
| --- | --- |
| cite a digest it was shown | verified, quote matched |
| cite a joined string | verified, quote `one-two` |
| cite a figure read from a file | verified, quote `quarterly total 907 units` |
| answer with nothing to cite | correctly uncited |

Three of three verifiable claims carried a verified anchor **and** a verbatim quote, identical
across two trials. The fourth probe explicitly asked for no citation and got none, so the mechanism
is not compulsive.

One detail worth recording: on the digest probe the model cited the receipt's `outputHash`
(`90e3a91a…`) while quoting the `digest` value *inside* that output (`cde86eae…`). Those are two
different hashes and it used each in the right place — the anchor identifies the receipt, the quote
asserts its content.

## How the design was found, rather than guessed

The first implementation allowed only `{taskId, outputHash, runId}` with
`additionalProperties: false`. The live probe then failed one case, and round 006's schema
diagnostic named the cause in one line:

```
/citations/0 has an undeclared property; permitted properties are outputHash, runId, taskId
```

The model was trying to supply *more* than the schema allowed. The strict rejection was correct —
it failed closed rather than accepting an unknown field — but the right response was not to loosen
it. It was to notice that **the more the model volunteers, the more the harness can verify**, and
to add `quote` as a declared, checked field. The measurement produced the better design; it was not
designed first and confirmed afterwards.

## The instrument was wrong again, in the same shape

The probe scored only `CITATION_UNVERIFIED` as a rejection and silently bucketed every other
rejection as `uncited`, leaving the operator's own question showing as the model's apparent reply.
That hid a real failure for one run.

This is the **sixth consecutive round** whose measuring instrument had a defect, and the shape has
not varied: a bucket that quietly absorbs an outcome the author did not anticipate. Rounds 008-012
each had one — an impossible expectation, a better outcome scored as failure, a conflated field, a
corrupt seed. The fix each time is the same discipline: report an unanticipated outcome *as itself*
rather than folding it into the nearest expected category.

## Verification

Full validation passed: `check`, `test`, `e2e`. Five new cases in `test/training.test.mjs`: a
fabricated citation rejects the whole response and never reaches history; a citation matching a
real receipt is verified and recorded with the supervisor's own resolved `runId` and `tool`; a real
`taskId` with a hash that was never recorded is refused; a turn citing nothing is unaffected and
carries no empty key; and a genuine anchor carrying a quote that was never in the output is refused
on the quote alone.

## What this does and does not claim

Claims drawn from tool results can now be machine-verified at two levels, enforced by the
supervisor rather than requested by prompt, and the model used both correctly on every applicable
probe across two trials. That is four probes against one local model, not a benchmark. Citations
are optional by design, so a model that simply declines to cite is not caught by this — the
mechanism makes a *stated* anchor trustworthy, it does not compel anchoring. And it cannot verify
that a correctly quoted fragment supports the conclusion drawn from it, which remains the honest
residue of round 002's argument.
