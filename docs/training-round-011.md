# Claude Code and Concord: supervised training round 011

Completed 2026-10-17 (America/Los_Angeles). It did not update model weights, and could not have.

Rounds 001-010 each fixed a behaviour. This round is about the **channel**: the operator asked for
all of the assisting model's knowledge to be transferred into Concord. Most of that request cannot
be satisfied, and the part that can was being throttled by a one-line bug.

## What is not possible, stated once

Weights cannot be transferred. The assisting model has no introspective read access to its own
parameters, and parameters from one architecture are meaningless in another — they cannot be loaded
into a 27B Qwen with different dimensions. The real technique that does move capability between
models is distillation, which means generating training pairs and **fine-tuning the student's
weights**; that needs a training stack this project deliberately does not have (Node built-ins,
zero dependencies, ever) and would produce a slightly better Qwen rather than a different model.

This project's own evidence already shows volume was never the variable. Rounds 004-006 had the
model holding the right information and failing five times; round 007 fixed it with one sentence
aimed at the real cause. Knowledge in context is not capability.

## The throttle, and the fix

`fetchMemoryExcerpt` requested `limit: 3` from `memory.recall` and then kept `results[0]`,
discarding two matches it had already scored and paid for. **One lesson per turn** was a hard
ceiling on how much learned knowledge could reach the model, for no benefit.

It now keeps several scoring matches, bounded by bytes rather than count — `MAX_RECALLED_LESSONS`
(6) and `MAX_MEMORY_EXCERPT_BYTES` (6000) — so the context cost stays fixed as the store grows,
matching every other bound in the harness. The primary match keeps its original field shape and is
always kept, so nothing that depended on it changed, and `related` is absent rather than empty when
there is only one match.

## Why bandwidth mattered more than expected

Retrieval is `lexical-overlap-v1`: literal term overlap, no embeddings. Measured against a labelled
query set over the real store:

| | top-1 correct | correct somewhere in the delivered set |
| --- | --- | --- |
| 10 entries | 7 / 10 | **10 / 10** |
| 17 entries | 7 / 10 | **10 / 10** |

The top keyword match is right about 70% of the time. Delivering six lessons instead of one
converts that into the right lesson arriving **every time** — the bandwidth increase compensates
for lexical retrieval's weakness rather than merely adding volume. One case shows why: "did you
actually inspect the archive, what did you find" shares almost no vocabulary with the
don't-cite-your-own-reply lesson, so it is never the top match, but it is reliably delivered.

Growing the store by 70% changed neither figure, so the channel scales rather than diluting.
Delivered payload measured 3,761 bytes against the 6,000 cap, with the full 7,230-byte store
correctly bounded away.

## What was transferred

Sixteen distilled lessons were promoted through the real gated path — `memory.candidate` (pure)
then `memory.promote` (write) with its own exact approval, one approval-requiring effect per plan,
honouring round 009's constraint. Promotion is content-addressed, so re-promoting an unchanged
lesson is idempotent rather than duplicating it.

Nine cover findings this series measured: reference form and paths, the single-approval rule,
failure-code semantics and retry safety, execution provenance, feasibility checking before
proposing, the `files.read`-returns-one-string limit, untrusted content, correctable rejections, and
what replay does and does not do. Seven cover the operating surface those rounds assumed but never
recorded: the native tool inventory, budget and limit codes, what `artifact.inspect` really
extracts per format, how to record a lesson, task ordering and dependencies, exactly what an
approval hash binds, and verification with `json.assert`.

Each is written deliberately keyword-dense in the vocabulary a relevant request would use, because
retrieval is lexical. That is a constraint of the mechanism, not style.

## The honest ceiling

Transferred knowledge arrives as `references.trust: "untrusted-data"`, by a round 001 decision. It
can inform Concord; it cannot command it. A knowledge transfer that arrives as untrusted reference
data is, correctly, not authority — and that is the right design even though it limits what any
transfer can do.

Ranked by this series' own measurements, what actually transfers, strongest first: **kernel guards**
(do not depend on the model complying at all), **structured environment data** such as `outputKeys`,
**diagnostics** that make a failure correctable, **contract rules** (effective only when aimed at
the real cause), and **recalled memory** (now several relevant lessons per turn). The durable
transfers are the ones that require the model to remember nothing, which is why rounds 009-010 put
guards in the kernel rather than instructions in the prompt.

## Verification

Full validation passed: `check`, `test`, `e2e`. Two new tests in `test/training.test.mjs` pin the
multi-lesson delivery: several scoring lessons arrive ordered by score within the byte bound, and a
single stored lesson still delivers exactly as before with no `related` key. Live checks read the
assembled prompt from the blocked `model.propose` input and confirm six lessons arriving
untruncated.

## What this does and does not claim

The channel is six times wider, measured, and its precision is unchanged by a 70% larger store.
Sixteen lessons of verified operational knowledge now reach the model on relevance instead of
sitting in `docs/` for humans. None of this is weight transfer, none of it is "all of a model's
knowledge", and none of it makes the local model more capable in general — it makes a specific,
measured body of knowledge about *this harness* available at the moment it is needed. The labelled
query set is ten cases written by the same party reading the results, so the precision figures
describe this store and these questions rather than retrieval in general.
