# Claude Code and Concord: supervised training round 014

Completed 2026-10-17 (America/Los_Angeles). It did not update model weights. This round is a kernel
and supervisor change verified by test, applying round 013's principle — verify rather than trust —
to stored memory.

Round 011 promoted sixteen distilled lessons into Concord's memory. Every one of them carried
`evidence` of the form `[{trainingRound: 9, verifiedBy: "measurement against the live provider"}]`,
which is a sentence someone wrote. In an evidence-based memory system, a lesson backed by recorded
execution looked **identical** to a lesson backed by prose. That is a soundness hole, and round 011
created instances of it.

## The distinction was already provable

`memory.candidate` computes `evidenceHashes` as `digest()` over each evidence item. A `$task`
reference resolves to the referenced task's real output *before* the tool runs. So for grounded
evidence, `digest(evidence item) === digest(task output) === that task's recorded outputHash`.

Verified empirically before anything was built:

| Evidence | Evidence hash | Matches a recorded `outputHash` |
| --- | --- | --- |
| `[{$task: 'src'}]` | `30c84354e708e829…` | **yes**, identical to task `src` |
| `[{trainingRound: 9, verifiedBy: '…'}]` | `b3ea1e6258f499f7…` | no |

So grounding was already checkable from data the harness holds, and had simply never been
surfaced. No schema change was needed — only a check nobody had written.

## Surfaced where the decision is made

`classifyEvidence` matches a candidate's evidence hashes against the run ledger and reports
`{groundedCount, unverifiedHereCount, grounded: [{evidenceHash, runId, taskId}]}`.

It appears in two places, chosen because they are the two moments the information changes
something:

- **At the approval gate.** When a plan blocks on `memory.promote`, the pending approval now
  carries `evidenceProvenance`. An operator about to persist a lesson is told whether its evidence
  is recorded execution — and *which run and task* produced it — rather than being asked to grant a
  write over content they cannot assess.
- **On recall.** A lesson reaching the model carries its own `groundedCount` and
  `unverifiedHereCount`, so the model is told whether what it is reading is execution-backed
  instead of having to assume.

The promotion is still **offered** either way. Provenance informs the decision; it does not make
it. An operator may legitimately want to record a lesson with no run behind it, and refusing that
would be the harness substituting its judgement for the operator's.

## The label is "unverifiable here", not "fabricated"

An evidence item that matches nothing in this session's ledger may be genuine evidence from an
earlier session whose runs were never loaded into it. Calling that fabricated would be a claim the
harness cannot support.

This is the same discipline round 010 applied to `OUTPUT_REJECTED` versus `EFFECT_INDETERMINATE`:
say exactly what is known, and do not let a stronger-sounding word stand in for it.

It also means the honest reading of round 011's own sixteen lessons is `unverifiedHereCount: 1`
each, in any fresh session. They are not thereby false — they summarise rounds that genuinely
happened — but nothing in the store proves it, and the harness now says so rather than letting
them pass as evidence-backed.

## The limit this leaves, stated plainly

Grounding is verifiable only against **this session's** run ledger. The runs that produced a
lesson in an earlier session are not in it, so cross-session grounding cannot be checked. Closing
that needs recorded run roots persisted and loaded alongside the memory store — a real change, not
a line, and deliberately not bundled here.

Until then the mechanism is strongest exactly where it matters most: at the moment a lesson is
*being created*, when the run that justifies it is still in the ledger and the operator is being
asked to persist it.

## Verification

Full validation passed: `check`, `test`, `e2e`. Two new cases in `test/training.test.mjs`: a
promotion whose evidence came from a `$task` reference reports `groundedCount: 1` with the
resolving `runId` and `taskId`, and a promotion whose evidence is invented prose reports
`unverifiedHereCount: 1`, an empty `grounded` list, and is still offered for approval with a valid
request hash.

## What this does and does not claim

A lesson's evidence can now be distinguished from a sentence about a lesson, at the moment it is
persisted and again when it is recalled, using a property that was already true and already
checkable. It does not verify that a grounded lesson's *text* follows from its evidence — the same
residue round 013 left open, where a real receipt can still support a wrong inference. And it does
not retroactively validate the existing store: the sixteen lessons from round 011 are now correctly
labelled as unverifiable in a fresh session, which is the honest outcome rather than a convenient
one.
