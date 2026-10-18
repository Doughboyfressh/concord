# Claude Code and Concord: supervised training round 016

Completed 2026-10-17 (America/Los_Angeles). It did not update model weights.

Round 015 built self-distillation and recorded three limitations. This round closes all three,
including the one it had deferred on principle — the deferral turned out to be a question of
granularity rather than a genuine conflict.

## 1. It learned only from failures

Self-distillation produced a lesson for every rejection and failure and nothing for success. Round
008 had established by hand that a *working topology* — which tools in which order, joined by which
reference shapes — is exactly the transferable fact, and nothing captured it.

A completed run now distils its own lesson naming the tool sequence, how many tasks consumed an
earlier result by reference, and the reference paths used:

> "A 2-task composition completed: files.read then text.concat. 1 task consumed an earlier result
> by reference using "/text". Principle: this topology and these reference paths are known to work,
> so reuse them for a request of the same shape rather than deriving them again."

Two filters keep it meaningful. Single-task runs are skipped, because one tool in isolation is not
a composition. The harness's own infrastructure plans — `live-proposal`, `memory-enrichment`,
`skill-enrichment`, `offline-demo` — are excluded, because they run every turn and teach nothing
about the work that was asked for. Without that filter every turn would mint a lesson about
`model.propose`.

## 2. It was precise but not insightful

A lesson named a cause without explaining the rule behind it. Two additions change that, and they
are different in kind.

**A principle table.** `PRINCIPLES` maps fifteen observed conditions to the generalizable rule
behind each, drawn from what rounds 002-015 actually measured: `INVALID_REFERENCE` to the reference
form and path discipline, `PLAN_UNEXECUTABLE` to one approval per plan, `OUTPUT_REJECTED` to the
effect having occurred, `OUTPUT_LIMIT` to a bound rather than a defect, and so on. This is the
honest form of knowledge transfer discussed in round 015: a finite, reviewable mapping rather than
prose, encoded where it keeps working.

**Recurrence counting.** A lesson now says *how many times this cause has appeared*:

> "This is occurrence 2 of this cause in this session, so the correction has not held; treat it as
> a pattern rather than an incident."

That is insight no human-written lesson can carry, because it depends on session state only the
harness holds. An incident and a pattern call for different responses, and distinguishing them is
the thing a mechanical composer can do better than a person writing in advance.

## 3. The deferred weakness: a thrown tool recorded no cause

Round 015 produced "no diagnostic was recorded" for every thrown tool, because the engine kept only
the outer category — `TOOL_FAILED` or `EFFECT_INDETERMINATE`. Round 010 had added `reason` for
`INPUT_INVALID` and `OUTPUT_REJECTED`, not for a throw.

It was deferred because a tool's thrown **message** is written by the tool author and can
interpolate caller data — this project's own `CITATION_UNVERIFIED` message interpolates a taskId and
a hash fragment. Surfacing messages would have reopened the channel round 006 closed.

The resolution is **granularity, not refusal**. A tool's error **code** is a closed-vocabulary
identifier chosen by the author; it cannot carry caller data. All 44 codes in the project were
enumerated to confirm this. The engine now records `toolCode` on a failed event, so:

```
Observed TOOL_FAILED / SCHEMA_MISMATCH on json.assert (task "check"). The tool raised SCHEMA_MISMATCH.
```

Three properties make it safe and durable:

- **Absence is diagnostic.** An unhandled exception records no `toolCode`, which distinguishes a
  tool reporting a condition it anticipated from one that crashed.
- **Replay verifies the shape.** The recorded failure's permitted key set is now computed from the
  optional fields actually present rather than enumerated, and `toolCode` must match
  `^[A-Z][A-Z0-9_]*$`. A journal rehashed to carry free text in that field is refused with
  `REPLAY_TRANSITION`, so the field cannot become a smuggling channel after the fact.
- **The message is still discarded.** Tested explicitly: a tool raising
  `HarnessError('MERGE_COLLISION', 'a message that is deliberately not recorded')` records the code
  and not the message.

## Verification

Full validation passed: `check`, `test`, `e2e`. One new case in `test/core.test.mjs` covers the
tool-code path at all three levels — a raised code recorded, an unhandled crash recording none, and
a forged non-identifier refused by replay. Two in `test/training.test.mjs` cover the principle and
recurrence on a repeated failure, and a success lesson naming its topology and reference path while
infrastructure plans produce none.

All three were also checked live through the MCP server rather than only by test.

## What this does and does not claim

The three asymmetries round 015 recorded are closed: the harness learns from success as well as
failure, states the principle behind a cause and whether it is recurring, and names the condition a
thrown tool actually hit. The privacy concern that deferred the third was resolved by narrowing
what is surfaced, not by overriding it.

What remains honest: a success lesson records that a topology *worked*, not that it was the best
available approach. The principle table is curated, so a condition absent from it yields a lesson
without a principle — fifteen entries cover the codes these rounds measured, not all forty-four.
And recurrence counts within a session only, because the candidate list is bounded and not
persisted, so a pattern spanning sessions is still invisible.
