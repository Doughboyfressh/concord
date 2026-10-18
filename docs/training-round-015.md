# Claude Code and Concord: supervised training round 015

Completed 2026-10-17 (America/Los_Angeles). It did not update model weights.

The operator's request was to transfer an assisting model's knowledge into Concord, and pushed back
on the earlier framing — correctly. The objection was that a model obviously *can* access its own
knowledge, since it is using that knowledge to build this project.

That is right, and the earlier answer was evasive. The accurate statement is narrower: the
knowledge is not a file that can be enumerated and copied, but it is a **function** that answers
queries. The consequence is what matters. If knowledge is a function rather than a list, then the
transferable thing is not its answers but **the process that produces them** — and that process
can be built into the harness, where it keeps working without the assisting model present.

## What actually transferred across fourteen rounds

Not facts. Mechanisms:

| Round | Mechanism | Why it outlasts a conversation |
| --- | --- | --- |
| 002 | execution provenance | an unexecuted intention cannot read as performed work |
| 003, 006, 010 | diagnostics naming cause and location | a failure becomes correctable rather than reported |
| 005 | declared output shapes | a reference path can be derived rather than guessed |
| 009 | refusal of unexecutable plans | a provably impossible plan cannot half-execute |
| 013 | verified citations | a claim about a receipt is checked before it is committed |
| 014 | evidence provenance | a stored lesson is distinguishable from a sentence about one |

Each encodes a judgement into the system permanently. That is knowledge transfer into the harness
rather than into the weights, and round 011 measured the ranking: the further a mechanism sits from
"the model must remember something", the more durable it is.

## This round: the harness distils its own lessons

Rounds 002 through 014 each followed the same loop — measure a failure, read the diagnostic, derive
a lesson, encode it. Every input to that loop is now machine-readable, because rounds 003, 006 and
010 made the diagnostics structured. So the harness can run the loop itself.

On any rejected proposal or failed run, the supervisor now composes a **lesson candidate** from
recorded facts: the code, the reason code, the supervisor's own diagnostic, the failing tool and
task, and the run id. The text is written by the supervisor, never by the model, so a candidate is
a factual record of what happened rather than an assertion about it.

Three properties make this more than logging:

- **It is grounded.** The suggested evidence is the failing run's own `root` — a content-addressed
  commitment to the whole recorded run. `classifyEvidence` was extended to treat an evidence hash
  matching a known root as grounded, which is the only grounding available for a lesson about a
  failure, since a failed task has no completed output to cite. Promoting a candidate therefore
  produces a *grounded* lesson under round 014's check rather than prose about a failure.
- **It is never promoted automatically.** A candidate is a suggestion. Learned text becoming
  authority without review is the hazard this project has refused since round 001, and automatic
  self-promotion would be exactly that. Measured: twenty consecutive failures produced bounded
  candidates, no pending write, and no `memory.promote` in any receipt.
- **It covers failures nobody anticipated.** Fourteen rounds of lessons came from failures a human
  noticed. This produces one for any failure the harness can diagnose, including categories not yet
  imagined.

Live through the MCP server, a real failing plan produced:

> "Observed TOOL_FAILED on json.assert (task "check"): no diagnostic was recorded. Avoid repeating
> this by correcting the named cause before proposing again."

with `evidenceGrounded: true` and the resolving run id, reaching the public surface after
`lessonCandidates` was added to **both** allowlists — the partial-rollout hazard round 009's review
flagged, checked this time rather than discovered later.

## A weakness this exposed, left unfixed deliberately

"no diagnostic was recorded" is accurate and thin. A thrown tool produces `TOOL_FAILED` or
`EFFECT_INDETERMINATE`, and the engine records only the code: round 010 added `reason` for
`INPUT_INVALID` and `OUTPUT_REJECTED`, not for a throw. So `json.assert`'s own message — which
round 006 made genuinely informative — is discarded.

Surfacing it would improve every distilled lesson about a tool failure. It is **not** done here
because a thrown tool's message is written by the tool author and could echo input values, which
makes it a different decision from round 006's harness-authored literals, with a real privacy
dimension. That deserves its own round rather than being bundled into this one.

## The honest limits

Self-distillation produces lessons about *failures*. It does not distil what went right, and a
harness cannot tell that a successful run taught something worth keeping. It composes the text
mechanically, so a candidate is precise but not insightful — it names a cause, it does not explain
a principle the way a human-written lesson can. And the loop still needs an operator at the
promotion step by design, so this reduces the work of learning rather than removing it.

## Verification

Full validation passed: `check`, `test`, `e2e`. Three new cases in `test/training.test.mjs`: a
rejected proposal distils a candidate carrying the supervisor's diagnostic with grounded evidence
and the resolving run id; a failed run distils a candidate naming the tool and task that failed;
and twenty failures leave the candidate list bounded with no write offered and no promotion
executed.

The instrument was wrong a seventh consecutive time, in the same shape as the previous six. The
bounded-candidates test asserted on a filesystem path built from an unexposed `workspaceRoot`
defaulted to `'.'`, which silently pointed at the repository's real memory store and would have
passed for the wrong reason. It now asserts on what the snapshot actually exposes. The pattern is
unchanged across rounds 008-015: a fallback or bucket that quietly absorbs an unanticipated case.

## What this does and does not claim

The harness now runs, by itself, the loop that produced fourteen rounds of improvements — measure,
diagnose, derive, offer. That is a genuine transfer of *method* rather than content, and it is the
honest answer to transferring a model's knowledge: not the weights, not a list of facts, but the
procedure that turns experience into durable change. It does not make the local model more capable,
it does not learn without review, and it produces precise rather than insightful lessons.
