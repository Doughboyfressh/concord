# Task-level recursion over plans

`src/variant.mjs` registers two tools, `variant.contrast` (`read`) and `variant.select` (`pure`).
Together they do what Harness² ([arXiv:2610.14224](https://arxiv.org/abs/2610.14224)) calls
propose / probe / compose: run a reference, run variants of it, contrast what was recorded, and
decide — with the part that cannot sit on this kernel removed, and the part this kernel can do
better than the paper made mechanical.

## What was removed, and why it had to be

Harness² freezes the model and optimises the harness, editing eight component files mid-task:
system prompt, guardrails, memory, tool guidance, subagents, skills, scripts, plugins. That is the
right instinct and the wrong substrate here, because every one of those is something `compile()`
hashes into a run's identity:

| Harness² component | what it is here | what it is hashed into |
| --- | --- | --- |
| guardrails | the normalized policy | `policyHash` |
| scripts, plugins | a descriptor's `config` | `registryHash` |
| system prompt | an instruction module pinned in `sources.lock.json` | `sourceHash` |

`approvalRequest` binds all of them, and `replayPlan` asserts the recorded identity still matches.
So a harness that rewrites its own configuration mid-run invalidates the grant it is holding and
makes the run unreplayable. There is no clever way around that: it is the guarantee, not a
limitation of the implementation.

What varies here is therefore the **plan**, which the kernel already treats as data, already
records event by event, and already replays one run at a time. Candidate plans execute through the
ordinary path — `runPlan`, the same registry, the same approval gate — so each candidate is an
independently replayable run before anything compares them. Nothing in this module executes a
plan, mutates a registry, or writes a file.

## The confound the kernel removes

Harness² probes candidates under "the same model and environment" and compares behaviour to the
reference. It cannot prove that is what happened; it arranges for it and proceeds.

A run's header here pins `policyHash`, `registryHash`, `sourceHash` and `workspaceRoot` by digest,
so `comparable` on each candidate is a **proof** that nothing but the plan differed. When something
else did move, the contrast names which digest — a differing `registryHash` means the tools changed
under the experiment, a differing `policyHash` means the authority did. `planHash` is excluded from
that check, because it is the thing required to differ; a candidate whose plan hashes the same as
the reference is reported with `variant: false`, since two runs of one plan measure run-to-run
variation rather than a variant.

Approvals are excluded too, and that is not an oversight: an approval hash binds the plan, so two
different plans never share one and comparing the hashes would reject every real variant. What is
comparable is how much authority each run actually *spent*, which travels as `grantsUsed` — the
number of `intent` events whose `requestHash` appears in the run's approvals, so a gated effect
that really executed under grant counts and nothing else does.

Counting `header.approvals` instead is wrong, and wrong in a way that only showed up in a live run:
that set is the session's accumulated grants and only ever grows, so every later run looks more
authorised than every earlier one. A pure two-task reference recorded 1 and a pure one-task
candidate recorded 2 because an unrelated model call had been approved in between, and the
`UNEQUAL_AUTHORITY` refusal then fired on a contrast between two plans that had exercised no
authority at all. `test/variant.test.mjs` pins the corrected reading.

## `variant.contrast`

Input is `{reference, candidates}` — run ids from the session ledger, at most six candidates.
Output is, per candidate, `comparable`, `variant`, the trajectory, the deliverable, the failure,
`authorityDelta`, and `differences`: a list of `{field, reference, candidate}` over a fixed table of
measured fields. Counts come from the journal's own events rather than from the plan, because only
an `intent` proves a tool was invoked and only a `completed` proves an output was recorded — a plan
lists what was asked for, which is the number that makes a call-count metric ambiguous.

The deliverable is content-addressed and task-id independent, which is the only way two *different*
plans can be asked whether they produced the same thing: their task ids do not correspond, their
output hashes do. Two fields, because they answer different questions. `digest` covers every
recorded output, so it matches only when the runs did the same work. `terminalHash` is the last
output actually recorded, and is the one that can show a leaner plan reaching the same answer — a
three-step plan and a one-step plan that end holding the same value differ in `digest` and agree in
`terminalHash`, which is the finding worth having. It is the last *completed* task rather than a
declared deliverable: with independent branches the kernel orders ready tasks alphabetically, so it
is an honest reading of what the run ended up holding, not a claim about which task mattered.

Warnings follow `experiment.compare`'s posture: per condition, never an aggregate. `SINGLE_CANDIDATE`,
`NOT_A_VARIANT`, `NO_BEHAVIOURAL_DIFFERENCE`, `INCOMPARABLE_RUN`, `UNEQUAL_AUTHORITY`, `INCOMPLETE_RUN`,
`UNKNOWN_RUN`, `REFERENCE_AS_CANDIDATE`, and `SHARED_FAILURE`. An id that names nothing comes back in
`missing` rather than failing the call, the way `conversation.turn` handles one. A contrast that would
exceed its byte bound fails closed with `CONTRAST_TOO_LARGE` rather than returning half a comparison.

## `variant.plan` — the propose half

Input is `{runId}`; output is that run's plan **verbatim**, plus `shape` (every task's id, tool and
dependencies), plus the run's summary so one call answers both what the plan was and how it went.
A plan too large for the byte bound is withheld entire with `oversized: true` — `shape` still names
every task, because the topology is what a variant varies and it stays small when the inputs do not.
A run id the store does not know comes back `found: false` rather than throwing.

It has to be a tool, and the reason is specific. A turn's user payload does carry `proposal`, but
`src/chat.mjs` overwrites it on every turn and nulls it when a proposal is rejected. So by the time
a model is asked to vary the plan it just ran, that plan has already been replaced by whatever the
current turn proposed. Asking it to vary "the plan from earlier" therefore asks it to work from
whatever survived compaction as prose — which is how a harness proposes a variant of a plan that
never existed. Addressed by run id against the recorded ledger, it is varying the thing that ran.

The plan store is separate from the summary ledger because the two are read for different reasons
and bounded differently: a summary is compared and digested, a plan is fetched whole. The tool is
registered only where a plan store is supplied, the way an adapter is registered only when its
configuration exists.

What this does *not* do is generate the variant. The model does that, exactly as Harness²'s editor
model writes its candidates — the kernel supplies the evidence, the model supplies the idea, and the
supervisor validates the result before it can become a proposal. A full cycle is therefore four
turns: run the reference, fetch its plan, propose and run the variant, contrast and select.

## `variant.select`

Input is a contrast, an ordered `prefer` list over `completed`, `fewerToolCalls`, `fewerTasks`, and an
optional `tolerance`. Criteria are compared lexicographically, so a later one speaks only where every
earlier one tied, and a numeric difference within the declared tolerance is a tie rather than a win.

Three outcomes, two of which decline:

- **`adopt`** — exactly one candidate strictly beat the reference and every other improver.
- **`keep`** — nothing beat the reference by more than the tolerance. This is Harness²'s fourth
  composition option, and the one its paper never reports a rate for. It is a decision, not a
  failure to decide.
- **`undecided`** — the evidence does not support naming a winner, with the reason in `declined`.

### Why it refuses

Harness²'s appendix is the argument for every refusal below. It reports nine regressions, one of them
selecting a candidate scoring 55 over one scoring 95, and premises that were wrong in the reference
propagating into every candidate at a cost of 2 to 11 points. Both have the same shape: a model
composer free-forming a judgement over evidence that did not actually separate the candidates.

- `COMMON_MODE_FAILURE` — every run failed the same way, so the contrast between them carries no
  information about the variants however large it looks. This is the propagating-premise failure
  stated mechanically.
- `INCOMPARABLE` — a candidate ran under a different harness identity. Deciding on the rest would be
  a confident answer that silently excluded a candidate which might have been the best one.
- `NOT_A_VARIANT` — a candidate ran the reference's own plan, so the set measures variability.
- `INCOMPLETE_RUN` — a run stopped at the approval gate. Worth its own refusal because a blocked run
  emits no `intent` at all, so its call count is zero and it beats every real run on any cost
  criterion. Adopting it would be adopting the plan that did nothing.
- `UNEQUAL_AUTHORITY` — a winner held more grants than the reference, so the win may be the grant
  rather than the plan. Checked after the comparison, not instead of it.
- `TIE` — never broken. A deterministic tiebreak would be reproducible and still arbitrary, and an
  arbitrary pick presented as a decision is the 55-over-95 failure exactly.

### The structural guarantee

An `adopt` carries `because`, taken **verbatim** from the contrast's own `differences`, plus the
`contrastHash` of the evidence it was computed from — the way `judgment.gate` pins a verdict to its
evidence. `assertGrounded` throws `SELECTION_UNGROUNDED` if a criterion decided on a field the
contrast never observed a difference in. So "rest each choice on a concrete observation" is enforced
by construction rather than asked for in a prompt: a reason this tool cannot produce is a reason it
cannot give.

## What this does not do

It contrasts what was recorded. It consults no ground truth, and a candidate that differs is
different rather than better — the same limit Harness² states for its own probe, and the reason the
refusals above exist instead of a score. An identical deliverable digest means the recorded outputs
hashed the same, not that the task was accomplished. `adopt` says a plan did better on the declared
criteria in these runs; it does not say the plan is correct.

Cost is the paper's other honest caveat and it applies here unchanged: a reference plus two
candidates is three executions of the same task before anything is decided. Running them in
parallel would cut latency, not compute.

## The ledger, and why it is a closure

`variant.contrast` reads the session's run ledger through a `readRuns` reference rather than through
its own `config`, for the reason `conversation.turn` takes the transcript that way.
`registryManifest` hashes every descriptor's config into the registry digest that binds every
approval hash and every replay check, so a config carrying the ledger would change each time a run
was recorded, invalidating the previous run's grants and making recorded runs unreplayable. The
config declares only what is stable, and `test/variant.test.mjs` asserts the digest holds still
while the ledger moves.

The ledger holds bounded summaries rather than second copies of journals — a summary is a few
hundred bytes against a journal's budget of megabytes. `src/app.mjs` appends one in `persistRun`,
before the file write rather than after it, because the run happened whether or not persisting it
succeeded and a contrast over a subset of what executed would be worse than none.

One property of this kernel is worth stating because it surprised the tests that found it: a run id
is `digest(journal)`, so two runs of the same plan over `pure` tools produce a byte-identical journal
and therefore the same id. They are not two ledger entries that happen to agree — they are one
entry. Run-to-run variation in that case is not rare, it is unrepresentable, and producing it at all
takes a tool that declares a non-`pure` effect.
