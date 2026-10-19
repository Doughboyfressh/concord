# Capability training round

Exercises run: **38**. Lessons earned and promoted: **38**. Findings: **0**. Tools exercised: **27/79**. Wall clock: **1.6s**. Stored lessons now: **100**.

Instruction modules deepened: **4** (rea, ecc, hermes-agent, vercel-skills). Skill corpus verified against its index: **1330** files match, **0** drifted, **98** not in this workspace.

Every lesson below came from a plan that ran through the real kernel, behaved exactly as predicted, and then replayed. A prediction that did not hold wrote nothing to memory and is listed as a finding instead: a surprise is something to investigate, not something to memorise.

## Earned

| Family | Tool | Lesson |
| --- | --- | --- |
| determinism | `json.hash` | json.hash hashes its entire input and, in a plan, that input IS the value: the {value: ...} wrapper exists only on the MCP surface, where a tool whose schema is not an object schema gets wrapped. A plan passing {value: X} hashes the wrapper, not X. Key order never matters either way, because canonicalisation happens first. |
| determinism | `json.assert` | json.assert returns a verdict carrying an evidence hash rather than a bare boolean, so a validation result can be cited later by that hash. |
| refusal | `json.assert` | A failing json.assert fails the task rather than returning passed:false, so a plan cannot continue past a violated invariant by ignoring a boolean. |
| values | `json.value` | json.value returns its input unchanged after canonical validation, which makes it the way to pin a literal into a plan that later tasks can depend on. |
| values | `json.mergeShallow` | json.mergeShallow takes a values array and merges it as a disjoint union, not as a patch applied over a base: there is no last-writer-wins, which is why it needs no notion of order. |
| values | `text.concat` | text.concat is bounded at 1000 values of 65536 characters each, so building a string inside a plan cannot become an unbounded allocation. |
| sources | `sources.catalog` | sources.catalog reports 13 pinned upstream sources as inert provenance: listing a source is not a claim that its runtime is installed or that its tools exist here. |
| knowledge | `capabilities.search` | capabilities.search answers from an inert index and states grantsCapabilities:false on every reply: finding a capability is never the same as acquiring one. |
| ranking | `skills.rank` | skills.rank is lexical-overlap-v1, not semantic: it scores shared tokens, so a corpus entry matching on one common word can outrank a relevant entry sharing none. Near-duplicate entries therefore crowd the top of a result list. |
| catalog | `rea.catalog` | rea.catalog reports all 117 REA tools with the realization route of each, keeping visible the difference between a reader Concord wrote and a bounded call to an operator-reviewed binary. |
| foreign | `foreign.catalog` | foreign.catalog reports availableNow:0 until an operator both configures a server and allow-lists a tool: importing a capability manifest grants nothing by itself. |
| formats | `artifact.inspect` | artifact.inspect identifies zip from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read. |
| formats | `artifact.inspect` | artifact.inspect identifies png from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read. |
| formats | `artifact.inspect` | artifact.inspect identifies wasm from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read. |
| formats | `artifact.inspect` | A file named .png whose bytes are a zip is reported as a zip: artifact.inspect reads content, so a wrong extension cannot mislead anything downstream of it. |
| evidence | `artifact.inspect` | artifact.inspect binds every claim to a digest of the bytes it read, so a later statement about a file can be checked against the exact content that produced it. |
| readers | `artifact.sourceMap` | artifact.sourceMap decodes VLQ mappings field by field rather than trusting a library: only generatedColumn resets per line, so a decoder resetting the others would report plausible wrong origins. |
| readers | `artifact.harCapture` | artifact.harCapture reports a capture structurally and copies no headers, cookies or bodies out of it: a HAR is full of credentials, so the reader withholds them by construction rather than by redaction. |
| governance | `hooks.evaluate` | hooks.evaluate returns the strictest matching decision, so an allow rule never cancels a deny that also matched. It reports a decision and enforces nothing. |
| delegation | `agent.delegate` | agent.delegate hands its sub-plan no approvals, so a write inside returns a recorded blocked event naming the tool rather than failing to compile or running on borrowed authority. |
| scheduling | `schedule.due` | schedule.due answers against a time the caller supplies, never a clock the kernel reads, which is what keeps a scheduling answer reproducible on replay. |
| scheduling | `schedule.declare` | schedule.declare is a write and takes a grant like any other, and it stores the plan hash: re-declaring the same id replaces it, which is how a finished schedule is advanced. |
| judgment | `judgment.gate` | judgment.gate reports accepted rather than passed, and states grantsCapabilities:false on the way out: clearing a quality bar is a judgement about a score, never permission to do anything. |
| comparison | `experiment.compare` | experiment.compare is a hypothesis test across named conditions, not a diff. confirmed, refuted and untestable are arrays of condition names rather than booleans, so an untested condition can never read as a passing one. |
| comparison | `experiment.compare` | experiment.compare warns NONDISCRIMINATING_EXPECTATION and reports discriminating:false when every condition declares the same expectation: an experiment whose conditions all expect the same outcome cannot distinguish the factor it varied from one that would pass regardless, so a green result there proves nothing. |
| memory | `memory.candidate` | memory.candidate is pure and yields only a content hash: nothing is remembered until memory.promote writes it under its own exact grant, so drafting a lesson costs no authority. |
| memory | `memory.recall` | memory.recall is lexical, and it counts stored entries it could not parse rather than skipping them silently: a corrupted lesson is reported, not hidden. |
| exchange | `peer.inbox` | peer.inbox reports open questions without consuming them: reading never removes a letter, because a tool that quietly drained the mailbox would make a lost message look like one that was never sent. |
| skills | `skills.snapshot` | skills.snapshot reads one named file and requires both its path and its sourceId: it is a read of a specific reviewed artefact rather than a browse, so a snapshot always says which source it came from. |
| skills | `skills.installed` | skills.installed reads an empty store as empty rather than failing, and separates a changed local copy from a changed upstream so a local edit is never reported as an update. |
| approval | `files.write` | A write blocks once with an exact request hash and runs only when that same hash is granted; the hash binds the resolved input, so an approval can never be reused for a different write. |
| skills | `skills.install` | skills.install verifies a file against the digest the inventory recorded before copying it, so an adopted skill is provably the reviewed bytes rather than whatever happens to be on disk now. |
| refusal | `json.mergeShallow` | json.mergeShallow refuses a key appearing in two inputs with MERGE_COLLISION rather than letting one silently win. A merge that picks a winner hides the disagreement that made two values exist. |
| refusal | `files.read` | files.read refuses a path climbing out of the workspace with PATH_DENIED, checked segment by segment, so containment never depends on the caller having normalised anything. |
| refusal | `files.read` | An absolute path is refused as PATH_DENIED rather than read: only unambiguous relative workspace paths are accepted, which is what makes the workspace boundary mean anything. |
| refusal | `skills.install` | skills.install refuses an unknown id with SKILL_UNKNOWN, but only once the write is granted: the approval gate sits in front of the tool, so a write tool blocks before it can tell you the request was nonsense. Round 022 learned this by predicting the refusal and getting a block instead. |
| refusal | `schedule.declare` | schedule.declare refuses a time it cannot parse as an instant with SCHEDULE_TIME, because a schedule compared as text rather than as an instant would come due at the wrong moment. |
| refusal | `agent.delegate` | agent.delegate refuses an empty sub-plan with DELEGATE_PLAN rather than returning a vacuous success, so a delegation that would have done nothing is reported as the mistake it is. |

## Findings

_None: every exercise behaved as predicted._

