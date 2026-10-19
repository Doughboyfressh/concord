# Capability training round

Exercises run: **15**. Lessons earned and promoted: **15**. Findings: **0**. Wall clock: **0.5s**. Stored lessons now: **34**.

Every lesson below came from a plan that ran through the real kernel, behaved exactly as predicted, and then replayed. A prediction that did not hold wrote nothing to memory and is listed as a finding instead: a surprise is something to investigate, not something to memorise.

## Earned

| Family | Tool | Lesson |
| --- | --- | --- |
| determinism | `json.hash` | json.hash hashes its entire input and, in a plan, that input IS the value: the {value: ...} wrapper exists only on the MCP surface, where a tool whose schema is not an object schema gets wrapped. A plan passing {value: X} hashes the wrapper, not X. Key order never matters either way, since canonicalisation happens first. |
| determinism | `json.assert` | json.assert returns a verdict carrying an evidence hash rather than a bare boolean, so a validation result can be cited later by that hash. |
| refusal | `json.assert` | A failing json.assert fails the task rather than returning passed:false, so a plan cannot continue past a violated invariant by ignoring a boolean. |
| sources | `sources.catalog` | sources.catalog reports 13 pinned upstream sources as inert provenance: listing a source is not a claim that its runtime is installed or that its tools exist here. |
| knowledge | `capabilities.search` | capabilities.search answers from an inert index and states grantsCapabilities:false on every reply: finding a capability is never the same as acquiring one. |
| ranking | `skills.rank` | skills.rank is lexical-overlap-v1, not semantic: it scores shared tokens, so a corpus entry matching on one common word can outrank a relevant entry that shares none. |
| governance | `hooks.evaluate` | hooks.evaluate returns the strictest matching decision, so an allow rule never cancels a deny that also matched. It reports a decision and enforces nothing. |
| delegation | `agent.delegate` | agent.delegate hands its sub-plan no approvals, so a write inside returns a recorded blocked event naming the tool rather than failing to compile or running on borrowed authority. |
| scheduling | `schedule.due` | schedule.due answers against a time the caller supplies, never a clock the kernel reads, which is what keeps a scheduling answer reproducible on replay. |
| memory | `memory.candidate` | memory.candidate is pure and yields only a content hash: nothing is remembered until memory.promote writes it under its own exact grant, so drafting a lesson costs no authority. |
| evidence | `artifact.inspect` | artifact.inspect identifies a file by magic bytes and reports its SHA-256, so a later claim about that file can be bound to the exact bytes that were read. |
| catalog | `rea.catalog` | rea.catalog reports all 117 REA tools with the realization route of each, keeping the difference visible between a reader Concord wrote and a bounded call to a reviewed binary. |
| foreign | `foreign.catalog` | foreign.catalog reports availableNow:0 until an operator both configures a server and allow-lists a tool: importing a capability manifest grants nothing by itself. |
| approval | `files.write` | A write blocks once with an exact request hash and runs only when that same hash is granted; the hash binds the resolved input, so an approval cannot be reused for a different write. |
| skills | `skills.install` | skills.install verifies a file against the digest the inventory recorded before copying it, so an adopted skill is provably the reviewed bytes rather than whatever happens to be on disk. |

## Findings

_None: every exercise behaved as predicted._

