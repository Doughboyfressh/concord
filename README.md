# Concord

Concord is a local AI **chat harness** combining the supplied projects' features, tools, instructions and ideas under one execution contract: **context → chat → propose → validate → authorize → execute → verify → replay → propose memory**.

The new design is an evidence-bound plan. Models, structured judges, imported skills, browser observations, analysis tools and external agent workers all contribute data to an immutable task graph. The supervisor owns ordering, policy, approvals, postconditions and receipts. A model response cannot grant itself a capability or silently become an executable plan.

This is a working local foundation with pinned upstream source snapshots and a searchable feature inventory. It does **not** mean every upstream feature has already been ported or all ten runtimes run natively together. See [feature synthesis and implementation status](docs/architecture.md), [adapters](docs/adapters.md), and [agent workers](docs/agent-workers.md).

## Start the chat harness

Requires Node.js 22 or newer; tested with Node.js 24.20.0 on Windows. No npm dependencies, install scripts, provider account, or API key are needed offline.

From this directory in PowerShell:

```powershell
node scripts/chat.mjs
```

Open the printed localhost URL. The interface provides chat, selected source instructions/skills, available tools, proposed plans, exact effect approvals and run replay. It starts in a clearly labeled **offline deterministic demonstration** with actual source context and executable pure tool plans.

To use a live model, configure a compatible endpoint and immutable model revision in a reviewed integration file, set its named credential environment variable, and start:

```powershell
node scripts/chat.mjs --integrations examples/integrations.example.json --workspace C:/path/to/your/project
```

The example also contains TypeSafe configuration; remove unused sections rather than supplying credentials you do not need. Each model request first presents its exact network grant. A returned tool plan is displayed for separate execution; protected actions require their own grants. Read [chat sessions](docs/chat-session.md), [source-derived instructions](docs/chat-instructions.md), and [the local interface](docs/chat-ui.md).

Chat evidence and snapshots persist under the printed local store. This version does not automatically resume interrupted tool effects or reconstruct old sessions into a new process. Preserve local run evidence for audit/replay.

## Supervised improvement

Twenty supervised training rounds have turned live failures into context and supervisor fixes,
regression tests, and an evidence-linked memory: [round 001](docs/training-round-001.md) (tool schemas,
recall, receipts), [round 002](docs/training-round-002.md) (execution provenance, so an unexecuted
intention can never read as performed work; injection resistance then tested and passed), and [round
003](docs/training-round-003.md) (schema fidelity measured at nine of ten, with correctable
rejection diagnostics), and [round 004](docs/training-round-004.md) (task generalization, where plan
structure generalized but value propagation failed twice and the attempted fixes did not help), and [round 005](docs/training-round-005.md) (declared tool output shapes, verified against real
execution, which fixed one of those failures and turned the other from a silent wrong answer into
a rejection), and [round 006](docs/training-round-006.md) (schema rejections that name the failing
field and rule without echoing any value, measured at ten of ten on the round 003 sweep), and [round
007](docs/training-round-007.md), which corrects rounds 005 and 006: the repeated reference
failure was not a model limitation but one untargeted condition, an array mixing a literal with a
reference, fixed by a single contract sentence and verified end to end. [Round 008](docs/training-round-008.md)
is the first properly varied generalization measurement: eight conditions across reference
topology, data type and failure propagation, each executed and value-checked, eight of eight
correct across two runs after one further contract rule about reference paths. [Round 009](docs/training-round-009.md)
closed the write-effect gap and found that a plan needing two approvals could never complete yet
would half-execute first; such a plan is now refused before any effect, leaving the workspace
untouched. [Round 010](docs/training-round-010.md) narrowed EFFECT_INDETERMINATE in the kernel: a
failure after a tool returns is reported as OUTPUT_REJECTED, because the effect certainly occurred
and only its output was unusable, while a genuine throw mid-effect stays indeterminate. [Round 011](docs/training-round-011.md)
widened the knowledge channel itself: recall delivered one lesson per turn while already scoring
several, so it now delivers up to six within a byte bound, which raised the right-lesson-arrives
rate from 7/10 to 10/10, and sixteen distilled lessons were promoted into memory. [Round 012](docs/training-round-012.md)
measured the interpretation gap that round 002 called irreducible: six of six receipt-reporting
conditions were faithful across two trials, and the one imprecision found traced to memory.recall
returning a ranked list whose length is not a match count, now stated as matchedCount. [Round 013](docs/training-round-013.md)
closed the enforceable part of that gap: a reply may anchor a claim to a recorded task's output
hash, optionally with a verbatim quote, and the supervisor verifies every anchor against the run
ledger before committing the reply — so a fabricated digest, or a real receipt quoted falsely, is
refused rather than merely auditable. [Round 014](docs/training-round-014.md) applied the same
principle to memory: a lesson whose evidence came from a task reference has an evidence hash
identical to that task's recorded output hash, so the approval gate now says whether a lesson about
to be persisted is backed by recorded execution or only asserted. [Round
015](docs/training-round-015.md) made the harness distil its own lessons: a rejected proposal or
failed run now composes a lesson candidate from the supervisor's recorded diagnostic, grounded in
that run's own root, offered for review and never promoted automatically. [Round
016](docs/training-round-016.md) closed the three asymmetries that left open: a successful
composition now distils its own lesson naming the topology and reference paths that worked, every
lesson carries the principle behind its cause plus a recurrence count, and a thrown tool records
its own error code — an identifier, never its message, which keeps caller data out of the
diagnostic. [Round 017](docs/training-round-017.md) encoded the measurement method itself as a
capability: experiment.compare takes named conditions and reports a verdict per condition with no
aggregate score, flagging conditions that vary nothing, expectations that cannot discriminate, and
outcomes that were never testable — the exact instrument faults rounds 004 to 015 committed. [Round
018](docs/training-round-018.md) removed the hand-written probe as the limit on learning: the
composition matrix is now generated from each tool's declared inputSchema and outputKeys, and 629
compositions ran in 0.575 seconds, proving 170 topologies and finding a misclassification
seventeen hand-written rounds had missed — a failed read reported as a possibly-occurred effect,
when a read changes nothing and is always safe to repeat. [Round
019](docs/training-round-019.md) answered the two limits that left: every one of the 170 working
compositions resolves its reference to exactly the right value, checked against the kernel's own
inputHash commitment rather than approximated, and the model reproduced eight of eight sampled
compositions with the correct reference path — the first capability measurement in this series
whose targets were established by execution rather than written by the measurer. [Round
020](docs/training-round-020.md) chained those verified pairs into 400 three-task plans, every one of
which held, and then stopped naming tools at all: given only a goal, the model chose its own
composition and the value was checked against an independently computed answer. That found a
shorthand reference the kernel had been accepting as ordinary text — a wrong answer carrying a
faithful receipt — and localised every remaining failure to one position, a reference beside a
literal inside an array, where a position-specific diagnostic took the result to six of six. This improves harness behavior and
guidance; it does not retrain model weights. `scripts/train.mjs` provides an explicitly opt-in six-turn local
model exercise with exact network grants, a reviewed pure tool plan, and replay checks. See the report for
the command, observations and limits. Normal validation remains offline.

## Connect an MCP client

```powershell
node src/mcp.mjs --workspace C:/path/to/your/project
```

Any MCP client (Claude Code, Claude Desktop, or another MCP-speaking provider) can connect over stdio to
call Concord's tools directly, read its 12 reviewed source instructions as resources, and hold a chat
session through five `concord_*` tools backed by the same `createChatHarness` the HTTP interface uses. See
[the MCP server](docs/mcp.md) for the exact client configuration and how write/network/process approval
surfaces through a protocol with no native "pending" primitive.

## Verify the execution kernel

```powershell
node scripts/check.mjs
node scripts/test.mjs
node scripts/e2e.mjs
node src/cli.mjs validate examples/offline.plan.json --policy examples/offline.policy.json
node src/cli.mjs run examples/offline.plan.json --policy examples/offline.policy.json --out runs/demo.json --journal runs/demo.events.jsonl
node src/cli.mjs replay runs/demo.json --plan examples/offline.plan.json --policy examples/offline.policy.json
```

Outputs and journals use exclusive creation. Choose a new filename for each capture. Preserve the original plan, policy, source catalog, capability inventory, tool configuration, workspace identity, Node version and Concord code to replay an existing run.

The demo selects skills with deterministic scoring, checks a postcondition, proposes a memory item, and hashes the evidence. Replay invokes **zero tools**. To anchor integrity independently, save the printed terminal root elsewhere and pass `--root <sha256>` during replay.

## All supplied projects

| Source | Concord role |
| --- | --- |
| [ECC](https://github.com/affaan-m/ECC) | Engineering workflows, skills, hooks, reviews, evaluations and memory |
| [ego-lite](https://github.com/citrolabs/ego-lite) | Browser task spaces, observations and action receipts |
| [REA](https://github.com/morluto/rea) | Artifact inspection and normalized evidence |
| [21st source](https://github.com/serafimcloud/21st), [21st.dev](https://21st.dev/) | UI registry and component acquisition |
| [Vercel skills](https://github.com/vercel-labs/skills) | Skill discovery, provenance, imports and updates |
| [Orca](https://github.com/stablyai/orca) | Workspaces, workers, terminals, browser and review |
| [TypeSafe](https://docs.typesafe.ai/introduction) | Typed judgment observations and routing advice |
| [Hermes](https://github.com/NousResearch/hermes-agent) | Agent, memory, delegation, scheduling and channel concepts |
| [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) | Plugin composition, sessions, SDK workers and replay |
| [awesome-cyber-skills](https://github.com/joe-shenouda/awesome-cyber-skills) | Searchable security skill corpus |
| [Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking) | Categorized security references and labs |

Exact audited revisions and license boundaries are in [sources.lock.json](sources.lock.json). All 117 of REA's reverse-engineering tools are now internal Concord tools, compiled from a contract table generated out of the pinned clone: 49 realized by zero-dependency readers (all 49 written: SQLite checked against `node:sqlite`, .NET ECMA-335 metadata against a real Windows assembly, source maps against Node's own `SourceMap`, WASM interfaces against Node's `WebAssembly`, plus Android DEX and binary XML, pcap and packet fields, PE resources, Go and Rust metadata, Dart and Flutter builds, Electron fuses, Apple plists, HarmonyOS packages, ELF core dumps and the evidence-composition tools) and 68 by bounded calls to operator-reviewed binaries, where the argv shape is the operator's and only pattern-checked slot values come from a plan: see [taking REA's capabilities internally](docs/rea-internal.md). A hermes installation on this machine was additionally inventoried in place — 99 tool contracts and 98 skill corpora, by static analysis without running it, plus the per-turn least-authority attenuation its webhook-safe toolset models: see [taking the hermes capability surface](docs/hermes-local.md). Original source trees and ZIP archives are under `upstream/` after you run `./scripts/acquire-upstreams.ps1` (see [source intake](docs/source-intake.md)); `upstream/` is git-ignored and is not part of a fresh clone, with acquisition metadata and per-file SHA-256 inventory written alongside it once acquired. Git history, Git LFS object payloads, submodule contents and linked external services are not part of GitHub source archives. Symbolic links are retained as inert text and disclosed in the manifest; original ZIPs retain their source representation.

After acquisition, [capabilities.lock.json](capabilities.lock.json) indexes skills, agents, commands, plugins and documentation headings from every source tree. Entries are inert, unreviewed source material; search never executes them.

```powershell
node src/cli.mjs run examples/capabilities.plan.json --policy examples/capabilities.policy.json --out runs/features.json
```

## Effects and exact grants

Each tool declares a name, version, input schema, configuration and effect: `pure`, `read`, `write`, `network`, or `process`. Policy must allow both tool and effect. Write, network and process calls also need an exact request-hash grant binding the resolved input, plan, policy, source lock, tool registry and workspace.

```powershell
node src/cli.mjs run examples/write.plan.json --policy examples/write.policy.json --out runs/blocked.json
```

This exits 3 without writing the target. Inspect the blocked event's actual input and request hash. Put that hash in a JSON array, then rerun with `--approvals approvals.json` and a new `--out` filename. Concord does not create grants from model text. `files.write` creates files exclusively and never replaces an existing file.

## Live AI and tools

[examples/integrations.example.json](examples/integrations.example.json) configures TypeSafe, a compatible chat endpoint, and explicit process bridges. Replace placeholder models with pinned revisions and supply credentials through the configured environment variable names. Nothing loads `.env` automatically. [examples/model.plan.json](examples/model.plan.json) generates a candidate plan as data. Review the returned proposal, save it as a new plan, and validate it under a separate execution policy.

The DeepSeek SDK transport uses initialize → prompt → wait → shutdown; protocol fixtures test it without installing upstream code. Real runtime/provider operation remains unverified. Hermes ACP, ego host, REA MCP, Orca native workflows and 21st asset acquisition still require dedicated runtime bridges. Their source and integration contracts are available here. A generic JSON process bridge supports reviewed wrappers; it is not represented as native integration.

## Determinism contract

- Canonical JSON uses sorted keys and finite safe numbers, rejecting duplicate/unsafe keys, accessors and non-JSON objects.
- DAG scheduling uses fixed task-ID order, direct declared dependencies and explicit JSON pointers.
- Policy, tool declarations, configuration, sources, runtime code and outputs are hashed.
- Each call has an intent and receipt. `--journal` fsyncs them before proceeding. Output, time, task and journal budgets are bounded.
- Replay validates context, chain, approvals, reference resolution, output schemas and legal transitions without invoking tools.
- Fresh inference and live tool results can vary. Recorded replay is deterministic; temperature zero is not the guarantee.

Hashes need an independently trusted root to resist full-history rewriting. JavaScript adapters are trusted code. Effect declarations are contracts, not OS sandboxes; upstream workers may have broad internal capabilities. Cancellation cannot prove all descendants stopped. An effect without a committed receipt is indeterminate and must not be automatically retried. Replay verifies the recorded contract, not the truth of an external system.

API callers must provide a fully qualified canonical real workspace path and pin their executable dependency closure. The CLI resolves the real path and pins its source files and Node runtime. Portable file checks reduce alias/race risks but cannot confine a continuously malicious concurrent filesystem writer; use OS isolation for that scenario.

## Project map

`src/engine.mjs` owns compilation, execution and replay. `src/value.mjs` owns values/schemas. Builtins provide verification, skill ranking, memory candidates and file effects. Source tools snapshot inert skills. Capability tools search the inventory. Integrations and workers own external transports. On top of that kernel, `src/chat-context.mjs` assembles the thirteen reviewed instruction modules each turn (see [source-derived instructions](docs/chat-instructions.md)), `src/chat.mjs` is the session broker that proposes, blocks, approves and replays (see [chat sessions](docs/chat-session.md)), `src/server.mjs` plus `app/` are the local HTTP interface (see [the local interface](docs/chat-ui.md)), and `src/mcp.mjs` is a third transport — a hand-rolled stdio [MCP server](docs/mcp.md) so external MCP clients can call Concord's tools, read its reviewed instructions as resources, and drive the same chat harness. [The architecture artifact](plans/concord/index.html) predates the chat layer and exports only the kernel/transport/source annotations below it; it has not been regenerated since.

Tests cover local HTTP, fixture subprocesses, policy/approval changes, tampered and rehashed traces, pointers, links, credentials, deadlines and output bounds. The test runner selects Concord's tests explicitly and never discovers tests in downloaded source trees. See [validation evidence](docs/validation.md).
