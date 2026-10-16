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

Exact audited revisions and license boundaries are in [sources.lock.json](sources.lock.json). Original source trees and ZIP archives are under `upstream/` after you run `./scripts/acquire-upstreams.ps1` (see [source intake](docs/source-intake.md)); `upstream/` is git-ignored and is not part of a fresh clone, with acquisition metadata and per-file SHA-256 inventory written alongside it once acquired. Git history, Git LFS object payloads, submodule contents and linked external services are not part of GitHub source archives. Symbolic links are retained as inert text and disclosed in the manifest; original ZIPs retain their source representation.

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

`src/engine.mjs` owns compilation, execution and replay. `src/value.mjs` owns values/schemas. Builtins provide verification, skill ranking, memory candidates and file effects. Source tools snapshot inert skills. Capability tools search the inventory. Integrations and workers own external transports. On top of that kernel, `src/chat-context.mjs` assembles the twelve reviewed instruction modules each turn (see [source-derived instructions](docs/chat-instructions.md)), `src/chat.mjs` is the session broker that proposes, blocks, approves and replays (see [chat sessions](docs/chat-session.md)), `src/server.mjs` plus `app/` are the local HTTP interface (see [the local interface](docs/chat-ui.md)), and `src/mcp.mjs` is a third transport — a hand-rolled stdio [MCP server](docs/mcp.md) so external MCP clients can call Concord's tools, read its reviewed instructions as resources, and drive the same chat harness. [The architecture artifact](plans/concord/index.html) predates the chat layer and exports only the kernel/transport/source annotations below it; it has not been regenerated since.

Tests cover local HTTP, fixture subprocesses, policy/approval changes, tampered and rehashed traces, pointers, links, credentials, deadlines and output bounds. The test runner selects Concord's tests explicitly and never discovers tests in downloaded source trees. See [validation evidence](docs/validation.md).
