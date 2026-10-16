# Implementation slices

The user authorized a unified harness across twelve supplied references. Default implementation is a local Node.js supervisor with optional upstream processes, rather than merging competing agent loops. No provider or deployment account is required for the offline path.

| Slice | Files | Depends on |
| --- | --- | --- |
| Deterministic core, CLI, offline workflow | src/value.mjs, src/engine.mjs, src/builtins.mjs, src/cli.mjs, examples/, scripts/, test/core.test.mjs | Base contract |
| External transports | src/integrations.mjs, test/integrations.test.mjs, docs/adapters.md, examples/integrations.example.json | Base contract |
| Provenance and skill snapshots | src/sources.mjs, sources.lock.json, test/sources.test.mjs, docs/sources.md | Base contract, source audit |
| Adversarial verification | test/core.test.mjs, docs/review.md | All slices |
| Source-derived chat context | src/chat-context.mjs, instructions/, test/chat-context.test.mjs | All pinned source corpus |
| Chat session and action broker | src/chat.mjs, test/chat.test.mjs | Kernel, instruction context |
| Local chat interface | src/server.mjs, app/, test/server.test.mjs | Chat session and broker |

Determinism means stable DAG order and content-addressed inputs, policies, sources, tool declarations, implementation files, workspace identity, and recorded outputs. Live inference and external effects remain nondeterministic. Replays validate a hash chain and return the recorded result without tool execution. No unattended arbitrary shell, automatic source hooks, autonomous privilege escalation, or claim of binary-level sandboxing.

The primary product is a chat harness. It assembles reviewed instruction modules from every source, selects matching source skills and capabilities, proposes tool plans, exposes exact effect approvals, and keeps evidence/replay available directly in the chat. Offline mode must be clearly labeled a deterministic demonstration rather than live AI.
