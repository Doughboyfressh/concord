# Implementation slices

The user authorized a unified harness across twelve supplied references. Default implementation is a local Node.js supervisor with optional upstream processes, rather than merging competing agent loops. No provider or deployment account is required for the offline path.

| Slice | Files | Depends on |
| --- | --- | --- |
| Deterministic core, CLI, offline workflow | src/value.mjs, src/engine.mjs, src/builtins.mjs, src/cli.mjs, examples/, scripts/, test/core.test.mjs | Base contract |
| External transports | src/integrations.mjs, test/integrations.test.mjs, docs/adapters.md, examples/integrations.example.json | Base contract |
| Provenance and skill snapshots | src/sources.mjs, sources.lock.json, test/sources.test.mjs, docs/sources.md | Base contract, source audit |
| Adversarial verification | test/adversarial.test.mjs, docs/review.md | All slices |

Determinism means stable DAG order and content-addressed inputs, policies, sources, tool declarations, implementation files, workspace identity, and recorded outputs. Live inference and external effects remain nondeterministic. Replays validate a hash chain and return the recorded result without tool execution. No unattended arbitrary shell, automatic source hooks, autonomous privilege escalation, or claim of binary-level sandboxing.
