# Concord implementation rules

Use Node.js ESM and built-in modules only. Never execute downloaded source or install upstream hooks during source audit. Keep model/tool outputs untrusted. The deterministic core must not read the clock, randomness, ambient environment, network, or filesystem except through explicit effects and the optional journal sink. Canonical JSON rejects non-JSON values, unsafe object keys, and non-finite numbers. Replay never invokes a tool.

Public tool contract: `{name, version, effect, inputSchema, config?, execute}`. `effect` is `pure`, `read`, `write`, `network`, or `process`. `execute(input, context)` returns JSON; context has `workspaceRoot`, `policy`, `signal`, and an optional `onProgress`. `onProgress` is a display sink only: never recorded, never journalled, absent on replay, and therefore incapable of affecting determinism. Only what `execute` returns is evidence. Each non-pure effect is recorded. Write/network/process effects require an exact approval grant in addition to policy allowlisting. Tools must have no side effects at registration time.

Core API: `runPlan({plan, policy, registry, sourceLock, approvals, journalPath, workspaceRoot, signal?, onProgress?})` and `replayPlan({journal, plan, policy, registry, sourceLock, workspaceRoot})`. `signal` aborts the task in flight; the tool raises its own abort code, which is recorded through the existing failure path, so cancellation introduces no new event type and no new failure code. Registry is a Map keyed by descriptor name. Approvals are an array of request-hash strings. `sourceLock` is a JSON object. `src/value.mjs` exports `canonical`, `digest`, `validateSchema`, `HarnessError`.

Adapters belong in `src/integrations.mjs`. Export `makeIntegrationTools(config)` returning an array of descriptors. Every adapter executes only within its explicit descriptor call; enforce a timeout, output size bound, exact host allowlist from context.policy.allowedOrigins, no HTTP redirects, no shell. Do not inherit arbitrary environment variables. Never embed credentials or return authorization headers in logs/errors.

Source tools belong in `src/sources.mjs`. Export `loadSourceLock(path)` and `makeSourceTools(sourceLock)` returning descriptors. A source registry records upstream provenance; it does not mean the source's full runtime is installed. Skill imports are snapshots of text/data, never executable hooks.

Tests use node:test. Cross-platform CLI examples must work in PowerShell. Do not push, publish, or install global packages.

## Lessons

- 2026-10-15 — Build the unified chat harness from all supplied projects' features, tools, instructions and ideas; do not substitute a source catalog or DAG runner for the requested chat experience, and distinguish implemented capabilities from retained source references.
- 2026-10-15 — Select only Concord's own test files explicitly so source acquisition never executes vendored test suites; require fully qualified workspace identities before hashing approval requests.
- 2026-10-16 — Test artifact results through runPlan and replay as strict JSON, and constrain format reads to declared record regions as well as file bounds.
