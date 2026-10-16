# External adapters

`makeIntegrationTools(config)` in `src/integrations.mjs` returns immutable tool descriptors for the deterministic kernel. Registration reads no credentials, starts no processes, and makes no network requests. Configuration becomes part of each descriptor's identity. The example in `examples/integrations.example.json` is a configuration template; it does not establish that any runtime or model is installed.

The kernel must authorize and record every network/process call, including its resolved input, descriptor configuration and approval grant. Calling `execute` directly bypasses kernel approval and journaling. Adapters enforce transport restrictions but are not an operating-system sandbox. A worker executable may itself access files, spawn descendants, or make network requests; use an external sandbox when those capabilities must be restricted.

## TypeSafe

Configure an exact `origin`, a versioned Jev `model` such as `jev-1.13.0`, and an `apiKeyEnv` containing the **name** of the credential environment variable. `jev-latest` and other aliases are refused. The default endpoint is `/v1/systemone`; a configured path must stay on the same origin.

Input is `{state, questions}`. State is a string, object or array. Supported question types are `noul`, `choice`, and `score`. The adapter POSTs `{model,state,questions}` and returns the parsed `{model,answers,...}` response. It verifies the returned model and answer types, closed choice options, distribution keys and probability bounds. Choice/Score confidence is a statistic supplied by the model, not proof of correctness. Score ranges from zero to `criteria.length - 1`.

The implementation uses Node's HTTP(S) libraries, with no SDK dependency. Its protocol and failure behavior have been tested against real local HTTP fixtures. No authenticated TypeSafe request was made. Remote availability, account access, billing and live model quality remain unverified. Official contracts: [HTTP API](https://docs.typesafe.ai/api), [models and aliases](https://docs.typesafe.ai/models), [Score semantics](https://docs.typesafe.ai/primitives/score).

## Model proposals

The optional `model` configuration uses the same origin, credential, timeout and output bounds. It implements the OpenAI-compatible chat-completions request shape at `/v1/chat/completions` or an explicit path. Input is `{prompt, system?}`. Requests set `temperature: 0` and `response_format: {type: 'json_object'}`. The first message content must contain one strict JSON object. The result is `{proposal,model,usage}`; no proposed command, plan or tool call is executed.

The caller must select an immutable provider model revision and validate the returned proposal as a plan before execution. A configured model string and temperature zero do not guarantee identical fresh inference. The endpoint may refuse this request format; provider-specific schemas and streaming are outside this adapter. Tests use a local compatible endpoint, with no provider account or model inference.

## JSON subprocess bridge

Each `workers` item supplies `name`, `version`, absolute `executable`, and fixed string `args`. Optional fields are a workspace-relative `cwd`, `env` containing explicit noncredential literal values, `allowedEnv` listing selected environment-variable names, `executableSha256`, `timeoutMs`, and `maxOutputBytes`. Omitted environment variables are not inherited. Credential-like literal environment names are refused; use explicitly named `allowedEnv` entries for credentials. Credential environment values are resolved only during execution and are not copied into descriptor configuration.

The executable must resolve to a regular file without symlink/path aliases. An optional SHA-256 digest is verified before launch. Prefer it when pinning deployed bridge binaries. The working directory is resolved and must stay inside the workspace. Shell execution is disabled, arguments cannot come from tool input, and windows are hidden on Windows.

The bridge receives exactly one UTF-8 JSON document followed by a newline on stdin, then EOF. It must exit successfully and write exactly one UTF-8 JSON document to stdout. Do not write log lines or protocol notifications to stdout. Stderr is drained and counted in the combined output bound, but its contents are not returned. Multiple JSON documents, duplicate keys, invalid UTF-8, unsafe JSON values, nonzero exit, timeout, cancellation, excessive output, missing executables and digest mismatches fail closed. Errors do not include raw process output or upstream HTTP bodies. HTTP results containing the configured API credential are refused; worker results containing credential-like named environment values are also refused. This catches known credential echoes, not every possible secret in arbitrary application data.

Example worker configuration (replace the paths and digest with reviewed local artifacts):

```json
{
  "workers": [{
    "name": "rea.bridge",
    "version": "bridge-revision-1",
    "executable": "C:/Program Files/nodejs/node.exe",
    "args": ["C:/reviewed/rea-bridge.mjs"],
    "cwd": ".",
    "env": {},
    "allowedEnv": [],
    "timeoutMs": 30000,
    "maxOutputBytes": 1048576
  }]
}
```

Hashing only the interpreter does not pin the bridge script or its dependencies. Their bytes must be included in your reviewed source lock and execution environment. Path and digest checks do not eliminate concurrent filesystem replacement races; enforce a stable, protected execution environment for production use. On timeout/cancellation the adapter kills its immediate child and closes its pipes. Descendant cleanup remains the bridge/runtime's responsibility.

## Generic process runner

`processes` items (sibling to `workers`) run `process.run`: a generic bounded local-command executor for any reviewed command, not the JSON subprocess bridge's one-document protocol. Configuration is identical to a worker's — `name`, `version`, absolute `executable`, fixed `args`, workspace-relative `cwd`, noncredential literal `env`, `allowedEnv`, `timeoutMs`, `maxOutputBytes` — with one difference: `executableSha256` is **mandatory** here, not optional, because this adapter accepts arbitrary reviewed commands rather than one pinned protocol binary. Task input is never read for argv; a plan cannot add or change arguments.

The child's stdout and stderr are captured separately and returned as `{exitCode, signal, stdout, stderr}`. Output must decode as strict UTF-8 or the call fails closed (`INTEGRATION_OUTPUT`) — there is no base64 fallback for binary output in this version. A nonzero exit or a signal termination is a distinct failure (`INTEGRATION_EXIT`), matching the worker bridge's posture. Never point `executable` at a path a `write`-effect tool in the same policy can also populate — two individually policy-correct tasks (write the file, then run it) can otherwise compose into arbitrary code execution; the mandatory digest pin only protects what's already on disk when the tool is configured, not what might be written later.

Credential-echo rejection checks environment values against both a name heuristic (`token`/`password`/`secret`/`api(_)key`) and a small set of credential-shaped value patterns (AWS access key IDs, PEM private key headers, JWTs, basic-auth-in-URL) — this catches common credential shapes landing under an unrelated variable name, but is still not a general secret scanner.

Example configuration (replace the path and digest with a reviewed local artifact; `executableSha256` is required, not optional):

```json
{
  "processes": [{
    "name": "process.run",
    "version": "1",
    "executable": "C:/Program Files/Git/usr/bin/grep.exe",
    "args": ["-c", "TODO"],
    "cwd": ".",
    "executableSha256": "REPLACE_WITH_THE_REVIEWED_BINARY_DIGEST",
    "timeoutMs": 10000,
    "maxOutputBytes": 1048576
  }]
}
```

## UI component registry

The optional `registry` configuration runs a UI component search client (21st-style) under the same `origin`/`apiKeyEnv`/`timeoutMs`/`maxOutputBytes` transport discipline as TypeSafe and the model adapter, minus a model ID (there is no model here). Input is `{query, limit?}`; the adapter POSTs `{query, limit}` to the configured path (default `/v1/components/search`) and validates the response as `{components: [{name, registryPath, dependencies?}]}` — not a bare passthrough. A response with more components than the requested limit, or any component missing `name`/`registryPath`, or a malformed `dependencies` array, is rejected (`INTEGRATION_OUTPUT`).

This is Concord's own defined contract, tested only against a local HTTP fixture. Real `21st.dev` wire compatibility is unverified — the live API's actual request/response shape has not been confirmed against this adapter.

## Policy and limits

`context.policy.allowedOrigins` must contain the exact normalized origin, including a nondefault port, for every HTTP call. Wildcards and origin prefixes are not accepted. Redirects are never followed. HTTP input is capped at 32 MiB, UTF-8 JSON is strict, response headers are capped at 16 KiB, TLS certificate verification remains enabled, and adapter requests use a fresh direct agent rather than a mutable global agent. HTTPS is appropriate for remote credentials; HTTP supports explicit local endpoints and test fixtures.

`timeoutMs` and `maxOutputBytes` default to 30,000 and 1,048,576 respectively. Positive policy values lower these bounds using the smaller value. Explicit `allowedTools` or `allowedEffects` arrays are checked again by adapters. Requests have no automatic retries. Abort signals stop active HTTP requests and workers. Policy and transport failures have stable `INTEGRATION_*` error codes, without authorization headers or echoed credential values in error messages.

## Integration coverage

| Upstream | Implemented and tested here | Remaining runtime boundary |
| --- | --- | --- |
| TypeSafe | Real bounded HTTP protocol using local fixtures; typed answers validated | Authenticated live API and model quality untested |
| Compatible chat model | Local HTTP request and strict JSON proposal response | Real inference, provider compatibility and immutable model availability untested |
| REA | Generic local JSON worker bridge transport, plus `artifact.inspect` (native, read-effect: magic-byte identification and bounds-checked ELF/PE header parsing) | Native REA `mcp` is JSON-RPC/MCP, not this worker protocol. A real MCP client/bridge must initialize, discover tools, preserve evidence contracts and manage sessions. No REA analysis engine was run; no disassembler or managed/JS/browser inspection path exists. |
| Orca | Generic local JSON worker bridge transport, plus `process.run` (native, process-effect: generic bounded command execution with a mandatory executable digest) | Orca CLI uses fixed subcommands and a running runtime. Orca's own worktree/terminal/desktop/mobile/SSH session model is not implemented; `process.run` covers the shared "execute a reviewed command" primitive only. |
| ego-lite | `browser.snapshot` (native, process-effect: launches a configured local Chrome/Chromium, drives it over raw CDP, extracts a bounded text snapshot) — verified against a real local browser, not just a fixture | One page open-and-extract capability. No click/type/multi-step scripting, shared logins, or persistent profiles. |
| Hermes | `memory.promote`/`memory.recall` (native, write/read-effect: persistent, content-addressed local memory store) | CLI/chat/session tooling needs a dedicated bridge and session lifecycle; no agent was run. Delegation, scheduling, and channels remain source corpus only. |
| DeepSeek Harness | Source/provenance belongs in the source catalog | ACP and persistent agent sessions require their actual handshake, messages, cancellation and lifecycle. They are not a one-document JSON subprocess call. No DSH/ACP integration is claimed. |
| 21st | `ui.components.search` (native, network-effect: Concord's own defined request/response contract with real schema enforcement) | Fixture-tested only; real 21st.dev wire compatibility unverified. |

Useful primary references: [REA MCP contracts](https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md), [REA installation/release boundaries](https://github.com/morluto/rea/blob/main/docs/installation.md), [Orca CLI](https://www.onorca.dev/docs/cli/overview), [Orca orchestration](https://www.onorca.dev/docs/cli/orchestration), and [TypeSafe's Hermes skill-selection example](https://docs.typesafe.ai/cookbooks/skill_suggestion).

Replay consumes the recorded tool result and never launches these transports. Identical replay is the deterministic guarantee; fresh external inference and runtime behavior remain external effects.
