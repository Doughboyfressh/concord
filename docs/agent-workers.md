# Delegated agent workers

`makeAgentTools` in `src/workers.mjs` registers a real DeepSeek Harness SDK process adapter. Registration performs no I/O. The adapter implements the upstream newline-delimited JSON-RPC lifecycle; its tests use a local Node protocol fixture. A real DSH installation, model provider, and authenticated live turn have **not** been tested here.

```js
import { makeAgentTools } from './src/workers.mjs';

const tools = makeAgentTools({
  dsh: {
    binary: 'C:/reviewed-dsh/dsh.exe',
    args: ['--profile', 'sdk'],
    home: 'C:/isolated-dsh-home',
    provider: 'deepseek-official',
    model: 'your-reviewed-model-id',
    reasoningEffort: 'max', // Optional; must be supported by that model.
    maxTokens: 4096,        // Optional conversation-model output cap.
    env: {},               // Explicit child environment; nothing is inherited.
  },
});
```

For a Node-distributed DSH executable, select the absolute Node binary and fixed arguments naming the reviewed DSH entrypoint followed by `--profile sdk`. Paths and argument arrays belong to adapter configuration, never task input. Configured arguments must not contain credentials. The caller provisions a compatible runtime and its profile beforehand; this adapter never downloads, installs, or updates upstream packages.

The descriptor is `dsh.run`, version `1.0.0`, with effect `process`. A task input is:

```json
{
  "prompt": "Inspect the project and report your findings.",
  "sessionId": "review-2026-10-15-001",
  "workdir": "."
}
```

`prompt` and `sessionId` are required. Session IDs start with an ASCII letter or digit, contain only letters, digits, `.`, `_`, and `-`, and are at most 128 characters. `workdir` is optional and resolves relative to `context.workspaceRoot`; its real path must remain inside that root. Select a new session identity and isolated home for independent work. Reusing homes exposes existing profiles, credentials, and persisted resources; this adapter does not clear or snapshot those resources, and the same session ID is not a fresh-state guarantee. There is no resume operation in this adapter.

## Protocol and evidence

The implementation follows the audited DSH revision `86a402200d95fecef4529d969836f1fe13c6cb0d`:

1. Spawn the absolute configured binary with fixed argv, no shell, and an explicitly constructed environment. `DSH_HOME` comes from the absolute configured `home`.
2. Send `initialize` with `cwd`, `provider`, `model`, and optional `reasoningEffort` and `maxTokens`. Require the wire-stable server name `deepseek-harness-sdk-runtime`.
3. Send `session/prompt` with `sessionId` and `contentBlocks: [{type: "text", text: prompt}]`; require its `messageId` receipt.
4. Send `session/wait` for that session. Collect `session.event`, `session.status`, `subagent.started`, and `subagent.finished` notifications.
5. Send `shutdown`, close stdin, and require successful direct-child exit before returning evidence.

The result contains the protocol transcript, notifications, prompt receipt, server identity, workspace, output byte counts, stderr digest, and successful exit status. The receipt identifies queued input. Upstream `session/wait` waits for root idle and progressing managed descendants; a notification or assistant message is not independently proven to be the causal answer to that prompt. The SDK emits events for every session in its runtime, so use an isolated worker home and profile when those events must be private to one run.

Configured environment values are bound into the descriptor through a hash, not included as plaintext in the public descriptor. Caller mutation after registration cannot change the captured configuration. Common Node, Python, loader, and shell injection environment variables are rejected, including `LD_AUDIT`. This filter is an accidental-injection guard, not an OS security boundary. No arbitrary parent environment is copied, including PATH and credentials. Supply any necessary benign runtime variables explicitly. Credentials may be supplied explicitly through environment variables when required; they remain accessible to the child. Values whose names identify secrets and common authorization/cookie fields are redacted in returned evidence, including secrets echoed as object keys. A key collision after redaction rejects the result. Stderr and runtime error messages are never returned as text. This is not a guarantee that arbitrary worker-produced content cannot disclose other secrets it can access.

Fixed adapter and JSON-RPC envelope keys, protocol method identifiers, and digest/count metadata retain their defined shape. Keys inside untrusted payload objects may change during redaction; treat those payloads as sanitized evidence. `transcriptHash` commits to the original parsed messages before redaction; therefore it may differ from a hash of the returned redacted transcript. `stderrSha256` commits to raw stderr bytes. These digests are evidence commitments, not proof that a worker's reported external actions occurred.

## Bounds and authority

Concord's policy must allow `process` and `dsh.run`, and the kernel requires the exact request-hash approval for execution. The descriptor binds binary path, fixed args, home, provider/model choices, and explicit environment identity. A path binding does not authenticate executable bytes or profile/plugin contents; pin and verify the external runtime and its home with the source/provenance workflow before use.

`context.policy.timeoutMs` bounds the entire invocation, including initialization and shutdown. `maxOutputBytes` bounds combined stdout/stderr and the returned evidence. Invalid JSON, duplicate keys, invalid UTF-8, unexpected response IDs, unknown notifications, server-initiated requests, malformed lifecycle results, and unsuccessful process exits fail closed. The implementation makes no automatic retries. Repeating a failed invocation may repeat already completed worker effects.

Abort and timeout request direct-child termination and wait for observed closure, with a bounded fallback that releases owned transport handles and reports unconfirmed closure. **This does not contain or prove termination of descendant processes, remote jobs, or daemon-owned work.** DSH has no SDK cancel/session-close method at the audited revision. Worker-internal filesystem, network, process, learning, and plugin actions are delegated under the approved `process` effect; they do not pass through Concord's individual tool/origin allowlists. Confinement requires a separately enforced OS/container/VM boundary. Restrict the profile to reviewed capabilities, and do not rely on either harness as the sole sandbox.

Offline Concord replay validates the recorded worker result without launching the worker. Live model output and external worker state are not deterministic. The deterministic contract applies to Concord orchestration and replay of captured evidence.

## Hermes boundary

Hermes is not registered by this module. Its current ACP entrypoint is a viewer while the gateway daemon owns MCP and execution, so killing an ACP client cannot establish cancellation of its effects. A truthful Hermes integration needs a separately tested ACP adapter and explicit daemon ownership/lifecycle policy. Listing a pinned Hermes source in the source registry does not install that runtime.

## Primary references

- [DSH SDK wire types](https://github.com/deepseek-ai/deepseek-harness/blob/86a402200d95fecef4529d969836f1fe13c6cb0d/packages/sdk/protocol/src/types.ts)
- [DSH protocol semantics and limitations](https://github.com/deepseek-ai/deepseek-harness/blob/86a402200d95fecef4529d969836f1fe13c6cb0d/packages/sdk/protocol/README.md)
- [DSH Python SDK: explicit home and profile launch](https://github.com/deepseek-ai/deepseek-harness/blob/86a402200d95fecef4529d969836f1fe13c6cb0d/python/sdk/README.md)
- [Hermes ACP ownership comments](https://github.com/NousResearch/hermes-agent/blob/4e59ac2b883b4133ea8a2d299abac45189781c09/acp_adapter/entry.py)
