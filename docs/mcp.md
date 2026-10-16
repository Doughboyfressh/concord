# MCP server

`src/mcp.mjs` is a third transport over the same kernel `src/cli.mjs` and `src/server.mjs`/`scripts/chat.mjs`
already use — a hand-rolled [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, with
zero npm dependencies, so an external MCP client (Claude Code, Claude Desktop, or any other MCP-speaking
provider) can call Concord's tools, read its reviewed source instructions, and hold a stateful chat session
with it. No existing Concord module changes to support this: the registry, policy, source lock, and chat
harness are assembled exactly as `scripts/chat.mjs` already does, and driven through the normal `runPlan`/
`createChatHarness` APIs.

## Start it

```powershell
node src/mcp.mjs --workspace C:/path/to/your/project
```

Or point an MCP client at it directly. For Claude Code/Claude Desktop-style config:

```json
{
  "mcpServers": {
    "concord": {
      "command": "node",
      "args": ["C:/path/to/concord/src/mcp.mjs", "--workspace", "C:/path/to/your/project"]
    }
  }
}
```

The same `--policy`, `--integrations`, `--workers`, and `--browser` flags `scripts/chat.mjs` accepts work
here too. Without `--policy`, the default is permissive — every registered tool, every effect — because the
policy allow-list and the exact request-hash grant (below) are independent gates; a permissive policy never
lets a write, network, or process effect skip its hash.

## Three kinds of MCP primitives

**Raw tool access.** Every policy-visible registered tool becomes one MCP tool. Dots in Concord's tool names
become underscores (`files.write` → `files_write`) because dotted names aren't safe across every client's
function-name validator; this mapping is asserted collision-free at server startup, not at first call. Two
tools (`json.value`, `json.hash`) accept any JSON value rather than an object, so their MCP-facing schema
wraps it: call them with `{"value": <anything>}`.

**The 12 reviewed instruction modules as resources.** `resources/list`/`resources/read` serve the same
digest-verified instruction text `src/chat-context.mjs` loads for every chat turn, built once at server
startup and cached — `chat-context.mjs` itself is unchanged. URIs are `concord://instructions/<sourceId>`.

**The chat harness as five tools.** `concord_chat`, `concord_approve`, `concord_execute_plan`,
`concord_replay`, and `concord_chat_state` mirror `src/server.mjs`'s four POST routes and one GET route,
one-for-one, over MCP instead of HTTP — the same `createChatHarness` instance, instruction-grounded and
evidence-recording, for the server's whole process lifetime. All five are serialized against each other (an
MCP client can legitimately fire concurrent calls from one model turn; the raw per-tool path has no shared
mutable state and isn't serialized).

## The `_confirm` round trip — how approval surfaces through MCP

MCP's `tools/call` has no native "pending approval" primitive: per the protocol's own spec, tool-call
confirmation is an application/client concern, not something the wire format provides. Concord's own
exact-grant model — an unapproved `write`/`network`/`process` effect never runs, no matter how permissive
the policy is — still has to hold across this transport, so it's bridged with a convention instead of a
protocol extension:

1. Call a gated tool (e.g. `files_write`) without `_confirm`. You get back a normal, successful result (not
   `isError`) stating the tool, effect, the resolved input, and a `requestHash`. Nothing has executed.
2. Call the *same* tool again with `_confirm` set to that exact `requestHash`. Only then does it execute.

**The plan wrapper around every raw call is a byte-identical constant** (`{version:1, name:'concord-mcp',
tasks:[{id:'call', tool, input}]}` — only `tool` and `input` vary). This isn't incidental: the request hash is
a digest of the *entire compiled plan*, so the propose-call and the confirm-call only produce the same hash
if nothing else about the plan shape drifts between them. `test/mcp.test.mjs` has a dedicated regression test
for this (identical call twice → identical hash; a different call → a different hash) because getting it
wrong fails silently — every "confirm" attempt would just produce a fresh block with a fresh hash, not a
crash, not an obvious symptom.

A stale or mismatched `_confirm` can never cause the wrong thing to execute: it simply fails to match the
freshly computed hash and blocks again, correctly, with the current one (confirmed by
`EFFECT_INDETERMINATE` — the same close-without-silent-replace guarantee `files.write`'s own exclusive-create
behavior already gives every other transport).

This two-layer shape is deliberate, not redundant: an MCP client's own human-approval UI (Claude Code and
Claude Desktop both prompt a human before trying a tool call at all) is the *outer* layer — "should this AI
try this tool right now" — while Concord's hash is the *inner* layer — "this exact input, byte for byte, is
what gets authorized," which protects against a model proposing different input on a retry after a human
approved something else.

## Protocol correctness

Framing mirrors `src/workers.mjs`'s existing newline-delimited JSON-RPC discipline exactly, just in the
opposite direction (reading the *client's* stdin instead of a spawned child's stdout): a streaming
`TextDecoder('utf-8', {fatal:true})`, a bounded max-buffered-line size before a newline arrives, and
`parseJson` (rejects duplicate keys) per line. **Stdout carries only valid JSON-RPC lines, nothing else,
ever** — this is the single invariant the whole protocol depends on, and `test/mcp.test.mjs` asserts it
across every collected line in every test. All diagnostics go to stderr.

Dispatch branches on whether the parsed message has an `id` property. No `id` means a notification
(`notifications/initialized`, `notifications/cancelled`, or anything else notification-shaped) — those never
get a response, not even an error, even if the method is unrecognized or the envelope is otherwise malformed.
Everything with an `id` gets exactly one response. Error codes: `-32700` parse error (text that isn't JSON at
all), `-32600` invalid envelope (valid JSON, not a valid JSON-RPC request), `-32601` unknown method, `-32602`
invalid params (unknown tool name, non-object `arguments`), `-32603` unexpected internal error, `-32002`
unknown resource URI. Anything that reaches the kernel — including schema-invalid tool input — comes back as
an ordinary JSON-RPC success with `result.isError: true`; the kernel already handles that gracefully, so
nothing here re-validates ahead of it.

## A real, documented kernel edge case — not an MCP bug

The raw per-tool-call path never declares `dependsOn`, so Concord's own reference-scanning (`$task` lookups
for cross-task data) has nothing to resolve against. If a tool argument happens to contain a nested object
with a `$task` key — plausible for `json.value`/`json.hash`'s arbitrary payload, or `files.write`'s arbitrary
`content` — the call fails closed with `INVALID_REFERENCE` as an ordinary `isError` result, not a crash. This
is correct, by-design kernel behavior inherited from every other transport; `test/mcp.test.mjs` has a
dedicated test for it so it reads as understood, not alarming.

## What is and isn't covered

- **Covered, tested against the real stdio protocol:** the `initialize`/`notifications/initialized`
  handshake, `tools/list` policy-filtering and name-safety, a pure tool call verified against an
  independently computed digest, the full write-effect blocked→confirm→stale-confirm round trip (including
  that the file genuinely doesn't exist until confirmed), the plan-shape hash-stability regression, unknown
  tool names, the `$task`-collision edge case, malformed/truncated/duplicate-key/invalid-UTF-8 input, all 12
  resources with independently recomputed digests, an unknown resource URI, an offline-demo
  chat→state→replay round trip, and the tool-name collision guard at server construction.
- **Not covered / deliberately out of scope:** JSON-RPC batch requests (real MCP clients over stdio don't
  send them in practice), request cancellation (`notifications/cancelled` is accepted and silently ignored,
  matching the rest of this codebase's "run to completion" posture), and a live-model
  propose→approve→execute-plan round trip driven *through* MCP specifically — `concord_approve`'s and
  `concord_execute_plan`'s underlying `harness.approve()`/`executePlan()` are already covered end-to-end,
  non-MCP, by `test/chat-flow.test.mjs`.
