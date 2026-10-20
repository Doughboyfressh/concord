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

## Four kinds of MCP primitives

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

**The other direction: Concord asking the client.** MCP is symmetric — a server may send requests to
its client — and until now Concord only ever answered. `src/peer.mjs` is that other half: three tools
that let Concord put a question to the agent on the other end of the session, or tell it something,
over the stdio connection that client already opened.

| Tool | Effect | What it does |
| --- | --- | --- |
| `peer_capabilities` | `read` | What the client said it was and could do, from its own `initialize` |
| `peer_ask` | `network` | `sampling/createMessage`: asks the client's **model**, returns its answer |
| `peer_request` | `network` | `elicitation/create`: asks the client to **obtain** an answer, usually from a person |
| `peer_tell` | `network` | `notifications/message`: one line, no reply |
| `peer_post` | `write` | files a message for the agent or the operator to collect |
| `peer_inbox` | `read` | collects what has been filed |

**Which one works depends on the client, and the two are not interchangeable.** Sampling asks the
client's model; elicitation asks the client to go and get input. A client declares what it supports
at `initialize`, and Concord asks only what was declared.

Measured against Claude Code 2.1.221, from its own `initialize`:

```json
{ "protocolVersion": "2025-11-25",
  "capabilities": { "roots": { "listChanged": true }, "elicitation": {} },
  "clientInfo": { "name": "claude-code", "version": "2.1.221" } }
```

It declares `elicitation` and `roots`, and **not** `sampling`. So on Claude Code, `peer_request` is
the channel that works and `peer_ask` is the one that refuses — with `PEER_UNSUPPORTED`, before a
line is written. That is not a limitation worked around; it is the capability gate doing its job on
a real client, and the reason the gate exists.

**The two directions reach different people, and that is the whole problem.** Sampling asks the
client's *model*. Elicitation asks the *person* operating it. They are not two ways of doing one
thing. Driven live against Claude Code, `peer_request` worked exactly as designed and the prompt
went to the operator, who answered it by hand — which is correct behaviour and still not what
"Concord talks to the agent" means. With `sampling` undeclared by that client, there is **no MCP
direction at all that reaches the connected agent's context**. That is a property of the client,
not a gap in Concord, and it cannot be worked around inside the protocol.

So the mailbox is not protocol. `peer_post` writes a message to a directory and `peer_inbox`
collects it. That makes those two unlike everything else here: they need no live client, they are
registered on the desktop application as readily as on the MCP server, and the two sides can be
separate processes that never meet — which is exactly the real arrangement, since Concord's own
agent runs in the desktop process and the connected agent arrives over stdio. Verified across two
independent server processes: one posted, the other collected the same letter.

A letter names its recipient (`agent` or `operator`) rather than leaving it implied, because a
message that does not say which audience it is for gets read by the wrong one. Reading never
consumes: pass `after` with the reported `latestSeq` to page. A tool that quietly drained the
mailbox would make a lost message indistinguishable from one that was never sent. The sequence
comes from what is already in the directory rather than from a clock, so two readers see the same
order. And nothing about this notifies anybody — it is a mailbox, and a letter sits until it is
collected.

**A deadline that was wrong, measured.** The first live elicitation failed with `TIMEOUT` while its
dialog was still on screen waiting to be read: the MCP server's default policy allowed sixty
seconds, and a policy deadline is the ceiling every tool shares. People are slower than models.
That default is now the kernel's own 300-second maximum, and `peer_request` takes the policy's
whole deadline rather than a shorter fixed cap, stopping a second early only so the failure reads
`PEER_TIMEOUT` — the client did not answer — rather than the kernel's generic `TIMEOUT`. A tool
that returns quickly still returns quickly; a ceiling is not a target.

`peer_request` sends a message and a `requestedSchema` built from a declared field list. MCP keeps
that schema to a flat object of primitives because the client has to render it, and building it
here rather than taking a caller's schema whole is what keeps it that way. A reply may be `accept`,
`decline` or `cancel`; declining is reported as an answer with `answered: false`, never as an error,
because treating "no" as a failure would make a refusal look like a broken channel and invite
retrying something a person already turned down. An accepted reply is still checked field by field:
a missing required value, a wrong type, or a value outside the offered choices is refused rather
than passed on.

Nothing here opens a socket, spawns a process, or reaches any party the client did not already connect.
The peer is whoever is on the other end of stdin and stdout, and that is the only thing reachable. These
tools exist **only on this transport** — the desktop and terminal launchers serve a browser, which is
not an agent that can be asked anything, so they register none of it rather than offering a tool that
could only ever refuse.

`peer_ask` is a `network` effect for the same reasons `model.propose` is: the answer is written by an
agent Concord does not control, it is not reproducible, so it requires its own exact grant through the
same `_confirm` round trip and is taken from the journal on replay. There is no origin to allowlist
because no socket is opened. The answer comes back labelled `untrusted` with its own limitations: it is
evidence of what that agent said, not that what it said is true, and whether the client showed the
question to a person or answered it with a model of its choosing is not visible from here.

Three things the channel refuses to do. It never asks a client that did not declare `sampling` at
`initialize` — the call fails with `PEER_UNSUPPORTED` before a line is written, because waiting for a
reply that cannot come is the worst of the available failures. It sends `includeContext: "none"`, so the
client is asked to include none of its own context: Concord states its question in full or not at all,
since inheriting whatever else that agent is working on would put text Concord never saw into a request
it is accountable for. And it accepts only a text reply; image and audio sampling results are legal MCP
and are refused here rather than silently dropped, which would misreport what the peer said.

A reply from the client carries an id and no method. That has to be claimed before the request
dispatcher sees it, or the dispatcher reads it as a malformed request and answers the client's perfectly
good reply with a protocol error. `test/peer.test.mjs` asserts exactly that, along with the timeout,
cancellation, transport-failure and in-flight bounds.

A note on what has been verified, and how. Both halves have been driven end to end against clients
written for the purpose: Concord sent `sampling/createMessage` to one that declared sampling and got
its answer back through `peer_ask`, and sent `elicitation/create` to one declaring exactly what Claude
Code declares and got `{"action": "accept", "content": {"answer": "..."}}` back through
`peer_request`. The capability set used in those tests was not guessed — it was captured from Claude
Code's real `initialize`. What remains unverified is the live round trip through Claude Code itself,
which needs a session where Concord is a connected server; `peer_capabilities` reports what the
client in front of it actually declared, which is the only trustworthy answer to that question.

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

## Talking to another session

`peer.ask` performs real MCP sampling: it issues `sampling/createMessage` and the connected client's model
answers. Its reach was always one client — the one on the other end of this stdio session — because stdio
means one server process per client. Two agents on the same machine each had a working sampling channel and
no way to reach each other, and the only thing joining them was the mailbox, which is a dead drop: a file is
written, nothing is woken, and a question waits until somebody looks. The message that prompted this work sat
for twenty minutes.

`src/peer-hub.mjs` brokers between sessions. The first Concord session to start binds a local endpoint — a
named pipe on Windows, a unix socket under `runs/peer-hub/` elsewhere, both from `node:net` — and becomes the
hub; later sessions connect to it and register the identity and capabilities their client declared at
`initialize`. The endpoint's name carries a digest of the workspace root, so two checkouts on one machine
never find each other.

Two tools use it. `peer.peers` (a `read` effect) lists who is connected and what each client declared,
including `canAnswer`, so a caller learns whether a direct question is possible instead of discovering it by
failure. `peer.askPeer` (a `network` effect, like `peer.ask`, needing its own grant and taken from the journal
on replay) names a peer and asks it.

What happens next is the point: the hub routes the question to the session that owns that peer, and **that
session issues a genuine `sampling/createMessage` to its own client**. The answer is produced by the target's
real model through the real protocol primitive. Concord carried the question and did nothing else to it —
`includeContext` is `none`, so the target sees exactly what was sent and nothing about the asking session.

Three mechanisms can carry a question and they are not equivalent, so every answer reports which one did, in
a `via` field:

- `sampling` — the target's client declared sampling and its model answered. Milliseconds.
- `rendezvous` — the target's client declared no sampling, so the question was parked as an ordinary mailbox
  letter and the existing watcher advertised it in the description of `concord_answer`, which is the push
  that does work on such a client. The agent answers with a tool it already has. Costs an agent turn, and
  reports `model: null`, because nothing was sampled — a person or an agent typed that text.
- refusal — the target cannot be sampled and no mailbox is configured, so `PEER_HUB_NO_SAMPLING` names the
  capability that is missing rather than returning something Concord invented.

Which path you get is decided by the target's client, and the measured answer is humbling. Read off a live
roster of connected sessions: Claude Code declares `elicitation` and `roots`; Codex declares `elicitation`,
`experimental` and `extensions`. **Neither declares `sampling`.** So between these two clients the fast path
is unavailable in *both* directions, and rendezvous is not a fallback at all — it is the only mechanism that
works.

This is worth stating plainly because the first version of this document claimed the opposite: that Codex
declared sampling and that this was what made the fast path work in that direction. That was assumed and then
written down, and reading the actual roster contradicted it. The sampling route is implemented, tested and
correct, and it waits for a client that declares the capability; today, on this machine, nothing does. The
fallback is carrying every real cross-session message.

A rendezvous cannot prove who answered, and this is the one place the two paths differ in kind rather than
in speed. The mailbox is shared by every session; the parked letter names its sender and its intended
recipient in the subject, but nothing in the kernel enforces that recipient, and a reply records no author.
So the first agent to answer that letter wins, even when it is not the peer named in `to`. This was observed
live rather than reasoned about: a question routed to one Claude was answered by a different Claude on another
client, seconds before the intended one got to it. `servedBy` is therefore `null` on the rendezvous path —
reporting the target's name there would attribute text to a party that may not have written it — and
`askedSeq`/`answeredSeq` give a caller the two mailbox sequence numbers, which are the only handle it has on
what actually happened. On the sampling path `servedBy` is the client that was sampled, which the channel does
establish.

The mailbox is not replaced. The socket is a doorbell and the file is the record: an exchange that exists
only as two closed sockets is not evidence and cannot be replayed, which is why `peer.askPeer` is a `network`
effect whose answer the journal keeps. Latency is what the hub fixes, not accountability.

Failure is bounded in the directions that matter. A session that goes away mid-question fails its asker at
once with `PEER_HUB_GONE` rather than leaving it to wait out a two-minute deadline; an unknown peer is refused
by name with the names that would have worked; a connection without the hub token is denied before it can ask
anything and never enters the roster; and a session that cannot reach the hub at all simply reports
`joined: false` and says the mailbox still reaches everyone. Joining is additive — Concord has never failed to
start because a socket was busy.

The token lives in `runs/peer-hub/token`. Its trust boundary is the workspace: anything that can read the
directory can read the token, which is the same boundary `runs/peer-mailbox` already had. It guards against a
stray local process stumbling in, and does not claim to withstand a hostile local user who already holds the
directory.

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
