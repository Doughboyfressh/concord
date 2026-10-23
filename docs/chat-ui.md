# The local interface

`src/server.mjs` serves three static assets (`app/index.html`, `app/style.css`, `app/client.mjs`) and five JSON
routes, bound to `127.0.0.1` (or `::1`) only. `scripts/chat.mjs` wires it to a `createChatHarness` instance and
prints the bound URL.

## Routes

| Route | Method | Purpose |
| --- | --- | --- |
| `/api/state` | GET | Returns `{state, status, token}` — the current chat snapshot, static inventory counts, and the session's instance token. |
| `/api/chat` | POST | `{message}` → the state after `harness.send(message)`. |
| `/api/approve` | POST | `{requestHash}` → the state after `harness.approve(requestHash)`. |
| `/api/execute` | POST | `{plan?}` → the state after `harness.executePlan(plan)`; omitting `plan` re-attempts the current proposed plan. |
| `/api/replay` | POST | `{runId}` → `{state, replay: {runId, verified, root?, eventCount?}}`. |

`publicState` filters the harness snapshot down to `mode`, `history`, `selected`, `sourceCoverage`, `pending`,
`proposedPlan`, `runs` before it ever reaches a response — no private harness property, provider configuration,
credential, or full run journal is exposed over HTTP.

## Request authorization

Every request must present the exact `Host` the server is actually listening on; the loopback IP on both ends
of the socket; and, for state-changing routes, an `Origin` matching that same host and an `X-Concord-Token`
header equal (via a timing-safe comparison) to the token minted once at server start and handed out by
`/api/state`. A request that fails any of these is denied before its body is even read. This is the mechanism
`test/server.test.mjs` exercises directly — missing token, wrong origin, wrong method, and unknown routes each
get their own assertion.

Every response — including error responses — carries a fixed set of security headers: `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, same-origin `Cross-Origin-*` policies, a
locked-down `Permissions-Policy`, and a `Content-Security-Policy` of `default-src 'none'` with narrow `'self'`
exceptions for script/style/connect/img/font. Exception messages, stack traces, upstream HTTP bodies, and
request headers are never forwarded to the client; an unrecognized error becomes a generic `REQUEST_FAILED`.

## The client

`app/client.mjs` is a single ES module, loaded same-origin under that CSP (no inline scripts, no `eval`, no
external font or image). It fetches `/api/state` once for the token, then renders two regions rather than a
grid of equally-weighted panels.

The **session rail** holds what is true for the whole session: a turn index (each turn dotted by its
`execution.kind`), the `authority` actually in force for the latest turn — effects, which of them are gated,
tool count, task ceiling, deadline — the workspace inventory, and the peer exchange. The **thread** holds the
conversation and everything transient. A proposed plan, a distilled lesson candidate and an approval gate are
not permanent panels; they appear inline, in that order, with the gate nearest the composer because it is the
only thing that blocks.

The thread's distinguishing element is the **receipt strip** under each assistant reply that proposed a plan.
Collapsed it is one line: whether the plan executed, how many attempts, which tools completed, and the run
root. Expanded it joins each settled attempt to that run's entry in `observations` by run id and lists every
task with its own `outputHash`, or its failure `code`/`toolCode` and the supervisor's diagnostic, or the
request hash it is still awaiting — plus a per-run Replay control that reports its verdict in place. A reply
carrying verified `citations` renders each quote with the task, run and output hash it was checked against;
the kernel refuses to record a quote that does not appear verbatim in that recorded output, so the marker is
a checked fact rather than the model's claim about itself.

`observations` arrives as a bounded-records envelope (`{records, omittedCount, totalCount, fullDigest}`), not
a bare array. The client reads `.records` and uses `omittedCount` to distinguish "this run has no receipt"
from "this run's receipt aged out of the window, and replay can still verify it from its journal".

Every value that could contain model- or capability-derived text is written through `textContent`, never
`innerHTML` — a malicious plan, reply, capability title, peer message or lesson cannot inject markup. The
single `h()` helper is the only place in the file that assigns text at all.

Light and dark are both driven by `prefers-color-scheme`, with an explicit override stored in `localStorage`.
Because the CSP forbids an inline bootstrap script, an override that differs from the system theme can flash
once before the module runs; relaxing `script-src` to avoid that was judged not worth a frame.

Keyboard: `Enter` sends, `Shift`+`Enter` inserts a newline, `Ctrl`/`Cmd`+`K` focuses the composer,
`Ctrl`/`Cmd`+`B` toggles the rail, and `Ctrl`/`Cmd`+`Enter` approves a pending request.

A model reply is rendered as markdown — fenced code with a copy control, headings, lists, quotes,
rules and inline code/bold/italic/links — built as DOM nodes rather than assembled HTML, so the
`textContent`-only invariant holds for text the model wrote. A person's own message is never
parsed. The rail filters the transcript, and every message can be copied; a message you sent can
be put back in the composer to edit and send again.

## Stopping a turn, and what is shown while it runs

`POST /api/cancel` aborts whatever is executing. The abort reaches the tool through `runPlan`'s
optional `signal`, so the tool raises its own abort code and the run is recorded as failed with a
real diagnostic — for a gated effect that is `EFFECT_INDETERMINATE`, which is the honest answer,
because a cancelled write may or may not have landed. There is no new event type and no new
failure code, so `replayPlan`'s legal-code check is unchanged.

`GET /api/stream` is a Server-Sent Events channel carrying progress for the turn in flight. It is
a display channel and nothing else: no output, no evidence, no approval, and a client that never
connects loses nothing. It carries no token because EventSource cannot set headers; the loopback,
`Host`, `Origin` and `sec-fetch-site` checks gate it exactly as they gate `GET /api/state`.

What it carries was decided by measurement rather than preference. Against the configured model, a
ten-second call spent its first 9.6 seconds emitting `reasoning_content` and produced the actual
`content` in a single 0.4-second burst at the end. So streaming the reply would show nothing for
95% of the wait. The channel therefore reports **how far the model has got**, and the two channels
are never conflated: `reasoning_content` is the model's private working and is counted but never
forwarded, because showing text that is neither the answer nor evidence as though it were one of
them is precisely what this interface exists not to do. Only `content` is previewed, incrementally
extracted from the partially-arrived JSON object, and labelled "preview — not yet recorded".

## Past sessions

`GET /api/sessions` lists recorded transcripts and `POST /api/session` opens one. Every turn
already appended a snapshot to the session store, so this reads back what was always being
written. Read-only by construction: a past session renders in place of the live transcript with
the composer withdrawn, because resuming one would mean adopting another session's approvals and
proposed plan as if they were this one's, and an approval is bound to the run that requested it.

Note that `src/app.mjs` hashes `app/index.html`, `app/style.css` and `app/client.mjs` into
`sourceLock.runtime.files`. Editing the interface therefore changes the source lock, which changes every
approval request hash and makes runs recorded under the previous interface refuse to replay with
`REPLAY_CONTEXT`. That is the guarantee working rather than a regression: a recorded run is bound to the
exact software that produced it, and the page is part of that software.
