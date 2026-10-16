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

`app/client.mjs` is a single ES module, loaded same-origin under that CSP (no inline scripts, no `eval`). It
fetches `/api/state` once for the token, then renders seven panels from the harness snapshot: the mode badge,
the source-knowledge sidebar (all twelve `sourceCoverage` entries plus any matching `selected` capability
references), the conversation, the pending-approval card, the proposed-plan card, the active-context card, and
the run-evidence list with per-run replay buttons. Every value that could contain model- or capability-derived
text is written through `textContent`, never `innerHTML` — a malicious plan, reply, or capability title cannot
inject markup into the page.
