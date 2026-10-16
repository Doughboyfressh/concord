# Validation evidence

```powershell
node scripts/validate.mjs
```

runs `scripts/check.mjs`, then `scripts/test.mjs`, then `scripts/e2e.mjs` in that order, captures each step's
combined stdout/stderr, and writes `.agents/evidence/validation-<timestamp>/{check,test,e2e}.log` plus a
`summary.json` (`{runtime, platform, results[], evidence}`). That directory is git-ignored; it is local proof
for the person who ran it, not a committed artifact. A nonzero exit from any step fails the whole run.

- **`check.mjs`** runs `node --check` over every `.mjs` file under `src/`, `scripts/`, and `test/` — a syntax
  gate, nothing more.
- **`test.mjs`** discovers `test/*.test.mjs` by an explicit filename allowlist (never by directory discovery,
  so it can never reach into `upstream/`) and runs them under `node --test`.
- **`e2e.mjs`** drives `src/cli.mjs` as a real child process through five scenarios: an offline run and its
  anchored replay, an exact-approval round trip for a blocked write effect, confirmation that replay does not
  repeat that write, and rejection of a trace whose `inputHash` has been tampered with and rehashed.

## What `test/*.test.mjs` actually covers

| File | Covers |
| --- | --- |
| `core.test.mjs` | Canonical JSON, schema validation, plan compilation, approval hashing, replay's chain/budget/transition checks. |
| `capabilities.test.mjs` | The capability inventory search tool. |
| `sources.test.mjs` | The source lock loader and skill-snapshot tool. |
| `integrations.test.mjs` | The TypeSafe and model HTTP adapters against local fixture endpoints. |
| `workers.test.mjs` | The DeepSeek Harness SDK process adapter against a local protocol fixture, including every listed protocol-violation and resource-bound case. |
| `chat-flow.test.mjs` | The chat session broker (`src/chat.mjs`) in-process: the offline demonstration end to end, and a live-model fixture's propose/approve/execute/approve/replay cycle. |
| `server.test.mjs` | The local HTTP server (`src/server.mjs`) over real sockets: host/origin/token enforcement, security headers, the offline and live-model flows through the actual `/api/*` routes, and a child-process run of the real `scripts/chat.mjs` entrypoint sending the same message twice. |

That last case in `server.test.mjs` is a direct regression test: a repeated identical chat turn recomputes the
same content-derived run id, and `scripts/chat.mjs`'s evidence writer must treat that as an idempotent no-op
rather than let the exclusive-create write throw `EEXIST` into an unhandled 500. This was found by manually
exercising the running server over HTTP and in a real browser — the unit-level `chat-flow.test.mjs` could not
have caught it, because it never calls `persistRun` at all. `server.test.mjs` closes that specific gap.

## What stays unverified by any script here

Live provider calls (a real model endpoint, a real TypeSafe account), the DeepSeek Harness native runtime, and
the Hermes/REA/ego-lite/Orca/21st runtime bridges are source-available and contract-documented but not
exercised by any test in this repository — see [adapters](adapters.md), [agent workers](agent-workers.md), and
[feature synthesis and implementation status](architecture.md) for exactly what each one's integration status
is. No test here grants network access to a real upstream service.
