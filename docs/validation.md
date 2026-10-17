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
| `training.test.mjs` | Bounded history, actual tool contracts, pure-only preview, tool receipt continuity, proposal provenance/rejection, deep output bounds and iterative plan edits. |
| `server.test.mjs` | The local HTTP server (`src/server.mjs`) over real sockets: host/origin/token enforcement, security headers, the offline and live-model flows through the actual `/api/*` routes, and a child-process run of the real `scripts/chat.mjs` entrypoint sending the same message twice. |
| `artifacts.test.mjs` | Native static format inspection, malformed/truncated records, ZIP/Mach-O/WASM bounds, and inspection through strict-JSON capture/replay. |
| `browser.test.mjs` | CDP browser contracts, multi-step automation, snapshots and structured form extraction. |
| `memory.test.mjs` | Reviewed memory promotion, recall and workspace containment. |
| `merge.test.mjs` | Explicit text/result composition tools. |
| `mcp.test.mjs` | MCP transport, tool/resource exposure and chat control. |

That last case in `server.test.mjs` is a direct regression test: a repeated identical chat turn recomputes the
same content-derived run id, and `scripts/chat.mjs`'s evidence writer must treat that as an idempotent no-op
rather than let the exclusive-create write throw `EEXIST` into an unhandled 500. This was found by manually
exercising the running server over HTTP and in a real browser — the unit-level `chat-flow.test.mjs` could not
have caught it, because it never calls `persistRun` at all. `server.test.mjs` closes that specific gap.

## What stays unverified by any script here

Normal validation does not make live provider calls. The DeepSeek Harness native runtime, TypeSafe account, and
the Hermes/REA/ego-lite/Orca/21st runtime bridges are source-available and contract-documented but not
exercised by normal tests in this repository — see [adapters](adapters.md), [agent workers](agent-workers.md), and
[feature synthesis and implementation status](architecture.md) for exactly what each one's integration status
is. No test here grants network access to a real upstream service.

The opt-in `scripts/train.mjs --live` exercise separately verifies the configured local model through a
fresh MCP process. The [first supervised round](training-round-001.md) passed six live turns and 89
structural checks, plus a separate two-response partial-failure exercise with nine checks. Semantic
responses are preserved for review and not assigned automatic correctness scores.

After the chat improvements, full validation passed **215 tests, three platform skips, zero failures**
(218 total), syntax and CLI end-to-end checks. Evidence:
`.agents/evidence/validation-2026-10-17T04-26-17-310Z/`.

The 2026-10-16 upgrade review passed syntax, the full suite (**205 passed, 3 platform-dependent skips,
0 failures**), and CLI end-to-end checks. See [upgrade review](upgrade-review.md) for the exact fixes and
evidence path. Validation now records the actual Git head, branch and remote names instead of the stale
assumption that the repository has no remote; it preserves existing work and does not rebase or push.
