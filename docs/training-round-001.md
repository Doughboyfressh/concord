# Codex and Concord: supervised training round 001

Completed 2026-10-16 (America/Los_Angeles), using Concord's native MCP connection and the local
`qwen3.8-27b` provider. This round improved the harness, context, supervision and persistent guidance.
It did not update model weights, and the provider's model alias is not an immutable weight revision.

## Measured failures and corrections

| Exercise | Initial live behavior | Fresh-process result after changes |
| --- | --- | --- |
| Propose one `text.concat` operation | Supervisor returned `SCHEMA_MISMATCH`. | Same request produced valid `{values:["alpha","beta"],separator:"|"}`; separately executed receipt returned `alpha|beta`. |
| Recall an arbitrary marker from the preceding turn | Model said the marker was unavailable; code had discarded prior history. | Recalled a session marker that its acknowledgment had not repeated. |
| Explain deterministic replay | Model incorrectly said replay re-executes tools. | Correctly explained recorded-event validation with no tool execution or fresh model call, and no guarantee of identical fresh inference. |

Codex presented these failures to Concord. Concord agreed that full tool contracts, bounded history and
observed receipts were needed, and proposed schema, recall and replay acceptance checks. Its feedback
explicitly distinguished coaching from weight training. A reviewed lesson was promoted through
`memory.candidate` / `memory.promote` and an exact write grant; replay of that promotion verified without
repeating the write. The lesson is stored at
`memory/3bdbcaba19d79680c4783b7797fab7aa93e6b706700c720fc9b328a8b8408a4b.json`.

## Durable changes

- Supply policy-filtered native tool schemas, versions, effects and approval requirements; exclude adapter
  configuration and implementation bodies.
- Supply bounded prior conversation, the current validated proposal for follow-up edits, and actual
  execution receipts with explicit omissions and full-record commitments.
- Keep acquired skills and recalled memories in structured untrusted reference data outside system
  instructions. Require a pure descriptor before direct capability preview.
- Reject malformed model proposals before committing their reply or plan. Surface rejection codes and
  indeterminate effects. Ordinary tool output cannot impersonate a model reply using a `proposal` property.
- Bound individual receipt outputs by bytes and depth, so valid deeply nested data cannot break future
  turns. Preserve hashes and omission reasons; the original run retains its full output.
- Provide an opt-in live evaluation command, separate from normal tests.

Independent review found two additional defects during this round: deeply nested output could exceed the
public envelope's JSON-depth limit, and follow-up inference lost the preceding proposal. Both were fixed
and given regression tests. The second review found no remaining high or medium findings in this scope.

## Verification

Full validation passed: **218 tests, 215 passed, three platform skips, zero failures**, plus syntax and CLI
end-to-end checks. Local evidence:
`.agents/evidence/validation-2026-10-17T04-26-17-310Z/`.

The repeatable six-turn fresh MCP exercise passed **89 structural checks**. It tested schema-valid planning,
marker continuity, real receipt reporting, absent Telegram delivery, and replay. These are checks within a
small exercise, not an intelligence score. Scripts leave semantic replies unscored; Codex separately
reviewed their text for the claimed behavior. Raw evidence: `runs/training-round-001/transcript.json` and
`runs/training-round-001/wire.jsonl`.

Concord's closing critique identified multi-step dependency failure as the next useful exercise. Codex ran
it against another fresh MCP process: `join` completed, the deliberately false `gate` assertion returned
`TOOL_FAILED`, and dependent `tail` never ran. Replay verified the failed run, and Concord accurately
reported partial completion while distinguishing a pure failure from `EFFECT_INDETERMINATE`.
This additional two-response exercise passed nine structural checks. Evidence: `runs/training-chain-001.json`.

Initial native probes and coaching are retained in `runs/training-codex-native-1792210874078.json`;
final feedback and memory promotion/replay are in `runs/training-codex-final-feedback.json`. Run directories
are local and git-ignored. Preserve them before deleting local evidence.

## Repeat the six-turn exercise

From this repository in PowerShell, with the existing local provider running:

```powershell
$trainingRoot = (Get-Location).Path
$env:CONCORD_MODEL_API_KEY = 'concord-local'
node scripts/train.mjs --live --root $trainingRoot --integrations "$trainingRoot/config/concord-live.json" --out "$trainingRoot/runs/training-round-002"
```

The non-secret placeholder applies to this unauthenticated local provider. The runner requires a reviewed
model-only loopback configuration and a new output directory. It approves only the current exact model
request and separately executes only the exact reviewed pure concatenation plan. It preserves failed
attempts and does not grant arbitrary model-proposed effects. Normal validation never calls a live provider.

These results establish observed improvement on these cases. They do not prove universal schema fidelity,
prompt-injection resistance, broad task generalization or deterministic live inference. Running MCP
processes retain imported code; the durable changes load when a fresh server starts.
