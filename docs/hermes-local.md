# Taking the hermes capability surface

A hermes installation on this machine was inventoried into Concord on 2026-10-17. It is catalogued
as the source `hermes-local`, separately from the pinned `hermes-agent` entry, because it is the
same repository at a different and much later snapshot: commit `f17021fb`, `0.22.2+1487.gf17021f`,
1,487 commits ahead of base. The install reported `dirty: false`, so its content corresponds
exactly to that commit; the cataloguer refuses a dirty install rather than pinning content that
matches no commit.

MIT, Copyright (c) 2025 Nous Research. The notice is preserved in the lock's license caveat.

## What was acquired

| Measured | Count |
| --- | --- |
| declared tool contracts, with description, parameter names and required fields | **99** |
| of hermes's 51-tool core toolset, covered | **50** (only `skill_manage`, which registers without a literal schema) |
| `SKILL.md` instruction corpora | **98** |
| skills absent from the pinned `hermes-agent` revision | **29** |
| capability entries added to `capabilities.lock.json` | **197** new, 0 existing entries modified or removed |

Acquisition is read-only static analysis: `scripts/acquire-hermes-local.py` parses the Python source
with `ast` and reads `SKILL.md` frontmatter. **No hermes module is imported and no gateway is
contacted.** Interpolated f-string values are dropped rather than guessed, so a recorded description
is literal source text or nothing.

## Two defects the first pass had

The inventory was wrong twice before it was right, both times by over-collecting:

1. **Test fixtures counted as capabilities.** `tests/` and `evals/` declare tool-shaped doubles —
   `fixture_echo`, `good_tool`, `charizard`, `noop`, `plugin_a` — that parse exactly like production
   contracts. 113 of an apparent 225 "tools" were doubles.
2. **UI themes counted as tools.** `hermes_cli/skin_engine.py` declares themes as
   `{name, description, colors}` dicts, structurally identical to a tool schema. `charizard` is
   "Volcanic theme — burnt orange and ember", not a capability. The discriminator is now structural
   rather than a path blocklist: a tool declares a `parameters` schema, so a dict without one is not
   treated as a tool.

225 → 112 → 99. A third over-collection was caught the same way: the skills walk reused the Python
tree's skip list, which contains `web`, silently dropping the real skill `web/blocked-page-recovery`.
The skills count is now asserted against `SKILL.md` files on disk: 98 of 98.

## Effects are classified by rule, with the rule recorded

Every tool entry carries an `effect` in Concord's taxonomy and an `effectBasis` naming the rule that
assigned it, so a reviewer can audit a classification instead of trusting it. A name matching no
rule is left `null` — unclassified rather than plausibly labelled.

| Effect | Count |
| --- | --- |
| `network` | 36 |
| `process` | 27 |
| `write` | 21 |
| `read` | 15 |
| unclassified | **0** |

Two classifications came from reading the implementation rather than the name, and both would have
been wrong otherwise. The `retaindb_*` and `brv_*` memory tools look like local state writes but use
an HTTP client, so they are `network`. The `meet_*` tools look like a remote API but spawn a headless
Chromium subprocess, so they are `process`.

An entry's effect is a claim about the **upstream** tool. It is not a Concord capability, and naming
an inventory entry never grants anything: only a tool present in the registry and permitted by the
policy in force can run.

## Skills ingest without translation

Concord's `skills.snapshot` already parses the `SKILL.md` + YAML frontmatter format hermes uses, so
the corpus needed no conversion. Measured by running the real tool over the real tree:

- **97 of 98 ingest cleanly**, each with a usable name and description, and 97 distinct snapshot
  digests (no collisions, so the digest is content-bound).
- The one refusal is correct behaviour: `research/research-paper-writing` bundles four conference
  template **PDFs**, and snapshots refuse binary content. Snapshotting its `SKILL.md` entrypoint
  directly ingests it — 103,674 bytes.

Unrecognised frontmatter keys (`version`, `author`, `license`, `platforms`, `metadata`) are ignored
rather than rejected, which is why hermes's richer frontmatter is compatible.

## The capability actually ported: least authority per turn

The one piece of hermes's design that became Concord kernel code is its webhook-safe toolset.
hermes serves untrusted third-party payloads from a reduced set — `web_search`, `web_extract`,
`vision_analyze`, `clarify`, with no file or system execution. That is the shape of the per-turn
attenuation Concord had named but never built.

`attenuatePolicy(policy, restriction)` in `src/engine.mjs` derives a narrower policy for one turn.
The property that makes it safe to apply automatically is that **it can only ever remove
authority**: a restriction naming a tool, effect or origin the base policy withholds is a mistake
rather than a grant and throws `POLICY_NOT_ATTENUATED`, and budgets may only be lowered. Widening is
refused in all five dimensions (`allowedTools`, `allowedEffects`, `allowedOrigins`, the byte and task
budgets, and `timeoutMs`).

`send(message, { attenuate })` applies it to a single turn. Three consequences are tested:

- The attenuated policy is computed **before** `buildContext`, so the context describes the authority
  the model will actually get rather than the base policy.
- It is enforced, not merely reported: a `files.read` the base policy permits is `POLICY_DENIED`
  once attenuated away.
- It is recorded per run. The request hash binds the policy, so replaying an attenuated turn against
  the base policy would not reproduce it; `replay` uses the run's own recorded policy. Runs recorded
  before this change still replay, via a fallback to the base policy.

A narrowed turn does not leak into the next one, and `snapshot().authority` surfaces the authority in
force so a client can display it instead of inferring it.

## What did not transfer, and why

hermes is roughly 21,000 Python files with a long-lived gateway, a SQLite state store, plugins, an
LSP bridge, sandboxes and desktop apps. Concord is Node ESM with **zero dependencies, ever**. A
literal port is not available at any effort level — it is the wrong language and the opposite
dependency and statefulness posture.

**Correction.** This section previously added that "every tool output must be a pure function of
its declared input so a recorded run can be replayed". That is true of `pure` and `read` tools and
false as stated: `replayPlan` never calls `execute`, and for an effectful tool it takes the
recorded value and asserts legality properties, which is how `process.run` and `browser.snapshot`
already replay. Purity is not what rules out a long-lived gateway; see
[taking REA's capabilities internally](rea-internal.md), where the same mistaken reasoning was
corrected and 66 device-backed tools were implemented through a reviewed-provider route instead.

So the transfer is deliberately three things: the **instruction corpus** (which is data, and moves
losslessly), the **tool contracts** (which become searchable inert inventory), and the **one design
idea** above (which became kernel code with its safety property tested). Runtime tool hot-swap genuinely is excluded, because
replay asserts the registry digest is unchanged between a run and its replay. Session state held
across separate approved calls is a different matter: it is a design choice, since each call is
separately approved and bounded, and the `dsh.run` pattern of putting a whole multi-step protocol
inside one bounded call is how that is expressed here.

## Reproducing it

```
python scripts/acquire-hermes-local.py <hermes-install-dir>   # writes upstream/hermes-local-surface.json
node scripts/catalog-upstream.mjs                            # folds it into capabilities.lock.json
```

The fold happens inside `catalog-upstream.mjs` rather than in a separate pass because that script
rewrites the whole lock; a post-processing step would be silently discarded on its next run. The
acquisition step is out of band, the same role `acquire-upstreams.ps1` already plays, and the
cataloguer itself stays pure Node built-ins.
