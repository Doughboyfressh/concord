# Turning a foreign thing into Concord tools

Concord takes an outside thing — an MCP server, a GitHub repo, a plugin directory, a published
HTTP API, a local agent install — and turns it into its own tools, skills and instructions. This
records the pipeline, what each step can honestly produce, and the line it does not cross.

The pipeline is deliberately two-stage, and the split is the whole design:

| Stage | Runs | Produces | Grants |
| --- | --- | --- | --- |
| **acquire** | out of band, by an operator | a capability manifest: inert JSON | nothing |
| **compile** | at registry build time | Concord tools | only what the operator configured *and* allowed |

Acquisition writes a file. Importing that file registers one `pure` catalog tool and nothing else.
A tool exists only where an operator separately named the server, pinned its executable digest and
listed the tool. Those are two independent decisions, and neither one alone is a grant.

## The three acquisition paths

| Script | Input | What it asks |
| --- | --- | --- |
| `scripts/acquire-mcp.mjs` | a reviewed MCP server | the server itself, via `tools/list` |
| `scripts/acquire-repo.mjs` | a local clone | the filesystem: six recognizers |
| `scripts/acquire-hermes-local.py` | a local install | the source, by static analysis |

None of them fetch anything. The operator clones or installs the thing first, which keeps every
source pinned the same way [sources.lock.json](../sources.lock.json) pins the twelve upstreams.

## Declared contract versus inferred candidate

This is the distinction the pipeline is built around, and conflating the two is exactly how an
importer invents tools that do not exist.

An MCP `tools/list` reply and an OpenAPI operation are **published contracts**: the name,
description and input schema are the source's own words. A `package.json` bin entry or a `SKILL.md`
convention is an **inferred candidate**: real evidence that something is there, but no statement of
how to call it. Every manifest entry therefore carries `evidence` (the file it came from),
`confidence` (`declared` or `inferred`) and `reason` (why the recognizer believed it).

Only a published contract can become a tool. A candidate needs a reviewed argv template first —
the same requirement [REA's 68 provider tools](rea-internal.md) meet, where the argv shape is the
operator's and only pattern-checked slot values come from a plan.

## Measured on real sources

Run against the pinned clones and against Concord's own MCP server:

| Source | Recognized | Confidence | Compilable tool contracts |
| --- | --- | --- | --- |
| `vercel-labs/skills` | 3 skills, 2 CLIs, 6 instructions | 9 declared, 2 inferred | **0** |
| `morluto/rea` | 1 MCP server, 4 skills, 3 CLIs, 112 instructions | — | **0** |
| Concord's own MCP server | 74 tools | 74 declared | **74** |

The two zeros are the point, not a shortfall. `vercel-labs/skills` declares no MCP server, so the
scan says so and reports its CLI entries as candidates. `morluto/rea` *does* declare one, so the
scan says to run `acquire-mcp.mjs` against it to get real contracts. Neither scan pretends a skill
directory is a callable tool.

All 74 of Concord's own published schemas came back enforceable (`schemaUsable: 74`, unusable `0`).

## Concord importing Concord

The round trip is proved against a server whose answers are independently computable here, so the
reply is *checked* rather than merely received. With `allow: ["json_hash", "text_concat"]`
configured, calling `foreign.concord-self.json_hash` returns

```json
{ "algorithm": "sha256/concord-json-v1", "digest": "39f596613a4e..." }
```

and that digest equals what local `digest()` computes for the same input. `test/foreign.test.mjs`
asserts the equality rather than the string, so it stays true if the algorithm is ever revised.

## Four properties the compiler holds

**Importing grants nothing.** With a 74-tool manifest and no server configured, the registry gains
exactly one tool: `foreign.catalog`, effect `pure`, reporting `availableNow: 0` and
`grantsCapabilities: false`. The namespaced name of every unprovisioned tool is still listed, so a
reviewer can see what a grant would add before making it.

**A foreign name cannot shadow a Concord name.** Every tool registers as
`foreign.<sourceId>.<toolName>`. A server publishing `json_hash` becomes
`foreign.concord-self.json_hash`; Concord's own `json.hash` is untouched, and two sources
publishing the same tool name produce two distinct Concord names.

**The argv is entirely the operator's.** `executable`, `args`, `cwd` and the environment come from
reviewed configuration. A plan contributes only arguments, validated against the server's own
published schema. There is no shell. The approval hash binds both the argv and the published
schema, so changing either changes what an approval authorizes — an approval granted against one
contract cannot authorize a call under a different one.

**A foreign schema is checked before it is trusted.** `usableForeignSchema` runs the server's
schema through Concord's own validator first. A schema that cannot be enforced — not an object, or
carrying something like an invalid `pattern` — is not silently accepted and not silently honored:
it is replaced with a bounded `{"type": "object", "additionalProperties": true}` fallback, and the
substitution is recorded as `schemaUsable: false` on the tool and in the catalog.
`acquire-mcp.mjs` records the same flag at acquisition time, so a reviewer sees which contracts
are really checked *before* deciding what to allow.

Foreign output is labeled `untrusted: true`. It is data from a program Concord does not control.

## Refusals

| Code | Raised when |
| --- | --- |
| `FOREIGN_MANIFEST_INVALID` | wrong `schemaVersion`, a source with no `kind` or no `tools` array, duplicate source ids, a duplicate or non-portable tool name |
| `FOREIGN_CONFIG` | an allow entry the source does not publish, a server id matching no source, non-string argv, a missing allow list, an unsupported field, duplicate server ids, a missing executable, a digest that is not 64 lower-case hex characters |
| `INTEGRATION_EXECUTABLE` | the reviewed digest is well formed but names a different binary than the one on disk |
| `SCHEMA_MISMATCH` | input violating the server's own published schema |
| `FOREIGN_OUTPUT_LIMIT` | the server produced more output than the budget permits |

Everything in the first two rows fires at registry build time, so a misconfiguration fails
before any process launches. The digest *shape* is checked there; the digest is then verified
against the actual file by the same `resolveExecutable` that guards `process.run`, before the
spawn, so a config naming a binary that has since changed refuses rather than runs.

## What this does not do

**One execution route exists today: MCP over stdio.** A `repo` source always compiles to zero
tools by construction — `acquire-repo.mjs` sets `tools: []` with a comment saying why. OpenAPI
`endpoint` entries are genuine declared contracts but have no route yet, so they are recorded as
capabilities and not registered.

**A website is not a capability source unless it publishes one.** A site with an OpenAPI document
yields declared operations. A site without one yields pages, and pages are reference material for
`capabilities.search`, not tools. Forcing a tool shape onto a page would fabricate a capability
that was never real.

**No runtime hot-swap.** A server is provisioned when the registry is built, never mid-run.
`replayPlan` asserts the recorded run's registry digest matches the current one, so a registry
mutated between a run and its replay would break replay verification by design.

**Nothing is granted by acquisition, ever.** Re-running an acquire script against a changed source
rewrites the manifest and can change a tool's `schemaDigest`; it cannot register a tool, widen an
allow list, or revive an approval granted against the previous contract.

## Using it

```powershell
# Ask a reviewed MCP server what it can do (spawns it; run this deliberately).
node scripts/acquire-mcp.mjs --id concord-self --executable C:\path\to\node.exe -- src/mcp.mjs --workspace .

# Scan a local clone. Recognizes MCP servers, OpenAPI operations, skills, plugins, CLIs, instructions.
node scripts/acquire-repo.mjs upstream/vercel-labs-skills --id vercel-skills

# Compile. Without --foreign, none of it exists.
node scripts/chat.mjs --foreign examples/foreign.example.json
node src/cli.mjs run <plan> --policy <policy> --foreign <file>
```

Both acquire scripts merge into `foreign-capabilities.json`, keyed by source id. That file is
git-ignored: it holds machine-specific absolute paths and local binary digests, which are facts
about one machine and not about Concord.
[examples/foreign.example.json](../examples/foreign.example.json) is the committed template; its
placeholder digests make it fail `FOREIGN_CONFIG` until an operator fills in a real one.

`foreign.catalog` is the discovery tool. It is `pure`, its data is frozen at build time, and it
reports the whole manifest — configured or not — so a model can see what is available now and what
would require a grant.
