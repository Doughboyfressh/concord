# Source-derived instructions

`buildChatContext({ message, history, observations?, proposedPlan?, sourceLock, inventory, registry, policy?, instructionRoot })` in
`src/chat-context.mjs` assembles everything a chat turn is grounded in. It reads only the explicit
`instructionRoot` it is given; it never touches the clock, the network, or any ambient environment variable.

## The thirteen reviewed modules

`instructions/manifest.json` lists one module per entry in `sources.lock.json` (`{sourceId, file, sha256,
bytes}`). Every turn, `buildChatContext`:

1. Loads the manifest and checks it covers exactly the pinned source set — no source missing, none extra,
   no duplicate `sourceId`.
2. Reads each module's file (bounded to 64 KiB) and recomputes its SHA-256. A mismatch against the manifest's
   recorded digest fails the turn closed rather than serving stale or tampered instruction text.
3. Concatenates all thirteen into the `systemPrompt` passed to a live model, and returns their source ids as
   `sourceCoverage` for display.

This is why `sourceCoverage.length` is always `13`: the instruction set is not retrieved or ranked per turn, it
is the complete reviewed corpus, every time. Changing an instruction module's text without updating its
manifest digest — or changing which sources are pinned without updating the manifest to match — breaks every
subsequent chat turn until the manifest is regenerated, by design.

## What does vary per turn: capability preview

`buildChatContext` also calls the already-registered `capabilities.search` tool directly, as a plain function
call, with the chat message as the query. This is deliberate and safe specifically because that tool's effect
is `pure`: a pure tool has no side effects by the kernel's own contract, so invoking it outside the kernel's
approval pipeline grants nothing and executes nothing a user didn't already have access to search. Its top
results (title, source id, kind, lexical score) become `selected`, shown in the chat UI's "Active context"
panel and in the per-source "N matching capability references" hint in "Source knowledge." If the tool throws
or the inventory is empty, `selected` is just `[]`; it never fails the turn.

The preview requires the descriptor to declare `effect: "pure"`. A replacement declared as a network,
process, read or write effect is never called directly by context assembly. When supplied, policy filters
the visible registry by both allowed tool names and allowed effects before preview and contract assembly.

## Tool contracts, continuity and evidence

The system prompt includes each visible tool's exact native `name`, `version`, `effect`, `inputSchema`, and
`requiresApproval` flag, in sorted name order. It excludes adapter configuration and implementation bodies.
The complete contract list has a 64 KiB budget; exceeding it fails closed rather than truncating schemas.
An explicit normalized policy supplies allowed origins and budgets; it does not supply approval grants.

The model's user payload is a JSON object with `currentRequest`, `conversation`, `observations`, `proposal`,
and `references`. Prior conversation retains a complete suffix of at most 24 messages and 16 KiB, excluding
the current request supplied separately. Supervisor receipts retain at most eight records and 16 KiB.
Both windows report `omittedCount`, `totalCount`, and a digest of the entire record list. Records are never
cut or summarized: if the newest record exceeds its window, no older records are substituted. A digest
does not give the model access to omitted content. The current validated proposal is supplied separately
for follow-up edits, with a 16 KiB bound and explicit omission metadata.

Receipts identify run, journal root, task, tool, status and output hash, with actual non-model outputs or
failure codes. Individual outputs have an 8 KiB and 32-level nesting budget to leave room for surrounding
JSON. Larger/deeper values retain their hash and explicit omission reason; full evidence remains in the
original run. Model outputs are represented by replies and the current proposal rather than recursively
embedding all responses. Rejected proposals produce supervisor observations. `EFFECT_INDETERMINATE`
remains explicit; it cannot establish that an effect did not occur.

Acquired skill excerpts, recalled memory, and selected catalog references are untrusted user-payload data,
outside the system instructions. Skill and memory text are bounded to 1,500 characters each, with explicit
truncation flags and source/candidate identity. Only the thirteen reviewed, digest-checked modules are system
instructions. Delimiting references helps the model follow their intended role; the kernel remains the
enforced authorization boundary.

## The offline deterministic reply

When no `model.propose` tool is registered, `src/chat.mjs` uses this module's deterministic demonstration
reply derived from the thirteen source ids, and the message itself only
feeds the `capabilities.search` query inside the demonstration plan it proposes. See
[chat sessions](chat-session.md) for how that plan is built and run.
