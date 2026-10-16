# Source-derived instructions

`buildChatContext({ message, history, sourceLock, inventory, registry, instructionRoot })` in
`src/chat-context.mjs` assembles everything a chat turn is grounded in. It reads only the explicit
`instructionRoot` it is given; it never touches the clock, the network, or any ambient environment variable.

## The twelve reviewed modules

`instructions/manifest.json` lists one module per entry in `sources.lock.json` (`{sourceId, file, sha256,
bytes}`). Every turn, `buildChatContext`:

1. Loads the manifest and checks it covers exactly the pinned source set — no source missing, none extra,
   no duplicate `sourceId`.
2. Reads each module's file (bounded to 64 KiB) and recomputes its SHA-256. A mismatch against the manifest's
   recorded digest fails the turn closed rather than serving stale or tampered instruction text.
3. Concatenates all twelve into the `systemPrompt` passed to a live model, and returns their source ids as
   `sourceCoverage` for display.

This is why `sourceCoverage.length` is always `12`: the instruction set is not retrieved or ranked per turn, it
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

## The offline deterministic reply

When no `model.propose` tool is registered, `src/chat.mjs` does not call this module for a reply — it
synthesizes one directly from `sourceCoverage.length` and the twelve source ids, and the message itself only
feeds the `capabilities.search` query inside the demonstration plan it proposes. See
[chat sessions](chat-session.md) for how that plan is built and run.
