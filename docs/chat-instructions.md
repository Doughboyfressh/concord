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

This is why `sourceCoverage.length` is always `13`: the reviewed instruction set is not retrieved or ranked per
turn, it is the complete reviewed corpus, every time. Changing an instruction module's text without updating its
manifest digest — or changing which sources are pinned without updating the manifest to match — breaks every
subsequent chat turn until the manifest is regenerated, by design.

### The one part of a module that is selected per turn

A module has two halves with different standing, and only one of them is always included entire.

The reviewed prose is the vetted contract for a source. It is included whole, every turn, which is what the
paragraph above is about. The `<!-- trained:begin -->` section is different: it is written by
`scripts/train-consolidate.mjs` from lessons training has proven, it grows as training earns more, and no
reviewer wrote it. Those bullets are selected per turn by `boundedByRelevance`, ranked by lexical overlap with
the current message and fitted to a byte budget.

This replaced a cap of twelve lessons per module applied when the file was written, which bounded the wrong
thing — what training was allowed to remember rather than what a turn needed to be told. Measured before the
change: 34 of 228 earned lessons reached the model, and which 34 was decided alphabetically. The cap is now 40
per module and the selection is per question.

Three properties are load-bearing:

- **Bounded.** The payload fits a declared budget regardless of how much training has accumulated. Measured at
  200,000 candidate lessons: the selection still came to 12,204 bytes against a 12,288-byte budget.
- **Deterministic.** Selection is a pure function of the message, the modules and the budget. Scores come from
  lexical overlap, ties break on the lesson's own id, and the kept set is emitted in the modules' own order, so
  the same turn assembles the same prompt byte for byte. This is why compaction here is not a model
  summarisation: a summary is a fresh inference each time, so a replayed run would be verifying itself against
  a context that no longer exists.
- **Declared.** What was dropped is reported, never hidden — the count, the digest of the whole set, and the id
  of each omitted lesson, returned as `trained` alongside the prompt and noted in the module text the model
  sees. An omission is auditable, and because each one is named by id it can be fetched back rather than lost.

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
and `references`. Prior conversation retains a complete run of at most 24 messages and 16 KiB, excluding
the current request supplied separately. Supervisor receipts retain at most eight records and 16 KiB.
Both windows report `omittedCount`, `droppedNewest`, `totalCount`, and a digest of the entire record list.
Records are never cut or summarized. A digest does not give the model access to omitted content. The current
validated proposal is supplied separately for follow-up edits, with a 16 KiB bound and explicit omission
metadata.

The kept run is the newest suffix unless the newest records are individually larger than the whole window,
and those are reported in `droppedNewest` rather than silently folded into `omittedCount`. Until recently
one such record blanked the window entirely: the fill walks backwards from the newest, so it broke on the
first step and returned no records at all, reporting every older record that would have fitted as omitted.
Measured: a plan holding six retrieved slices made a single receipt of roughly 24 KB against the 16 KiB
budget, and the turn was handed `records: []` with all seventeen observations gone, then asked a question
only those observations could answer.

The old rule had a real reason — the envelope could describe only a dropped leading prefix, so keeping
older records in place of a newer one would have shown stale state as though it were current, with no way
to say otherwise. `droppedNewest` is that missing way to say otherwise, so the records that fit are now
kept. The distinction matters to a reader: `omittedCount` is history falling off the back, while a non-zero
`droppedNewest` means *the most recent thing is missing* and the newest record shown is stale. Where the
caller supplies `idOf`, `droppedNewestIds` names them by the same absolute ids `omittedIds` uses, so they
are fetched back through `conversation.turn` exactly like any other omission. An oversized record in the
middle of the set is not a tail, and still counts with the omitted prefix, which is what `omittedCount` has
always meant.

`conversation` additionally reports `omittedIds`: the dropped turns named `turn-N`, in transcript order,
where N indexes the full history. A count says that something is missing; an id is the way back to it.
`conversation.turn` takes up to 32 of those ids and returns the turns verbatim — a `read` effect, so it
needs no grant, and nothing is reachable through it that the turn was not already entitled to be told,
since these are turns of the same conversation. It bounds its own result at 6 KiB, below the 8 KiB an
observation keeps, so a result it accepts is a result the model actually sees; a turn that does not fit
is listed in `deferredIds` and can be asked for next, withheld whole rather than cut. Ids that name
nothing come back in `missing` instead of failing the call. This is the same pair `references.trained`
and `instructions.lesson` already form for the lesson corpus: compaction names what it dropped, and a
separate read fetches it back, so the context stays bounded without the history becoming unreachable.

The transcript reaches that tool through a closure rather than its `config`, which is not a style
choice. `registryManifest` hashes every descriptor's config into the registry digest that binds each
approval hash and each replay check, so a config carrying the history would change on every turn —
invalidating the previous turn's grants and making recorded runs unreplayable. The config declares only
what is stable, and `test/conversation.test.mjs` asserts the digest holds still while the transcript moves.

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

## No model, no turn

A model is required. When no `model.propose` tool is registered, `src/chat.mjs` refuses the turn with
`CHAT_NO_MODEL` before anything is mutated, rather than falling back to a deterministic reply assembled from
the source ids. A harness that answers from its own pure tools when nothing is configured looks like it is
working and is not, and that confusion is the thing this project exists to refuse. The refusal is raised per
turn rather than at startup, so state, runs and receipts stay readable over `/api/*` with no model present.

Both launchers default `--integrations` to `config/concord-live.json` when that file exists, so a machine with
a configured model is live without passing a flag. See [chat sessions](chat-session.md) for how a proposed
plan is built and run.
