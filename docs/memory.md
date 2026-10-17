# Persistent memory

`memory.promote` (`write`-effect) and `memory.recall` (`read`-effect) in `src/builtins.mjs`
implement Hermes's persistent-memory role — and, more directly, they implement the design
`docs/architecture.md` already described before either tool existed: "Promotion is a separate
write under an exact grant, keeping learned text from becoming authority." `memory.candidate`
(`pure`-effect, pre-existing) produces an inert, unexecuted proposal; these two tools are what
actually persists and later recalls one.

## memory.promote

Input is exactly `memory.candidate`'s own output shape: `{version, lesson, evidenceHashes[],
status, executable, candidateHash}`. The tool recomputes the digest of every field except
`candidateHash` and rejects the call if it doesn't match — a candidate cannot be promoted under a
hash that doesn't actually correspond to its content.

Storage is one file per promoted record, named by its content digest, under a fixed `memory/`
subdirectory of the workspace: `memory/<candidateHash>.json`. This reuses `files.write`'s
exclusive-create discipline unchanged. Because the filename is content-derived, resubmitting the
exact same candidate is an idempotent no-op (the existing file's content is compared byte-for-byte
before accepting the "already exists" case as success) rather than an `EEXIST` error — the same
pattern `scripts/chat.mjs`'s own evidence writer uses for the identical reason. A colliding
filename with *different* content — which would mean a hash collision or tampering — fails closed.

Like every `write` effect, this needs an exact request-hash grant through the kernel before it
runs; an unapproved promotion blocks exactly like an unapproved `files.write`.

## memory.recall

Input is `{query, limit?}`. It lists `memory/`, reads each entry through the same TOCTOU-safe
bounded read `artifact.inspect` and `files.read` use, re-validates each one's schema and digest,
and scores lexical overlap between the query and the lesson text (the same tokenize-and-score
approach `skills.rank`/`capabilities.search` already use), returning results ranked by score with a
deterministic tie-break on `candidateHash`. Reading an absent `memory/` directory returns an empty
result, not an error.

A non-conforming entry — wrong schema, a digest that doesn't match the content, a symlinked or
hard-linked file (rejected identically to every other read-effect tool here) — does not fail the
whole call; it's counted in `corruptedEntries` and excluded from `results`. The total entry count
is bounded (`OUTPUT_LIMIT`) so an oversized store fails closed rather than scanning without end.

Live chat uses the top relevant lesson as bounded, explicitly untrusted reference data in the model's
user payload, with its candidate hash and truncation flag. Promotion makes it durable; it never makes
it a system instruction or grants tool authority. See the [first supervised training round](training-round-001.md)
for a real evidence-linked promotion and replay.

## What is and isn't covered

- **Covered, tested:** digest verification on promote, idempotent resubmission, a planted symlink
  named `memory` rejected rather than followed, the exact-grant gate through the kernel (blocked
  without approval, completes once approved, replay repeats neither the digest check nor the
  write), empty/absent store handling, ranked recall with a deterministic tie-break, bounded entry
  count, non-conforming and hard-linked entries counted as corrupted without breaking recall.
- **Not covered:** this is local, per-workspace storage — there is no cross-session index, no
  sharing between workspaces, and no automatic promotion. A memory candidate only becomes durable
  when a caller explicitly approves its `memory.promote` grant.
