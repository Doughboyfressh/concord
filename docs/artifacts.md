# Artifact inspection

`makeArtifactTools()` in `src/artifacts.mjs` registers `artifact.inspect`, a `read`-effect tool. It
is REA's reverse-engineering role implemented natively, scoped to identification and basic header
inspection — not a decompiler, disassembler, or a port of REA's own analysis engine.

## What it does

Given `{path}` (a workspace-relative path, same convention as `files.read`), it reads the file
once via `src/workspace-fs.mjs`'s TOCTOU-safe bounded read (the same identity-pinning discipline
`files.read` uses — stat before opening, pin identity on the open descriptor, bounded read loop,
re-check identity and metadata after), then from that single in-memory buffer:

1. Computes its SHA-256.
2. Identifies its format from a fixed magic-byte table (ELF, PE via its `MZ` + `PE\0\0` signature,
   Mach-O in all four 32/64-bit, big/little-endian variants, ZIP/JAR, PNG, gzip, PDF).
3. For ELF and PE specifically, hand-parses the fixed-size header: class, data encoding, type,
   machine, entry point, and section count for ELF; machine, section count, timestamp, and entry
   point for PE.

Unrecognized formats return identification (`"unknown"`) and the hash as a success, not an error —
this tool's job is identification and basic structure, not gatekeeping.

## Bounds-checked by construction, not by convention

Every multi-byte field read — including PE's `e_lfanew`-derived signature offset, which comes
from the file's own content — is checked against the actual remaining buffer length before the
read happens (`readUint()` returns `undefined` rather than throwing when a header would read past
the end of the buffer). A file truncated right after its magic bytes degrades to a partial result
(e.g. ELF's `class`/`dataEncoding` with `truncatedHeader: true`) instead of an uncaught
`RangeError`. A PE whose `e_lfanew` points past the end of the file is identified as `"mz-dos"`,
not `"pe"` — no PE-specific fields are reported at all once the signature can't be confirmed in
bounds.

Section/symbol count fields (ELF's `sectionCount`, PE's `sectionCount`) are **only ever reported as
data**, never used to drive a parsing loop over that many sections — there is no code path where an
attacker-controlled count field causes an unbounded loop or allocation.

## What is and isn't covered

- **Covered, tested:** SHA-256 correctness, magic-byte identification for every table entry,
  correct field extraction for hand-built minimal ELF32/ELF64/PE fixtures, truncated-header
  degradation for both ELF and PE, a huge section count causing no loop, empty files, oversized
  files failing closed on the read budget (not silently truncating and hashing the wrong bytes),
  arbitrary non-UTF-8 binary content (this tool never attempts text decoding), symlinked files
  rejected identically to `files.read`.
- **Not covered:** any format beyond the fixed magic-byte table gets identification + hash only;
  no section/symbol table walking, string table parsing, import/export table parsing, or
  disassembly of any kind exists for any format, including ELF and PE.
