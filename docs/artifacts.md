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
4. For ELF, also walks the Program Header Table to the `PT_DYNAMIC` segment and lists `DT_NEEDED`
   entries — the shared library names the dynamic linker itself would load, as plain strings
   (`elf.neededLibraries`). For PE, also walks the Optional Header's Data Directory to the Import
   Directory Table and lists the imported DLL names (`pe.imports`). Both are **static**: the same
   bytes a real loader would read, never executed, never loaded — see the dedicated section below
   for why this is the deliberate line this tool does not cross.

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

Section/symbol count fields (ELF's `sectionCount`, PE's `sectionCount`) and the newer
program-header/section-table counts used to locate the dynamic/import tables are **always bounded
independently of their own reported value** — `MAX_PROGRAM_HEADERS` (64), `MAX_SECTIONS` (96),
`MAX_DYNAMIC_ENTRIES` (500), `MAX_IMPORT_DESCRIPTORS` (200), and `MAX_NEEDED_LIBRARIES` (200) cap
iteration regardless of what the file itself claims, and every individual field read inside those
loops still goes through the same bounds-checked `readUint`/`readCString` — there is no code path
where an attacker-controlled count field causes an unbounded loop, and a crafted or truncated
dynamic/import table degrades to an empty list, never a crash.

## Runtime behavior tracing: rejected, a deliberate permanent boundary

Concord's own live agent, asked what capability would help it most, proposed running an artifact
in a sandbox to trace its actual behavior (network calls, file access, process spawning). This was
researched and **rejected outright**, not deferred. Two independent reasons:

1. **It isn't buildable honestly here.** Real behavior tracing needs OS-level syscall
   interception (ptrace/strace, ETW) or a real sandbox (gVisor, Firecracker) — none of which exist
   as a Node built-in, and AGENTS.md's contract is Node built-ins only, zero npm dependencies,
   ever. The only Node-native path to "observe behavior" is `child_process` — i.e. `process.run`,
   whose own documentation already discloses the ceiling: it "enforce[s] transport restrictions
   but [is] not an operating-system sandbox." Any "tracing" assembled from Node built-ins alone
   would be cosmetic — logging only what the harness's own wrapper happens to see — dressed up to
   look like confinement it does not actually provide.
2. **It inverts this tool's founding axiom.** `artifact.inspect` exists specifically to read bytes
   *without ever executing them*. Tracing requires running an unreviewed, potentially malicious
   artifact as a subprocess with only `process.run`'s already-disclosed non-sandbox guarantees —
   not "artifact.inspect plus a feature," but a different tool with the opposite threat model
   wearing the same name. That crosses a sharper line than the other deliberate boundaries already
   documented in this project (DSH runtime plugin hot-swap, a persistent cross-call browser
   session): those were about preserving determinism/replay; this one is about not executing
   untrusted code at all.

The static import/`DT_NEEDED` enumeration above is the safe alternative that answers the real
underlying need — real "what does this artifact link against" signal — without ever running the
artifact.

## What is and isn't covered

- **Covered, tested:** SHA-256 correctness, magic-byte identification for every table entry,
  correct field extraction for hand-built minimal ELF32/ELF64/PE fixtures, truncated-header
  degradation for both ELF and PE, a huge section/program-header/section-table count causing no
  crash or unbounded loop, empty files, oversized files failing closed on the read budget (not
  silently truncating and hashing the wrong bytes), arbitrary non-UTF-8 binary content (this tool
  never attempts text decoding), symlinked files rejected identically to `files.read`. ELF
  `DT_NEEDED` and PE import-table enumeration are each verified against a real local binary (a
  real ELF64 shared library and a real small PE executable), not only hand-built fixtures, and
  their parsing spec was independently cross-checked in a second implementation before being
  written here.
- **Not covered:** any format beyond the fixed magic-byte table gets identification + hash only;
  no export-table parsing, section *name*-string-table walking, symbol table parsing, or
  disassembly of any kind exists for any format, including ELF and PE. Dynamic/runtime execution
  tracing is not a gap — it is explicitly rejected, see above.
