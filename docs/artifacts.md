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
   Mach-O in all four 32/64-bit, big/little-endian variants, ZIP/JAR/APK, PNG, gzip, PDF, WASM).
3. For ELF and PE specifically, hand-parses the fixed-size header: class, data encoding, type,
   machine, entry point, and section count for ELF; machine, section count, timestamp, and entry
   point for PE.
4. For ELF, also walks the Program Header Table to the `PT_DYNAMIC` segment and lists `DT_NEEDED`
   entries — the shared library names the dynamic linker itself would load, as plain strings
   (`elf.neededLibraries`). For PE, also walks the Optional Header's Data Directory to the Import
   Directory Table and lists the imported DLL names (`pe.imports`). Both are **static**: the same
   bytes a real loader would read, never executed, never loaded — see the dedicated section below
   for why this is the deliberate line this tool does not cross.
5. For any Mach-O variant, hand-parses the fixed-size header (`cpuType`, `fileType`,
   `loadCommandCount`) and walks the load-command list right after it, collecting
   `LC_LOAD_DYLIB`/`LC_LOAD_WEAK_DYLIB` names (`machO.dylibs`), the `LC_UUID` bytes as a hex string
   (`machO.uuid`), and `LC_SEGMENT`/`LC_SEGMENT_64` names (`machO.segments`) — the same bytes `dyld`
   itself would read, never loaded.
6. For ZIP (and ZIP-family containers — JAR, APK, MSIX all share this structure), locates the End
   Of Central Directory record and walks the central directory to list every entry's name,
   compressed/uncompressed size, and compression method (`zip.entries`) — without ever inflating
   or extracting an entry's actual data.
7. For WASM, walks the module's section sequence (each a 1-byte id plus a ULEB128-encoded size)
   and lists which sections are present and how large each is (`wasm.version`, `wasm.sections`) —
   without ever instantiating the module.

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

The same discipline applies to the three newer formats. Mach-O's load-command walk is capped by
`MAX_MACHO_LOAD_COMMANDS` (512), with `MAX_MACHO_DYLIBS` (200) and `MAX_MACHO_SEGMENTS` (64)
separately bounding collected lists. Reads stay inside the header's `sizeofcmds` region and each
command's declared `cmdsize`; alignment and command-specific minimum sizes are checked. Dylib
strings must terminate inside their command. Missing UUIDs are omitted, preserving strict JSON.
The weak-dylib command is `0x80000018`, as defined by [Apple's loader format](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h).

ZIP's End Of Central Directory search is bounded to 65535 + 22 bytes. Candidate comment lengths
must reach EOF, and the central directory must fit entirely before its EOCD — though not flush
against it, since a spec-legal archive may carry a ZIP64 EOCD record and locator in the gap. What
rules out a signature forged inside a ZIP comment is that a real non-empty central directory
begins with a central-directory file header signature, which is checked. Each complete entry, including its name,
extra fields and comment, must remain inside the declared directory. The walk is capped at
10000 entries; decoded names use at most 1024 input bytes. ZIP64 sentinels and multi-disk metadata
return an `unsupported` marker instead of misleading ordinary sizes. This is bounded listing
under the [PKWARE format](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), not archive
validation or extraction.

WASM's section walk is capped at 128. Section sizes use arithmetic over at most five ULEB128
bytes, with the fifth byte restricted to the unsigned 32-bit range defined by the
[WebAssembly binary format](https://webassembly.github.io/spec/core/binary/values.html). Valid
padded encodings remain accepted. Partial headers return `truncatedHeader`; unsupported module
versions return `unsupportedVersion` without interpreting sections under the wrong version.

`truncated`, `malformed`, `limited`, and `unsupported`/`unsupportedVersion` fields disclose partial
or unsupported inspection where applicable. Successful identification does not establish that a
file is valid or safe, and all returned metadata remains untrusted. Replay records and validates
these JSON results without reopening the artifact.

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
  degradation for ELF, PE, and Mach-O, a huge section/program-header/section-table/load-command/
  entry count causing no crash or unbounded loop, empty files, oversized files failing closed on
  the read budget (not silently truncating and hashing the wrong bytes), arbitrary non-UTF-8
  binary content (this tool never attempts text decoding), symlinked files rejected identically to
  `files.read`. ELF `DT_NEEDED`, PE import-table enumeration, Mach-O dylib/UUID/segment parsing,
  and WASM section-sequence parsing are each additionally verified against a real local binary
  (a real ELF64 shared library, a real small PE executable, a real Mach-O bundle from a node-pty
  prebuild, and a real WASM module from tesseract.js-core), not only hand-built fixtures, and
  every format's parsing spec was independently cross-checked in a second implementation (a
  standalone Python script run against the same real file) before being written here. ZIP's
  entry listing is verified against archives built fresh by the test itself (a genuinely valid
  ZIP — local headers, real CRC-32s, central directory, and EOCD — walked exactly as any unzip
  tool would), including the variable-length cases real writers actually emit: nonzero per-entry
  extra fields and comments (so the skip arithmetic that finds the *next* entry is exercised,
  not just the first) and a trailing ZIP64 EOCD record + locator. Those last two were added after
  checking the parser against a genuinely third-party-written archive on this host, which a
  synthetic-only fixture set had been silently failing on — see the regression note in
  `test/artifacts.test.mjs`. Being hand-built rather than tool-produced is the one place this
  format's coverage is weaker than ELF/PE/Mach-O/WASM's, since no archive of known provenance
  ships with the repo.
- **Not covered:** any format beyond the fixed magic-byte table gets identification + hash only;
  no export-table parsing, section *name*-string-table walking, symbol table parsing, or
  disassembly of any kind exists for any format, including ELF and PE. Mach-O's 32-bit
  `LC_SEGMENT` branch is structurally identical to the 64-bit `LC_SEGMENT_64` path (same `segname`
  offset) but was not separately verified against a real 32-bit file — genuinely 32-bit Mach-O
  binaries are now rare. ZIP64 and multi-disk extensions are not *parsed*: when a 32-bit field
  actually holds its sentinel value (so the real value lives only in a ZIP64 record), the listing
  is refused and disclosed as `unsupported: 'zip64'` rather than reporting a wrong size. The mere
  *presence* of a ZIP64 EOCD record and locator is not treated as unsupported — common writers
  emit both even for small archives whose every 32-bit field is valid, and such an archive lists
  normally. A central directory need not end flush against its EOCD (that gap is where those
  ZIP64 records live), but it must sit at a true file offset: prepended self-extracting stubs,
  which shift every stored offset, are still not supported. ZIP filenames are decoded as UTF-8 regardless of the legacy CP437 flag
  bit — a deliberate simplification, not a spec bug, consistent with this tool's "best-effort,
  untrusted" framing elsewhere. WASM section parsing is identification-only (which sections exist
  and their byte sizes) — no semantic parsing of a section's actual contents (types, exports,
  code) exists. Dynamic/runtime execution tracing is not a gap — it is explicitly rejected, see
  above.

## Upgrade review, 2026-10-16

The unfinished upgrade was reviewed independently and corrected with regressions for false EOCD
signatures in comments, out-of-region Mach-O metadata, the weak-dylib constant, WASM integer
overflow, and strict-JSON results for header-only artifacts. Tests also run inspection through
`runPlan` and anchored `replayPlan`, covering the harness contract beyond direct parser calls.
Synthetic Mach-O commands now have valid alignment; synthetic ZIPs include correct CRCs. Real
Mach-O/WASM fixtures remain conditional on their availability on the host.
