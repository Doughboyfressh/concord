# Upgrade review — 2026-10-16

The supplied `close-concords-self-identified-gaps` transcript described ZIP central-directory, Mach-O
load-command and WASM section parsers awaiting a completed adversarial review. The actual working tree
contained those changes on top of the native browser, memory, process, composition and MCP upgrades.
The review used the current files and preserved the user's implementation.

## Findings fixed

- ZIP EOCD signatures inside comments could conceal a real directory. Candidate lengths and directory
  boundaries are now checked; entry names, extras and comments cannot borrow bytes from outside it.
- Mach-O metadata could come from outside `sizeofcmds` or `cmdsize`. The parser now checks alignment,
  command minima, table boundaries and string termination within each command.
- The weak-library command constant is corrected to `0x80000018`.
- Header-only Mach-O without a UUID and short WASM inputs could contain `undefined` properties that
  failed the harness JSON contract. Partial results now remain valid JSON through capture and replay.
- WASM unsigned section sizes reject fifth-byte overflow while preserving valid padded encodings.
- ZIP64, multi-disk archives and unsupported WASM versions return explicit unsupported markers.

Synthetic Mach-O fixtures now have valid command alignment, and ZIP fixtures have correct CRCs.
Seven added regression tests cover these cases, including end-to-end `runPlan` and anchored replay.
The separate reviewer also caught a ZIP64-sentinel variant of the comment-signature issue. The
search now retains unsupported sentinel candidates only as a fallback while looking for a
coherent ordinary directory, with an added regression case. An independent WASM review found no
remaining high/medium defects in that parser.
The final reviewer reran the sentinel reproducer and confirmed it returns the real entry;
no findings remain from this focused review.

## Validation

`node scripts/validate.mjs` passed syntax checks, **205 tests with 3 skips and no failures**, and CLI
end-to-end capture/replay, exact grants, no repeated writes and tamper rejection. Node.js v24.20.0,
Windows. The skips were two host-disallowed symlink fixtures and a descendant-stdio condition this
host does not reproduce. Real local PE, ELF, Mach-O and WASM fixtures passed; no inspected binary
was executed.

Final evidence: `.agents/evidence/validation-2026-10-17T03-37-32-513Z/` (UTC directory timestamp;
local review date October 16). This full run includes the sentinel-comment regression and the
corrected validator Git metadata, recording the actual branch, head and `origin` remote name.

Changes remain local and uncommitted. No upstream runtime was installed, no artifact was executed,
and no GitHub push or publication was performed. This completes the parser review; it does not
claim a new audit of every previously added native tool or live provider.
