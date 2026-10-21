# Building, as an attestation

`makeBuildTools(config)` in `src/build.mjs` registers three tools with three different effects:

| Tool | Effect | What it is for |
| --- | --- | --- |
| `build.detect` | `read` | What build systems this tree contains, with the marker file and its digest as the evidence |
| `build.run` | `process` | Run one reviewed target and return a receipt binding inputs to outputs |
| `build.compare` | `pure` | Read two receipts and separate "the inputs changed" from "the output changed" |

Registration is skipped entirely when `config` is `undefined`. A configuration with **no targets**
still registers `build.detect` and `build.compare`: neither needs an executable, so both stay
useful on a machine that is not permitted to build anything, while a `build.run` that could only
ever refuse would be a capability in name only. Only the tool that starts a process costs an
approval — which is exactly the split an operator wants when permitting a harness to see what a
tree *would* build without permitting it to build.

## build.detect separates "present" from "runnable"

A reviewed marker table (`markers-v1`, named in the output) maps a file to a build system:
`package.json`→npm, `Makefile`→make, `CMakeLists.txt`, `Cargo.toml`, `go.mod`, `build.gradle`,
`build.gradle.kts`, `pom.xml`, `pyproject.toml`, `tsconfig.json`, `global.json`, `build.zig`.

Each system found is reported with its `marker`, that file's `markerSha256` and `bytes`, and the
`entries` this harness **actually read out of the file** — `package.json`'s script names and a
`Makefile`'s targets. Where nothing can be read honestly there is no reader and `entries` is
empty with `entriesRead: false`: a `Cargo.toml` does not list its own build targets, and
pretending otherwise would be the most convincing kind of wrong answer. A marker whose contents
cannot be parsed is still reported as *present* with `entriesRead: false`, because "there is a
package.json here and its scripts could not be read" is a different fact from "there is no
package.json".

`multiple: true` when more than one system is present — the normal real-world case, and the usual
source of a confident wrong guess about which build system a repository "is". It is reported
rather than resolved; choosing for the caller would hide the ambiguity that is the actual finding.
`runnable` lists only the systems that have a reviewed target behind them, and each system row
carries the target names that declare it. Detection says what exists; configuration says what may
run.

Detection looks for markers exactly where it was asked — the root, or an optional relative
`directory` — and never searches. A search would find the build system of a vendored dependency
and report it as this project's.

## build.run returns a receipt

Input is `{target, expectArtifactsSha256?}`, where `target` is an **enum generated from the
configured target names**. There is no executable, args, cwd or env field anywhere in the schema,
so a plan selects a build that was reviewed rather than describing one — the invariant
`process.run` already holds: argv comes only from reviewed configuration, never from a plan or a
model.

One call produces:

- `inputs` — every declared input file with its digest and size, sorted, and `inputsSha256` over
  that list **together with the declared path list**. Digested *before* the child runs, so the
  receipt describes what was compiled rather than whatever the tree looks like afterwards. An
  input set exceeding the file bound is refused `BUILD_INPUT_LIMIT` rather than truncated: a
  digest silently covering a prefix of the inputs while claiming to cover all of them is worse
  than no digest. Links are skipped and counted in `inputsSkipped`, so the digest describes
  exactly what the walk read.
- `artifacts` and `artifactsSha256` — the same, digested *after* the run. The declared list is
  inside the digest too, so a target asked for an artifact it never produced does not hash the
  same as a target asked for no artifacts at all; otherwise a build that produced nothing would
  look perfectly reproducible against one that was never asked to produce anything.
- `exitCode`, `signal`, `ok`. **A non-zero exit is the result, not an exception.** This is why
  `build.run` does not reuse integrations' `spawnBounded`, whose contract is to reject on any
  non-zero exit: that would discard the diagnostics of every failing build, which is the case that
  matters most. A child killed by a signal reports `exitCode: -1` with `signal` carrying the
  detail, so its receipt stays comparable.
- `diagnostics` — structured, each with `severity`, `code`, `message`, `line`, `column`, the
  reported `file`, its `workspacePath`, and **`fileSha256`: the digest of that file as the build
  saw it**. A diagnostic is a claim about a file at a moment; recording the digest is what makes
  the claim checkable later, so a diagnostic that outlived its file can be shown to be stale
  without rebuilding. A path outside the workspace or one that cannot be read gets a null digest
  rather than a fabricated one. `diagnosticCounts` tallies by severity.
- `stdoutSha256`/`stderrSha256` with `stdoutBytes`/`stderrBytes` and a bounded `stdoutTail`/
  `stderrTail` — the digest covers the whole stream, the tail is what a human reads. Output past
  the budget sets `truncated: true` rather than failing the build: a compiler emitting ten
  thousand warnings has still told you its exit code.
- `argv` — the executable's **basename** plus the reviewed args. The configured path is never
  echoed back; it belongs to the configuration, not to the result.
- `receipt` — the digest of `{target, argv, executableSha256, inputsSha256, artifactsSha256,
  exitCode}`. The same inputs through the same reviewed toolchain produce the same receipt.
- `reproduced` — `null` when nothing was claimed; otherwise whether the artifacts matched
  `expectArtifactsSha256`. A rebuild that was asked to match and did not reports `false` **as a
  value**, with the build still reported as having succeeded: that is a finding that needs its
  diagnostics and both digests, not an exception that discards them.

The executable guard is literally integrations' own `resolveExecutable` and `processEnv`, reused
rather than reimplemented — realpath, regular file, workspace-contained cwd, mandatory digest
match. It therefore reports `INTEGRATION_EXECUTABLE`/`INTEGRATION_CWD`/`INTEGRATION_PATH`, and
keeping those codes is the point: one guard, one set of codes, nothing to drift. A parallel
implementation with prettier codes would be the more dangerous choice.

### Diagnostic matchers

`diagnostics` in a target's configuration names one reviewed matcher: `gcc-v1` (gcc/clang),
`tsc-v1`, `msvc-v1`, `rustc-v1`, `node-uncaught-v1`, or `none`. Matchers are code, not
configuration: a caller cannot supply a pattern, because a pattern supplied per call could claim
any `file:line` it liked and the diagnostic would still be reported as the compiler's. Every
matcher is fed LF-normalised text.

`node-uncaught-v1` is worth describing, because node's own first line lies about location. An
uncaught assertion heads its stack with `node:internal/modules/run_main:107`, and the file the
operator edited appears only in the first non-internal **stack frame**. So the matcher takes the
frame, falls back to the header only when the header is not itself inside node, and reports **no
location at all** when every frame is internal — a location inside node points at the wrong code
far more convincingly than a null does. Three things in these matchers were wrong on first contact
with real compiler output and were fixed by running one rather than reading about one: a path
character class excluding colons matched nothing on `file:///C:/…`; an optional `functionName (`
prefix excluding only parentheses matched *across* the line break and consumed the next frame's
paren, so a stack whose first frame was the operator's file matched only the node frame; and
requiring a prefix before `Error|Exception` silently missed every plain `Error:`.

## build.compare asks the two questions a pass/fail cannot

Given two receipts — a whole `build.run` result is a valid receipt, so a plan can wire
`{"$task": "before"}` straight in — it reports `inputsChanged` and `artifactsChanged` and the
verdict that follows from the pair:

| Inputs | Artifacts | Verdict |
| --- | --- | --- |
| same | same | `identical` |
| changed | changed | `changed` |
| changed | same | `inputs-changed-output-did-not` — the edit never reached what was built |
| same | changed | `nondeterministic-build` — not reproducible from its declared inputs |

The last two are invisible to a harness that only knows whether the build succeeded, and the last
one is the one no amount of rerunning a build will tell you about.

The exit-code transition — `still-succeeding`, `still-failing`, `broken`, `fixed` — is reported on
its **own axis** rather than folded into the verdict, because "the build now fails" and "the build
is not reproducible" are independent findings and a single score would hide whichever one it did
not name. Like `experiment.compare`, this deliberately emits no aggregate.

## What is and isn't covered

- **Covered** (`test/build.test.mjs`, 16 tests, 1 skipped; `scripts/train-exercises-build.mjs`, 18
  training exercises; and an end-to-end CLI run in which Concord built itself under the approval
  gate — two grants, 38 input files digested, `build.compare` reporting `identical`, replayed to
  the same root, and replay *refused* once the reviewed args changed): detection with entries read
  from real marker files, detected-versus-runnable, an unparsable marker, an empty tree, a
  path-escaping directory, a successful build's receipt, receipt stability across two identical
  runs, `reproduced` true and false, the declared-but-missing artifact digest, a failing build's
  diagnostics bound to the input set's own digest, a timeout, a digest mismatch, the read/process
  effect split, a skipped symlink, every matcher against measured output with and without CRLF,
  and all four verdicts with all four transitions.
- **Not covered:** incremental-build awareness (every run digests the whole declared input set),
  dependency-graph discovery (the input set is declared, not inferred from includes or imports),
  parallel targets in one call (`process.runMany` exists for concurrency), build caching, and
  toolchains that need an interactive terminal.
- **Residual, disclosed:** the receipt attests the inputs *declared* for the target, not every
  file the compiler actually opened — a build reading a header outside the declared set is not
  covered by its own digest, and the declaration is the operator's responsibility. Artifacts are
  digested after the process exits, so a toolchain that writes asynchronously after exit is not
  described correctly. `build.run` inherits every disclosure the `process` effect carries: an
  effect declaration is a contract, not an OS sandbox.

## Configuration

```json
{
  "timeoutMs": 120000,
  "maxOutputBytes": 1048576,
  "targets": [
    { "name": "check", "system": "npm",
      "executable": "C:/Program Files/nodejs/node.exe",
      "executableSha256": "…64 hex characters…",
      "args": ["scripts/check.mjs"],
      "diagnostics": "node-uncaught-v1",
      "inputs": ["src", "scripts"], "artifacts": [] }
  ]
}
```

`executable` must be an absolute path and `executableSha256` is **mandatory** — unlike
`browser.snapshot`, where it is optional because browsers update often. A build receipt without a
pinned toolchain would attest that some compiler at that path produced those bytes, which is a
claim about a filename rather than about a program. `args` are fixed strings (at most 64), `cwd`
is relative to the workspace, and `inputs`/`artifacts` are unambiguous relative workspace paths —
an escaping or absolute path is refused `BUILD_CONFIG` at registration, because the input set is
what the receipt attests over.

See `examples/build.example.json`, `examples/build.plan.json` and `examples/build.policy.json`.
Pass the configuration with `--build FILE` to `src/cli.mjs`, `src/mcp.mjs` or the chat server.
