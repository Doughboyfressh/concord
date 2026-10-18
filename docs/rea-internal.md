# Taking REA's capabilities internally

REA (`morluto/rea`, MIT, revision `1b97b0f3`) is a reverse-engineering CLI and MCP server: 117
declared tools across native, managed, Android, JavaScript, Electron, firmware, EVM, WASM and
browser targets. All 117 are now internal Concord tools: Concord owns every contract, input
schema, bound, effect, approval gate and journaled receipt. This records how, by which of two
realization routes, and what each route does and does not give you.

## The surface, classified

Every tool REA declares calls `toolContractMetadata("<name>")`, so the list is recovered from the
pinned clone during cataloguing rather than by a separate acquisition step.

| | Count |
| --- | --- |
| declared REA tools | **117** |
| realized by an internal reader (`static`) | **49** |
| realized by a reviewed provider (`provider`) | **68** |
| static readers written | **49 of 49** |
| entries with no realization route | **0** |

Each entry carries an `effect`, an `effectBasis` naming the rule that assigned it, an
`internalizable` flag, and `implementedBy` where a Concord tool now provides the capability.

## What became native

| REA tool | Concord tool | Effect |
| --- | --- | --- |
| `inspect_wasm_artifact` | `artifact.wasmInterface` | `read` |
| `compare_wasm_interfaces` | `artifact.compareWasmInterfaces` | `pure` |
| `inspect_evm_interface` | `artifact.evmInterface` | `read` |
| `inspect_binary_layout` | `artifact.inspect` (already present) | `read` |
| `inspect_sqlite_database` | `artifact.sqlite` | `read` |
| `inspect_packet_capture`, `inspect_pcap_capture` | `artifact.pcap` | `read` |
| `inspect_packet_fields` | `artifact.packetFields` | `read` |
| `inspect_pe_resources` | `artifact.peResources` | `read` |
| `inspect_go_binary` | `artifact.goBuildInfo` | `read` |
| `inspect_android_package` | `artifact.apk` | `read` |
| `inspect_android_class` | `artifact.dexClass` | `read` |
| `inspect_android_method` | `artifact.dexMethod` | `read` |
| `search_android_classes` | `artifact.dexSearch` | `read` |
| `trace_android_references` | `artifact.dexReferences` | `read` |
| `decode_android_resources` | `artifact.androidManifest` | `read` |
| `project_android_application_graph` | `artifact.dexGraph` | `read` |
| `inspect_managed_artifact` | `artifact.managed` | `read` |
| `inspect_managed_members` | `artifact.managedMembers` | `read` |
| `compare_managed_members` | `artifact.compareManagedMembers` | `pure` |
| `inspect_managed_native_boundaries` | `artifact.managedNativeBoundaries` | `read` |
| `verify_managed_native_boundaries` | `artifact.verifyManagedNativeBoundaries` | `pure` |
| `project_managed_application_graph` | `artifact.managedGraph` | `read` |
| `import_managed_reconstruction` | `artifact.importManagedReconstruction` | `pure` |

Every reader is zero-dependency and deterministic, which is what makes it replayable. Each was
checked against an independent authority where one exists, and against byte-exact fixtures where
none does.

### SQLite, checked against SQLite

`artifact.sqlite` reads the documented header and the `sqlite_master` records on page 1. The oracle
is the engine itself, through Node's built-in `node:sqlite`: the reported schema must equal what
`SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master` returns, and the header fields must
equal `PRAGMA page_size`, `encoding`, `user_version`, `page_count` and `schema_version`. All six
comparisons match on a database carrying two tables, two indexes, a view and a trigger.

That oracle earned its place immediately. `rootpage` came back `null` for every table, because the
existing `readUint` helper supports only sizes 2 and 4 and **falls through to a 64-bit read for
anything else** — so asking it for SQLite's 1-byte signed serial type silently read eight bytes and
returned a string. A dedicated signed big-endian reader fixed it. An expectation written by hand
would likely have been written to match the wrong output.

A record whose payload overflows its page is reported rather than chased through the overflow
chain, because a partly reassembled record is indistinguishable from a complete one in the output.
A page size that is not a power of two is refused instead of being used to walk the file.

### Captures, PE resources and Go metadata

No second implementation ships with Node for these, so each fixture encodes a distinctive value at
a known offset and the assertion is that the reader returns exactly that — which is what catches an
offset, endianness or layer-walk error:

- `artifact.pcap` recovers byte order and timestamp unit **from the magic** rather than assuming
  them, and the same capture written big-endian yields identical values. A record declaring more
  captured bytes than the file holds stops the sweep with a stated limitation instead of reporting
  a packet count the file cannot support. pcapng is recognised as a different container and
  reported at block level rather than mis-read as classic pcap.
- `artifact.packetFields` walks Ethernet, VLAN, IPv4, IPv6, TCP and UDP. The VLAN case is the one
  that matters: a tag shifts every later layer by four bytes, so a reader that failed to unwrap it
  would report the wrong addresses and ports. A sliced packet reports truncation rather than
  reading past what was captured.
- `artifact.peResources` walks the three-level type/name/language tree, decodes UTF-16LE named
  entries, and maps each leaf's RVA back through the section table to a real file offset. The
  resource type is threaded down to the leaf, since a leaf is three levels below where the type
  is known.
- `artifact.goBuildInfo` reads the inline layout Go has used since 1.18 — version string and
  build settings — and reports the older pointer layout as present but **unresolved**, because its
  strings live in the data section and following them needs the mapping they were written for.

### WASM interface

REA recovers this through WABT, an external toolkit. Concord decodes it from the bytes: the type,
import, function, table and memory sections, with the **function index space reconstructed**
(imports occupy the low indices, then definitions) so an exported function reports its real
signature rather than the wrong one. Entries follow REA's model — `direction`, `module`, `name`,
`kind`, `index`, `signature`, plus a deterministic `wat_form` so a diff reads as text.

Correctness is measured against an independent implementation rather than against an expectation
written here: **Node's own `WebAssembly.Module.imports()`/`exports()`**. Agreement is 4/4 across
the fixtures, each first confirmed legal by `WebAssembly.validate` — a fixture the real engine
rejects would make any agreement vacuous, and an earlier draft of the probe was exactly that
(a function section with no code section, so two of four fixtures were invalid and unchecked).

The comparison tool reports `added`/`removed`/`changed`/`unchanged`/`unknown`. A duplicated name is
`unknown`, never paired arbitrarily: with two same-named imports there is no fact about which
corresponds to which, and inventing a pairing converts an unknown into a confident wrong answer. A
`partial` side raises a stated limitation, because an absence there is not evidence of removal.

### EVM bytecode

REA recovers selectors with bundled EVMole plus a host `prlimit`. That dataflow analysis is **not**
reproduced and **not** claimed. What is returned is what the bytes determine:

- An opcode sweep that **skips PUSH immediates by width** — the difference between reading code and
  reading data that happens to look like opcodes. The regression test puts `63 deadbeef` inside a
  `PUSH32` immediate and requires that `deadbeef` is *not* reported, while a real `PUSH4` in code
  position is.
- **Selector candidates** from PUSH4 immediates, labelled as candidates in `limitations`, because an
  ordinary four-byte constant is indistinguishable from a selector without following the dispatcher.
  Checked against REA's own fixture `60003560e01c630000000014601057005b00`, where EVMole expects
  exactly `0x00000000` — and this reader returns exactly that.
- A **Solidity metadata trailer**, accepted only when the two-byte length prefix addresses a CBOR
  root map that ends exactly where the prefix says. A prefix pointing at anything else is reported,
  not believed, and the trailer is excluded from the swept code region.
- Two **distinct digests**: the carrier identifies the exact file including hex casing and
  whitespace; the bytecode digest identifies the decoded bytes. Neither is Ethereum's Keccak code
  hash. Hex carriers follow REA's strict rules — one optional `0x`, outer ASCII whitespace only;
  odd length, interior separators, a BOM and invalid UTF-8 are rejected.
- EOF (`EF00`) containers return `unsupported_target` by name rather than being decoded as legacy.

One real bug was found by writing the test: the opcode table split `0x50-0x5b` from `0x5f-0x9f`,
which reported `TLOAD`, `TSTORE` and `MCOPY` as undefined opcodes. They have been assigned since
Cancun, making `0x50-0x9f` contiguous. A regression test now pins that.

### Android: DEX, APK and binary XML

`src/dex.mjs`. DEX index tables are read with their own encodings — uleb128 sizes, index deltas,
and **MUTF-8**, which is not UTF-8: U+0000 arrives as two bytes and anything above the BMP arrives
as two three-byte sequences holding surrogates, which a plain UTF-8 decoder rejects outright.
Decoding to UTF-16 code units handles both.

Class members are delta-encoded, so the virtual method in the fixture has index 0 + 1; a reader
ignoring the delta would report the constructor's prototype in its place. That is what the test
asserts, rather than merely that a method was found.

Writing the binary-XML fixture exposed **three real offset bugs** at once. `ResXMLTree_node` is
sixteen bytes, so a start tag's `attributeStart` is measured from the attribute extension rather
than from the chunk; a string attribute's pool index lives in the `data` word, not in the packed
size/type word before it; and a CDATA chunk's index sits immediately after the node header. Each
would have produced plausible-looking wrong output.

### .NET: the ECMA-335 tables

`src/managed.mjs`. The part that cannot be skipped is row sizing. Table rows are variable width —
heap index widths come from the `HeapSizes` byte, simple table indices widen past 65535 rows, and
a coded index widens on the largest row count among the tables it may point at. Reaching table N
means stepping over every table before it, so the schema carries **all** tables including the ones
this reader does not decode. A schema with a gap would silently misread everything after it.

Verified against a real Windows assembly, `NGenTaskLauncher.dll`, and the oracle discipline paid
off twice.

First, the oracle had to be validated before it could be trusted. PowerShell's `Assembly::LoadFrom`
returns an assembly already loaded under the same simple name, so three of six candidates were
silently **shadowed**: for `System.Resources.Writer` the oracle reported version 10.0.0.0 with
eight types while this reader reported 4.0.0.0 with a single TypeDef.
`AssemblyName.GetAssemblyName`, which reads the file manifest directly, confirmed **4.0.0.0** — the
reader was right and the oracle was wrong. Only assemblies whose loaded version equalled their
file version were used as ground truth.

On a validated assembly it then found a genuine bug: nested types. A nested type carries an empty
namespace and names its parent only through the `NestedClass` table, so `Logger+LogLevel` was being
reported as a top-level `LogLevel`. After joining that table, all fifteen type names match
reflection exactly. P/Invoke was correct first time — three boundaries matching `ImplMap = 3`, with
`Win32Native::CreateEvent` resolved to `kernel32.dll` through the `MemberForwarded` coded index.

Two deliberate honesty choices carry through this family. Member signatures live in the blob heap
and are not decoded, so overloads share a name — stated in `limitations`, and the reason a
duplicated key compares as `unknown` rather than being paired arbitrarily. And
`artifact.importManagedReconstruction` accepts a reconstruction only for members the artifact
actually declares, so a reconstruction cannot introduce a member the evidence does not support.

## Correction: replay does not forbid a device-backed tool

An earlier draft of this document claimed that replay requires a tool's output to be a pure
function of its declared input, and used that to exclude 66 tools as impossible to internalize.
**That was wrong.** `replayPlan` never calls `execute`: for an effectful tool it *takes* the
recorded value and asserts legality properties of it, which is why `process.run`,
`browser.snapshot` and `dsh.run` already replay despite being non-reproducible. Purity is required
of `pure` and `read` tools, not of the `process` effect.

The real constraint is narrower and different: Concord cannot *reimplement* adb's protocol stack
or Ghidra's decompiler in Node built-ins. Neither does REA — it invokes the same provisioned
binaries. So those tools are internal in the sense that matters: Concord owns the contract, the
input schema, the bounds, the effect, the approval gate and the journaled receipt.

## The capability compiler

`reverse-tools.json` is the contract table, generated from the pinned clone during cataloguing so
the tool list has one source of truth rather than a transcription that can drift. `src/reverse.mjs`
compiles it into live tools by one of two routes:

| Route | Count | How |
| --- | --- | --- |
| `static` | **51** | an internal reader in `src/artifacts.mjs` |
| `provider` | **66** | a bounded single call to an operator-reviewed executable, `process` effect |

Nothing is registered that cannot run. With no provider provisioned, the only registered tool is
`rea.catalog` — a `pure` tool reporting all 117 entries with their provider, realization and
availability, so the surface stays discoverable without pretending to be executable. Provisioning
adb registers its 24 tools; provisioning Frida registers its 8. A static capability is reported by
the catalog but registered in `src/artifacts.mjs`, so no capability exists twice under two names.

### argv shape is the operator's, values are the plan's

This carries over `processRun`'s invariant, which exists because a plan that could choose argv
could run anything the executable can do. A reviewed template may open `{placeholder}` slots:

```json
{ "name": "adb", "executable": "/usr/bin/adb", "executableSha256": "...",
  "commands": { "inspect_adb_package": ["-s", "{serial}", "shell", "dumpsys", "package", "{package}"] } }
```

- The **slots the operator wrote determine the tool's input schema**, so a plan cannot reach a slot
  that was never opened. An undeclared field fails as `SCHEMA_MISMATCH` before any argv is built.
- Each value must match a fixed pattern for its slot, and **no value may begin with `-`** whatever
  its pattern allows: an argument that looks like an option changes the meaning of the operator's
  command rather than supplying data to it.
- A `{path}` slot is **resolved for workspace containment** rather than pattern-matched, because
  containment is the property that matters for a path.
- There is no shell. Arguments are passed as an array to the one audited `spawnBounded` already
  used by `process.run`, now shared rather than duplicated.
- The reviewed template's digest is in the tool's `config`, so it is bound into the approval hash:
  changing the operator's command invalidates an approval granted for the previous one.

Tested: option injection, an embedded space, shell metacharacters and a newline are each refused as
`REVERSE_INPUT`; `../` and absolute paths as `PATH_DENIED`; a command naming an unknown tool, a
command belonging to another provider, an unknown slot and an empty template each refused as
`REVERSE_CONFIG` at registration.

## Correction: two tools were classified static and are not

An earlier pass counted 51 internalizable tools and 66 provider-backed. Reading REA's own
documentation rather than trusting the name-based rule changed that to **49 and 68**.
`decode_signal_recording` drives caller-supplied **sigrok-cli** with libsigrokdecode, and
`inspect_signal_decoders` queries the **installed** sigrok catalog. Neither is static analysis, so
both moved to the `sigrok` provider with a basis naming what they need. The rule that misread them
matched on the `decode_`/`inspect_` prefix, which is exactly the kind of plausible inference this
project keeps having to correct.

`inspect_recorded_crash` went the other way. Its documentation lists pwntools, pyelftools and
Unicorn, which looks like a provider dependency, but what those libraries parse is an ELF64 core's
documented note layout. That is byte parsing, so it became `artifact.coreDump`.

## All 49 readers are written

The remaining families, each verified the same way:

| Family | Tools | How it was checked |
| --- | --- | --- |
| Android DEX, APK, binary XML | 7 | byte-exact fixtures; MUTF-8 and uleb128 decoded directly |
| .NET ECMA-335 metadata | 7 | a real Windows assembly, against validated reflection |
| JavaScript, source maps, HAR | 11 | `node:module`'s `SourceMap`, entry by entry |
| Firmware, Rust, Dart, Electron, Apple, Harmony | 8 | documented headers and wire formats |
| Recorded crashes and evidence composition | 6 | ABI register offsets written into the fixture |

Four things found by writing the tests, each a real defect rather than a test adjustment:

- **Three AXML offset bugs at once.** `ResXMLTree_node` is sixteen bytes, so `attributeStart` is
  measured from the attribute extension and not the chunk; a string attribute's pool index lives
  in the `data` word rather than the packed size word; and a CDATA index sits immediately after
  the node header. Each would have produced plausible wrong output.
- **Nested .NET types reported by their bare name.** A nested type carries an empty namespace and
  names its parent only through the `NestedClass` table, so `Logger+LogLevel` was surfacing as a
  top-level `LogLevel`. After joining that table all fifteen type names match reflection exactly.
- **A lazy regex that truncated every XML plist value** to one character, because a lazy body
  followed by an optional closing tag matches as little as possible.
- **A one-byte existence probe that reported every real file as absent.**
  `readWorkspaceFile` refuses a file larger than the limit it is given, so probing with a limit of
  one byte failed for anything bigger. The module graph found no modules at all until resolution
  went through a real read.

### Two oracles that were wrong

Both times the independent authority disagreed with the reader and the reader was right, which is
why the oracle gets validated before it is trusted:

- **A shadowed assembly.** PowerShell's `Assembly::LoadFrom` returns an assembly already loaded
  under the same simple name. For `System.Resources.Writer` the oracle reported version 10.0.0.0
  with eight types while this reader reported 4.0.0.0 with a single TypeDef.
  `AssemblyName.GetAssemblyName`, reading the file manifest directly, confirmed **4.0.0.0**. Three
  of six candidate oracles were shadowed this way; only those whose loaded version equalled their
  file version were used.
- **A carried-forward source map name.** Node's `SourceMap` reports a name on a four-field segment,
  which per Source Map Revision 3 carries none. The regression test *counts* the VLQ fields to
  prove the segment has four, asserts this reader returns `null`, and pins Node's answer too, so a
  later change that "fixes" the divergence is caught.

## What the readers deliberately will not say

Each reader states its own limits in a `limitations` array rather than implying completeness:

- A firmware signature is **evidence of a format, not proof** — those byte sequences occur inside
  compressed data — and a region length is the distance to the next signature, an upper bound.
- Rust, Flutter and bundler identification rest on **embedded strings**, so a stripped build can
  use them and show nothing.
- The JavaScript tools are a **lexical scan, not a parse**; `stripNonCode` blanks comments,
  strings, templates and regexes while preserving offsets so a match cannot fire inside them, but
  no runtime construct is visible.
- A **static fact raises a candidate obligation and never closes one**, and an **inferred
  observation never promotes coverage**, so that case is `unknown` rather than covered.
- `artifact.traceFeature` is a name match over a supplied inventory and says plainly that nothing
  in it establishes that a matched entry implements the feature.
- Secrets are withheld structurally: a script `nonce` is reported as present without its value,
  and HAR header, cookie and body values are never copied, because a capture routinely carries
  credentials.

The 68 provider-backed tools need no further code — each becomes available as the operator reviews
a template for it. That is provisioning, not implementation.

## Using it

The contract table ships with the repository; provider configuration is operator-supplied and
optional. `examples/reverse.example.json` is a starting point — fill in the SHA-256 of each binary
you have actually reviewed, and delete the providers you do not intend to grant:

```
node src/mcp.mjs --workspace <dir> --reverse examples/reverse.example.json
node src/cli.mjs --plan <plan> --reverse <file>
```

With no `--reverse`, `rea.catalog` is the only REA tool registered and the static readers are
available through `artifact.*`. The example as shipped registers nothing, because its placeholder
digests match no binary; that is deliberate, so copying it cannot accidentally grant a provider.

To regenerate the contract table after moving to a newer REA revision:

```
node scripts/catalog-upstream.mjs    # rewrites capabilities.lock.json and reverse-tools.json
```

## Skills and instructions

REA's four skills — `reverse-engineer-anything`, `rea-tool-design`, `rea-ci-tests-audit`,
`rea-changelog-update` — are catalogued as `kind: 'skill'` and reachable through
`capabilities.search`. `instructions/rea.md` gains a statement of which capabilities are internal,
that a `partial` result is not a failure and an absence inside one is not evidence, and that a
scanned selector candidate is not a confirmed interface.
