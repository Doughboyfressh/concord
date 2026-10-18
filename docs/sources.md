# Sources and local skill snapshots

`sources.lock.json` records the twelve references originally requested for this harness,
plus `hermes-local`, a locally installed hermes build catalogued separately from the pinned
`hermes-agent` revision. Eleven
repository entries name full forty-character Git commits. The two hosted websites
are explicitly unpinned mutable observations. `observedOn` is audit metadata written
into the file; source tools never read the clock. No repository, upstream runtime,
MCP server, SDK, skill collection, or website body is installed by this catalog.

| Source id | Normalized role | Integration boundary |
| --- | --- | --- |
| `ecc` | Workflow, skills, evaluation guidance | Reviewed instruction snapshots |
| `ego-lite` | Agent runtime and orchestration reference | Explicit runtime adapter |
| `rea` | Reverse engineering | Explicit analysis adapter |
| `twentyfirst-repository` | UI assets and registry protocol | Reviewed component snapshots |
| `twentyfirst-website` | Hosted UI discovery | Recorded network acquisition |
| `vercel-skills` | Skill discovery and distribution | Reviewed SKILL.md snapshots |
| `orca` | Browser automation and testing | Explicit browser adapter |
| `typesafe-docs` | Typed contracts and evaluation reference | Hosted documentation reference |
| `hermes-agent` | Agent runtime, skills, memory | Explicit runtime adapter |
| `hermes-local` | Tool contracts, skills, least-authority posture | Static surface inventory |
| `deepseek-harness` | Harness and evaluation reference | Explicit runtime adapter |
| `awesome-cyber-skills` | Security practice environments | Reference catalog only |
| `awesome-hacking` | Security resource index | Reference catalog only |

The `hermes-local` entry is an inventory of a hermes installation on this machine, acquired by
static analysis without running it: see [taking the hermes capability surface](hermes-local.md).

The lock includes the original normalized URL, canonical primary links, revision,
license scope and caveat, capabilities, and integration status for each entry.
The two security lists are links and descriptions, not executable agent skills.
Repository licensing does not license the independent projects linked by a list.
The 21st application repository's MIT license does not blanket-license community
components. Individual assets, skills, dependencies, targets, and remote services
must retain their own license and access metadata when acquired.

## API

```js
import { loadSourceLock, makeSourceTools } from './src/sources.mjs';

const sourceLock = await loadSourceLock('./sources.lock.json');
const registry = new Map(makeSourceTools(sourceLock).map(tool => [tool.name, tool]));
```

`loadSourceLock(path)` is an explicit bounded startup read. It accepts strict UTF-8
JSON without duplicate keys, validates unique source ids and immutable repository
pins, and rejects websites presented as pinned repositories. A lock is at most
1 MiB. `makeSourceTools(lock)` performs no filesystem or network reads. It copies
the lock and binds both tool descriptors to its canonical JSON digest using
`config.sourceLockDigest`.

`sources.catalog` version `1.0.0` is pure. Input is `{}` or
`{"sourceId":"ecc","role":"skills"}` with either filter optional. Unknown source
ids fail; role filters return the matching catalog entries sorted by id. Results
are independent JSON copies. Catalog membership is provenance metadata and does
not grant permission, establish trust, or assert installation.

`skills.snapshot` version `1.0.0` is a read effect. Input is:

```json
{"path":"skills/example","sourceId":"ecc"}
```

`path` selects a directory containing a root `SKILL.md`, or a `SKILL.md` file. A
directory captures all regular text files recursively; selecting the file captures
only that file. `sourceId` must be known. It binds the supplied provenance claim to
the catalog's exact revision or mutable website marker. The reader does not prove
that local bytes came from upstream, so output states `binding: caller-declared`,
`upstreamVerified: false`, `trust: unreviewed-data`, and `executable: false`.

Every file contains its relative path, exact UTF-8 text, raw byte length, and
lowercase SHA-256 of the original bytes. Files use portable forward-slash paths
and a fixed code-unit ordering. `SKILL.md` must provide nonempty `name` and
`description` frontmatter. Plain scalar text, JSON-style double quotes, YAML single
quotes, and basic `|`/`>` text blocks are supported for these fields. This is a
metadata extractor, not a general YAML interpreter. Hooks and scripts may be
captured as text; they are never evaluated, imported, sourced, or executed.

## Digests and verification

`snapshotDigest` is lowercase SHA-256 of canonical JSON for precisely:

```js
{ schemaVersion: 1, provenance, metadata, files }
```

The returned `digestAlgorithm` is `sha256-canonical-json-v1`. Local folder placement,
summary counts, and trust labels are not part of this identity. Provenance,
metadata, file names, raw hashes, byte counts, and content are included. Identical
bundles with the same provenance produce the same digest in different folders;
changed content or a changed source claim produces a different digest. Raw file
`sha256` hashes and the canonical JSON snapshot digest are distinct hash domains.

An optional `expectedDigest` containing a trusted prior snapshot digest makes
capture fail on mismatch:

```json
{"path":"skills/example","sourceId":"ecc","expectedDigest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
```

This compares the complete snapshot identity. It is not a signature, upstream
attestation, or automatic trust promotion. Acquiring or approving skills is a
separate operation. Replay uses recorded outputs and must never invoke this reader.

## Boundaries

Snapshot paths are relative to `context.workspaceRoot`. Use forward slashes in
PowerShell JSON too. The reader rejects traversal, absolute/drive/UNC paths,
alternate streams, Windows reserved names, trailing dots/spaces, symlinks,
junctions, hard-linked files, special files, Git metadata, and `node_modules`. It checks each ancestor
with `lstat`/`realpath`, uses `O_NOFOLLOW` where supported, compares opened file
identity and timestamps, and rechecks directories after capture.

Node's cross-platform filesystem API has no portable directory-handle-relative
open. These checks detect ordinary traversal and observed races; they are not an
OS sandbox against an adversary continuously replacing workspace ancestors. Use a
quiescent workspace or external filesystem isolation for adversarial concurrent
writers. A normal snapshot does not establish that untrusted instructions are safe.

Limits are 128 files, 256 directory entries, depth 12, 256 KiB per file, and a total
read bound derived from `policy.maxOutputBytes`. The complete serialized JSON output
must also fit `maxOutputBytes` (default 1 MiB). Invalid UTF-8 and NUL-containing binary
files fail. An abort signal is checked during traversal and bounded reads. Errors
do not return partially read content or arbitrary filesystem error messages.

Run the focused checks with `node --test test/sources.test.mjs`. Link tests are
explicitly skipped when the environment disallows creating links. Run in a host
environment that permits symlinks, Windows junctions, and hard links to exercise
those checks; restricted test runs must not be reported as having covered them.
