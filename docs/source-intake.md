# Source intake

The ten repository URLs were acquired as original GitHub source ZIPs at the exact revisions in `sources.lock.json`. The two website URLs supply separately cited interface/instruction research; proprietary hosted datasets and service internals are not implied by a public repository license.

Acquisition completed with **82,092 files**. The generated catalog contains **4,884 feature/reference records** and **1,330 `SKILL.md` file entries**. These counts include upstream fixtures, snapshots and bundled copies; they are not a count of unique tested Concord features or individually reviewed skills.

- `upstream/manifest.json` records each repository, commit, archive SHA-256, size, file count and symlinks materialized as inert text.
- `upstream/archives/` retains all original source archives.
- `upstream/<owner>--<repo>/` retains the extracted source corpus.
- `upstream/files.sha256.json` records every acquired file's path, byte length and SHA-256.
- `capabilities.lock.json` indexes skills, agent/command/plugin documents and README/documentation headings as untrusted data.
- `instructions/manifest.json` identifies the reviewed source-derived instruction modules actually used in chat.

No upstream code, hooks, install scripts or tests were executed. Concord's own tests use an explicit allowlist of test files so discovery cannot reach the acquired corpus. Original licenses remain in their source trees. Git history, Git LFS object contents, submodules, recursively linked projects and premium service content are outside source archive acquisition.

To reproduce source acquisition on Windows, run `./scripts/acquire-upstreams.ps1` from a trusted checkout. It makes bounded HTTPS archive requests and never executes downloaded code. Respect upstream rate limits; the original run backed off before resuming after one GitHub rate-limit response. Rebuild the searchable index with `node scripts/catalog-upstream.mjs`. Updating any source pin or inventory changes the context identity and requires new exact grants.
