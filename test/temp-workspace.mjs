import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after } from 'node:test';

/**
 * Scratch directories that are removed when the test file finishes.
 *
 * Every test file used to call fs.mkdtempSync directly, and most never removed what they created:
 * artifacts.test.mjs alone opened fifty-three workspaces and cleaned up eleven. Three days of
 * ordinary `node --test` runs had left several thousand concord-artifacts- and concord-memory-
 * folders in the system temp directory, and nothing in the suite would ever notice, because a
 * leaked directory makes no test fail.
 *
 * Registering the cleanup here rather than in each test is what makes it hard to get wrong. A
 * per-test `t.after` has to be remembered at every call site — fifty-three of them in one file —
 * and the ones that were remembered were the minority. One root-level hook per file cannot be
 * half-applied.
 *
 * Deliberately not per-test: some tests hand a workspace to a later test in the same file, so
 * directories live until the file is done rather than until the test that made one returns. The
 * runner gives each file its own process, so this module's state is never shared between files.
 *
 * Removal is best-effort. A directory a live child process still holds open cannot be unlinked on
 * Windows, and failing a green test run over tidying up would be the wrong trade — the same
 * reasoning the training harness applies to its own scratch directory.
 */
const created = [];

after(() => {
  for (const directory of created.splice(0)) {
    try { fs.rmSync(directory, { recursive: true, force: true }); }
    catch { /* best effort: see above */ }
  }
});

/** A fresh scratch directory under the system temp directory, cleaned up with the file. */
export function tempDir(prefix) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  created.push(directory);
  return directory;
}

/** The same, with symlinks resolved — what a workspace root needs on macOS and Windows. */
export function realTempDir(prefix) {
  return fs.realpathSync(tempDir(prefix));
}
