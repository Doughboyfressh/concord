import { constants, openSync, readSync, closeSync, fstatSync, lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { HarnessError } from './value.mjs';

/** Resolve an unambiguous relative path to a real file inside root; reject links, escapes, and reserved names. */
export function workspaceFile(root, relative) {
  if (typeof relative !== 'string' || !relative || relative.includes('\\') || relative.includes(':') || relative.includes('\0') || relative.split('/').some(p => !p || p === '.' || p === '..' || /[. ]$/.test(p) || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p)) || path.isAbsolute(relative)) throw new HarnessError('PATH_DENIED', 'Expected an unambiguous relative workspace path');
  const base = realpathSync(root);
  const target = path.resolve(base, relative);
  if (!target.startsWith(base + path.sep)) throw new HarnessError('PATH_DENIED', 'Path escapes workspace');
  let current = base;
  const parts = relative.split('/');
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    try {
      const stat = lstatSync(current);
      if (stat.isSymbolicLink()) throw new HarnessError('PATH_DENIED', 'Links are not accepted');
      if (i < parts.length - 1 && !stat.isDirectory()) throw new HarnessError('PATH_DENIED', 'Parent is not a directory');
      if (i === parts.length - 1 && !stat.isFile()) throw new HarnessError('PATH_DENIED', 'Expected a regular file');
    } catch (e) { if (!(e.code === 'ENOENT' && i === parts.length - 1)) throw e; }
  }
  return target;
}

/**
 * The same path, resolved for a directory rather than a regular file.
 *
 * workspaceFile insists the final component be a regular file, which is right for every caller
 * it has and leaves a directory with no validated form at all: memory.promote reaches its own
 * folder by joining a module constant, which works precisely because no caller chose that name.
 * A tool that makes, moves or copies on an operator's path cannot do that.
 *
 * Every check above is kept and only the last one differs, so a link anywhere along the path, a
 * traversal, an absolute path, a reserved device name or anything resolving outside the root is
 * refused here exactly as it is there. Duplicating those rules into a tool would be the obvious
 * way to get one of them subtly wrong later.
 */
export function workspaceDir(root, relative) {
  if (typeof relative !== 'string' || !relative || relative.includes('\\') || relative.includes(':') || relative.includes('\0') || relative.split('/').some(p => !p || p === '.' || p === '..' || /[. ]$/.test(p) || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p)) || path.isAbsolute(relative)) throw new HarnessError('PATH_DENIED', 'Expected an unambiguous relative workspace path');
  const base = realpathSync(root);
  const target = path.resolve(base, relative);
  if (!target.startsWith(base + path.sep)) throw new HarnessError('PATH_DENIED', 'Path escapes workspace');
  let current = base;
  const parts = relative.split('/');
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    try {
      const stat = lstatSync(current);
      if (stat.isSymbolicLink()) throw new HarnessError('PATH_DENIED', 'Links are not accepted');
      // Unlike workspaceFile, the last component is a directory when it is there at all. A file
      // already sitting at the name is refused rather than treated as somewhere to put things.
      if (!stat.isDirectory()) throw new HarnessError('PATH_DENIED', i < parts.length - 1 ? 'Parent is not a directory' : 'Expected a directory');
    } catch (e) {
      // A component that does not exist yet is acceptable from the first missing one onwards,
      // which is what makes a recursive create legal and a path through a missing parent to an
      // existing child impossible.
      if (e.code !== 'ENOENT') throw e;
      break;
    }
  }
  return target;
}

/**
 * Read a bounded, TOCTOU-safe snapshot of a workspace file's raw bytes: stat before
 * opening, pin identity on the open descriptor, read loop bounded by limit, then
 * re-check identity and metadata after the read. Throws if the file is linked,
 * changes identity, grows past the budget, or changes during the read.
 */
export function readWorkspaceFile(root, relative, limit) {
  const filename = workspaceFile(root, relative);
  const before = lstatSync(filename);
  if (!before.isFile() || before.nlink !== 1) throw new HarnessError('PATH_DENIED', 'Expected a regular file with one link');
  const fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.ino !== before.ino || stat.dev !== before.dev || stat.size > limit) throw new HarnessError('OUTPUT_LIMIT', 'File identity or read budget changed');
    const buffer = Buffer.alloc(limit + 1);
    let used = 0;
    while (used < buffer.length) {
      const n = readSync(fd, buffer, used, buffer.length - used, used);
      if (!n) break;
      used += n;
    }
    if (used > limit) throw new HarnessError('OUTPUT_LIMIT', 'File grew past read budget');
    const after = fstatSync(fd);
    workspaceFile(root, relative);
    const current = lstatSync(filename);
    if (after.nlink !== 1 || current.nlink !== 1 || current.ino !== stat.ino || current.dev !== stat.dev || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs || current.size !== after.size || current.mtimeMs !== after.mtimeMs || used !== stat.size) throw new HarnessError('PATH_DENIED', 'File changed during read');
    return buffer.subarray(0, used);
  } finally { closeSync(fd); }
}
