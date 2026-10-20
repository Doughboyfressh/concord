import { constants } from 'node:fs';
import { lstat, open, opendir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, digest, HarnessError, parseJson, validateSchema } from './value.mjs';

const MAX_LOCK_BYTES = 1024 * 1024;
const MAX_FILES = 128;
const MAX_DEPTH = 12;
const MAX_ENTRIES = 256;
const MAX_FILE_BYTES = 256 * 1024;
const DEFAULT_OUTPUT_BYTES = 1024 * 1024;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code, message, details) => { throw new HarnessError(code, message, details); };
const jsonCopy = (value) => JSON.parse(canonical(value));
const sorted = (values) => values.sort((a, b) => a < b ? -1 : a > b ? 1 : 0);

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('SOURCE_LOCK_INVALID', `${label} must be an object`);
}

function checkLock(value) {
  // canonical also rejects unsafe keys and non-JSON values before cloning.
  canonical(value);
  requireObject(value, 'Source lock');
  if (value.schemaVersion !== 1 || !Array.isArray(value.sources) || value.sources.length === 0) {
    fail('SOURCE_LOCK_INVALID', 'Source lock requires schemaVersion 1 and a nonempty sources array');
  }
  const ids = new Set();
  for (const source of value.sources) {
    requireObject(source, 'Source');
    if (typeof source.id !== 'string' || !/^[a-z][a-z0-9-]{0,79}$/.test(source.id) || ids.has(source.id)) {
      fail('SOURCE_LOCK_INVALID', 'Source ids must be unique portable identifiers');
    }
    ids.add(source.id);
    if (!['repository', 'website', 'distribution'].includes(source.kind)) fail('SOURCE_LOCK_INVALID', 'Unsupported source kind', { sourceId: source.id });
    for (const field of ['requestedUrl', 'url']) {
      let url;
      try { url = new URL(source[field]); } catch { fail('SOURCE_LOCK_INVALID', 'Invalid primary source URL', { sourceId: source.id, field }); }
      if (url.protocol !== 'https:' || url.username || url.password || url.hash) fail('SOURCE_LOCK_INVALID', 'Source URLs must use HTTPS without credentials or fragments', { sourceId: source.id, field });
    }
    if (!Array.isArray(source.roles) || source.roles.length === 0 || source.roles.some((role) => typeof role !== 'string' || !/^[a-z][a-z0-9-]*$/.test(role))) {
      fail('SOURCE_LOCK_INVALID', 'Source roles must be portable identifiers', { sourceId: source.id });
    }
    requireObject(source.license, 'Source license');
    requireObject(source.integration, 'Source integration');
    if (source.integration.runtimeInstalled !== false || typeof source.integration.status !== 'string' || typeof source.license.caveat !== 'string') {
      fail('SOURCE_LOCK_INVALID', 'Catalog entries must disclose installation status and license scope', { sourceId: source.id });
    }
    if (source.kind === 'repository') {
      if (source.mutability !== 'immutable-reference' || typeof source.revision !== 'string' || !/^[a-f0-9]{40}$/.test(source.revision)) {
        fail('SOURCE_LOCK_INVALID', 'Repositories require a full immutable Git revision', { sourceId: source.id });
      }
    } else if (source.kind === 'distribution') {
      // A released archive is pinned, but not by a commit: the pin is the release identifier it
      // ships under. Forcing it into either existing kind would have to lie — calling it immutable
      // would claim a revision that is not recorded, and calling it a mutable observation would
      // claim it can change under a fixed name, which a released archive cannot.
      if (source.mutability !== 'pinned-release-archive' || source.revision !== null
        || typeof source.release !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(source.release)) {
        fail('SOURCE_LOCK_INVALID', 'Distributions require a release identifier and no Git revision', { sourceId: source.id });
      }
    } else if (source.mutability !== 'mutable-observation' || source.revision !== null) {
      fail('SOURCE_LOCK_INVALID', 'Websites must be marked as unpinned mutable observations', { sourceId: source.id });
    }
  }
  return jsonCopy(value);
}

/** Explicit startup read. No network or upstream code is executed. */
export async function loadSourceLock(lockPath) {
  const handle = await open(lockPath, constants.O_RDONLY);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_LOCK_BYTES) fail('SOURCE_LOCK_INVALID', 'Source lock must be a regular file of at most 1 MiB');
    const bytes = await readBounded(handle, MAX_LOCK_BYTES);
    let parsed;
    try { parsed = parseJson(decoder.decode(bytes)); } catch { fail('SOURCE_LOCK_INVALID', 'Source lock must contain strict UTF-8 JSON without duplicate keys'); }
    return checkLock(parsed);
  } finally { await handle.close(); }
}

function outputLimit(context) {
  const value = context?.policy?.maxOutputBytes ?? DEFAULT_OUTPUT_BYTES;
  if (!Number.isSafeInteger(value) || value <= 0) fail('POLICY_INVALID', 'maxOutputBytes must be a positive safe integer');
  return value;
}

function boundedOutput(value, limit) {
  if (Buffer.byteLength(canonical(value), 'utf8') > limit) fail('OUTPUT_LIMIT', 'Source tool output exceeds maxOutputBytes');
  return value;
}

function aborted(signal) {
  if (signal?.aborted) fail('ABORTED', 'Source snapshot was aborted');
}

function portablePath(input) {
  if (typeof input !== 'string' || input.length === 0 || Buffer.byteLength(input) > 1024 || /[\\:<>"|?*\x00-\x1f\x7f]/.test(input) || path.posix.isAbsolute(input) || path.win32.isAbsolute(input)) {
    fail('PATH_DENIED', 'Snapshot path must be a portable relative path using forward slashes');
  }
  if (input === '.') return input;
  const parts = input.split('/');
  if (parts.some((part) => !part || part === '.' || part === '..' || /[. ]$/.test(part) || /^(con(?:in\$|out\$)?|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\.|$)/i.test(part))) {
    fail('PATH_DENIED', 'Snapshot path contains an unsafe path segment');
  }
  return parts.join('/');
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}

async function checkedPath(root, candidate, signal) {
  aborted(signal);
  if (!isWithin(root, candidate)) fail('PATH_DENIED', 'Snapshot path escapes the workspace');
  const relative = path.relative(root, candidate);
  const parts = relative ? relative.split(path.sep) : [];
  let cursor = root;
  let stat = await lstat(root);
  for (const part of parts) {
    cursor = path.join(cursor, part);
    stat = await lstat(cursor);
    if (stat.isSymbolicLink()) fail('PATH_DENIED', 'Symlinks and junctions are forbidden in skill snapshots');
    const resolved = await realpath(cursor);
    if (!isWithin(root, resolved)) fail('PATH_DENIED', 'Snapshot path resolves outside the workspace');
  }
  return stat;
}

async function readBounded(handle, limit, signal) {
  const chunks = [];
  let length = 0;
  while (true) {
    aborted(signal);
    const buffer = Buffer.alloc(Math.min(64 * 1024, limit - length + 1));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
    if (!bytesRead) break;
    length += bytesRead;
    if (length > limit) fail('OUTPUT_LIMIT', 'Source file exceeds the bounded read size');
    chunks.push(buffer.subarray(0, bytesRead));
  }
  return Buffer.concat(chunks, length);
}

function sameFile(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
}

async function snapshotFile(root, filename, relativePath, byteLimit, signal) {
  const before = await checkedPath(root, filename, signal);
  if (!before.isFile()) fail('PATH_DENIED', 'Snapshots support regular files only');
  if (before.nlink !== 1) fail('PATH_DENIED', 'Hard-linked files are forbidden in skill snapshots');
  if (before.size > MAX_FILE_BYTES || before.size > byteLimit) fail('OUTPUT_LIMIT', 'Skill file exceeds the bounded read size');
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFile(before, opened)) fail('SOURCE_CHANGED', 'Skill file changed while opening');
    await checkedPath(root, filename, signal);
    const bytes = await readBounded(handle, Math.min(MAX_FILE_BYTES, byteLimit), signal);
    const after = await handle.stat();
    const pathAfter = await checkedPath(root, filename, signal);
    if (!sameFile(opened, after) || !sameFile(opened, pathAfter)) fail('SOURCE_CHANGED', 'Skill file changed during capture');
    let content;
    try { content = decoder.decode(bytes); } catch { fail('SKILL_INVALID', 'Skill snapshots support UTF-8 text and data only', { path: relativePath }); }
    if (content.includes('\0')) fail('SKILL_INVALID', 'Binary content is not allowed in a skill snapshot', { path: relativePath });
    return { path: relativePath, bytes: bytes.length, sha256: sha256(bytes), content };
  } finally { await handle.close(); }
}

function parseScalar(raw) {
  const value = raw.trim();
  if (value.startsWith('"')) {
    try { const parsed = JSON.parse(value); if (typeof parsed === 'string') return parsed; } catch { /* rejected below */ }
    fail('SKILL_INVALID', 'Malformed quoted skill metadata');
  }
  if (value.startsWith("'")) {
    if (!value.endsWith("'") || value.length < 2) fail('SKILL_INVALID', 'Malformed quoted skill metadata');
    return value.slice(1, -1).replaceAll("''", "'");
  }
  if (/^[!&*[{]/.test(value)) fail('SKILL_INVALID', 'Skill metadata must contain scalar text');
  return value;
}

function skillMetadata(content) {
  const lines = content.replace(/^\uFEFF/, '').replaceAll('\r\n', '\n').split('\n');
  if (lines[0] !== '---') fail('SKILL_INVALID', 'SKILL.md requires YAML frontmatter');
  const end = lines.indexOf('---', 1);
  if (end < 0 || lines.slice(0, end).join('\n').length > 32768) fail('SKILL_INVALID', 'Skill frontmatter is missing or too large');
  const metadata = {};
  for (let i = 1; i < end; i += 1) {
    const match = /^(name|description):\s*(.*)$/.exec(lines[i]);
    if (!match) continue;
    const [, key, raw] = match;
    if (Object.hasOwn(metadata, key)) fail('SKILL_INVALID', 'Duplicate skill metadata field', { field: key });
    if (/^[|>][+-]?$/.test(raw.trim())) {
      const block = [];
      while (i + 1 < end && (/^\s/.test(lines[i + 1]) || lines[i + 1] === '')) block.push(lines[++i].replace(/^\s+/, ''));
      metadata[key] = block.join(raw.trim().startsWith('>') ? ' ' : '\n').trim();
    } else metadata[key] = parseScalar(raw);
  }
  if (typeof metadata.name !== 'string' || !metadata.name.trim() || metadata.name.length > 128 || typeof metadata.description !== 'string' || !metadata.description.trim() || metadata.description.length > 4096) {
    fail('SKILL_INVALID', 'Skill name and description must be nonempty bounded text');
  }
  return metadata;
}

const catalogSchema = {
  type: 'object', additionalProperties: false,
  properties: { sourceId: { type: 'string', minLength: 1, maxLength: 80 }, role: { type: 'string', minLength: 1, maxLength: 80 } },
};
const snapshotSchema = {
  type: 'object', additionalProperties: false, required: ['path', 'sourceId'],
  properties: {
    path: { type: 'string', minLength: 1, maxLength: 1024 },
    sourceId: { type: 'string', minLength: 1, maxLength: 80 },
    expectedDigest: { type: 'string', minLength: 64, maxLength: 64 },
  },
};

/** Pure registration: no filesystem, network, environment, or clock reads. */
export function makeSourceTools(sourceLock) {
  const lock = checkLock(sourceLock);
  const lockDigest = digest(lock);
  const sources = new Map(lock.sources.map((source) => [source.id, source]));
  const config = { sourceLockDigest: lockDigest };
  return [
    {
      name: 'sources.catalog', version: '1.0.0', effect: 'pure', inputSchema: catalogSchema, config,
      execute(input, context) {
        validateSchema(input, catalogSchema);
        if (input.sourceId && !sources.has(input.sourceId)) fail('SOURCE_UNKNOWN', 'Unknown source id');
        const entries = [...sources.values()].filter((source) => (!input.sourceId || source.id === input.sourceId) && (!input.role || source.roles.includes(input.role)));
        entries.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
        return boundedOutput(jsonCopy({ schemaVersion: 1, sourceLockDigest: lockDigest, sources: entries }), outputLimit(context));
      },
    },
    {
      name: 'skills.snapshot', version: '1.0.0', effect: 'read', inputSchema: snapshotSchema, config: { ...config, maxFiles: MAX_FILES, maxEntries: MAX_ENTRIES, maxDepth: MAX_DEPTH, maxFileBytes: MAX_FILE_BYTES },
      async execute(input, context) {
        validateSchema(input, snapshotSchema);
        if (input.expectedDigest && !/^[a-f0-9]{64}$/.test(input.expectedDigest)) fail('SCHEMA_MISMATCH', 'expectedDigest must be lowercase SHA-256 hexadecimal');
        const source = sources.get(input.sourceId);
        if (!source) fail('SOURCE_UNKNOWN', 'Unknown source id');
        const requested = portablePath(input.path);
        if (typeof context?.workspaceRoot !== 'string' || !context.workspaceRoot) fail('WORKSPACE_INVALID', 'A workspace root is required');
        const limit = outputLimit(context);
        const signal = context.signal;
        aborted(signal);
        try {
          const root = await realpath(context.workspaceRoot);
          const rootStat = await lstat(root);
          if (!rootStat.isDirectory()) fail('WORKSPACE_INVALID', 'Workspace root must be a directory');
          const selected = path.resolve(root, requested);
          const selectedStat = await checkedPath(root, selected, signal);
          const directory = selectedStat.isDirectory() ? selected : path.dirname(selected);
          if (!selectedStat.isDirectory() && path.basename(selected) !== 'SKILL.md') fail('SKILL_INVALID', 'Select a skill directory or its SKILL.md file');
          const filenames = [];
          const directories = [];
          let entryCount = 0;
          async function visit(current, depth) {
            if (depth > MAX_DEPTH) fail('OUTPUT_LIMIT', 'Skill snapshot exceeds the directory depth limit');
            const before = await checkedPath(root, current, signal);
            if (!before.isDirectory()) fail('SOURCE_CHANGED', 'Skill directory changed during capture');
            directories.push({ path: current, stat: before });
            const names = [];
            for await (const entry of await opendir(current)) {
              if (++entryCount > MAX_ENTRIES) fail('OUTPUT_LIMIT', 'Skill snapshot exceeds the directory entry limit');
              names.push(entry.name);
            }
            for (const name of sorted(names)) {
              portablePath(name);
              const filename = path.join(current, name);
              const stat = await checkedPath(root, filename, signal);
              if (stat.isDirectory()) {
                if (name === '.git' || name === 'node_modules') fail('SKILL_INVALID', 'Skill snapshots cannot include Git metadata or dependency installations');
                await visit(filename, depth + 1);
              } else if (stat.isFile()) {
                filenames.push(filename);
                if (filenames.length > MAX_FILES) fail('OUTPUT_LIMIT', 'Skill snapshot exceeds the file count limit');
              } else fail('PATH_DENIED', 'Skill snapshots support regular files and directories only');
            }
          }
          if (selectedStat.isDirectory()) await visit(selected, 0);
          else filenames.push(selected);
          filenames.sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
          const files = [];
          let totalBytes = 0;
          for (const filename of filenames) {
            const relativePath = path.relative(directory, filename).split(path.sep).join('/');
            const file = await snapshotFile(root, filename, relativePath, Math.max(0, limit - totalBytes), signal);
            totalBytes += file.bytes;
            files.push(file);
          }
          for (const entry of directories) {
            const after = await checkedPath(root, entry.path, signal);
            if (!sameFile(entry.stat, after)) fail('SOURCE_CHANGED', 'Skill directory changed during capture');
          }
          const entrypoint = files.find((file) => file.path === 'SKILL.md');
          if (!entrypoint) fail('SKILL_INVALID', 'Skill snapshot requires a root SKILL.md');
          const snapshot = {
            schemaVersion: 1,
            provenance: { sourceId: source.id, url: source.url, revision: source.revision, mutability: source.mutability, binding: 'caller-declared', upstreamVerified: false },
            metadata: skillMetadata(entrypoint.content),
            files,
          };
          const snapshotDigest = digest(snapshot);
          if (input.expectedDigest && snapshotDigest !== input.expectedDigest) fail('DIGEST_MISMATCH', 'Skill snapshot does not match expectedDigest');
          return boundedOutput({ ...snapshot, snapshotDigest, digestAlgorithm: 'sha256-canonical-json-v1', localPath: requested, fileCount: files.length, totalBytes, executable: false, trust: 'unreviewed-data' }, limit);
        } catch (error) {
          if (error instanceof HarnessError) throw error;
          const code = error?.code;
          if (['ELOOP', 'EMLINK'].includes(code)) fail('PATH_DENIED', 'Symlink traversal is forbidden');
          if (code === 'ENOENT') fail('SOURCE_NOT_FOUND', 'Skill snapshot path does not exist');
          fail('SOURCE_READ_FAILED', 'Unable to capture local skill snapshot', { filesystemCode: typeof code === 'string' ? code : 'UNKNOWN' });
        }
      },
    },
  ];
}
