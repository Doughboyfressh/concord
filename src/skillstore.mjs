import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, parseJson, HarnessError } from './value.mjs';
import { workspaceFile } from './workspace-fs.mjs';

/**
 * The skill lifecycle: install, verify, remove.
 *
 * Vercel's skills project is about the part nobody writes: not finding a skill, but adopting one
 * and then knowing, later, whether what you adopted is still what you reviewed. Concord already
 * ranked skills and read their text. It had no way to take one into the workspace, record what it
 * took, and detect that it had since changed. That is this module.
 *
 * Three properties hold it together, and each answers a way adoption normally rots:
 *
 * An install verifies before it copies. The inventory records a digest for every indexed file; a
 * copy whose bytes do not match that digest is refused rather than installed. An import that does
 * not check is only a copy, and a lock over unchecked copies locks nothing.
 *
 * The lock records what was installed, not what was available. It carries the source id, the
 * upstream path, the digest at install time, and where the copy went — so a later reader can ask
 * two separate questions: has my copy changed, and has upstream moved on.
 *
 * Nothing here executes a skill. An installed skill is text in the workspace, exactly as inert as
 * it was in the corpus, and the status the inventory gave it travels with it.
 */

const SKILL_DIR = 'skills';
const LOCK_FILE = SKILL_DIR + '/installed.json';
const MAX_SKILL_BYTES = 1_048_576;
const MAX_INSTALLED = 512;

const fail = (code, message, detail) => { throw new HarnessError(code, message, detail); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** A portable file name for an inventory id like `ecc:docs/ja-JP/skills/python-patterns/SKILL.md`. */
export function skillSlug(id) {
  const slug = String(id).replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase().slice(0, 120);
  if (!slug) fail('SKILL_ID', 'That identifier does not reduce to a usable file name', { id });
  return slug;
}

function readLock(root) {
  try {
    const parsed = parseJson(fs.readFileSync(workspaceFile(root, LOCK_FILE), 'utf8'));
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.installed)) return { version: 1, installed: [] };
    return parsed;
  } catch (error) {
    // No lock yet is the ordinary state of a workspace nobody has installed into.
    if (error && error.code === 'ENOENT') return { version: 1, installed: [] };
    throw error;
  }
}

/**
 * The skills directory, created if absent. workspaceFile() guards a file path and tolerates only
 * a missing final segment, so the parent has to exist before it is asked anything.
 */
function skillDir(root) {
  const directory = path.join(fs.realpathSync(root), SKILL_DIR);
  fs.mkdirSync(directory, { recursive: true });
  return directory;
}

function writeLock(root, installed) {
  const sorted = { version: 1, installed: [...installed].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)) };
  skillDir(root);
  const file = workspaceFile(root, LOCK_FILE);
  fs.writeFileSync(file, canonical(sorted) + '\n', 'utf8');
  return sorted;
}

export function makeSkillStoreTools(inventory) {
  const entries = new Map();
  for (const entry of inventory?.capabilities ?? []) {
    if (entry && typeof entry.id === 'string') entries.set(entry.id, entry);
  }

  const idSchema = { type: 'string', minLength: 1, maxLength: 512 };

  return [
    {
      name: 'skills.install', version: '1.0.0', effect: 'write',
      outputKeys: ['id', 'installedAs', 'sha256', 'sourceId', 'title', 'status', 'bytes', 'limitations'],
      inputSchema: { type: 'object', additionalProperties: false, required: ['id'], properties: { id: idSchema } },
      execute(input, context) {
        const entry = entries.get(input.id);
        if (!entry) fail('SKILL_UNKNOWN', 'No indexed capability has that id', { id: input.id });
        if (typeof entry.path !== 'string') fail('SKILL_UNKNOWN', 'That inventory entry records no path', { id: input.id });

        let bytes;
        try { bytes = fs.readFileSync(workspaceFile(context.workspaceRoot, entry.path)); }
        catch { return fail('SKILL_SOURCE', 'The indexed file is not present in this workspace; acquire the upstream sources first', { path: entry.path }); }
        if (bytes.length > MAX_SKILL_BYTES) fail('SKILL_SOURCE', 'That skill is larger than the bound permits', { bytes: bytes.length });

        // Verified before it is copied. An import that does not check the digest it was indexed
        // with is only a copy, and a lock over unchecked copies locks nothing.
        const digestNow = sha256(bytes);
        if (typeof entry.sourceSha256 === 'string' && digestNow !== entry.sourceSha256) {
          fail('SKILL_DIGEST', 'The file on disk does not match the digest the inventory recorded for it', { id: input.id, expected: entry.sourceSha256, actual: digestNow });
        }

        const lock = readLock(context.workspaceRoot);
        if (lock.installed.length >= MAX_INSTALLED && !lock.installed.some((row) => row.id === input.id)) {
          fail('SKILL_LIMIT', 'As many skills are installed as the bound permits', { installed: lock.installed.length });
        }

        const extension = path.extname(entry.path) || '.md';
        const installedAs = SKILL_DIR + '/' + skillSlug(input.id) + extension;
        skillDir(context.workspaceRoot);
        fs.writeFileSync(workspaceFile(context.workspaceRoot, installedAs), bytes);

        const row = {
          id: input.id, installedAs, sha256: digestNow,
          sourceId: typeof entry.sourceId === 'string' ? entry.sourceId : null,
          title: typeof entry.title === 'string' ? entry.title : null,
          sourcePath: entry.path,
          status: typeof entry.status === 'string' ? entry.status : null,
        };
        writeLock(context.workspaceRoot, [...lock.installed.filter((existing) => existing.id !== input.id), row]);

        return {
          id: row.id, installedAs, sha256: digestNow, sourceId: row.sourceId, title: row.title,
          status: row.status, bytes: bytes.length,
          limitations: [
            'An installed skill is inert text in the workspace; installing it executes nothing and grants nothing',
            'The status the inventory recorded travels with it: an unreviewed source stays unreviewed after installation',
          ],
        };
      },
    },
    {
      name: 'skills.installed', version: '1.0.0', effect: 'read',
      outputKeys: ['installed', 'count', 'changed', 'missing', 'upstreamChanged', 'limitations'],
      inputSchema: { type: 'object', additionalProperties: false, properties: { sourceId: { type: 'string', maxLength: 64 } } },
      execute(input, context) {
        const lock = readLock(context.workspaceRoot);
        const rows = [];
        let changed = 0;
        let missing = 0;
        let upstreamChanged = 0;

        for (const row of lock.installed) {
          if (input.sourceId !== undefined && row.sourceId !== input.sourceId) continue;
          // Two separate questions, deliberately not merged: has my copy changed, and has the
          // source moved on. Collapsing them would report a local edit as an upstream update.
          let present = true;
          let localDigest = null;
          try { localDigest = sha256(fs.readFileSync(workspaceFile(context.workspaceRoot, row.installedAs))); }
          catch { present = false; }

          let upstream = null;
          if (typeof row.sourcePath === 'string') {
            try { upstream = sha256(fs.readFileSync(workspaceFile(context.workspaceRoot, row.sourcePath))); }
            catch { upstream = null; }
          }

          const localChanged = present && localDigest !== row.sha256;
          const moved = upstream !== null && upstream !== row.sha256;
          if (!present) missing += 1;
          if (localChanged) changed += 1;
          if (moved) upstreamChanged += 1;

          rows.push({
            id: row.id, installedAs: row.installedAs, sourceId: row.sourceId, title: row.title,
            status: row.status, lockedSha256: row.sha256,
            present, localChanged,
            upstream: upstream === null ? 'unavailable' : (moved ? 'changed' : 'same'),
          });
        }

        return {
          installed: rows, count: rows.length, changed, missing, upstreamChanged,
          limitations: [
            'An upstream reported as unavailable only means the source tree is not in this workspace, not that it is gone',
          ],
        };
      },
    },
    {
      name: 'skills.remove', version: '1.0.0', effect: 'write',
      outputKeys: ['id', 'removed', 'fileRemoved', 'remaining', 'limitations'],
      inputSchema: { type: 'object', additionalProperties: false, required: ['id'], properties: { id: idSchema } },
      execute(input, context) {
        const lock = readLock(context.workspaceRoot);
        const row = lock.installed.find((existing) => existing.id === input.id);
        if (!row) fail('SKILL_UNKNOWN', 'No skill with that id is installed', { id: input.id });

        let fileRemoved = false;
        try { fs.rmSync(workspaceFile(context.workspaceRoot, row.installedAs)); fileRemoved = true; }
        catch { fileRemoved = false; }

        const remaining = writeLock(context.workspaceRoot, lock.installed.filter((existing) => existing.id !== input.id));
        return {
          id: input.id, removed: true, fileRemoved, remaining: remaining.installed.length,
          // Reported rather than hidden: a lock entry can outlive its file if someone deleted the
          // copy by hand, and saying so beats pretending the removal was uniform.
          limitations: fileRemoved ? [] : ['The lock entry was removed but its file was already gone'],
        };
      },
    },
  ];
}
