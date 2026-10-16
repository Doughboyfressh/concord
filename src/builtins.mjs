import { constants, openSync, readSync, writeFileSync, closeSync, fstatSync, lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, digest, validateSchema, HarnessError } from './value.mjs';

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
function workspaceFile(root, relative) {
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

export function makeBuiltinTools() {
  return [
    { name: 'json.value', version: '1.0.0', effect: 'pure', inputSchema: true,
      execute(input) { return input; } },
    { name: 'json.hash', version: '1.0.0', effect: 'pure', inputSchema: true,
      execute(input) { return { algorithm: 'sha256/concord-json-v1', digest: digest(input) }; } },
    { name: 'json.assert', version: '1.0.0', effect: 'pure', inputSchema: object({ value: true, schema: true }),
      execute({ value, schema }) { validateSchema(value, schema); return { passed: true, value, evidenceHash: digest(value) }; } },
    { name: 'skills.rank', version: '1.0.0', effect: 'pure', inputSchema: object({ query: string, skills: { type: 'array', maxItems: 10000, items: object({ id: string, text: string }) }, limit: { type: 'integer', minimum: 1, maximum: 100 } }, ['query', 'skills']),
      execute({ query, skills, limit = 5 }) {
        const tokenize = text => [...new Set(text.toLowerCase().match(/[a-z0-9]+/g) ?? [])];
        const terms = tokenize(query);
        const ids = new Set();
        const ranked = skills.map(skill => {
          if (ids.has(skill.id)) throw new HarnessError('INVALID_SKILLS', 'Duplicate skill ID');
          ids.add(skill.id);
          const tokens = new Set(tokenize(skill.text));
          const matched = terms.filter(t => tokens.has(t));
          return { id: skill.id, score: matched.length, matched, contentHash: digest(skill) };
        }).sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
        return { strategy: 'lexical-overlap-v1', ranked: ranked.slice(0, limit) };
      } },
    { name: 'judgment.gate', version: '1.0.0', effect: 'pure', inputSchema: object({ score: { type: 'number', minimum: 0, maximum: 1 }, threshold: { type: 'number', minimum: 0, maximum: 1 }, evidence: true }),
      execute({ score, threshold, evidence }) {
        if (score < threshold) throw new HarnessError('JUDGMENT_REJECTED', 'Evidence does not meet the declared threshold');
        return { accepted: true, score, threshold, evidenceHash: digest(evidence), grantsCapabilities: false };
      } },
    { name: 'memory.candidate', version: '1.0.0', effect: 'pure', inputSchema: object({ lesson: string, evidence: { type: 'array', minItems: 1, maxItems: 1000, items: true } }),
      execute({ lesson, evidence }) {
        const candidate = { version: 1, lesson, evidenceHashes: evidence.map(digest).sort(), status: 'proposed', executable: false };
        return { ...candidate, candidateHash: digest(candidate) };
      } },
    { name: 'files.read', version: '1.0.0', effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const filename = workspaceFile(context.workspaceRoot, relative);
        const before = lstatSync(filename);
        if (!before.isFile() || before.nlink !== 1) throw new HarnessError('PATH_DENIED', 'Expected a regular file with one link');
        const fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
        try {
          const stat = fstatSync(fd);
          const limit = Math.floor(context.policy.maxOutputBytes / 8);
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
          workspaceFile(context.workspaceRoot, relative);
          const current = lstatSync(filename);
          if (after.nlink !== 1 || current.nlink !== 1 || current.ino !== stat.ino || current.dev !== stat.dev || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs || current.size !== after.size || current.mtimeMs !== after.mtimeMs || used !== stat.size) throw new HarnessError('PATH_DENIED', 'File changed during read');
          const bytes = buffer.subarray(0, used);
          const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
          return { path: relative, text, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), untrusted: true };
        } finally { closeSync(fd); }
      } },
    { name: 'files.write', version: '1.0.0', effect: 'write', inputSchema: object({ path: string, content: true }),
      execute({ path: relative, content }, context) {
        const filename = workspaceFile(context.workspaceRoot, relative);
        const text = canonical(content) + '\n';
        if (Buffer.byteLength(text) > context.policy.maxOutputBytes) throw new HarnessError('OUTPUT_LIMIT', 'Write exceeds byte budget');
        // Exclusive creation: an approval cannot silently replace existing user data.
        writeFileSync(filename, text, { flag: 'wx', encoding: 'utf8' });
        return { path: relative, contentHash: digest(content), created: true };
      } }
  ];
}
