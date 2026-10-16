import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonical, parseJson } from '../src/value.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const upstream = path.join(root, 'upstream');
const acquisition = parseJson(fs.readFileSync(path.join(upstream, 'manifest.json'), 'utf8'));
const lock = parseJson(fs.readFileSync(path.join(root, 'sources.lock.json'), 'utf8'));
const sourceFiles = [], capabilities = [], repositories = [];
const hash = b => createHash('sha256').update(b).digest('hex');
for (const source of acquisition) {
  const sourceRoot = path.join(root, source.directory);
  const catalogEntry = lock.sources.find(s => s.repository === source.repository);
  let files = 0, bytes = 0, lfsPointers = 0;
  function walk(directory, relative = '') {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const rel = relative ? relative + '/' + entry.name : entry.name;
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error('Unexpected live link in acquired source');
      if (entry.isDirectory()) { walk(full, rel); continue; }
      if (!entry.isFile()) throw new Error('Unexpected non-file in source');
      const data = fs.readFileSync(full);
      files++; bytes += data.length;
      const sha256 = hash(data);
      sourceFiles.push({ sourceId: catalogEntry.id, path: rel, bytes: data.length, sha256 });
      if (data.length < 4096 && data.toString('utf8').startsWith('version https://git-lfs.github.com/spec/v1')) lfsPointers++;
      if (data.length > 1048576 || !/\.(md|mdx)$/i.test(rel)) continue;
      const text = data.toString('utf8');
      const headings = [...text.matchAll(/^#{1,4}\s+(.+)$/gm)].map(m => m[1].replace(/<[^>]+>/g, '').trim());
      const skill = /(?:^|\/)SKILL\.md$/i.test(rel);
      const command = /(?:^|\/)(?:commands|agents|plugins)\//.test(rel);
      const primaryDoc = /(?:^|\/)README(?:\.[a-z-]+)?\.md$/i.test(rel) || /(?:^|\/)docs?\//i.test(rel);
      if (skill || command || primaryDoc) capabilities.push({
        id: catalogEntry.id + ':' + rel, sourceId: catalogEntry.id,
        kind: skill ? 'skill' : command ? 'agent-command-plugin' : 'documentation',
        title: headings[0] ?? rel, headings,
        path: source.directory + '/' + rel, sourceSha256: sha256,
        sourceUrl: catalogEntry.url + '/blob/' + source.revision + '/' + rel.split('/').map(encodeURIComponent).join('/'),
        executable: false, status: 'source-available-unreviewed'
      });
    }
  }
  walk(sourceRoot);
  repositories.push({ sourceId: catalogEntry.id, repository: source.repository, revision: source.revision, files, bytes, lfsPointers, inertSymlinks: source.symlinksMaterializedAsText });
}
const catalog = { schemaVersion: 1, note: 'Source features and ideas are indexed as untrusted data. A source entry is not a working Concord implementation.', repositories, capabilities };
fs.writeFileSync(path.join(root, 'capabilities.lock.json'), canonical(catalog) + '\n');
fs.writeFileSync(path.join(upstream, 'files.sha256.json'), canonical({ schemaVersion: 1, files: sourceFiles }) + '\n');
console.log(JSON.stringify({ repositories: repositories.length, files: sourceFiles.length, capabilities: capabilities.length, skills: capabilities.filter(c => c.kind === 'skill').length, catalogSha256: hash(Buffer.from(canonical(catalog))) }, null, 2));
