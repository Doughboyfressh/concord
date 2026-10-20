import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { link, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSourceLock, makeSourceTools } from '../src/sources.mjs';
import { digest } from '../src/value.mjs';

const lockPath = fileURLToPath(new URL('../sources.lock.json', import.meta.url));
const lock = await loadSourceLock(lockPath);
const tools = new Map(makeSourceTools(lock).map((tool) => [tool.name, tool]));
const catalog = tools.get('sources.catalog');
const snapshot = tools.get('skills.snapshot');
const header = '---\nname: example\ndescription: A local test skill\n---\n# Instructions\n';
const errorCode = (code) => (error) => error?.code === code;

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'concord-sources-'));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  const skill = path.join(root, 'skill');
  await mkdir(skill);
  await writeFile(path.join(skill, 'SKILL.md'), header);
  return { root, skill, context: { workspaceRoot: root, policy: { maxOutputBytes: 1024 * 1024 } } };
}

async function directoryLink(t, target, destination) {
  try { await symlink(target, destination, process.platform === 'win32' ? 'junction' : 'dir'); return true; }
  catch (error) {
    if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) {
      t.skip('This environment does not permit creating directory links; run outside the restricted container to exercise this check.');
      return false;
    }
    throw error;
  }
}

test('source lock covers eleven immutable repositories, two mutable websites and one pinned distribution', () => {
  assert.equal(lock.sources.length, 14);
  assert.equal(lock.sources.filter((source) => source.kind === 'repository').length, 11);
  assert.equal(lock.sources.filter((source) => source.kind === 'website').length, 2);
  assert.equal(lock.sources.filter((source) => source.kind === 'distribution').length, 1);
  for (const source of lock.sources) {
    assert.equal(source.integration.runtimeInstalled, false);
    assert.ok(source.license.caveat);
    assert.ok(source.primaryLinks.length);
    if (source.kind === 'repository') assert.match(source.revision, /^[a-f0-9]{40}$/);
    else if (source.kind === 'distribution') {
      // Pinned, but by a release identifier rather than a commit. Both facts are asserted because
      // a distribution that recorded neither would be an unpinned reference wearing a pinned name.
      assert.equal(source.revision, null);
      assert.equal(source.mutability, 'pinned-release-archive');
      assert.match(source.release, /^[A-Za-z0-9][A-Za-z0-9._-]*$/);
    } else {
      assert.equal(source.revision, null);
      assert.equal(source.mutability, 'mutable-observation');
    }
  }
  assert.equal(catalog.config.sourceLockDigest, digest(lock));
  assert.equal(snapshot.effect, 'read');
  assert.equal(catalog.effect, 'pure');
});

test('source locks reject duplicate identifiers, short pins, and falsely pinned websites', () => {
  const duplicate = structuredClone(lock);
  duplicate.sources.push(duplicate.sources[0]);
  assert.throws(() => makeSourceTools(duplicate), errorCode('SOURCE_LOCK_INVALID'));
  const short = structuredClone(lock);
  short.sources[0].revision = 'main';
  assert.throws(() => makeSourceTools(short), errorCode('SOURCE_LOCK_INVALID'));
  const website = structuredClone(lock);
  website.sources.find((source) => source.kind === 'website').revision = '0'.repeat(40);
  assert.throws(() => makeSourceTools(website), errorCode('SOURCE_LOCK_INVALID'));
  // A distribution's pin is its release identifier, so dropping it leaves an unpinned entry that
  // still claims to be pinned. That is the one way this kind can lie, so it is refused.
  const unpinned = structuredClone(lock);
  delete unpinned.sources.find((source) => source.kind === 'distribution').release;
  assert.throws(() => makeSourceTools(unpinned), errorCode('SOURCE_LOCK_INVALID'));
  const falselyCommitted = structuredClone(lock);
  falselyCommitted.sources.find((source) => source.kind === 'distribution').revision = '0'.repeat(40);
  assert.throws(() => makeSourceTools(falselyCommitted), errorCode('SOURCE_LOCK_INVALID'));
});

test('source lock loading rejects duplicate JSON keys and oversized documents', async (t) => {
  const { root } = await fixture(t);
  const filename = path.join(root, 'lock.json');
  await writeFile(filename, '{"schemaVersion":1,"schemaVersion":1,"sources":[]}');
  await assert.rejects(loadSourceLock(filename), errorCode('SOURCE_LOCK_INVALID'));
  await writeFile(filename, ' '.repeat(1024 * 1024 + 1));
  await assert.rejects(loadSourceLock(filename), errorCode('SOURCE_LOCK_INVALID'));
});

test('catalog filters roles, binds a copy of the lock, and returns independent JSON', () => {
  const original = structuredClone(lock);
  const [localCatalog] = makeSourceTools(original);
  original.sources[0].revision = '0'.repeat(40);
  const result = localCatalog.execute({ role: 'security-reference' }, { policy: {} });
  assert.deepEqual(result.sources.map((source) => source.id), ['awesome-cyber-skills', 'awesome-hacking']);
  result.sources[0].url = 'https://example.invalid/';
  assert.notEqual(localCatalog.execute({ sourceId: 'awesome-cyber-skills' }).sources[0].url, result.sources[0].url);
  assert.notEqual(localCatalog.execute({ sourceId: 'ecc' }).sources[0].revision, original.sources[0].revision);
  assert.throws(() => localCatalog.execute({ sourceId: 'missing' }), errorCode('SOURCE_UNKNOWN'));
  assert.throws(() => localCatalog.execute({ extra: true }), errorCode('SCHEMA_MISMATCH'));
  assert.throws(() => localCatalog.execute({}, { policy: { maxOutputBytes: 10 } }), errorCode('OUTPUT_LIMIT'));
});

test('snapshots capture sorted UTF-8 bytes and reproducible digests independent of local directory', async (t) => {
  const { root, skill, context } = await fixture(t);
  await mkdir(path.join(skill, 'references'));
  const text = 'Unicode: café 世界\r\n';
  await writeFile(path.join(skill, 'references', 'notes.md'), text);
  const result = await snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context);
  assert.deepEqual(result.files.map((file) => file.path), ['SKILL.md', 'references/notes.md']);
  assert.equal(result.files[1].sha256, createHash('sha256').update(Buffer.from(text)).digest('hex'));
  assert.equal(result.files[1].bytes, Buffer.byteLength(text));
  assert.equal(result.files[1].content, text);
  assert.equal(result.executable, false);
  assert.equal(result.provenance.upstreamVerified, false);
  assert.equal(result.provenance.revision, lock.sources.find((source) => source.id === 'ecc').revision);
  assert.deepEqual(result.metadata, { name: 'example', description: 'A local test skill' });
  await mkdir(path.join(root, 'copy', 'references'), { recursive: true });
  await writeFile(path.join(root, 'copy', 'SKILL.md'), header);
  await writeFile(path.join(root, 'copy', 'references', 'notes.md'), text);
  const copy = await snapshot.execute({ path: 'copy', sourceId: 'ecc', expectedDigest: result.snapshotDigest }, context);
  assert.equal(copy.snapshotDigest, result.snapshotDigest);
});

test('expectedDigest detects a changed body and binds the claimed source revision', async (t) => {
  const { skill, context } = await fixture(t);
  const before = await snapshot.execute({ path: 'skill/SKILL.md', sourceId: 'ecc' }, context);
  await writeFile(path.join(skill, 'SKILL.md'), header + 'Changed instructions\n');
  await assert.rejects(snapshot.execute({ path: 'skill/SKILL.md', sourceId: 'ecc', expectedDigest: before.snapshotDigest }, context), errorCode('DIGEST_MISMATCH'));
  const after = await snapshot.execute({ path: 'skill/SKILL.md', sourceId: 'ecc' }, context);
  const otherSource = await snapshot.execute({ path: 'skill/SKILL.md', sourceId: 'vercel-skills' }, context);
  assert.notEqual(after.snapshotDigest, before.snapshotDigest);
  assert.notEqual(after.snapshotDigest, otherSource.snapshotDigest);
});

test('snapshot inputs reject unknown fields, malformed digests, and unknown sources', async (t) => {
  const { context } = await fixture(t);
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc', execute: true }, context), errorCode('SCHEMA_MISMATCH'));
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc', expectedDigest: 'X'.repeat(64) }, context), errorCode('SCHEMA_MISMATCH'));
  await assert.rejects(snapshot.execute({ path: 'nonexistent', sourceId: 'missing' }, context), errorCode('SOURCE_UNKNOWN'));
});

test('snapshot paths reject traversal, absolute paths, Windows aliases, and alternate streams', async (t) => {
  const { context } = await fixture(t);
  for (const unsafePath of ['../skill', '/tmp/skill', 'C:/skill', 'C:skill', '\\\\server\\share', 'skill\\SKILL.md', 'skill/../SKILL.md', 'skill//SKILL.md', 'skill/SKILL.md:stream', 'skill/NUL.txt', 'skill/CONIN$', 'skill/COM¹', 'skill/a?b', 'skill/hidden.', 'skill/hidden ']) {
    await assert.rejects(snapshot.execute({ path: unsafePath, sourceId: 'ecc' }, context), errorCode('PATH_DENIED'), unsafePath);
  }
});

test('snapshot rejects directory symlinks or Windows junctions even when pointing inside the workspace', async (t) => {
  const { root, skill, context } = await fixture(t);
  const link = path.join(root, 'linked-skill');
  if (!await directoryLink(t, skill, link)) return;
  await assert.rejects(snapshot.execute({ path: 'linked-skill', sourceId: 'ecc' }, context), errorCode('PATH_DENIED'));
  if (!await directoryLink(t, root, path.join(skill, 'nested-link'))) return;
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context), errorCode('PATH_DENIED'));
});

test('snapshot rejects junctions escaping the workspace', async (t) => {
  const { root, context } = await fixture(t);
  const outside = await mkdtemp(path.join(os.tmpdir(), 'concord-outside-'));
  t.after(async () => { await rm(outside, { recursive: true, force: true }); });
  await writeFile(path.join(outside, 'SKILL.md'), header);
  if (!await directoryLink(t, outside, path.join(root, 'escape'))) return;
  await assert.rejects(snapshot.execute({ path: 'escape/SKILL.md', sourceId: 'ecc' }, context), errorCode('PATH_DENIED'));
});

test('snapshot rejects hard links to files outside the selected skill', async (t) => {
  const { root, skill, context } = await fixture(t);
  const original = path.join(root, 'original.md');
  await writeFile(original, 'outside skill content');
  try { await link(original, path.join(skill, 'linked.md')); }
  catch (error) {
    if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) { t.skip('This environment does not permit creating hard links.'); return; }
    throw error;
  }
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context), errorCode('PATH_DENIED'));
});

test('snapshot bounds both raw file input and serialized output', async (t) => {
  const { skill, context } = await fixture(t);
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, { ...context, policy: { maxOutputBytes: 100 } }), errorCode('OUTPUT_LIMIT'));
  await writeFile(path.join(skill, 'too-large.txt'), 'x'.repeat(256 * 1024 + 1));
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context), errorCode('OUTPUT_LIMIT'));
});

test('snapshot bounds file count, empty directory count, and depth', async (t) => {
  const { skill, context } = await fixture(t);
  await Promise.all(Array.from({ length: 128 }, (_, i) => writeFile(path.join(skill, `file-${i}.txt`), 'x')));
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context), errorCode('OUTPUT_LIMIT'));
  const directories = await fixture(t);
  await Promise.all(Array.from({ length: 256 }, (_, i) => mkdir(path.join(directories.skill, `empty-${i}`))));
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, directories.context), errorCode('OUTPUT_LIMIT'));
  const deep = await fixture(t);
  await mkdir(path.join(deep.skill, ...Array(13).fill('nested')), { recursive: true });
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, deep.context), errorCode('OUTPUT_LIMIT'));
});

test('snapshot rejects invalid UTF-8, binary data, and malformed metadata', async (t) => {
  const { skill, context } = await fixture(t);
  const badFile = path.join(skill, 'data.txt');
  await writeFile(badFile, Buffer.from([0xff]));
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context), errorCode('SKILL_INVALID'));
  await writeFile(badFile, 'nul\0byte');
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context), errorCode('SKILL_INVALID'));
  await rm(badFile);
  for (const body of ['# Missing metadata', '---\nname: only-name\n---\n', '---\nname: duplicate\nname: duplicate\ndescription: text\n---\n']) {
    await writeFile(path.join(skill, 'SKILL.md'), body);
    await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context), errorCode('SKILL_INVALID'));
  }
});

test('snapshot parses text metadata without evaluating hooks or commands', async (t) => {
  const { skill, context } = await fixture(t);
  await writeFile(path.join(skill, 'SKILL.md'), '---\nname: "safe snapshot"\ndescription: >-\n  First line\n  second line\n---\nRun hooks.sh\n');
  await writeFile(path.join(skill, 'hooks.sh'), 'echo should-never-run > execution-marker.txt\n');
  const result = await snapshot.execute({ path: 'skill', sourceId: 'ecc' }, context);
  assert.equal(result.metadata.description, 'First line second line');
  assert.ok(result.files.some((file) => file.path === 'hooks.sh'));
  await assert.rejects(readFile(path.join(skill, 'execution-marker.txt')), (error) => error.code === 'ENOENT');
});

test('aborted snapshots stop before filesystem capture and policy limits are validated', async (t) => {
  const { context } = await fixture(t);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(snapshot.execute({ path: 'missing', sourceId: 'ecc' }, { ...context, signal: controller.signal }), errorCode('ABORTED'));
  await assert.rejects(snapshot.execute({ path: 'skill', sourceId: 'ecc' }, { ...context, policy: { maxOutputBytes: -1 } }), errorCode('POLICY_INVALID'));
});
