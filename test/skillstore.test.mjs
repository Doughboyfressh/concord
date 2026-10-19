import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { makeSkillStoreTools, skillSlug } from '../src/skillstore.mjs';
import { parseJson } from '../src/value.mjs';
import { realTempDir } from './temp-workspace.mjs';

// Adopting a skill, and knowing later whether what you adopted is still what you reviewed.

const policy = { maxOutputBytes: 1048576, timeoutMs: 10000 };
const byName = (tools) => new Map(tools.map((tool) => [tool.name, tool]));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** A workspace holding one real corpus file, and an inventory that describes it truthfully. */
function fixture(body = '# Greeting\n\nSay hello.\n') {
  const root = realTempDir('concord-skills-');
  const relative = 'upstream/example/skills/greeting/SKILL.md';
  fs.mkdirSync(path.join(root, path.dirname(relative)), { recursive: true });
  fs.writeFileSync(path.join(root, relative), body);
  const inventory = {
    capabilities: [{
      id: 'example:skills/greeting/SKILL.md', kind: 'skill', path: relative,
      sourceId: 'example', title: 'Greeting', status: 'source-available-unreviewed',
      sourceSha256: sha256(Buffer.from(body)),
    }],
  };
  return { root, relative, body, inventory, tools: byName(makeSkillStoreTools(inventory)), context: { workspaceRoot: root, policy } };
}

test('an install verifies the digest it was indexed with before it copies anything', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  const install = f.tools.get('skills.install');
  assert.equal(install.effect, 'write');

  const done = install.execute({ id: 'example:skills/greeting/SKILL.md' }, f.context);
  assert.equal(done.sha256, f.inventory.capabilities[0].sourceSha256);
  assert.equal(done.sourceId, 'example');
  assert.equal(done.title, 'Greeting');
  // The status the inventory recorded travels with it: unreviewed stays unreviewed.
  assert.equal(done.status, 'source-available-unreviewed');
  assert.equal(fs.readFileSync(path.join(f.root, done.installedAs), 'utf8'), f.body);

  const lock = parseJson(fs.readFileSync(path.join(f.root, 'skills/installed.json'), 'utf8'));
  assert.equal(lock.installed.length, 1);
  assert.equal(lock.installed[0].id, 'example:skills/greeting/SKILL.md');
  assert.equal(lock.installed[0].sourcePath, f.relative);

  // Installing the same skill twice is one entry, not two.
  install.execute({ id: 'example:skills/greeting/SKILL.md' }, f.context);
  assert.equal(parseJson(fs.readFileSync(path.join(f.root, 'skills/installed.json'), 'utf8')).installed.length, 1);
});

test('a file that does not match its recorded digest is refused rather than installed', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  // Someone edited the corpus after it was indexed. An import that does not check this is only a
  // copy, and a lock over unchecked copies locks nothing.
  fs.writeFileSync(path.join(f.root, f.relative), '# Greeting\n\nSay something else entirely.\n');
  assert.throws(
    () => f.tools.get('skills.install').execute({ id: 'example:skills/greeting/SKILL.md' }, f.context),
    (error) => error.code === 'SKILL_DIGEST',
  );
  assert.equal(fs.existsSync(path.join(f.root, 'skills')), false, 'nothing is written when the check fails');
});

test('an unknown id and an absent corpus are different refusals', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  const install = f.tools.get('skills.install');
  assert.throws(() => install.execute({ id: 'nobody:such/thing.md' }, f.context), (error) => error.code === 'SKILL_UNKNOWN');

  // The index can outlive the tree it indexed; saying which happened beats one vague error.
  fs.rmSync(path.join(f.root, 'upstream'), { recursive: true, force: true });
  assert.throws(() => install.execute({ id: 'example:skills/greeting/SKILL.md' }, f.context), (error) => error.code === 'SKILL_SOURCE');
});

test('a local edit and an upstream change are reported as different things', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  const installed = f.tools.get('skills.installed');
  assert.equal(installed.effect, 'read');

  // An empty store reads as empty rather than failing.
  assert.deepEqual(installed.execute({}, f.context).installed, []);

  const done = f.tools.get('skills.install').execute({ id: 'example:skills/greeting/SKILL.md' }, f.context);
  const clean = installed.execute({}, f.context);
  assert.equal(clean.count, 1);
  assert.equal(clean.installed[0].localChanged, false);
  assert.equal(clean.installed[0].upstream, 'same');

  // Editing my copy is not an upstream update, and collapsing the two would report it as one.
  fs.writeFileSync(path.join(f.root, done.installedAs), '# Greeting\n\nLocally adjusted.\n');
  const edited = installed.execute({}, f.context);
  assert.equal(edited.installed[0].localChanged, true);
  assert.equal(edited.installed[0].upstream, 'same');
  assert.equal(edited.changed, 1);
  assert.equal(edited.upstreamChanged, 0);

  // Upstream moving on is the other question.
  fs.writeFileSync(path.join(f.root, f.relative), '# Greeting\n\nUpstream rewrote this.\n');
  const moved = installed.execute({}, f.context);
  assert.equal(moved.installed[0].upstream, 'changed');
  assert.equal(moved.upstreamChanged, 1);

  // And a corpus that simply is not here is unavailable, not gone.
  fs.rmSync(path.join(f.root, 'upstream'), { recursive: true, force: true });
  assert.equal(installed.execute({}, f.context).installed[0].upstream, 'unavailable');

  assert.deepEqual(installed.execute({ sourceId: 'nobody' }, f.context).installed, []);
});

test('removing takes the file and the lock entry, and says when they disagreed', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  const remove = f.tools.get('skills.remove');
  assert.equal(remove.effect, 'write');
  assert.throws(() => remove.execute({ id: 'example:skills/greeting/SKILL.md' }, f.context), (error) => error.code === 'SKILL_UNKNOWN');

  const done = f.tools.get('skills.install').execute({ id: 'example:skills/greeting/SKILL.md' }, f.context);
  const gone = remove.execute({ id: 'example:skills/greeting/SKILL.md' }, f.context);
  assert.equal(gone.fileRemoved, true);
  assert.equal(gone.remaining, 0);
  assert.deepEqual(gone.limitations, []);
  assert.equal(fs.existsSync(path.join(f.root, done.installedAs)), false);

  // A lock entry can outlive its file if someone deleted the copy by hand; that is reported
  // rather than hidden behind a uniform-looking success.
  f.tools.get('skills.install').execute({ id: 'example:skills/greeting/SKILL.md' }, f.context);
  fs.rmSync(path.join(f.root, done.installedAs));
  const partial = remove.execute({ id: 'example:skills/greeting/SKILL.md' }, f.context);
  assert.equal(partial.fileRemoved, false);
  assert.equal(partial.limitations.length, 1);
});

test('an inventory id becomes a portable file name', () => {
  assert.equal(skillSlug('ecc:docs/ja-JP/skills/python-patterns/SKILL.md'), 'ecc-docs-ja-jp-skills-python-patterns-skill-md');
  assert.equal(skillSlug('a/b'), 'a-b');
  assert.ok(skillSlug('x'.repeat(400)).length <= 120);
  assert.throws(() => skillSlug('///'), (error) => error.code === 'SKILL_ID');
});
