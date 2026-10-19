import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { parseJson } from '../src/value.mjs';

/**
 * What a training round leaves behind besides memory.
 *
 * Memory is the easy half: a lesson is a file. The harder half is that the lessons should change
 * what Concord brings to its next turn, and that the corpus it draws on should be checked rather
 * than assumed. Two jobs, kept apart:
 *
 * Instructions. A reviewed instruction module is loaded into every chat turn and verified against
 * a digest in the manifest, and the manifest must cover *exactly* the pinned source set — one
 * module per source, named for it. So training cannot add a module, and does not try. What it can
 * do is deepen a module that already exists, in a delimited section it owns, and refresh that
 * module's digest. Only lessons genuinely about that source's own subject are written there; a
 * fact about Concord's kernel does not belong in REA's instructions just because it was learned
 * on the same afternoon.
 *
 * Skills. Every indexed skill carries the digest it was indexed with. Re-checking the corpus
 * against those digests is cheap and is the only way to notice that a source tree has drifted
 * from the index that describes it. A mismatch is reported, never repaired: the index is the
 * reviewed record, and silently rewriting it to match whatever is on disk now would destroy the
 * evidence that something changed.
 */

const BEGIN = '<!-- trained:begin -->';
const END = '<!-- trained:end -->';
// Raised from 12 once the chat context began selecting lessons per turn rather than taking the
// whole section. The module is the durable store and the context layer decides what a given turn
// needs, so this bounds what training may accumulate per source rather than what a model sees.
const MAX_LESSONS_PER_MODULE = 40;

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/**
 * Which source's instructions a family of lessons belongs in.
 *
 * Deliberately partial. Most of what training proves is about Concord's own kernel — approvals,
 * canonical values, refusals — and that belongs in memory rather than in a particular upstream's
 * instruction module. An unmapped family is simply not written anywhere.
 */
const FAMILY_TO_SOURCE = {
  readers: 'rea',
  formats: 'rea',
  evidence: 'rea',
  catalog: 'rea',
  skills: 'vercel-skills',
  delegation: 'hermes-agent',
  scheduling: 'hermes-agent',
  memory: 'hermes-agent',
  exchange: 'hermes-agent',
  governance: 'ecc',
};

/** Replace the section training owns, or append it; never touch the reviewed text around it. */
function rewriteSection(text, body) {
  const section = `${BEGIN}\n${body}\n${END}`;
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  if (start >= 0 && end > start) return text.slice(0, start) + section + text.slice(end + END.length);
  return text.replace(/\s*$/, '\n\n') + section + '\n';
}

export function updateInstructions({ root, learned }) {
  const instructionRoot = path.join(root, 'instructions');
  const manifestPath = path.join(instructionRoot, 'manifest.json');
  const manifest = parseJson(fs.readFileSync(manifestPath, 'utf8'));

  const bySource = new Map();
  for (const entry of learned) {
    const sourceId = FAMILY_TO_SOURCE[entry.family];
    if (!sourceId) continue;
    if (!bySource.has(sourceId)) bySource.set(sourceId, []);
    bySource.get(sourceId).push(entry);
  }

  const updated = [];
  for (const [sourceId, entries] of bySource) {
    const module = manifest.modules.find((candidate) => candidate.sourceId === sourceId);
    const file = path.join(instructionRoot, `${sourceId}.md`);
    if (!module || !fs.existsSync(file)) continue;

    /**
     * One slot per lesson, not one per tool that happens to share it.
     *
     * Deduplicating on the exact text was not enough. Reader lessons are generated from a template
     * and differ only by the tool name they open with, so twenty-six of them are the same sentence
     * twenty-six times over — and three of rea.md's twelve slots were holding it. These modules are
     * loaded into every live chat turn, so a quarter of that module's training payload was one
     * fact repeated, crowding out lessons that say something else.
     *
     * Collapsing on the text with the tool's own name removed fixes it, and the representative says
     * how many tools it speaks for. Dropping the count would be worse than keeping the duplicates:
     * a reader would have no way to tell a fact about one tool from a fact about twenty-six.
     *
     * Still sorted and capped, so the same lesson set always produces the same bytes — a module
     * that churned every round would make its digest worthless as a record of review. The count
     * only moves when the lessons themselves do, which is exactly when the digest should change.
     */
    const familyOf = (entry) => entry.lesson.split(entry.tool).join('').replace(/\s+/g, ' ').trim();
    const ordered = [...entries].sort((a, b) => (a.tool < b.tool ? -1 : a.tool > b.tool ? 1 : (a.lesson < b.lesson ? -1 : 1)));
    const families = new Map();
    for (const entry of ordered) {
      const key = familyOf(entry);
      if (!families.has(key)) families.set(key, { entry, shared: 0 });
      else families.get(key).shared += 1;
    }
    const lessons = [...families.values()].slice(0, MAX_LESSONS_PER_MODULE);

    const body = [
      '## Proven by training',
      '',
      'Each line below came from a plan that ran through this kernel, behaved exactly as predicted,',
      'and replayed. These are observations about behaviour, not permissions: nothing here grants',
      'anything, and an unreviewed source stays unreviewed.',
      '',
      ...lessons.map(({ entry, shared }) => shared
        ? `- \`${entry.tool}\`, and ${shared} other tool${shared === 1 ? '' : 's'} alike — ${entry.lesson}`
        : `- \`${entry.tool}\` — ${entry.lesson}`),
    ].join('\n');

    const next = rewriteSection(fs.readFileSync(file, 'utf8'), body);
    const bytes = Buffer.from(next, 'utf8');
    if (sha256(bytes) === module.sha256) continue;

    fs.writeFileSync(file, bytes);
    module.sha256 = sha256(bytes);
    module.bytes = bytes.length;
    updated.push({ sourceId, lessons: lessons.length, bytes: bytes.length });
  }

  if (updated.length) {
    // The manifest keeps exactly the modules it had: this refreshes digests and nothing else.
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  }
  return updated;
}

/**
 * Check every indexed skill against the digest it was indexed with.
 *
 * Fast enough to do in full rather than by sample, which matters: a sample that happens to miss
 * the one drifted file reports a clean corpus and is worse than not checking.
 */
export function verifyCorpus({ root, inventory }) {
  let verified = 0;
  let absent = 0;
  const mismatched = [];
  for (const entry of inventory.capabilities ?? []) {
    if (entry.kind !== 'skill' || typeof entry.sourceSha256 !== 'string' || typeof entry.path !== 'string') continue;
    const file = path.join(root, entry.path);
    let bytes;
    try { bytes = fs.readFileSync(file); } catch { absent += 1; continue; }
    if (sha256(bytes) === entry.sourceSha256) verified += 1;
    else mismatched.push({ id: entry.id, sourceId: entry.sourceId });
  }
  return { verified, absent, mismatched };
}
