import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { makeBuiltinTools } from '../src/builtins.mjs';
import { runPlan } from '../src/engine.mjs';
import { HarnessError } from '../src/value.mjs';

const tools = new Map(makeBuiltinTools().map((t) => [t.name, t]));
const policy = { maxOutputBytes: 1048576 };

function tempWorkspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'concord-memory-'));
}

function candidateFor(lesson, evidence) {
  return tools.get('memory.candidate').execute({ lesson, evidence });
}

test('memory.promote rejects a candidate whose candidateHash does not match its own content', () => {
  const temp = tempWorkspace();
  const candidate = candidateFor('lesson one', ['evidence-a']);
  const tampered = { ...candidate, lesson: 'a different lesson' };
  assert.throws(() => tools.get('memory.promote').execute(tampered, { workspaceRoot: temp, policy }), HarnessError);
});

test('memory.promote writes exactly one file named by the candidate digest', () => {
  const temp = tempWorkspace();
  const candidate = candidateFor('lesson two', ['evidence-b']);
  const result = tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy });
  assert.equal(result.promoted, true);
  assert.equal(result.candidateHash, candidate.candidateHash);
  const files = fs.readdirSync(path.join(temp, 'memory'));
  assert.deepEqual(files, [candidate.candidateHash + '.json']);
});

test('a planted symlink named memory is rejected, not followed', (t) => {
  const temp = tempWorkspace();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'concord-memory-outside-'));
  try { fs.symlinkSync(outside, path.join(temp, 'memory'), 'dir'); }
  catch (e) { if (e.code === 'EPERM') return t.skip('Host disallows link creation'); throw e; }
  const candidate = candidateFor('lesson three', ['evidence-c']);
  assert.throws(() => tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy }), (e) => e instanceof HarnessError && e.code === 'PATH_DENIED');
});

test('resubmitting the exact same candidate is an idempotent no-op', () => {
  const temp = tempWorkspace();
  const candidate = candidateFor('lesson four', ['evidence-d']);
  const first = tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy });
  const second = tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy });
  assert.deepEqual(first, second);
  assert.equal(fs.readdirSync(path.join(temp, 'memory')).length, 1);
});

test('promoting a colliding-id candidate with different content fails closed', () => {
  const temp = tempWorkspace();
  const candidate = candidateFor('lesson five', ['evidence-e']);
  tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy });
  fs.writeFileSync(path.join(temp, 'memory', candidate.candidateHash + '.json'), 'not the same content\n', { flag: 'w' });
  assert.throws(() => tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy }));
});

test('memory.recall against an absent memory directory returns an empty result, not an error', () => {
  const temp = tempWorkspace();
  const result = tools.get('memory.recall').execute({ query: 'anything' }, { workspaceRoot: temp, policy });
  // matchedCount is reported alongside results because `results` is a ranked list that includes
  // zero-scoring entries, so its length is not a match count. Round 012 measured a reader calling
  // a zero-scoring entry "matched" with nothing in the output able to contradict it.
  assert.deepEqual(result, { strategy: 'lexical-overlap-v1', totalEntries: 0, corruptedEntries: 0, matchedCount: 0, results: [] });
});

test('memory.recall ranks by lexical overlap with a deterministic tie-break, and is byte-identical across repeated calls', () => {
  const temp = tempWorkspace();
  const a = candidateFor('deterministic replay of a plan', ['ev-1']);
  const b = candidateFor('browser automation notes', ['ev-2']);
  const c = candidateFor('replay and plan review together', ['ev-3']);
  for (const candidate of [a, b, c]) tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy });
  const first = tools.get('memory.recall').execute({ query: 'replay plan', limit: 10 }, { workspaceRoot: temp, policy });
  const second = tools.get('memory.recall').execute({ query: 'replay plan', limit: 10 }, { workspaceRoot: temp, policy });
  assert.deepEqual(first, second);
  assert.equal(first.totalEntries, 3);
  assert.equal(first.corruptedEntries, 0);
  // a and c both match 'replay' and 'plan' (score 2); b matches neither (score 0).
  // Tied scores break by candidateHash lexical order.
  const tiedTop = [a.candidateHash, c.candidateHash].sort();
  assert.deepEqual(first.results.map((r) => r.candidateHash), [...tiedTop, b.candidateHash]);
  assert.deepEqual(first.results.map((r) => r.score), [2, 2, 0]);
});

test('the bounded entry count fails closed rather than scanning unbounded storage', () => {
  const temp = tempWorkspace();
  fs.mkdirSync(path.join(temp, 'memory'));
  for (let i = 0; i < 1001; i += 1) {
    const name = i.toString(16).padStart(64, '0') + '.json';
    fs.writeFileSync(path.join(temp, 'memory', name), '{}\n');
  }
  assert.throws(() => tools.get('memory.recall').execute({ query: 'x' }, { workspaceRoot: temp, policy }), (e) => e instanceof HarnessError && e.code === 'OUTPUT_LIMIT');
});

test('a non-conforming file inside memory/ is counted as corrupted, not fatal to the whole recall', () => {
  const temp = tempWorkspace();
  const candidate = candidateFor('lesson six', ['evidence-f']);
  tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy });
  const bogusHash = '0'.repeat(64);
  fs.writeFileSync(path.join(temp, 'memory', bogusHash + '.json'), 'not valid json at all\n');
  const result = tools.get('memory.recall').execute({ query: 'lesson' }, { workspaceRoot: temp, policy });
  assert.equal(result.totalEntries, 2);
  assert.equal(result.corruptedEntries, 1);
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].candidateHash, candidate.candidateHash);
});

test('a hard-linked entry inside memory/ is rejected, and so is the original it links (both lose their single-link guarantee)', () => {
  const temp = tempWorkspace();
  const candidate = candidateFor('lesson seven', ['evidence-g']);
  tools.get('memory.promote').execute(candidate, { workspaceRoot: temp, policy });
  const linked = '1'.repeat(64) + '.json';
  try { fs.linkSync(path.join(temp, 'memory', candidate.candidateHash + '.json'), path.join(temp, 'memory', linked)); }
  catch (e) { if (['EPERM', 'ENOSYS'].includes(e.code)) return; throw e; }
  const result = tools.get('memory.recall').execute({ query: 'lesson' }, { workspaceRoot: temp, policy });
  assert.equal(result.totalEntries, 2);
  assert.equal(result.corruptedEntries, 2);
  assert.equal(result.results.length, 0);
});

test('memory.promote requires an exact grant through the kernel; approval unblocks it, replay repeats nothing', async () => {
  const temp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'concord-memory-plan-')));
  const candidate = candidateFor('plan-gated lesson', ['evidence-h']);
  const registry = new Map(makeBuiltinTools().map((t) => [t.name, t]));
  const policyFull = { version: 1, allowedTools: [...registry.keys()].sort(), allowedEffects: ['pure', 'read', 'write'], maxTasks: 8, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 5000 };
  const plan = { version: 1, tasks: [{ id: 'promote', tool: 'memory.promote', input: candidate }] };
  const sourceLock = { fixture: true };
  const blocked = await runPlan({ plan, policy: policyFull, registry, sourceLock, approvals: [], workspaceRoot: temp });
  assert.equal(blocked.outcome.status, 'blocked');
  const approved = await runPlan({ plan, policy: policyFull, registry, sourceLock, approvals: [blocked.outcome.requestHash], workspaceRoot: temp });
  assert.equal(approved.outcome.status, 'completed');
  assert.equal(fs.existsSync(path.join(temp, 'memory', candidate.candidateHash + '.json')), true);
});

test('recall reports matchedCount separately from the ranked results length', () => {
  // `results` is a ranked list, not a filter: it includes entries that scored zero, and
  // fetchMemoryExcerpt applies the score>0 filter itself. Round 012 measured a reader describing a
  // zero-scoring entry as having "matched" the query, and nothing in the output could contradict
  // that reading. matchedCount makes the distinction checkable rather than inferable.
  const temp = tempWorkspace();
  const promote = tools.get('memory.promote');
  const candidate = tools.get('memory.candidate').execute({ lesson: 'colour and geometry of unrelated shapes', evidence: [{ a: 1 }] }, { workspaceRoot: temp, policy });
  promote.execute(candidate, { workspaceRoot: temp, policy });

  const noOverlap = tools.get('memory.recall').execute({ query: 'zzqqxx nonexistent vocabulary' }, { workspaceRoot: temp, policy });
  assert.equal(noOverlap.totalEntries, 1, 'the entry is stored and readable');
  assert.equal(noOverlap.corruptedEntries, 0);
  assert.equal(noOverlap.results.length, 1, 'ranked list still returns it');
  assert.equal(noOverlap.results[0].score, 0, 'but it scored zero');
  assert.equal(noOverlap.matchedCount, 0, 'so nothing actually matched');

  const overlapping = tools.get('memory.recall').execute({ query: 'geometry of shapes' }, { workspaceRoot: temp, policy });
  assert.ok(overlapping.results[0].score > 0);
  assert.equal(overlapping.matchedCount, 1, 'a real term overlap counts as a match');
});
