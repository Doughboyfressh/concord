#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonical, digest, parseJson, HarnessError } from '../src/value.mjs';
import { runPlan, replayPlan } from '../src/engine.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';
import { makeSourceTools, loadSourceLock } from '../src/sources.mjs';
import { makeCapabilityTools } from '../src/capabilities.mjs';
import { makeArtifactTools } from '../src/artifacts.mjs';
import { makeReaderTools } from '../src/readers.mjs';
import { makeReverseTools } from '../src/reverse.mjs';
import { makeForeignTools } from '../src/foreign.mjs';
import { makeMailboxTools } from '../src/peer.mjs';
import { makeSkillStoreTools } from '../src/skillstore.mjs';
import { makeGovernanceTools } from '../src/governance.mjs';
import { exercises } from './train-exercises.mjs';
import { updateInstructions, verifyCorpus } from './train-consolidate.mjs';

/**
 * Fast training: exercise every capability, keep what the runs prove.
 *
 * `scripts/train.mjs` is the other kind — a live model answering six prompts, minutes per turn,
 * granting nothing. This is the cheap kind, and it is cheap because it needs no model at all.
 * Every exercise below is a real plan through the real kernel against the real registry, and
 * what gets written down afterwards is what the run actually demonstrated.
 *
 * The rule that makes this training rather than noise: a lesson is promoted only if the exercise
 * that produced it behaved exactly as predicted and then replayed. An exercise that surprises us
 * writes nothing to memory and is reported as a finding instead — a surprise is something to
 * investigate, not something to memorise.
 *
 * Refusals are first-class exercises. "This tool declines X, with code Y" is a durable fact about
 * the system and is usually worth more than another success.
 *
 *   node scripts/train-capabilities.mjs [--out docs/training-round-NNN.md]
 */

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const readJson = (file) => parseJson(fs.readFileSync(file, 'utf8'));

async function buildRegistry() {
  const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
  const inventory = readJson(path.join(root, 'capabilities.lock.json'));
  const reverseTable = readJson(path.join(root, 'reverse-tools.json'));
  const descriptors = [
    ...makeBuiltinTools(), ...makeSourceTools(catalog), ...makeCapabilityTools(inventory),
    ...makeArtifactTools(), ...makeReaderTools(), ...makeReverseTools(reverseTable, {}),
    ...makeForeignTools({ schemaVersion: 1, sources: [] }, {}),
    ...makeMailboxTools({ directory: path.join(root, 'runs', 'peer-mailbox') }),
    ...makeSkillStoreTools(inventory),
  ];
  const registry = new Map(descriptors.map((tool) => [tool.name, tool]));
  const runtimeFiles = fs.readdirSync(path.join(root, 'src')).filter((f) => f.endsWith('.mjs')).map((f) => 'src/' + f).sort();
  const sourceLock = {
    catalog, inventoryHash: digest(inventory),
    runtime: { node: process.version, platform: process.platform, arch: process.arch, files: runtimeFiles.map((f) => ({ path: f, sha256: sha256(fs.readFileSync(path.join(root, f))) })) },
  };
  for (const tool of makeGovernanceTools({ registry, sourceLock })) registry.set(tool.name, tool);
  const policy = {
    version: 1, allowedTools: [...registry.keys()].sort(),
    allowedEffects: ['pure', 'read', 'write', 'network', 'process'], allowedOrigins: [],
    maxTasks: 32, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 60000,
  };
  return { registry, policy, sourceLock, inventory };
}

/**
 * Run one plan, granting exactly the effects this exercise expects.
 *
 * A blocked run is re-attempted with that precise request hash, which is the approval loop the
 * whole system is built around rather than a shortcut past it.
 */
async function attempt({ plan, registry, policy, sourceLock, workspaceRoot, grant }) {
  let result = await runPlan({ plan, policy, registry, sourceLock, approvals: [], workspaceRoot });
  const approvals = [];
  while (grant && result.outcome.status === 'blocked' && approvals.length < 8) {
    approvals.push(result.outcome.requestHash);
    result = await runPlan({ plan, policy, registry, sourceLock, approvals, workspaceRoot });
  }
  return { result, approvals };
}

async function main() {
  const started = Date.now();
  const outFlag = process.argv.indexOf('--out');
  const outPath = outFlag > 0 && process.argv[outFlag + 1] ? path.resolve(root, process.argv[outFlag + 1]) : null;

  const { registry, policy, sourceLock, inventory } = await buildRegistry();
  const temp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'concord-train-')));
  const learned = [];
  const findings = [];

  for (const exercise of exercises(inventory)) {
    const workspaceRoot = exercise.workspace === 'temp' ? temp : root;
    // A reader exercise is only worth anything against real bytes, so a fixture is written into
    // the scratch workspace first. Built here rather than committed: a fixture that drifts from
    // the test that needs it is worse than no fixture.
    if (exercise.fixture) {
      try { exercise.fixture(temp); }
      catch (error) { findings.push({ family: exercise.family, tool: exercise.tool, note: 'fixture failed: ' + error.message }); continue; }
    }
    if (exercise.needsCorpus && !fs.existsSync(path.join(root, exercise.needsCorpus))) {
      findings.push({ family: exercise.family, tool: exercise.tool, note: 'skipped: the indexed corpus file is not present in this workspace' });
      continue;
    }
    if (exercise.needsCorpus && workspaceRoot === temp) {
      const target = path.join(temp, exercise.needsCorpus);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(root, exercise.needsCorpus), target);
    }

    let outcome;
    try {
      outcome = await attempt({ plan: exercise.plan, registry, policy, sourceLock, workspaceRoot, grant: exercise.grant });
    } catch (error) {
      findings.push({ family: exercise.family, tool: exercise.tool, note: 'threw ' + (error instanceof HarnessError ? error.code : error.message) });
      continue;
    }

    const { result, approvals } = outcome;
    const failure = result.events.find((event) => event.type === 'failed');
    const held = (() => {
      try {
        if (exercise.expectCode) return failure?.data?.toolCode === exercise.expectCode;
        return Boolean(exercise.expect(result, { workspaceRoot }));
      } catch { return false; }
    })();
    const approvalsMatch = exercise.expectApprovals === undefined || approvals.length === exercise.expectApprovals;

    if (!held || !approvalsMatch) {
      findings.push({
        family: exercise.family, tool: exercise.tool,
        note: `prediction did not hold (status ${result.outcome.status}, ${approvals.length} approvals)`,
      });
      continue;
    }

    // Replay is the second half of the evidence: a lesson is only as good as a run that
    // reproduces, so one that cannot be replayed is not promoted.
    let replayed = false;
    try {
      const check = replayPlan({ journal: result, plan: exercise.plan, policy, registry, sourceLock, approvals, workspaceRoot });
      replayed = check?.replayed === true;
    } catch { replayed = false; }
    if (!replayed) {
      findings.push({ family: exercise.family, tool: exercise.tool, note: 'ran as predicted but did not replay, so it was not promoted' });
      continue;
    }

    learned.push({
      family: exercise.family, tool: exercise.tool, lesson: exercise.lesson,
      // Evidence names what proved the lesson, not which run happened to prove it. The run root
      // changes on every execution, so including it made each round mint a fresh copy of an
      // identical lesson: 114 files for 61 lessons before this was caught. A plan digest plus
      // the outcome is reproducible by anyone, which is what evidence is supposed to be.
      evidence: { tool: exercise.tool, planHash: digest(exercise.plan), outcome: result.outcome.status, approvals: approvals.length, replayed: true },
    });
  }

  // Promotion goes through the same two-phase grant as everything else.
  const candidate = registry.get('memory.candidate');
  const kept = new Set();
  let promoted = 0;
  for (const entry of learned) {
    const draft = candidate.execute({ lesson: entry.lesson, evidence: [entry.evidence] });
    const plan = { version: 1, name: 'promote', tasks: [{ id: 'p', tool: 'memory.promote', input: draft }] };
    try {
      const { result } = await attempt({ plan, registry, policy, sourceLock, workspaceRoot: root, grant: true });
      if (result.outcome.status === 'completed') { promoted += 1; kept.add(draft.candidateHash); }
      else findings.push({ family: entry.family, tool: 'memory.promote', note: 'lesson did not promote: ' + result.outcome.status });
    } catch (error) {
      findings.push({ family: entry.family, tool: 'memory.promote', note: 'promotion threw ' + (error instanceof HarnessError ? error.code : error.message) });
    }
  }

  /**
   * Remove redundant copies of a lesson this round just promoted.
   *
   * Earlier rounds embedded the run root in their evidence, so the same lesson was stored again
   * on every execution: 114 files for 61 lessons. The evidence is reproducible now, but the old
   * copies remain, and a memory full of near-identical entries degrades recall the same way
   * near-duplicate corpus entries crowd a ranking. Only a lesson the round itself re-earned is
   * touched, and only its other copies: nothing is ever removed outright.
   */
  let pruned = 0;
  if (process.argv.includes('--prune')) {
    const memoryDir = path.join(root, 'memory');
    const promotedLessons = new Map();
    for (const name of fs.readdirSync(memoryDir).filter((entry) => entry.endsWith('.json'))) {
      let record;
      try { record = parseJson(fs.readFileSync(path.join(memoryDir, name), 'utf8')); } catch { continue; }
      if (!promotedLessons.has(record.lesson)) promotedLessons.set(record.lesson, []);
      promotedLessons.get(record.lesson).push({ name, hash: record.candidateHash });
    }
    for (const copies of promotedLessons.values()) {
      const keeper = copies.find((copy) => kept.has(copy.hash));
      if (!keeper) continue;
      for (const copy of copies) {
        if (copy.name === keeper.name) continue;
        fs.rmSync(path.join(memoryDir, copy.name));
        pruned += 1;
      }
    }
  }

  // Memory was the easy half. These two are what make the round change the next turn.
  const instructionsUpdated = updateInstructions({ root, learned });
  const corpus = verifyCorpus({ root, inventory });
  for (const bad of corpus.mismatched.slice(0, 5)) {
    findings.push({ family: 'corpus', tool: bad.sourceId, note: 'indexed digest does not match the file on disk: ' + bad.id });
  }

  fs.rmSync(temp, { recursive: true, force: true });
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  const stored = fs.readdirSync(path.join(root, 'memory')).filter((name) => name.endsWith('.json')).length;
  const exercised = new Set([...learned, ...findings].map((entry) => entry.tool));
  const coverage = `${exercised.size}/${registry.size}`;

  const report = [
    '# Capability training round',
    '',
    `Exercises run: **${learned.length + findings.length}**. Lessons earned and promoted: **${promoted}**. Findings: **${findings.length}**. Tools exercised: **${coverage}**. Wall clock: **${seconds}s**. Stored lessons now: **${stored}**.`,
    '',
    `Instruction modules deepened: **${instructionsUpdated.length}** (${instructionsUpdated.map((entry) => entry.sourceId).join(', ') || 'none'}). Skill corpus verified against its index: **${corpus.verified}** files match, **${corpus.mismatched.length}** drifted, **${corpus.absent}** not in this workspace.`,
    '',
    'Every lesson below came from a plan that ran through the real kernel, behaved exactly as predicted, and then replayed. A prediction that did not hold wrote nothing to memory and is listed as a finding instead: a surprise is something to investigate, not something to memorise.',
    '',
    '## Earned',
    '',
    '| Family | Tool | Lesson |',
    '| --- | --- | --- |',
    ...learned.map((entry) => `| ${entry.family} | \`${entry.tool}\` | ${entry.lesson} |`),
    '',
    '## Findings',
    '',
    ...(findings.length
      ? ['| Family | Tool | What happened |', '| --- | --- | --- |', ...findings.map((entry) => `| ${entry.family} | \`${entry.tool}\` | ${entry.note} |`)]
      : ['_None: every exercise behaved as predicted._']),
    '',
  ].join('\n');

  if (outPath) fs.writeFileSync(outPath, report + '\n');
  console.log(canonical({
    exercises: learned.length + findings.length, promoted, findings: findings.length, coverage,
    instructionsUpdated: instructionsUpdated.length, corpusVerified: corpus.verified,
    corpusDrifted: corpus.mismatched.length, pruned, seconds: Number(seconds), storedLessons: stored,
  }));
  for (const finding of findings) console.log('finding: ' + finding.family + ' ' + finding.tool + ' - ' + finding.note);
  if (outPath) console.log('report: ' + path.relative(root, outPath).split(path.sep).join('/'));
}

main().catch((error) => {
  console.error(error instanceof HarnessError ? `${error.code}: ${error.message}` : String(error?.stack ?? error));
  process.exitCode = 1;
});
