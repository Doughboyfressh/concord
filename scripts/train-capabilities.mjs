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
import { analyseGaps, renderGaps, observeAssertedKeys } from './train-gaps.mjs';
import { CONTRACTS } from './train-exercises-derived.mjs';

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
  // A refusal code is only known to be reachable from a plan once a run has actually raised one.
  const observedCodes = new Set();
  // tool -> output keys some prediction was observed reading, accumulated across the round.
  const assertedByTool = new Map();
  // tool -> output keys a real result actually contained this round.
  const returnedByTool = new Map();

  /**
   * Derived contracts, tallied rather than promoted one tool at a time.
   *
   * A generated exercise carries no lesson of its own: seventy-two copies of "this tool refuses
   * malformed input" would crowd the memory they are supposed to improve. Each contract keeps the
   * tools it applies to and the tools that satisfied it, and becomes a single lesson afterwards
   * only if those two sets match.
   */
  const contracts = new Map();
  const contractFor = (name) => {
    if (!contracts.has(name)) contracts.set(name, { applicable: new Set(), held: new Set() });
    return contracts.get(name);
  };
  /** Route a verified exercise: a hand-written one earns its lesson, a generated one a tally. */
  const credit = (exercise, evidence) => {
    if (exercise.contract) { contractFor(exercise.contract).held.add(exercise.tool); return; }
    learned.push({ family: exercise.family, tool: exercise.tool, lesson: exercise.lesson, evidence });
  };

  // Counted here rather than inferred from what was learned: a derived exercise credits a contract
  // tally instead of a lesson, so counting lessons undercounts the work by the hundred-odd
  // generated checks, and the two contract lessons carry a contract name where a tool name goes.
  let attempted = 0;
  const exercisedTools = new Set();

  for (const exercise of exercises(inventory, registry)) {
    if (exercise.contract) contractFor(exercise.contract).applicable.add(exercise.tool);
    attempted += 1;
    if (registry.has(exercise.tool)) exercisedTools.add(exercise.tool);
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

    /**
     * A tighter output budget, for the exercises that exist to hit a budget.
     *
     * Narrowing only, and clamped rather than trusted: an exercise asking for a larger budget than
     * the round was given would be granting itself authority, which is the one thing a policy must
     * never let its subject do. Needed because some limits are only reachable at an exact budget —
     * memory.promote's OUTPUT_LIMIT fires on precisely one value, where the budget equals the
     * resolved input size, and no fixed round-wide budget can sit on every tool's boundary at once.
     */
    const taskPolicy = Number.isInteger(exercise.maxOutputBytes)
      ? { ...policy, maxOutputBytes: Math.min(exercise.maxOutputBytes, policy.maxOutputBytes) }
      : policy;

    let outcome;
    try {
      outcome = await attempt({ plan: exercise.plan, registry, policy: taskPolicy, sourceLock, workspaceRoot, grant: exercise.grant });
    } catch (error) {
      const code = error instanceof HarnessError ? error.code : null;
      if (code) observedCodes.add(code);
      /**
       * A plan refused while compiling never produces a journal, so there is nothing to replay.
       *
       * Reproducibility is still the price of promotion, and compiling a second time is what pays
       * it here: a refusal that fires once and not again is a flake, not a rule. The evidence says
       * it was proven by a repeated refusal rather than by a replayed run, because recording a
       * replay that never happened would corrupt the one thing memory is for.
       */
      if (exercise.expectThrow && code === exercise.expectThrow) {
        let again = null;
        try { await attempt({ plan: exercise.plan, registry, policy: taskPolicy, sourceLock, workspaceRoot, grant: exercise.grant }); }
        catch (second) { again = second instanceof HarnessError ? second.code : null; }
        if (again === code) {
          credit(exercise, { tool: exercise.tool, planHash: digest(exercise.plan), outcome: 'refused-at-compile', code, provenBy: 'compile-refusal-twice' });
        } else {
          findings.push({ family: exercise.family, tool: exercise.tool, note: 'refused ' + code + ' once but ' + (again ?? 'not at all') + ' on a second compile' });
        }
        continue;
      }
      findings.push({ family: exercise.family, tool: exercise.tool, note: 'threw ' + (code ?? error.message) });
      continue;
    }

    const { result, approvals } = outcome;
    const failure = result.events.find((event) => event.type === 'failed');
    if (failure?.data?.toolCode) observedCodes.add(failure.data.toolCode);
    if (failure?.data?.code) observedCodes.add(failure.data.code);
    if (result.outcome.code) observedCodes.add(result.outcome.code);
    const held = (() => {
      try {
        if (exercise.expectCode) {
          // toolCode is the refusal a tool itself raised; code is the engine's own, and is all
          // there is when the engine refused before any tool ran. The specific one wins.
          const raised = failure?.data?.toolCode ?? failure?.data?.code;
          if (raised !== exercise.expectCode) return false;
          // Distinct guards can share a single code, so the reason is sometimes the only thing
          // that tells them apart. Asserting the code alone would let one guard stand in for
          // another and report coverage it does not have.
          return !exercise.expectReason || String(failure?.data?.reason ?? '').includes(exercise.expectReason);
        }
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

    /**
     * Every tool returns every key it declares, with nothing undefined.
     *
     * Enforced here for every exercise rather than asserted inside each prediction, for two
     * reasons. A universal contract checked in one place cannot be forgotten by the next exercise
     * someone writes. And leaving it to predictions corrupted the measurement: a prediction that
     * touched all seven of a reader's keys to confirm they existed scored the same as one that
     * checked what the values meant, so key coverage read as 317/418 when most of that was
     * presence rather than content.
     *
     * An undefined value is the specific thing worth catching: it is outside the JSON domain, so
     * the kernel refuses to record the output and the run fails as OUTPUT_REJECTED naming no
     * cause. That is exactly how the artifact.compareHar defect presented.
     */
    const shapeGap = [];
    for (const [taskId, value] of Object.entries(result.results ?? {})) {
      const taskTool = exercise.plan?.tasks?.find((task) => task.id === taskId)?.tool;
      const declaredOut = registry.get(taskTool)?.outputKeys;
      if (!Array.isArray(declaredOut) || !value || typeof value !== 'object') continue;
      for (const key of declaredOut) if (value[key] === undefined) shapeGap.push(taskTool + '.' + key);
    }
    if (shapeGap.length) {
      findings.push({
        family: exercise.family, tool: exercise.tool,
        note: 'returned less than it declares: ' + shapeGap.join(', '),
      });
      continue;
    }

    // Which output keys this prediction actually read, watched rather than guessed from its text.
    // Only predictions that held are recorded: a key touched by a prediction that turned out to be
    // wrong has not been verified against anything.
    for (const [taskId, keys] of observeAssertedKeys(exercise, result, { workspaceRoot })) {
      const tool = exercise.plan?.tasks?.find((task) => task.id === taskId)?.tool;
      if (!tool) continue;
      if (!assertedByTool.has(tool)) assertedByTool.set(tool, new Set());
      for (const key of keys) assertedByTool.get(tool).add(key);
    }

    // What each tool actually returned, which is a different question from what a prediction read.
    // A declared key that never appears in any real result means the descriptor promises more than
    // the tool delivers, and callers written against the declaration would branch on a key that is
    // never there. No exercise has to be written per tool for this: the round already has the
    // outputs, so the check is free and cannot be forgotten.
    for (const [taskId, value] of Object.entries(result.results ?? {})) {
      const tool = exercise.plan?.tasks?.find((task) => task.id === taskId)?.tool;
      if (!tool || !value || typeof value !== 'object') continue;
      if (!returnedByTool.has(tool)) returnedByTool.set(tool, new Set());
      for (const key of Object.keys(value)) returnedByTool.get(tool).add(key);
    }

    // Replay is the second half of the evidence: a lesson is only as good as a run that
    // reproduces, so one that cannot be replayed is not promoted.
    let replayed = false;
    try {
      const check = replayPlan({ journal: result, plan: exercise.plan, policy: taskPolicy, registry, sourceLock, approvals, workspaceRoot });
      replayed = check?.replayed === true;
    } catch { replayed = false; }
    if (!replayed) {
      findings.push({ family: exercise.family, tool: exercise.tool, note: 'ran as predicted but did not replay, so it was not promoted' });
      continue;
    }

    // Evidence names what proved the lesson, not which run happened to prove it. The run root
    // changes on every execution, so including it made each round mint a fresh copy of an
    // identical lesson: 114 files for 61 lessons before this was caught. A plan digest plus
    // the outcome is reproducible by anyone, which is what evidence is supposed to be.
    credit(exercise, { tool: exercise.tool, planHash: digest(exercise.plan), outcome: result.outcome.status, approvals: approvals.length, replayed: true });
  }

  /**
   * A contract that held everywhere it applied becomes exactly one lesson.
   *
   * Promoted only if every tool the contract applies to satisfied it; a single exception makes the
   * general claim false, and recording it anyway would be the most misleading thing in the memory.
   * The evidence is the tool count and the sorted tool list, so the claim can be rechecked rather
   * than taken on trust.
   */
  for (const [name, tally] of contracts) {
    const lesson = CONTRACTS[name];
    if (!lesson) continue;
    const failed = [...tally.applicable].filter((tool) => !tally.held.has(tool)).sort();
    if (failed.length) {
      findings.push({ family: 'contract', tool: name, note: `held for ${tally.held.size} of ${tally.applicable.size} tools but not ${failed.slice(0, 6).join(', ')}, so the general claim was not promoted` });
      continue;
    }
    learned.push({
      family: 'contract', tool: name, lesson,
      evidence: { contract: name, tools: tally.held.size, appliesTo: [...tally.held].sort(), provenBy: 'every-tool-it-applies-to' },
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
  const coverage = `${exercisedTools.size}/${registry.size}`;
  const contractChecks = [...contracts.values()].reduce((sum, tally) => sum + tally.applicable.size, 0);
  const contractsHeld = [...contracts.values()].filter((tally) => tally.held.size === tally.applicable.size).length;
  // Derived, so the round names its own frontier rather than waiting for someone to notice it.
  const gaps = analyseGaps({ root, exercises: exercises(inventory, registry), registry, observedCodes, assertedByTool, returnedByTool });

  const report = [
    '# Capability training round',
    '',
    `Exercises run: **${attempted}**. Lessons earned and promoted: **${promoted}**. Findings: **${findings.length}**. Tools exercised: **${coverage}**. Wall clock: **${seconds}s**. Stored lessons now: **${stored}**.`,
    '',
    `Of those exercises, **${contractChecks}** were generated from the tools' own declarations rather than written by hand, across **${contracts.size}** derived contracts, **${contractsHeld}** of which held for every tool they apply to. A generated check cannot discover that a declaration is wrong, only that a tool and its declaration disagree, so each contract earns one lesson rather than one per tool.`,
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
    renderGaps(gaps),
    '',
  ].join('\n');

  if (outPath) fs.writeFileSync(outPath, report + '\n');
  console.log(canonical({
    exercises: attempted, promoted, findings: findings.length, coverage,
    contractChecks, contracts: contracts.size, contractsHeld,
    instructionsUpdated: instructionsUpdated.length, corpusVerified: corpus.verified,
    codesNamed: gaps.codes.named, codesObserved: gaps.codes.observed, codesUnproven: gaps.codes.unproven,
    outputKeys: gaps.outputKeys.asserted + '/' + gaps.outputKeys.declared, composed: gaps.composition.composed,
    corpusDrifted: corpus.mismatched.length, pruned, seconds: Number(seconds), storedLessons: stored,
  }));
  for (const finding of findings) console.log('finding: ' + finding.family + ' ' + finding.tool + ' - ' + finding.note);
  if (outPath) console.log('report: ' + path.relative(root, outPath).split(path.sep).join('/'));
}

main().catch((error) => {
  console.error(error instanceof HarnessError ? `${error.code}: ${error.message}` : String(error?.stack ?? error));
  process.exitCode = 1;
});
