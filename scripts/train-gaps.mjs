import fs from 'node:fs';
import path from 'node:path';

/**
 * Where the training is still blind, derived rather than remembered.
 *
 * Coverage counted by tools reached 79/79 and then stopped being informative: it says every tool
 * was touched once, which is the weakest thing coverage can mean. This derives the harder numbers
 * from the source and from the exercises themselves, so each round states its own frontier instead
 * of waiting for someone to notice it.
 *
 * Three axes, each chosen because it is checkable rather than because it is flattering:
 *
 *   codes        every refusal a source file can raise, against the ones an exercise names. Most
 *                are raised while building a registry and no plan can reach them, so a raw ratio
 *                would be a lie. Reachability is therefore not guessed: a code counts as reachable
 *                once a real run has actually raised it, and everything else is reported as
 *                unproven rather than as a failure.
 *   outputKeys   every key a tool declares it returns, against the ones an exercise reads. A tool
 *                whose `limitations` is never read has an untested disclosure, which is exactly the
 *                kind of thing that rots quietly.
 *   composition  tools exercised only in a single-task plan. The kernel exists to compose tools, so
 *                a suite made entirely of one-task plans has never tested the thing it is for.
 *
 * The honest limit of all this: it finds gaps, it does not fill them. A prediction this file wrote
 * and then confirmed would prove nothing at all, so it proposes work and never grades itself.
 */

/**
 * A thrown refusal and a code returned as data are not the same thing.
 *
 * Both spellings were counted together at first, and that made the frontier dishonest: three of
 * the codes it listed as "not yet shown reachable" were `experiment.compare` warnings, which are
 * returned inside a completed result and can never be raised as a refusal at all. They would have
 * sat on the frontier forever, and the denominator they inflated made coverage look worse than it
 * was. Only the thrown forms belong in a refusal count.
 */
/**
 * Matched on the shape a raised code always has: the code, then its message.
 *
 * The first version matched the call instead — `assert\([^,]+,\s*'CODE'` — and a negated character
 * class cannot cross a comma, so every assert whose *condition* contained one was skipped in
 * silence. REPLAY_CONTEXT and REPLAY_CHAIN were invisible that way, which means the denominator was
 * wrong in both directions at once: codes that do not exist sat on the frontier while codes that
 * do were never counted. Anchoring on the code-and-message pair instead is indifferent to whatever
 * the condition looks like, and it covers fail(), HarnessError() and assert() with one rule.
 *
 * The second string has to look like a message — containing a space or a lower-case letter —
 * because a bare pair of shouted strings is usually a list rather than a refusal. Without that,
 * `['ELOOP', 'EMLINK'].includes(code)` contributed ELOOP as a refusal code that nothing can raise,
 * and it would have sat on the frontier forever inflating the denominator.
 */
const THROWN_PATTERNS = [
  /'([A-Z][A-Z0-9_]{2,})'\s*,\s*'[^']*[a-z ][^']*'/g,
];

/**
 * `code: 'X'` in an object literal. A mixed population, which is why it is kept apart rather than
 * dropped: the engine builds its own failure codes this way, and so do tools reporting a warning
 * as part of a successful answer. Nothing can tell those apart by reading the text, so this is
 * reported as context and never used as a coverage denominator.
 */
const REPORTED_PATTERN = /code:\s*'([A-Z_]+)'/g;

/** Every refusal code the source can throw, with the first place it is thrown. */
export function declaredCodes(root) {
  const found = new Map();
  const reported = new Map();
  const dir = path.join(root, 'src');
  for (const name of fs.readdirSync(dir).filter((entry) => entry.endsWith('.mjs')).sort()) {
    const lines = fs.readFileSync(path.join(dir, name), 'utf8').split('\n');
    lines.forEach((line, index) => {
      for (const pattern of [...THROWN_PATTERNS, REPORTED_PATTERN]) {
        const into = pattern === REPORTED_PATTERN ? reported : found;
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(line)) !== null) {
          if (!into.has(match[1])) into.set(match[1], { code: match[1], file: 'src/' + name, line: index + 1 });
        }
      }
    });
  }
  // A code that is both thrown somewhere and built as data elsewhere counts as thrown.
  for (const code of found.keys()) reported.delete(code);
  found.reportedOnly = reported;
  return found;
}

/**
 * Which output keys an exercise reads, guessed from its source text.
 *
 * A fallback, and a poor one: it reads literal `results.a.key` spellings, so a prediction that
 * loops over a tool's declared keys checks every one of them and scores nothing. That measures how
 * a prediction is phrased rather than what it verifies. The caller should supply `assertedByTool`
 * instead, recorded from a real run by watching which properties the prediction actually touches.
 * This exists so the module still answers when run standalone, with no round to observe.
 */
export function assertedKeys(exercise) {
  if (typeof exercise.expect !== 'function') return new Set();
  const text = exercise.expect.toString();
  const keys = new Set();
  for (const pattern of [/results\.[a-z0-9]+\.([a-zA-Z0-9_]+)/g, /results\.[a-z0-9]+\[['"]([^'"]+)['"]\]/g]) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) keys.add(match[1]);
  }
  return keys;
}

/**
 * Watch a prediction run and record every output key it touches.
 *
 * Each task result is handed to the prediction behind a proxy that notes which properties are read.
 * That turns key coverage from a claim about source text into an observation of a real execution,
 * and it credits destructuring, computed keys and loops exactly as it credits a literal spelling.
 */
export function observeAssertedKeys(exercise, result, context) {
  const touched = new Map();
  if (typeof exercise.expect !== 'function' || !result?.results) return touched;
  const results = {};
  for (const [id, value] of Object.entries(result.results)) {
    if (!value || typeof value !== 'object') { results[id] = value; continue; }
    const seen = new Set();
    touched.set(id, seen);
    results[id] = new Proxy(value, {
      get(target, key) { if (typeof key === 'string') seen.add(key); return target[key]; },
    });
  }
  // The prediction has already been evaluated for real; this replay is only for observation, so a
  // throw here must never change the round's verdict.
  try { exercise.expect({ ...result, results }, context); } catch { /* observation only */ }
  return touched;
}

/** Tools that appear in a plan with more than one task. */
export function composedTools(exercises) {
  const composed = new Set();
  for (const exercise of exercises) {
    const tasks = exercise.plan?.tasks ?? [];
    if (tasks.length > 1) for (const task of tasks) composed.add(task.tool);
  }
  return composed;
}

/**
 * The whole picture.
 *
 * `observedCodes` is supplied by the caller from the round it just ran, because a code is only
 * known to be reachable once something has actually raised it. Nothing here infers reachability.
 */
export function analyseGaps({ root, exercises, registry, observedCodes = new Set(), assertedByTool = null, returnedByTool = null }) {
  const declared = declaredCodes(root);
  // Both kinds of prediction name a code: expectCode for a task that failed, expectThrow for a
  // plan refused while compiling. Counting only the first understated coverage of exactly the
  // guards that are hardest to reach.
  const named = new Set(exercises.flatMap((exercise) => [exercise.expectCode, exercise.expectThrow]).filter(Boolean));

  // A code an exercise names, or that a run raised, is proven reachable. The rest is the frontier.
  const proven = new Set([...named, ...observedCodes]);
  const unproven = [...declared.values()].filter((entry) => !proven.has(entry.code));
  // Raised by a real run but named by no prediction: the cheapest exercises to add next, because
  // reachability is already established and only the assertion is missing.
  const reachableUnnamed = [...observedCodes].filter((code) => !named.has(code) && declared.has(code)).sort();

  // Observed keys when the caller watched a round; otherwise the text-scanning fallback.
  const byTool = assertedByTool ?? (() => {
    const guessed = new Map();
    for (const exercise of exercises) {
      if (!guessed.has(exercise.tool)) guessed.set(exercise.tool, new Set());
      for (const key of assertedKeys(exercise)) guessed.get(exercise.tool).add(key);
    }
    return guessed;
  })();

  let declaredKeyCount = 0;
  let assertedKeyCount = 0;
  const unreadKeys = [];
  // A declared key that no real result ever contained: the descriptor overstates the tool.
  const overdeclared = [];
  for (const [name, tool] of registry) {
    const keys = tool.outputKeys;
    if (!Array.isArray(keys) || !keys.length) continue;
    const seen = byTool.get(name) ?? new Set();
    declaredKeyCount += keys.length;
    const missing = keys.filter((key) => !seen.has(key));
    assertedKeyCount += keys.length - missing.length;
    if (missing.length) unreadKeys.push({ tool: name, missing });

    const returned = returnedByTool?.get(name);
    if (!returned) continue;
    const absent = keys.filter((key) => !returned.has(key));
    if (absent.length) overdeclared.push({ tool: name, absent });
  }

  const composed = composedTools(exercises);
  const exercised = new Set(exercises.map((exercise) => exercise.tool));
  /**
   * Only a registry tool can appear in a plan, so only a registry tool can be a composition gap.
   *
   * This counted every exercise label, and most of the stragglers it kept reporting were labels
   * no plan could ever name: factories, engine entry points, value helpers, and the configured
   * tools a round registers nothing for. Thirty-nine of forty-one were in that class, which made
   * the number say "the suite is barely composing" when the truth was that it had nearly run out
   * of composable tools. A denominator containing permanently unreachable entries is the same
   * mistake the refusal count made with warnings returned as data, fixed the same way.
   */
  const addressable = [...exercised].filter((name) => registry?.has?.(name));
  const singleTaskOnly = addressable.filter((name) => !composed.has(name)).sort();
  const notAddressable = [...exercised].filter((name) => !registry?.has?.(name)).sort();

  return {
    codes: {
      declared: declared.size, named: named.size, observed: observedCodes.size,
      proven: proven.size, unproven: unproven.length,
      reportedOnly: declared.reportedOnly?.size ?? 0,
      reachableUnnamed,
      frontier: unproven.slice(0, 40).map((entry) => entry.code + ' (' + entry.file + ':' + entry.line + ')'),
    },
    outputKeys: {
      declared: declaredKeyCount, asserted: assertedKeyCount,
      unread: unreadKeys.sort((a, b) => b.missing.length - a.missing.length).slice(0, 25),
      overdeclared,
    },
    composition: {
      composed: composed.size, addressable: addressable.length,
      singleTaskOnly: singleTaskOnly.length, examples: singleTaskOnly.slice(0, 20),
      notAddressable: notAddressable.length,
    },
  };
}

/** Rendered into the round report, so the next round's work is read rather than recalled. */
export function renderGaps(gaps) {
  const lines = [
    '## Where the training is still blind',
    '',
    'Derived from the source and from the predictions themselves, not recorded by hand. Tool',
    'coverage is saturated, so these are the axes that still discriminate.',
    '',
    `**Refusal codes.** ${gaps.codes.declared} distinct codes are thrown across \`src/\`. ${gaps.codes.named} are named by a prediction and ${gaps.codes.observed} were actually raised during this round, leaving ${gaps.codes.unproven} whose reachability from a plan is unproven. A further ${gaps.codes.reportedOnly} codes only ever appear as data in an object literal, mixing the engine's own failure codes with warnings a tool returns inside a successful answer; they are excluded from the count above because a warning cannot be reached by refusing anything. Of what remains, much is raised while building a registry or driving a browser, where no plan reaches it, so this is a frontier rather than a failing grade — but it is not all unreachable, and the list below is where to look.`,
    '',
    `**Output keys.** ${gaps.outputKeys.asserted}/${gaps.outputKeys.declared} declared output keys are read by some prediction. A key no prediction reads has never been checked against a real run.`,
    '',
    `**Composition.** ${gaps.composition.composed} of the ${gaps.composition.addressable} registry tools an exercise names appear in a plan with more than one task; ${gaps.composition.singleTaskOnly === 1 ? 'one is exercised only alone' : gaps.composition.singleTaskOnly + ' are exercised only alone'}. A further ${gaps.composition.notAddressable} exercise labels are not plan-addressable at all - factories, engine entry points, value helpers, and tools a configured adapter would have to register - and are counted separately rather than held against this axis. The kernel exists to compose tools, so this is the axis where a high tool count is most misleading.`,
    '',
  ];
  if (gaps.codes.reachableUnnamed.length) {
    lines.push('### Raised by a run, named by no prediction', '',
      'The cheapest exercises to add next: a real run already raised these, so reachability is',
      'settled and only the assertion is missing.', '',
      ...gaps.codes.reachableUnnamed.map((code) => `- \`${code}\``), '');
  }
  if (gaps.outputKeys.overdeclared?.length) {
    lines.push('### Declared keys no real result contained', '',
      'The descriptor promises more than the tool delivered in this round. Either the tool omits a',
      'key it declares, in which case a caller trusting the declaration branches on something that',
      'is never there, or the exercise never reached the path that produces it. Both are worth',
      'knowing and they are not the same thing.', '',
      ...gaps.outputKeys.overdeclared.map((entry) => `- \`${entry.tool}\` — ${entry.absent.map((key) => '`' + key + '`').join(', ')}`), '');
  }
  if (gaps.outputKeys.unread.length) {
    lines.push('### Declared output keys no prediction reads', '',
      ...gaps.outputKeys.unread.map((entry) => `- \`${entry.tool}\` — ${entry.missing.map((key) => '`' + key + '`').join(', ')}`), '');
  }
  if (gaps.codes.frontier.length) {
    lines.push('### Refusal codes not yet shown reachable from a plan', '',
      ...gaps.codes.frontier.map((entry) => `- \`${entry}\``), '');
  }
  return lines.join('\n');
}
