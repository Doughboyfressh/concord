import { mkdirSync, readFileSync, readdirSync, writeFileSync, lstatSync, realpathSync, rmSync, renameSync, existsSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, digest, validateSchema, HarnessError } from './value.mjs';
import { workspaceFile, workspaceDir, readWorkspaceFile } from './workspace-fs.mjs';

// The optional third argument is a schema `description`: an allowed keyword that validation
// ignores and that the system prompt carries verbatim, so it is how a tool tells a model what it
// is for. Omitted by default, so every existing schema hashes exactly as it did.
/**
 * Create a file, or accept that it already holds exactly these bytes.
 *
 * Exclusive creation is why an approval can never silently replace existing user data, and that
 * stays. What changes is the one case where "already there" and "what you approved" are the same
 * thing: identical bytes. Re-running is then a no-op rather than an EEXIST, and `created` says
 * which happened, so a receipt never claims to have written something it found.
 *
 * This is what makes a long build recoverable. A plan whose fourth task fails cannot be
 * "resumed" — correcting the fourth task changes the plan hash, hence every approval hash, so it
 * is a different run by construction. The corrected plan therefore re-runs the three writes that
 * already landed, and before this it died on the first of them. The approval hash binds the exact
 * content, so bytes that match are bytes the operator approved; nothing else is ever accepted.
 *
 * @returns {boolean} true if this call created the file, false if it already held these bytes.
 */
function writeExclusiveOrIdentical(filename, contents) {
  const intended = Buffer.isBuffer(contents) ? contents : Buffer.from(contents, 'utf8');
  try {
    writeFileSync(filename, intended, { flag: 'wx' });
    return true;
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    // Compared as bytes, never as decoded text: two different encodings of the same string are
    // different files, and a comparison that called them equal would skip a write that mattered.
    if (!readFileSync(filename).equals(intended)) throw error;
    return false;
  }
}

const object = (properties, required = Object.keys(properties), description) => ({
  type: 'object', properties, required, additionalProperties: false,
  ...(description === undefined ? {} : { description }),
});
const string = { type: 'string', maxLength: 65536 };
const hash64 = { type: 'string', minLength: 64, maxLength: 64 };
const MAX_MEMORY_ENTRIES = 1000;
const MEMORY_DIR = 'memory';
/**
 * A promoted lesson, optionally retracting earlier ones.
 *
 * `supersedes` is absent from the required list on purpose. Records promoted before retraction
 * existed do not carry it, and they must keep validating and keep hashing to their own filenames
 * — the store is content-addressed, so a schema that rejected them would turn every lesson earned
 * so far into a corrupted entry. Present or absent, the digest is taken over whatever is there.
 */
const MAX_SUPERSEDES = 100;
const candidateSchema = object({
  version: { const: 1 }, lesson: string,
  evidenceHashes: { type: 'array', minItems: 1, maxItems: 1000, items: hash64 },
  status: { const: 'proposed' }, executable: { const: false }, candidateHash: hash64,
  supersedes: { type: 'array', maxItems: MAX_SUPERSEDES, items: hash64 },
}, ['version', 'lesson', 'evidenceHashes', 'status', 'executable', 'candidateHash']);
/** How many retracted or dangling hashes recall will name. The counts beside them stay exact. */
const MAX_LISTED_RETRACTIONS = 32;

// ---------------------------------------------------------------------------
// Arithmetic.
//
// A calculator has to be a parser, never an evaluator. `eval` and `new Function` would execute
// model-supplied source inside the kernel, and model output is untrusted by contract, so neither
// appears here. What follows is a recursive-descent parser over a fixed grammar: no variables, no
// assignment, no property access, no way to name anything outside the expression text.
//
// The operator set is chosen for REPRODUCIBILITY rather than for completeness, which is why it is
// smaller than a pocket calculator's. A pure tool makes the strictest promise in this codebase:
// the same input yields the same bytes on any machine, under any future Node, forever. IEEE-754
// specifies +, -, *, /, % and sqrt as exactly rounded, so those hold that promise. It does NOT
// specify sin, cos, tan, log, exp, or a fractional power — those are allowed to differ in the
// last bit between implementations, and V8 has changed its own more than once. Shipping them
// would mean recording a run here that replays differently on another machine, which is a worse
// failure than not offering the function. They are refused by name so a model is told the
// operation is excluded and why, instead of meeting a bare "unknown function".
const MATH_MAX_DEPTH = 32;
const MATH_MAX_EXPONENT = 1024;

const MATH_EXCLUDED = new Set([
  'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'atan2', 'sinh', 'cosh', 'tanh',
  'log', 'ln', 'log2', 'log10', 'exp', 'pow', 'random',
]);

const MATH_CONSTANTS = { pi: Math.PI, e: Math.E };

/**
 * Refuse a result canonical JSON could not carry.
 *
 * Infinity and NaN are not representable in this kernel's canonical form, so a tool returning one
 * would produce output that cannot be journalled — the failure would surface later, somewhere
 * less informative. Division by zero and overflow are therefore errors at the point they happen,
 * named for the operation that caused them.
 */
function mathFinite(value, operation) {
  if (Number.isNaN(value)) throw new HarnessError('MATH_UNDEFINED', `${operation} is undefined for those operands`);
  if (!Number.isFinite(value)) throw new HarnessError('MATH_RANGE', `${operation} overflowed the range a recorded number can hold`);
  return value;
}

/**
 * Integer exponentiation by squaring, built only from multiplications.
 *
 * Math.pow is not exactly rounded, so it cannot be used. Each multiplication here is, which makes
 * the result identical everywhere even though squaring rounds differently from a naive repeated
 * multiply. A fractional exponent has no such construction and is refused rather than approximated.
 */
function mathPower(base, exponent) {
  if (!Number.isInteger(exponent)) {
    throw new HarnessError('MATH_UNSUPPORTED', 'Only an integer exponent is supported: a fractional power is not specified to the last bit and so would not replay identically');
  }
  if (Math.abs(exponent) > MATH_MAX_EXPONENT) {
    throw new HarnessError('MATH_RANGE', `An exponent must be between -${MATH_MAX_EXPONENT} and ${MATH_MAX_EXPONENT}`, { exponent });
  }
  let result = 1;
  let factor = base;
  let remaining = Math.abs(exponent);
  while (remaining > 0) {
    if (remaining % 2 === 1) result = mathFinite(result * factor, 'exponentiation');
    remaining = Math.floor(remaining / 2);
    if (remaining > 0) factor = mathFinite(factor * factor, 'exponentiation');
  }
  return exponent < 0 ? mathFinite(1 / result, 'exponentiation') : result;
}

// Every one of these is exactly specified by IEEE-754 or by ECMA-262 in terms that leave no
// implementation freedom, so each returns the same bits on every platform.
const MATH_FUNCTIONS = {
  sqrt: { min: 1, max: 1, apply: ([x]) => {
    if (x < 0) throw new HarnessError('MATH_UNDEFINED', 'sqrt is undefined for a negative number', { value: x });
    return Math.sqrt(x);
  } },
  abs: { min: 1, max: 1, apply: ([x]) => Math.abs(x) },
  floor: { min: 1, max: 1, apply: ([x]) => Math.floor(x) },
  ceil: { min: 1, max: 1, apply: ([x]) => Math.ceil(x) },
  round: { min: 1, max: 1, apply: ([x]) => Math.round(x) },
  trunc: { min: 1, max: 1, apply: ([x]) => Math.trunc(x) },
  sign: { min: 1, max: 1, apply: ([x]) => Math.sign(x) },
  min: { min: 1, max: 64, apply: (args) => Math.min(...args) },
  max: { min: 1, max: 64, apply: (args) => Math.max(...args) },
};

function mathTokens(source) {
  const tokens = [];
  let at = 0;
  while (at < source.length) {
    const character = source[at];
    if (character === ' ' || character === '\t' || character === '\n' || character === '\r') { at += 1; continue; }
    if (character >= '0' && character <= '9' || character === '.') {
      const literal = /^(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?/.exec(source.slice(at));
      if (!literal) throw new HarnessError('MATH_SYNTAX', 'A number could not be read', { at });
      const value = Number(literal[0]);
      if (!Number.isFinite(value)) throw new HarnessError('MATH_RANGE', 'A literal is outside the range a number can hold', { literal: literal[0] });
      tokens.push({ type: 'number', value });
      at += literal[0].length;
      continue;
    }
    if (/[a-zA-Z]/.test(character)) {
      const name = /^[a-zA-Z][a-zA-Z0-9]*/.exec(source.slice(at))[0];
      tokens.push({ type: 'name', value: name.toLowerCase() });
      at += name.length;
      continue;
    }
    if ('+-*/%^(),'.includes(character)) { tokens.push({ type: character }); at += 1; continue; }
    throw new HarnessError('MATH_SYNTAX', 'Unexpected character in the expression', { character, at });
  }
  return tokens;
}

/**
 * expression := term (('+' | '-') term)*
 * term       := unary (('*' | '/' | '%') unary)*
 * unary      := ('+' | '-') unary | power
 * power      := primary ('^' unary)?
 * primary    := number | constant | name '(' expression (',' expression)* ')' | '(' expression ')'
 *
 * `unary` sits above `power` so that -2^2 is -(2^2), the convention every calculator uses, and
 * `power`'s right side is a unary so that 2^-1 parses and 2^3^2 associates rightwards.
 */
function mathParse(tokens, source) {
  let index = 0;
  let depth = 0;
  const peek = () => tokens[index];

  const expect = (type, message) => {
    if (peek()?.type !== type) throw new HarnessError('MATH_SYNTAX', message, { expression: source });
    index += 1;
  };

  function expression() {
    depth += 1;
    if (depth > MATH_MAX_DEPTH) throw new HarnessError('MATH_DEPTH', `An expression may nest at most ${MATH_MAX_DEPTH} deep`);
    let value = term();
    for (;;) {
      const token = peek();
      if (token?.type === '+') { index += 1; value = mathFinite(value + term(), 'addition'); continue; }
      if (token?.type === '-') { index += 1; value = mathFinite(value - term(), 'subtraction'); continue; }
      break;
    }
    depth -= 1;
    return value;
  }

  function term() {
    let value = unary();
    for (;;) {
      const token = peek();
      if (token?.type === '*') { index += 1; value = mathFinite(value * unary(), 'multiplication'); continue; }
      if (token?.type === '/') {
        index += 1;
        const divisor = unary();
        if (divisor === 0) throw new HarnessError('MATH_UNDEFINED', 'Division by zero');
        value = mathFinite(value / divisor, 'division');
        continue;
      }
      if (token?.type === '%') {
        index += 1;
        const divisor = unary();
        if (divisor === 0) throw new HarnessError('MATH_UNDEFINED', 'Remainder by zero');
        value = mathFinite(value % divisor, 'remainder');
        continue;
      }
      break;
    }
    return value;
  }

  function unary() {
    const token = peek();
    if (token?.type === '-') { index += 1; return mathFinite(-unary(), 'negation'); }
    if (token?.type === '+') { index += 1; return unary(); }
    return power();
  }

  function power() {
    const base = primary();
    if (peek()?.type === '^') { index += 1; return mathPower(base, unary()); }
    return base;
  }

  function primary() {
    const token = peek();
    if (token === undefined) throw new HarnessError('MATH_SYNTAX', 'The expression ended before it was complete', { expression: source });
    if (token.type === 'number') { index += 1; return token.value; }
    if (token.type === '(') {
      index += 1;
      const value = expression();
      expect(')', 'A parenthesis was opened and never closed');
      return value;
    }
    if (token.type === 'name') {
      index += 1;
      const name = token.value;
      if (peek()?.type !== '(') {
        if (Object.hasOwn(MATH_CONSTANTS, name)) return MATH_CONSTANTS[name];
        throw new HarnessError('MATH_UNKNOWN', 'Unknown name in the expression', { name, known: Object.keys(MATH_CONSTANTS).sort().join(',') });
      }
      if (MATH_EXCLUDED.has(name)) {
        throw new HarnessError('MATH_UNSUPPORTED', `${name} is deliberately not offered: its result is not specified to the last bit, so a run recorded with it could replay differently on another machine`, { name });
      }
      if (!Object.hasOwn(MATH_FUNCTIONS, name)) {
        throw new HarnessError('MATH_UNKNOWN', 'Unknown function', { name, known: Object.keys(MATH_FUNCTIONS).sort().join(',') });
      }
      index += 1;
      const args = [expression()];
      while (peek()?.type === ',') { index += 1; args.push(expression()); }
      expect(')', `The arguments to ${name} were not closed`);
      const definition = MATH_FUNCTIONS[name];
      if (args.length < definition.min || args.length > definition.max) {
        throw new HarnessError('MATH_ARITY', `${name} takes between ${definition.min} and ${definition.max} arguments`, { given: args.length });
      }
      return mathFinite(definition.apply(args), name);
    }
    throw new HarnessError('MATH_SYNTAX', 'An operator appeared where a value was expected', { expression: source });
  }

  const value = expression();
  if (index !== tokens.length) throw new HarnessError('MATH_SYNTAX', 'The expression had trailing text that is not part of it', { expression: source });
  return value;
}

export function makeBuiltinTools() {
  return [
    { name: 'json.value', version: '1.0.0', effect: 'pure', inputSchema: true,
      execute(input) { return input; } },
    { name: 'json.hash', version: '1.0.0', outputKeys: ['algorithm', 'digest'], effect: 'pure', inputSchema: true,
      execute(input) { return { algorithm: 'sha256/concord-json-v1', digest: digest(input) }; } },
    { name: 'json.assert', version: '1.0.0', outputKeys: ['evidenceHash', 'passed', 'value'], effect: 'pure', inputSchema: object({ value: {}, schema: {} }),
      execute({ value, schema }) { validateSchema(value, schema); return { passed: true, value, evidenceHash: digest(value) }; } },
    { name: 'text.concat', version: '1.0.0', outputKeys: ['value'], effect: 'pure', inputSchema: object({ values: { type: 'array', items: string, minItems: 1, maxItems: 1000 }, separator: string }),
      // A fixed, explicit join over caller-ordered values — no format sniffing, no implicit separator.
      // Self-validates rather than trusting the declared schema alone: a pure tool's execute()
      // can be, and elsewhere in this codebase already is, called directly on unsanitized input
      // (chat-context.mjs calls capabilities.search.execute() directly for exactly this reason).
      execute({ values, separator }) {
        if (!values.every((v) => typeof v === 'string')) throw new HarnessError('INPUT_INVALID', 'Every value must be a string');
        return { value: values.join(separator) };
      } },
    { name: 'json.mergeShallow', version: '1.0.0', outputKeys: ['value'], effect: 'pure', inputSchema: object({ values: { type: 'array', items: { type: 'object' }, minItems: 1, maxItems: 1000 } }),
      // Fail-closed on any key collision rather than silently last-write-wins: combining
      // concurrent results (e.g. process.runMany's own output) must not hide a real conflict.
      // Rejects __proto__/prototype/constructor itself rather than relying solely on the
      // kernel's own canonical()/validateSchema() gate for that discipline (same reasoning as
      // text.concat above) — assigning an untrusted "__proto__" key into a plain {} object
      // triggers Object.prototype's accessor instead of creating a normal own property.
      execute({ values }) {
        const unsafe = new Set(['__proto__', 'prototype', 'constructor']);
        const seen = new Set();
        const merged = {};
        for (const entry of values) {
          if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) throw new HarnessError('INPUT_INVALID', 'Every value must be a plain object');
          for (const key of Object.keys(entry)) {
            if (unsafe.has(key)) throw new HarnessError('INPUT_INVALID', 'Unsafe object key', { key });
            if (seen.has(key)) throw new HarnessError('MERGE_COLLISION', 'Duplicate key across merge inputs', { key });
            seen.add(key);
            merged[key] = entry[key];
          }
        }
        return { value: merged };
      } },
    // Pure, because arithmetic is a function of its input and nothing else. That is also why the
    // grammar is restricted: see the note above mathTokens for which operations are exactly
    // specified and which are refused for being unable to promise the same bits twice.
    { name: 'math.evaluate', version: '1.0.0', outputKeys: ['value', 'expression', 'limitations'], effect: 'pure',
      inputSchema: object({ expression: { type: 'string', minLength: 1, maxLength: 1024 } }, ['expression'],
        'Evaluate an arithmetic expression exactly. Supports + - * / % and ^ with an integer exponent, parentheses, the functions sqrt abs floor ceil round trunc sign min max, and the constants pi and e. Transcendental functions are refused because their results are not bit-identical across platforms and so would not replay.'),
      // Self-validates rather than trusting the declared schema alone, for the same reason
      // text.concat does: a pure tool's execute() is called directly on unsanitized input elsewhere.
      execute({ expression }) {
        if (typeof expression !== 'string') throw new HarnessError('INPUT_INVALID', 'expression must be a string');
        const value = mathParse(mathTokens(expression), expression);
        return {
          value,
          expression,
          limitations: [
            'Computed in IEEE-754 double precision: about 15 significant digits, and 0.1 + 0.2 is not exactly 0.3. Do not settle money to the cent with it',
            'sin, cos, tan, log, exp and fractional powers are refused rather than approximated, because their results are not specified to the last bit and a run recorded with one could replay differently elsewhere',
          ],
        };
      } },
    // A read effect, not a pure one, and this is the whole design of it.
    //
    // The kernel may not read a clock — reading one twice gives two answers, which is the exact
    // shape of thing that breaks replay. AGENTS.md allows ambient state in only one way: through
    // an explicit effect. A read effect is recorded when it runs and never invoked again on
    // replay, so the recorded instant is what a replay sees. The run stays byte-identical; what
    // changes is only that two LIVE runs of the same plan differ, which is already true of every
    // tool that reads a file.
    //
    // schedule.due is left exactly as it was, still requiring `now` from its caller. It was
    // written that way to keep itself reproducible, and it still is — the difference is that the
    // caller now has somewhere true to get the answer instead of the model inventing a timestamp.
    // Feed one into the other with a task reference: {"$task": "clock", "path": "/iso"}.
    { name: 'time.now', version: '1.0.0', outputKeys: ['iso', 'epochMs', 'limitations'], effect: 'read',
      inputSchema: { type: 'object', additionalProperties: false, properties: {},
        description: 'Read the current time from the host clock, as a UTC ISO-8601 timestamp and epoch milliseconds. Recorded when it runs, so a replay sees the instant that was recorded rather than the time of the replay.' },
      execute() {
        const at = new Date();
        const epochMs = at.getTime();
        // Date can hold an invalid instant; a tool that returned one would emit NaN, which
        // canonical JSON cannot carry. Checked rather than assumed.
        if (!Number.isFinite(epochMs)) throw new HarnessError('CLOCK_UNAVAILABLE', 'The host clock did not return a usable instant');
        return {
          iso: at.toISOString(),
          epochMs,
          limitations: [
            'UTC only, to millisecond precision. No timezone or calendar conversion is performed here',
            'The instant is whatever the host clock said, which is not evidence that the host clock is correct',
            'Recorded, so a replay returns the instant this run observed and not the time of the replay',
          ],
        };
      } },
    { name: 'skills.rank', version: '1.0.0', outputKeys: ['ranked', 'strategy'], effect: 'pure', inputSchema: object({ query: string, skills: { type: 'array', maxItems: 10000, items: object({ id: string, text: string }) }, limit: { type: 'integer', minimum: 1, maximum: 100 } }, ['query', 'skills']),
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
    // Measurement discipline as a capability rather than as advice. Sixteen rounds of this project
    // produced one finding more reliable than any other: the instrument is usually wrong before the
    // system under test is. Round 007 treated five runs of an UNVARIED test as five data points and
    // published a conclusion it had to withdraw. Rounds 008 through 015 each shipped a probe whose
    // own expectation was faulty — an impossible demand, a better outcome scored as failure, a
    // bucket that silently absorbed an unanticipated case, a test that passed identically whether or
    // not the defect was present. Those are mechanically detectable, and detecting them is worth
    // more than any individual lesson, so they are checked here instead of being hoped for.
    //
    // Deliberately emits NO aggregate score. "Nine of ten" hides which condition failed, which is
    // precisely how rounds 004 and 005 drew the wrong conclusion from their own results table.
    { name: 'experiment.compare', version: '1.0.0',
      outputKeys: ['hypothesis', 'verdicts', 'confirmed', 'refuted', 'untestable', 'warnings', 'discriminating'],
      effect: 'pure',
      inputSchema: object({
        hypothesis: string,
        conditions: { type: 'array', minItems: 1, maxItems: 200, items: object({
          name: string, varied: true, expected: true, actual: true,
        }, ['name', 'varied']) },
      }),
      execute({ hypothesis, conditions }) {
        const names = conditions.map((c) => c.name);
        if (new Set(names).size !== names.length) throw new HarnessError('INPUT_INVALID', 'Condition names must be distinct');

        const verdicts = conditions.map((c) => {
          // An absent expectation or outcome cannot be judged. Reporting it as a pass or a failure
          // is how a probe invents a finding; untestable is the honest third verdict.
          if (c.expected === undefined) return { name: c.name, verdict: 'untestable', why: 'no expectation was declared' };
          if (c.actual === undefined) return { name: c.name, verdict: 'untestable', why: 'no outcome was recorded' };
          return canonical(c.actual) === canonical(c.expected)
            ? { name: c.name, verdict: 'confirmed' }
            : { name: c.name, verdict: 'refuted', why: 'the recorded outcome differs from the declared expectation' };
        });

        const warnings = [];
        if (conditions.length === 1) {
          warnings.push({ code: 'SINGLE_CONDITION', detail: 'One condition cannot isolate a cause; vary a named factor and compare.' });
        }
        // Identical varied factors are one data point repeated, not several. This is the round 007
        // error stated mechanically.
        const byVaried = new Map();
        for (const c of conditions) {
          const key = canonical(c.varied);
          byVaried.set(key, [...(byVaried.get(key) ?? []), c.name]);
        }
        for (const group of byVaried.values()) {
          if (group.length > 1) {
            warnings.push({ code: 'UNVARIED_CONDITIONS',
              detail: `These conditions vary nothing between them, so they are one data point rather than ${group.length}: ${group.join(', ')}.` });
          }
        }
        // If every condition expects the same thing, a pass does not show the varied factor
        // mattered — the test would read identically whether or not the effect was present.
        const expectations = new Set(conditions.filter((c) => c.expected !== undefined).map((c) => canonical(c.expected)));
        const discriminating = !(conditions.length > 1 && expectations.size === 1);
        if (!discriminating) {
          warnings.push({ code: 'NONDISCRIMINATING_EXPECTATION',
            detail: 'Every condition declares the same expectation, so the result cannot distinguish the varied factor from a test that would pass regardless.' });
        }

        const count = (v) => verdicts.filter((x) => x.verdict === v).map((x) => x.name);
        // Per condition, never a rate: an aggregate conceals which condition failed.
        return { hypothesis, verdicts, confirmed: count('confirmed'), refuted: count('refuted'),
          untestable: count('untestable'), warnings, discriminating };
      } },
    { name: 'judgment.gate', version: '1.0.0', effect: 'pure', inputSchema: object({ score: { type: 'number', minimum: 0, maximum: 1 }, threshold: { type: 'number', minimum: 0, maximum: 1 }, evidence: {} }),
      execute({ score, threshold, evidence }) {
        if (score < threshold) throw new HarnessError('JUDGMENT_REJECTED', 'Evidence does not meet the declared threshold');
        return { accepted: true, score, threshold, evidenceHash: digest(evidence), grantsCapabilities: false };
      } },
    /**
     * A lesson, and what it retracts.
     *
     * The store is content-addressed and append-only, which is what makes it tamper-evident and
     * is not negotiable. So a lesson that later evidence falsifies cannot be edited or deleted —
     * the only honest move is to record the correction as a new lesson that NAMES the one it
     * replaces. That keeps the fact that something was once believed, and why, which a deletion
     * would destroy; `memory.recall` then stops serving what a retraction supersedes.
     *
     * `supersedes` is always emitted, empty when nothing is retracted, because outputKeys names
     * the keys a result ALWAYS has and a model builds task references from exactly that list.
     */
    { name: 'memory.candidate', version: '2.0.0', outputKeys: ['candidateHash', 'evidenceHashes', 'executable', 'lesson', 'status', 'supersedes', 'version'], effect: 'pure',
      inputSchema: object({
        lesson: string,
        evidence: { type: 'array', minItems: 1, maxItems: 1000, items: true },
        supersedes: { type: 'array', maxItems: MAX_SUPERSEDES, items: hash64 },
      }, ['lesson', 'evidence']),
      execute({ lesson, evidence, supersedes = [] }) {
        const candidate = { version: 1, lesson, evidenceHashes: evidence.map(digest).sort(), status: 'proposed', executable: false,
          // Sorted and de-duplicated so the same retraction expressed two ways is one record.
          supersedes: [...new Set(supersedes)].sort() };
        return { ...candidate, candidateHash: digest(candidate) };
      } },
    { name: 'files.read', version: '1.0.0', outputKeys: ['bytes', 'path', 'sha256', 'text', 'untrusted'], effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, limit);
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        return { path: relative, text, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), untrusted: true };
      } },
    /**
     * Two write tools, and the only thing distinguishing them was their names.
     *
     * A model is given each tool's name, version, effect and inputSchema and nothing else, so
     * `files.write` reads as the general one and `files.writeText` as a variant for a special
     * case — when the truth is the other way round for anything a browser or compiler has to
     * read. Measured live: asked for a static site, Concord chose files.write four times and
     * produced four JSON documents, each one a quoted string where HTML and CSS should have been.
     * The plan completed, every receipt was honest, and the site did not exist.
     *
     * `description` is already an allowed schema keyword and is inert during validation, so the
     * fix belongs in the contract the model actually reads rather than in prose somewhere else.
     */
    { name: 'files.write', version: '1.2.0', outputKeys: ['contentHash', 'created', 'path'], effect: 'write',
      inputSchema: object({
        path: string,
        content: { description: 'Any JSON value. It is written as canonical JSON, so a string arrives on disk quoted and escaped rather than as its own bytes.' },
      }, ['path', 'content'], 'Create a JSON document. Use this for structured records this harness will read back. For a file whose bytes must be exactly the text given — HTML, CSS, JavaScript, Markdown, anything another program parses — use files.writeText instead.'),
      execute({ path: relative, content }, context) {
        const filename = workspaceFile(context.workspaceRoot, relative);
        const text = canonical(content) + '\n';
        // Unreachable from a plan, and kept anyway. The engine admits a task only if its whole
        // resolved input fits the same budget, and here that input is the content plus a wrapper of
        // key names, so it always exceeds the bound strictly earlier and the task fails INPUT_LIMIT
        // instead. A boundary sweep confirmed it: no content size produces this refusal. It stays
        // because the tool should not depend on a caller having checked, and because the identical
        // guard in memory.promote is reachable, at exactly the budget equal to its input.
        if (Buffer.byteLength(text) > context.policy.maxOutputBytes) throw new HarnessError('OUTPUT_LIMIT', 'Write exceeds byte budget');
        // Exclusive creation: an approval cannot silently replace existing user data. An identical
        // rewrite is the one exception, and it is not an exception to that rule at all -- see
        // `created` below.
        const created = writeExclusiveOrIdentical(filename, text);
        return { path: relative, contentHash: digest(content), created };
      } },
    /**
     * Changing a file that already exists, bound to the bytes it expected to find.
     *
     * files.write creates exclusively, on the stated grounds that an approval must not silently
     * replace existing user data. That is right, and it left this harness able to create a file
     * and never able to change one: of six write tools exactly one touched the filesystem, and it
     * could only ever add. These three close that without giving up the reason for it.
     *
     * The binding is expectedSha256. A plan states which bytes it believes are there, the
     * approval hash covers that claim along with the rest of the resolved input, and the edit
     * lands only if the file still hashes to it. So an operator approves a change to content they
     * reviewed, and a file that moved underneath them refuses instead of being overwritten from a
     * stale reading. It is the bargain the approval gate already makes about effects, applied to
     * the thing the effect is about.
     *
     * A precondition that does not hold is DATA, not a refusal: it returns applied:false with a
     * reason. Throwing would be worse than useless, because the engine records any throw from a
     * gated tool as EFFECT_INDETERMINATE - "this may have happened" - when nothing has happened
     * at all. build.run already draws this line, treating a non-zero exit as data and reserving
     * refusal for transport, timeout and abort. The same line is drawn here.
     */
    { name: 'files.edit', version: '1.0.0',
      outputKeys: ['path', 'applied', 'reason', 'replacements', 'sha256Before', 'sha256After', 'bytesBefore', 'bytesAfter'],
      effect: 'write',
      inputSchema: object({
        path: string,
        expectedSha256: { type: 'string', minLength: 64, maxLength: 64 },
        find: { type: 'string', minLength: 1, maxLength: 65536 },
        replace: { type: 'string', maxLength: 65536 },
        expectedOccurrences: { type: 'integer', minimum: 1, maximum: 10000 },
      }, ['path', 'expectedSha256', 'find', 'replace']),
      execute({ path: relative, expectedSha256, find, replace, expectedOccurrences }, context) {
        const filename = workspaceFile(context.workspaceRoot, relative);
        const before = readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / 8));
        const sha256Before = createHash('sha256').update(before).digest('hex');
        const unchanged = { path: relative, applied: false, replacements: 0, sha256Before, sha256After: sha256Before, bytesBefore: before.length, bytesAfter: before.length };
        if (sha256Before !== expectedSha256) {
          return { ...unchanged, reason: 'The file does not currently hash to expectedSha256, so this edit was written against different content' };
        }
        let text;
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(before); }
        catch { return { ...unchanged, reason: 'The file is not valid UTF-8 text, so a textual edit cannot be applied to it' }; }
        const parts = text.split(find);
        const found = parts.length - 1;
        if (found === 0) return { ...unchanged, reason: 'The text to replace does not appear in the file' };
        // One match unless the caller said how many to expect. An edit that silently changed
        // three places where its author pictured one is the failure this guard exists for.
        const wanted = expectedOccurrences ?? 1;
        if (found !== wanted) {
          return { ...unchanged, reason: `The text to replace appears ${found} times and expectedOccurrences is ${wanted}; name the real count to change them all, or give more context to match one` };
        }
        const after = parts.join(replace);
        const encoded = Buffer.from(after, 'utf8');
        if (encoded.length > context.policy.maxOutputBytes) throw new HarnessError('OUTPUT_LIMIT', 'Write exceeds byte budget');
        // No 'wx': this write may replace, and what makes that safe is the digest above rather
        // than the flag.
        writeFileSync(filename, encoded);
        return { path: relative, applied: true, reason: null, replacements: found, sha256Before,
          sha256After: createHash('sha256').update(encoded).digest('hex'), bytesBefore: before.length, bytesAfter: encoded.length };
      } },
    { name: 'files.append', version: '1.0.0',
      outputKeys: ['path', 'appended', 'reason', 'sha256Before', 'sha256After', 'bytesBefore', 'bytesAfter'],
      effect: 'write',
      // Canonical JSON and a newline, matching files.write: a file this harness appends to stays
      // a record it can read back, rather than becoming prose with a shape nobody declared.
      inputSchema: object({ path: string, expectedSha256: { type: 'string', minLength: 64, maxLength: 64 }, content: {} },
        ['path', 'expectedSha256', 'content']),
      execute({ path: relative, expectedSha256, content }, context) {
        const filename = workspaceFile(context.workspaceRoot, relative);
        const before = readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / 8));
        const sha256Before = createHash('sha256').update(before).digest('hex');
        if (sha256Before !== expectedSha256) {
          return { path: relative, appended: false, sha256Before, sha256After: sha256Before, bytesBefore: before.length, bytesAfter: before.length,
            reason: 'The file does not currently hash to expectedSha256, so this append was written against different content' };
        }
        const encoded = Buffer.concat([before, Buffer.from(canonical(content) + '\n', 'utf8')]);
        if (encoded.length > context.policy.maxOutputBytes) throw new HarnessError('OUTPUT_LIMIT', 'Write exceeds byte budget');
        writeFileSync(filename, encoded);
        return { path: relative, appended: true, reason: null, sha256Before,
          sha256After: createHash('sha256').update(encoded).digest('hex'), bytesBefore: before.length, bytesAfter: encoded.length };
      } },
    { name: 'files.delete', version: '1.0.0',
      outputKeys: ['path', 'removed', 'reason', 'sha256', 'bytes'],
      effect: 'write',
      inputSchema: object({ path: string, expectedSha256: { type: 'string', minLength: 64, maxLength: 64 } }),
      execute({ path: relative, expectedSha256 }, context) {
        const filename = workspaceFile(context.workspaceRoot, relative);
        const before = readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / 8));
        const sha256 = createHash('sha256').update(before).digest('hex');
        if (sha256 !== expectedSha256) {
          return { path: relative, removed: false, sha256, bytes: before.length,
            reason: 'The file does not currently hash to expectedSha256, so this deletion was written against different content' };
        }
        // Reading the whole file first is not incidental: a deletion that records the digest of
        // what it removed can be told apart from one of something nobody can now describe.
        rmSync(filename);
        return { path: relative, removed: true, reason: null, sha256, bytes: before.length };
      } },
    /**
     * Writing something that is not JSON.
     *
     * files.write canonicalises its content, so everything a plan could create was a JSON
     * document. That is a fine guarantee for a record and a hard floor on everything else: no
     * plan could produce a .mjs, a .md, an .html or a stylesheet. Building a website with this
     * harness meant authoring the site as one JSON manifest and having a reviewed build step turn
     * it into files, because the kernel could describe a program and not write one.
     *
     * Kept apart from files.write rather than folded into it, so that tool's promise - what it
     * writes can be read back as the structure it was given - stays exactly as strong as it was.
     * Text has no such promise and should not borrow one. Exclusive creation for the same reason
     * files.write has it, and the parent directory must already exist: files.mkdir is a separate
     * grant because making a tree somewhere is a different act from putting a file in one.
     */
    { name: 'files.writeText', version: '1.2.0', outputKeys: ['path', 'created', 'sha256', 'bytes'], effect: 'write',
      inputSchema: object({
        path: string,
        text: { type: 'string', maxLength: 4194304, description: 'The exact bytes of the file. Written as UTF-8 with nothing added, so what you supply is what another program will read.' },
      }, ['path', 'text'], 'Create a text file whose bytes are exactly the text given. This is the one to use for source files, markup, stylesheets, scripts and documents. For a structured record this harness will read back as JSON, use files.write instead.'),
      execute({ path: relative, text }, context) {
        const filename = workspaceFile(context.workspaceRoot, relative);
        const encoded = Buffer.from(text, 'utf8');
        if (encoded.length > context.policy.maxOutputBytes) throw new HarnessError('OUTPUT_LIMIT', 'Write exceeds byte budget');
        const created = writeExclusiveOrIdentical(filename, encoded);
        return { path: relative, created, sha256: createHash('sha256').update(encoded).digest('hex'), bytes: encoded.length };
      } },
    { name: 'files.mkdir', version: '1.0.0', outputKeys: ['path', 'created'], effect: 'write',
      inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const target = workspaceDir(context.workspaceRoot, relative);
        // recursive, so a tree arrives in one grant rather than one per level; and `created`
        // distinguishes making it from finding it, because "the directory is there now" and
        // "this call put it there" are different claims and only one of them is this tool's.
        const existed = existsSync(target);
        mkdirSync(target, { recursive: true });
        return { path: relative, created: !existed };
      } },
    /**
     * Moving and copying, bound to the bytes at the source and refusing to land on anything.
     *
     * expectedSha256 for the same reason files.edit takes one: the approval covers which file
     * the operator believed they were moving. The destination must not exist, which keeps the
     * rule files.write established - an approval never silently replaces existing data - true of
     * the one operation most likely to break it by accident.
     */
    { name: 'files.move', version: '1.0.0', outputKeys: ['from', 'to', 'moved', 'reason', 'sha256', 'bytes'], effect: 'write',
      inputSchema: object({ from: string, to: string, expectedSha256: { type: 'string', minLength: 64, maxLength: 64 } }),
      execute({ from, to, expectedSha256 }, context) {
        const source = workspaceFile(context.workspaceRoot, from);
        const bytes = readWorkspaceFile(context.workspaceRoot, from, Math.floor(context.policy.maxOutputBytes / 8));
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        const unchanged = { from, to, moved: false, sha256, bytes: bytes.length };
        if (sha256 !== expectedSha256) return { ...unchanged, reason: 'The source does not currently hash to expectedSha256, so this move was written against different content' };
        const destination = workspaceFile(context.workspaceRoot, to);
        if (existsSync(destination)) return { ...unchanged, reason: 'The destination already exists, and a move never replaces what is there' };
        renameSync(source, destination);
        return { from, to, moved: true, reason: null, sha256, bytes: bytes.length };
      } },
    { name: 'files.copy', version: '1.0.0', outputKeys: ['from', 'to', 'copied', 'reason', 'sha256', 'bytes'], effect: 'write',
      inputSchema: object({ from: string, to: string, expectedSha256: { type: 'string', minLength: 64, maxLength: 64 } }),
      execute({ from, to, expectedSha256 }, context) {
        const bytes = readWorkspaceFile(context.workspaceRoot, from, Math.floor(context.policy.maxOutputBytes / 8));
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        const unchanged = { from, to, copied: false, sha256, bytes: bytes.length };
        if (sha256 !== expectedSha256) return { ...unchanged, reason: 'The source does not currently hash to expectedSha256, so this copy was written against different content' };
        const destination = workspaceFile(context.workspaceRoot, to);
        if (existsSync(destination)) return { ...unchanged, reason: 'The destination already exists, and a copy never replaces what is there' };
        // Written from the bytes already read and digested rather than copyFileSync, so what
        // lands is provably what was measured instead of whatever the file says a moment later.
        writeFileSync(destination, bytes, { flag: 'wx' });
        return { from, to, copied: true, reason: null, sha256, bytes: bytes.length };
      } },
    { name: 'memory.promote', version: '1.0.0', outputKeys: ['candidateHash', 'path', 'promoted'], effect: 'write', inputSchema: candidateSchema,
      // Promotion is a separate write under an exact grant, keeping learned text from becoming authority.
      execute(candidate, context) {
        const { candidateHash, ...rest } = candidate;
        if (digest(rest) !== candidateHash) throw new HarnessError('MEMORY_INVALID', 'candidateHash does not match the candidate content');
        const base = realpathSync(context.workspaceRoot);
        mkdirSync(path.join(base, MEMORY_DIR), { recursive: true });
        const relative = MEMORY_DIR + '/' + candidateHash + '.json';
        const filename = workspaceFile(context.workspaceRoot, relative);
        const text = canonical(candidate) + '\n';
        if (Buffer.byteLength(text) > context.policy.maxOutputBytes) throw new HarnessError('OUTPUT_LIMIT', 'Write exceeds byte budget');
        try { writeFileSync(filename, text, { flag: 'wx', encoding: 'utf8' }); }
        catch (error) {
          // The filename is content-derived: an identical resubmission is an idempotent no-op.
          if (error.code !== 'EEXIST' || readFileSync(filename, 'utf8') !== text) throw error;
        }
        return { path: relative, candidateHash, promoted: true };
      } },
    { name: 'memory.recall', version: '2.0.0', outputKeys: ['corruptedEntries', 'danglingSupersedes', 'matchedCount', 'results', 'retracted', 'retractedCount', 'strategy', 'totalEntries'], effect: 'read', inputSchema: object({ query: string, limit: { type: 'integer', minimum: 1, maximum: 100 } }, ['query']),
      execute({ query, limit = 10 }, context) {
        const base = realpathSync(context.workspaceRoot);
        let names;
        try { names = readdirSync(path.join(base, MEMORY_DIR)); }
        catch (error) { if (error.code === 'ENOENT') names = []; else throw error; }
        names = names.filter((n) => /^[a-f0-9]{64}\.json$/.test(n)).sort();
        if (names.length > MAX_MEMORY_ENTRIES) throw new HarnessError('OUTPUT_LIMIT', 'Memory store exceeds the bounded entry count');
        const terms = new Set(query.toLowerCase().match(/[a-z0-9]+/g) ?? []);
        const limitBytes = Math.floor(context.policy.maxOutputBytes / 8);
        let corruptedEntries = 0;
        const matches = [];
        for (const name of names) {
          try {
            const bytes = readWorkspaceFile(context.workspaceRoot, MEMORY_DIR + '/' + name, limitBytes);
            const candidate = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
            validateSchema(candidate, candidateSchema);
            const { candidateHash, ...rest } = candidate;
            if (digest(rest) !== candidateHash || candidateHash !== name.slice(0, -'.json'.length)) throw new HarnessError('MEMORY_INVALID', 'Stored entry does not match its own digest');
            const tokens = new Set(candidate.lesson.toLowerCase().match(/[a-z0-9]+/g) ?? []);
            const score = [...terms].filter((t) => tokens.has(t)).length;
            matches.push({ candidateHash, lesson: candidate.lesson, evidenceHashes: candidate.evidenceHashes,
              supersedes: candidate.supersedes ?? [], score });
          } catch { corruptedEntries += 1; }
        }

        // Retraction is monotone and permanent: a lesson is withheld if ANY valid stored record
        // supersedes it, including a record that something else has since superseded. The
        // alternative -- letting a retracted retraction resurrect what it replaced -- makes what
        // the model is told depend on a chain nobody can see, and a falsified lesson coming back
        // to life is the one outcome this must never produce. To restore a lesson, promote it
        // again with its own evidence; that is a new record and a new grant, which is the point.
        const retractedBy = new Map();
        for (const entry of matches) {
          for (const hash of entry.supersedes) {
            if (hash === entry.candidateHash) continue; // a record cannot retract itself
            if (!retractedBy.has(hash)) retractedBy.set(hash, []);
            retractedBy.get(hash).push(entry.candidateHash);
          }
        }
        const stored = new Set(matches.map((entry) => entry.candidateHash));
        // Named but not present: a retraction of something this store never held, or no longer
        // does. Reported rather than ignored, because a mistyped hash retracts nothing and would
        // otherwise look exactly like a retraction that worked.
        const dangling = [...retractedBy.keys()].filter((hash) => !stored.has(hash)).sort();
        const retracted = [...retractedBy.keys()].filter((hash) => stored.has(hash)).sort();
        const live = matches.filter((entry) => !retractedBy.has(entry.candidateHash));

        live.sort((a, b) => b.score - a.score || (a.candidateHash < b.candidateHash ? -1 : a.candidateHash > b.candidateHash ? 1 : 0));
        // `results` is a RANKED list, not a filter: it includes entries that scored zero, and
        // fetchMemoryExcerpt applies the score>0 filter itself. Round 012 measured a reader
        // calling a zero-scoring entry "matched", which the output gave no way to contradict.
        // matchedCount states how many actually share a term with the query.
        return { strategy: 'lexical-overlap-v1', totalEntries: names.length, corruptedEntries,
          // Declared, never silent: a withheld lesson is named so an operator can see that a
          // retraction took effect, the same way compaction names the records it drops. Counts
          // are exact; the lists beside them are bounded.
          retractedCount: retracted.length, retracted: retracted.slice(0, MAX_LISTED_RETRACTIONS),
          danglingSupersedes: dangling.slice(0, MAX_LISTED_RETRACTIONS),
          matchedCount: live.filter((m) => m.score > 0).length, results: live.slice(0, limit) };
      } },
  ];
}
