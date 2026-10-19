import { mkdirSync, readFileSync, readdirSync, writeFileSync, lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, digest, validateSchema, HarnessError } from './value.mjs';
import { workspaceFile, readWorkspaceFile } from './workspace-fs.mjs';

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const hash64 = { type: 'string', minLength: 64, maxLength: 64 };
const MAX_MEMORY_ENTRIES = 1000;
const MEMORY_DIR = 'memory';
const candidateSchema = object({
  version: { const: 1 }, lesson: string,
  evidenceHashes: { type: 'array', minItems: 1, maxItems: 1000, items: hash64 },
  status: { const: 'proposed' }, executable: { const: false }, candidateHash: hash64,
});

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
    { name: 'memory.candidate', version: '1.0.0', outputKeys: ['candidateHash', 'evidenceHashes', 'executable', 'lesson', 'status', 'version'], effect: 'pure', inputSchema: object({ lesson: string, evidence: { type: 'array', minItems: 1, maxItems: 1000, items: true } }),
      execute({ lesson, evidence }) {
        const candidate = { version: 1, lesson, evidenceHashes: evidence.map(digest).sort(), status: 'proposed', executable: false };
        return { ...candidate, candidateHash: digest(candidate) };
      } },
    { name: 'files.read', version: '1.0.0', outputKeys: ['bytes', 'path', 'sha256', 'text', 'untrusted'], effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, limit);
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        return { path: relative, text, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), untrusted: true };
      } },
    { name: 'files.write', version: '1.0.0', outputKeys: ['contentHash', 'created', 'path'], effect: 'write', inputSchema: object({ path: string, content: {} }),
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
        // Exclusive creation: an approval cannot silently replace existing user data.
        writeFileSync(filename, text, { flag: 'wx', encoding: 'utf8' });
        return { path: relative, contentHash: digest(content), created: true };
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
    { name: 'memory.recall', version: '1.0.0', outputKeys: ['corruptedEntries', 'matchedCount', 'results', 'strategy', 'totalEntries'], effect: 'read', inputSchema: object({ query: string, limit: { type: 'integer', minimum: 1, maximum: 100 } }, ['query']),
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
            matches.push({ candidateHash, lesson: candidate.lesson, evidenceHashes: candidate.evidenceHashes, score });
          } catch { corruptedEntries += 1; }
        }
        matches.sort((a, b) => b.score - a.score || (a.candidateHash < b.candidateHash ? -1 : a.candidateHash > b.candidateHash ? 1 : 0));
        // `results` is a RANKED list, not a filter: it includes entries that scored zero, and
        // fetchMemoryExcerpt applies the score>0 filter itself. Round 012 measured a reader
        // calling a zero-scoring entry "matched", which the output gave no way to contradict.
        // matchedCount states how many actually share a term with the query.
        return { strategy: 'lexical-overlap-v1', totalEntries: names.length, corruptedEntries,
          matchedCount: matches.filter((m) => m.score > 0).length, results: matches.slice(0, limit) };
      } },
  ];
}
