import { mkdirSync, readFileSync, readdirSync, writeFileSync, lstatSync, realpathSync, rmSync, renameSync, existsSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, digest, validateSchema, HarnessError } from './value.mjs';
import { workspaceFile, workspaceDir, readWorkspaceFile } from './workspace-fs.mjs';

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
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
    { name: 'files.writeText', version: '1.0.0', outputKeys: ['path', 'created', 'sha256', 'bytes'], effect: 'write',
      inputSchema: object({ path: string, text: { type: 'string', maxLength: 4194304 } }),
      execute({ path: relative, text }, context) {
        const filename = workspaceFile(context.workspaceRoot, relative);
        const encoded = Buffer.from(text, 'utf8');
        if (encoded.length > context.policy.maxOutputBytes) throw new HarnessError('OUTPUT_LIMIT', 'Write exceeds byte budget');
        writeFileSync(filename, encoded, { flag: 'wx' });
        return { path: relative, created: true, sha256: createHash('sha256').update(encoded).digest('hex'), bytes: encoded.length };
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
