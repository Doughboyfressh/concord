import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, parseJson, HarnessError } from './value.mjs';

/**
 * The trained section of an instruction module, and the tool that fetches back what a turn omitted.
 *
 * Context compaction selects the lessons a turn is told and declares the rest by id. Declaring an
 * omission is only honest if the omitted thing can still be reached, otherwise the id is a receipt
 * for something nobody can collect — so this is the other half of that design, not an extra.
 *
 * Every module is verified against the manifest digest before any of its text is returned, exactly
 * as buildChatContext does. Without that this tool would be a way to read instruction text that no
 * reviewer signed: the compaction path checks digests and the retrieval path would not, and the
 * weaker of two routes to the same bytes is the one that matters.
 *
 * An id that resolves to nothing is reported in `missing` rather than raised as a refusal. A batch
 * fetch that fails wholesale because one of twenty ids was stale is less useful than one that
 * returns the nineteen and says which was not found, and the caller is usually working from an
 * omission record that may be a turn or two old.
 */

const MAX_INSTRUCTION_BYTES = 65536;
const MAX_MANIFEST_BYTES = 65536;
const MAX_IDS = 64;
const decoder = new TextDecoder('utf-8', { fatal: true });

const TRAINED_BEGIN = '<!-- trained:begin -->';
const TRAINED_END = '<!-- trained:end -->';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code, message, detail) => { throw new HarnessError(code, message, detail); };

function readBounded(file, limit, code) {
  const bytes = readFileSync(file);
  if (bytes.length > limit) fail(code, 'File exceeds the bounded read size', { file: path.basename(file) });
  return bytes;
}

/**
 * Split a module into its reviewed prose and its individually addressable trained lessons.
 *
 * A lesson's id is its source, the tool it opens with, and a prefix of the digest of the line
 * itself. The digest is not decoration: the first version used source and tool alone, and a tool
 * may have several lessons — memory.promote has three — so ids collided, the store kept whichever
 * it saw first, and every other lesson for that tool was declared omitted while being impossible
 * to fetch. The round trip looked sound because nothing was reported missing; the wrong lesson
 * came back instead. Content-addressing fixes it and is the right shape anyway: an id names a
 * lesson, so rewording one should produce a different id.
 *
 * Lines in the section that are not bullets are the preamble and travel with the kept set,
 * because they say what the section is.
 */
export function splitTrained(sourceId, text) {
  const begin = text.indexOf(TRAINED_BEGIN);
  const end = text.indexOf(TRAINED_END);
  if (begin < 0 || end < begin) return { prose: text, preamble: '', lessons: [] };
  const section = text.slice(begin + TRAINED_BEGIN.length, end);
  const prose = text.slice(0, begin) + text.slice(end + TRAINED_END.length);
  const lessons = [];
  const preamble = [];
  for (const line of section.split('\n')) {
    const match = /^- `([^`]+)`/.exec(line);
    if (match) {
      lessons.push({
        id: `${sourceId}:${match[1]}@${sha256(Buffer.from(line)).slice(0, 12)}`,
        tool: match[1], sourceId, text: line,
      });
    } else if (line.trim()) preamble.push(line);
  }
  return { prose, preamble: preamble.join('\n'), lessons };
}

/** Every trained lesson across the manifest, each verified against its module's recorded digest. */
export function loadLessons(directory) {
  const manifest = parseJson(decoder.decode(readBounded(path.join(directory, 'manifest.json'), MAX_MANIFEST_BYTES, 'INSTRUCTION_STORE')));
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.modules)) {
    fail('INSTRUCTION_STORE', 'The instruction manifest must declare schemaVersion 1 and a module list');
  }
  const lessons = new Map();
  for (const module of manifest.modules) {
    if (!module || typeof module.sourceId !== 'string' || typeof module.file !== 'string' || typeof module.sha256 !== 'string') {
      fail('INSTRUCTION_STORE', 'Invalid instruction manifest entry');
    }
    if (module.file !== `${module.sourceId}.md`) {
      fail('INSTRUCTION_STORE', 'Instruction manifest entry has an unexpected filename', { sourceId: module.sourceId });
    }
    const bytes = readBounded(path.join(directory, module.file), MAX_INSTRUCTION_BYTES, 'INSTRUCTION_STORE');
    // The same check buildChatContext makes. A module that has drifted from its reviewed digest is
    // not served here either, so neither route to this text is the weaker one.
    if (sha256(bytes) !== module.sha256) {
      fail('INSTRUCTION_STORE', 'Instruction module does not match its recorded digest', { sourceId: module.sourceId });
    }
    for (const lesson of splitTrained(module.sourceId, decoder.decode(bytes)).lessons) {
      if (!lessons.has(lesson.id)) lessons.set(lesson.id, lesson);
    }
  }
  return lessons;
}

/**
 * The retrieval half of compaction: fetch lessons a turn left out, by the ids it declared.
 *
 * Read rather than pure, because it reads files that can change between calls. It needs no
 * approval: a read effect is not gated, and the text it returns is the same reviewed text the
 * prompt is assembled from, so nothing is reachable here that the turn could not already be told.
 */
export function makeInstructionTools({ directory } = {}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) {
    fail('INSTRUCTION_CONFIG', 'The instruction store needs an absolute directory');
  }
  const inputSchema = {
    type: 'object', additionalProperties: false, required: ['ids'],
    properties: {
      ids: { type: 'array', minItems: 1, maxItems: MAX_IDS, items: { type: 'string', minLength: 1, maxLength: 256 } },
    },
  };
  return [Object.freeze({
    name: 'instructions.lesson', version: '1.0.0', effect: 'read',
    outputKeys: ['lessons', 'requested', 'returned', 'missing', 'limitations'],
    inputSchema,
    config: { directory },
    execute(input, context) {
      const available = loadLessons(directory);
      const requested = [...new Set(input.ids)].sort();
      const lessons = [];
      const missing = [];
      for (const id of requested) {
        const lesson = available.get(id);
        if (lesson) lessons.push({ id: lesson.id, sourceId: lesson.sourceId, tool: lesson.tool, text: lesson.text });
        else missing.push(id);
      }
      const result = {
        lessons, requested: requested.length, returned: lessons.length, missing,
        limitations: [
          'Each lesson is returned from a module verified against its manifest digest, so this is the same reviewed text the turn context is assembled from and nothing more',
          'A lesson records what a training run observed about behaviour; it grants no capability and is not an approval',
        ],
      };
      const limit = context?.policy?.maxOutputBytes ?? 1048576;
      if (Buffer.byteLength(canonical(result)) > limit) {
        fail('INSTRUCTION_LIMIT', 'The requested lessons exceed the output byte budget', { requested: requested.length });
      }
      return result;
    },
  })];
}
