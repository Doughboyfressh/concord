import { canonical, HarnessError } from './value.mjs';

/**
 * The retrieval half of observation compaction: fetch a recorded output a turn could not be shown.
 *
 * `boundedValue` keeps 8192 bytes per task output, and past that it does not truncate — it drops
 * the value entirely and leaves `{fullDigest, bytes, omitted: true}`. So a turn that reads a 20 KB
 * file is told a hash and a byte count and nothing else. That is honest and, on its own, inert:
 * measured repeatedly in this project, a model handed a digest where content should be does not
 * say it cannot see the file, it describes the file. Six fabricated readings in one session, all
 * of them of outputs that really existed and really were recorded.
 *
 * The same shape already closes this elsewhere. Compaction names the turns it drops and
 * `conversation.turn` fetches them; `boundedByRelevance` names the lessons it omits and
 * `instructions.lesson` fetches those. An oversized observation was the one case that declared a
 * loss with no way back. The data was never missing — it is in the journal, under the very hash
 * the turn was shown.
 *
 * Read rather than pure, because the ledger grows between calls. It needs no approval, and nothing
 * is reachable through it that the turn was not already entitled to see: these are outputs of
 * tasks this session already ran, under grants already given, recorded in receipts already shown.
 *
 * Slicing here is not the truncation this project refuses elsewhere. Compaction cut silently and
 * left no handle; a slice is asked for by offset, reports the offset it returned, the total it
 * came from, and whether more remains. The caller always knows what it is holding.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });

/** Below the 8 KiB an observation keeps, so a slice this returns is a slice the model sees. */
const DEFAULT_MAX_BYTES = 4096;
const ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
/** Listing the keys of a value too large to return is how a caller finds a deeper path. */
const MAX_LISTED_KEYS = 64;
const UNSAFE_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

const LIMITATIONS = [
  'This returns what a recorded receipt already holds; it runs nothing and reaches no tool',
  'The output is as it was recorded, never summarised or rewritten; outputHash is the hash the receipt was shown under',
  'An observation being omitted from a turn is a limit on what that turn could be shown, not on what happened',
];

/**
 * RFC 6901, matching the kernel's own rule in engine.mjs rather than a looser one, so a path that
 * addresses a value here addresses the same value in a task reference.
 */
function resolvePointer(value, pointer) {
  if (pointer === '') return { found: true, value };
  if (!pointer.startsWith('/') || /~(?![01])/u.test(pointer)) {
    throw new HarnessError('INPUT_INVALID', 'Expected an RFC 6901 JSON pointer');
  }
  let current = value;
  for (const token of pointer.slice(1).split('/')) {
    const key = token.replaceAll('~1', '/').replaceAll('~0', '~');
    if (UNSAFE_KEYS.has(key)) throw new HarnessError('INPUT_INVALID', 'Unsafe reference key');
    if (current === null || typeof current !== 'object' || !Object.hasOwn(current, key)) return { found: false, value: null };
    if (Array.isArray(current) && !(/^(0|[1-9]\d*)$/.test(key) && Number(key) < current.length)) return { found: false, value: null };
    current = current[key];
  }
  return { found: true, value: current };
}

/** The longest prefix of `text` from `offset` whose UTF-8 encoding fits, never splitting a character. */
function sliceToBytes(text, offset, maxBytes) {
  let end = Math.min(text.length, offset + maxBytes);
  let slice = text.slice(offset, end);
  // Shrink rather than estimate: multi-byte characters make a character count an unreliable
  // proxy for a byte count, and returning one byte over the bound would have the observation
  // window drop the whole reply — the exact failure this tool exists to undo.
  while (Buffer.byteLength(slice) > maxBytes && end > offset) {
    end -= Math.max(1, Math.ceil((Buffer.byteLength(slice) - maxBytes) / 4));
    slice = text.slice(offset, end);
  }
  return slice;
}

export function makeObservationTools({ readOutput, maxBytes = DEFAULT_MAX_BYTES } = {}) {
  if (typeof readOutput !== 'function') {
    throw new HarnessError('OBSERVATION_CONFIG', 'The observation store needs a readOutput function');
  }
  if (!Number.isInteger(maxBytes) || maxBytes < 512) {
    throw new HarnessError('OBSERVATION_CONFIG', 'maxBytes must be an integer of at least 512');
  }

  return [Object.freeze({
    name: 'observation.part', version: '1.0.0', effect: 'read',
    outputKeys: ['runId', 'taskId', 'found', 'path', 'kind', 'text', 'value', 'keys',
      'offset', 'returned', 'totalLength', 'hasMore', 'outputHash', 'limitations'],
    inputSchema: object({
      runId: { type: 'string', minLength: 1, maxLength: 128 },
      taskId: { type: 'string', minLength: 1, maxLength: 128 },
      path: { type: 'string', maxLength: 1024, description: 'RFC 6901 pointer into the recorded output, for example /text. Omit for the whole value.' },
      offset: { type: 'integer', minimum: 0, maximum: 1073741824, description: 'Where in a string field to start. Characters, not bytes.' },
    }, ['runId', 'taskId']),
    // Stable, so the registry digest is. The store arrives through a closure for the reason
    // conversation.turn takes the transcript that way: config is hashed into the registry digest
    // that binds every approval and every replay, so a config holding recorded outputs would
    // change on each run and invalidate the grants of the one before.
    config: { source: 'session-observation-store-v1', maxBytes },
    execute(input) {
      if (!ID_PATTERN.test(input.runId) || !ID_PATTERN.test(input.taskId)) {
        throw new HarnessError('INPUT_INVALID', 'A run id and task id must be bare identifiers');
      }
      const pointer = input.path ?? '';
      const offset = input.offset ?? 0;
      const record = readOutput(input.runId, input.taskId);

      const base = {
        runId: input.runId, taskId: input.taskId, path: pointer,
        text: null, value: null, keys: [], offset, returned: 0, totalLength: 0, hasMore: false,
      };
      // Not found is data, not a failure, the same way an unknown turn id is: naming something
      // that is not there is a question, and the answer is no.
      if (!record) {
        return { ...base, found: false, kind: 'absent', outputHash: null,
          limitations: [...LIMITATIONS, 'No completed task with this run id and task id is recorded in this session'] };
      }

      const resolved = resolvePointer(record.output, pointer);
      if (!resolved.found) {
        return { ...base, found: false, kind: 'absent', outputHash: record.outputHash ?? null,
          limitations: [...LIMITATIONS, 'That path does not exist in this recorded output'] };
      }

      if (typeof resolved.value === 'string') {
        const total = resolved.value.length;
        const text = offset >= total ? '' : sliceToBytes(resolved.value, offset, maxBytes);
        return {
          ...base, found: true, kind: 'string', text,
          returned: text.length, totalLength: total, hasMore: offset + text.length < total,
          outputHash: record.outputHash ?? null,
          limitations: [...LIMITATIONS,
            'This is a slice of a recorded string, verbatim and unmodified; offset and totalLength say which part of what',
            'hasMore being true means the rest is still there: ask again with offset set past what you have'],
        };
      }

      // A non-string value is returned whole or not at all. Half an object is a different object,
      // and a caller handed one could not tell. When it does not fit, its keys are listed so a
      // deeper path can be chosen — naming what was withheld rather than only refusing.
      const encoded = canonical(resolved.value);
      if (Buffer.byteLength(encoded) <= maxBytes) {
        return { ...base, found: true, kind: 'value', value: resolved.value, outputHash: record.outputHash ?? null,
          limitations: [...LIMITATIONS, 'This value fitted the bound and is returned entire'] };
      }
      const keys = resolved.value !== null && typeof resolved.value === 'object'
        ? (Array.isArray(resolved.value)
          ? resolved.value.map((unused, index) => String(index)).slice(0, MAX_LISTED_KEYS)
          : Object.keys(resolved.value).slice(0, MAX_LISTED_KEYS))
        : [];
      return {
        ...base, found: true, kind: 'oversized', keys,
        totalLength: Buffer.byteLength(encoded), outputHash: record.outputHash ?? null,
        limitations: [...LIMITATIONS,
          'This value exceeds the byte bound and is withheld entire rather than cut; keys names what it holds, so a deeper path can fetch a part of it',
          'A string field inside it can be sliced; name it with path and read it in pieces'],
      };
    },
  })];
}
