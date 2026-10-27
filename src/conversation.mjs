import { canonical, HarnessError } from './value.mjs';

/**
 * The retrieval half of conversation compaction: fetch turns a context left out, by declared id.
 *
 * Compaction drops the oldest turns to fit a budget and reports how many went. That is honest but
 * inert: a count and a digest tell a turn that something is missing and give it no way to find
 * out what. The instruction corpus has not had that problem, because boundedByRelevance names the
 * ids it omits and instructions.lesson fetches them back. This is the same pair for conversation.
 *
 * Read rather than pure, for the reason instructions.lesson is: the transcript grows between
 * calls, so the same input does not always yield the same output. It needs no approval, because a
 * read effect is not gated and nothing here is reachable that the turn could not already be told
 * - these are turns of this very conversation, already written by the operator or by the model.
 *
 * The transcript arrives through a closure rather than through `config`, and that is deliberate
 * rather than stylistic. registryManifest hashes every descriptor's config into the registry
 * digest, which binds every approval hash and every replay check. A config that carried the
 * history would change on each turn, so each turn would invalidate the grants of the one before
 * and no recorded run would replay. The config below therefore declares only what is stable.
 */

/** Enough to rebuild a lost thread, bounded so one call cannot ask for the whole history. */
const MAX_IDS = 32;

/**
 * Below the 8 KiB a turn's observation window keeps, so a result this tool accepts is a result the
 * model actually sees. Bounding at the policy ceiling instead would let a call return a megabyte
 * that the observation budget then discards whole - technically a success, and useless.
 */
const DEFAULT_MAX_BYTES = 6144;

/** `turn-12` addresses index 12 of the full history. Parsed strictly; anything else is unknown. */
const ID_PATTERN = /^turn-(0|[1-9][0-9]{0,6})$/;

export const turnId = (index) => `turn-${index}`;

export function makeConversationTools({ readTranscript, maxBytes = DEFAULT_MAX_BYTES } = {}) {
  if (typeof readTranscript !== 'function') {
    throw new HarnessError('CONVERSATION_CONFIG', 'The conversation store needs a readTranscript function');
  }
  if (!Number.isInteger(maxBytes) || maxBytes < 1024) {
    throw new HarnessError('CONVERSATION_CONFIG', 'maxBytes must be an integer of at least 1024');
  }
  const inputSchema = {
    type: 'object', additionalProperties: false, required: ['ids'],
    properties: {
      ids: { type: 'array', minItems: 1, maxItems: MAX_IDS, items: { type: 'string', minLength: 1, maxLength: 64 } },
    },
  };
  return [Object.freeze({
    name: 'conversation.turn', version: '1.0.0', effect: 'read',
    outputKeys: ['turns', 'requested', 'returned', 'missing', 'deferredIds', 'totalCount', 'limitations'],
    inputSchema,
    // Stable across every turn, so the registry digest is too. The byte bound belongs here because
    // it is an operator's choice about this build, not something a plan may vary per call.
    config: { source: 'session-transcript-v1', maxBytes },
    execute(input) {
      const history = readTranscript();
      if (!Array.isArray(history)) {
        throw new HarnessError('CONVERSATION_STORE', 'The session transcript is unavailable');
      }
      // De-duplicated and ordered by index, so the answer is a function of the id *set* rather
      // than of the order a model happened to list them in, and a transcript always reads oldest
      // first. Asking for the same turn twice is not an error, it is one turn.
      const requested = [...new Set(input.ids)];
      const wanted = requested
        .map((id) => ({ id, index: ID_PATTERN.test(id) ? Number(id.slice('turn-'.length)) : -1 }))
        .sort((a, b) => a.index - b.index || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

      const turns = [];
      const missing = [];
      const deferredIds = [];
      let bytes = 2;
      for (const { id, index } of wanted) {
        const record = index >= 0 ? history[index] : undefined;
        if (!record || typeof record.content !== 'string') { missing.push(id); continue; }
        const turn = { id, index, role: record.role, content: record.content };
        const size = Buffer.byteLength(canonical(turn)) + (turns.length ? 1 : 0);
        // Deferred, not truncated: half a turn is a misquote, and a turn silently shortened is
        // worse than one openly withheld. The caller is told which ids to ask for next.
        if (bytes + size > maxBytes) { deferredIds.push(id); continue; }
        bytes += size;
        turns.push(turn);
      }
      return {
        turns,
        requested: requested.length,
        returned: turns.length,
        missing,
        deferredIds,
        totalCount: history.length,
        limitations: [
          'These are turns of this same conversation, returned verbatim as recorded; nothing here is summarised, shortened or rewritten',
          'A turn that did not fit the byte bound is listed in deferredIds and can be asked for in a later call; it was withheld whole, never cut',
          'An assistant turn records what was said, not what was done: only a completed receipt in observations shows that a tool ran',
        ],
      };
    },
  })];
}
