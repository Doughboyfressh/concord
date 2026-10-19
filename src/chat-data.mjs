import { canonical, clone, digest } from './value.mjs';

/** Leave headroom for receipt/payload envelopes within canonical JSON's depth limit. */
export function boundedValue(value, { maxBytes = 8192, maxDepth = 32 } = {}) {
  const encoded = canonical(value);
  const bytes = Buffer.byteLength(encoded);
  const commitment = { fullDigest: digest(value), bytes };
  if (bytes > maxBytes) return { ...commitment, omitted: true, reason: 'byte-limit' };
  const tooDeep = (v, depth) => depth > maxDepth || (v !== null && typeof v === 'object' && Object.values(v).some(child => tooDeep(child, depth + 1)));
  if (tooDeep(value, 0)) return { ...commitment, omitted: true, reason: 'depth-limit' };
  return { ...commitment, omitted: false, value: JSON.parse(encoded) };
}

/**
 * The same tokenisation skills.rank and capabilities.search already use, so one turn ranks
 * instructions, skills and catalogue entries by a single rule rather than three similar ones.
 */
const tokenize = (text) => [...new Set(String(text).toLowerCase().match(/[a-z0-9]+/g) ?? [])];

/**
 * A relevance-selected subset that fits a byte budget, chosen by a pure function.
 *
 * boundedRecords keeps a suffix because for a conversation the newest turns are the ones that
 * matter. For standing material — instruction lessons, catalogue entries — recency means nothing
 * and relevance to the current request means everything, so this ranks instead of truncating. The
 * rules it inherits are the ones that matter: never cut an item in half, never invent a summary.
 *
 * Deterministic in every part, which is the whole point. Scores come from lexical overlap, ties
 * break on the item's own id, and the kept set is emitted in the input's own order rather than
 * score order — so the same message against the same material produces the same bytes, and a run
 * whose context was compacted can still be replayed. Compaction by asking a model to summarise
 * cannot offer that: it is a fresh inference every time, so replay would be verifying a context
 * that no longer exists.
 *
 * What is dropped is declared rather than hidden: the count, the digest of the whole set, and the
 * ids left out. A reader can tell that something was omitted, how much, and exactly which — and
 * because an omitted item is named by id, it can be fetched back rather than being lost.
 */
export function boundedByRelevance(items, { query = '', maxBytes = 16384, maxItems = Number.MAX_SAFE_INTEGER } = {}) {
  const all = clone(items);
  const terms = tokenize(query);
  const scored = all.map((item, index) => {
    const tokens = new Set(tokenize(item.text ?? ''));
    return { item, index, score: terms.filter((term) => tokens.has(term)).length };
  });
  // Highest overlap first; an item's own id settles ties so the choice never depends on input order.
  scored.sort((a, b) => b.score - a.score
    || (String(a.item.id) < String(b.item.id) ? -1 : String(a.item.id) > String(b.item.id) ? 1 : a.index - b.index));

  const keptIndexes = new Set();
  let bytes = 2;
  for (const entry of scored) {
    if (keptIndexes.size >= maxItems) break;
    const size = Buffer.byteLength(canonical(entry.item)) + (keptIndexes.size ? 1 : 0);
    // Skipped rather than stopped: one oversized item must not hide every smaller one behind it.
    if (bytes + size > maxBytes) continue;
    bytes += size;
    keptIndexes.add(entry.index);
  }

  const kept = all.filter((unused, index) => keptIndexes.has(index));
  const omitted = all.filter((unused, index) => !keptIndexes.has(index));
  return {
    items: kept,
    omittedCount: omitted.length,
    totalCount: all.length,
    fullDigest: digest(all),
    omittedIds: omitted.map((item) => item.id).sort(),
    strategy: 'lexical-overlap-v1',
  };
}

/** A complete-record suffix: never cut JSON, invent a summary, or skip a large newest record. */
export function boundedRecords(records, { maxItems = 24, maxBytes = 16384 } = {}) {
  const copy = clone(records);
  let bytes = 2;
  let start = copy.length;
  while (start > 0 && copy.length - start < maxItems) {
    const size = Buffer.byteLength(canonical(copy[start - 1])) + (start === copy.length ? 0 : 1);
    if (bytes + size > maxBytes) break;
    bytes += size;
    start--;
  }
  return { records: copy.slice(start), omittedCount: start, totalCount: copy.length, fullDigest: digest(copy) };
}
