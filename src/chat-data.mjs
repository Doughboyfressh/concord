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
