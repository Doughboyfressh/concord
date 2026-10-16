import { canonical, digest, clone, deepFreeze, HarnessError } from './value.mjs';

// The complete acquired feature inventory is inert data. Selection grants no effects.
export function makeCapabilityTools(inventory = { schemaVersion: 1, repositories: [], capabilities: [] }) {
  const data = deepFreeze(clone(inventory));
  if (data.schemaVersion !== 1 || !Array.isArray(data.repositories) || !Array.isArray(data.capabilities)) throw new HarnessError('INVALID_CAPABILITIES', 'Invalid capability inventory');
  const seen = new Set();
  for (const feature of data.capabilities) {
    if (typeof feature.id !== 'string' || seen.has(feature.id) || typeof feature.title !== 'string' || !Array.isArray(feature.headings) || feature.headings.some(h => typeof h !== 'string')) throw new HarnessError('INVALID_CAPABILITIES', 'Invalid capability entry');
    seen.add(feature.id);
  }
  return [{ name: 'capabilities.search', version: '1.0.0', effect: 'pure', config: { inventoryHash: digest(data) },
    inputSchema: { type: 'object', properties: { query: { type: 'string', minLength: 1, maxLength: 4096 }, sourceId: { type: 'string' }, kind: { enum: ['skill', 'agent-command-plugin', 'documentation'] }, limit: { type: 'integer', minimum: 1, maximum: 100 } }, required: ['query'], additionalProperties: false },
    execute({ query, sourceId, kind, limit = 10 }, context) {
      const terms = [...new Set(query.toLowerCase().match(/[a-z0-9]+/g) ?? [])];
      const ranked = data.capabilities.filter(f => (!sourceId || f.sourceId === sourceId) && (!kind || f.kind === kind)).map(f => {
        const title = new Set(f.title.toLowerCase().match(/[a-z0-9]+/g) ?? []);
        const body = new Set((f.id + ' ' + f.headings.join(' ')).toLowerCase().match(/[a-z0-9]+/g) ?? []);
        const score = terms.reduce((n, t) => n + (title.has(t) ? 4 : body.has(t) ? 1 : 0), 0);
        return { ...f, score };
      }).filter(f => f.score > 0).sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      const result = { inventoryHash: digest(data), strategy: 'title-weighted-lexical-v1', totalMatches: ranked.length, results: ranked.slice(0, limit), grantsCapabilities: false };
      if (Buffer.byteLength(canonical(result)) > context.policy.maxOutputBytes) throw new HarnessError('OUTPUT_LIMIT', 'Capability search output exceeds budget');
      return result;
    }
  }];
}
