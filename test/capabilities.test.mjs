import test from 'node:test';
import assert from 'node:assert/strict';
import { makeCapabilityTools } from '../src/capabilities.mjs';
test('cross-source inventory selection has deterministic tie-breaks and grants no authority', () => {
  const inventory = { schemaVersion: 1, repositories: [], capabilities: ['z','a'].map(id => ({ id, sourceId: 'ecc', kind: 'skill', title: 'replay', headings: ['verify'], executable: false })) };
  const [tool] = makeCapabilityTools(inventory);
  inventory.capabilities[0].title = 'mutated';
  const result = tool.execute({ query: 'replay', limit: 2 }, { policy: { maxOutputBytes: 10000 } });
  assert.deepEqual(result.results.map(f => f.id), ['a', 'z']);
  assert.equal(result.grantsCapabilities, false);
  assert.equal(tool.execute({ query: 'replay', sourceId: 'other' }, { policy: { maxOutputBytes: 10000 } }).totalMatches, 0);
  assert.throws(() => tool.execute({ query: 'replay' }, { policy: { maxOutputBytes: 1 } }));
});
