import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { makeForeignTools, usableForeignSchema } from '../src/foreign.mjs';
import { digest, parseJson } from '../src/value.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
// The foreign server under test is Concord's own MCP server. It is a real server with real
// published contracts, it needs no network and no external dependency, and because its answers
// are computable here the reply can be checked rather than merely received.
const node = process.execPath;
const nodeSha = createHash('sha256').update(fs.readFileSync(node)).digest('hex');
const SERVER_ARGS = ['src/mcp.mjs', '--workspace', '.'];

// The two contracts this test uses, exactly as Concord's MCP server publishes them.
const manifest = () => ({
  schemaVersion: 1,
  sources: [{
    id: 'concord-self', kind: 'mcp', acquiredBy: 'scripts/acquire-mcp.mjs',
    server: { name: 'concord', version: '0.2.0', protocolVersion: '2025-06-18' },
    command: { executable: node, executableSha256: nodeSha, args: SERVER_ARGS, cwd: '.' },
    tools: [
      { name: 'json_hash', description: 'Concord tool "json.hash" (pure effect).',
        inputSchema: { type: 'object', properties: { value: {} }, required: ['value'], additionalProperties: false },
        schemaUsable: true },
      { name: 'text_concat', description: 'Concord tool "text.concat" (pure effect).',
        inputSchema: { type: 'object', additionalProperties: false, required: ['values', 'separator'],
          properties: { values: { type: 'array', minItems: 1, maxItems: 1000, items: { type: 'string', maxLength: 65536 } },
            separator: { type: 'string', maxLength: 65536 } } },
        schemaUsable: true },
      // A schema Concord cannot enforce: the pattern is not a valid expression.
      { name: 'unenforceable', description: 'A tool whose published schema cannot be enforced.',
        inputSchema: { type: 'object', properties: { bad: { pattern: '[' } } }, schemaUsable: false },
    ],
  }],
});

const serverConfig = (allow, overrides = {}) => ({ servers: [{
  id: 'concord-self', executable: node, executableSha256: nodeSha, args: SERVER_ARGS, cwd: '.',
  allow, timeoutMs: 120000, maxOutputBytes: 1048576, ...overrides,
}] });
const byName = (tools) => new Map(tools.map((t) => [t.name, t]));
const context = { workspaceRoot: root, policy: { maxOutputBytes: 1048576, timeoutMs: 120000 } };

test('importing a manifest grants nothing, and the catalog still reports the whole surface', () => {
  const tools = makeForeignTools(manifest());
  // Three published contracts and no configured server means one pure catalog tool, nothing else.
  assert.deepEqual(tools.map((t) => t.name), ['foreign.catalog']);
  const catalog = tools[0];
  assert.equal(catalog.effect, 'pure');
  const all = catalog.execute({});
  assert.equal(all.total, 3);
  assert.equal(all.availableNow, 0);
  assert.equal(all.grantsCapabilities, false);
  assert.equal(all.tools.every((row) => row.configured === false && row.allowed === false), true);
  // The namespaced name is reported before anything is registered, so a reviewer sees what a
  // grant would add.
  assert.equal(all.tools.find((row) => row.tool === 'json_hash').concordName, 'foreign.concord-self.json_hash');
  assert.equal(catalog.execute({ source: 'nope' }).matched, 0);
  assert.equal(catalog.execute({ availableOnly: true }).matched, 0);
});

test('only a configured server with the tool in its allow list registers it', () => {
  const named = byName(makeForeignTools(manifest(), serverConfig(['json_hash'])));
  // One of three allowed: the other two published contracts stay unregistered.
  assert.deepEqual([...named.keys()].sort(), ['foreign.catalog', 'foreign.concord-self.json_hash']);
  const catalog = named.get('foreign.catalog').execute({});
  assert.equal(catalog.availableNow, 1);
  assert.equal(catalog.total, 3);

  // An empty allow list is the same as no grant at all.
  assert.deepEqual(makeForeignTools(manifest(), serverConfig([])).map((t) => t.name), ['foreign.catalog']);

  const tool = named.get('foreign.concord-self.json_hash');
  assert.equal(tool.effect, 'process');
  // The input schema is the server's own published contract, not something written here.
  assert.deepEqual(tool.inputSchema, manifest().sources[0].tools[0].inputSchema);
  assert.equal(tool.config.schemaUsable, true);
  assert.equal(tool.config.source, 'concord-self');
  assert.equal(tool.config.foreignTool, 'json_hash');
});

test('a foreign call reaches the real server and its answer matches local computation', async () => {
  const named = byName(makeForeignTools(manifest(), serverConfig(['json_hash', 'text_concat'])));

  const subject = { alpha: 1, beta: ['two', 3] };
  const hashed = await named.get('foreign.concord-self.json_hash').execute({ value: subject }, context);
  assert.equal(hashed.isError, false);
  // Output from a program Concord does not control.
  assert.equal(hashed.untrusted, true);
  assert.equal(hashed.source, 'concord-self');
  assert.deepEqual(hashed.limitations, []);
  // The server computed a digest and digest() is available here, so the reply is checkable
  // rather than merely received.
  assert.equal(parseJson(hashed.text).digest, digest(subject));

  const joined = await named.get('foreign.concord-self.text_concat')
    .execute({ values: ['a', 'b', 'c'], separator: '-' }, context);
  assert.equal(joined.isError, false);
  assert.equal(parseJson(joined.text).value, 'a-b-c');
});

test('the published schema is enforced, and an unenforceable one is replaced and reported', async () => {
  const named = byName(makeForeignTools(manifest(), serverConfig(['json_hash', 'unenforceable'])));

  // The server said `value` is required and no other key is allowed, and that is applied here.
  const tool = named.get('foreign.concord-self.json_hash');
  await assert.rejects(tool.execute({ nope: 1 }, context), (e) => e.code === 'SCHEMA_MISMATCH');
  await assert.rejects(tool.execute({}, context), (e) => e.code === 'SCHEMA_MISMATCH');

  // A schema Concord cannot enforce is not silently accepted: a bounded fallback is used and the
  // substitution is recorded on the tool, so a reviewer sees which contracts are really checked.
  const loose = named.get('foreign.concord-self.unenforceable');
  assert.equal(loose.config.schemaUsable, false);
  assert.deepEqual(loose.inputSchema, { type: 'object', additionalProperties: true });
  assert.equal(loose.config.schemaDigest, digest(null));
  assert.equal(usableForeignSchema({ type: 'object', properties: { bad: { pattern: '[' } } }), null);
  // Only an object schema can carry MCP arguments, so a non-object contract is unusable too.
  assert.equal(usableForeignSchema({ type: 'string' }), null);
  assert.equal(usableForeignSchema(null), null);
  assert.notEqual(usableForeignSchema({ type: 'object', properties: { a: { type: 'string' } } }), null);

  const row = named.get('foreign.catalog').execute({}).tools.find((entry) => entry.tool === 'unenforceable');
  assert.equal(row.schemaUsable, false);
});

test('a foreign name cannot shadow a Concord tool or another source', () => {
  // A server publishing a name Concord already uses still lands under its own namespace.
  const shadowing = manifest();
  shadowing.sources[0].tools = [{ name: 'json_hash', inputSchema: { type: 'object', properties: {} } }];
  shadowing.sources.push({ id: 'other', kind: 'mcp', tools: [{ name: 'json_hash', inputSchema: { type: 'object', properties: {} } }] });
  const names = makeForeignTools(shadowing, serverConfig(['json_hash'])).map((t) => t.name);
  assert.ok(names.includes('foreign.concord-self.json_hash'));
  assert.equal(names.includes('json.hash'), false);
  // Two sources publishing the same tool name produce two distinct Concord names.
  const both = makeForeignTools(shadowing, { servers: [
    serverConfig(['json_hash']).servers[0],
    { ...serverConfig(['json_hash']).servers[0], id: 'other' },
  ] }).map((t) => t.name).sort();
  assert.deepEqual(both, ['foreign.catalog', 'foreign.concord-self.json_hash', 'foreign.other.json_hash']);
});

test('reviewed configuration and the manifest are both checked before anything registers', () => {
  const base = manifest();
  for (const [why, config] of [
    ['an allow entry the source does not publish', serverConfig(['not_published'])],
    ['a server id matching no manifest source', serverConfig(['json_hash'], { id: 'absent' })],
    ['non-string argv', serverConfig(['json_hash'], { args: ['ok', 7] })],
    ['a missing allow list', { servers: [{ id: 'concord-self', executable: node, executableSha256: nodeSha, args: SERVER_ARGS }] }],
    ['an unsupported server field', serverConfig(['json_hash'], { shell: true })],
    ['no executable', serverConfig(['json_hash'], { executable: '' })],
    ['a missing executable digest', serverConfig(['json_hash'], { executableSha256: undefined })],
    ['a placeholder rather than a digest', serverConfig(['json_hash'], { executableSha256: 'REPLACE_ME' })],
    ['an upper-case digest', serverConfig(['json_hash'], { executableSha256: nodeSha.toUpperCase() })],
  ]) {
    assert.throws(() => makeForeignTools(base, config), (e) => e.code === 'FOREIGN_CONFIG', why);
  }
  assert.throws(() => makeForeignTools(base, { unknownField: 1 }), (e) => e.code === 'FOREIGN_CONFIG');
  assert.throws(() => makeForeignTools(base, { servers: [serverConfig(['json_hash']).servers[0], serverConfig([]).servers[0]] }),
    (e) => e.code === 'FOREIGN_CONFIG');

  for (const [why, bad] of [
    ['the wrong schema version', { schemaVersion: 2, sources: [] }],
    ['a source with no kind', { schemaVersion: 1, sources: [{ id: 'x', tools: [] }] }],
    ['a source with no tools array', { schemaVersion: 1, sources: [{ id: 'x', kind: 'mcp' }] }],
    ['duplicate source ids', { schemaVersion: 1, sources: [{ id: 'x', kind: 'mcp', tools: [] }, { id: 'x', kind: 'mcp', tools: [] }] }],
    ['a duplicate tool name', { schemaVersion: 1, sources: [{ id: 'x', kind: 'mcp', tools: [{ name: 'a' }, { name: 'a' }] }] }],
    ['a tool name that is not portable', { schemaVersion: 1, sources: [{ id: 'x', kind: 'mcp', tools: [{ name: 'a b/c' }] }] }],
  ]) {
    assert.throws(() => makeForeignTools(bad), (e) => e.code === 'FOREIGN_MANIFEST_INVALID', why);
  }
});

test('the approval binds the reviewed command and the published contract', () => {
  const tool = (config) => byName(makeForeignTools(manifest(), config)).get('foreign.concord-self.json_hash');
  const original = tool(serverConfig(['json_hash']));
  // Changing the operator's argv must change what an approval authorizes.
  const moved = tool(serverConfig(['json_hash'], { args: [...SERVER_ARGS, '--extra'] }));
  assert.notEqual(moved.config.argvDigest, original.config.argvDigest);

  // Changing the server's published contract must also change it, so an approval granted against
  // one schema cannot authorize a call under a different one.
  const changed = manifest();
  changed.sources[0].tools[0].inputSchema = { type: 'object', properties: { value: {}, extra: {} }, required: ['value'], additionalProperties: false };
  const reshaped = byName(makeForeignTools(changed, serverConfig(['json_hash']))).get('foreign.concord-self.json_hash');
  assert.notEqual(reshaped.config.schemaDigest, original.config.schemaDigest);
});

test('a digest naming a different binary is refused before the server is spawned', async () => {
  // The digest is the operator's statement about which binary they reviewed. A config whose
  // digest is well formed but does not match the file must fail, and must fail without running
  // anything -- otherwise the field is decoration.
  const wrong = 'a'.repeat(64);
  const named = byName(makeForeignTools(manifest(), serverConfig(['json_hash'], { executableSha256: wrong })));
  const tool = named.get('foreign.concord-self.json_hash');
  await assert.rejects(tool.execute({ value: 1 }, context), (e) => e.code === 'INTEGRATION_EXECUTABLE');
});
