import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { makeReverseTools } from '../src/reverse.mjs';
import { parseJson } from '../src/value.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const table = parseJson(fs.readFileSync(path.join(root, 'reverse-tools.json'), 'utf8'));
// The reviewed executable is this very interpreter, so the real spawn path is exercised rather
// than mocked: a provider tool that never actually runs would prove nothing about argv handling.
const node = process.execPath;
const nodeSha = createHash('sha256').update(fs.readFileSync(node)).digest('hex');
const byName = (tools) => new Map(tools.map((t) => [t.name, t]));

function workspace(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'concord-reverse-')));
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });
  fs.writeFileSync(path.join(dir, 'show.js'), 'console.log(process.argv.slice(2).join("|"));');
  return { dir, context: { workspaceRoot: dir, policy: { maxOutputBytes: 65536, timeoutMs: 20000 } } };
}

const adbProvider = (commands) => ({
  name: 'adb', executable: node, executableSha256: nodeSha,
  timeoutMs: 20000, maxOutputBytes: 65536, commands,
});

test('the contract table covers REAs whole surface and every entry is classified', () => {
  assert.equal(table.schemaVersion, 1);
  assert.match(table.revision, /^[0-9a-f]{40}$/);
  assert.equal(table.tools.length, 117);
  for (const entry of table.tools) {
    assert.match(entry.name, /^[a-z][a-z0-9_]{2,80}$/);
    // Every tool has a realization route: an internal reader, or a provider that can run it.
    assert.ok(entry.internalizable === true || entry.provider, entry.name);
    assert.ok(typeof entry.basis === 'string' && entry.basis.length, entry.name);
  }
  assert.equal(table.tools.filter((e) => e.provider).length, 66);
  assert.equal(table.tools.filter((e) => e.internalizable === true).length, 51);
});

test('with nothing provisioned only the catalog registers, and it reports the whole surface', () => {
  const tools = makeReverseTools(table);
  assert.deepEqual(tools.map((t) => t.name), ['rea.catalog']);
  const catalog = tools[0];
  assert.equal(catalog.effect, 'pure');
  const all = catalog.execute({});
  assert.equal(all.total, 117);
  // Naming a capability is never acquiring it.
  assert.equal(all.grantsCapabilities, false);
  assert.equal(all.tools.filter((r) => r.realization === 'provider').length, 66);
  assert.equal(all.availableNow, all.tools.filter((r) => r.available).length);
  // Static capabilities are reported here but registered in src/artifacts.mjs, never twice.
  for (const row of all.tools.filter((r) => r.realization === 'static')) {
    assert.ok(row.implementedBy.startsWith('artifact.'), row.name);
  }
  assert.equal(catalog.execute({ provider: 'adb' }).matched, 24);
  assert.equal(catalog.execute({ query: 'frida' }).tools.every((r) => r.name.includes('frida')), true);
  assert.ok(catalog.execute({ availableOnly: true }).tools.every((r) => r.available));
});

test('a reviewed provider registers real process tools whose input schema is its own slots', async (t) => {
  const { context } = workspace(t);
  const tools = makeReverseTools(table, { providers: [adbProvider({
    list_adb_devices: ['show.js', 'devices', '-l'],
    inspect_adb_package: ['show.js', '-s', '{serial}', 'shell', 'dumpsys', 'package', '{package}'],
  })] });
  const named = byName(tools);
  assert.deepEqual([...named.keys()].sort(), ['rea.catalog', 'rea.inspect_adb_package', 'rea.list_adb_devices']);

  const pkg = named.get('rea.inspect_adb_package');
  assert.equal(pkg.effect, 'process');
  // The operator's template decides the input surface, so a plan cannot reach an unopened slot.
  assert.deepEqual(pkg.inputSchema.required, ['package', 'serial']);
  assert.deepEqual(pkg.config.slots, ['serial', 'package']);

  const ran = await pkg.execute({ serial: 'ABC123', package: 'com.example.app' }, context);
  assert.equal(ran.exitCode, 0);
  assert.equal(ran.untrusted, true);
  assert.equal(ran.stdout.trim(), '-s|ABC123|shell|dumpsys|package|com.example.app');

  // A template with no slots takes no input at all.
  const list = named.get('rea.list_adb_devices');
  assert.deepEqual(list.inputSchema.required, []);
  assert.equal((await list.execute({}, context)).stdout.trim(), 'devices|-l');
});

test('slot values cannot inject options, separators or paths outside the workspace', async (t) => {
  const { context } = workspace(t);
  const named = byName(makeReverseTools(table, { providers: [adbProvider({
    inspect_adb_package: ['show.js', '-s', '{serial}', 'package', '{package}'],
    pull_adb_file: ['show.js', 'pull', '{path}'],
  })] }));
  const pkg = named.get('rea.inspect_adb_package');

  for (const [why, input] of [
    ['a leading dash would change the meaning of the reviewed command', { serial: '-rf', package: 'com.example' }],
    ['a space would split into extra arguments', { serial: 'a b', package: 'com.example' }],
    ['shell metacharacters are not permitted by the pattern', { serial: 'A1', package: 'com.example; rm -rf /' }],
    ['a newline cannot be smuggled through a slot', { serial: 'A1\nB2', package: 'com.example' }],
  ]) {
    await assert.rejects(pkg.execute(input, context), (e) => e.code === 'REVERSE_INPUT', why);
  }
  // Absent and undeclared slots fail at the schema, before any argv is built.
  await assert.rejects(pkg.execute({ serial: 'A1' }, context), (e) => e.code === 'SCHEMA_MISMATCH');
  await assert.rejects(pkg.execute({ serial: 'A1', package: 'com.example', extra: 'x' }, context), (e) => e.code === 'SCHEMA_MISMATCH');

  // A path slot is resolved for containment rather than pattern-matched.
  const pull = named.get('rea.pull_adb_file');
  for (const bad of ['../outside.txt', path.join(root, 'README.md')]) {
    await assert.rejects(pull.execute({ path: bad }, context), (e) => e.code === 'PATH_DENIED', bad);
  }
  fs.writeFileSync(path.join(context.workspaceRoot, 'inside.bin'), 'x');
  assert.equal((await pull.execute({ path: 'inside.bin' }, context)).stdout.trim(), 'pull|inside.bin');
});

test('reviewed configuration is checked at registration, and the template binds the approval', () => {
  for (const [why, commands] of [
    ['a command naming no REA tool', { not_a_rea_tool: ['x'] }],
    ['a command belonging to another provider', { cutter_command: ['x'] }],
    ['a slot the compiler does not define', { list_adb_devices: ['{whatever}'] }],
    ['an empty template', { list_adb_devices: [] }],
    ['no commands at all', {}],
  ]) {
    assert.throws(() => makeReverseTools(table, { providers: [adbProvider(commands)] }),
      (e) => e.code === 'REVERSE_CONFIG', why);
  }
  assert.throws(() => makeReverseTools(table, { providers: [adbProvider({ list_adb_devices: ['x'] }), adbProvider({ list_adb_devices: ['y'] })] }),
    (e) => e.code === 'REVERSE_CONFIG');
  assert.throws(() => makeReverseTools(table, { unknownField: 1 }), (e) => e.code === 'REVERSE_CONFIG');
  assert.throws(() => makeReverseTools({ schemaVersion: 1, tools: [] }), (e) => e.code === 'REVERSE_TABLE_INVALID');
  assert.throws(() => makeReverseTools({ ...table, revision: 'short' }), (e) => e.code === 'REVERSE_TABLE_INVALID');

  // Changing the operator's argv must change the digest, so an approval for the old command
  // cannot authorize the new one.
  const digestOf = (commands) => byName(makeReverseTools(table, { providers: [adbProvider(commands)] }))
    .get('rea.list_adb_devices').config.templateDigest;
  assert.notEqual(digestOf({ list_adb_devices: ['show.js', 'devices'] }), digestOf({ list_adb_devices: ['show.js', 'devices', '-l'] }));
});
