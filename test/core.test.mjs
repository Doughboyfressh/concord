import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync, existsSync, linkSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { canonical, digest, parseJson, validateSchema, clone } from '../src/value.mjs';
import { runPlan, replayPlan, inspectPlan, attenuatePolicy } from '../src/engine.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';
import { makeArtifactTools } from '../src/artifacts.mjs';
import { makeReaderTools } from '../src/readers.mjs';
import { HarnessError } from '../src/value.mjs';
import { tempDir } from './temp-workspace.mjs';
import { writeGhidraFixtures } from './ghidra-fixtures.mjs';

const registry = new Map(makeBuiltinTools().map(t => [t.name, t]));
const policy = { version: 1, allowedTools: [...registry.keys()], allowedEffects: ['pure', 'read', 'write'], maxOutputBytes: 10000, maxJournalBytes: 100000 };
const base = (plan, overrides = {}) => ({ plan, policy, registry, sourceLock: { version: 1 }, workspaceRoot: path.resolve('/explicit/workspace'), ...overrides });
const task = (id, input = 1) => ({ id, tool: 'json.value', input });
const one = { version: 1, tasks: [task('a')] };

test('canonical identity is independent of key insertion, distinct for order', () => {
  assert.equal(canonical({ z: 1, a: [2, 3] }), '{"a":[2,3],"z":1}');
  assert.equal(digest({ z: 1, a: 2 }), digest({ a: 2, z: 1 }));
  assert.notEqual(digest([1, 2]), digest([2, 1]));
});
test('canonical rejects unsupported, unsafe, cyclic and hidden data without invoking accessors', () => {
  const cycle = {}; cycle.a = cycle;
  const accessor = {}; Object.defineProperty(accessor, 'a', { enumerable: true, get() { throw Error('called'); } });
  for (const bad of [undefined, NaN, Infinity, 9007199254740992, 1n, new Date(), cycle, [, 1], accessor, JSON.parse('{"__proto__":1}'), { a: undefined }]) assert.throws(() => canonical(bad), e => e.code === 'INVALID_JSON');
});
test('strict JSON rejects duplicate keys, unsafe keys and extra content', () => {
  for (const bad of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"constructor":1}', '1 2', '[1,]', '{"a":NaN}', '"unterminated', '{"x":01}']) assert.throws(() => parseJson(bad));
  assert.deepEqual(parseJson(' {"a":"\\\"x", "b":[true, null, -1.5e2]} '), { a: '"x', b: [true, null, -150] });
});
test('schema subset is explicit and fails closed', () => {
  validateSchema({ a: 2 }, { type: 'object', properties: { a: { type: 'integer', minimum: 1 } }, required: ['a'], additionalProperties: false });
  assert.throws(() => validateSchema({ a: 2, b: 3 }, { type: 'object', properties: { a: true }, additionalProperties: false }));
  assert.throws(() => validateSchema('a', { pattern: '.' }), e => e.code === 'INVALID_SCHEMA');
  assert.throws(() => validateSchema('a', { oneOf: [true, true] }));
});
test('equivalent captures have identical roots and stable topological order', async () => {
  const plan = { version: 1, tasks: [task('z'), task('b'), { ...task('a'), dependsOn: ['b'] }] };
  const a = await runPlan(base(plan)), b = await runPlan(base(plan));
  assert.deepEqual(a, b);
  assert.deepEqual(a.events[0].data.order, ['b', 'a', 'z']);
  assert.equal(replayPlan({ ...base(plan), journal: a, expectedRoot: a.root }).replayed, true);
});
test('invalid graph and unknown capabilities fail before tools', async () => {
  for (const tasks of [[task('constructor')], [task('prototype')], [task('a'), task('a')], [{ ...task('a'), dependsOn: ['missing'] }], [{ ...task('a'), dependsOn: ['b'] }, { ...task('b'), dependsOn: ['a'] }], [{ ...task('a'), tool: 'unknown' }], [{ ...task('a'), input: { $task: 'b' } }, task('b')]]) await assert.rejects(runPlan(base({ version: 1, tasks })));
  await assert.rejects(runPlan(base(one, { policy: { ...policy, allowedTools: [] } })), e => e.code === 'POLICY_DENIED');
  await assert.rejects(runPlan(base(one, { policy: { ...policy, allowedEffects: [] } })), e => e.code === 'POLICY_DENIED');
});
test('references use direct dependencies and RFC6901 own-property paths', async () => {
  const plan = { version: 1, tasks: [task('a', { 'x/y': { '~z': [7] } }), { ...task('b', { $task: 'a', path: '/x~1y/~0z/0' }), dependsOn: ['a'] }] };
  const j = await runPlan(base(plan));
  assert.equal(j.results.b, 7);
  replayPlan({ ...base(plan), journal: j });
  for (const pointer of ['/x~1y/~0z/00', '/x~1y/~0z/length', '/constructor', '/missing']) {
    const bad = clone(plan); bad.tasks[1].input.path = pointer;
    const result = await runPlan(base(bad));
    assert.equal(result.outcome.code, 'INPUT_INVALID');
    replayPlan({ ...base(bad), journal: result });
  }
});
test('exact approval binds resolved input, policy, sources, tool config and workspace', async () => {
  let calls = 0;
  const tool = { name: 'write', version: '1', effect: 'write', inputSchema: true, config: { target: 'one' }, execute() { calls++; return true; } };
  const p = { version: 1, allowedTools: ['write'], allowedEffects: ['write'], maxOutputBytes: 10000, maxJournalBytes: 100000 };
  const plan = { version: 1, tasks: [{ id: 'a', tool: 'write', input: { data: 1 } }] };
  const o = base(plan, { policy: p, registry: new Map([['write', tool]]) });
  const blocked = await runPlan(o);
  assert.equal(calls, 0); assert.equal(blocked.outcome.status, 'blocked');
  const approvals = [blocked.outcome.requestHash];
  const done = await runPlan({ ...o, approvals }); assert.equal(calls, 1); assert.equal(done.outcome.status, 'completed');
  replayPlan({ ...o, journal: done }); assert.equal(calls, 1);
  for (const change of [{ sourceLock: { version: 2 } }, { workspaceRoot: path.resolve('/different') }, { policy: { ...p, timeoutMs: 123 } }, { plan: { version: 1, tasks: [{ ...plan.tasks[0], input: { data: 2 } }] } }, { registry: new Map([['write', { ...tool, config: { target: 'two' } }]]) }]) {
    const result = await runPlan({ ...o, ...change, approvals }); assert.equal(result.outcome.status, 'blocked');
  }
});
test('replay rejects changed context, chain, root, truncation and trailing events', async () => {
  const j = await runPlan(base(one));
  for (const mutate of [x => { x.events[1].data.inputHash = '0'.repeat(64); }, x => { x.root = '1'.repeat(64); }, x => { x.events.pop(); }, x => { x.results.a = 2; }, x => { x.outcome.status = 'failed'; }, x => { x.events.push(x.events[0]); }]) {
    const bad = clone(j); mutate(bad);
    assert.throws(() => replayPlan({ ...base(one), journal: bad }));
  }
  assert.throws(() => replayPlan({ ...base(one, { sourceLock: {} }), journal: j }));
  assert.throws(() => replayPlan({ ...base(one), journal: j, expectedRoot: '0'.repeat(64) }));
});
test('rehashing an illegal transition does not make it replayable', async () => {
  const j = clone(await runPlan(base(one)));
  j.events[1].type = 'completed';
  let previous = digest(j.header);
  for (const e of j.events) { e.previous = previous; e.hash = digest({ previous, seq: e.seq, type: e.type, data: e.data }); previous = e.hash; }
  j.root = previous;
  assert.throws(() => replayPlan({ ...base(one), journal: j }), e => e.code === 'REPLAY_TRANSITION');
});
test('postconditions stop dependents and replay records failure without execution', async () => {
  const plan = { version: 1, tasks: [{ ...task('a', 2), outputSchema: { const: 1 } }, { ...task('b'), dependsOn: ['a'] }] };
  const j = await runPlan(base(plan)); assert.equal(j.outcome.status, 'failed'); assert.equal(j.results.b, undefined);
  replayPlan({ ...base(plan), journal: j });
});
test('deadlines and non-JSON outputs fail closed, with distinct codes', async () => {
  // Both still fail closed; round 010 separated the stage at which they fail. A non-JSON return
  // value means the tool RETURNED and its output was unusable (OUTPUT_REJECTED); a deadline means
  // execution never produced a value at all (TOOL_FAILED here, since the tool is pure). The
  // distinction exists for effectful tools, where only the second case is genuinely indeterminate.
  for (const [execute, expected] of [[() => undefined, 'OUTPUT_REJECTED'], [() => new Promise(() => {}), 'TOOL_FAILED']]) {
    const tool = { name: 'x', version: '1', effect: 'pure', inputSchema: true, execute };
    const options = base({ version: 1, tasks: [{ id: 'a', tool: 'x', input: null }] }, { registry: new Map([['x', tool]]), policy: { ...policy, allowedTools: ['x'], timeoutMs: 10 } });
    const j = await runPlan(options); assert.equal(j.outcome.code, expected); replayPlan({ ...options, journal: j });
  }
});
test('reserve journal budget before invoking effects', async () => {
  let calls = 0;
  const tool = { name: 'x', version: '1', effect: 'pure', inputSchema: true, execute() { calls++; return 1; } };
  const o = base({ version: 1, tasks: [{ id: 'a', tool: 'x', input: null }] }, { registry: new Map([['x', tool]]), policy: { ...policy, allowedTools: ['x'], maxOutputBytes: 10000, maxJournalBytes: 4000 } });
  const j = await runPlan(o); assert.equal(calls, 0); assert.equal(j.outcome.code, 'BUDGET_EXHAUSTED'); replayPlan({ ...o, journal: j });
});
test('intent is durable before execution and existing journals are refused', async () => {
  const temp = tempDir('concord-journal-');
  try {
    const filename = path.join(temp, 'events.jsonl');
    const tool = { name: 'x', version: '1', effect: 'read', inputSchema: true, execute() { const log = readFileSync(filename, 'utf8'); assert.match(log, /"type":"intent"/); return true; } };
    const o = base({ version: 1, tasks: [{ id: 'a', tool: 'x', input: null }] }, { registry: new Map([['x', tool]]), policy: { ...policy, allowedTools: ['x'] }, journalPath: filename });
    const j = await runPlan(o); assert.equal(j.outcome.status, 'completed'); await assert.rejects(runPlan(o), e => e.code === 'EEXIST');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
test('file write requires grant, uses exclusive create, and is not repeated on replay', async () => {
  const temp = tempDir('concord-write-');
  try {
    const plan = { version: 1, tasks: [{ id: 'a', tool: 'files.write', input: { path: 'memory.json', content: { lesson: 'x' } } }] };
    const o = base(plan, { workspaceRoot: temp });
    const b = await runPlan(o); assert.equal(existsSync(path.join(temp, 'memory.json')), false);
    const j = await runPlan({ ...o, approvals: [b.outcome.requestHash] });
    assert.equal(j.outcome.status, 'completed'); replayPlan({ ...o, journal: j });
    assert.deepEqual(JSON.parse(readFileSync(path.join(temp, 'memory.json'), 'utf8')), { lesson: 'x' });
    const second = await runPlan({ ...o, approvals: [b.outcome.requestHash] }); assert.equal(second.outcome.code, 'EFFECT_INDETERMINATE');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
test('untrusted inputs cannot mutate downstream evidence', async () => {
  const evil = { name: 'x', version: '1', effect: 'pure', inputSchema: true, execute(input) { input.x = 2; return input; } };
  const options = base({ version: 1, tasks: [{ id: 'a', tool: 'x', input: { x: 1 } }] }, { registry: new Map([['x', evil]]), policy: { ...policy, allowedTools: ['x'] } });
  assert.equal((await runPlan(options)).outcome.status, 'failed');
});
test('file reads reject hardlinks and directories before reading', (t) => {
  const temp = tempDir('concord-links-');
  try {
    const workspace = path.join(temp, 'workspace'); mkdirSync(workspace);
    const outside = path.join(temp, 'outside'); writeFileSync(outside, 'secret');
    const tool = registry.get('files.read');
    const context = { workspaceRoot: workspace, policy: { maxOutputBytes: 10000 } };
    assert.throws(() => tool.execute({ path: 'directory' }, context));
    mkdirSync(path.join(workspace, 'directory'));
    assert.throws(() => tool.execute({ path: 'directory' }, context));
    try { linkSync(outside, path.join(workspace, 'alias')); }
    catch (error) { if (['EPERM', 'EACCES'].includes(error.code)) { t.skip('Host disallows link creation'); return; } throw error; }
    assert.throws(() => tool.execute({ path: 'alias' }, context), e => e.code === 'PATH_DENIED');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
test('replay enforces post-intent receipt reserve', async () => {
  const o = base(one, { policy: { ...policy, maxOutputBytes: 10000, maxJournalBytes: 13000 } });
  const j = clone(await runPlan(o));
  const output = 'x'.repeat(9998);
  j.events.find(e => e.type === 'completed').data = { taskId: 'a', output, outputHash: digest(output) };
  j.results.a = output;
  let previous = digest(j.header);
  for (const e of j.events) { e.previous = previous; e.hash = digest({ previous, seq: e.seq, type: e.type, data: e.data }); previous = e.hash; }
  j.root = previous;
  assert.throws(() => replayPlan({ ...o, journal: j }), e => e.code === 'REPLAY_LIMIT');
});
test('ambient working-directory roots cannot enter approval identity', async () => {
  const roots = ['.', '..', 'relative/path', 'C:relative'];
  if (path.sep === '\\') roots.push('/drive-relative', '\\drive-relative');
  for (const workspaceRoot of roots) await assert.rejects(runPlan(base(one, { workspaceRoot })), e => e.code === 'INVALID_WORKSPACE');
});

test('the input-schema gate rejects static inputs before approval and defers references to a clean INPUT_INVALID', async () => {
  let invoked = 0;
  const strict = { name: 'strict.write', version: '1', effect: 'write',
    inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'], additionalProperties: false },
    execute() { invoked++; return true; } };
  const reg = new Map([...makeBuiltinTools(), strict].map(t => [t.name, t]));
  const pol = { ...policy, allowedTools: [...reg.keys()], allowedEffects: ['pure', 'read', 'write'] };
  const ctx = p => ({ plan: p, policy: pol, registry: reg, sourceLock: { version: 1 }, workspaceRoot: path.resolve('/explicit/workspace') });

  // A static input of the wrong type is refused structurally: no execution, no approval hash.
  const staticBad = { version: 1, tasks: [{ id: 'w', tool: 'strict.write', input: { text: 42 } }] };
  await assert.rejects(runPlan(ctx(staticBad)), e => e.code === 'SCHEMA_MISMATCH');
  assert.throws(() => inspectPlan(ctx(staticBad)), e => e.code === 'SCHEMA_MISMATCH');
  assert.equal(invoked, 0);

  // A $task reference cannot be validated until its dependency resolves, which inspectPlan
  // discloses in its own note rather than papering over.
  const referenced = { version: 1, tasks: [
    { id: 'n', tool: 'json.value', input: 42 },
    { id: 'w', tool: 'strict.write', input: { text: { $task: 'n' } }, dependsOn: ['n'] },
  ] };
  assert.match(inspectPlan(ctx(referenced)).note, /resolve when dependency evidence is available/);

  const journal = await runPlan(ctx(referenced));
  assert.equal(journal.outcome.status, 'failed');
  assert.equal(journal.outcome.taskId, 'w');
  // The decisive assertion. A write whose resolved input fails validation reports INPUT_INVALID,
  // never EFFECT_INDETERMINATE: validation provably precedes execute(), so "the effect may have
  // occurred" would be a false indeterminate, and this project's guidance forbids retrying one.
  assert.equal(journal.outcome.code, 'INPUT_INVALID');
  assert.equal(invoked, 0);
  // Nothing was ever offered for approval, because the input could not validate.
  // Scoped to the failing task: its pure dependency legitimately ran and recorded its own intent.
  assert.ok(!journal.events.some(e => e.type === 'blocked' && e.data.taskId === 'w'));
  assert.ok(!journal.events.some(e => e.type === 'intent' && e.data.taskId === 'w'));
  assert.ok(journal.events.some(e => e.type === 'intent' && e.data.taskId === 'n'));
  replayPlan({ ...ctx(referenced), journal });
});

test('a journaled INPUT_INVALID records which rule it broke, and replay reconstructs it', async () => {
  // Measured in round 004: asked to extract a field nested inside a JSON file's text, the model
  // proposed a reference path into files.read's result object, where that field does not exist.
  // The plan was structurally valid (references defer validation by design) and failed only at
  // execution, where a bare INPUT_INVALID gave no way to tell a nonexistent path from a malformed
  // pointer. Both sides of the kernel must record the same diagnostic or replay breaks.
  const plan = { version: 1, tasks: [
    { id: 'a', tool: 'json.value', input: { text: 'flat' } },
    { id: 'b', tool: 'json.value', input: { v: { $task: 'a', path: '/project/topic' } }, dependsOn: ['a'] },
  ] };
  const journal = await runPlan(base(plan));
  assert.equal(journal.outcome.code, 'INPUT_INVALID');
  const failed = journal.events.find(e => e.type === 'failed');
  assert.equal(failed.data.taskId, 'b');
  assert.match(failed.data.reason, /Reference path does not exist/);
  // The outcome stays exactly as before, so the settled envelope is unchanged.
  assert.deepEqual(journal.outcome, { status: 'failed', taskId: 'b', code: 'INPUT_INVALID' });
  // Replay must reconstruct the identical event, including the diagnostic.
  replayPlan({ ...base(plan), journal });

  // The sibling rule is caught earlier still: a pointer that is not RFC 6901 does not depend on
  // any resolved value, so inspectRefs rejects it structurally at compile time and the plan never
  // reaches execution or an approval hash. The two rules share one code but not one stage.
  const badPointer = clone(plan);
  badPointer.tasks[1].input.v.path = 'project/topic';
  await assert.rejects(runPlan(base(badPointer)), e => e.code === 'INVALID_REFERENCE' && /RFC 6901/.test(e.message));
  assert.throws(() => inspectPlan(base(badPointer)), e => e.code === 'INVALID_REFERENCE');
});

test('every declared outputKeys set is really present in that tool\'s actual result', async () => {
  // A declared output shape that drifts from reality would be a new false-assurance channel:
  // the model would build reference paths from it and the kernel would reject them at execution.
  // So the declaration is verified by running each tool, not by inspection. `outputKeys` means
  // "always present", so a tool with conditional extras (artifact.inspect's per-format blocks)
  // is checked as a subset and never over-promises.
  const temp = tempDir('concord-outputkeys-');
  writeFileSync(path.join(temp, 'f.txt'), 'hello');
  // Real carriers, so the tools below are exercised on their main path rather than their
  // not-this-format fallback: an empty but valid WASM module, and legacy EVM bytecode.
  writeFileSync(path.join(temp, 'm.wasm'), Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
  writeFileSync(path.join(temp, 'code.bin'), Buffer.from([0x60, 0x01, 0x50, 0x00]));
  // The Ghidra readers each have a not-this-format branch, so a wrong-shaped carrier would check
  // nothing here: every one would answer `supported: false` and still have all its declared keys.
  // These fixtures are valid against the shipped RelaxNG schemas, and the .sla is a real zlib
  // PackedFormat stream, so the keys are checked on the path that actually decodes something.
  const ghidraInputs = writeGhidraFixtures(temp);
  const context = { workspaceRoot: temp, policy: { maxOutputBytes: 100000 }, requestHash: 'a'.repeat(64) };
  const tools = new Map([...makeBuiltinTools(), ...makeArtifactTools(), ...makeReaderTools()].map(t => [t.name, t]));
  const candidate = await tools.get('memory.candidate').execute({ lesson: 'a lesson worth keeping', evidence: [{ a: 1 }] }, context);
  const inputs = {
    'json.hash': { a: 1 },
    'json.assert': { value: 1, schema: true },
    // Round 017 added this tool, and this test caught it unexercised on the first run — round 005's
    // rule that a declared output shape must be verified against real execution, working as built.
    'experiment.compare': { hypothesis: 'a varied factor explains the difference',
      conditions: [{ name: 'a', varied: { factor: 1 }, expected: 1, actual: 1 },
        { name: 'b', varied: { factor: 2 }, expected: 2, actual: 2 }] },
    'text.concat': { values: ['a', 'b'], separator: '-' },
    'json.mergeShallow': { values: [{ a: 1 }, { b: 2 }] },
    'files.read': { path: 'f.txt' },
    'files.write': { path: 'out.txt', content: { k: 1 } },
    'artifact.inspect': { path: 'f.txt' },
    'artifact.wasmInterface': { path: 'm.wasm' },
    'artifact.sqlite': { path: 'f.txt' },
    'artifact.pcap': { path: 'f.txt' },
    'artifact.packetFields': { path: 'f.txt' },
    'artifact.peResources': { path: 'f.txt' },
    'artifact.goBuildInfo': { path: 'f.txt' },
    'artifact.dex': { path: 'f.txt' },
    'artifact.dexClass': { path: 'f.txt', descriptor: 'Lx/Y;' },
    'artifact.dexMethod': { path: 'f.txt', descriptor: 'Lx/Y;' },
    'artifact.dexSearch': { path: 'f.txt', query: 'x' },
    'artifact.dexReferences': { path: 'f.txt', type: 'Lx/Y;' },
    'artifact.dexGraph': { path: 'f.txt' },
    'artifact.androidManifest': { path: 'f.txt' },
    'artifact.apk': { path: 'f.txt' },
    'artifact.managed': { path: 'f.txt' },
    'artifact.managedMembers': { path: 'f.txt' },
    'artifact.managedNativeBoundaries': { path: 'f.txt' },
    'artifact.managedGraph': { path: 'f.txt' },
    'artifact.compareManagedMembers': { left: { members: [] }, right: { members: [] } },
    'artifact.verifyManagedNativeBoundaries': { boundaries: [] },
    'artifact.importManagedReconstruction': { observed: { members: [] }, reconstruction: [] },
    'artifact.sourceMap': { path: 'f.txt' },
    'artifact.sourceLocation': { path: 'f.txt', line: 0, column: 0 },
    'artifact.recoverSources': { path: 'f.txt' },
    'artifact.moduleImports': { path: 'f.txt' },
    'artifact.jsExports': { path: 'f.txt' },
    'artifact.jsSemantics': { path: 'f.txt' },
    'artifact.webBundle': { path: 'f.txt' },
    'artifact.htmlScripts': { path: 'f.txt' },
    'artifact.harCapture': { path: 'f.txt' },
    'artifact.jsApplication': { entry: 'f.txt' },
    'artifact.compareJsExports': { left: { exports: [] }, right: { exports: [] } },
    'artifact.compareSourceToBundle': { source: { exports: [] }, bundle: { exports: [] } },
    'artifact.compareHar': { left: { entries: [] }, right: { entries: [] } },
    'artifact.firmware': { path: 'f.txt' },
    'artifact.firmwareRegion': { path: 'f.txt', offset: 0 },
    'artifact.rustBinary': { path: 'f.txt' },
    'artifact.dartSnapshot': { path: 'f.txt' },
    'artifact.flutterBuild': { path: 'f.txt' },
    'artifact.electronFuses': { path: 'f.txt' },
    'artifact.plist': { path: 'f.txt' },
    'artifact.appleGraph': { plist: 'f.txt' },
    'artifact.harmonyGraph': { path: 'f.txt' },
    'artifact.coreDump': { path: 'f.txt' },
    'artifact.analysisView': { view: { records: [] } },
    'artifact.obligationLedger': { facts: [] },
    'artifact.reconstructionCoverage': { boundaryId: 'b', obligations: [] },
    'artifact.compareApplicationVersions': { left: { entries: [] }, right: { entries: [] } },
    'artifact.traceFeature': { feature: 'x', inventory: { entries: [] } },
    'artifact.evmInterface': { path: 'code.bin', encoding: 'raw' },
    'artifact.compareWasmInterfaces': { left: { state: 'complete', entries: [] }, right: { state: 'complete', entries: [] } },
    'memory.candidate': { lesson: 'a lesson worth keeping', evidence: [{ a: 1 }] },
    'memory.promote': candidate,
    'memory.recall': { query: 'lesson', limit: 3 },
    'skills.rank': { query: 'binary', skills: [{ id: 'a', text: 'binary analysis' }] },
    ...ghidraInputs,
  };
  const declared = [...tools.values()].filter(t => Array.isArray(t.outputKeys));
  assert.ok(declared.length >= 11, 'declarations exist to verify');
  for (const tool of declared) {
    assert.ok(inputs[tool.name], `${tool.name} declares outputKeys and must be exercised here`);
    const output = await tool.execute(inputs[tool.name], context);
    assert.ok(output && typeof output === 'object' && !Array.isArray(output), `${tool.name} returns an object`);
    const actual = Object.keys(output);
    for (const key of tool.outputKeys) assert.ok(actual.includes(key), `${tool.name} result is missing declared key ${key}`);
  }
  // The one that actually mattered: files.read's text is a single string, so a path into the
  // JSON it happens to contain is not addressable. This is what round 004's failure assumed.
  const read = tools.get('files.read');
  assert.ok(read.outputKeys.includes('text'));
  assert.ok(!read.outputKeys.includes('project'));
  rmSync(temp, { recursive: true, force: true });
});

test('a task reference serialised into a string is rejected, not silently executed as data', async () => {
  // Round 005 measured this three times: the model described the correct unstringified reference
  // in prose and emitted a quoted one. A quoted reference is a valid string, so it passed every
  // schema, executed, and produced a result built from the reference's own source text — a wrong
  // answer carrying a faithful receipt. Rejected at compile time so the mistake is correctable,
  // never repaired, because the harness must not reinterpret what a caller actually wrote.
  const quoted = JSON.stringify({ $task: 'a', path: '/value' });
  for (const input of [
    quoted,                                   // the whole input
    { values: ['literal', quoted] },          // nested in an array, as text.concat emitted it
    { [quoted]: null },                       // used as an object key, as the later attempt emitted
    { nested: { deep: quoted } },             // arbitrarily deep
  ]) {
    const plan = { version: 1, tasks: [task('a'), { id: 'b', tool: 'json.value', input, dependsOn: ['a'] }] };
    await assert.rejects(runPlan(base(plan)), e => e.code === 'INVALID_REFERENCE' && /written as a string/.test(e.message));
    assert.throws(() => inspectPlan(base(plan)), e => e.code === 'INVALID_REFERENCE');
  }
  // The genuine unstringified form still works, and still resolves to the referenced value.
  const good = { version: 1, tasks: [task('a', { value: 'real' }), { id: 'b', tool: 'json.value', input: { $task: 'a', path: '/value' }, dependsOn: ['a'] }] };
  const journal = await runPlan(base(good));
  assert.equal(journal.results.b, 'real');
  replayPlan({ ...base(good), journal });
  // Ordinary strings that merely look JSON-ish are untouched: the signature is exact.
  for (const benign of ['{"a":1}', '{ not json', '{"$task":1,"extra":2}', 'plain text', '["$task"]']) {
    const plan = { version: 1, tasks: [{ id: 'a', tool: 'json.value', input: { v: benign } }] };
    const j = await runPlan(base(plan));
    assert.equal(j.outcome.status, 'completed', `benign string rejected: ${benign}`);
  }
});

test('a schema rejection names where and which rule, without ever echoing a value', () => {
  // Round 005 measured the cost of a locationless message: a rejection reading only "Value does
  // not satisfy the declared schema" names the rule but not the field, and could not be acted on.
  const concat = { type: 'object', properties: { values: { type: 'array', items: { type: 'string' }, minItems: 1 }, separator: { type: 'string' } }, required: ['values', 'separator'], additionalProperties: false };
  const message = (value, schema = concat) => { try { validateSchema(value, schema); return null; } catch (e) { return e.message; } };

  assert.match(message({ values: ['a', 42], separator: '-' }), /\/values\/1 expected type string but found number/);
  assert.match(message({ values: [], separator: ',' }), /\/values needs at least 1 item but has 0/);
  assert.match(message({ separator: ',' }), /missing required property values/);
  // An undeclared key is caller data and is never named; the schema's permitted names are.
  assert.match(message({ values: ['a'], separator: ',', extra: 1 }), /has an undeclared property; permitted properties are separator, values/);
  assert.match(message({ outer: { inner: [{ k: 'str' }] } }, { type: 'object', properties: { outer: { type: 'object', properties: { inner: { type: 'array', items: { type: 'object', properties: { k: { type: 'number' } } } } } } } }), /\/outer\/inner\/0\/k expected type number but found string/);
  // Property names are RFC 6901 escaped, matching how task references address the same structures.
  assert.match(message({ 'a/b': 1 }, { type: 'object', properties: { 'a/b': { type: 'string' } } }), /\/a~1b /);

  // The invariant that matters: the offending value never appears. This text reaches model context
  // and journaled failure reasons, so it must not become a channel for the data being validated.
  const secret = 'SENSITIVE-VALUE-DO-NOT-ECHO';
  for (const value of [{ values: [secret, 1], separator: ',' }, { values: ['a'], separator: 7, [secret]: 1 }]) {
    const text = message(value);
    assert.ok(text, 'rejected');
    assert.doesNotMatch(text, new RegExp(secret), 'a validated value must never appear in the diagnostic');
  }
  // A failure inside an anyOf alternative is speculative, so the report stays at the alternative.
  assert.match(message(7, { anyOf: [{ type: 'string' }, { type: 'object', properties: { a: { type: 'string' } } }] }), /matches none of the permitted alternatives/);

  // Deterministic: identical content in a different key order yields an identical message,
  // which is required because this text is recorded in journals and must replay byte for byte.
  const pair = { type: 'object', properties: { a: { type: 'string' }, b: { type: 'string' } } };
  assert.equal(message({ a: 1, b: 2 }, pair), message({ b: 2, a: 1 }, pair));
});

test('an array may mix literal values with references, and resolves each in place', async () => {
  // Rounds 004-006 read a repeated failure here as a model serialisation weakness. That was wrong:
  // references emit correctly alone in an array, as an object property, and several per array. The
  // single failing condition was an array MIXING a literal with a reference, where the reference
  // was coerced to a string for type-homogeneity with its neighbour. The kernel always accepted
  // the mixed form; this pins that, so no future reference check (such as the stringified-reference
  // rejection) can start refusing a legitimate mixed array.
  const plan = { version: 1, tasks: [
    { id: 'join', tool: 'text.concat', input: { values: ['x', 'y'], separator: '-' } },
    { id: 'mixed', tool: 'text.concat', input: { values: ['label:', { $task: 'join', path: '/value' }], separator: ' ' }, dependsOn: ['join'] },
  ] };
  const journal = await runPlan(base(plan));
  assert.equal(journal.outcome.status, 'completed');
  // The reference resolved to the referenced value, not to its own source text.
  assert.equal(journal.results.mixed.value, 'label: x-y');
  replayPlan({ ...base(plan), journal });

  // Several references and literals interleaved, each resolving independently and in order.
  const interleaved = { version: 1, tasks: [
    { id: 'a', tool: 'text.concat', input: { values: ['p', 'q'], separator: '' } },
    { id: 'b', tool: 'text.concat', input: { values: ['r', 's'], separator: '' } },
    { id: 'both', tool: 'text.concat', input: { values: [{ $task: 'a', path: '/value' }, 'middle', { $task: 'b', path: '/value' }], separator: '|' }, dependsOn: ['a', 'b'] },
  ] };
  const second = await runPlan(base(interleaved));
  assert.equal(second.results.both.value, 'pq|middle|rs');
  replayPlan({ ...base(interleaved), journal: second });
});

test('a failure after the tool returned is not reported as a possibly-occurred effect', async () => {
  // Round 009 saw EFFECT_INDETERMINATE for a write that had certainly happened. Round 010 measured
  // the unambiguous version of that: when a tool RETURNS and the failure is about its output, the
  // engine is holding the output, so the effect definitely occurred. Calling that "may have
  // occurred" invites retrying something non-idempotent, which is the hazard the code exists for.
  const temp = tempDir('concord-stage-');
  const tool = { name: 'w', version: '1', effect: 'write', inputSchema: true,
    execute({ name }, ctx) { writeFileSync(path.join(ctx.workspaceRoot, name), 'x'); return { big: 'y'.repeat(50) }; } };
  const opts = (plan, pol = {}) => ({ plan, registry: new Map([['w', tool]]), sourceLock: { version: 1 }, workspaceRoot: temp,
    policy: { version: 1, allowedTools: ['w'], allowedEffects: ['write'], maxOutputBytes: 10000, maxJournalBytes: 100000, ...pol } });
  const grantAndRun = async (o) => { const b = await runPlan(o); return runPlan({ ...o, approvals: [b.events.find(e => e.type === 'blocked').data.requestHash] }); };

  // The declared outputSchema rejects a result the tool really produced.
  const schemaCase = opts({ version: 1, tasks: [{ id: 'a', tool: 'w', input: { name: 'A.txt' }, outputSchema: { const: 'never' } }] });
  const a = await grantAndRun(schemaCase);
  assert.equal(a.outcome.code, 'OUTPUT_REJECTED');
  assert.ok(existsSync(path.join(temp, 'A.txt')), 'the effect really happened');
  assert.match(a.events.find(e => e.type === 'failed').data.reason, /required constant/);
  replayPlan({ ...schemaCase, journal: a });

  // The output exceeds the byte budget, which is also a post-return condition.
  const budgetCase = opts({ version: 1, tasks: [{ id: 'b', tool: 'w', input: { name: 'B.txt' } }] }, { maxOutputBytes: 20 });
  const b = await grantAndRun(budgetCase);
  assert.equal(b.outcome.code, 'OUTPUT_REJECTED');
  assert.ok(existsSync(path.join(temp, 'B.txt')));
  replayPlan({ ...budgetCase, journal: b });

  // A throw out of execute stays indeterminate: the kernel genuinely cannot know how far it got.
  const thrower = { name: 't', version: '1', effect: 'write', inputSchema: true, execute() { throw new Error('midway'); } };
  const throwCase = { plan: { version: 1, tasks: [{ id: 'c', tool: 't', input: {} }] }, registry: new Map([['t', thrower]]),
    sourceLock: { version: 1 }, workspaceRoot: temp,
    policy: { version: 1, allowedTools: ['t'], allowedEffects: ['write'], maxOutputBytes: 10000, maxJournalBytes: 100000 } };
  const c = await grantAndRun(throwCase);
  assert.equal(c.outcome.code, 'EFFECT_INDETERMINATE');
  replayPlan({ ...throwCase, journal: c });

  // Replay still refuses a journal claiming a code illegal for this tool's effect, so taking the
  // recorded failure rather than re-deriving it did not give up the check that matters.
  const forged = clone(c);
  forged.events.find(e => e.type === 'failed').data.code = 'TOOL_FAILED';
  forged.outcome.code = 'TOOL_FAILED';
  let previous = digest(forged.header);
  for (const e of forged.events) { e.previous = previous; e.hash = digest({ previous, seq: e.seq, type: e.type, data: e.data }); previous = e.hash; }
  forged.root = previous;
  assert.throws(() => replayPlan({ ...throwCase, journal: forged }), e => e.code === 'REPLAY_TRANSITION');
  rmSync(temp, { recursive: true, force: true });
});

test('a thrown tool records its own error code, which replay verifies as an identifier', async () => {
  // Round 015 produced "no diagnostic was recorded" for every thrown tool, because the engine kept
  // only the outer category. Surfacing the tool's MESSAGE was refused: a message is written by the
  // tool author and can interpolate caller data. A CODE is a closed-vocabulary identifier and
  // cannot, so this is the granularity that is both informative and safe.
  const raising = { name: 'r', version: '1', effect: 'pure', inputSchema: true,
    execute() { throw new HarnessError('MERGE_COLLISION', 'a message that is deliberately not recorded'); } };
  const crashing = { name: 'c', version: '1', effect: 'pure', inputSchema: true, execute() { throw new Error('plain crash'); } };
  const reg = new Map([['r', raising], ['c', crashing]]);
  const opts = (tool) => ({ plan: { version: 1, tasks: [{ id: 'a', tool, input: null }] }, registry: reg,
    sourceLock: { version: 1 }, workspaceRoot: path.resolve('/explicit/workspace'),
    policy: { version: 1, allowedTools: ['r', 'c'], allowedEffects: ['pure'], maxOutputBytes: 10000, maxJournalBytes: 100000 } });

  const raised = await runPlan(opts('r'));
  const raisedEvent = raised.events.find(e => e.type === 'failed');
  assert.equal(raisedEvent.data.code, 'TOOL_FAILED');
  assert.equal(raisedEvent.data.toolCode, 'MERGE_COLLISION', 'the tool names the condition it hit');
  assert.equal(raisedEvent.data.reason, undefined, 'the message itself is deliberately not recorded');
  replayPlan({ ...opts('r'), journal: raised });

  // An unhandled exception records no tool code, and that absence is itself diagnostic.
  const crashed = await runPlan(opts('c'));
  assert.equal(crashed.events.find(e => e.type === 'failed').data.toolCode, undefined);
  replayPlan({ ...opts('c'), journal: crashed });

  // Replay rejects a forged tool code that is not a bare identifier, so the field cannot become a
  // smuggling channel for text after the fact.
  const forged = clone(raised);
  forged.events.find(e => e.type === 'failed').data.toolCode = 'some free text';
  let previous = digest(forged.header);
  for (const e of forged.events) { e.previous = previous; e.hash = digest({ previous, seq: e.seq, type: e.type, data: e.data }); previous = e.hash; }
  forged.root = previous;
  assert.throws(() => replayPlan({ ...opts('r'), journal: forged }), e => e.code === 'REPLAY_TRANSITION');
});

test('experiment.compare detects the measurement faults this project kept making', () => {
  // Sixteen rounds produced one finding more reliable than any other: the instrument is usually
  // wrong before the system under test is. These faults are mechanically detectable, so they are
  // checked rather than hoped for. Each case below is a real fault from a real round.
  const compare = new Map(makeBuiltinTools().map(t => [t.name, t])).get('experiment.compare');

  // Round 007: five runs of an unvaried test treated as five data points, and a conclusion
  // published then withdrawn. The conditions vary nothing between them.
  const unvaried = compare.execute({ hypothesis: 'the model cannot emit nested references', conditions: [
    { name: 'try 1', varied: { form: 'mixed array' }, expected: 'emitted', actual: 'stringified' },
    { name: 'try 2', varied: { form: 'mixed array' }, expected: 'emitted', actual: 'stringified' },
  ] });
  assert.deepEqual(unvaried.refuted, ['try 1', 'try 2']);
  const codes = unvaried.warnings.map(w => w.code);
  assert.ok(codes.includes('UNVARIED_CONDITIONS'));
  assert.match(unvaried.warnings.find(w => w.code === 'UNVARIED_CONDITIONS').detail, /one data point rather than 2/);

  // Round 012: a test that reads identically whether or not the defect is present, because every
  // condition declares the same expectation.
  assert.equal(unvaried.discriminating, false);
  assert.ok(codes.includes('NONDISCRIMINATING_EXPECTATION'));

  // Rounds 008 and 012: a probe whose expectation was never written, scored as a result anyway.
  const missing = compare.execute({ hypothesis: 'receipts are reported faithfully', conditions: [
    { name: 'digest', varied: { kind: 'hash' }, expected: { ok: true }, actual: { ok: true } },
    { name: 'number', varied: { kind: 'number' }, actual: { ok: true, value: 7 } },
  ] });
  assert.deepEqual(missing.untestable, ['number']);
  assert.equal(missing.verdicts.find(v => v.name === 'number').why, 'no expectation was declared');
  assert.deepEqual(missing.confirmed, ['digest']);

  // Round 008 done properly: one factor varied per condition, distinct expectations, no warnings.
  const sound = compare.execute({ hypothesis: 'topology determines whether a plan computes correctly', conditions: [
    { name: 'chain', varied: { topology: 'chain' }, expected: 'ab', actual: 'ab' },
    { name: 'fan-in', varied: { topology: 'fan-in' }, expected: 'pq+rs', actual: 'pq+rs' },
    { name: 'diamond', varied: { topology: 'diamond' }, expected: 'mn-L,mn-R', actual: 'mn-L,mn-R' },
  ] });
  assert.deepEqual(sound.warnings, []);
  assert.equal(sound.discriminating, true);
  assert.deepEqual(sound.confirmed, ['chain', 'fan-in', 'diamond']);

  // A single condition cannot isolate a cause, and says so.
  assert.ok(compare.execute({ hypothesis: 'h', conditions: [{ name: 'only', varied: {}, expected: 1, actual: 1 }] })
    .warnings.some(w => w.code === 'SINGLE_CONDITION'));

  // No aggregate is emitted at all. "Nine of ten" is exactly how rounds 004 and 005 drew the wrong
  // conclusion from their own results, so the shape makes that reading unavailable.
  for (const key of ['rate', 'score', 'passRate', 'total', 'summary']) assert.ok(!(key in sound), key);
  assert.throws(() => compare.execute({ hypothesis: 'h', conditions: [
    { name: 'dup', varied: {}, expected: 1, actual: 1 }, { name: 'dup', varied: {}, expected: 2, actual: 2 }] }),
    e => e.code === 'INPUT_INVALID', 'condition names must be distinct to be addressable');
});

test('a failed read is not reported as a possibly-occurred effect', async () => {
  // Found by generating the composition matrix rather than by review: 26 of 629 generated
  // compositions reported EFFECT_INDETERMINATE for a read. A read requires no approval and a
  // failed read leaves nothing mutated, so "may have occurred, do not retry" was both wrong and
  // consequential — retrying an observation is always safe. Round 010 split pure from non-pure
  // and left read on the wrong side; grantedEffects already names the effects that can change
  // the world, so that is the line the classification should follow.
  const temp = tempDir('concord-readfail-');
  const tools = new Map(makeBuiltinTools().map(t => [t.name, t]));
  const opts = {
    plan: { version: 1, tasks: [{ id: 'r', tool: 'files.read', input: { path: 'nonexistent.txt' } }] },
    registry: tools, sourceLock: { version: 1 }, workspaceRoot: temp,
    policy: { version: 1, allowedTools: [...tools.keys()], allowedEffects: ['pure', 'read'], maxOutputBytes: 100000, maxJournalBytes: 1000000 },
  };
  const journal = await runPlan(opts);
  assert.equal(tools.get('files.read').effect, 'read');
  assert.equal(journal.outcome.code, 'TOOL_FAILED', 'a read that fails changed nothing');
  replayPlan({ ...opts, journal });

  // A write that throws stays indeterminate, because it genuinely may have landed before throwing.
  const throwing = { name: 'w', version: '1', effect: 'write', inputSchema: true, execute() { throw new Error('midway'); } };
  const writeOpts = { plan: { version: 1, tasks: [{ id: 'w', tool: 'w', input: null }] },
    registry: new Map([['w', throwing]]), sourceLock: { version: 1 }, workspaceRoot: temp,
    policy: { version: 1, allowedTools: ['w'], allowedEffects: ['write'], maxOutputBytes: 100000, maxJournalBytes: 1000000 } };
  const blocked = await runPlan(writeOpts);
  const wrote = await runPlan({ ...writeOpts, approvals: [blocked.outcome.requestHash] });
  assert.equal(wrote.outcome.code, 'EFFECT_INDETERMINATE');
  replayPlan({ ...writeOpts, approvals: [blocked.outcome.requestHash], journal: wrote });

  // A journal recorded before this narrowing still verifies, so the change does not invalidate
  // recorded history — the same compatibility stance round 010 took for its own narrowing.
  const legacy = clone(journal);
  legacy.events.find(e => e.type === 'failed').data.code = 'EFFECT_INDETERMINATE';
  // The settled event carries its own copy of the outcome, so a legacy journal has to be
  // consistent in both places; mutating only the envelope leaves an illegal transition.
  legacy.events.find(e => e.type === 'settled').data.code = 'EFFECT_INDETERMINATE';
  legacy.outcome.code = 'EFFECT_INDETERMINATE';
  let previous = digest(legacy.header);
  for (const e of legacy.events) { e.previous = previous; e.hash = digest({ previous, seq: e.seq, type: e.type, data: e.data }); previous = e.hash; }
  legacy.root = previous;
  assert.equal(replayPlan({ ...opts, journal: legacy }).replayed, true, 'older read journals still verify');
  rmSync(temp, { recursive: true, force: true });
});

test('a reference written in invented shorthand is refused, and prose mentioning one is not', async () => {
  // Round 020 measured a new mis-serialisation: asked to join a literal with a file's text, the
  // model emitted the string "$task:read/text" — its own shorthand, not JSON. The kernel accepted
  // it as an ordinary string, concatenated it literally and produced "body=$task:read/text", a
  // wrong answer with a faithful receipt. Round 005's check could not see it because it only
  // matches a JSON object inside a string. The signature is a value that BEGINS with $task, which
  // leaves prose that merely mentions the form alone.
  const reg = new Map(makeBuiltinTools().map(t => [t.name, t]));
  const opts = (plan) => ({ plan, registry: reg, sourceLock: { version: 1 }, workspaceRoot: path.resolve('/explicit/workspace'),
    policy: { version: 1, allowedTools: [...reg.keys()], allowedEffects: ['pure', 'read'], maxOutputBytes: 10000, maxJournalBytes: 100000 } });

  for (const form of ['$task:read/text', '$task.read', '$task read /text', '$task']) {
    const plan = { version: 1, tasks: [
      { id: 'read', tool: 'json.value', input: 1 },
      { id: 'j', tool: 'text.concat', input: { values: ['body=', form], separator: '' }, dependsOn: ['read'] }] };
    await assert.rejects(runPlan(opts(plan)), e => e.code === 'INVALID_REFERENCE' && /shorthand text/.test(e.message), form);
  }

  // Prose that mentions a reference must still pass: the check is anchored, not a substring search.
  for (const benign of ['use {"$task":"x"} here', 'the $task field', 'cost is $task-free', 'plain text']) {
    const j = await runPlan(opts({ version: 1, tasks: [{ id: 'a', tool: 'json.value', input: { v: benign } }] }));
    assert.equal(j.outcome.status, 'completed', benign);
  }

  // The genuine object form is still the way to do it, and still computes correctly.
  const good = { version: 1, tasks: [
    { id: 'read', tool: 'json.value', input: { text: 'contents' } },
    { id: 'j', tool: 'text.concat', input: { values: ['body=', { $task: 'read', path: '/text' }], separator: '' }, dependsOn: ['read'] }] };
  const journal = await runPlan(opts(good));
  assert.equal(journal.results.j.value, 'body=contents');
  replayPlan({ ...opts(good), journal });
});

test('policy attenuation only ever narrows authority, and the narrowed set is what the engine enforces', async () => {
  // hermes restricts untrusted webhook input to a no-execution subset of its toolset. What makes
  // that safe to apply without review is that attenuation cannot grant anything, so the check
  // below is that widening is refused in every dimension, not merely that narrowing works.
  const narrowed = attenuatePolicy(policy, { allowedTools: ['json.value', 'text.concat'], allowedEffects: ['pure'], maxOutputBytes: 500 });
  assert.deepEqual(narrowed.allowedTools, ['json.value', 'text.concat']);
  assert.deepEqual(narrowed.allowedEffects, ['pure']);
  assert.equal(narrowed.maxOutputBytes, 500);
  for (const name of narrowed.allowedTools) assert.ok(policy.allowedTools.includes(name));
  for (const effect of narrowed.allowedEffects) assert.ok(policy.allowedEffects.includes(effect));

  for (const widening of [{ allowedTools: ['tool.not.in.the.base.policy'] }, { allowedEffects: ['network'] },
    { maxOutputBytes: policy.maxOutputBytes + 1 }, { maxJournalBytes: policy.maxJournalBytes + 1 }, { timeoutMs: 300000 }]) {
    assert.throws(() => attenuatePolicy(policy, widening), e => e.code === 'POLICY_NOT_ATTENUATED', JSON.stringify(widening));
  }

  // Enforced rather than merely reported: a read the base policy permits is denied once attenuated away.
  const read = { version: 1, tasks: [{ id: 'a', tool: 'files.read', input: { path: 'x.txt' } }] };
  await assert.rejects(runPlan(base(read, { policy: narrowed })), e => e.code === 'POLICY_DENIED');
  const allowed = await runPlan(base(one, { policy: narrowed }));
  assert.equal(allowed.outcome.status, 'completed');

  // Attenuating nothing is the identity, so an unrestricted turn is not quietly altered.
  assert.deepEqual(attenuatePolicy(policy, {}), attenuatePolicy(policy));
});
