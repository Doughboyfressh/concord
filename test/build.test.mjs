import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { makeBuildTools, internals } from '../src/build.mjs';
import { canonical, HarnessError } from '../src/value.mjs';
import { realTempDir } from './temp-workspace.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const code = (expected) => (error) => error instanceof HarnessError && error.code === expected;

const NODE = process.execPath;
// Digested once: node.exe is around a hundred megabytes and every reviewed target needs its hash.
const NODE_SHA256 = sha256(fs.readFileSync(NODE));

const BUILDS = 'import fs from "node:fs";\nfs.writeFileSync("out.txt", "built");\nconsole.log("ok");\n';
const ASSERTS = 'import assert from "node:assert";\nassert.equal(1, 2);\n';

function workspace(files) {
  const root = realTempDir('concord-build-');
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
  }
  return root;
}
const target = (over = {}) => ({
  name: 'main', system: 'npm', executable: NODE, executableSha256: NODE_SHA256,
  args: ['src/main.mjs'], diagnostics: 'node-uncaught-v1', inputs: ['src'], artifacts: ['out.txt'], ...over,
});
const toolsFor = (over = {}) => makeBuildTools({ timeoutMs: 20_000, maxOutputBytes: 262_144, ...over });
const policy = {
  version: 1, allowedTools: ['build.detect', 'build.run', 'build.compare'],
  allowedEffects: ['pure', 'read', 'process'], timeoutMs: 20_000, maxOutputBytes: 262_144,
};

test('makeBuildTools(undefined) registers nothing, and build.run appears only once a target is reviewed', () => {
  assert.deepEqual(makeBuildTools(undefined), []);
  assert.deepEqual(makeBuildTools({}).map((tool) => `${tool.name}:${tool.effect}`), ['build.detect:read', 'build.compare:pure']);
  assert.deepEqual(toolsFor({ targets: [target()] }).map((tool) => `${tool.name}:${tool.effect}`),
    ['build.detect:read', 'build.run:process', 'build.compare:pure']);
});

test('configuration refusals are BUILD_CONFIG, one per malformed field', () => {
  const refused = [
    { unexpected: true },
    { detectName: 'build detect' },
    { detectName: 'same', runName: 'same' },
    { targets: [] },
    { targets: [target({ executable: 'node' })] },
    { targets: [target({ executableSha256: undefined })] },
    { targets: [target({ executableSha256: 'not-a-digest' })] },
    { targets: [target({ diagnostics: 'invented-matcher' })] },
    { targets: [target({ args: Array.from({ length: 65 }, () => 'x') })] },
    { targets: [target({ args: ['ok', 42] })] },
    { targets: [target({ cwd: '/absolute' })] },
    { targets: [target({ cwd: '../outside' })] },
    { targets: [target({ inputs: ['../escape'] })] },
    { targets: [target({ artifacts: ['c:/absolute'] })] },
    { targets: [target({ inputs: Array.from({ length: 65 }, (unused, index) => `src/${index}`) })] },
    { targets: [target({ unexpected: 1 })] },
    { targets: [target(), target()] },
    { targets: Array.from({ length: 33 }, (unused, index) => target({ name: `t${index}` })) },
  ];
  // JSON.stringify rather than canonical() for the message: one of these configs sets a field to
  // undefined on purpose, which canonical() refuses outright as outside the JSON domain.
  for (const config of refused) assert.throws(() => makeBuildTools(config), code('BUILD_CONFIG'), JSON.stringify(config).slice(0, 120));
});

test('the run input schema offers a reviewed target name and nothing that could supply argv', () => {
  const [, run] = toolsFor({ targets: [target(), target({ name: 'other' })] });
  assert.deepEqual(run.inputSchema, {
    type: 'object', required: ['target'], additionalProperties: false,
    properties: { target: { enum: ['main', 'other'] }, expectArtifactsSha256: { type: 'string', minLength: 64, maxLength: 64 } },
  });
});

// ---- detect: what is here, and separately what may be run ----------------------------------

test('detect reports each marker with its digest and the entries it actually read out of the file', () => {
  const root = workspace({
    'package.json': JSON.stringify({ name: 'x', scripts: { build: 'node .', test: 'node --test' } }),
    Makefile: 'all: dist\n\ndist:\n\techo hi\n\nclean:\n\trm -rf dist\n',
    'Cargo.toml': '[package]\nname = "x"\n',
  });
  const [detect] = toolsFor({ targets: [target({ system: 'npm' })] });
  const result = detect.execute({}, { policy, workspaceRoot: root });
  assert.equal(result.detector, 'markers-v1');
  assert.equal(result.count, 3);
  assert.equal(result.multiple, true, 'three build systems in one tree is the ambiguity, and it is reported rather than resolved');
  const byName = new Map(result.systems.map((entry) => [entry.system, entry]));
  assert.deepEqual(byName.get('npm').entries, ['build', 'test']);
  assert.equal(byName.get('npm').entriesRead, true);
  assert.equal(byName.get('npm').markerSha256, sha256(fs.readFileSync(path.join(root, 'package.json'))));
  assert.deepEqual(byName.get('make').entries, ['all', 'clean', 'dist']);
  assert.deepEqual(byName.get('cargo').entries, [], 'a Cargo.toml does not list its build targets, so none are invented');
  assert.equal(byName.get('cargo').entriesRead, false);
  // Detected and runnable are different facts: only npm has a reviewed target behind it.
  assert.deepEqual(result.runnable, ['npm']);
  assert.deepEqual(byName.get('npm').targets, ['main']);
  assert.deepEqual(byName.get('make').targets, []);
  for (const key of detect.outputKeys) assert.notEqual(result[key], undefined, `missing ${key}`);
});

test('a marker that cannot be parsed is still reported as present, with entriesRead false', () => {
  const root = workspace({ 'package.json': '{ this is not json' });
  const [detect] = toolsFor();
  const result = detect.execute({}, { policy, workspaceRoot: root });
  assert.equal(result.count, 1);
  assert.equal(result.systems[0].system, 'npm');
  assert.equal(result.systems[0].entriesRead, false);
  assert.deepEqual(result.systems[0].entries, []);
});

test('detect finds nothing in an empty tree, looks inside a named subdirectory, and refuses an escaping one', () => {
  const root = workspace({ 'app/package.json': JSON.stringify({ scripts: { dev: 'node .' } }), 'keep.txt': 'x' });
  const [detect] = toolsFor();
  const empty = detect.execute({}, { policy, workspaceRoot: root });
  assert.equal(empty.count, 0);
  assert.equal(empty.multiple, false);
  const nested = detect.execute({ directory: 'app' }, { policy, workspaceRoot: root });
  assert.equal(nested.directory, 'app');
  assert.equal(nested.systems[0].marker, 'app/package.json');
  assert.deepEqual(nested.systems[0].entries, ['dev']);
  for (const directory of ['..', '../elsewhere', '/etc', 'app\\win']) {
    assert.throws(() => detect.execute({ directory }, { policy, workspaceRoot: root }), code('BUILD_CONFIG'), directory);
  }
});

test('detect is a read and build.compare is pure, so neither can be refused for lacking a process grant', () => {
  const root = workspace({ 'package.json': '{}' });
  const [detect, compare] = toolsFor();
  const readOnly = { ...policy, allowedEffects: ['pure', 'read'] };
  assert.doesNotThrow(() => detect.execute({}, { policy: readOnly, workspaceRoot: root }));
  assert.throws(() => detect.execute({}, { policy: { ...policy, allowedEffects: ['pure'] }, workspaceRoot: root }), code('BUILD_POLICY'));
  assert.throws(() => detect.execute({}, { policy: { ...policy, allowedTools: ['other'] }, workspaceRoot: root }), code('BUILD_POLICY'));
  assert.equal(typeof compare.execute({
    left: { inputsSha256: 'a'.repeat(64), artifactsSha256: 'b'.repeat(64), exitCode: 0 },
    right: { inputsSha256: 'a'.repeat(64), artifactsSha256: 'b'.repeat(64), exitCode: 0 },
  }).verdict, 'string');
});

// ---- run: the receipt ----------------------------------------------------------------------

test('a build that succeeds attests which input bytes produced which output bytes', async () => {
  const root = workspace({ 'src/main.mjs': BUILDS });
  const [, run] = toolsFor({ targets: [target()] });
  const result = await run.execute({ target: 'main' }, { policy, workspaceRoot: root });
  assert.equal(result.ok, true);
  assert.equal(result.exitCode, 0);
  assert.deepEqual(result.argv, [path.basename(NODE), 'src/main.mjs']);
  assert.equal(result.argv.includes(NODE), false, 'the configured executable path is never echoed back');
  assert.deepEqual(result.inputs, [{ path: 'src/main.mjs', sha256: sha256(Buffer.from(BUILDS)), bytes: Buffer.byteLength(BUILDS) }]);
  assert.deepEqual(result.artifacts, [{ path: 'out.txt', sha256: sha256(Buffer.from('built')), bytes: 5 }]);
  assert.equal(result.stdoutTail.trim(), 'ok');
  assert.equal(result.stdoutSha256, sha256(fs.readFileSync(path.join(root, 'src/main.mjs'), 'utf8').length ? result.stdoutTail : ''), 'the digest covers the whole stream the tail was taken from');
  assert.deepEqual(result.diagnostics, []);
  assert.deepEqual(result.diagnosticCounts, {});
  assert.equal(result.reproduced, null, 'nothing was claimed, so nothing is reported as reproduced');
  assert.equal(result.matcher, 'node-uncaught-v1');
  for (const key of run.outputKeys) assert.notEqual(result[key], undefined, `missing ${key}`);
  assert.doesNotThrow(() => canonical(result));
});

test('the same inputs through the same toolchain produce the same receipt, and a changed input changes it', async () => {
  const root = workspace({ 'src/main.mjs': BUILDS });
  const [, run, compare] = toolsFor({ targets: [target()] });
  const context = { policy, workspaceRoot: root };
  const first = await run.execute({ target: 'main' }, context);
  const second = await run.execute({ target: 'main', expectArtifactsSha256: first.artifactsSha256 }, context);
  assert.equal(second.reproduced, true);
  assert.equal(second.receipt, first.receipt);
  assert.equal(compare.execute({ left: first, right: second }).verdict, 'identical');

  // An edit that cannot reach the output: the input digest moves, the artifact bytes do not.
  fs.appendFileSync(path.join(root, 'src/main.mjs'), '// a comment\n');
  const third = await run.execute({ target: 'main', expectArtifactsSha256: first.artifactsSha256 }, context);
  assert.notEqual(third.inputsSha256, first.inputsSha256);
  assert.equal(third.artifactsSha256, first.artifactsSha256);
  assert.equal(third.reproduced, true);
  assert.notEqual(third.receipt, first.receipt, 'the receipt binds the inputs, so it moves even when the output does not');
  assert.equal(compare.execute({ left: first, right: third }).verdict, 'inputs-changed-output-did-not');

  // And an edit that does reach it.
  fs.writeFileSync(path.join(root, 'src/main.mjs'), BUILDS.replace('"built"', '"rebuilt"'));
  const fourth = await run.execute({ target: 'main', expectArtifactsSha256: first.artifactsSha256 }, context);
  assert.equal(fourth.reproduced, false, 'a rebuild that was asked to match and did not is a value, not a refusal');
  assert.equal(fourth.ok, true, 'and the build itself still succeeded, which is the point of not throwing');
  assert.equal(compare.execute({ left: first, right: fourth }).verdict, 'changed');
});

test('a declared artifact that was never produced does not hash the same as declaring no artifacts', async () => {
  const root = workspace({ 'src/main.mjs': 'console.log("no artifact");\n' });
  const [, run] = toolsFor({ targets: [target(), target({ name: 'nodeclare', artifacts: [] })] });
  const context = { policy, workspaceRoot: root };
  const declared = await run.execute({ target: 'main' }, context);
  const undeclared = await run.execute({ target: 'nodeclare' }, context);
  assert.deepEqual(declared.artifacts, []);
  assert.deepEqual(undeclared.artifacts, []);
  assert.notEqual(declared.artifactsSha256, undeclared.artifactsSha256,
    'both found no files, but one was asked for an artifact and did not produce it');
});

test('a failing build returns its diagnostics bound to the bytes of the file it blames', async () => {
  const root = workspace({ 'src/main.mjs': ASSERTS });
  const [, run] = toolsFor({ targets: [target()] });
  const result = await run.execute({ target: 'main' }, { policy, workspaceRoot: root });
  assert.equal(result.ok, false);
  assert.equal(result.exitCode, 1);
  assert.deepEqual(result.diagnosticCounts, { error: 1 });
  const [diagnostic] = result.diagnostics;
  assert.equal(diagnostic.code, 'ERR_ASSERTION');
  assert.equal(diagnostic.message, '1 == 2');
  assert.equal(diagnostic.severity, 'error');
  assert.equal(diagnostic.workspacePath, 'src/main.mjs');
  assert.equal(diagnostic.line, 2);
  assert.equal(diagnostic.fileSha256, sha256(Buffer.from(ASSERTS)));
  assert.equal(diagnostic.fileSha256, result.inputs[0].sha256, 'the diagnostic and the input set agree about the bytes');
  for (const key of run.outputKeys) assert.notEqual(result[key], undefined, `missing ${key}`);
});

test('an unknown target, a malformed expected digest, a missing binary and a cancelled call each fail closed', async () => {
  const root = workspace({ 'src/main.mjs': BUILDS });
  const [, run] = toolsFor({ targets: [target()] });
  const context = { policy, workspaceRoot: root };
  await assert.rejects(run.execute({ target: 'absent' }, context), (error) => error instanceof HarnessError);
  await assert.rejects(run.execute({ target: 'main', expectArtifactsSha256: 'Z'.repeat(64) }, context), code('BUILD_INPUT'));
  await assert.rejects(run.execute({ target: 'main' }, { ...context, policy: { ...policy, allowedEffects: ['read'] } }), code('BUILD_POLICY'));
  await assert.rejects(run.execute({ target: 'main' }, { ...context, signal: AbortSignal.abort() }), code('BUILD_ABORTED'));
  const moved = toolsFor({ targets: [target({ executable: path.join(root, 'no-such-toolchain.exe') })] })[1];
  await assert.rejects(moved.execute({ target: 'main' }, context), code('INTEGRATION_PATH'));
  const wrongDigest = toolsFor({ targets: [target({ executableSha256: 'a'.repeat(64) })] })[1];
  await assert.rejects(wrongDigest.execute({ target: 'main' }, context), code('INTEGRATION_EXECUTABLE'));
});

test('a build that outruns its deadline is a refusal, not a silent partial receipt', async () => {
  const root = workspace({ 'src/main.mjs': 'setTimeout(() => {}, 10_000);\n' });
  const [, run] = toolsFor({ targets: [target({ timeoutMs: 600 })] });
  await assert.rejects(run.execute({ target: 'main' }, { policy, workspaceRoot: root }), code('BUILD_TIMEOUT'));
});

test('a symlink inside a declared input set is skipped and counted rather than silently digested', async (t) => {
  const root = workspace({ 'src/main.mjs': BUILDS, 'elsewhere.txt': 'outside the input set' });
  try { fs.symlinkSync(path.join(root, 'elsewhere.txt'), path.join(root, 'src', 'link.txt')); }
  catch { t.skip('this platform or account cannot create a symlink'); return; }
  const [, run] = toolsFor({ targets: [target()] });
  const result = await run.execute({ target: 'main' }, { policy, workspaceRoot: root });
  assert.equal(result.inputsSkipped, 1);
  assert.deepEqual(result.inputs.map((entry) => entry.path), ['src/main.mjs']);
});

// ---- the matchers, against measured output --------------------------------------------------

test('each diagnostic matcher reads the output its toolchain really prints, with CRLF or without', () => {
  const parse = (name, output) => internals.MATCHERS[name].parse(output.replace(/\r\n?/g, '\n'));
  assert.deepEqual(parse('gcc-v1', 'main.c:4:12: error: expected \u2018;\u2019 before \u2018}\u2019\r\nmain.c:9:1: warning: unused variable\r\n'), [
    { file: 'main.c', line: 4, column: 12, severity: 'error', message: 'expected \u2018;\u2019 before \u2018}\u2019', code: null },
    { file: 'main.c', line: 9, column: 1, severity: 'warning', message: 'unused variable', code: null },
  ]);
  assert.deepEqual(parse('tsc-v1', "src/a.ts(12,5): error TS2322: Type 'string' is not assignable to type 'number'.\n"), [
    { file: 'src/a.ts', line: 12, column: 5, severity: 'error', code: 'TS2322', message: "Type 'string' is not assignable to type 'number'." },
  ]);
  assert.deepEqual(parse('msvc-v1', 'c:\\src\\a.cpp(41): error C2065: undeclared identifier\n'), [
    { file: 'c:\\src\\a.cpp', line: 41, column: null, severity: 'error', code: 'C2065', message: 'undeclared identifier' },
  ]);
  assert.deepEqual(parse('rustc-v1', 'error[E0425]: cannot find value `x` in this scope\r\n  --> src/main.rs:3:13\r\n'), [
    { file: 'src/main.rs', line: 3, column: 13, severity: 'error', code: 'E0425', message: 'cannot find value `x` in this scope' },
  ]);
  assert.deepEqual(parse('none', 'error: anything at all\n'), [], 'the none matcher claims nothing, which is its contract');
});

test("node's header line names a location inside node, so the matcher takes the first frame an operator wrote", () => {
  // Measured output, not invented: an uncaught assertion really does head its stack with a
  // node-internal path, and a matcher trusting that line blames node for every failing test.
  const assertion = [
    'node:internal/modules/run_main:107',
    '    triggerUncaughtException(',
    '    ^',
    '',
    'AssertionError [ERR_ASSERTION]: 1 == 2',
    '    at file:///C:/work/src/main.mjs:2:8',
    '    at ModuleJob.run (node:internal/modules/esm/module_job:561:25)',
  ].join('\n');
  const [found] = internals.MATCHERS['node-uncaught-v1'].parse(assertion);
  assert.equal(found.file, 'file:///C:/work/src/main.mjs');
  assert.equal(found.line, 2);
  assert.equal(found.column, 8);
  assert.equal(found.code, 'ERR_ASSERTION');

  // A syntax error has no stack frame in the operator's file at all; the header is the location.
  const syntax = ['file:///C:/work/src/main.mjs:1', 'const x = ;', '          ^', '', "SyntaxError: Unexpected token ';'", '    at compileSourceTextModule (node:internal/modules/esm/utils:319:16)'].join('\n');
  const [parsed] = internals.MATCHERS['node-uncaught-v1'].parse(syntax);
  assert.equal(parsed.file, 'file:///C:/work/src/main.mjs');
  assert.equal(parsed.line, 1);
  assert.equal(parsed.column, null);
  assert.equal(parsed.code, 'SyntaxError');

  // And when every frame and the header are inside node, there is no location to report.
  const internal = ['node:internal/modules/run_main:107', '', 'Error: nothing of ours', '    at run (node:internal/modules/esm/loader:647:26)'].join('\n');
  const [none] = internals.MATCHERS['node-uncaught-v1'].parse(internal);
  assert.equal(none.file, null, 'a location inside node is worse than no location: it points at the wrong code');
  assert.equal(none.line, null);
  assert.equal(none.message, 'nothing of ours');
  assert.deepEqual(internals.MATCHERS['node-uncaught-v1'].parse('just some ordinary build chatter\n'), []);
});

// ---- compare: two independent axes ----------------------------------------------------------

test('compare separates "the inputs changed" from "the output bytes changed", and reports the exit transition apart from both', () => {
  const [, , compare] = toolsFor({ targets: [target()] });
  const a = 'a'.repeat(64);
  const b = 'b'.repeat(64);
  const receipt = (inputs, artifacts, exitCode) => ({ inputsSha256: inputs, artifactsSha256: artifacts, exitCode });
  const verdict = (left, right) => compare.execute({ left, right }).verdict;
  assert.equal(verdict(receipt(a, b, 0), receipt(a, b, 0)), 'identical');
  assert.equal(verdict(receipt(a, b, 0), receipt(b, a, 0)), 'changed');
  assert.equal(verdict(receipt(a, b, 0), receipt(b, b, 0)), 'inputs-changed-output-did-not');
  assert.equal(verdict(receipt(a, b, 0), receipt(a, a, 0)), 'nondeterministic-build');

  const transition = (left, right) => compare.execute({ left, right }).transition;
  assert.equal(transition(receipt(a, b, 0), receipt(a, b, 0)), 'still-succeeding');
  assert.equal(transition(receipt(a, b, 1), receipt(a, b, 1)), 'still-failing');
  assert.equal(transition(receipt(a, b, 0), receipt(a, b, 1)), 'broken');
  assert.equal(transition(receipt(a, b, 1), receipt(a, b, 0)), 'fixed');

  const full = compare.execute({ left: { ...receipt(a, b, 0), receipt: a }, right: { ...receipt(a, a, 1), receipt: b } });
  assert.equal(full.sameReceipt, false);
  assert.equal(full.verdict, 'nondeterministic-build');
  assert.equal(full.transition, 'broken');
  assert.match(full.interpretation, /not reproducible/);
  assert.equal(compare.execute({ left: receipt(a, b, 0), right: receipt(a, b, 0) }).sameReceipt, null, 'receipts that were not supplied cannot be compared');
  for (const key of compare.outputKeys) assert.notEqual(full[key], undefined, `missing ${key}`);
  assert.throws(() => compare.execute({ left: receipt(a, b, 0) }), (error) => error instanceof HarnessError);
  assert.throws(() => compare.execute({ left: receipt('short', b, 0), right: receipt(a, b, 0) }), (error) => error instanceof HarnessError);
});
