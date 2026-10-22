import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { makeBuildTools, internals } from '../src/build.mjs';

/**
 * The building half of the write side: what a tree contains, what one reviewed target produces,
 * and what two receipts of the same target mean when they differ.
 *
 * Direct calls rather than plans, like the web and process families, because these tools exist
 * only where an operator configured a toolchain. The toolchain here is node itself — already on
 * this machine as process.execPath, already digestible, and perfectly capable of being a
 * compiler that succeeds, fails, writes an artifact or hangs past its deadline. Nothing had to be
 * installed to exercise any of this.
 *
 * Fixtures live under one directory of their own inside the round's shared scratch workspace. The
 * whole round shares that workspace, so a target declaring `inputs: ['src']` would digest
 * whatever every other family happened to leave in src/, and the receipt exercises would compare
 * against a moving tree. Nothing here asserts an absolute digest for that reason: every claim is
 * a relation between two runs, or between a digest and bytes this file wrote itself.
 */

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const NODE = process.execPath;
// Digested once per round: the executable is around a hundred megabytes and every target needs it.
let nodeDigest = null;
export const digestOfNode = () => (nodeDigest ??= sha256(fs.readFileSync(NODE)));

const ROOT = 'build-fixture';
const BUILDS = 'import fs from "node:fs";\nfs.writeFileSync("build-fixture/out.txt", "built");\nconsole.log("build ok");\n';
const FAILS = 'import assert from "node:assert";\nassert.equal(1, 2);\n';
const SLEEPS = 'setTimeout(() => {}, 5000);\n';
const PACKAGE = JSON.stringify({ name: 'fixture', scripts: { build: 'node .', test: 'node --test' } }, null, 2);
const MAKEFILE = 'all: dist\n\ndist:\n\techo building\n\nclean:\n\trm -rf dist\n';

/**
 * Write the fixture tree. Called by the runner before the exercise that declares it, and by the
 * round itself for the composed plans, which need the same tree in the same scratch workspace.
 */
export function fixture(dir) {
  fs.mkdirSync(path.join(dir, ROOT, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, ROOT, 'src', 'builds.mjs'), BUILDS);
  fs.writeFileSync(path.join(dir, ROOT, 'src', 'fails.mjs'), FAILS);
  fs.writeFileSync(path.join(dir, ROOT, 'package.json'), PACKAGE);
  fs.writeFileSync(path.join(dir, ROOT, 'Makefile'), MAKEFILE);
}
function slowFixture(dir) {
  fixture(dir);
  fs.writeFileSync(path.join(dir, ROOT, 'src', 'sleeps.mjs'), SLEEPS);
}

const policyFor = (over = {}) => ({
  version: 1, allowedTools: ['build.detect', 'build.run', 'build.compare'],
  allowedEffects: ['pure', 'read', 'write', 'network', 'process'],
  allowedOrigins: [], maxTasks: 32, maxOutputBytes: 262_144, maxJournalBytes: 16_777_216, timeoutMs: 20_000, ...over,
});

export const targetFor = (over = {}) => ({
  name: 'main', system: 'npm', executable: NODE, executableSha256: digestOfNode(),
  args: [`${ROOT}/src/builds.mjs`], diagnostics: 'node-uncaught-v1',
  inputs: [`${ROOT}/src`], artifacts: [`${ROOT}/out.txt`], ...over,
});
const toolsFor = (config = {}) => makeBuildTools({ timeoutMs: 20_000, maxOutputBytes: 262_144, ...config });

/**
 * The reviewed targets the round registers, so these tools can be driven by a plan.
 *
 * Four rather than one, because the interesting states of a build are different *targets* and not
 * different inputs: a target that succeeds and writes its artifact, one that fails and prints a
 * diagnostic, one that outruns its deadline, and one that declares an artifact it never produces.
 * A plan selects among reviewed names and can never describe a command, so each state a round
 * wants to reach has to exist as something an operator approved — which is the invariant, not a
 * limitation of the fixture.
 */
export const trainingTargets = () => [
  targetFor(),
  targetFor({ name: 'fails', args: [`${ROOT}/src/fails.mjs`] }),
  targetFor({ name: 'slow', args: [`${ROOT}/src/sleeps.mjs`], timeoutMs: 700 }),
  targetFor({ name: 'noartifact', args: [`${ROOT}/src/builds.mjs`], artifacts: [`${ROOT}/never-written.txt`] }),
];
const runnerFor = (targets, over = {}) => toolsFor({ targets, ...over }).find((tool) => tool.name === 'build.run');

export function buildExercises() {
  return [
    // ---- what exists, and what may be run --------------------------------------------
    {
      family: 'build', tool: 'build.factory',
      call: () => ({
        unconfigured: makeBuildTools(undefined).length,
        noTargets: makeBuildTools({}).map((tool) => `${tool.name}:${tool.effect}`),
        withTarget: toolsFor({ targets: [targetFor()] }).map((tool) => `${tool.name}:${tool.effect}`),
      }),
      expect: (r) => r.unconfigured === 0
        && r.noTargets.join(' ') === 'build.detect:read build.compare:pure'
        && r.withTarget.join(' ') === 'build.detect:read build.run:process build.compare:pure',
      lesson: 'An absent build configuration registers nothing, and a configuration with no reviewed targets still registers build.detect and build.compare but not build.run. Those two need no executable — detecting a build system is a read and comparing two receipts is pure — so they remain useful on a machine that is not permitted to build anything, while a build.run that could only ever refuse would be a capability in name only. The three effects are deliberately different: only the one that starts a process costs an approval.',
    },
    {
      family: 'build', tool: 'build.run',
      call: () => ({ schema: runnerFor([targetFor(), targetFor({ name: 'other' })]).inputSchema }),
      expect: (r) => Array.isArray(r.schema.properties.target.enum)
        && r.schema.properties.target.enum.join(',') === 'main,other'
        && r.schema.additionalProperties === false
        && Object.keys(r.schema.properties).join(',') === 'target,expectArtifactsSha256',
      lesson: 'build.run\'s input offers a choice among the reviewed target names and nothing else: the enum is generated from the configuration, so a plan selects a build that was reviewed rather than describing one. There is no executable, args, cwd or env field anywhere in the schema, which keeps the invariant process.run already holds — argv comes only from reviewed configuration, never from a plan or a model.',
    },

    // ---- configuration refusals ------------------------------------------------------
    {
      family: 'build', tool: 'build.factory', expectThrow: 'BUILD_CONFIG',
      call: () => toolsFor({ targets: [targetFor({ executableSha256: undefined })] }),
      lesson: 'A build target without an exact executable digest is refused BUILD_CONFIG at registration. The digest is what makes the receipt mean anything: without it the receipt would attest that some compiler at that path produced those bytes, which is a claim about a filename rather than about a program.',
    },
    {
      family: 'build', tool: 'build.factory', expectThrow: 'BUILD_CONFIG',
      call: () => toolsFor({ targets: [targetFor({ diagnostics: 'invented-matcher' })] }),
      lesson: 'A diagnostics matcher that is not one of the reviewed set is refused BUILD_CONFIG, and the refusal names the ones that exist. Matchers are code, not configuration: a caller cannot supply a pattern, because a pattern supplied per call could claim any file:line it liked and the diagnostic would still be reported as the compiler\'s.',
    },
    {
      family: 'build', tool: 'build.factory', expectThrow: 'BUILD_CONFIG',
      call: () => toolsFor({ targets: [targetFor({ inputs: ['../outside'] })] }),
      lesson: 'A declared input or artifact path that escapes the workspace is refused BUILD_CONFIG at registration, and so is an absolute one. The input set is what the receipt attests over, so a path reaching outside the workspace would put bytes nobody can review inside a digest that claims to describe the build.',
    },

    // ---- detect: present is not the same as runnable -----------------------------------
    {
      family: 'build', tool: 'build.detect', workspace: 'temp', fixture,
      call: ({ workspaceRoot }) => {
        const [detect] = toolsFor({ targets: [targetFor()] });
        const result = detect.execute({ directory: ROOT }, { policy: policyFor(), workspaceRoot });
        return {
          detector: result.detector, count: result.count, multiple: result.multiple, runnable: result.runnable,
          systems: result.systems.map((entry) => [entry.system, entry.entries.join('|'), entry.entriesRead, entry.targets.join('|')]),
          packageDigest: result.systems.find((entry) => entry.system === 'npm').markerSha256,
          everyDeclaredKeyPresent: detect.outputKeys.every((key) => result[key] !== undefined),
        };
      },
      expect: (r) => r.detector === 'markers-v1' && r.count === 2 && r.multiple === true
        && r.systems[0][0] === 'npm' && r.systems[0][1] === 'build|test' && r.systems[0][2] === true && r.systems[0][3] === 'main'
        && r.systems[1][0] === 'make' && r.systems[1][1] === 'all|clean|dist' && r.systems[1][3] === ''
        && r.runnable.join(',') === 'npm'
        && r.packageDigest === sha256(Buffer.from(PACKAGE))
        && r.everyDeclaredKeyPresent,
      lesson: 'build.detect reports each build system it found with the marker file, that file\'s digest, and the script or target names it actually read out of it — package.json\'s scripts and a Makefile\'s targets are read, while a Cargo.toml reports none because it does not list its own, and entriesRead distinguishes "read nothing" from "nothing to read". Two facts are kept apart: what the tree contains, and which of those systems has a reviewed target behind it, reported separately as runnable. Several build systems in one tree is the normal case and the usual source of a confident wrong guess, so multiple:true reports the ambiguity rather than resolving it.',
    },
    {
      family: 'build', tool: 'build.detect', workspace: 'temp', fixture,
      call: ({ workspaceRoot }) => {
        const [detect] = toolsFor();
        const result = detect.execute({}, { policy: policyFor(), workspaceRoot });
        return { count: result.count, multiple: result.multiple, runnable: result.runnable.length, directory: result.directory };
      },
      expect: (r) => r.count === 0 && r.multiple === false && r.runnable === 0 && r.directory === null,
      lesson: 'A directory with no marker reports count:0 rather than guessing a build system from file extensions. The fixture tree one level down is invisible from the root, because detection looks for markers exactly where it was asked rather than searching: a search would find a build system belonging to a vendored dependency and report it as this project\'s.',
    },
    {
      family: 'build', tool: 'build.detect', expectThrow: 'BUILD_CONFIG', workspace: 'temp', fixture,
      call: ({ workspaceRoot }) => toolsFor()[0].execute({ directory: '../elsewhere' }, { policy: policyFor(), workspaceRoot }),
      lesson: 'A directory argument that escapes the workspace is refused BUILD_CONFIG, as are an absolute path and one containing a backslash. The input is the one part of detection a plan controls, so it gets the same path rules every workspace reader here applies.',
    },

    // ---- run: the receipt --------------------------------------------------------------
    /**
     * A plan rather than a direct call, now that the round registers the reviewed targets.
     *
     * The assertions are the same ones this exercise made as a direct call; only the mechanism
     * changed, and it changed for two reasons. A plan is the stronger evidence — blocked, granted,
     * run through the kernel and replayed from the journal, instead of invoked twice and compared.
     * And a direct call hides what it read: the round watches which output keys a prediction
     * touches on a *plan* result, so every key this exercise checked was counted as unread while
     * the projection it built was invisible. Twenty-one of build.run's keys sat at the top of the
     * round's own blind-spot list for that reason alone.
     */
    {
      family: 'build', tool: 'build.run', grant: true, expectApprovals: 1, workspace: 'temp', fixture,
      plan: { version: 1, name: 'one-reviewed-build', tasks: [
        { id: 'a', tool: 'build.run', input: { target: 'main' } },
      ] },
      expect: (r) => {
        const result = r.results.a;
        return result.target === 'main' && result.system === 'npm' && result.matcher === 'node-uncaught-v1'
          && result.ok === true && result.exitCode === 0 && result.signal === null && result.truncated === false
          && result.argv.join(' ') === `node.exe ${ROOT}/src/builds.mjs`
          && !result.argv.some((entry) => entry.includes(path.sep))
          && result.inputs.find((entry) => entry.path.endsWith('builds.mjs')).sha256 === sha256(Buffer.from(BUILDS))
          && result.inputsSkipped === 0 && /^[a-f0-9]{64}$/.test(result.inputsSha256)
          && result.artifacts.length === 1 && result.artifacts[0].sha256 === sha256(Buffer.from('built'))
          && result.artifactsProduced.join(',') === `${ROOT}/out.txt`
          && /^[a-f0-9]{64}$/.test(result.artifactsSha256) && /^[a-f0-9]{64}$/.test(result.receipt)
          && result.diagnostics.length === 0 && Object.keys(result.diagnosticCounts).length === 0
          && result.stdoutTail.trim() === 'build ok' && result.stdoutBytes > 0
          && result.stdoutSha256 === sha256(Buffer.from(result.stdoutTail))
          && result.stderrBytes === 0 && result.stderrTail === ''
          && result.reproduced === null && result.untrusted === true;
      },
      lesson: 'A successful build.run returns a receipt rather than a transcript: every declared input file with its digest, every declared artifact with its digest, the exact argv, the exit code, and the digest of each output stream beside the tail a human reads. The input digests are computed before the child runs and the artifact digests after, so the receipt describes what was compiled and what came out rather than whatever the tree looks like later. The executable\'s own path is never echoed back — its basename plus the reviewed args is what a reader needs, and the path belongs to the configuration. With nothing claimed about the expected output, reproduced is null rather than true. One process effect, one approval hash bound to the resolved target, and a journal that replays without building anything again.',
    },
    {
      family: 'build', tool: 'build.run', workspace: 'temp', fixture,
      call: async ({ workspaceRoot }) => {
        const run = runnerFor([targetFor()]);
        const context = { policy: policyFor(), workspaceRoot };
        const first = await run.execute({ target: 'main' }, context);
        const second = await run.execute({ target: 'main', expectArtifactsSha256: first.artifactsSha256 }, context);
        const wrongClaim = await run.execute({ target: 'main', expectArtifactsSha256: 'a'.repeat(64) }, context);
        return {
          sameReceipt: first.receipt === second.receipt,
          sameInputs: first.inputsSha256 === second.inputsSha256,
          reproduced: second.reproduced, deniedClaim: wrongClaim.reproduced, stillBuilt: wrongClaim.ok,
        };
      },
      expect: (r) => r.sameReceipt && r.sameInputs && r.reproduced === true
        && r.deniedClaim === false && r.stillBuilt === true,
      lesson: 'The same inputs through the same reviewed toolchain produce the same receipt, which is what makes a receipt comparable at all: it is the digest of the inputs, the argv, the executable digest, the artifact digests and the exit code together. Asking for a specific artifact digest and not getting it reports reproduced:false as a value rather than throwing, and the build is still reported as having succeeded — a rebuild whose output drifted is a finding that needs its diagnostics and both digests, not an exception that discards them.',
    },
    {
      family: 'build', tool: 'build.compare', workspace: 'temp', fixture,
      call: async ({ workspaceRoot }) => {
        const [, run, compare] = toolsFor({ targets: [targetFor()] });
        const context = { policy: policyFor(), workspaceRoot };
        const before = await run.execute({ target: 'main' }, context);
        // An edit that cannot reach the output: a comment appended to the build script.
        fs.appendFileSync(path.join(workspaceRoot, ROOT, 'src', 'builds.mjs'), '// an edit that changes nothing it writes\n');
        const after = await run.execute({ target: 'main' }, context);
        const verdict = compare.execute({ left: before, right: after });
        // Restored, so a second invocation of this exercise starts from the same tree it did.
        fs.writeFileSync(path.join(workspaceRoot, ROOT, 'src', 'builds.mjs'), BUILDS);
        return {
          inputsMoved: before.inputsSha256 !== after.inputsSha256,
          artifactsHeld: before.artifactsSha256 === after.artifactsSha256,
          receiptMoved: before.receipt !== after.receipt,
          verdict: verdict.verdict, transition: verdict.transition, sameReceipt: verdict.sameReceipt,
          everyDeclaredKeyPresent: compare.outputKeys.every((key) => verdict[key] !== undefined),
        };
      },
      expect: (r) => r.inputsMoved && r.artifactsHeld && r.receiptMoved
        && r.verdict === 'inputs-changed-output-did-not' && r.transition === 'still-succeeding'
        && r.sameReceipt === false && r.everyDeclaredKeyPresent,
      lesson: 'build.compare answers two questions a pass-or-fail cannot: did the declared inputs change, and did the output bytes change. An edit to a source file that never reaches the artifact gives inputs-changed-output-did-not — the receipt moves because it binds the inputs, while the artifact digest holds — and that is the verdict a harness knowing only "the build succeeded" cannot produce. It consumes a whole build.run result as its input rather than four projected fields, so a plan can wire {$task} straight from one build to the next.',
    },
    {
      family: 'build', tool: 'build.compare',
      call: () => {
        const compare = toolsFor({ targets: [targetFor()] }).find((tool) => tool.name === 'build.compare');
        const a = 'a'.repeat(64);
        const b = 'b'.repeat(64);
        const receipt = (inputs, artifacts, exitCode) => ({ inputsSha256: inputs, artifactsSha256: artifacts, exitCode });
        const verdict = (left, right) => compare.execute({ left, right }).verdict;
        const transition = (left, right) => compare.execute({ left, right }).transition;
        return {
          identical: verdict(receipt(a, b, 0), receipt(a, b, 0)),
          changed: verdict(receipt(a, b, 0), receipt(b, a, 0)),
          noEffect: verdict(receipt(a, b, 0), receipt(b, b, 0)),
          nondeterministic: verdict(receipt(a, b, 0), receipt(a, a, 0)),
          transitions: [
            transition(receipt(a, b, 0), receipt(a, b, 0)), transition(receipt(a, b, 1), receipt(a, b, 1)),
            transition(receipt(a, b, 0), receipt(a, b, 1)), transition(receipt(a, b, 1), receipt(a, b, 0)),
          ].join(','),
          unsuppliedReceipts: compare.execute({ left: receipt(a, b, 0), right: receipt(a, b, 0) }).sameReceipt,
        };
      },
      expect: (r) => r.identical === 'identical' && r.changed === 'changed'
        && r.noEffect === 'inputs-changed-output-did-not' && r.nondeterministic === 'nondeterministic-build'
        && r.transitions === 'still-succeeding,still-failing,broken,fixed'
        && r.unsuppliedReceipts === null,
      lesson: 'The four verdicts are exactly the four combinations of "inputs moved" and "artifacts moved": identical, changed, inputs-changed-output-did-not, and nondeterministic-build — identical inputs producing different output bytes, which is the one no amount of rerunning a build will tell you about. The exit-code transition (still-succeeding, still-failing, broken, fixed) is reported on its own axis rather than folded in, because "the build now fails" and "the build is not reproducible" are independent findings and a single score would hide whichever one it did not name. Like experiment.compare, this deliberately emits no aggregate.',
    },
    {
      family: 'build', tool: 'build.run', grant: true, expectApprovals: 1, workspace: 'temp', fixture,
      plan: { version: 1, name: 'a-build-that-fails', tasks: [
        { id: 'a', tool: 'build.run', input: { target: 'fails' } },
      ] },
      expect: (r) => {
        const result = r.results.a;
        const [diagnostic] = result.diagnostics;
        return result.ok === false && result.exitCode === 1 && result.target === 'fails'
          && result.stderrBytes > 0 && result.stdoutBytes === 0
          && JSON.stringify(result.diagnosticCounts) === '{"error":1}'
          && diagnostic.code === 'ERR_ASSERTION' && diagnostic.message === '1 == 2'
          && diagnostic.line === 2 && diagnostic.column === 8 && diagnostic.severity === 'error'
          && diagnostic.workspacePath === `${ROOT}/src/fails.mjs`
          && diagnostic.fileSha256 === sha256(Buffer.from(FAILS))
          && diagnostic.fileSha256 === result.inputs.find((entry) => entry.path.endsWith('fails.mjs')).sha256
          // The declared artifact exists - an earlier exercise in this shared scratch workspace
          // built it - and this run wrote nothing, which is exactly the distinction to assert.
          && result.artifacts.length === 1 && result.artifactsProduced.length === 0;
      },
      lesson: 'A failing build is a result, not an exception: build.run reports exitCode, ok:false and its structured diagnostics, where integrations\' spawnBounded would have rejected on the non-zero exit and discarded the diagnostics of every failing build — the case that matters most. Each diagnostic carries the SHA-256 of the file it blames as the build saw it, matching that file\'s entry in the input set, so a reported error is attributable to exact bytes and a diagnostic that outlived its file can be shown to be stale without rebuilding. This failing run also lists a declared artifact that exists, because an earlier build in the same workspace wrote it, while reporting artifactsProduced as empty: the existence of an output and the authorship of it are different claims, and conflating them would let a receipt attest to bytes the run had nothing to do with. The distinction exists because this exercise caught the receipt making exactly that claim.',
    },
    {
      family: 'build', tool: 'build.run', expectCode: 'BUILD_TIMEOUT', grant: true, expectApprovals: 1,
      workspace: 'temp', fixture: slowFixture,
      plan: { version: 1, name: 'a-build-that-outruns-its-deadline', tasks: [
        { id: 'a', tool: 'build.run', input: { target: 'slow' } },
      ] },
      lesson: 'A build that outruns its deadline is refused BUILD_TIMEOUT and the child is killed, rather than returning a partial receipt. From a plan the refusal arrives after the grant, because the gate precedes the tool. A receipt whose artifact digests were taken while a compiler was still writing would attest to a half-written file, which is worse than no attestation: it would compare as a legitimate difference against the finished one.',
    },
    {
      family: 'build', tool: 'build.run', expectThrow: 'INTEGRATION_EXECUTABLE', workspace: 'temp', fixture,
      call: ({ workspaceRoot }) => runnerFor([targetFor({ executableSha256: 'f'.repeat(64) })])
        .execute({ target: 'main' }, { policy: policyFor(), workspaceRoot }),
      lesson: 'A toolchain whose digest does not match the reviewed one is refused INTEGRATION_EXECUTABLE even though the file exists and would run — and the code is the integration layer\'s on purpose, because this is literally integrations\' own resolveExecutable guard rather than a second copy of it. One guard means one set of codes and nothing to drift; a parallel implementation with prettier codes would be the more dangerous choice.',
    },
    {
      family: 'build', tool: 'build.run', expectThrow: 'BUILD_POLICY', workspace: 'temp', fixture,
      call: ({ workspaceRoot }) => runnerFor([targetFor()])
        .execute({ target: 'main' }, { policy: policyFor({ allowedEffects: ['pure', 'read'] }), workspaceRoot }),
      lesson: 'build.run is refused BUILD_POLICY when the policy does not allow the process effect, while build.detect continues to work under the same policy because it is a read. The split is what lets an operator permit a harness to see what a tree would build without permitting it to build anything.',
    },
    {
      family: 'build', tool: 'build.compare', grant: true, expectApprovals: 2, workspace: 'temp', fixture,
      plan: { version: 1, name: 'a-missing-artifact-is-not-no-artifact', tasks: [
        { id: 'declared', tool: 'build.run', input: { target: 'noartifact' } },
        { id: 'produced', tool: 'build.run', dependsOn: ['declared'], input: { target: 'main' } },
        { id: 'verdict', tool: 'build.compare', dependsOn: ['declared', 'produced'], input: {
          left: { $task: 'declared' }, right: { $task: 'produced' },
        } },
      ] },
      expect: (r) => r.results.declared.ok === true && r.results.declared.artifacts.length === 0
        && r.results.produced.artifacts.length === 1
        && r.results.declared.inputsSha256 === r.results.produced.inputsSha256
        && r.results.declared.artifactsSha256 !== r.results.produced.artifactsSha256
        && r.results.verdict.verdict === 'nondeterministic-build'
        && r.results.verdict.inputsChanged === false && r.results.verdict.artifactsChanged === true
        && r.results.verdict.transition === 'still-succeeding',
      lesson: 'Two targets over the same source tree, one asked for an artifact it never writes and one that writes it, hash their inputs identically and their artifacts differently — because the declared path list is part of each digest, not only the files found under it. Without that, a build that produced nothing would hash the empty list exactly like one that was never asked to produce anything, and the two would compare as identical. The verdict here reads nondeterministic-build, which is the honest answer to the question build.compare was asked: identical declared inputs did produce different output bytes. It is also the clearest demonstration that a verdict is about the two receipts handed to it and not about a target\'s identity, so a caller comparing receipts from different targets gets a true statement about the digests and a misleading one about the world — the verdict names what moved, never why.',
    },

    // ---- composed: the whole chain in one plan, each process effect approved separately --
    {
      family: 'composition', tool: 'build.run', grant: true, expectApprovals: 2, workspace: 'temp', fixture,
      plan: { version: 1, name: 'build-twice-and-compare', tasks: [
        { id: 'present', tool: 'build.detect', input: { directory: ROOT } },
        { id: 'before', tool: 'build.run', input: { target: 'main' } },
        { id: 'after', tool: 'build.run', dependsOn: ['before'], input: { target: 'main' } },
        { id: 'verdict', tool: 'build.compare', dependsOn: ['before', 'after'], input: {
          left: { $task: 'before' }, right: { $task: 'after' },
        } },
      ] },
      expect: (r) => r.results.present.runnable.includes('npm')
        && r.results.present.directory === ROOT && r.results.present.detector === 'markers-v1'
        && r.results.present.markersChecked >= 12 && r.results.present.count === 2
        && r.results.present.multiple === true && r.results.present.untrusted === true
        && r.results.present.systems.some((entry) => entry.system === 'npm' && entry.targets.includes('main'))
        && r.results.before.ok === true && r.results.after.ok === true
        && r.results.before.receipt === r.results.after.receipt
        && r.results.verdict.verdict === 'identical'
        && r.results.verdict.transition === 'still-succeeding'
        && r.results.verdict.sameReceipt === true,
      lesson: 'The whole build chain composes in one plan: detect what the tree contains, build the reviewed target twice, and compare the two receipts by reference. Each build is its own process effect and takes its own approval hash - two grants for two runs, not one grant for the plan - because the gate binds a resolved input rather than an intention. build.compare reads both receipts as {$task} references, which is why it accepts a whole build.run result instead of four projected fields, and the comparison reports identical with the same receipt because nothing between the two runs touched a declared input. The run replays from the journal without building anything again.',
    },
    {
      family: 'composition', tool: 'artifact.inspect', grant: true, expectApprovals: 1, workspace: 'temp', fixture,
      plan: { version: 1, name: 'build-then-read-what-was-built', tasks: [
        { id: 'built', tool: 'build.run', input: { target: 'main' } },
        { id: 'read', tool: 'artifact.inspect', dependsOn: ['built'], input: {
          path: { $task: 'built', path: '/artifacts/0/path' },
        } },
      ] },
      expect: (r) => r.results.built.artifacts.length === 1
        && r.results.read.sha256 === r.results.built.artifacts[0].sha256
        && r.results.read.bytes === r.results.built.artifacts[0].bytes
        && r.results.read.untrusted === true,
      lesson: 'A build hands its own output to a reader by reference, and the two agree about the bytes: the path comes from the receipt rather than from the plan, and the digest artifact.inspect computes independently equals the one build.run attested. That equality is the point of the receipt - it is the difference between a harness that says a build succeeded and one that can show which bytes it produced - and it closes the loop between the write side and the sixty-five readers, since whatever a build emits is immediately an artifact the rest of the harness can inspect.',
    },

    // ---- what a plan can and cannot reach, now that the target is in the registry --------
    {
      family: 'build', tool: 'build.run', expectCode: 'BUILD_INPUT', grant: true, expectApprovals: 1, workspace: 'temp', fixture,
      plan: { version: 1, name: 'claim-a-malformed-digest', tasks: [
        { id: 'a', tool: 'build.run', input: { target: 'main', expectArtifactsSha256: 'Z'.repeat(64) } },
      ] },
      lesson: 'A claimed artifact digest that is the right length but not hexadecimal is refused BUILD_INPUT by the tool, and only after the process effect has been granted — the approval gate sits in front of the tool, so a build that could never have satisfied its own claim still blocks first. The schema can bound the length of that field but not its alphabet, because the kernel\'s schema subset has no pattern keyword, which is exactly why the check exists inside execute rather than in the declaration.',
    },
    {
      family: 'build', tool: 'build.run', expectThrow: 'SCHEMA_MISMATCH', workspace: 'temp', fixture,
      plan: { version: 1, name: 'ask-for-an-unreviewed-target', tasks: [
        { id: 'a', tool: 'build.run', input: { target: 'no-such-target' } },
      ] },
      lesson: 'A plan naming a target that was never reviewed is refused SCHEMA_MISMATCH while compiling, not BUILD_UNKNOWN_TARGET at run time: the input schema\'s enum is generated from the configured target names, so the kernel rejects the plan before the tool is ever called. The tool keeps its own BUILD_UNKNOWN_TARGET guard for a direct call, which means that code is unreachable from any plan — and that is an improvement rather than a coverage gap. A declaration tight enough to make a tool\'s own refusal unnecessary is the better place for the check, because it fails at compile time for free and names the names that would have worked.',
    },

    // ---- the matcher trap worth remembering --------------------------------------------
    {
      family: 'build', tool: 'build.matchers',
      call: () => {
        const parse = (name, output) => internals.MATCHERS[name].parse(output.replace(/\r\n?/g, '\n'));
        const assertion = parse('node-uncaught-v1', [
          'node:internal/modules/run_main:107', '    triggerUncaughtException(', '    ^', '',
          'AssertionError [ERR_ASSERTION]: 1 == 2',
          '    at file:///C:/work/src/main.mjs:2:8',
          '    at ModuleJob.run (node:internal/modules/esm/module_job:561:25)',
        ].join('\n'));
        const internal = parse('node-uncaught-v1', ['node:internal/modules/run_main:107', '', 'Error: nothing of ours', '    at run (node:internal/modules/esm/loader:647:26)'].join('\n'));
        const gcc = parse('gcc-v1', 'main.c:4:12: error: expected a semicolon\r\nmain.c:9:1: warning: unused variable\r\n');
        const rustc = parse('rustc-v1', 'error[E0425]: cannot find value `x`\r\n  --> src/main.rs:3:13\r\n');
        return {
          firstFrameWins: assertion[0]?.file, line: assertion[0]?.line, column: assertion[0]?.column,
          noLocationRatherThanNodes: internal[0]?.file, plainErrorStillRead: internal[0]?.message,
          gcc: gcc.map((entry) => `${entry.severity}@${entry.line}:${entry.column}:${entry.message}`).join('|'),
          rustc: `${rustc[0]?.code}@${rustc[0]?.file}:${rustc[0]?.line}`,
          nothingClaimed: parse('none', 'error: anything at all\n').length,
        };
      },
      expect: (r) => r.firstFrameWins === 'file:///C:/work/src/main.mjs' && r.line === 2 && r.column === 8
        && r.noLocationRatherThanNodes === null && r.plainErrorStillRead === 'nothing of ours'
        && r.gcc === 'error@4:12:expected a semicolon|warning@9:1:unused variable'
        && r.rustc === 'E0425@src/main.rs:3' && r.nothingClaimed === 0,
      lesson: 'node\'s own first line lies about location: an uncaught assertion heads its stack with node:internal/modules/run_main:107, and the file the operator edited appears only in the first non-internal stack frame, so the matcher takes the frame and falls back to the header only when the header is not itself inside node. When every frame is internal it reports no location at all, because a location inside node points at the wrong code more convincingly than a null does. Three things here were wrong on first contact with real output and were fixed by running a compiler rather than reading about one: a path class excluding colons matched nothing on file:///C:/… , an optional "functionName (" prefix that excluded only parentheses matched across the line break and consumed the next frame\'s paren, and a required prefix before Error|Exception silently missed every plain "Error:". Every matcher is fed LF-normalised text, or CRLF leaves a stray carriage return inside each captured message and a multi-line pattern like rustc\'s never matches at all.',
    },
  ];
}
