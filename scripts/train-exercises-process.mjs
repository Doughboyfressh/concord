import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnBounded, limits, resolveExecutable, makeIntegrationTools } from '../src/integrations.mjs';
import { makeAgentTools } from '../src/workers.mjs';
import { makeBrowserTools } from '../src/browser.mjs';
import { makeForeignTools } from '../src/foreign.mjs';

/**
 * The refusals that need a real child process, which turned out to need almost no setup.
 *
 * Fifty-one codes were parked as "needs a subprocess" on the assumption that reaching them meant
 * installing something — a browser, an agent SDK, an MCP server. It did not. Node is already here
 * as process.execPath, spawnBounded takes any executable, and the browser and worker factories
 * accept any absolute path. So a four-line script is a worker that speaks nonsense, a server that
 * never handshakes, or a browser that never opens a DevTools port, and each of those is exactly
 * the failure the code in question exists to report.
 *
 * Two deliberate constraints. The fixtures sleep for about two seconds against deadlines of a few
 * hundred milliseconds: long enough that the timeout is the thing being tested, short enough that
 * no child outlives the round. Writing them the other way round left node processes holding the
 * scratch directory open, and the first probe could not delete its own temp folder — EPERM on
 * rmSync, which is how this was noticed. And every digest is computed rather than written down,
 * because a hardcoded hash of node would stop matching on the next upgrade.
 *
 * What is shadowed rather than reachable, measured not assumed: FOREIGN_ABORTED and
 * FOREIGN_SPAWN_FAILED raise INTEGRATION_ABORTED and INTEGRATION_PATH instead, because the shared
 * integration layer checks the signal and resolves the executable first. That is the same pattern
 * as REVERSE_ABORTED. The checks behind them are not dead, only unreachable by the obvious route.
 */

const NODE = process.execPath;
const nodeDigest = () => createHash('sha256').update(fs.readFileSync(NODE)).digest('hex');

/** A child that lives long enough to miss a deadline and not long enough to outlive the round. */
const SLEEP = 'setTimeout(() => {}, 2000);\n';
const script = (dir, name, body) => {
  const file = path.join(dir, name);
  fs.writeFileSync(file, body);
  return file;
};

const policyFor = (over = {}) => ({
  version: 1, allowedTools: [], allowedEffects: ['pure', 'read', 'write', 'network', 'process'],
  allowedOrigins: [], maxTasks: 32, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 20000, ...over,
});

/** A worker service backed by node running one of the fixture scripts. */
const workerFor = (dir, args, over = {}) => makeAgentTools({ dsh: {
  name: 'dsh.run', binary: NODE, home: dir, args, provider: 'training', model: 'training-model', ...over,
} }).find((tool) => tool.effect === 'process');

const runWorker = (tool, dir, over = {}) => tool.execute(
  { sessionId: 'training', prompt: 'hello' },
  { workspaceRoot: dir, policy: policyFor({ allowedTools: ['dsh.run'] }), ...over },
);

/** The manifest is the inventory of foreign sources; the config is what may actually be executed. */
const FOREIGN_MANIFEST = { schemaVersion: 1, sources: [{ id: 'training', kind: 'mcp-server', tools: [{ name: 'training_call' }] }] };
const foreignFor = (args, over = {}) => makeForeignTools(FOREIGN_MANIFEST, {
  servers: [{ id: 'training', executable: NODE, executableSha256: nodeDigest(), args, cwd: '.', allow: ['training_call'], timeoutMs: 400, maxOutputBytes: 65536, ...over }],
});

export function processExercises() {
  return [
    // ---- spawnBounded: the lifecycle of a child -----------------------------------------
    {
      family: 'process', tool: 'integrations.spawnBounded', expectThrow: 'INTEGRATION_EXIT', workspace: 'temp',
      call: ({ workspaceRoot }) => spawnBounded({ executable: NODE, args: ['-e', 'process.exit(3)'], cwd: workspaceRoot, env: {}, secrets: [], timeoutMs: 5000, maxOutputBytes: 65536 }),
      lesson: 'A child exiting with a nonzero status is refused INTEGRATION_EXIT rather than returned as output with a status field attached. A process that failed did not produce a result, so there is nothing for a caller to accidentally treat as one.',
    },
    {
      family: 'process', tool: 'integrations.spawnBounded', expectThrow: 'INTEGRATION_OUTPUT_LIMIT', workspace: 'temp',
      call: ({ workspaceRoot }) => spawnBounded({ executable: NODE, args: ['-e', 'process.stdout.write("z".repeat(200000))'], cwd: workspaceRoot, env: {}, secrets: [], timeoutMs: 5000, maxOutputBytes: 8192 }),
      lesson: 'Output beyond the byte budget is refused INTEGRATION_OUTPUT_LIMIT, and the bound covers stdout and stderr together. One combined budget is what makes the limit meaningful: a child could otherwise stay inside a stdout bound while writing without limit to stderr.',
    },
    {
      family: 'process', tool: 'integrations.spawnBounded', expectThrow: 'INTEGRATION_TIMEOUT', workspace: 'temp',
      call: ({ workspaceRoot }) => spawnBounded({ executable: NODE, args: ['-e', SLEEP], cwd: workspaceRoot, env: {}, secrets: [], timeoutMs: 250, maxOutputBytes: 65536 }),
      lesson: 'A child that outlives its deadline is refused INTEGRATION_TIMEOUT and the process is terminated rather than left running. The deadline is enforced from outside the child, so a program that ignores signals still cannot run past its budget.',
    },
    {
      family: 'process', tool: 'integrations.spawnBounded', expectThrow: 'INTEGRATION_PROCESS', workspace: 'temp',
      call: ({ workspaceRoot }) => spawnBounded({ executable: path.join(workspaceRoot, 'not-here.exe'), args: [], cwd: workspaceRoot, env: {}, secrets: [], timeoutMs: 2000, maxOutputBytes: 65536 }),
      lesson: 'An executable that cannot be started is refused INTEGRATION_PROCESS, distinct from a child that started and failed. Nothing ran, so the failure is about the request rather than about anything the child did.',
    },
    {
      family: 'process', tool: 'integrations.spawnBounded', expectThrow: 'INTEGRATION_ABORTED', workspace: 'temp',
      call: ({ workspaceRoot }) => {
        const controller = new AbortController();
        controller.abort();
        return spawnBounded({ executable: NODE, args: ['-e', '0'], cwd: workspaceRoot, env: {}, secrets: [], timeoutMs: 2000, maxOutputBytes: 65536, signal: controller.signal });
      },
      lesson: 'An already-aborted signal refuses INTEGRATION_ABORTED without spawning anything. Cancellation is checked before the process exists, so work nobody wants is never started — which also means this code shadows the more specific abort checks in the reverse and foreign layers that sit behind it.',
    },
    {
      family: 'process', tool: 'integrations.spawnBounded', expectThrow: 'INTEGRATION_SECRET', workspace: 'temp',
      call: ({ workspaceRoot }) => spawnBounded({ executable: NODE, args: ['-e', 'process.stdout.write("tok-training-secret")'], cwd: workspaceRoot, env: {}, secrets: ['tok-training-secret'], timeoutMs: 5000, maxOutputBytes: 65536 }),
      lesson: 'A child echoing a configured credential back in its output is refused INTEGRATION_SECRET. The credential was given to the process, so seeing it again proves nothing and risks writing it into a journal — the output is rejected rather than redacted, because a result that had to be censored is not a result worth keeping.',
    },

    // ---- limits and executable resolution, before anything spawns -----------------------
    {
      family: 'process', tool: 'integrations.limits', expectThrow: 'INTEGRATION_POLICY',
      call: () => limits({ timeoutMs: 1000, maxOutputBytes: 1000 }, { policy: policyFor({ allowedTools: ['something-else'] }) }, 'training.tool', 'process'),
      lesson: 'An integration tool absent from allowedTools is refused INTEGRATION_POLICY before any process is launched. The allow list is checked where the work would start rather than only when the plan compiles, so a tool reached by any route still has to be permitted.',
    },
    {
      family: 'process', tool: 'integrations.resolveExecutable', expectThrow: 'INTEGRATION_PATH', workspace: 'temp',
      call: ({ workspaceRoot }) => resolveExecutable({ executable: path.join(workspaceRoot, 'absent.exe'), cwd: '.' }, workspaceRoot),
      lesson: 'An executable that is not on disk is refused INTEGRATION_PATH while the request is being resolved. Resolution happens before the spawn so that a missing program is reported as a configuration problem rather than as a process that failed.',
    },
    {
      family: 'process', tool: 'integrations.resolveExecutable', expectThrow: 'INTEGRATION_EXECUTABLE', workspace: 'temp',
      call: ({ workspaceRoot }) => resolveExecutable({ executable: workspaceRoot, cwd: '.' }, workspaceRoot),
      lesson: 'A directory named as the executable is refused INTEGRATION_EXECUTABLE: it must be an existing regular file reached without path aliases. Resolving through a symlink is refused for the same reason the digest is checked — the thing that runs has to be the thing that was reviewed.',
    },
    {
      family: 'process', tool: 'integrations.resolveExecutable', expectThrow: 'INTEGRATION_EXECUTABLE', workspace: 'temp',
      call: ({ workspaceRoot }) => resolveExecutable({ executable: NODE, cwd: '.', executableSha256: 'a'.repeat(64) }, workspaceRoot),
      lesson: 'An executable whose digest does not match the reviewed one is refused INTEGRATION_EXECUTABLE even though the file exists and is runnable. Existence is not identity: the digest is what ties a configured command to the binary somebody actually examined.',
    },
    {
      family: 'process', tool: 'integrations.resolveExecutable', expectThrow: 'INTEGRATION_CWD', workspace: 'temp',
      call: ({ workspaceRoot }) => resolveExecutable({ executable: NODE, cwd: '../..' }, workspaceRoot),
      lesson: 'A working directory resolving outside the workspace is refused INTEGRATION_CWD. The child inherits that directory, so it is the same boundary every file tool enforces, applied to the one place a subprocess could otherwise step around it.',
    },
    {
      family: 'process', tool: 'integrations.factory', expectThrow: 'INTEGRATION_CONFIG',
      call: () => makeIntegrationTools({ nonsense: true }),
      lesson: 'makeIntegrationTools refuses INTEGRATION_CONFIG for a configuration field it does not recognise. The configuration decides which external programs and endpoints exist at all, so an unrecognised key is a reviewer having meant something the code cannot honour.',
    },

    // ---- workers: a node script standing in for an agent --------------------------------
    {
      family: 'process', tool: 'workers.factory', expectThrow: 'WORKER_CONFIG', workspace: 'temp',
      call: ({ workspaceRoot }) => workerFor(workspaceRoot, ['-e', '0'], { binary: 'relative/node' }),
      lesson: 'A worker binary or home that is not an absolute path is refused WORKER_CONFIG. A relative program path would resolve against whatever directory the host happened to start in, which is not a reviewable statement about what will run.',
    },
    {
      family: 'process', tool: 'workers.factory', expectThrow: 'WORKER_CONFIG', workspace: 'temp',
      call: ({ workspaceRoot }) => workerFor(workspaceRoot, ['-e', '0'], { env: { Ab: '1', AB: '2' } }),
      lesson: 'Worker environment names must be unique without regard to case, so Ab and AB together are refused WORKER_CONFIG. Case-insensitive environments exist, so a pair that is distinct here and identical there would make the child see a different environment depending on the platform.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_INPUT', workspace: 'temp',
      call: ({ workspaceRoot }) => workerFor(workspaceRoot, ['-e', '0']).execute({ sessionId: 'not a valid id!', prompt: 'hi' }, { workspaceRoot, policy: policyFor({ allowedTools: ['dsh.run'] }) }),
      lesson: 'A session identity that is not a safe identifier is refused WORKER_INPUT. The session id names state that persists between calls, so it has to be something that can be used as a path component and compared exactly.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_WORKSPACE', workspace: 'temp',
      call: ({ workspaceRoot }) => runWorker(workerFor(workspaceRoot, ['-e', '0']), workspaceRoot, { workspaceRoot: 'a/relative/root' }),
      lesson: 'A worker refuses WORKER_WORKSPACE without an absolute workspace root, because the child is given a working directory derived from it and a relative root makes that directory depend on the host process.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_ABORTED', workspace: 'temp',
      call: ({ workspaceRoot }) => {
        const controller = new AbortController();
        controller.abort();
        return runWorker(workerFor(workspaceRoot, ['-e', SLEEP]), workspaceRoot, { signal: controller.signal });
      },
      lesson: 'A worker invocation carrying an aborted signal is refused WORKER_ABORTED before the agent starts. Unlike the integration layer this check comes first here, so the worker-specific code is the one reported.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_START', workspace: 'temp',
      call: ({ workspaceRoot }) => runWorker(workerFor(workspaceRoot, ['-e', '0'], { binary: path.join(workspaceRoot, 'absent-agent.exe') }), workspaceRoot, { policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 2000 }) }),
      lesson: 'A worker binary that cannot be launched is refused WORKER_START, separately from a worker that started and then failed. The distinction tells an operator whether to look at their installation or at the agent itself.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_TIMEOUT', workspace: 'temp',
      fixture: (dir) => script(dir, 'worker-silent.cjs', SLEEP),
      call: ({ workspaceRoot }) => runWorker(workerFor(workspaceRoot, [path.join(workspaceRoot, 'worker-silent.cjs')]), workspaceRoot, { policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 300 }) }),
      lesson: 'A worker that never answers is refused WORKER_TIMEOUT at the deadline and the child is terminated. A silent agent is indistinguishable from a hung one from outside, so the deadline is the only thing that can end the wait.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_PROTOCOL', workspace: 'temp',
      fixture: (dir) => script(dir, 'worker-garbage.cjs', 'process.stdout.write("this is not json-rpc\\n");\n' + SLEEP),
      call: ({ workspaceRoot }) => runWorker(workerFor(workspaceRoot, [path.join(workspaceRoot, 'worker-garbage.cjs')]), workspaceRoot, { policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 1500 }) }),
      lesson: 'A worker writing anything that is not valid JSON-RPC is refused WORKER_PROTOCOL. A line that cannot be parsed is not partial progress to be tolerated, because a protocol half-followed is one where neither side can say what state the session is in.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_EXIT', workspace: 'temp',
      fixture: (dir) => script(dir, 'worker-dies.cjs', 'process.exit(7);\n'),
      call: ({ workspaceRoot }) => runWorker(workerFor(workspaceRoot, [path.join(workspaceRoot, 'worker-dies.cjs')]), workspaceRoot, { policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 1500 }) }),
      lesson: 'A worker that exits before answering is refused WORKER_EXIT rather than reported as an empty answer. An agent that died is not an agent that had nothing to say.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_OUTPUT_LIMIT', workspace: 'temp',
      fixture: (dir) => script(dir, 'worker-flood.cjs', 'process.stdout.write("z".repeat(300000));\n' + SLEEP),
      call: ({ workspaceRoot }) => runWorker(workerFor(workspaceRoot, [path.join(workspaceRoot, 'worker-flood.cjs')]), workspaceRoot, { policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 2500, maxOutputBytes: 4096 }) }),
      lesson: 'A worker producing more than its byte budget is refused WORKER_OUTPUT_LIMIT while it is still running, rather than after the whole transcript has been buffered. Reading without a bound is how a cooperative protocol becomes a way to exhaust memory.',
    },

    // ---- browser: node standing in for one -----------------------------------------------
    {
      family: 'process', tool: 'browser.factory', expectThrow: 'BROWSER_CONFIG',
      call: () => makeBrowserTools({ executable: 'chrome' }),
      lesson: 'A browser executable that is not an absolute path is refused BROWSER_CONFIG. Resolving a browser through PATH would mean the reviewed configuration did not say which program runs.',
    },
    {
      family: 'process', tool: 'browser.factory', expectThrow: 'BROWSER_CONFIG',
      call: () => makeBrowserTools({ name: 'Not A Tool Name', executable: NODE }),
      lesson: 'A browser tool name that is not a valid identifier is refused BROWSER_CONFIG, because the name becomes an entry in the registry and in the policy allow list, where it has to be matched exactly.',
    },
    {
      family: 'process', tool: 'browser.snapshot', expectThrow: 'BROWSER_INPUT', workspace: 'temp',
      call: ({ workspaceRoot }) => makeBrowserTools({ executable: NODE })[0]
        .execute({ url: 'file:///etc/passwd' }, { workspaceRoot, policy: policyFor({ allowedTools: ['browser.snapshot'] }) }),
      lesson: 'A url that is not http or https is refused BROWSER_INPUT before the browser launches. The scheme list is an allow list rather than a block list, so a file or data url is refused by not being named rather than by being anticipated.',
    },
    {
      family: 'process', tool: 'browser.snapshot', expectThrow: 'BROWSER_POLICY', workspace: 'temp',
      call: ({ workspaceRoot }) => makeBrowserTools({ executable: NODE })[0]
        .execute({ url: 'http://127.0.0.1/' }, { workspaceRoot, policy: policyFor({ allowedTools: ['something-else'] }) }),
      lesson: 'A browser tool absent from allowedTools is refused BROWSER_POLICY before any process starts. Driving a browser is the broadest capability Concord has, so it is gated where the work begins and not only where the plan was compiled.',
    },
    {
      family: 'process', tool: 'browser.snapshot', expectThrow: 'BROWSER_ABORTED', workspace: 'temp',
      call: ({ workspaceRoot }) => {
        const controller = new AbortController();
        controller.abort();
        return makeBrowserTools({ executable: NODE })[0]
          .execute({ url: 'http://127.0.0.1/' }, { workspaceRoot, policy: policyFor({ allowedTools: ['browser.snapshot'] }), signal: controller.signal });
      },
      lesson: 'An aborted signal refuses BROWSER_ABORTED before a browser is launched, so a cancelled snapshot never leaves a browser process or a temporary profile directory behind.',
    },
    {
      family: 'process', tool: 'browser.snapshot', expectThrow: 'BROWSER_PATH', workspace: 'temp',
      call: ({ workspaceRoot }) => {
        const tools = makeBrowserTools({ executable: path.join(workspaceRoot, 'absent-browser.exe') });
        return tools[0].execute({ url: 'http://127.0.0.1/' }, { workspaceRoot, policy: policyFor({ allowedTools: [tools[0].name] }) });
      },
      lesson: 'A browser executable that is not present is refused BROWSER_PATH, separately from BROWSER_EXECUTABLE for a file that exists but is not the reviewed one. Absent and wrong are different problems with different fixes.',
    },
    {
      family: 'process', tool: 'browser.snapshot', expectThrow: 'BROWSER_TIMEOUT', workspace: 'temp',
      // node launches cleanly and is not a browser, so it never opens a DevTools port. That is the
      // honest shape of this failure: the executable was reviewed and started, and still could not
      // be driven.
      call: ({ workspaceRoot }) => makeBrowserTools({ executable: NODE, timeoutMs: 600 })[0]
        .execute({ url: 'http://127.0.0.1/' }, { workspaceRoot, policy: policyFor({ allowedTools: ['browser.snapshot'], timeoutMs: 600 }) }),
      lesson: 'A program that starts but never opens a DevTools port is refused BROWSER_TIMEOUT rather than hanging, and the launched process and its temporary profile are cleaned up. Launching successfully is not the same as being controllable, so the port is what the wait is actually for.',
    },

    // ---- foreign servers: node standing in for an MCP server ----------------------------
    {
      family: 'process', tool: 'foreign.factory', expectThrow: 'FOREIGN_CONFIG',
      call: () => makeForeignTools(FOREIGN_MANIFEST, { servers: [{ id: 'training', executable: NODE, executableSha256: nodeDigest(), args: [], nonsense: 1 }] }),
      lesson: 'A foreign server entry with an unrecognised field is refused FOREIGN_CONFIG, naming the field. The manifest and the configuration are separate on purpose: the manifest says which foreign sources exist, and the configuration says which may actually be executed and with what argv.',
    },
    {
      family: 'process', tool: 'foreign.factory', expectThrow: 'FOREIGN_CONFIG',
      call: () => makeForeignTools(FOREIGN_MANIFEST, { servers: [{ id: 'training', executable: NODE, executableSha256: 'abc', args: [] }] }),
      lesson: 'A foreign server whose executableSha256 is not 64 lower-case hex characters is refused FOREIGN_CONFIG at build time. The digest is verified against the file before spawning, so a malformed one could never have produced a working call — checking its shape here turns a failure on first use into a failure to build the registry.',
    },
    {
      family: 'process', tool: 'foreign.call', expectThrow: 'FOREIGN_TIMEOUT', workspace: 'temp',
      fixture: (dir) => script(dir, 'server-silent.cjs', SLEEP),
      call: ({ workspaceRoot }) => {
        const tools = foreignFor([path.join(workspaceRoot, 'server-silent.cjs')]);
        const call = tools.find((tool) => tool.effect === 'process');
        return call.execute({}, { workspaceRoot, policy: policyFor({ allowedTools: tools.map((tool) => tool.name) }) });
      },
      lesson: 'A foreign server that starts but never completes the handshake is refused FOREIGN_TIMEOUT. A server that is running and silent cannot be told from one that is wedged, so the deadline is what ends the exchange, and the child is terminated rather than abandoned.',
    },
    {
      family: 'process', tool: 'foreign.call', expectThrow: 'FOREIGN_OUTPUT_LIMIT', workspace: 'temp',
      fixture: (dir) => script(dir, 'server-flood.cjs', 'process.stdout.write("z".repeat(500000));\n' + SLEEP),
      call: ({ workspaceRoot }) => {
        const tools = foreignFor([path.join(workspaceRoot, 'server-flood.cjs')], { timeoutMs: 2000, maxOutputBytes: 4096 });
        const call = tools.find((tool) => tool.effect === 'process');
        return call.execute({}, { workspaceRoot, policy: policyFor({ allowedTools: tools.map((tool) => tool.name) }) });
      },
      lesson: 'A foreign server producing more than its budget is refused FOREIGN_OUTPUT_LIMIT as it writes. A foreign server is the least trusted thing Concord talks to, so its output is bounded while being read rather than after it has all arrived.',
    },
  ];
}
