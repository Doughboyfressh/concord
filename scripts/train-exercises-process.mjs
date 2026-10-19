import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { spawnBounded, limits, resolveExecutable, makeIntegrationTools } from '../src/integrations.mjs';
import { makeAgentTools } from '../src/workers.mjs';
import { makeBrowserTools, discoverPageTarget } from '../src/browser.mjs';
import { findAppBrowser } from '../src/desktop.mjs';
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

/**
 * The HTTP connector half, driven by a server started for the length of one call.
 *
 * A loopback server on an ephemeral port is enough to reach every refusal on the response path,
 * and it is honest about what it is testing: these codes are about how Concord treats an answer it
 * did not compute, so the answer has to come over a socket rather than from a stub.
 */
const TOKEN_ENV = 'CONCORD_TRAINING_TOKEN';
const TOKEN = 'tok-training-credential';

/** Start a loopback server, run one call against it, and always shut it down. */
async function againstServer(handler, run, { token = TOKEN } = {}) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const previous = process.env[TOKEN_ENV];
  if (token === null) delete process.env[TOKEN_ENV]; else process.env[TOKEN_ENV] = token;
  try {
    return await run(origin);
  } finally {
    server.close();
    if (previous === undefined) delete process.env[TOKEN_ENV]; else process.env[TOKEN_ENV] = previous;
  }
}

/** A TypeSafe connector pointed at a given origin. Its question shape is strict, so it is fixed. */
const typeSafeFor = (origin, over = {}) => makeIntegrationTools({ typesafe: {
  origin, apiKeyEnv: TOKEN_ENV, model: 'jev-1.0.0', timeoutMs: 1500, maxOutputBytes: 65536, ...over,
} })[0];
const TYPESAFE_INPUT = {
  state: 'a state the evaluator is asked about',
  questions: { q1: { type: 'choice', instructions: 'pick one', criteria: { yes: 'it holds', no: 'it does not' } } },
};
const askTypeSafe = (tool, origin, over = {}) => tool.execute(TYPESAFE_INPUT, {
  workspaceRoot: process.cwd(),
  policy: policyFor({ allowedTools: ['typesafe.evaluate'], allowedOrigins: [origin], ...over }),
});

/**
 * A worker that completes the whole DSH handshake, so the checks after it can be reached.
 *
 * initialize, session/prompt, session/wait, shutdown — and the identity assertion is exact: the
 * serverInfo name must be deepseek-harness-sdk-runtime or the session is refused. Everything
 * downstream of the handshake was unreachable until a fixture could get through it.
 */
const handshakingWorker = (extraReceiptFields = '') => [
  'let buf = "";',
  'const send = (o) => process.stdout.write(JSON.stringify(o) + "\\n");',
  'process.stdin.on("data", (chunk) => {',
  '  buf += chunk.toString();',
  '  let i;',
  '  while ((i = buf.indexOf("\\n")) >= 0) {',
  '    const line = buf.slice(0, i); buf = buf.slice(i + 1);',
  '    if (!line.trim()) continue;',
  '    const m = JSON.parse(line);',
  '    if (m.id === undefined) continue;',
  '    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { serverInfo: { name: "deepseek-harness-sdk-runtime", version: "1.0.0" } } });',
  '    else if (m.method === "session/prompt") send({ jsonrpc: "2.0", id: m.id, result: { messageId: "m1"' + extraReceiptFields + ' } });',
  '    else send({ jsonrpc: "2.0", id: m.id, result: {} });',
  '  }',
  '});',
  SLEEP,
].join('\n');

/** A foreign server that refuses to initialize at all. */
const HANDSHAKE_REFUSING_SERVER = [
  'let buf = "";',
  'process.stdin.on("data", (chunk) => {',
  '  buf += chunk.toString();',
  '  let i;',
  '  while ((i = buf.indexOf("\\n")) >= 0) {',
  '    const line = buf.slice(0, i); buf = buf.slice(i + 1);',
  '    if (!line.trim()) continue;',
  '    const m = JSON.parse(line);',
  '    if (m.id !== undefined) process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32600, message: "will not initialize" } }) + "\\n");',
  '  }',
  '});',
  SLEEP,
].join('\n');

/** A worker that reads JSON-RPC and answers every request with a protocol error. */
const ERRORING_WORKER = [
  'let buf = "";',
  'process.stdin.on("data", (chunk) => {',
  '  buf += chunk.toString();',
  '  let i;',
  '  while ((i = buf.indexOf("\\n")) >= 0) {',
  '    const line = buf.slice(0, i); buf = buf.slice(i + 1);',
  '    if (!line.trim()) continue;',
  '    const msg = JSON.parse(line);',
  '    if (msg.id !== undefined) process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: "refused" } }) + "\\n");',
  '  }',
  '});',
  SLEEP,
].join('\n');

/** A foreign server that handshakes correctly and then refuses the tool call. */
const CALL_ERRORING_SERVER = [
  'let buf = "";',
  'process.stdin.on("data", (chunk) => {',
  '  buf += chunk.toString();',
  '  let i;',
  '  while ((i = buf.indexOf("\\n")) >= 0) {',
  '    const line = buf.slice(0, i); buf = buf.slice(i + 1);',
  '    if (!line.trim()) continue;',
  '    const msg = JSON.parse(line);',
  '    if (msg.id === undefined) continue;',
  '    if (msg.method === "initialize") {',
  '      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "training", version: "1" } } }) + "\\n");',
  '    } else {',
  '      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "the server declined" } }) + "\\n");',
  '    }',
  '  }',
  '});',
  SLEEP,
].join('\n');

/**
 * Serve one DevTools target list and run discovery against it.
 *
 * discoverPageTarget is exported for exactly this, so every BROWSER_CDP route is reachable with a
 * loopback HTTP server and no browser at all. Worth noticing: the target list is the first thing
 * Concord believes from the browser, and a browser is the least trustworthy thing it talks to, so
 * each malformed shape gets its own refusal rather than one catch-all.
 */
async function againstTargetList(body, { status = 200 } = {}) {
  const server = http.createServer((request, response) => {
    response.writeHead(status, { 'content-type': 'application/json' });
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try { return await discoverPageTarget(server.address().port); }
  finally { server.close(); }
}

/** Serve a page for a real browser to load, run one snapshot against it, then close. */
async function againstPage(html, run) {
  const server = http.createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(html);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try { return await run('http://127.0.0.1:' + server.address().port + '/'); }
  finally { server.close(); }
}

/**
 * A browser this machine actually has, or null.
 *
 * The output-budget refusal is the one code here that cannot be reached without driving a real
 * browser through a real CDP session, so its exercise is emitted only where one exists. Absent
 * rather than failing: a machine with no browser should report one fewer exercise, not a finding
 * about its own installation.
 */
const INSTALLED_BROWSER = (() => {
  try { return findAppBrowser(); } catch { return null; }
})();

export function processExercises() {
  return [
    // ---- the DevTools target list, which is the first thing a browser is believed about --
    {
      family: 'process', tool: 'browser.discoverPageTarget', expectThrow: 'BROWSER_CDP',
      call: () => againstTargetList('this is not json'),
      lesson: 'A DevTools target list that is not strict JSON is refused BROWSER_CDP. The list is the first thing Concord believes from a browser, and a browser is the least trustworthy process it launches, so the response is parsed strictly rather than leniently.',
    },
    {
      family: 'process', tool: 'browser.discoverPageTarget', expectThrow: 'BROWSER_CDP',
      call: () => againstTargetList([{ type: 'background_page', webSocketDebuggerUrl: 'ws://127.0.0.1:1/x' }]),
      lesson: 'A target list containing no inspectable page is refused BROWSER_CDP rather than falling back to whatever target happens to be present. Attaching to a background page or a service worker instead of the page that was asked for would snapshot something nobody requested.',
    },
    {
      family: 'process', tool: 'browser.discoverPageTarget', expectThrow: 'BROWSER_CDP',
      call: () => againstTargetList([{ type: 'page', webSocketDebuggerUrl: 'ws://example.com/devtools/page/1' }]),
      lesson: 'A DevTools WebSocket endpoint that is not loopback is refused BROWSER_CDP, and so is one whose scheme is not ws. This is the sharpest check in the browser path: the endpoint comes from the browser rather than from configuration, so a compromised or confused browser could otherwise redirect a debugging session — with full page control — to a host across the network.',
    },

    // ---- the HTTP connector: refusing an answer it did not compute ----------------------
    {
      family: 'process', tool: 'typesafe.evaluate', expectThrow: 'INTEGRATION_ORIGIN',
      call: () => askTypeSafe(typeSafeFor('http://127.0.0.1:9'), 'http://127.0.0.1:9', { allowedOrigins: [] }),
      lesson: 'A configured origin absent from the policy allowedOrigins is refused INTEGRATION_ORIGIN before any connection is attempted. Configuring an endpoint and permitting it are separate decisions: the configuration says what exists, the policy says what this run may reach.',
    },
    {
      family: 'process', tool: 'typesafe.evaluate', expectThrow: 'INTEGRATION_INPUT',
      call: () => typeSafeFor('http://127.0.0.1:9').execute({ state: 's', questions: {} }, {
        workspaceRoot: process.cwd(),
        policy: policyFor({ allowedTools: ['typesafe.evaluate'], allowedOrigins: ['http://127.0.0.1:9'] }),
      }),
      lesson: 'TypeSafe refuses INTEGRATION_INPUT for a request carrying no questions, and refuses a question whose type is not choice, score or noul or which omits its instructions. The rubric is entirely caller-supplied, so its shape is the one thing that must be checked here rather than discovered by the far end.',
    },
    {
      family: 'process', tool: 'typesafe.evaluate', expectThrow: 'INTEGRATION_CREDENTIAL',
      call: () => againstServer(
        (request, response) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}'); },
        (origin) => askTypeSafe(typeSafeFor(origin), origin),
        { token: null },
      ),
      lesson: 'A credential environment variable that is unset, or holding anything outside printable ASCII, is refused INTEGRATION_CREDENTIAL before the request is built. The token is read from the environment at call time rather than stored in the configuration, so a missing credential is a runtime condition and is reported as one.',
    },
    {
      family: 'process', tool: 'typesafe.evaluate', expectThrow: 'INTEGRATION_HTTP',
      // Port 9 is the discard port: reserved, and reliably not listening.
      call: () => againstServer(
        (request, response) => response.end('{}'),
        () => askTypeSafe(typeSafeFor('http://127.0.0.1:9'), 'http://127.0.0.1:9'),
      ),
      lesson: 'A request that cannot reach its endpoint is refused INTEGRATION_HTTP, separately from a response that arrived with a failing status. One means the far end was never spoken to and the other means it answered unhelpfully, and only the second says anything about the service.',
    },
    {
      family: 'process', tool: 'typesafe.evaluate', expectThrow: 'INTEGRATION_HTTP_STATUS',
      call: () => againstServer(
        (request, response) => { response.writeHead(503); response.end('busy'); },
        (origin) => askTypeSafe(typeSafeFor(origin), origin),
      ),
      lesson: 'A non-2xx response is refused INTEGRATION_HTTP_STATUS with the status included, and the body is discarded rather than parsed. An error page is not a result, and attempting to read one as the answer is how an outage becomes a confident wrong answer.',
    },
    {
      family: 'process', tool: 'typesafe.evaluate', expectThrow: 'INTEGRATION_OUTPUT',
      call: () => againstServer(
        (request, response) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end(Buffer.from([0xff, 0xfe, 0x00])); },
        (origin) => askTypeSafe(typeSafeFor(origin), origin),
      ),
      lesson: 'A response that is not valid UTF-8 JSON is refused INTEGRATION_OUTPUT. Decoding is strict rather than lossy, because a replacement character silently substituted into an answer would be recorded in a journal as though the service had sent it.',
    },

    // ---- worker protocol: a child that speaks, and speaks badly -------------------------
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_POLICY', workspace: 'temp',
      call: ({ workspaceRoot }) => runWorker(workerFor(workspaceRoot, ['-e', '0']), workspaceRoot, { policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 0 }) }),
      lesson: 'A worker refuses WORKER_POLICY when the policy deadline or output budget is not a positive bounded integer, and checks both before spawning. A zero budget permits nothing, so treating it as absent and substituting a default would run the child under a bound nobody chose.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_RPC', workspace: 'temp',
      fixture: (dir) => script(dir, 'worker-errors.cjs', ERRORING_WORKER),
      call: ({ workspaceRoot }) => runWorker(workerFor(workspaceRoot, [path.join(workspaceRoot, 'worker-errors.cjs')]), workspaceRoot, { policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 2500 }) }),
      lesson: 'A worker that answers a request with a JSON-RPC error is refused WORKER_RPC, and only the numeric code is carried out — not the message. A runtime diagnostic may contain credentials or paths, so the code travels and the prose does not.',
    },

    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_INPUT_LIMIT', workspace: 'temp',
      fixture: (dir) => script(dir, 'worker-handshakes.cjs', handshakingWorker()),
      call: ({ workspaceRoot }) => workerFor(workspaceRoot, [path.join(workspaceRoot, 'worker-handshakes.cjs')])
        .execute({ sessionId: 'training', prompt: 'z'.repeat(6000) }, {
          workspaceRoot, policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 4000, maxOutputBytes: 900 }),
        }),
      lesson: 'A request Concord is about to send that exceeds the byte budget is refused WORKER_INPUT_LIMIT before it is written to the child. The budget bounds both directions: a prompt large enough to be a denial of service against the agent is refused on this side rather than delivered and regretted. Reaching it needs a worker that completes the handshake, because the small initialize request fits where the prompt does not.',
    },
    {
      family: 'process', tool: 'dsh.run', expectThrow: 'WORKER_REDACTION', workspace: 'temp',
      // Two keys that are different until the credential is removed, and identical afterwards.
      fixture: (dir) => script(dir, 'worker-collides.cjs', handshakingWorker(', "x[redacted]y": 1, "xSECRETVALUEy": 2')),
      call: ({ workspaceRoot }) => workerFor(workspaceRoot, [path.join(workspaceRoot, 'worker-collides.cjs')], { env: { API_KEY: 'SECRETVALUE' } })
        .execute({ sessionId: 'training', prompt: 'hello' }, {
          workspaceRoot, policy: policyFor({ allowedTools: ['dsh.run'], timeoutMs: 4000 }),
        }),
      lesson: 'Credentials are redacted out of everything a worker returns, and two object keys that become identical once the credential is removed are refused WORKER_REDACTION rather than silently merged. A worker could otherwise smuggle a value out by arranging for redaction itself to collapse two keys into one, and the collapsed object would look ordinary.',
    },
    {
      family: 'process', tool: 'browser.snapshot', expectThrow: 'BROWSER_EXECUTABLE', workspace: 'temp',
      call: ({ workspaceRoot }) => {
        const tools = makeBrowserTools({ executable: NODE, executableSha256: 'a'.repeat(64) });
        return tools[0].execute({ url: 'http://127.0.0.1/' }, { workspaceRoot, policy: policyFor({ allowedTools: [tools[0].name] }) });
      },
      lesson: 'A browser whose digest does not match the reviewed one is refused BROWSER_EXECUTABLE even though the file exists and would run. This is the check that makes pinning a browser mean something: an updated or substituted binary is a different program, and driving a browser is the broadest thing Concord can be asked to do.',
    },

    // ---- foreign protocol: a server that handshakes and then declines -------------------
    {
      family: 'process', tool: 'foreign.call', expectThrow: 'FOREIGN_HANDSHAKE_FAILED', workspace: 'temp',
      fixture: (dir) => script(dir, 'server-refuses-init.cjs', HANDSHAKE_REFUSING_SERVER),
      call: ({ workspaceRoot }) => {
        const tools = foreignFor([path.join(workspaceRoot, 'server-refuses-init.cjs')], { timeoutMs: 2500 });
        const call = tools.find((tool) => tool.effect === 'process');
        return call.execute({}, { workspaceRoot, policy: policyFor({ allowedTools: tools.map((tool) => tool.name) }) });
      },
      lesson: 'A foreign server that answers initialize with an error is refused FOREIGN_HANDSHAKE_FAILED. The distinction from a timeout is real and was measured: a server replying with an unrecognised result still satisfies the handshake, so this code is specifically about a server that declined rather than one that was malformed or silent.',
    },

    {
      family: 'process', tool: 'foreign.call', expectThrow: 'FOREIGN_CALL_FAILED', workspace: 'temp',
      fixture: (dir) => script(dir, 'server-declines.cjs', CALL_ERRORING_SERVER),
      call: ({ workspaceRoot }) => {
        const tools = foreignFor([path.join(workspaceRoot, 'server-declines.cjs')], { timeoutMs: 2500 });
        const call = tools.find((tool) => tool.effect === 'process');
        return call.execute({}, { workspaceRoot, policy: policyFor({ allowedTools: tools.map((tool) => tool.name) }) });
      },
      lesson: 'A foreign server that completes the handshake and then returns an error for the call is refused FOREIGN_CALL_FAILED, which is distinct from a handshake that never finished and from a deadline that expired. Each says something different about where the exchange broke, and a server answering an error is one that is working as designed.',
    },

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

    // ---- and the one that needs a browser this machine actually has ---------------------
    ...(INSTALLED_BROWSER ? [{
      family: 'process', tool: 'browser.snapshot', expectThrow: 'BROWSER_OUTPUT_LIMIT', workspace: 'temp',
      call: ({ workspaceRoot }) => againstPage(
        '<html><body><h1>Training page</h1><p>' + 'word '.repeat(400) + '</p></body></html>',
        (url) => {
          const tools = makeBrowserTools({ executable: INSTALLED_BROWSER.executable, timeoutMs: 45000, maxOutputBytes: 200 });
          const snapshot = tools.find((tool) => tool.name === 'browser.snapshot');
          return snapshot.execute({ url }, {
            workspaceRoot,
            policy: policyFor({ allowedTools: ['browser.snapshot'], maxOutputBytes: 200, timeoutMs: 45000 }),
          });
        },
      ),
      lesson: 'A snapshot whose result exceeds the output budget is refused BROWSER_OUTPUT_LIMIT after the page has been read and before the result is returned, and the browser process and its temporary profile are still cleaned up. This is the only browser refusal that needs a real CDP session: the page is served from loopback, loaded by a headless browser this machine actually has, and the whole round trip takes about three hundred milliseconds. The budget is checked against the serialised result rather than the page, because what matters is what would enter the journal.',
    }] : []),
  ];
}
