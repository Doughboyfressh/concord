import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer, listenServer } from '../src/server.mjs';
import { createChatHarness } from '../src/chat.mjs';
import { buildChatContext } from '../src/chat-context.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';
import { makeCapabilityTools } from '../src/capabilities.mjs';
import { loadSourceLock, makeSourceTools } from '../src/sources.mjs';
import { parseJson } from '../src/value.mjs';
import { tempDir } from './temp-workspace.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
const inventory = parseJson(fs.readFileSync(path.join(root, 'capabilities.lock.json'), 'utf8'));

// A turn needs a model: the harness has no demonstration path. This stand-in supplies one where
// the test is about the HTTP surface rather than the model call. `pure` because it reaches no
// network, so these turns do not stop at a grant; the grant test at line 128 supplies its own
// `network` fixture, which wins by name.
const defaultModel = {
  name: 'model.propose', version: 'fixture-1', effect: 'pure',
  inputSchema: { type: 'object' }, config: { fixture: true },
  execute() {
    return { model: 'fixture-1', proposal: {
      reply: 'Proposed a pure-tool evidence plan over the reviewed sources.',
      plan: { version: 1, tasks: [{ id: 'coverage', tool: 'sources.catalog', input: {} }] } } };
  },
};

function harnessFixture(workspaceRoot, additional = []) {
  const supplied = additional.some((tool) => tool.name === 'model.propose');
  const descriptors = [...makeBuiltinTools(), ...makeCapabilityTools(inventory), ...makeSourceTools(catalog),
    ...(supplied ? [] : [defaultModel]), ...additional];
  const registry = new Map(descriptors.map((t) => [t.name, t]));
  const buildContext = ({ message, history }) => buildChatContext({
    message, history, sourceLock: catalog, inventory, registry, instructionRoot: path.join(root, 'instructions'),
  });
  return createChatHarness({
    registry, sourceLock: catalog, workspaceRoot, buildContext,
    policy: {
      version: 1, allowedTools: [...registry.keys()], allowedEffects: ['pure', 'read', 'write', 'network'],
      maxTasks: 32, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 10000,
    },
  });
}

async function startServer(harness, status = {}) {
  const server = createServer({ harness, status, host: '127.0.0.1', port: 0 });
  const url = await listenServer(server);
  return { url, close: () => new Promise((resolve) => server.close(resolve)) };
}

function postJson(url, routePath, token, body) {
  const headers = { 'Content-Type': 'application/json; charset=utf-8', Origin: url };
  if (token !== undefined) headers['X-Concord-Token'] = token;
  return fetch(url + routePath, { method: 'POST', headers, body: JSON.stringify(body ?? {}) });
}

async function readState(url) {
  const response = await fetch(url + '/api/state');
  assert.equal(response.status, 200);
  return response.json();
}

test('the local server enforces loopback host, origin, and token checks and sends its security headers', async () => {
  const temp = tempDir('concord-server-security-');
  const { url, close } = await startServer(harnessFixture(temp));
  try {
    const state = await fetch(url + '/api/state');
    assert.equal(state.status, 200);
    assert.equal(state.headers.get('content-security-policy'), "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    assert.equal(state.headers.get('cache-control'), 'no-store');

    const { token } = await state.json();
    assert.match(token, /^[A-Za-z0-9_-]{32,}$/);

    const missingToken = await postJson(url, '/api/chat', undefined, { message: 'hi' });
    assert.equal(missingToken.status, 403);

    const wrongOrigin = await fetch(url + '/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8', Origin: 'http://evil.example', 'X-Concord-Token': token },
      body: JSON.stringify({ message: 'hi' }),
    });
    assert.equal(wrongOrigin.status, 403);

    const wrongMethod = await fetch(url + '/api/chat');
    assert.equal(wrongMethod.status, 405);

    const unknownRoute = await fetch(url + '/api/does-not-exist');
    assert.equal(unknownRoute.status, 404);

    const asset = await fetch(url + '/client.mjs');
    assert.equal(asset.status, 200);
    assert.equal(asset.headers.get('content-type'), 'text/javascript; charset=utf-8');
  } finally {
    await close();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a turn completes and replays over real HTTP', async () => {
  const temp = tempDir('concord-server-turn-');
  const { url, close } = await startServer(harnessFixture(temp), { sourceCount: catalog.sources.length, files: 0, capabilities: 0, skillFiles: 0, tools: [] });
  try {
    const { token } = await readState(url);
    const chat = await postJson(url, '/api/chat', token, { message: 'Inspect the source knowledge and explain what is connected.' });
    assert.equal(chat.status, 200);
    const chatBody = await chat.json();
    assert.equal(chatBody.state.mode, 'live');
    // Every pinned source is covered. Asserted against the lock rather than a literal, which went
    // stale the moment a thirteenth source was pinned.
    assert.equal(chatBody.state.sourceCoverage.length, catalog.sources.length);
    assert.ok(chatBody.state.runs.some((r) => r.status === 'completed'));

    const runId = chatBody.state.runs.at(-1).id;
    const replay = await postJson(url, '/api/replay', token, { runId });
    assert.equal(replay.status, 200);
    const replayBody = await replay.json();
    assert.equal(replayBody.replay.verified, true);
    assert.equal(replayBody.replay.runId, runId);
  } finally {
    await close();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a live model proposal and its file effect need separate exact grants over real HTTP', async () => {
  const temp = tempDir('concord-server-live-');
  let calls = 0;
  const model = {
    name: 'model.propose', version: 'fixture-1', effect: 'network', inputSchema: { type: 'object' }, config: { fixture: true },
    execute() {
      calls += 1;
      return { model: 'fixture-1', proposal: { reply: 'Saving this reviewed memory.', plan: { version: 1, tasks: [{ id: 'save', tool: 'files.write', input: { path: 'memory.json', content: { lesson: 'HTTP-level evidence closes the loop.' } } }] } } };
    },
  };
  const { url, close } = await startServer(harnessFixture(temp, [model]));
  try {
    const { token } = await readState(url);
    let chat = await postJson(url, '/api/chat', token, { message: 'Propose a memory update.' });
    let body = await chat.json();
    assert.equal(calls, 0);
    assert.equal(body.state.pending.effect, 'network');

    let approve = await postJson(url, '/api/approve', token, { requestHash: body.state.pending.requestHash });
    body = await approve.json();
    assert.equal(calls, 1);
    assert.ok(body.state.proposedPlan);

    let execute = await postJson(url, '/api/execute', token, {});
    body = await execute.json();
    assert.equal(body.state.pending.effect, 'write');
    assert.equal(fs.existsSync(path.join(temp, 'memory.json')), false);

    approve = await postJson(url, '/api/approve', token, { requestHash: body.state.pending.requestHash });
    body = await approve.json();
    assert.equal(fs.existsSync(path.join(temp, 'memory.json')), true);

    const runId = body.state.runs.at(-1).id;
    const replay = await postJson(url, '/api/replay', token, { runId });
    const replayBody = await replay.json();
    assert.equal(replayBody.replay.verified, true);
    assert.equal(calls, 1);
  } finally {
    await close();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

function findFreePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function waitForStartupLine(child) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      const match = /Concord chat: (http:\/\/\S+)/.exec(buffer);
      if (match) { child.stdout.off('data', onData); resolve(match[1]); }
    };
    child.stdout.on('data', onData);
    child.once('error', reject);
    child.once('exit', (code) => reject(new Error('scripts/chat.mjs exited early with code ' + code)));
  });
}

test('scripts/chat.mjs tolerates a repeated identical turn without crashing (regression for the content-addressed evidence collision)', async () => {
  const store = tempDir('concord-chat-script-store-');
  const port = await findFreePort();
  const child = spawn(process.execPath, [path.join(root, 'scripts', 'chat.mjs'), '--port', String(port), '--store', store], { cwd: root });
  try {
    const url = await waitForStartupLine(child);
    const { token } = await readState(url);
    const message = { message: 'Combine deterministic replay, browser tools, security review and memory in this chat harness.' };

    const first = await postJson(url, '/api/chat', token, message);
    assert.equal(first.status, 200);
    const second = await postJson(url, '/api/chat', token, message);
    assert.equal(second.status, 200);
    const secondBody = await second.json();
    assert.ok(secondBody.state.runs.length >= 2);
  } finally {
    child.kill();
    fs.rmSync(store, { recursive: true, force: true });
  }
});

test('every API route names a method the running facade actually exposes', async () => {
  // advance shipped with a route, a schema, a button and six passing tests, and answered 404 in
  // the browser: src/app.mjs hands the server a facade built from an explicit method list, and
  // the new method was not on it. Every unit test drove the harness directly and so could not see
  // it. This holds the two halves together instead.
  const { routes } = await import('../src/server.mjs');
  const source = await fs.promises.readFile(new URL('../src/app.mjs', import.meta.url), 'utf8');

  // The facade's own keys, plus the list it copies across from the harness.
  const declared = new Set([...source.matchAll(/^\s{4}(\w+):/gm)].map((m) => m[1]));
  const forwarded = source.match(/for \(const method of \[([^\]]+)\]\) wrapped\[method\]/);
  assert.ok(forwarded, 'the forwarding list must stay findable for this check to mean anything');
  for (const name of forwarded[1].match(/'([^']+)'/g).map((q) => q.slice(1, -1))) declared.add(name);

  for (const [path, route] of routes) {
    assert.ok(declared.has(route.method), `${path} calls ${route.method}, which the app facade does not expose`);
  }
});

test('every route that takes one field names a field its own schema declares', async () => {
  // The dispatch used to be a chain testing two method names and falling through to input.plan,
  // so a route added after those two was handed the wrong field and nothing said so. /api/advance
  // received undefined for an afternoon: first silently defaulting, then failing validation, and
  // in both cases looking like a problem with the model rather than with the route table.
  const { routes } = await import('../src/server.mjs');
  for (const [path, route] of routes) {
    if (route.whole) {
      assert.equal(route.field, undefined, `${path} takes the whole body and must not also name a field`);
      continue;
    }
    const declared = Object.keys(route.schema.properties ?? {});
    if (declared.length === 0) {
      assert.equal(route.field, undefined, `${path} declares no fields, so it must not name one`);
      continue;
    }
    assert.ok(route.field, `${path} takes one field but does not say which`);
    assert.ok(declared.includes(route.field),
      `${path} names ${route.field}, which is not in its schema (${declared.join(', ')})`);
  }
});
