import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseJson, digest } from '../src/value.mjs';
import { createMcpServer } from '../src/mcp.mjs';
import { fileMessage } from '../src/peer.mjs';
import { loadSourceLock } from '../src/sources.mjs';
import { tempDir } from './temp-workspace.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));

function startMcpServer(workspaceRoot, extraArgs = []) {
  // Each session gets its own exchange directory. Sharing the live one would make the pushed
  // tool description depend on whatever the operator happens to have asked.
  const child = spawn(process.execPath, [path.join(root, 'src', 'mcp.mjs'), '--workspace', workspaceRoot, '--mailbox', path.join(workspaceRoot, 'exchange'), ...extraArgs], { stdio: ['pipe', 'pipe', 'pipe'], cwd: root });
  const stdoutLines = [];
  const pending = new Map();
  let buffered = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => {
    buffered += chunk.toString('utf8');
    let boundary;
    while ((boundary = buffered.indexOf('\n')) >= 0) {
      const line = buffered.slice(0, boundary);
      buffered = buffered.slice(boundary + 1);
      if (!line.trim()) continue;
      stdoutLines.push(line);
      let message;
      try { message = JSON.parse(line); } catch { continue; }
      if (message && typeof message === 'object' && Object.hasOwn(message, 'id') && pending.has(message.id)) {
        const resolve = pending.get(message.id);
        pending.delete(message.id);
        resolve(message);
      }
    }
  });
  child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
  let nextId = 1;
  function request(method, params) {
    const id = nextId++;
    return new Promise((resolve) => {
      pending.set(id, resolve);
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }
  function notify(method, params) {
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  }
  function sendRaw(text) { child.stdin.write(text + '\n'); }
  function sendBytes(buffer) { child.stdin.write(buffer); }
  async function close() {
    child.stdin.end();
    await Promise.race([new Promise((resolve) => child.once('exit', resolve)), new Promise((resolve) => setTimeout(resolve, 1000))]);
    try { child.kill(); } catch { /* already exited */ }
  }
  return { child, request, notify, sendRaw, sendBytes, stdoutLines, close, stderr: () => stderr };
}

async function handshake(session) {
  const response = await session.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'concord-mcp-test', version: '0.0.1' } });
  session.notify('notifications/initialized');
  return response;
}

async function waitForNextLine(session, timeoutMs = 3000) {
  const start = session.stdoutLines.length;
  const deadline = Date.now() + timeoutMs;
  while (session.stdoutLines.length === start) {
    if (Date.now() > deadline) throw new Error('Timed out waiting for a new stdout line');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Every line this server ever writes to stdout must be a well-formed JSON-RPC envelope. */
function assertStdoutIsPureJsonRpc(session) {
  for (const line of session.stdoutLines) {
    const message = parseJson(line);
    assert.equal(message.jsonrpc, '2.0');
    // A server-initiated notification is a well-formed envelope with a method and no id. The
    // server emits one when the exchange changes, which is how it reaches an idle client at all.
    if (!Object.hasOwn(message, 'id')) {
      assert.equal(typeof message.method, 'string');
      continue;
    }
    assert.notEqual(Object.hasOwn(message, 'result'), Object.hasOwn(message, 'error'));
  }
}

async function withSession(prefix, run) {
  const temp = tempDir(prefix);
  const session = startMcpServer(temp);
  try {
    await run(session, temp);
    assertStdoutIsPureJsonRpc(session);
  } finally {
    await session.close();
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

test('handshake negotiates the protocol version and never responds to a notification', async () => {
  await withSession('concord-mcp-handshake-', async (session) => {
    const init = await handshake(session);
    assert.equal(init.result.protocolVersion, '2025-06-18');
    assert.equal(init.result.serverInfo.name, 'concord');
    assert.ok(init.result.capabilities.tools);
    assert.ok(init.result.capabilities.resources);
    // Declared true because it is true: the answering tool's description changes as questions
    // arrive, and a client told the list never changes has no reason to re-read it.
    assert.equal(init.result.capabilities.tools.listChanged, true);

    const before = session.stdoutLines.length;
    session.notify('notifications/initialized');
    const ping = await session.request('ping', {});
    assert.deepEqual(ping.result, {});
    // Exactly one new line appeared: ping's own response. The notification produced none.
    assert.equal(session.stdoutLines.length, before + 1);
    assert.equal(JSON.parse(session.stdoutLines.at(-1)).id, ping.id);
  });
});

test('tools/list exposes only policy-visible tools, every name MCP-safe, with the five chat tools present', async () => {
  await withSession('concord-mcp-list-', async (session) => {
    await handshake(session);
    const list = await session.request('tools/list');
    const names = list.result.tools.map((t) => t.name);
    assert.ok(names.every((n) => /^[a-zA-Z0-9_-]+$/.test(n)));
    assert.equal(new Set(names).size, names.length);
    for (const chatName of ['concord_chat', 'concord_approve', 'concord_execute_plan', 'concord_replay', 'concord_chat_state']) {
      assert.ok(names.includes(chatName));
    }
    assert.ok(names.includes('files_write'));
    assert.ok(names.includes('sources_catalog'));
    const jsonValue = list.result.tools.find((t) => t.name === 'json_value');
    assert.deepEqual(jsonValue.inputSchema, { type: 'object', properties: { value: {} }, required: ['value'], additionalProperties: false });
  });
});

test('a pure tool call executes immediately and matches an independently computed digest', async () => {
  await withSession('concord-mcp-pure-', async (session) => {
    await handshake(session);
    const call = await session.request('tools/call', { name: 'json_hash', arguments: { value: { a: 1, b: [1, 2, 3] } } });
    assert.equal(call.result.isError, undefined);
    const body = JSON.parse(call.result.content[0].text);
    assert.equal(body.digest, digest({ a: 1, b: [1, 2, 3] }));
  });
});

test('a write effect blocks with a requestHash, executes once confirmed, and refuses a stale confirm', async () => {
  await withSession('concord-mcp-write-', async (session, temp) => {
    await handshake(session);
    const propose = await session.request('tools/call', { name: 'files_write', arguments: { path: 'round.json', content: { v: 1 } } });
    assert.equal(propose.result.isError, undefined);
    const proposed = JSON.parse(propose.result.content[0].text);
    assert.equal(proposed.status, 'blocked');
    assert.equal(proposed.tool, 'files.write');
    assert.equal(proposed.effect, 'write');
    assert.match(proposed.requestHash, /^[a-f0-9]{64}$/);
    assert.equal(fs.existsSync(path.join(temp, 'round.json')), false);

    const confirm = await session.request('tools/call', { name: 'files_write', arguments: { path: 'round.json', content: { v: 1 }, _confirm: proposed.requestHash } });
    assert.equal(confirm.result.isError, undefined);
    const confirmed = JSON.parse(confirm.result.content[0].text);
    assert.equal(confirmed.created, true);
    assert.equal(fs.existsSync(path.join(temp, 'round.json')), true);

    // Repeating the SAME request with the same hash is not a stale confirm, it is the same
    // request: the hash is derived from the content, so identical bytes mean this grant still
    // describes exactly what is on disk. It is a no-op, and `created` says so.
    const again = await session.request('tools/call', { name: 'files_write', arguments: { path: 'round.json', content: { v: 1 }, _confirm: proposed.requestHash } });
    assert.equal(again.result.isError, undefined);
    assert.equal(JSON.parse(again.result.content[0].text).created, false);

    // A genuinely stale confirm is a hash that does not bind this call. Still refused, which is
    // the property this test is named for: a grant is for one exact request, not for a path.
    const stale = await session.request('tools/call', { name: 'files_write', arguments: { path: 'round.json', content: { v: 2 }, _confirm: proposed.requestHash } });
    const staleBody = JSON.parse(stale.result.content[0].text);
    assert.equal(staleBody.status, 'blocked', 'a hash bound to different content grants nothing');
    assert.notEqual(staleBody.requestHash, proposed.requestHash);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(temp, 'round.json'), 'utf8')), { v: 1 }, 'and nothing was overwritten');
  });
});

/**
 * A delegate session: the workspace is the delegate's, and the grants file lives beside it, not
 * in it — which is the arrangement the mode requires.
 */
async function withDelegateSession(prefix, run) {
  const outer = tempDir(prefix);
  const workspace = path.join(outer, 'workspace');
  fs.mkdirSync(workspace);
  const grants = path.join(outer, 'grants.json');
  const session = startMcpServer(workspace, ['--grants', grants]);
  try {
    await run(session, { workspace, grants, requests: `${grants}.requests.jsonl` });
    assertStdoutIsPureJsonRpc(session);
  } finally {
    await session.close();
    fs.rmSync(outer, { recursive: true, force: true });
  }
}

const writeArgs = { path: 'out.json', content: { v: 1 } };

test('a delegate cannot approve its own effect by echoing the hash back', async () => {
  await withDelegateSession('concord-mcp-delegate-self-', async (session, { workspace, requests }) => {
    const init = await handshake(session);
    assert.match(init.result.instructions, /DELEGATE/, 'the delegate is told what it is at the first message');

    const propose = await session.request('tools/call', { name: 'files_write', arguments: writeArgs });
    const proposed = JSON.parse(propose.result.content[0].text);
    assert.equal(proposed.status, 'blocked');

    // The move that makes an ordinary session's gate a formality for an autonomous agent.
    const selfConfirm = await session.request('tools/call', { name: 'files_write', arguments: { ...writeArgs, _confirm: proposed.requestHash } });
    const refused = JSON.parse(selfConfirm.result.content[0].text);
    assert.equal(refused.status, 'blocked');
    assert.equal(refused.code, 'DELEGATE_UNGRANTED');
    assert.equal(fs.existsSync(path.join(workspace, 'out.json')), false, 'nothing was written');

    // The parent reviews what was asked for from a record, not from the delegate's account of it.
    const logged = fs.readFileSync(requests, 'utf8').trim().split('\n').map((line) => parseJson(line));
    assert.equal(logged.length, 1, 'one request, recorded once however often it is retried');
    assert.equal(logged[0].requestHash, proposed.requestHash);
    assert.equal(logged[0].tool, 'files.write');
    assert.equal(logged[0].effect, 'write');
  });
});

test('a grant the parent writes takes effect on the next attempt, and only for that exact request', async () => {
  await withDelegateSession('concord-mcp-delegate-grant-', async (session, { workspace, grants }) => {
    await handshake(session);
    const proposed = JSON.parse((await session.request('tools/call', { name: 'files_write', arguments: writeArgs })).result.content[0].text);

    // The parent grants while the delegate session is still running: no restart.
    fs.writeFileSync(grants, JSON.stringify({ grants: [proposed.requestHash] }));
    const confirmed = await session.request('tools/call', { name: 'files_write', arguments: { ...writeArgs, _confirm: proposed.requestHash } });
    assert.equal(confirmed.result.isError, undefined);
    assert.equal(JSON.parse(confirmed.result.content[0].text).created, true);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(workspace, 'out.json'), 'utf8')), { v: 1 });

    // A granted hash cannot be spent on different content: the kernel still requires it to bind
    // the exact request, so the grant is for one write, not for a path.
    const other = await session.request('tools/call', { name: 'files_write', arguments: { path: 'other.json', content: { v: 2 }, _confirm: proposed.requestHash } });
    assert.equal(JSON.parse(other.result.content[0].text).status, 'blocked');
    assert.equal(fs.existsSync(path.join(workspace, 'other.json')), false);
  });
});

test('a malformed or revoked grants file grants nothing', async () => {
  await withDelegateSession('concord-mcp-delegate-revoke-', async (session, { workspace, grants }) => {
    await handshake(session);
    const proposed = JSON.parse((await session.request('tools/call', { name: 'files_write', arguments: writeArgs })).result.content[0].text);

    // Unparseable must fail closed, not open.
    fs.writeFileSync(grants, '{ "grants": [ not json');
    const malformed = JSON.parse((await session.request('tools/call', { name: 'files_write', arguments: { ...writeArgs, _confirm: proposed.requestHash } })).result.content[0].text);
    assert.equal(malformed.code, 'DELEGATE_UNGRANTED');

    // Granted and then withdrawn before use: withdrawal is honoured because the file is re-read.
    fs.writeFileSync(grants, JSON.stringify({ grants: [proposed.requestHash] }));
    fs.writeFileSync(grants, JSON.stringify({ grants: [] }));
    const revoked = JSON.parse((await session.request('tools/call', { name: 'files_write', arguments: { ...writeArgs, _confirm: proposed.requestHash } })).result.content[0].text);
    assert.equal(revoked.code, 'DELEGATE_UNGRANTED');
    assert.equal(fs.existsSync(path.join(workspace, 'out.json')), false);
  });
});

test('the chat-harness approval route is closed to a delegate too', async () => {
  await withDelegateSession('concord-mcp-delegate-chat-', async (session) => {
    await handshake(session);
    const approve = await session.request('tools/call', { name: 'concord_approve', arguments: { requestHash: 'a'.repeat(64) } });
    assert.equal(approve.result.isError, true);
    assert.equal(JSON.parse(approve.result.content[0].text).code, 'DELEGATE_UNGRANTED');
  });
});

test('a grants file inside the delegate workspace is refused at startup', async () => {
  const workspace = tempDir('concord-mcp-delegate-inside-');
  try {
    // Concord's file tools reach anywhere in the workspace, so a grants file there is one the
    // delegate could write for itself. The server must not start rather than run that way.
    const { createDelegateGrants } = await import('../src/mcp.mjs');
    const real = fs.realpathSync(workspace);
    assert.throws(() => createDelegateGrants(path.join(real, 'grants.json'), real), { code: 'MCP_CONFIG' });
    assert.throws(() => createDelegateGrants(path.join(real, 'nested', '..', 'grants.json'), real), { code: 'MCP_CONFIG' });
    const outside = createDelegateGrants(path.join(path.dirname(real), 'grants.json'), real);
    assert.equal(outside.granted('a'.repeat(64)), false, 'absent file grants nothing');
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

async function withAutonomousSession(prefix, run, { policy, logIsDirectory = false } = {}) {
  const outer = tempDir(prefix);
  const workspace = path.join(outer, 'workspace');
  fs.mkdirSync(workspace);
  const log = path.join(outer, 'autonomy.jsonl');
  if (logIsDirectory) fs.mkdirSync(log);
  const extra = ['--autonomous', log];
  if (policy) {
    const policyFile = path.join(outer, 'policy.json');
    fs.writeFileSync(policyFile, JSON.stringify(policy));
    extra.push('--policy', policyFile);
  }
  const session = startMcpServer(workspace, extra);
  try {
    await run(session, { workspace, log });
    assertStdoutIsPureJsonRpc(session);
  } finally {
    await session.close();
    fs.rmSync(outer, { recursive: true, force: true });
  }
}

const readLog = (file) => fs.readFileSync(file, 'utf8').trim().split('\n').map((line) => parseJson(line));

test('an autonomous delegate acts in one call, and every act is on the record', async () => {
  await withAutonomousSession('concord-mcp-auto-act-', async (session, { workspace, log }) => {
    const init = await handshake(session);
    assert.match(init.result.instructions, /AUTONOMOUS DELEGATE/);

    // No propose, no _confirm: the effect happens on the first call.
    const call = await session.request('tools/call', { name: 'files_write', arguments: writeArgs });
    assert.equal(call.result.isError, undefined);
    const body = JSON.parse(call.result.content[0].text);
    assert.equal(body.created, true);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(workspace, 'out.json'), 'utf8')), { v: 1 });

    // Intent before, outcome after, tied together by the exact hash the kernel computed.
    const [intent, outcome] = readLog(log);
    assert.equal(intent.phase, 'intent');
    assert.equal(intent.tool, 'files.write');
    assert.equal(intent.effect, 'write');
    assert.deepEqual(intent.input, writeArgs);
    assert.match(intent.requestHash, /^[a-f0-9]{64}$/);
    assert.equal(outcome.phase, 'outcome');
    assert.equal(outcome.requestHash, intent.requestHash);
    assert.equal(outcome.status, 'completed');
    assert.equal(outcome.outputDigest, digest(body), 'the log can be checked against what the caller was given');
  });
});

test('the policy is the whole boundary on what an autonomous delegate may do', async () => {
  const policy = {
    version: 1, allowedTools: ['files.writeText', 'files.read'], allowedEffects: ['pure', 'read', 'write'],
    allowedOrigins: [], maxTasks: 4, maxOutputBytes: 65536, maxJournalBytes: 1048576, timeoutMs: 30000,
  };
  await withAutonomousSession('concord-mcp-auto-policy-', async (session, { workspace }) => {
    await handshake(session);
    const listed = await session.request('tools/list', {});
    const names = listed.result.tools.map((tool) => tool.name);
    assert.ok(names.includes('files_writeText'));
    // Autonomy is not authority: a tool outside the policy is not merely refused, it is not there.
    assert.ok(!names.includes('files_delete'));
    assert.ok(!names.includes('files_write'));
    const outside = await session.request('tools/call', { name: 'files_delete', arguments: { path: 'anything' } });
    assert.ok(outside.error || outside.result?.isError, 'a tool the policy leaves out cannot be called');
    // The server keeps its own run store and exchange in the workspace; nothing else may appear.
    assert.deepEqual(fs.readdirSync(workspace).filter((name) => !['exchange', 'runs'].includes(name)), []);
  }, { policy });
});

test('no record, no effect: an autonomous write is refused if the log cannot be written', async () => {
  await withAutonomousSession('concord-mcp-auto-nolog-', async (session, { workspace }) => {
    await handshake(session);
    const call = await session.request('tools/call', { name: 'files_write', arguments: writeArgs });
    assert.equal(call.result.isError, true);
    assert.equal(JSON.parse(call.result.content[0].text).code, 'DELEGATE_LOG_UNAVAILABLE');
    assert.equal(fs.existsSync(path.join(workspace, 'out.json')), false, 'the effect was not performed');
  }, { logIsDirectory: true });
});

test('the autonomy log must be outside the workspace, and the two delegate modes are exclusive', async () => {
  const workspace = tempDir('concord-mcp-auto-inside-');
  try {
    const { createAutonomousLog } = await import('../src/mcp.mjs');
    const real = fs.realpathSync(workspace);
    // Inside, the delegate could rewrite the record of what it did.
    assert.throws(() => createAutonomousLog(path.join(real, 'autonomy.jsonl'), real), { code: 'MCP_CONFIG' });
    assert.equal(createAutonomousLog(path.join(path.dirname(real), 'autonomy.jsonl'), real).mode, 'autonomous');

    const both = spawn(process.execPath, [path.join(root, 'src', 'mcp.mjs'), '--workspace', real,
      '--grants', path.join(path.dirname(real), 'g.json'), '--autonomous', path.join(path.dirname(real), 'a.jsonl')], { stdio: ['pipe', 'pipe', 'pipe'], cwd: root });
    const exitCode = await new Promise((resolve) => both.once('exit', resolve));
    assert.notEqual(exitCode, 0, 'asking for supervised and autonomous at once is refused, not resolved by precedence');
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test('an ordinary session keeps the two-step confirm exactly as before', async () => {
  await withSession('concord-mcp-not-delegate-', async (session, temp) => {
    const init = await handshake(session);
    assert.doesNotMatch(init.result.instructions, /DELEGATE/);
    const proposed = JSON.parse((await session.request('tools/call', { name: 'files_write', arguments: writeArgs })).result.content[0].text);
    const confirmed = JSON.parse((await session.request('tools/call', { name: 'files_write', arguments: { ...writeArgs, _confirm: proposed.requestHash } })).result.content[0].text);
    assert.equal(confirmed.created, true);
    assert.equal(fs.existsSync(path.join(temp, 'out.json')), true);
  });
});

test('the propose-call plan shape is a byte-identical constant: same call -> same hash, different call -> different hash', async () => {
  await withSession('concord-mcp-shape-', async (session) => {
    await handshake(session);
    const a1 = await session.request('tools/call', { name: 'files_write', arguments: { path: 'a.json', content: { v: 1 } } });
    const a2 = await session.request('tools/call', { name: 'files_write', arguments: { path: 'a.json', content: { v: 1 } } });
    const b1 = await session.request('tools/call', { name: 'files_write', arguments: { path: 'b.json', content: { v: 2 } } });
    const hashA1 = JSON.parse(a1.result.content[0].text).requestHash;
    const hashA2 = JSON.parse(a2.result.content[0].text).requestHash;
    const hashB1 = JSON.parse(b1.result.content[0].text).requestHash;
    assert.equal(hashA1, hashA2);
    assert.notEqual(hashA1, hashB1);
  });
});

test('an unknown tool name is rejected as an invalid param, not a crash', async () => {
  await withSession('concord-mcp-unknown-', async (session) => {
    await handshake(session);
    const call = await session.request('tools/call', { name: 'does_not_exist', arguments: {} });
    assert.equal(call.error.code, -32602);
  });
});

test('a nested $task reference in raw tool input fails closed as a graceful isError, not a crash', async () => {
  await withSession('concord-mcp-taskref-', async (session) => {
    await handshake(session);
    const call = await session.request('tools/call', { name: 'json_hash', arguments: { value: { $task: 'x' } } });
    assert.equal(call.result.isError, true);
    const body = JSON.parse(call.result.content[0].text);
    assert.equal(body.code, 'INVALID_REFERENCE');

    const ping = await session.request('ping', {});
    assert.deepEqual(ping.result, {});
  });
});

test('malformed and adversarial JSON-RPC input fails closed without crashing the server', async () => {
  await withSession('concord-mcp-malformed-', async (session) => {
    await handshake(session);

    session.sendRaw('{not json at all');
    await waitForNextLine(session);
    let last = JSON.parse(session.stdoutLines.at(-1));
    assert.equal(last.error.code, -32700);
    assert.equal(last.id, null);

    session.sendRaw('"just a string"');
    await waitForNextLine(session);
    last = JSON.parse(session.stdoutLines.at(-1));
    assert.equal(last.error.code, -32600);
    assert.equal(last.id, null);

    session.sendRaw(JSON.stringify({ id: 77, params: {} })); // missing jsonrpc/method
    await waitForNextLine(session);
    last = JSON.parse(session.stdoutLines.at(-1));
    assert.equal(last.error.code, -32600);
    assert.equal(last.id, 77);

    session.sendRaw('{"jsonrpc":"2.0","id":78,"method":"ping","id":78}'); // duplicate key -> strict parse failure
    await waitForNextLine(session);
    last = JSON.parse(session.stdoutLines.at(-1));
    assert.equal(last.error.code, -32700);

    session.sendBytes(Buffer.from([0xff, 0xfe, 0x0a])); // invalid UTF-8 terminated by a newline
    await waitForNextLine(session);
    last = JSON.parse(session.stdoutLines.at(-1));
    assert.equal(last.error.code, -32700);

    const ping = await session.request('ping', {});
    assert.deepEqual(ping.result, {});
  });
});

test('resources expose all reviewed instruction modules with digests matching the manifest', async () => {
  const manifest = parseJson(fs.readFileSync(path.join(root, 'instructions', 'manifest.json'), 'utf8'));
  await withSession('concord-mcp-resources-', async (session) => {
    await handshake(session);
    const list = await session.request('resources/list');
    // Filtered by kind rather than counted whole: the server also publishes its app surface as a
    // ui:// resource, and a bare length check would make "a resource of another kind exists" look
    // like "an instruction module is missing".
    const instructions = list.result.resources.filter((resource) => resource.uri.startsWith('concord://instructions/'));
    assert.equal(instructions.length, manifest.modules.length);
    for (const resource of instructions) {
      assert.match(resource.uri, /^concord:\/\/instructions\/[a-z0-9-]+$/);
      assert.equal(resource.mimeType, 'text/markdown');
    }

    // The app surface, at exactly the MIME type the MCP Apps extension requires.
    const apps = list.result.resources.filter((resource) => resource.uri.startsWith('ui://'));
    assert.deepEqual(apps.map((resource) => resource.uri), ['ui://concord/chat']);
    assert.equal(apps[0].mimeType, 'text/html;profile=mcp-app');
    const app = await session.request('resources/read', { uri: 'ui://concord/chat' });
    assert.equal(app.result.contents[0].mimeType, 'text/html;profile=mcp-app');
    // Self-contained: a host renders this in a sandbox, so a reference it would have to fetch is
    // a reference that silently does not load.
    assert.equal(/\bsrc=|\bhref=/.test(app.result.contents[0].text), false);
    const [first] = manifest.modules;
    const read = await session.request('resources/read', { uri: `concord://instructions/${first.sourceId}` });
    const text = read.result.contents[0].text;
    assert.equal(createHash('sha256').update(text, 'utf8').digest('hex'), first.sha256);

    const missing = await session.request('resources/read', { uri: 'concord://instructions/not-a-real-source' });
    assert.equal(missing.error.code, -32002);
  });
});

test('a chat turn with no model configured refuses, and the state wrapper still answers', async () => {
  // There is no demonstration mode: this session is spawned without --integrations, so nothing
  // registers model.propose and a turn has nothing to propose with. Refusing is the whole point
  // -- answering from pure tools would look like the harness was working when it was not.
  await withSession('concord-mcp-chat-', async (session) => {
    await handshake(session);
    const chat = await session.request('tools/call', { name: 'concord_chat', arguments: { message: 'Explain what Concord combines.' } });
    assert.equal(chat.result.isError, true);
    assert.equal(JSON.parse(chat.result.content[0].text).code, 'CHAT_NO_MODEL');

    // The read-only wrapper is unaffected: state, runs and receipts stay inspectable with no
    // model registered, which is why the refusal is raised per turn rather than at startup.
    const state = await session.request('tools/call', { name: 'concord_chat_state', arguments: {} });
    assert.equal(state.result.isError, undefined);
    const stateBody = JSON.parse(state.result.content[0].text);
    assert.deepEqual(stateBody.state.history, []);
    assert.deepEqual(stateBody.state.runs, []);

    // And the replay wrapper refuses an id it has never recorded rather than inventing a verdict.
    // Replay of a real run over the wire is covered in test/server.test.mjs, which can register
    // an in-process model fixture; this session is a real subprocess and cannot.
    const replay = await session.request('tools/call', { name: 'concord_replay', arguments: { runId: 'never-recorded' } });
    assert.equal(replay.result.isError, true);
    assert.equal(JSON.parse(replay.result.content[0].text).code, 'CHAT_REPLAY');
  });
});

test('createMcpServer rejects a dotted/underscored tool-name collision at construction, not at first call', () => {
  const stubTool = (name) => ({ name, version: '1.0.0', effect: 'pure', inputSchema: { type: 'object', properties: {}, additionalProperties: false }, execute() { return {}; } });
  const registry = new Map([['a.b', stubTool('a.b')], ['a_b', stubTool('a_b')]]);
  const policy = { version: 1, allowedTools: ['a.b', 'a_b'], allowedEffects: ['pure'], allowedOrigins: [], maxTasks: 10, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 10000 };
  const stubHarness = { send: async () => ({}), approve: async () => ({}), executePlan: async () => ({}), replay: async () => ({}), snapshot: () => ({}) };
  assert.throws(
    () => createMcpServer({ registry, policy, sourceLock: catalog, workspaceRoot: root, harness: stubHarness, instructionModules: [] }),
    (error) => error.code === 'MCP_CONFIG',
  );
});

test('a question asked in Concord reaches an idle client, unprompted, in a tool description', async () => {
  await withSession('concord-mcp-push-', async (session, temp) => {
    await handshake(session);
    const exchange = path.join(temp, 'exchange');

    const before = (await session.request('tools/list')).result.tools.find((tool) => tool.name === 'concord_answer');
    assert.ok(before, 'the answering tool is published whenever an exchange is configured');
    assert.match(before.description, /Nothing is waiting/);

    // The operator types in Concord's own chat box. This client asks for nothing.
    const asked = fileMessage(exchange, { message: 'Does this reach you with nobody polling?', audience: 'agent' });

    // MCP gives a server no way to put text in a client's model context unless that client
    // declares sampling, and neither Anthropic client does. A tool description is model-visible
    // text, and listChanged invites the client to re-read it: that is the push.
    const deadline = Date.now() + 5000;
    let notified = false;
    while (!notified && Date.now() < deadline) {
      notified = session.stdoutLines.some((line) => parseJson(line).method === 'notifications/tools/list_changed');
      if (!notified) await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(notified, true, 'the server speaks first when the exchange changes');

    const after = (await session.request('tools/list')).result.tools.find((tool) => tool.name === 'concord_answer');
    assert.notEqual(after.description, before.description);
    // Carrying the question itself, not merely the fact that one exists: a notification without
    // content is an alarm, not a message.
    assert.match(after.description, /Does this reach you with nobody polling\?/);
    assert.match(after.description, new RegExp('#' + asked.seq));

    // And the same tool is how the agent answers, which closes the question.
    const answered = await session.request('tools/call', { name: 'concord_answer', arguments: { seq: asked.seq, answer: 'It did.' } });
    assert.equal(JSON.parse(answered.result.content[0].text).answered, asked.seq);
    const cleared = (await session.request('tools/list')).result.tools.find((tool) => tool.name === 'concord_answer');
    assert.match(cleared.description, /Nothing is waiting/);

    for (const bad of [{ seq: 1 }, { answer: 'x' }, { seq: 99999, answer: 'x' }]) {
      const refused = await session.request('tools/call', { name: 'concord_answer', arguments: bad });
      assert.ok(refused.error || refused.result.isError, 'an answer to nothing is refused');
    }
  });
});
