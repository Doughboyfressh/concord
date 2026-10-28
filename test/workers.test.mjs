import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { makeAgentTools } from '../src/workers.mjs';
import { canonical, digest, validateSchema } from '../src/value.mjs';

// The fixture is our own protocol peer, not downloaded upstream code.
const fixture = `
import { createInterface } from 'node:readline';
import { spawn } from 'node:child_process';
const rl = createInterface({ input: process.stdin });
const mode = process.env.FIXTURE_CASE ?? 'ok';
let initialized, sessionId, step = 0;
const send = message => process.stdout.write(JSON.stringify(message) + '\\n');
const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
const notify = (method, params) => send({ jsonrpc: '2.0', method, params });
rl.on('line', line => {
  const message = JSON.parse(line);
  const expected = ['initialize', 'session/prompt', 'session/wait', 'shutdown'][step++];
  if (message.method !== expected) throw new Error('Wrong lifecycle order');
  if (mode === 'hang') return;
  if (mode === 'early-exit') { process.exit(0); return; }
  if (mode === 'rpc-error') {
    send({ jsonrpc: '2.0', id: message.id, error: { code: -32603, message: 'sensitive-runtime-diagnostic' } }); return;
  }
  if (mode === 'malformed') { process.stdout.write('not json\\n'); return; }
  if (mode === 'duplicate-key') { process.stdout.write('{"jsonrpc":"2.0","id":1,"id":1,"result":{}}\\n'); return; }
  if (mode === 'unterminated') { process.stdout.write('{"jsonrpc":"2.0"}'); process.exit(0); return; }
  if (mode === 'unknown-id') { reply(999, {}); return; }
  if (mode === 'server-request') { send({ jsonrpc: '2.0', id: 9, method: 'approval/request', params: {} }); return; }
  if (mode === 'unknown-notification') { notify('unknown', {}); return; }
  if (mode === 'stdout-flood') { process.stdout.write('x'.repeat(100000)); return; }
  if (mode === 'stderr-flood') { process.stderr.write('x'.repeat(100000)); return; }
  if (mode === 'invalid-utf8') { process.stdout.write(Buffer.from([0xff, 0x0a])); return; }
  if (message.method === 'initialize') {
    initialized = message.params;
    reply(message.id, { serverInfo: { name: mode === 'wrong-server' ? 'other-server' : 'deepseek-harness-sdk-runtime', version: '0.0.1',
      ...(mode === 'secret-key-echo' ? { [process.env.TEST_API_KEY]: 'server echo' } : {}) } });
  } else if (message.method === 'session/prompt') {
    sessionId = message.params.sessionId;
    if (message.params.contentBlocks.length !== 1 || message.params.contentBlocks[0].type !== 'text') throw new Error('Wrong content blocks');
    reply(message.id, mode === 'bad-receipt' ? {} : { messageId: 'message-1' });
  } else if (message.method === 'session/wait') {
    if (message.params.sessionId !== sessionId) throw new Error('Wrong wait identity');
    notify('session.event', { sessionId, event: { type: 'fixture/context', initialize: initialized,
      env: { ambient: process.env.CONCORD_AMBIENT_TEST ?? null, explicit: process.env.EXPLICIT_VALUE ?? null, home: process.env.DSH_HOME },
      secret: process.env.TEST_API_KEY ?? null, authorization: 'Bearer fixture-authorization',
      ...(mode === 'secret-key-echo' ? { [process.env.TEST_API_KEY]: 'key echo' } : {}),
      ...(mode === 'secret-key-collision' ? { [process.env.TEST_API_KEY]: 'one', '[redacted]': 'two' } : {}) } });
    notify('subagent.started', { parentSessionId: sessionId, childSessionId: 'child-1' });
    notify('session.event', { sessionId: 'child-1', event: { type: 'assistant/message', text: 'child output' } });
    notify('subagent.finished', { parentSessionId: sessionId, childSessionId: 'child-1', provider: 'fixture', agentId: 'child-1', status: 'ok', stopReason: 'completed' });
    notify('session.event', { sessionId, event: { type: 'assistant/message', text: 'Hello, 世界' } });
    notify('session.status', { sessionId, status: 'idle' });
    process.stderr.write('fixture diagnostics ' + (process.env.TEST_API_KEY ?? 'none'));
    reply(message.id, mode === 'bad-wait' ? { unexpected: true } : {});
  } else {
    if (mode === 'shutdown-hang') return;
    reply(message.id, {});
    if (mode === 'inherited-pipes') {
      spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 6000)'], { stdio: ['ignore', 1, 2], env: {}, windowsHide: true }).unref();
      process.exit(0);
    }
    if (mode === 'nonzero-exit') process.exitCode = 7;
  }
});
`;

async function setup(t, mode = 'ok', extra = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'concord-worker-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const script = path.join(root, 'peer.mjs');
  await writeFile(script, fixture);
  const settings = {
    binary: process.execPath, args: [script], home: path.join(root, 'dsh-home'), provider: 'fixture-provider', model: 'fixture-model',
    env: { FIXTURE_CASE: mode, EXPLICIT_VALUE: 'explicit', ...extra.env },
    reasoningEffort: 'max', maxTokens: 1024, ...extra,
  };
  const [tool] = makeAgentTools({ dsh: settings });
  const context = { workspaceRoot: root, policy: { timeoutMs: 5000, maxOutputBytes: 32768 } };
  return { root, settings, tool, context, input: { prompt: 'Hello fixture', sessionId: 'session-1' } };
}

// A stand-in for `codex exec` / `claude -p`: reads the whole prompt from stdin, writes an
// answer, and exits with whatever code the case asks for. Deliberately not a protocol peer —
// the point of the cli adapter is that there is no handshake to rely on.
const cliFixture = `
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  const mode = process.env.CLI_CASE ?? 'ok';
  if (mode === 'hang') { setTimeout(() => {}, 60000); return; }
  if (mode === 'flood') { process.stdout.write('x'.repeat(200000)); process.exit(0); }
  if (mode === 'fail') { process.stderr.write('agent refused: ' + process.env.SECRET_VALUE); process.exit(3); }
  if (mode === 'json') { process.stdout.write(JSON.stringify({ result: 'answer for: ' + input.trim() })); process.exit(0); }
  process.stdout.write('echo: ' + input.trim());
  process.exit(0);
});
`;

async function cliSetup(t, mode = 'ok', extra = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'concord-cli-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const script = path.join(root, 'agent.mjs');
  await writeFile(script, cliFixture);
  const settings = {
    adapter: 'cli', binary: process.execPath, args: [script],
    env: { CLI_CASE: mode, SECRET_VALUE: 'super-secret-token', ...extra.env },
    ...extra,
  };
  const [tool] = makeAgentTools({ dsh: { name: 'agent.run', ...settings } });
  const context = { workspaceRoot: root, policy: { timeoutMs: 5000, maxOutputBytes: 32768 } };
  return { root, tool, context, input: { prompt: 'do the thing', sessionId: 'session-1' } };
}

test('a cli agent is given the prompt on stdin and its answer is recorded', async t => {
  const { tool, context, input } = await cliSetup(t);
  assert.equal(tool.effect, 'process', 'spawning an agent is a gated effect like any other');
  const result = await tool.execute(input, context);
  assert.equal(result.adapter, 'cli');
  assert.equal(result.exitCode, 0);
  // The prompt reached the child, which is the whole point: the model supplies this, argv does not.
  assert.equal(result.stdout, 'echo: do the thing');
  assert.equal(result.truncated, false);
  assert.ok(result.limitations.some(line => /does not control/.test(line)));
  assert.ok(result.limitations.some(line => /not in this journal/.test(line)), 'the gate hole is stated, not hidden');
});

test('a cli agent that fails is evidence, not an exception', async t => {
  // processRun's contract throws on non-zero exit. That would discard the stderr explaining
  // why the agent refused, which is the only useful thing about a failed delegation.
  const { tool, context, input } = await cliSetup(t, 'fail');
  const result = await tool.execute(input, context);
  assert.equal(result.exitCode, 3);
  assert.match(result.stderr, /agent refused/);
  // Configured environment values are redacted out of the child's own output.
  assert.doesNotMatch(canonical(result), /super-secret-token/);
});

test('a cli answer is extracted only where the operator said it lives', async t => {
  const plain = await cliSetup(t, 'json');
  const withoutPath = await plain.tool.execute(plain.input, plain.context);
  assert.equal(withoutPath.answer, undefined, 'no resultPath means no guessing at another agent output shape');

  const pointed = await cliSetup(t, 'json', { resultPath: '/result' });
  const withPath = await pointed.tool.execute(pointed.input, pointed.context);
  assert.equal(withPath.answer, 'answer for: do the thing');
});

test('a cli agent is bounded in bytes, in time, and by abort', async t => {
  const flood = await cliSetup(t, 'flood');
  const bounded = await flood.tool.execute(flood.input, flood.context);
  assert.equal(bounded.truncated, true, 'a prefix is reported as a prefix');
  assert.ok(bounded.stdoutBytes <= flood.context.policy.maxOutputBytes);
  assert.ok(bounded.limitations.some(line => /byte budget/.test(line)));

  const slow = await cliSetup(t, 'hang');
  await assert.rejects(
    slow.tool.execute(slow.input, { ...slow.context, policy: { timeoutMs: 300, maxOutputBytes: 32768 } }),
    { code: 'WORKER_TIMEOUT' });

  const aborting = await cliSetup(t, 'hang');
  const controller = new AbortController();
  const running = aborting.tool.execute(aborting.input, { ...aborting.context, signal: controller.signal });
  controller.abort();
  await assert.rejects(running, { code: 'WORKER_ABORTED' });
});

test('a cli service needs no dsh home, provider or model, and an acp service must name its agent', () => {
  // Those three are what DSH needs, and they stay required of DSH.
  assert.throws(() => makeAgentTools({ dsh: { adapter: 'dsh', binary: process.execPath } }), { code: 'WORKER_CONFIG' });
  // A cli agent takes its model from its own configuration, so demanding them here would have
  // made the fields decorative.
  assert.deepEqual(makeAgentTools({ dsh: { adapter: 'cli', binary: process.execPath } }).length, 2);
  // An acp agent is pinned to an identity the operator states, the same discipline dsh applies.
  assert.throws(() => makeAgentTools({ dsh: { adapter: 'acp', binary: process.execPath } }), { code: 'WORKER_CONFIG' });
  assert.deepEqual(makeAgentTools({ dsh: { adapter: 'acp', binary: process.execPath, agentName: 'hermes-agent' } }).length, 2);
});

test('registration is optional, strict, immutable, and binds explicit configuration without exposing environment values', async t => {
  assert.deepEqual(makeAgentTools(), []);
  assert.throws(() => makeAgentTools({ hermes: {} }), { code: 'SCHEMA_MISMATCH' });
  assert.throws(() => makeAgentTools({ dsh: { binary: 'dsh', home: '/home', provider: 'p', model: 'm' } }), { code: 'WORKER_CONFIG' });
  const run = await setup(t, 'ok', { env: { EXPLICIT_VALUE: 'before', TEST_API_KEY: 'fixture-secret-value' } });
  assert.equal(run.tool.effect, 'process');
  assert.equal(run.tool.name, 'dsh.run');
  validateSchema(run.input, run.tool.inputSchema);
  assert.ok(Object.isFrozen(run.tool.config));
  assert.equal(canonical(run.tool.config).includes('fixture-secret-value'), false);
  assert.equal(run.tool.config.environmentHash, digest(run.settings.env));
  const binding = canonical(run.tool.config);
  run.settings.env.EXPLICIT_VALUE = 'after'; run.settings.args.push('untrusted');
  assert.equal(canonical(run.tool.config), binding);
  const output = await run.tool.execute(run.input, run.context);
  assert.equal(output.notifications[0].params.event.env.explicit, 'before');
  assert.equal(canonical(output).includes('fixture-secret-value'), false);
  assert.equal(output.notifications[0].params.event.secret, '[redacted]');
  assert.equal(output.notifications[0].params.event.authorization, '[redacted]');
});

test('an array of named dsh services registers one tool per service plus a shared dsh.catalog', () => {
  const base = { binary: process.execPath, args: ['peer.mjs'], home: path.join(tmpdir(), 'dsh-home-a'), provider: 'fixture-provider' };
  const tools = makeAgentTools({ dsh: [
    { ...base, name: 'dsh.research.run', model: 'research-model', version: '2.0.0' },
    { ...base, name: 'dsh.coder.run', model: 'coder-model' },
  ] });
  assert.deepEqual(tools.map(t => t.name).sort(), ['dsh.catalog', 'dsh.coder.run', 'dsh.research.run']);
  assert.equal(tools.find(t => t.name === 'dsh.research.run').version, '2.0.0');
  assert.equal(tools.find(t => t.name === 'dsh.coder.run').version, '1.0.0'); // defaulted
  const catalog = tools.find(t => t.name === 'dsh.catalog');
  assert.equal(catalog.effect, 'pure');
  const output = catalog.execute({}, {});
  // `adapter` is reported now that a service can be dsh, acp or cli: which kind a service is
  // decides what a caller can expect back from it, so discovery has to say which.
  assert.deepEqual(output.services, [
    { adapter: 'dsh', name: 'dsh.coder.run', version: '1.0.0', provider: 'fixture-provider', model: 'coder-model' },
    { adapter: 'dsh', name: 'dsh.research.run', version: '2.0.0', provider: 'fixture-provider', model: 'research-model' },
  ]);
  assert.equal(canonical(output).includes(base.home), false);
  assert.equal(canonical(output).includes(process.execPath), false);
});

test('duplicate dsh service names are rejected at registration', () => {
  const base = { binary: process.execPath, args: [], home: path.join(tmpdir(), 'dsh-home-b'), provider: 'p', model: 'm' };
  assert.throws(() => makeAgentTools({ dsh: [{ ...base, name: 'dsh.run' }, { ...base, name: 'dsh.run' }] }), { code: 'WORKER_CONFIG' });
});

test('an array entry without a name, or an invalid name, is rejected at registration', () => {
  const base = { binary: process.execPath, args: [], home: path.join(tmpdir(), 'dsh-home-c'), provider: 'p', model: 'm' };
  assert.throws(() => makeAgentTools({ dsh: [base] }), { code: 'WORKER_CONFIG' });
  assert.throws(() => makeAgentTools({ dsh: [{ ...base, name: 'bad name with spaces' }] }), { code: 'WORKER_CONFIG' });
});

test('DSH executes the exact initialize, prompt, wait, shutdown lifecycle and records session evidence', async t => {
  const run = await setup(t);
  const previous = process.env.CONCORD_AMBIENT_TEST;
  process.env.CONCORD_AMBIENT_TEST = 'must-not-inherit';
  t.after(() => { if (previous === undefined) delete process.env.CONCORD_AMBIENT_TEST; else process.env.CONCORD_AMBIENT_TEST = previous; });
  const output = await run.tool.execute(run.input, run.context);
  const requests = output.transcript.filter(row => row.direction === 'sent').map(row => row.message);
  assert.deepEqual(requests.map(row => row.method), ['initialize', 'session/prompt', 'session/wait', 'shutdown']);
  assert.deepEqual(requests.map(row => row.id), [1, 2, 3, 4]);
  assert.deepEqual(requests[0].params, { cwd: output.cwd, provider: 'fixture-provider', model: 'fixture-model', reasoningEffort: 'max', maxTokens: 1024 });
  assert.deepEqual(requests[1].params, { sessionId: 'session-1', contentBlocks: [{ type: 'text', text: 'Hello fixture' }] });
  assert.deepEqual(requests[2].params, { sessionId: 'session-1' });
  assert.equal(Object.hasOwn(requests[3], 'params'), false);
  assert.equal(output.messageId, 'message-1');
  assert.equal(output.notifications[0].params.event.env.ambient, null);
  assert.equal(output.notifications[0].params.event.env.home, run.settings.home);
  assert.equal(output.notifications.at(-2).params.event.text, 'Hello, 世界');
  assert.equal(output.notifications.at(-1).params.status, 'idle');
  assert.equal(output.exitCode, 0);
  assert.match(output.transcriptHash, /^[a-f0-9]{64}$/);
  assert.match(output.stderrSha256, /^[a-f0-9]{64}$/);
  assert.ok(output.stderrBytes > 0);
  assert.equal(Object.hasOwn(output, 'stderr'), false);
});

test('workspace resolution allows contained directories and rejects traversal', async t => {
  const run = await setup(t);
  await mkdir(path.join(run.root, 'nested'));
  const output = await run.tool.execute({ ...run.input, workdir: 'nested' }, run.context);
  assert.equal(output.cwd, path.join(run.root, 'nested'));
  await assert.rejects(run.tool.execute({ ...run.input, workdir: '..' }, run.context), { code: 'WORKER_WORKSPACE' });
});

test('workspace resolution rejects an escaping filesystem junction when the platform permits its creation', async t => {
  const run = await setup(t);
  const outside = await mkdtemp(path.join(tmpdir(), 'concord-worker-outside-'));
  t.after(() => rm(outside, { recursive: true, force: true }));
  try { await symlink(outside, path.join(run.root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) {
    if (['EPERM', 'ENOTSUP', 'EACCES'].includes(error.code)) { t.skip('This sandbox does not permit filesystem junction creation'); return; }
    throw error;
  }
  await assert.rejects(run.tool.execute({ ...run.input, workdir: 'escape' }, run.context), { code: 'WORKER_WORKSPACE' });
});

test('unsafe environment injection, ambiguous names, and mutable environment home are rejected', () => {
  const base = { binary: process.execPath, home: path.resolve('work/dsh'), provider: 'p', model: 'm' };
  for (const env of [{ NODE_OPTIONS: '--import attacker.mjs' }, { node_path: 'untrusted' }, { LD_AUDIT: 'audit-library.so' }, { GCONV_PATH: 'loader-modules' }, { DSH_HOME: 'elsewhere' }, { PATH: 'a', Path: 'b' }, { VALID: '\0' }]) {
    assert.throws(() => makeAgentTools({ dsh: { ...base, env } }), { code: 'WORKER_CONFIG' });
  }
});

test('credential keys are redacted recursively and collisions fail closed', async t => {
  const run = await setup(t, 'secret-key-echo', { env: { FIXTURE_CASE: 'secret-key-echo', TEST_API_KEY: 'credential-value-that-must-not-leak' } });
  const output = await run.tool.execute(run.input, run.context);
  assert.equal(canonical(output).includes(run.settings.env.TEST_API_KEY), false);
  assert.equal(output.notifications[0].params.event['[redacted]'], 'key echo');
  const collision = await setup(t, 'secret-key-collision', { env: { FIXTURE_CASE: 'secret-key-collision', TEST_API_KEY: 'credential-value-that-must-not-leak' } });
  await assert.rejects(collision.tool.execute(collision.input, collision.context), { code: 'WORKER_REDACTION' });
});

test('short secrets do not corrupt fixed protocol identifiers or hash commitments', async t => {
  const run = await setup(t, 'ok', { env: { TEST_API_KEY: 'a' } });
  const output = await run.tool.execute(run.input, run.context);
  assert.equal(output.protocol, 'dsh-sdk-jsonrpc/86a402200d95fecef4529d969836f1fe13c6cb0d');
  assert.equal(output.serverInfo.name, 'deepseek-harness-sdk-runtime');
  assert.match(output.transcriptHash, /^[a-f0-9]{64}$/);
  assert.match(output.stderrSha256, /^[a-f0-9]{64}$/);
  assert.equal(output.transcript[0].direction, 'sent');
  assert.equal(output.transcript[0].message.jsonrpc, '2.0');
  assert.equal(output.transcript[0].message.method, 'initialize');
  assert.equal(Object.hasOwn(output.transcript[0].message, 'params'), true);
  assert.equal(output.notifications[0].method, 'session.event');
  assert.equal(Object.hasOwn(output.notifications[0], 'params'), true);
});

test('unconfirmed closure releases owned handles when a descendant retains stdio', async t => {
  const run = await setup(t, 'inherited-pipes');
  const moduleUrl = pathToFileURL(path.resolve('src/workers.mjs')).href;
  const client = `import { makeAgentTools } from ${JSON.stringify(moduleUrl)};
    const [tool] = makeAgentTools({ dsh: ${JSON.stringify(run.settings)} });
    try { await tool.execute(${JSON.stringify(run.input)}, ${JSON.stringify({ ...run.context, policy: { timeoutMs: 500, maxOutputBytes: 32768 } })}); console.log('no-retained-pipes'); }
    catch (error) { if (error.code !== 'WORKER_TERMINATION_UNCONFIRMED') process.exitCode = 4; else console.log('released-retained-pipes'); }`;
  // The child deliberately does not call process.exit(): referenced pipe handles
  // would keep it alive past this bound even after its invocation rejects.
  const result = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', client], { timeout: 3500, windowsHide: true, env: {} });
  if (result.stdout.trim() === 'no-retained-pipes') { t.skip('This host closes inherited pipes when the direct worker exits'); return; }
  assert.equal(result.stdout.trim(), 'released-retained-pipes');
});

for (const mode of ['malformed', 'duplicate-key', 'unknown-id', 'server-request', 'unknown-notification', 'invalid-utf8', 'wrong-server', 'bad-receipt', 'bad-wait', 'unterminated', 'early-exit']) {
  test('fails closed on protocol violation: ' + mode, async t => {
    const run = await setup(t, mode);
    await assert.rejects(run.tool.execute(run.input, run.context), { code: 'WORKER_PROTOCOL' });
  });
}

test('runtime errors expose a numeric code without copying sensitive diagnostic text', async t => {
  const run = await setup(t, 'rpc-error');
  await assert.rejects(run.tool.execute(run.input, run.context), error => {
    assert.equal(error.code, 'WORKER_RPC');
    assert.deepEqual(error.details, { rpcCode: -32603 });
    assert.equal(canonical({ message: error.message, details: error.details }).includes('sensitive-runtime-diagnostic'), false);
    return true;
  });
});

for (const mode of ['stdout-flood', 'stderr-flood']) {
  test('bounds combined worker output: ' + mode, async t => {
    const run = await setup(t, mode);
    run.context.policy.maxOutputBytes = 4096;
    await assert.rejects(run.tool.execute(run.input, run.context), { code: 'WORKER_OUTPUT_LIMIT' });
  });
}

for (const mode of ['hang', 'shutdown-hang']) {
  test('bounds the entire lifecycle including shutdown: ' + mode, async t => {
    const run = await setup(t, mode);
    run.context.policy.timeoutMs = 500;
    await assert.rejects(run.tool.execute(run.input, run.context), { code: 'WORKER_TIMEOUT' });
  });
}

test('abort before spawn and during execution rejects and requests direct child termination', async t => {
  const run = await setup(t, 'hang');
  const before = new AbortController(); before.abort();
  await assert.rejects(run.tool.execute(run.input, { ...run.context, signal: before.signal }), { code: 'WORKER_ABORTED' });
  const during = new AbortController();
  const timer = setTimeout(() => during.abort(), 200);
  t.after(() => clearTimeout(timer));
  await assert.rejects(run.tool.execute(run.input, { ...run.context, signal: during.signal }), { code: 'WORKER_ABORTED' });
});

test('nonzero exit and missing executable cannot appear as successful worker evidence', async t => {
  const run = await setup(t, 'nonzero-exit');
  await assert.rejects(run.tool.execute(run.input, run.context), { code: 'WORKER_EXIT' });
  const [missing] = makeAgentTools({ dsh: { ...run.settings, binary: path.join(run.root, 'missing-executable') } });
  await assert.rejects(missing.execute(run.input, run.context), { code: 'WORKER_START' });
});

test('request and final evidence budgets and malformed timeout policy are enforced', async t => {
  const run = await setup(t);
  await assert.rejects(run.tool.execute({ ...run.input, sessionId: '../outside' }, run.context), { code: 'WORKER_INPUT' });
  await assert.rejects(run.tool.execute({ ...run.input, prompt: 'x'.repeat(10000) }, { ...run.context, policy: { timeoutMs: 5000, maxOutputBytes: 2048 } }), { code: 'WORKER_INPUT_LIMIT' });
  await assert.rejects(run.tool.execute(run.input, { ...run.context, policy: { timeoutMs: 5000, maxOutputBytes: 2500 } }), { code: 'WORKER_OUTPUT_LIMIT' });
  await assert.rejects(run.tool.execute(run.input, { ...run.context, policy: { timeoutMs: 0, maxOutputBytes: 4096 } }), { code: 'WORKER_POLICY' });
});
