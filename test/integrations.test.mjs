import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm, realpath, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeIntegrationTools } from '../src/integrations.mjs';

const credentialName = 'CONCORD_INTEGRATION_TEST_KEY';
const token = 'local-fixture-credential-12345';
const executable = await realpath(process.execPath);
const question = { state: 'A local fixture', questions: { yes: { type: 'noul', instructions: 'Is this a fixture?' } } };
const answer = { model: 'jev-1.13.0', answers: { yes: { type: 'noul', noul: 0.98 } }, usage: { input_tokens: 2, output_tokens: 1 } };
const checkCode = code => error => { assert.equal(error.code, code); assert.ok(!String(error).includes(token)); return true; };

async function httpFixture(handler, fn) {
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const previous = process.env[credentialName];
  process.env[credentialName] = token;
  try { return await fn(origin); }
  finally {
    if (previous === undefined) delete process.env[credentialName]; else process.env[credentialName] = previous;
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}
function typeSafe(origin, extra = {}) {
  return makeIntegrationTools({ typesafe: { origin, model: 'jev-1.13.0', apiKeyEnv: credentialName, ...extra } })[0];
}
const networkContext = (origin, extra = {}) => ({ policy: { allowedOrigins: [origin], ...extra } });
async function processFixture(source, fn) {
  const directory = await mkdtemp(join(tmpdir(), 'concord-integrations-'));
  const script = join(directory, 'worker.mjs');
  await writeFile(script, source, 'utf8');
  const config = { name: 'fixture.worker', version: 'fixture-1', executable, args: [script], timeoutMs: 5000 };
  try { return await fn(config, { workspaceRoot: directory, policy: { allowedEffects: ['process'] } }, directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}
const worker = (config, extra = {}) => makeIntegrationTools({ workers: [{ ...config, ...extra }] })[0];
const executableSha256 = createHash('sha256').update(await readFile(executable)).digest('hex');
const run = (config, extra = {}) => makeIntegrationTools({ processes: [{ ...config, executableSha256, ...extra }] })[0];
async function runFixture(source, fn) {
  const directory = await mkdtemp(join(tmpdir(), 'concord-integrations-run-'));
  const script = join(directory, 'run.mjs');
  await writeFile(script, source, 'utf8');
  const config = { name: 'fixture.process', version: 'fixture-1', executable, args: [script], timeoutMs: 5000 };
  try { return await fn(config, { workspaceRoot: directory, policy: { allowedEffects: ['process'] } }, directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}
function registry(origin, extra = {}) {
  return makeIntegrationTools({ registry: { origin, apiKeyEnv: credentialName, ...extra } })[0];
}
async function batchFixture(sources, fn) {
  const directory = await mkdtemp(join(tmpdir(), 'concord-integrations-batch-'));
  const entries = [];
  for (const [name, source] of Object.entries(sources)) {
    const script = join(directory, `${name}.mjs`);
    await writeFile(script, source, 'utf8');
    entries.push({ name, version: 'fixture-1', executable, args: [script], executableSha256, timeoutMs: 5000 });
  }
  const [tool] = makeIntegrationTools({ processesBatch: entries });
  try { return await fn(tool, { workspaceRoot: directory, policy: { allowedEffects: ['process'] } }, directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

test('registration is data-only and rejects aliases, inline credentials, names and unsafe paths', () => {
  const config = { origin: 'https://api.typesafe.ai', model: 'jev-1.13.0', apiKeyEnv: 'MISSING_TEST_KEY' };
  const tool = makeIntegrationTools({ typesafe: config })[0];
  assert.equal(tool.effect, 'network');
  assert.equal(tool.config.apiKeyEnv, 'MISSING_TEST_KEY');
  assert.ok(Object.isFrozen(tool.config));
  assert.ok(Object.isFrozen(tool.inputSchema));
  assert.throws(() => makeIntegrationTools({ typesafe: { ...config, model: 'jev-latest' } }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => makeIntegrationTools({ typesafe: { ...config, apiKey: token } }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => makeIntegrationTools({ typesafe: { ...config, path: '//elsewhere.test/api' } }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => makeIntegrationTools({ workers: [{ executable: 'node', version: '1' }] }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => makeIntegrationTools({ workers: [{ name: 'worker', executable, version: '1', env: { API_KEY: token } }] }), checkCode('INTEGRATION_CONFIG'));
});

test('TypeSafe makes a real bounded local HTTP request and binds model, state, questions', async () => {
  let received;
  await httpFixture(async (request, response) => {
    assert.equal(request.url, '/v1/systemone');
    assert.equal(request.headers.authorization, `Bearer ${token}`);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks));
    response.end(JSON.stringify(answer));
  }, async origin => {
    const tool = typeSafe(origin);
    assert.deepEqual(await tool.execute(question, networkContext(origin)), answer);
    assert.ok(!JSON.stringify(tool.config).includes(token));
  });
  assert.deepEqual(received, { model: 'jev-1.13.0', ...question });
});

test('HTTP exact-origin allowlist, tool allowlist and effect allowlist are enforced before requests', async () => {
  let hits = 0;
  await httpFixture((request, response) => { hits++; response.end(JSON.stringify(answer)); }, async origin => {
    const tool = typeSafe(origin);
    await assert.rejects(tool.execute(question, networkContext(`${origin}/`)), checkCode('INTEGRATION_ORIGIN'));
    await assert.rejects(tool.execute(question, networkContext(origin, { allowedTools: [] })), checkCode('INTEGRATION_POLICY'));
    await assert.rejects(tool.execute(question, networkContext(origin, { allowedEffects: ['read'] })), checkCode('INTEGRATION_POLICY'));
  });
  assert.equal(hits, 0);
});

test('HTTP never follows redirects or exposes response bodies in errors', async () => {
  let hits = 0;
  await httpFixture((request, response) => {
    hits++;
    response.writeHead(302, { location: '/redirect-target' });
    response.end(token);
  }, async origin => {
    await assert.rejects(typeSafe(origin).execute(question, networkContext(origin)), checkCode('INTEGRATION_HTTP_STATUS'));
  });
  assert.equal(hits, 1);
});

test('HTTP output bound counts bytes and policy limits can lower adapter limits', async () => {
  await httpFixture((request, response) => response.end(JSON.stringify({ padding: 'é'.repeat(128) })), async origin => {
    await assert.rejects(typeSafe(origin).execute(question, networkContext(origin, { maxOutputBytes: 64 })), checkCode('INTEGRATION_OUTPUT_LIMIT'));
  });
});

test('HTTP timeout and cancellation stop requests', async () => {
  await httpFixture(() => {}, async origin => {
    await assert.rejects(typeSafe(origin, { timeoutMs: 25 }).execute(question, networkContext(origin)), checkCode('INTEGRATION_TIMEOUT'));
    const controller = new AbortController();
    const pending = typeSafe(origin).execute(question, { ...networkContext(origin), signal: controller.signal });
    controller.abort();
    await assert.rejects(pending, checkCode('INTEGRATION_ABORTED'));
  });
});

test('TypeSafe rejects malformed and mismatched answers', async () => {
  for (const result of [null, { ...answer, model: 'jev-1.14.0' }, { ...answer, answers: {} }, { ...answer, answers: { yes: { type: 'noul', noul: 2 } } }]) {
    await httpFixture((request, response) => response.end(JSON.stringify(result)), async origin => {
      await assert.rejects(typeSafe(origin).execute(question, networkContext(origin)), checkCode('INTEGRATION_OUTPUT'));
    });
  }
});

test('HTTP rejects invalid UTF-8 JSON and missing credentials without leaking data', async () => {
  await httpFixture((request, response) => response.end(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])), async origin => {
    await assert.rejects(typeSafe(origin).execute(question, networkContext(origin)), checkCode('INTEGRATION_OUTPUT'));
    delete process.env[credentialName];
    await assert.rejects(typeSafe(origin).execute(question, networkContext(origin)), checkCode('INTEGRATION_CREDENTIAL'));
  });
});

test('HTTP rejects duplicate JSON keys before consuming answers', async () => {
  await httpFixture((request, response) => response.end('{"model":"jev-1.13.0","model":"jev-1.13.0","answers":{}}'), async origin => {
    await assert.rejects(typeSafe(origin).execute(question, networkContext(origin)), checkCode('INTEGRATION_OUTPUT'));
  });
});

test('configured credentials echoed by an HTTP endpoint are rejected before journaling', async () => {
  await httpFixture((request, response) => response.end(JSON.stringify({ ...answer, echoed: token })), async origin => {
    await assert.rejects(typeSafe(origin).execute(question, networkContext(origin)), checkCode('INTEGRATION_SECRET'));
  });
});

test('TypeSafe validates choice and score distributions against the requested options', async () => {
  const input = { state: {}, questions: {
    route: { type: 'choice', instructions: 'Choose a route', criteria: { code: 'Write code', inspect: 'Inspect only' } },
    quality: { type: 'score', instructions: 'Rate quality', criteria: ['low', 'high'] },
  } };
  const result = { model: 'jev-1.13.0', answers: {
    route: { type: 'choice', choice: 'code', probabilities: { code: 0.8, inspect: 0.2 }, confidence: 0.6 },
    quality: { type: 'score', score: 0.7, probabilities: { 0: 0.3, 1: 0.7 }, confidence: 0.4 },
  } };
  await httpFixture((request, response) => response.end(JSON.stringify(result)), async origin => {
    assert.deepEqual(await typeSafe(origin).execute(input, networkContext(origin)), result);
    result.answers.route.probabilities.inspect = 2;
    await assert.rejects(typeSafe(origin).execute(input, networkContext(origin)), checkCode('INTEGRATION_OUTPUT'));
  });
});

test('model adapter returns a JSON proposal and never executes its proposed command', async () => {
  let received;
  const proposal = { command: 'this must remain data', plan: { steps: [] } };
  await httpFixture(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks));
    response.end(JSON.stringify({ model: 'local-model-revision-1', choices: [{ message: { content: JSON.stringify(proposal) } }], usage: { total_tokens: 5 } }));
  }, async origin => {
    const tool = makeIntegrationTools({ model: { origin, model: 'local-model-revision-1', apiKeyEnv: credentialName } })[0];
    const result = await tool.execute({ prompt: 'Propose a plan', system: 'Return JSON only' }, networkContext(origin));
    assert.deepEqual(result.proposal, proposal);
  });
  assert.equal(received.model, 'local-model-revision-1');
  assert.equal(received.temperature, 0);
  assert.deepEqual(received.messages.map(message => message.role), ['system', 'user']);
  // The provider is told where to stop. Without this the byte budget was enforced only on the way
  // back, so an open-ended prompt could spend all of it and then fail the turn for exceeding it —
  // which is how a request to list every limitation became a page of cycling synonyms.
  assert.equal(received.max_tokens, Math.floor(1048576 / 4));
});

test('a narrowed output budget lowers the model token ceiling but never to nothing', async () => {
  let received;
  await httpFixture(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks));
    response.end(JSON.stringify({ model: 'local-model-revision-1', choices: [{ message: { content: '{}' } }] }));
  }, async origin => {
    const tool = makeIntegrationTools({ model: { origin, model: 'local-model-revision-1', apiKeyEnv: credentialName } })[0];
    await tool.execute({ prompt: 'Propose a plan' }, networkContext(origin, { maxOutputBytes: 100 }));
  });
  // Derived from the attenuated policy, then floored: a budget this small would otherwise cut off
  // every reply mid-sentence, and a ceiling of twenty-five tokens is not a brake but a gag.
  assert.equal(received.max_tokens, 256);
});

test('subprocess sends one JSON document and receives one JSON document with isolated environment', async () => {
  await processFixture(`let input = ''; for await (const chunk of process.stdin) input += chunk; process.stdout.write(JSON.stringify({ input: JSON.parse(input), cwd: process.cwd(), sentinel: process.env.CONCORD_PRIVATE_SENTINEL ?? null, explicit: process.env.EXPLICIT ?? null }));`, async (config, context, directory) => {
    const previous = process.env.CONCORD_PRIVATE_SENTINEL;
    process.env.CONCORD_PRIVATE_SENTINEL = 'should-not-be-inherited';
    try {
      const result = await worker(config, { env: { EXPLICIT: 'chosen' } }).execute({ value: 'shell; $() & text' }, context);
      assert.deepEqual(result.input, { value: 'shell; $() & text' });
      assert.equal(result.sentinel, null);
      assert.equal(result.explicit, 'chosen');
      assert.equal(result.cwd, await realpath(directory));
    } finally { if (previous === undefined) delete process.env.CONCORD_PRIVATE_SENTINEL; else process.env.CONCORD_PRIVATE_SENTINEL = previous; }
  });
});

test('subprocess rejects nonzero exit, malformed output and combined output overflow', async () => {
  for (const [source, extra, code] of [
    ['process.exit(7)', {}, 'INTEGRATION_EXIT'],
    ['process.stdout.write("not json")', {}, 'INTEGRATION_OUTPUT'],
    ['process.stderr.write("x".repeat(1024)); process.stdout.write("{}")', { maxOutputBytes: 64 }, 'INTEGRATION_OUTPUT_LIMIT'],
  ]) {
    await processFixture(source, async (config, context) => {
      await assert.rejects(worker(config, extra).execute({}, context), checkCode(code));
    });
  }
});

test('subprocess timeout, cancellation, missing executable and digest mismatch are bounded', async () => {
  await processFixture('setInterval(() => {}, 1000)', async (config, context) => {
    await assert.rejects(worker(config, { timeoutMs: 50 }).execute({}, context), checkCode('INTEGRATION_TIMEOUT'));
    const controller = new AbortController();
    const pending = worker(config).execute({}, { ...context, signal: controller.signal });
    setTimeout(() => controller.abort(), 25);
    await assert.rejects(pending, checkCode('INTEGRATION_ABORTED'));
    await assert.rejects(worker(config, { executable: join(context.workspaceRoot, 'missing.exe') }).execute({}, context), checkCode('INTEGRATION_PATH'));
    await assert.rejects(worker(config, { executableSha256: '0'.repeat(64) }).execute({}, context), checkCode('INTEGRATION_EXECUTABLE'));
  });
});

test('subprocess cwd cannot escape the workspace', async () => {
  await processFixture('process.stdout.write("{}")', async (config, context) => {
    await assert.rejects(worker(config, { cwd: '..' }).execute({}, context), checkCode('INTEGRATION_CWD'));
  });
});

test('subprocess passes only named ambient values and refuses echoed credentials', async () => {
  await processFixture('process.stdout.write(JSON.stringify({ selected: process.env.CONCORD_SELECTED ?? null, credential: process.env.CONCORD_API_KEY ?? null }))', async (config, context) => {
    const previousSelected = process.env.CONCORD_SELECTED;
    const previousKey = process.env.CONCORD_API_KEY;
    process.env.CONCORD_SELECTED = 'explicitly-selected';
    process.env.CONCORD_API_KEY = token;
    try {
      const selected = await worker(config, { allowedEnv: ['CONCORD_SELECTED'] }).execute({}, context);
      assert.deepEqual(selected, { selected: 'explicitly-selected', credential: null });
      await assert.rejects(worker(config, { allowedEnv: ['CONCORD_API_KEY'] }).execute({}, context), checkCode('INTEGRATION_SECRET'));
    } finally {
      if (previousSelected === undefined) delete process.env.CONCORD_SELECTED; else process.env.CONCORD_SELECTED = previousSelected;
      if (previousKey === undefined) delete process.env.CONCORD_API_KEY; else process.env.CONCORD_API_KEY = previousKey;
    }
  });
});

test('duplicate names and malformed fixed arguments are rejected', () => {
  const config = { name: 'worker', version: '1', executable, args: [] };
  assert.throws(() => makeIntegrationTools({ workers: [config, config] }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => worker(config, { args: ['valid', 12] }), checkCode('INTEGRATION_CONFIG'));
});

// Regression for a confirmed security review finding: a credential-shaped value under a
// non-keyword env key name (e.g. CONFIG_FLAG set to an AWS access key) must be caught by
// value pattern, not only by the "token/password/secret/apikey" key-name heuristic.
const awsKeyLookingValue = 'AKIAIOSFODNN7EXAMPLE';

test('a credential-shaped literal env value under an innocuous key name is rejected at worker/process.run registration', () => {
  assert.throws(() => worker({ name: 'worker', version: '1', executable, args: [] }, { env: { CONFIG_FLAG: awsKeyLookingValue } }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => run({ name: 'run', version: '1', executable, args: [] }, { env: { CONFIG_FLAG: awsKeyLookingValue } }), checkCode('INTEGRATION_CONFIG'));
});

test('a credential-shaped value reaching the child via allowedEnv under an innocuous name is still redacted if echoed', async () => {
  await processFixture('process.stdout.write(JSON.stringify({ value: process.env.CONFIG_FLAG ?? null }))', async (config, context) => {
    const previous = process.env.CONFIG_FLAG;
    process.env.CONFIG_FLAG = awsKeyLookingValue;
    try { await assert.rejects(worker(config, { allowedEnv: ['CONFIG_FLAG'] }).execute({}, context), checkCode('INTEGRATION_SECRET')); }
    finally { if (previous === undefined) delete process.env.CONFIG_FLAG; else process.env.CONFIG_FLAG = previous; }
  });
  await runFixture('process.stdout.write(process.env.CONFIG_FLAG ?? "")', async (config, context) => {
    const previous = process.env.CONFIG_FLAG;
    process.env.CONFIG_FLAG = awsKeyLookingValue;
    try { await assert.rejects(run(config, { allowedEnv: ['CONFIG_FLAG'] }).execute({}, context), checkCode('INTEGRATION_SECRET')); }
    finally { if (previous === undefined) delete process.env.CONFIG_FLAG; else process.env.CONFIG_FLAG = previous; }
  });
});

test('an allowed ambient value that merely resembles the real value, not a known credential shape, is still delivered unredacted', async () => {
  // Regression guard the other direction: the existing intentional-echo test must keep working —
  // a plain, non-credential-shaped allowed value should never be caught by the broadened check.
  await processFixture('process.stdout.write(JSON.stringify({ value: process.env.CONFIG_FLAG ?? null }))', async (config, context) => {
    const previous = process.env.CONFIG_FLAG;
    process.env.CONFIG_FLAG = 'plainly-not-a-credential';
    try {
      const result = await worker(config, { allowedEnv: ['CONFIG_FLAG'] }).execute({}, context);
      assert.deepEqual(result, { value: 'plainly-not-a-credential' });
    } finally { if (previous === undefined) delete process.env.CONFIG_FLAG; else process.env.CONFIG_FLAG = previous; }
  });
});

test('process.run registration rejects a relative executable, non-array args, credential-named env, and requires an exact digest', () => {
  const base = { name: 'run', version: '1', executable, args: [], executableSha256 };
  assert.throws(() => makeIntegrationTools({ processes: [{ ...base, executable: 'node' }] }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => makeIntegrationTools({ processes: [{ ...base, args: ['ok', 12] }] }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => makeIntegrationTools({ processes: [{ ...base, env: { API_KEY: token } }] }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => makeIntegrationTools({ processes: [{ name: 'run', version: '1', executable, args: [] }] }), checkCode('INTEGRATION_CONFIG'));
  assert.throws(() => makeIntegrationTools({ processes: [base, base] }), checkCode('INTEGRATION_CONFIG'));
  const tool = makeIntegrationTools({ processes: [base] })[0];
  assert.equal(tool.effect, 'process');
  assert.ok(Object.isFrozen(tool.config));
});

test('process.run captures exact stdout, stderr, and exit code; task input never reaches argv', async () => {
  await runFixture('process.stdout.write("out-line\\n"); process.stderr.write("err-line\\n");', async (config, context) => {
    const a = await run(config).execute({}, context);
    const b = await run(config).execute({ ignored: 'anything, even shell; $() syntax' }, context);
    assert.deepEqual(a, { exitCode: 0, signal: null, stdout: 'out-line\n', stderr: 'err-line\n' });
    assert.deepEqual(b, a);
  });
});

test('process.run surfaces a nonzero exit as a distinct, structured failure', async () => {
  await runFixture('process.exitCode = 3;', async (config, context) => {
    await assert.rejects(run(config).execute({}, context), checkCode('INTEGRATION_EXIT'));
  });
});

test('process.run bounds combined stdout/stderr output and rejects non-UTF-8 output', async () => {
  await runFixture('process.stdout.write("x".repeat(1024)); process.stderr.write("y".repeat(1024));', async (config, context) => {
    await assert.rejects(run(config, { maxOutputBytes: 64 }).execute({}, context), checkCode('INTEGRATION_OUTPUT_LIMIT'));
  });
  await runFixture('process.stdout.write(Buffer.from([0xff, 0xfe, 0x80]));', async (config, context) => {
    await assert.rejects(run(config).execute({}, context), checkCode('INTEGRATION_OUTPUT'));
  });
});

test('process.run timeout, cancellation, missing executable, and digest mismatch are bounded', async () => {
  await runFixture('setInterval(() => {}, 1000)', async (config, context) => {
    await assert.rejects(run(config, { timeoutMs: 50 }).execute({}, context), checkCode('INTEGRATION_TIMEOUT'));
    const controller = new AbortController();
    const pending = run(config).execute({}, { ...context, signal: controller.signal });
    setTimeout(() => controller.abort(), 25);
    await assert.rejects(pending, checkCode('INTEGRATION_ABORTED'));
    await assert.rejects(run(config, { executable: join(context.workspaceRoot, 'missing.exe') }).execute({}, context), checkCode('INTEGRATION_PATH'));
    await assert.rejects(run(config, { executableSha256: '0'.repeat(64) }).execute({}, context), checkCode('INTEGRATION_EXECUTABLE'));
  });
});

test('process.run cwd cannot escape the workspace', async () => {
  await runFixture('process.stdout.write("")', async (config, context) => {
    await assert.rejects(run(config, { cwd: '..' }).execute({}, context), checkCode('INTEGRATION_CWD'));
  });
});

test('process.run passes only named ambient values and refuses echoed credentials', async () => {
  await runFixture('process.stdout.write(process.env.CONCORD_RUN_SELECTED ?? "")', async (config, context) => {
    const previousSelected = process.env.CONCORD_RUN_SELECTED;
    process.env.CONCORD_RUN_SELECTED = 'explicitly-selected';
    try {
      const result = await run(config, { allowedEnv: ['CONCORD_RUN_SELECTED'] }).execute({}, context);
      assert.equal(result.stdout, 'explicitly-selected');
    } finally {
      if (previousSelected === undefined) delete process.env.CONCORD_RUN_SELECTED; else process.env.CONCORD_RUN_SELECTED = previousSelected;
    }
  });
  await runFixture('process.stdout.write(process.env.CONCORD_RUN_TOKEN ?? "")', async (config, context) => {
    const previousToken = process.env.CONCORD_RUN_TOKEN;
    process.env.CONCORD_RUN_TOKEN = token;
    try { await assert.rejects(run(config, { allowedEnv: ['CONCORD_RUN_TOKEN'] }).execute({}, context), checkCode('INTEGRATION_SECRET')); }
    finally { if (previousToken === undefined) delete process.env.CONCORD_RUN_TOKEN; else process.env.CONCORD_RUN_TOKEN = previousToken; }
  });
});

test('process.runMany executes selected entries concurrently, not sequentially', async () => {
  await batchFixture({
    a: 'await new Promise(r => setTimeout(r, 300)); process.stdout.write("a-done");',
    b: 'await new Promise(r => setTimeout(r, 300)); process.stdout.write("b-done");',
  }, async (tool, context) => {
    const start = Date.now();
    const output = await tool.execute({ names: ['a', 'b'] }, context);
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 550, `expected concurrent children to finish in ~300ms, took ${elapsed}ms`);
    const byName = Object.fromEntries(output.results.map(r => [r.name, r]));
    assert.equal(byName.a.stdout, 'a-done');
    assert.equal(byName.b.stdout, 'b-done');
  });
});

test('one failing or timing-out child does not suppress the others\' results', async () => {
  await batchFixture({
    good: 'process.stdout.write("ok");',
    bad: 'process.exitCode = 3;',
  }, async (tool, context) => {
    const output = await tool.execute({ names: ['good', 'bad'] }, context);
    const byName = Object.fromEntries(output.results.map(r => [r.name, r]));
    assert.equal(byName.good.stdout, 'ok');
    assert.equal(byName.bad.failed, true);
    assert.equal(byName.bad.code, 'INTEGRATION_EXIT');
  });
});

test('per-child output budget is the aggregate policy budget divided by the selected count', async () => {
  await batchFixture({
    small: 'process.stdout.write("x".repeat(100));',
    big: 'process.stdout.write("y".repeat(600));',
  }, async (tool, context) => {
    const bounded = { ...context, policy: { ...context.policy, maxOutputBytes: 1000 } }; // 500 bytes/child after division
    const output = await tool.execute({ names: ['small', 'big'] }, bounded);
    const byName = Object.fromEntries(output.results.map(r => [r.name, r]));
    assert.equal(byName.small.stdout, 'x'.repeat(100));
    assert.equal(byName.big.failed, true);
    assert.equal(byName.big.code, 'INTEGRATION_OUTPUT_LIMIT');
  });
});

test('an unknown requested name is rejected before any process launches', async () => {
  await batchFixture({ a: 'process.stdout.write("should not run");' }, async (tool, context) => {
    await assert.rejects(() => tool.execute({ names: ['does-not-exist'] }, context), { code: 'SCHEMA_MISMATCH' });
  });
});

test('abort kills every still-running child in the batch', async () => {
  await batchFixture({
    a: 'await new Promise(r => setTimeout(r, 5000)); process.stdout.write("should not finish");',
    b: 'await new Promise(r => setTimeout(r, 5000)); process.stdout.write("should not finish");',
  }, async (tool, context) => {
    const controller = new AbortController();
    const promise = tool.execute({ names: ['a', 'b'] }, { ...context, signal: controller.signal });
    setTimeout(() => controller.abort(), 100);
    const output = await promise;
    const byName = Object.fromEntries(output.results.map(r => [r.name, r]));
    assert.equal(byName.a.failed, true);
    assert.equal(byName.a.code, 'INTEGRATION_ABORTED');
    assert.equal(byName.b.failed, true);
    assert.equal(byName.b.code, 'INTEGRATION_ABORTED');
  });
});

const components = { components: [{ name: 'accordion', registryPath: 'r/shadcn/accordion', dependencies: ['radix-ui'] }] };

test('the UI component registry client makes a real bounded local HTTP request and enforces a real response schema', async () => {
  let received;
  await httpFixture(async (request, response) => {
    assert.equal(request.url, '/v1/components/search');
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks));
    response.end(JSON.stringify(components));
  }, async origin => {
    const result = await registry(origin).execute({ query: 'accordion' }, networkContext(origin));
    assert.deepEqual(result, components);
  });
  assert.deepEqual(received, { query: 'accordion', limit: 10 });
});

test('the registry client rejects a response that is not a real schema-conforming component list', async () => {
  for (const bad of [
    { components: 'not an array' },
    { components: [{ registryPath: 'r/x' }] },
    { components: [{ name: 'x', registryPath: 'r/x', dependencies: [1, 2] }] },
    { components: [{ name: 'x', registryPath: 'r/x' }, { name: 'y', registryPath: 'r/y' }, { name: 'z', registryPath: 'r/z' }] },
  ]) {
    await httpFixture((request, response) => response.end(JSON.stringify(bad)), async origin => {
      await assert.rejects(registry(origin).execute({ query: 'x', limit: 2 }, networkContext(origin)), checkCode('INTEGRATION_OUTPUT'));
    });
  }
});

test('the registry client rejects an empty or overlong query before any request is made', async () => {
  let hits = 0;
  await httpFixture(() => { hits++; }, async origin => {
    await assert.rejects(registry(origin).execute({ query: '' }, networkContext(origin)), () => true);
    await assert.rejects(registry(origin).execute({ query: 'x'.repeat(5000) }, networkContext(origin)), () => true);
  });
  assert.equal(hits, 0);
});

test('the registry client enforces the exact-origin allowlist and rejects credential echoes', async () => {
  await httpFixture((request, response) => response.end(JSON.stringify(components)), async origin => {
    await assert.rejects(registry(origin).execute({ query: 'x' }, networkContext(`${origin}/`)), checkCode('INTEGRATION_ORIGIN'));
  });
  await httpFixture((request, response) => response.end(JSON.stringify({ components: [], echoed: token })), async origin => {
    await assert.rejects(registry(origin).execute({ query: 'x' }, networkContext(origin)), checkCode('INTEGRATION_SECRET'));
  });
});

/**
 * A streamed reply is not the reply.
 *
 * Every token arrives inside its own `data: {...}` frame, so counting wire bytes against
 * maxOutputBytes charged the text budget for framing it never produced. Only the streaming path
 * was affected, which meant the chat UI -- it always streams, because it passes onProgress -- had
 * a far smaller real ceiling than the CLI running the identical adapter. Measured live against a
 * local qwen3: three turns failed INTEGRATION_OUTPUT_LIMIT for replies nowhere near the limit.
 */
const modelTool = (origin, extra = {}) =>
  makeIntegrationTools({ model: { origin, model: 'fixture-1', apiKeyEnv: credentialName, path: '/v1/chat/completions', ...extra } })[0];

/**
 * One frame per eight characters, which is roughly how a server batches tokens and already
 * enough for the envelope to cost several times the text it carries.
 */
function sseFor(text) {
  const frames = [];
  for (let i = 0; i < text.length; i += 8) {
    frames.push(`data: ${JSON.stringify({ model: 'fixture-1', choices: [{ index: 0, finish_reason: null, delta: { content: text.slice(i, i + 8) } }] })}\n\n`);
  }
  return frames.join('') + 'data: [DONE]\n\n';
}

test('a streamed reply is bounded by its text, not by the framing around it', async () => {
  const reply = JSON.stringify({ reply: 'x'.repeat(2000) });
  const body = sseFor(reply);
  // The framing really does dominate: this is the whole point of the fix.
  assert.ok(body.length > reply.length * 5, 'the framing really does cost several times the text');

  await httpFixture((request, response) => {
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.end(body);
  }, async (origin) => {
    // A budget comfortably above the text and well below the wire bytes. Before the fix this
    // combination was exactly what failed.
    const tool = modelTool(origin, { maxOutputBytes: 8192 });
    const progress = [];
    const result = await tool.execute({ prompt: 'hello' }, {
      ...networkContext(origin),
      onProgress: (update) => progress.push(update.phase),
    });
    assert.equal(result.proposal.reply, 'x'.repeat(2000));
    assert.ok(progress.includes('drafting'), 'it really did take the streaming path');
  });
});

test('a streamed reply whose text exceeds the budget is still refused', async () => {
  // The bound did not go away, it moved to where the text is. Reasoning counts toward it: that is
  // generation the model spent, and the budget is about what it produced rather than about which
  // half survives into the reply.
  const body = sseFor(JSON.stringify({ reply: 'y'.repeat(20000) }));
  await httpFixture((request, response) => {
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.end(body);
  }, async (origin) => {
    // Chosen so the TEXT bound is what fires: the wire body stays under the raw ceiling.
    const tool = modelTool(origin, { maxOutputBytes: 8192 });
    assert.ok(body.length < 8192 * 64, 'the raw ceiling must not be what refuses this');
    await assert.rejects(
      tool.execute({ prompt: 'hello' }, { ...networkContext(origin), onProgress: () => {} }),
      checkCode('INTEGRATION_OUTPUT_LIMIT'));
  });
});

test('a non-streamed reply is still bounded by the raw body exactly as before', async () => {
  // The two bounds coincide when the body IS the text, so nothing changed for this path.
  const payload = JSON.stringify({ model: 'fixture-1', choices: [{ message: { content: JSON.stringify({ reply: 'z'.repeat(20000) }) } }] });
  await httpFixture((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(payload);
  }, async (origin) => {
    const tool = modelTool(origin, { maxOutputBytes: 4096 });
    await assert.rejects(
      tool.execute({ prompt: 'hello' }, networkContext(origin)),
      checkCode('INTEGRATION_OUTPUT_LIMIT'));
  });
});

/**
 * Stopping because the room ran out, not because the work was done.
 *
 * Measured by replaying a failed turn against the local model: finish_reason "length",
 * completion_tokens exactly max_tokens, 116,017 characters of reasoning and zero content. It
 * surfaced as INTEGRATION_OUTPUT, "no message content" - true, and useless, because it reads as a
 * broken provider when the provider did exactly what it was told.
 */
function sseWithFinish(reasoning, content, finishReason) {
  const frames = [];
  for (let i = 0; i < reasoning.length; i += 8) {
    frames.push(`data: ${JSON.stringify({ model: 'fixture-1', choices: [{ index: 0, delta: { reasoning_content: reasoning.slice(i, i + 8) } }] })}\n\n`);
  }
  for (let i = 0; i < content.length; i += 8) {
    frames.push(`data: ${JSON.stringify({ model: 'fixture-1', choices: [{ index: 0, delta: { content: content.slice(i, i + 8) } }] })}\n\n`);
  }
  frames.push(`data: ${JSON.stringify({ model: 'fixture-1', choices: [{ index: 0, finish_reason: finishReason, delta: {} }] })}\n\n`);
  return frames.join('') + 'data: [DONE]\n\n';
}

test('a model that reasons until its budget is gone says so, rather than looking broken', async () => {
  const body = sseWithFinish('t'.repeat(2000), '', 'length');
  await httpFixture((request, response) => {
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.end(body);
  }, async (origin) => {
    const tool = modelTool(origin, { maxOutputBytes: 65536 });
    await assert.rejects(
      tool.execute({ prompt: 'something hard' }, { ...networkContext(origin), onProgress: () => {} }),
      (error) => {
        assert.equal(error.code, 'INTEGRATION_TRUNCATED');
        // The number is the diagnosis: it says where the budget went.
        assert.match(error.message, /2000 characters of reasoning/);
        assert.doesNotMatch(error.message, /retry/i, 'repeating it unchanged is exactly the wrong response');
        return true;
      });
  });
});

test('a truncated reply that did answer is kept, because the answer is judgeable', async () => {
  // finish_reason length only matters when nothing came of it. A model cut off after producing a
  // usable proposal has still produced one, and the caller validates it like any other.
  const body = sseWithFinish('t'.repeat(100), JSON.stringify({ reply: 'partial but present' }), 'length');
  await httpFixture((request, response) => {
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.end(body);
  }, async (origin) => {
    const tool = modelTool(origin, { maxOutputBytes: 65536 });
    const result = await tool.execute({ prompt: 'x' }, { ...networkContext(origin), onProgress: () => {} });
    assert.equal(result.proposal.reply, 'partial but present');
  });
});

test('a normal stop is untouched by the truncation check', async () => {
  const body = sseWithFinish('t'.repeat(50), JSON.stringify({ reply: 'done properly' }), 'stop');
  await httpFixture((request, response) => {
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.end(body);
  }, async (origin) => {
    const tool = modelTool(origin, { maxOutputBytes: 65536 });
    const result = await tool.execute({ prompt: 'x' }, { ...networkContext(origin), onProgress: () => {} });
    assert.equal(result.proposal.reply, 'done properly');
  });
});
