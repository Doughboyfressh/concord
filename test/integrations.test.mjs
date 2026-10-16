import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm, realpath } from 'node:fs/promises';
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
