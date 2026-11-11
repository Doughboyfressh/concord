import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createClientChannel, makePeerTools, makeMailboxTools } from '../src/peer.mjs';
import { createMcpServer } from '../src/mcp.mjs';
import { tempDir } from './temp-workspace.mjs';

// The other direction of the MCP session: Concord asking, the client answering. Every test drives
// the protocol directly, so none of this needs a transport or a real client.

const CLIENT = { protocolVersion: '2025-06-18', clientInfo: { name: 'probe', version: '2.0.0' }, capabilities: { sampling: {}, roots: { listChanged: false } } };
const byName = (tools) => new Map(tools.map((t) => [t.name, t]));
const context = { policy: { timeoutMs: 5000, maxOutputBytes: 1048576 } };

/** A channel plus the lines it wrote, and a way to answer the last question it asked. */
function harness(clientParams = CLIENT) {
  const sent = [];
  const channel = createClientChannel({ send: (line) => sent.push(JSON.parse(line)), timeoutMs: 5000 });
  if (clientParams) channel.rememberClient(clientParams);
  const answerLast = (result) => {
    const request = sent.filter((m) => Object.hasOwn(m, 'id')).at(-1);
    return channel.deliver({ jsonrpc: '2.0', id: request.id, result });
  };
  const refuseLast = (error) => {
    const request = sent.filter((m) => Object.hasOwn(m, 'id')).at(-1);
    return channel.deliver({ jsonrpc: '2.0', id: request.id, error });
  };
  return { channel, sent, answerLast, refuseLast, tools: byName(makePeerTools({ channel })) };
}

test('a request to the client is answered by the matching response and nothing else', async () => {
  const { channel, sent, answerLast } = harness();
  const pending = channel.request('sampling/createMessage', { messages: [] });
  assert.equal(channel.pendingCount(), 1);
  assert.equal(sent.at(-1).method, 'sampling/createMessage');
  assert.equal(sent.at(-1).jsonrpc, '2.0');
  // The id is namespaced, because the client numbers its own requests and the two schemes must
  // never meet.
  assert.match(String(sent.at(-1).id), /^concord-\d+$/);

  // Nothing else claims this response: not another id, not a request, not a notification.
  assert.equal(channel.deliver({ jsonrpc: '2.0', id: 'concord-999', result: {} }), false);
  assert.equal(channel.deliver({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }), false);
  assert.equal(channel.deliver({ jsonrpc: '2.0', method: 'notifications/initialized' }), false);
  assert.equal(channel.deliver(null), false);
  assert.equal(channel.pendingCount(), 1);

  assert.equal(answerLast({ ok: true }), true);
  assert.deepEqual(await pending, { ok: true });
  assert.equal(channel.pendingCount(), 0);
  // A late duplicate of an answered response is not routed twice.
  assert.equal(channel.deliver({ jsonrpc: '2.0', id: sent.at(-1).id, result: { ok: false } }), false);
});

test('a client that refuses, stalls, or is cancelled fails the request instead of hanging', async () => {
  const { channel, refuseLast } = harness();

  const refused = channel.request('sampling/createMessage', {});
  refuseLast({ code: -32601, message: 'This client does not do that' });
  await assert.rejects(refused, (e) => e.code === 'PEER_REFUSED' && e.message === 'This client does not do that');

  const quick = createClientChannel({ send: () => {}, timeoutMs: 20 });
  quick.rememberClient(CLIENT);
  // The channel's deadline timer is unref'd and this channel has no transport holding the event
  // loop open, so keep it alive until the deadline fires or the runner cancels the rest of the file.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    await assert.rejects(quick.request('sampling/createMessage', {}), (e) => e.code === 'PEER_TIMEOUT');
  } finally { clearInterval(keepAlive); }
  assert.equal(quick.pendingCount(), 0);

  const controller = new AbortController();
  const cancelled = channel.request('sampling/createMessage', {}, { signal: controller.signal });
  controller.abort();
  await assert.rejects(cancelled, (e) => e.code === 'PEER_ABORTED');

  // A channel whose transport is gone reports that rather than waiting on a line nobody read.
  const broken = createClientChannel({ send: () => { throw new Error('pipe closed'); } });
  broken.rememberClient(CLIENT);
  await assert.rejects(broken.request('sampling/createMessage', {}), (e) => e.code === 'PEER_TRANSPORT');

  // Unbounded in-flight questions would be a way to make the client the bottleneck.
  const busy = createClientChannel({ send: () => {}, timeoutMs: 5000, maxPending: 2 });
  busy.rememberClient(CLIENT);
  busy.request('sampling/createMessage', {});
  busy.request('sampling/createMessage', {});
  await assert.rejects(busy.request('sampling/createMessage', {}), (e) => e.code === 'PEER_BUSY');
});

test('what the client declared is what Concord reports, and no client is reported as none', () => {
  const { tools } = harness();
  const capabilities = tools.get('peer.capabilities');
  assert.equal(capabilities.effect, 'read');
  const seen = capabilities.execute({});
  assert.equal(seen.connected, true);
  assert.equal(seen.client.name, 'probe');
  assert.equal(seen.client.version, '2.0.0');
  assert.deepEqual(seen.supports, { sampling: true, elicitation: false, roots: true });
  assert.deepEqual(seen.limitations, []);

  const fresh = harness(null);
  const none = fresh.tools.get('peer.capabilities').execute({});
  assert.equal(none.connected, false);
  assert.equal(none.client, null);
  assert.deepEqual(none.supports, { sampling: false, elicitation: false, roots: false });
  assert.equal(none.limitations.length, 1);

  // A client that declares nothing is not assumed to support anything.
  const bare = harness({ clientInfo: { name: 'bare' } });
  assert.deepEqual(bare.tools.get('peer.capabilities').execute({}).supports, { sampling: false, elicitation: false, roots: false });
});

test('asking the client sends its own question and returns its own answer, labelled untrusted', async () => {
  const { tools, sent, answerLast } = harness();
  const ask = tools.get('peer.ask');
  // Non-deterministic text from an agent Concord does not control: it needs an exact grant and is
  // taken from the journal on replay, exactly like any other network effect.
  assert.equal(ask.effect, 'network');

  const pending = ask.execute({ question: 'Who is asking?', maxTokens: 64 }, context);
  const request = sent.at(-1);
  assert.equal(request.method, 'sampling/createMessage');
  assert.deepEqual(request.params.messages, [{ role: 'user', content: { type: 'text', text: 'Who is asking?' } }]);
  assert.equal(request.params.maxTokens, 64);
  // Concord states its question in full or not at all. Inheriting whatever else that agent is
  // working on would put text Concord never saw into a request it is accountable for.
  assert.equal(request.params.includeContext, 'none');
  assert.equal(Object.hasOwn(request.params, 'systemPrompt'), false);

  answerLast({ role: 'assistant', content: { type: 'text', text: 'I am the client.' }, model: 'probe-model', stopReason: 'endTurn' });
  const answer = await pending;
  assert.equal(answer.text, 'I am the client.');
  assert.equal(answer.model, 'probe-model');
  assert.equal(answer.stopReason, 'endTurn');
  assert.equal(answer.source, 'probe');
  assert.equal(answer.untrusted, true);
  assert.equal(answer.limitations.length, 2);

  // A system prompt is sent only when given.
  const withSystem = harness();
  const second = withSystem.tools.get('peer.ask').execute({ question: 'q', systemPrompt: 'be brief' }, context);
  assert.equal(withSystem.sent.at(-1).params.systemPrompt, 'be brief');
  withSystem.answerLast({ role: 'assistant', content: { type: 'text', text: 'ok' }, model: 'm' });
  await second;
});

test('a client that cannot be asked is not asked, and a malformed answer is not believed', async () => {
  // The capability gate: no sampling declared means the question is refused before a line is
  // written, because waiting for a reply that cannot come is the worst available failure.
  const deaf = harness({ clientInfo: { name: 'deaf' }, capabilities: { roots: {} } });
  await assert.rejects(deaf.tools.get('peer.ask').execute({ question: 'hello' }, context), (e) => e.code === 'PEER_UNSUPPORTED');
  assert.equal(deaf.sent.length, 0);

  const nobody = harness(null);
  await assert.rejects(nobody.tools.get('peer.ask').execute({ question: 'hello' }, context), (e) => e.code === 'PEER_NO_CLIENT');
  // peer.tell answers synchronously because a notification has nothing to wait for.
  assert.throws(() => nobody.tools.get('peer.tell').execute({ message: 'hello' }), (e) => e.code === 'PEER_NO_CLIENT');
  assert.equal(nobody.sent.length, 0);

  for (const bad of [
    undefined,
    {},
    { content: { type: 'image', data: 'AAAA' } },
    { content: { type: 'text' } },
    { content: { type: 'text', text: 'x'.repeat(65537) } },
  ]) {
    const { tools, answerLast } = harness();
    const pending = tools.get('peer.ask').execute({ question: 'q' }, context);
    answerLast(bad);
    await assert.rejects(pending, (e) => e.code === 'PEER_RESPONSE');
  }

  assert.throws(() => makePeerTools({}), (e) => e.code === 'PEER_CONFIG');
});

test('telling the client something is one-way, and says so rather than claiming it was read', () => {
  const { tools, sent } = harness();
  const tell = tools.get('peer.tell');
  // It leaves a mark on someone else and cannot be taken back, so it is gated like any other
  // outward effect.
  assert.equal(tell.effect, 'network');

  const result = tell.execute({ message: 'Concord has something to say.', level: 'warning' });
  const notification = sent.at(-1);
  assert.equal(notification.method, 'notifications/message');
  // A notification carries no id: there is nothing to answer.
  assert.equal(Object.hasOwn(notification, 'id'), false);
  assert.deepEqual(notification.params, { level: 'warning', logger: 'concord', data: 'Concord has something to say.' });
  assert.equal(result.delivered, true);
  assert.equal(result.level, 'warning');
  assert.equal(result.limitations.length, 1);
  assert.match(result.limitations[0], /not that the client read/);

  assert.equal(tell.execute({ message: 'default level' }).level, 'info');
});

test('the transport routes a client reply to the channel instead of answering it as a bad request', async () => {
  const stubTool = (name) => ({ name, version: '1.0.0', effect: 'pure', inputSchema: { type: 'object', properties: {}, additionalProperties: false }, execute() { return {}; } });
  const registry = new Map([['a.b', stubTool('a.b')]]);
  const policy = { version: 1, allowedTools: ['a.b'], allowedEffects: ['pure'], allowedOrigins: [], maxTasks: 10, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 10000 };
  const stubHarness = { send: async () => ({}), approve: async () => ({}), executePlan: async () => ({}), replay: async () => ({}), snapshot: () => ({}) };

  const sent = [];
  const channel = createClientChannel({ send: (line) => sent.push(JSON.parse(line)), timeoutMs: 5000 });
  const server = createMcpServer({ registry, policy, sourceLock: { sources: [] }, workspaceRoot: process.cwd(), harness: stubHarness, instructionModules: [], channel });

  // initialize is where the client says what it can do, and the server has to keep that.
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: CLIENT }));
  assert.equal(channel.supports('sampling'), true);
  assert.equal(channel.describeClient().name, 'probe');

  const pending = channel.request('sampling/createMessage', { messages: [] });
  const asked = sent.at(-1);

  // The reply carries an id and no method. Before this routing existed the request dispatcher
  // read exactly that as a malformed request and answered the client's good reply with an error.
  const response = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: asked.id, result: { role: 'assistant', content: { type: 'text', text: 'hello' }, model: 'm' } }));
  assert.equal(response, null, 'a reply is consumed, never answered');
  assert.deepEqual((await pending).content, { type: 'text', text: 'hello' });

  // A reply to nothing is still a malformed request, and is still reported as one.
  const stray = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 'concord-404', result: {} }));
  assert.equal(JSON.parse(stray).error.code, -32600);
});

// Measured from Claude Code 2.1.221's own initialize: it declares elicitation and roots, and it
// does not declare sampling. The two halves of this channel are not interchangeable, so the tests
// below use the capability set a real client actually sends.
const CLAUDE_CODE = {
  protocolVersion: '2025-11-25',
  clientInfo: { name: 'claude-code', version: '2.1.221' },
  capabilities: { roots: { listChanged: true }, elicitation: {} },
};

test('a client declaring elicitation but not sampling can be asked one way and not the other', async () => {
  const { tools, sent, answerLast } = harness(CLAUDE_CODE);
  assert.deepEqual(tools.get('peer.capabilities').execute({}).supports, { sampling: false, elicitation: true, roots: true });

  // The wrong primitive for this client refuses, and refuses without writing a line.
  await assert.rejects(tools.get('peer.ask').execute({ question: 'hi' }, context), (e) => e.code === 'PEER_UNSUPPORTED');
  assert.equal(sent.length, 0);

  const pending = tools.get('peer.request').execute({ message: 'Can you hear me?' }, context);
  const request = sent.at(-1);
  assert.equal(request.method, 'elicitation/create');
  assert.equal(request.params.message, 'Can you hear me?');
  // The default shape is a question with room for an answer in words.
  assert.deepEqual(request.params.requestedSchema, {
    type: 'object',
    properties: { answer: { type: 'string', description: 'Your answer to Concord' } },
    required: ['answer'],
  });

  answerLast({ action: 'accept', content: { answer: 'Yes.' } });
  const reply = await pending;
  assert.equal(reply.action, 'accept');
  assert.equal(reply.answered, true);
  assert.deepEqual(reply.content, { answer: 'Yes.' });
  assert.equal(reply.source, 'claude-code');
  assert.equal(reply.untrusted, true);
});

test('declining is an answer, not a failure', async () => {
  for (const action of ['decline', 'cancel']) {
    const { tools, answerLast } = harness(CLAUDE_CODE);
    const pending = tools.get('peer.request').execute({ message: 'May I?' }, context);
    answerLast({ action });
    const reply = await pending;
    // Treating "no" as an error would make a refusal look like a broken channel and invite
    // retrying something a person already turned down.
    assert.equal(reply.action, action);
    assert.equal(reply.answered, false);
    assert.equal(reply.content, null);
    assert.match(reply.limitations[0], /entitled to make/);
  }
});

test('a structured request is built from declared fields and checked against them', async () => {
  const fields = [
    { name: 'choice', type: 'string', enum: ['keep', 'change'] },
    { name: 'confidence', type: 'number', description: 'How sure' },
    { name: 'note', type: 'string', required: false },
  ];
  const { tools, sent, answerLast } = harness(CLAUDE_CODE);
  const pending = tools.get('peer.request').execute({ message: 'Pick one.', fields }, context);
  assert.deepEqual(sent.at(-1).params.requestedSchema, {
    type: 'object',
    properties: {
      choice: { type: 'string', enum: ['keep', 'change'] },
      confidence: { type: 'number', description: 'How sure' },
      note: { type: 'string' },
    },
    required: ['choice', 'confidence'],
  });
  answerLast({ action: 'accept', content: { choice: 'keep', confidence: 0.8 } });
  assert.deepEqual((await pending).content, { choice: 'keep', confidence: 0.8 });

  // An accepted answer is still checked: the client is not trusted to honour the schema it was
  // handed just because it said accept.
  for (const content of [
    { choice: 'keep' },                       // a required field left out
    { choice: 'keep', confidence: 'high' },   // the wrong type
    { choice: 'other', confidence: 1 },       // outside the offered choices
  ]) {
    const attempt = harness(CLAUDE_CODE);
    const call = attempt.tools.get('peer.request').execute({ message: 'Pick one.', fields }, context);
    attempt.answerLast({ action: 'accept', content });
    await assert.rejects(call, (e) => e.code === 'PEER_RESPONSE');
  }

  const unknown = harness(CLAUDE_CODE);
  const call = unknown.tools.get('peer.request').execute({ message: 'Pick one.' }, context);
  unknown.answerLast({ action: 'maybe' });
  await assert.rejects(call, (e) => e.code === 'PEER_RESPONSE');
});

test('a request Concord cannot render for a person is refused before it is sent', async () => {
  const { tools, sent } = harness(CLAUDE_CODE);
  const request = (fields) => tools.get('peer.request').execute({ message: 'q', fields }, context);
  // A field name becomes a property key in a schema the client has to render.
  await assert.rejects(request([{ name: 'a b', type: 'string' }]), (e) => e.code === 'PEER_REQUEST');
  await assert.rejects(request([{ name: '1st', type: 'string' }]), (e) => e.code === 'PEER_REQUEST');
  await assert.rejects(request([{ name: 'x', type: 'string' }, { name: 'x', type: 'number' }]), (e) => e.code === 'PEER_REQUEST');
  // Only a string field can offer a fixed set of choices.
  await assert.rejects(request([{ name: 'n', type: 'number', enum: ['a'] }]), (e) => e.code === 'PEER_REQUEST');
  assert.equal(sent.length, 0);
});

// The mailbox is the half that needs no client. Only two MCP directions reach anyone and they
// reach different people: sampling asks the client's model, elicitation asks the person operating
// it. Against a client that declares elicitation and not sampling, nothing reaches the connected
// agent at all — so these two tools are files rather than protocol.

function mailbox() {
  const directory = tempDir('concord-mailbox-');
  const tools = byName(makeMailboxTools({ directory }));
  return { directory, post: tools.get('peer.post'), inbox: tools.get('peer.inbox') };
}

test('a message posted by one process is collected by another', () => {
  const { directory, post, inbox } = mailbox();
  // Writing a file that outlives the run takes a grant; collecting letters does not.
  assert.equal(post.effect, 'write');
  assert.equal(inbox.effect, 'read');

  const first = post.execute({ message: 'Concord has something to say.', subject: 'hello' });
  assert.equal(first.seq, 1);
  assert.equal(first.for, 'agent');
  assert.match(first.id, /^000001-[0-9a-f]{12}$/);
  assert.equal(post.execute({ message: 'and another' }).seq, 2);

  // A separate construction over the same directory is the cross-process case: the desktop
  // application posts and the MCP server collects, and they never share memory.
  const elsewhere = byName(makeMailboxTools({ directory })).get('peer.inbox');
  const seen = elsewhere.execute({});
  assert.equal(seen.total, 2);
  assert.equal(seen.latestSeq, 2);
  assert.deepEqual(seen.messages.map((m) => m.message), ['Concord has something to say.', 'and another']);
  assert.equal(seen.messages[0].subject, 'hello');
  fs.rmSync(directory, { recursive: true, force: true });
});

test('an unread mailbox is empty rather than an error, and reading never consumes', () => {
  const absent = byName(makeMailboxTools({ directory: path.join(os.tmpdir(), 'concord-mailbox-never-created-' + process.pid) })).get('peer.inbox');
  // A mailbox nobody has written to yet and one that does not exist are the same thing to a
  // reader, and neither is a failure.
  assert.deepEqual(absent.execute({}).messages, []);
  assert.equal(absent.execute({}).total, 0);

  const { directory, post, inbox } = mailbox();
  post.execute({ message: 'one' });
  assert.equal(inbox.execute({}).returned, 1);
  // Reading twice returns the same letter: a tool that quietly consumed evidence would make a
  // lost message indistinguishable from one that was never sent.
  assert.equal(inbox.execute({}).returned, 1);
  assert.equal(inbox.execute({ after: 1 }).returned, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});

test('a letter says who it is for, and pages without being drained', () => {
  const { directory, post, inbox } = mailbox();
  post.execute({ message: 'for the agent' });
  post.execute({ message: 'for the operator', for: 'operator' });
  post.execute({ message: 'for the agent again', for: 'agent' });

  assert.deepEqual(inbox.execute({ for: 'agent' }).messages.map((m) => m.seq), [1, 3]);
  assert.deepEqual(inbox.execute({ for: 'operator' }).messages.map((m) => m.seq), [2]);
  assert.deepEqual(inbox.execute({ after: 1 }).messages.map((m) => m.seq), [2, 3]);
  assert.deepEqual(inbox.execute({ limit: 1 }).messages.map((m) => m.seq), [1]);
  // total counts the whole mailbox even when a filter or a page returns less of it.
  const page = inbox.execute({ limit: 1 });
  assert.equal(page.returned, 1);
  assert.equal(page.total, 3);
  assert.equal(page.latestSeq, 3);
  fs.rmSync(directory, { recursive: true, force: true });
});

test('the mailbox ignores what it did not write, and needs an absolute directory', () => {
  const { directory, post, inbox } = mailbox();
  post.execute({ message: 'real' });
  // Anything not matching the mailbox's own naming is not a letter, and a letter that cannot be
  // parsed is skipped rather than failing the whole collection.
  fs.writeFileSync(path.join(directory, 'notes.txt'), 'not a letter');
  fs.writeFileSync(path.join(directory, '000009-abcdefabcdef.json'), '{ this is not json');
  const seen = inbox.execute({});
  assert.deepEqual(seen.messages.map((m) => m.message), ['real']);
  assert.equal(seen.total, 2, 'the malformed letter still counts as occupying a slot');

  assert.throws(() => makeMailboxTools({ directory: 'relative/path' }), (e) => e.code === 'PEER_CONFIG');
  assert.throws(() => makeMailboxTools({}), (e) => e.code === 'PEER_CONFIG');
  fs.rmSync(directory, { recursive: true, force: true });
});
