import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { joinHub, hubAddress, peerIdFor } from '../src/peer-hub.mjs';
import { createClientChannel, createHubResponder, makePeerTools, fileMessage, readMailbox } from '../src/peer.mjs';
import { canonical } from '../src/value.mjs';
import { tempDir } from './temp-workspace.mjs';

/**
 * Sampling across sessions.
 *
 * `peer.ask` could always reach the client on its own session; nothing could reach another session,
 * because MCP over stdio gives every client its own server process. These tests drive two sessions
 * at once in one process, which still exercises the real endpoint: the first binds it and the
 * second connects over it, so the frames genuinely cross a socket rather than a function call.
 *
 * The cases chosen are the ones where a plausible implementation is wrong — an answer attributed to
 * sampling when a person typed it, an asker left hanging on a session that has gone away, an
 * unauthenticated peer that can ask before it is admitted.
 */

const SAMPLING = { protocolVersion: '2025-06-18', clientInfo: { name: 'codex', version: '0.9' }, capabilities: { sampling: {}, roots: {} } };
const ELICITING = { protocolVersion: '2025-06-18', clientInfo: { name: 'claude-code', version: '2.0' }, capabilities: { elicitation: {}, roots: {} } };
const context = { policy: { timeoutMs: 5000, maxOutputBytes: 1048576 } };
const byName = (tools) => new Map(tools.map((tool) => [tool.name, tool]));
const capabilitiesOf = (params) => Object.keys(params.capabilities).sort();

/** Wait for a condition the socket has to carry, rather than guessing a sleep that is usually enough. */
async function until(predicate, timeoutMs = 3000) {
  const limit = Date.now() + timeoutMs;
  while (Date.now() < limit) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return false;
}

/**
 * A session: a client channel that answers its own sampling requests, plus hub membership.
 *
 * `answerWith` is what the client's model would have said. Producing it from inside the send hook is
 * what makes this a round trip rather than a mock: the responder really issues
 * sampling/createMessage, and really waits for a reply to the id it chose.
 */
async function session(root, clientParams, { answerWith = null, mailboxDir = null, stall = false, rendezvousMs } = {}) {
  const sampled = [];
  const channel = createClientChannel({ send: (line) => {
    const message = JSON.parse(line);
    if (message.method !== 'sampling/createMessage') return;
    sampled.push(message.params);
    if (stall) return; // a client that never answers, for the deadline cases
    setImmediate(() => channel.deliver({ jsonrpc: '2.0', id: message.id, result: {
      role: 'assistant', model: 'test-model', stopReason: 'endTurn',
      content: { type: 'text', text: `${answerWith}${message.params.messages[0].content.text}` },
    } }));
  }, timeoutMs: 5000 });
  channel.rememberClient(clientParams);
  const membership = await joinHub({
    root,
    identity: { name: clientParams.clientInfo.name, version: clientParams.clientInfo.version, capabilities: capabilitiesOf(clientParams) },
    onServe: stall
      ? () => new Promise(() => {})
      : createHubResponder({ channel, mailboxDir, timeoutMs: 5000, ...(rendezvousMs === undefined ? {} : { rendezvousMs }) }),
  });
  return { channel, membership, sampled, tools: byName(makePeerTools({ channel, hub: () => membership })) };
}

test('the endpoint is scoped to one workspace, so two checkouts never find each other', () => {
  const a = hubAddress(tempDir('hub'));
  const b = hubAddress(tempDir('hub'));
  assert.notEqual(a.address, b.address);
  assert.notEqual(a.stamp, b.stamp);
  // A name that collided would introduce unrelated Concord installations to each other.
  assert.match(a.stamp, /^[0-9a-f]{16}$/);
});

test('a peer name is taken from the client, and disambiguated only when it has to be', () => {
  assert.equal(peerIdFor('Claude Code'), 'claude-code');
  assert.equal(peerIdFor('codex', new Set(['codex'])), 'codex-2');
  assert.equal(peerIdFor(null), 'unknown');
  assert.equal(peerIdFor('!!!'), 'unknown');
});

test('the first session binds and later ones join it, and each reports what its client declared', async (t) => {
  const root = tempDir('hub');
  const first = await session(root, SAMPLING, { answerWith: '' });
  const second = await session(root, ELICITING, { answerWith: '' });
  t.after(() => { first.membership.close(); second.membership.close(); });

  assert.equal(first.membership.role, 'hub');
  assert.equal(second.membership.role, 'spoke');
  assert.equal(first.membership.peerId, 'codex');
  assert.equal(second.membership.peerId, 'claude-code');

  assert.ok(await until(() => second.membership.peers().length === 2), 'the spoke must learn the roster over the socket');
  const seen = second.tools.get('peer.peers').execute({}, context);
  assert.equal(seen.joined, true);
  assert.equal(seen.counts.peers, 2);
  // The field a caller needs before asking: who can actually answer.
  assert.equal(seen.counts.canAnswer, 1);
  assert.equal(seen.peers.find((peer) => peer.peerId === 'codex').canAnswer, true);
  assert.equal(seen.peers.find((peer) => peer.peerId === 'claude-code').canAnswer, false);
  assert.equal(seen.peers.find((peer) => peer.peerId === 'claude-code').self, true);
});

test('a question crosses sessions and is answered by the target client\'s own model', async (t) => {
  const root = tempDir('hub');
  const codex = await session(root, SAMPLING, { answerWith: 'codex answering: ' });
  const claude = await session(root, ELICITING, { answerWith: '' });
  t.after(() => { codex.membership.close(); claude.membership.close(); });
  assert.ok(await until(() => claude.membership.peers().length === 2));

  const answer = await claude.tools.get('peer.askPeer').execute({ to: 'codex', question: 'who are you' }, context);

  assert.equal(answer.text, 'codex answering: who are you');
  assert.equal(answer.via, 'sampling');
  assert.equal(answer.servedBy, 'codex');
  assert.equal(answer.model, 'test-model');
  assert.equal(answer.stopReason, 'endTurn');
  assert.equal(answer.untrusted, true);

  // The real protocol primitive was used, with the question standing on its own: inheriting the
  // target's context would put text Concord never saw into an exchange it is accountable for.
  assert.equal(codex.sampled.length, 1);
  assert.equal(codex.sampled[0].includeContext, 'none');
  assert.equal(codex.sampled[0].messages[0].content.text, 'who are you');
  // The answer has to survive the journal, or the run that produced it cannot be replayed.
  assert.equal(typeof canonical(answer), 'string');
});

test('an unknown peer is refused by name, with the names that would have worked', async (t) => {
  const root = tempDir('hub');
  const codex = await session(root, SAMPLING, { answerWith: '' });
  t.after(() => codex.membership.close());
  await assert.rejects(
    () => codex.tools.get('peer.askPeer').execute({ to: 'gemini', question: 'x' }, context),
    (error) => error.code === 'PEER_HUB_UNKNOWN' && error.details.peers.includes('codex'),
  );
});

test('a session cannot ask itself, which would deadlock on its own answer', async (t) => {
  const root = tempDir('hub');
  const codex = await session(root, SAMPLING, { answerWith: '' });
  const other = await session(root, ELICITING, { answerWith: '' });
  t.after(() => { codex.membership.close(); other.membership.close(); });
  await assert.rejects(() => codex.membership.ask('codex', 'x', { timeoutMs: 1000 }), (error) => error.code === 'PEER_HUB_SELF');
});

test('a target whose client declared no sampling refuses rather than inventing an answer', async (t) => {
  const root = tempDir('hub');
  // No mailbox given, so the rendezvous fallback is unavailable and the honest answer is a refusal.
  const claude = await session(root, ELICITING, { answerWith: '' });
  const codex = await session(root, SAMPLING, { answerWith: '' });
  t.after(() => { claude.membership.close(); codex.membership.close(); });
  assert.ok(await until(() => codex.membership.peers().length === 2));

  await assert.rejects(
    () => codex.tools.get('peer.askPeer').execute({ to: 'claude-code', question: 'x' }, context),
    (error) => error.code === 'PEER_HUB_NO_SAMPLING',
  );
});

test('a target that cannot be sampled is reached through the mailbox, and says so', async (t) => {
  const root = tempDir('hub');
  const mailboxDir = path.join(root, 'mailbox');
  fs.mkdirSync(mailboxDir, { recursive: true });
  const claude = await session(root, ELICITING, { answerWith: '', mailboxDir, rendezvousMs: 8000 });
  const codex = await session(root, SAMPLING, { answerWith: '' });
  t.after(() => { claude.membership.close(); codex.membership.close(); });
  assert.ok(await until(() => codex.membership.peers().length === 2));

  const pending = codex.tools.get('peer.askPeer').execute({ to: 'claude-code', question: 'did it land' }, { policy: { timeoutMs: 20000 } });

  // The question becomes an open letter, which is what the existing watcher advertises in the
  // description of concord_answer. Answering it here is what that tool does.
  assert.ok(await until(() => readMailbox(mailboxDir).some((entry) => entry.open && entry.for === 'agent')));
  const asked = readMailbox(mailboxDir).find((entry) => entry.open && entry.for === 'agent');
  assert.match(asked.subject, /peer hub by codex/);
  assert.equal(asked.message, 'did it land');
  fileMessage(mailboxDir, { audience: 'operator', replyTo: asked.seq, message: 'yes it did' });

  const answer = await pending;
  assert.equal(answer.text, 'yes it did');
  // The distinctions that must not be lost. Nothing was sampled, so no model is claimed. And the
  // mailbox is shared with no enforced recipient and no recorded author, so the answer is not proven
  // to come from the peer named in `to` - servedBy must be null rather than the target name.
  assert.equal(answer.via, 'rendezvous');
  assert.equal(answer.model, null);
  assert.equal(answer.servedBy, null);
  assert.equal(answer.askedSeq, asked.seq);
  assert.ok(answer.answeredSeq > asked.seq);
  assert.match(answer.limitations.join(' '), /not proven to be the peer named/);
  assert.match(asked.subject, /for claude-code/);
  assert.equal(claude.sampled.length, 0);
});

test('a question nobody answers reports the letter it left behind', async (t) => {
  const root = tempDir('hub');
  const mailboxDir = path.join(root, 'mailbox');
  fs.mkdirSync(mailboxDir, { recursive: true });
  const claude = await session(root, ELICITING, { answerWith: '', mailboxDir, rendezvousMs: 300 });
  const codex = await session(root, SAMPLING, { answerWith: '' });
  t.after(() => { claude.membership.close(); codex.membership.close(); });
  assert.ok(await until(() => codex.membership.peers().length === 2));

  await assert.rejects(
    () => codex.tools.get('peer.askPeer').execute({ to: 'claude-code', question: 'anyone there' }, context),
    (error) => error.code === 'PEER_HUB_UNANSWERED' && Number.isInteger(error.details.seq),
  );
  // Unanswered, not undelivered: the letter is still there to be found later.
  assert.equal(readMailbox(mailboxDir).filter((entry) => entry.open).length, 1);
});

test('a session that goes away mid-question fails the asker at once, not at its deadline', async (t) => {
  const root = tempDir('hub');
  const asker = await session(root, SAMPLING, { answerWith: '' });
  const stuck = await session(root, ELICITING, { stall: true });
  t.after(() => { asker.membership.close(); stuck.membership.close(); });
  assert.ok(await until(() => asker.membership.peers().length === 2));

  const started = Date.now();
  const pending = asker.membership.ask('claude-code', 'are you there', { timeoutMs: 60_000 });
  await new Promise((resolve) => setTimeout(resolve, 100));
  stuck.membership.close();

  await assert.rejects(pending, (error) => error.code === 'PEER_HUB_GONE');
  // The whole point. Waiting out a sixty second deadline for an answer that cannot arrive is the
  // failure this guards, and it is invisible in a test that only checks the error code.
  assert.ok(Date.now() - started < 5000, `failed in ${Date.now() - started}ms, which means it waited rather than noticed`);
});

test('a peer without the hub token is refused and never joins the roster', async (t) => {
  const root = tempDir('hub');
  const codex = await session(root, SAMPLING, { answerWith: '' });
  t.after(() => codex.membership.close());

  const reply = await new Promise((resolve) => {
    const socket = net.connect(hubAddress(root).address, () => {
      socket.write(JSON.stringify({ kind: 'hello', token: '0'.repeat(64), identity: { name: 'imposter' } }) + '\n');
    });
    let buffer = '';
    socket.on('data', (chunk) => { buffer += chunk; if (buffer.includes('\n')) resolve(buffer.trim()); });
    socket.on('error', () => resolve('{"kind":"error"}'));
    socket.on('close', () => resolve(buffer.trim() || '{"kind":"closed"}'));
    setTimeout(() => resolve('{"kind":"silent"}'), 2000);
  });

  assert.equal(JSON.parse(reply).kind, 'denied');
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(codex.membership.peers().map((peer) => peer.peerId), ['codex']);
});

test('without a hub the tools say so and point at the channel that still works', async () => {
  const channel = createClientChannel({ send: () => {} });
  channel.rememberClient(ELICITING);
  const tools = byName(makePeerTools({ channel }));

  const seen = tools.get('peer.peers').execute({}, context);
  assert.equal(seen.joined, false);
  assert.deepEqual(seen.peers, []);
  assert.match(seen.limitations.join(' '), /mailbox still reaches/);

  await assert.rejects(
    () => tools.get('peer.askPeer').execute({ to: 'codex', question: 'x' }, context),
    (error) => error.code === 'PEER_HUB_UNJOINED',
  );
});

test('every hub tool declares the keys it always returns, and returns them', async (t) => {
  const root = tempDir('hub');
  const codex = await session(root, SAMPLING, { answerWith: 'x' });
  const claude = await session(root, ELICITING, { answerWith: '' });
  t.after(() => { codex.membership.close(); claude.membership.close(); });
  assert.ok(await until(() => claude.membership.peers().length === 2));

  const peers = claude.tools.get('peer.peers');
  const asked = claude.tools.get('peer.askPeer');
  for (const [tool, result] of [[peers, peers.execute({}, context)], [asked, await asked.execute({ to: 'codex', question: 'q' }, context)]]) {
    for (const key of tool.outputKeys) assert.ok(key in result, `${tool.name} declares ${key} and did not return it`);
    assert.equal(typeof canonical(result), 'string', `${tool.name} output must survive canonicalisation`);
  }
});
