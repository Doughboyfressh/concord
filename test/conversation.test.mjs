import test from 'node:test';
import assert from 'node:assert/strict';
import { makeConversationTools, turnId } from '../src/conversation.mjs';
import { boundedRecords } from '../src/chat-data.mjs';
import { registryManifest } from '../src/engine.mjs';
import { digest, canonical } from '../src/value.mjs';

const history = (count, body = (i) => `turn ${i} body`) =>
  Array.from({ length: count }, (unused, i) => ({ role: i % 2 === 0 ? 'user' : 'assistant', content: body(i) }));

const toolOver = (readTranscript, options = {}) =>
  makeConversationTools({ readTranscript, ...options })[0];

const context = { workspaceRoot: '.', policy: { maxOutputBytes: 1048576 } };

test('compaction names the turns it drops, oldest first, and those names resolve to them', () => {
  const full = history(30);
  const bounded = boundedRecords(full, { idOf: (record, index) => turnId(index) });

  // The count and the names have to agree, or one of them is lying about the same omission.
  assert.equal(bounded.omittedCount, 6);
  assert.equal(bounded.omittedIds.length, bounded.omittedCount);
  assert.deepEqual(bounded.omittedIds, ['turn-0', 'turn-1', 'turn-2', 'turn-3', 'turn-4', 'turn-5']);

  // Record order, not sorted order. turn-10 sorts before turn-2 lexically, so a .sort() here
  // would read the transcript back in an order it never happened in.
  const wide = boundedRecords(history(40), { idOf: (record, index) => turnId(index), maxItems: 4 });
  assert.deepEqual(wide.omittedIds.slice(8, 12), ['turn-8', 'turn-9', 'turn-10', 'turn-11']);

  const fetched = toolOver(() => full).execute({ ids: bounded.omittedIds }, context);
  assert.equal(fetched.returned, 6);
  assert.deepEqual(fetched.turns.map((t) => t.id), bounded.omittedIds);
  // Verbatim: the point of retrieval is that it is the turn, not a description of the turn.
  for (const turn of fetched.turns) {
    assert.equal(turn.content, full[turn.index].content);
    assert.equal(turn.role, full[turn.index].role);
  }
});

test('an omitted id survives the round trip the model actually makes', () => {
  // The whole feature in one line: what compaction dropped, retrieval returns unchanged.
  const full = history(30, (i) => `secret marker ${i} cobalt-otter`);
  const bounded = boundedRecords(full, { idOf: (record, index) => turnId(index) });
  assert.ok(!bounded.records.some((r) => r.content.includes('marker 0 ')), 'turn 0 was dropped from the context');

  const recovered = toolOver(() => full).execute({ ids: ['turn-0'] }, context);
  assert.equal(recovered.turns[0].content, 'secret marker 0 cobalt-otter');
});

test('every declared outputKeys is really present in the result', () => {
  const tool = toolOver(() => history(4));
  const result = tool.execute({ ids: ['turn-0'] }, context);
  for (const key of tool.outputKeys) assert.ok(key in result, `missing declared key ${key}`);
});

test('an id that names nothing is reported missing rather than thrown', () => {
  const tool = toolOver(() => history(4));
  // Out of range, not an id at all, and a leading-zero form the pattern deliberately refuses -
  // accepting turn-01 as turn-1 would give one turn two names and two digests.
  const result = tool.execute({ ids: ['turn-999', 'not-an-id', 'turn-01'] }, context);
  assert.deepEqual(result.turns, []);
  assert.equal(result.returned, 0);
  assert.deepEqual([...result.missing].sort(), ['not-an-id', 'turn-01', 'turn-999']);
  assert.equal(result.totalCount, 4);
});

test('the same turn asked for twice is one turn, and order comes from the index', () => {
  const tool = toolOver(() => history(6));
  const result = tool.execute({ ids: ['turn-4', 'turn-1', 'turn-4'] }, context);
  assert.equal(result.requested, 2);
  assert.deepEqual(result.turns.map((t) => t.id), ['turn-1', 'turn-4']);
});

test('a turn too large for the bound is deferred whole, never cut in half', () => {
  const full = history(3, (i) => (i === 1 ? 'x'.repeat(4000) : `small ${i}`));
  const tool = toolOver(() => full, { maxBytes: 1024 });
  const result = tool.execute({ ids: ['turn-0', 'turn-1', 'turn-2'] }, context);

  assert.deepEqual(result.deferredIds, ['turn-1']);
  assert.deepEqual(result.turns.map((t) => t.id), ['turn-0', 'turn-2']);
  // Nothing returned is a fragment: every content is exactly what the transcript holds.
  for (const turn of result.turns) assert.equal(turn.content, full[turn.index].content);
  assert.ok(Buffer.byteLength(canonical(result.turns)) <= 1024);
});

test('the registry digest does not move when the transcript does', () => {
  // The reason the transcript is a closure and not config. registryManifest hashes every
  // descriptor's config into the digest that binds approval hashes and replay, so a config
  // carrying history would invalidate the previous turn's grants on every single turn.
  let transcript = history(2);
  const tool = toolOver(() => transcript);
  const before = digest(registryManifest(new Map([[tool.name, tool]])));

  transcript = history(500);
  const after = digest(registryManifest(new Map([[tool.name, tool]])));

  assert.equal(before, after);
  // And the tool really is reading the new transcript, so the digest held still for the right
  // reason rather than because the closure was stale.
  assert.equal(tool.execute({ ids: ['turn-400'] }, context).returned, 1);
});

test('without idOf the bounded envelope names only what it can resolve', () => {
  // The id fields stay behind idOf, because an id a caller cannot resolve is worse than no id.
  // The counts do not: droppedNewest is always present and zero when nothing was dropped, so a
  // reader never has to tell "no tail was dropped" apart from "this envelope cannot say".
  const plain = boundedRecords(history(30));
  assert.deepEqual(Object.keys(plain).sort(), ['droppedNewest', 'fullDigest', 'omittedCount', 'records', 'totalCount']);
  assert.equal('omittedIds' in plain, false);
  assert.equal('droppedNewestIds' in plain, false);
  assert.equal(plain.droppedNewest, 0);
});

test('a record too big for the window no longer blanks the window', () => {
  // Measured live before this: a plan holding six retrieved slices made one ~24 KB receipt
  // against a 16 KiB budget, the fill broke on its first step, and the turn was handed
  // records:[] with all seventeen observations reported omitted. Everything that would have fit
  // was thrown away to avoid showing it.
  const records = [...history(6), { role: 'user', content: 'x'.repeat(40000) }];
  const bounded = boundedRecords(records, { idOf: (record, index) => turnId(index) });

  assert.equal(bounded.droppedNewest, 1, 'the oversized newest record is skipped, not fatal');
  assert.deepEqual(bounded.droppedNewestIds, ['turn-6'], 'and named, so it can be fetched back');
  assert.ok(bounded.records.length > 0, 'the records that fit are still shown');
  assert.equal(bounded.records.at(-1).content, 'turn 5 body', 'the newest that fits is the newest shown');

  // Every record is accounted for in exactly one place.
  assert.equal(bounded.records.length + bounded.omittedCount + bounded.droppedNewest, bounded.totalCount);

  // And the declaration is not inert: the id it named resolves to the record it dropped.
  const fetched = toolOver(() => records).execute({ ids: bounded.droppedNewestIds }, context);
  assert.equal(fetched.deferredIds.length, 1, 'too large for one call, so deferred rather than cut');
  assert.deepEqual(fetched.deferredIds, ['turn-6']);
});

test('an oversized record in the middle is counted with the omitted prefix', () => {
  // Only a trailing oversized record is skipped. One further back stops the backward fill, so it
  // and everything older are the omitted prefix - which is what omittedCount has always meant.
  const records = [...history(3), { role: 'user', content: 'y'.repeat(40000) }, ...history(3)];
  const bounded = boundedRecords(records, { idOf: (record, index) => turnId(index) });
  assert.equal(bounded.droppedNewest, 0);
  assert.equal(bounded.omittedCount, 4, 'the big one and the three before it');
  assert.deepEqual(bounded.omittedIds, ['turn-0', 'turn-1', 'turn-2', 'turn-3']);
  assert.equal(bounded.records.length, 3);
});

test('the store refuses a configuration it cannot read a transcript from', () => {
  assert.throws(() => makeConversationTools({}), /CONVERSATION_CONFIG|readTranscript/);
  assert.throws(() => makeConversationTools({ readTranscript: () => [], maxBytes: 16 }), /CONVERSATION_CONFIG|maxBytes/);
  const broken = makeConversationTools({ readTranscript: () => null })[0];
  assert.throws(() => broken.execute({ ids: ['turn-0'] }, context), /CONVERSATION_STORE|unavailable/);
});
