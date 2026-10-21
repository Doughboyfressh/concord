import test from 'node:test';
import assert from 'node:assert/strict';
import { createCallbacks, createSession, extractSource, protocol, CORE_TYPES } from '../src/decompiler.mjs';

/**
 * Speaking to Ghidra's decompiler.
 *
 * Nothing here needs the Ghidra distribution or a process. `createSession` takes `spawn` as an
 * argument precisely so the protocol can be driven against a scripted transport, which is what
 * makes these deterministic — a real decompiler answers on its own schedule and splits its output
 * wherever the pipe happens to break.
 *
 * Two external oracles keep this from being a closed loop where my encoder validates my decoder.
 * The query bytes in the round-trip test were captured from the running decompiler, so Ghidra's own
 * PackedEncode wrote them. And the document in the extraction tests is hand-encoded from the format
 * in marshal.hh rather than produced by PackedWriter.
 *
 * The cases chosen are the ones that actually went wrong. Every response rule below was learned
 * from a crash or, worse, from a silence: a decompilation that reported success and returned
 * nothing.
 */

const P = protocol;

/** A fake decompiler: feed it bytes, see what the session writes back. */
function scriptedChild() {
  const writes = [];
  let onData = null;
  let onExit = null;
  return {
    writes,
    feed(buffer) { onData?.(buffer); },
    exit(code) { onExit?.(code); },
    child: {
      stdout: { on: (event, fn) => { if (event === 'data') onData = fn; } },
      stderr: { resume() {} },
      stdin: { write: (bytes) => { writes.push(Buffer.from(bytes)); return true; }, end() {} },
      on: (event, fn) => { if (event === 'exit') onExit = fn; },
    },
  };
}

/** The marker/payload shape of a stream, for asserting structure rather than bytes. */
function outline(buffer) {
  const parts = [];
  let index = 0;
  while (index < buffer.length) {
    if (buffer[index] === 0 && buffer[index + 1] === 0 && buffer[index + 2] === 1 && index + 3 < buffer.length) {
      parts.push(buffer[index + 3]);
      index += 4;
    } else {
      let end = index;
      while (end < buffer.length && buffer[end] !== 0) end += 1;
      parts.push(end - index);
      index = end;
    }
  }
  return parts;
}

// ---------------------------------------------------------------------------------------------
// The codec, against bytes Ghidra wrote
// ---------------------------------------------------------------------------------------------

test('a query captured from the running decompiler decodes, and re-encodes to the same bytes', () => {
  // Observed on the wire: the first question the decompiler ever asks, during architecture
  // initialization. Ghidra's PackedEncode produced these six bytes.
  const observed = Buffer.from('6281ca20a281', 'hex');

  const query = P.decodePacked(observed);
  assert.equal(query.element, P.QUERY.getUserOpName);
  assert.equal(query.element, 257);
  assert.equal(query.attributes.get(P.ATTRIB.INDEX), 0n);

  const writer = new P.PackedWriter();
  writer.openElement(P.QUERY.getUserOpName).writeSignedInteger(P.ATTRIB.INDEX, 0).closeElement(P.QUERY.getUserOpName);
  assert.deepEqual(writer.toBuffer(), observed, 'the encoder must agree with Ghidra byte for byte');
});

test('an id above five bits extends into a second byte, and a zero value occupies none', () => {
  const writer = new P.PackedWriter();
  writer.openElement(257);
  assert.deepEqual(writer.toBuffer(), Buffer.from([0x62, 0x81]));

  // marshal.cc writeInteger: val == 0 gives lenCode 0, so the value contributes no raw bytes.
  const zero = new P.PackedWriter();
  zero.writeSignedInteger(P.ATTRIB.INDEX, 0);
  assert.deepEqual(zero.toBuffer(), Buffer.from([0xca, 0x20]));

  const small = new P.PackedWriter();
  small.openElement(11);
  assert.deepEqual(small.toBuffer(), Buffer.from([0x4b]), 'an id that fits needs no extend bit');
});

test('bytes travel as nibbles offset by A, which is what keeps payload clear of markers', () => {
  const bytes = Buffer.from('4883ec28', 'hex');   // SUB RSP,0x28
  const framed = P.answerBytes(bytes);
  const payload = framed.subarray(8, framed.length - 4);

  assert.equal(payload.toString('latin1'), 'EIIDOMCI');
  // Inverted exactly as ghidra_arch.cc:744 does it.
  const back = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) back[i] = ((payload[i * 2] - 0x41) << 4) | (payload[i * 2 + 1] - 0x41);
  assert.deepEqual(back, bytes);
  // The point of the encoding: no byte can begin a burst marker.
  assert.ok(payload.every((byte) => byte !== 0), 'nibble bytes must never be zero');
});

test('a query puts its address in a child element, not in its own attributes', () => {
  // getBytes, getPcode and getMappedSymbols all call Address::encode, which emits <addr>. A decoder
  // that stopped at the first child read those three as having no address at all, and the handlers
  // then answered about address undefined.
  const writer = new P.PackedWriter();
  writer.openElement(P.QUERY.getBytes);
  writer.openElement(P.ELEM.ADDR);
  writer.writeSpace(P.ATTRIB.SPACE, 3).writeUnsignedInteger(P.ATTRIB.OFFSET, 0x401000).writeSignedInteger(P.ATTRIB.SIZE, 4);
  writer.closeElement(P.ELEM.ADDR);
  writer.closeElement(P.QUERY.getBytes);

  const query = P.decodePacked(writer.toBuffer());
  assert.equal(query.element, P.QUERY.getBytes);
  assert.equal(query.children.length, 1);
  assert.equal(query.children[0].element, P.ELEM.ADDR);
  assert.equal(query.children[0].attributes.get(P.ATTRIB.OFFSET), 0x401000n);
});

test('an element that closes with a different id is a misread stream, not a surprise', () => {
  const bytes = Buffer.from([0x4b, 0x91]);   // open 11, close 17
  assert.throws(() => P.decodePacked(bytes), (error) => error.code === 'DECOMPILE_PROTOCOL');
});

// ---------------------------------------------------------------------------------------------
// The callbacks
// ---------------------------------------------------------------------------------------------

/** A language with two registers and two user-defined ops, which is all these handlers read. */
const language = () => ({
  symbols: new Map([
    ['RAX', { kind: 'varnode', name: 'RAX', space: 'register', offset: '0x0', size: 8 }],
    ['RSP', { kind: 'varnode', name: 'RSP', space: 'register', offset: '0x20', size: 8 }],
  ]),
  userops: ['LOCK', 'UNLOCK'],
});

const spaceIndex = (name) => ({ const: 0, unique: 2, ram: 3, register: 4 }[name] ?? 0);

const ask = (element, build) => {
  const writer = new P.PackedWriter();
  writer.openElement(element);
  build?.(writer);
  writer.closeElement(element);
  return P.decodePacked(writer.toBuffer());
};

const askAddress = (element, { space = 3, offset = 0x401000, size }) => {
  const writer = new P.PackedWriter();
  writer.openElement(element);
  writer.openElement(P.ELEM.ADDR);
  writer.writeSpace(P.ATTRIB.SPACE, space).writeUnsignedInteger(P.ATTRIB.OFFSET, offset);
  if (size !== undefined) writer.writeSignedInteger(P.ATTRIB.SIZE, size);
  writer.closeElement(P.ELEM.ADDR);
  writer.closeElement(element);
  return P.decodePacked(writer.toBuffer());
};

/** The text of a string-framed answer, or null when the answer carries no string. */
const answeredString = (answer) => {
  const start = answer.indexOf(Buffer.from([0, 0, 1, P.BURST.STRING]));
  if (start === -1) return null;
  return answer.toString('latin1', start + 4, answer.indexOf(Buffer.from([0, 0, 1, P.BURST.STRING_END])));
};

/** The decoded element inside a packed answer. */
const answeredElement = (answer) => {
  const start = answer.indexOf(Buffer.from([0, 0, 1, P.BURST.STRING]));
  if (start === -1) return null;
  return P.decodePacked(answer.subarray(start + 4, answer.indexOf(Buffer.from([0, 0, 1, P.BURST.STRING_END]))));
};

test('a user-defined op is answered by name, and an unknown index by the empty string', () => {
  const callbacks = createCallbacks({ language: language(), spaceIndex });
  assert.equal(answeredString(callbacks.answer(ask(P.QUERY.getUserOpName, (w) => w.writeSignedInteger(P.ATTRIB.INDEX, 1)))), 'UNLOCK');

  // Not answerNothing: readStringStream(istream&,string&) throws on anything that is not a string
  // frame, and that aborted a whole registerProgram with an alignment error.
  const unknown = callbacks.answer(ask(P.QUERY.getUserOpName, (w) => w.writeSignedInteger(P.ATTRIB.INDEX, 9)));
  assert.equal(answeredString(unknown), '');
  assert.deepEqual(outline(unknown), [P.BURST.QUERY_RESPONSE, P.BURST.STRING, P.BURST.STRING_END, P.BURST.QUERY_RESPONSE_END]);
});

test('a register is answered as its storage, and only an exact location answers in reverse', () => {
  const callbacks = createCallbacks({ language: language(), spaceIndex });
  const decoded = answeredElement(callbacks.answer(ask(P.QUERY.getRegister, (w) => w.writeString(P.ATTRIB.NAME, 'RSP'))));
  assert.equal(decoded.element, P.ELEM.ADDR);
  assert.equal(decoded.attributes.get(P.ATTRIB.OFFSET), 0x20n);
  assert.equal(decoded.attributes.get(P.ATTRIB.SIZE), 8n);

  assert.equal(answeredString(callbacks.answer(askAddress(P.QUERY.getRegisterName, { offset: 0x20, size: 8 }))), 'RSP');
  // A register that merely overlaps would name the wrong storage, so a partial match answers empty.
  assert.equal(answeredString(callbacks.answer(askAddress(P.QUERY.getRegisterName, { offset: 0x20, size: 4 }))), '');
  assert.equal(answeredString(callbacks.answer(ask(P.QUERY.getRegister, (w) => w.writeString(P.ATTRIB.NAME, 'NOSUCH')))), null);
});

test('image bytes are answered when every byte asked for is mapped, and refused otherwise', () => {
  const image = Buffer.from('b82a000000c3', 'hex');
  const base = 0x401000n;
  const callbacks = createCallbacks({
    language: language(), spaceIndex,
    readImage: (offset, size) => {
      const at = BigInt(offset) - base;
      if (at < 0n || at + BigInt(size) > BigInt(image.length)) return null;
      return image.subarray(Number(at), Number(at) + size);
    },
  });

  const answer = callbacks.answer(askAddress(P.QUERY.getBytes, { offset: 0x401000, size: 2 }));
  assert.deepEqual(outline(answer), [P.BURST.QUERY_RESPONSE, P.BURST.BYTES, 4, P.BURST.QUERY_RESPONSE_END]);

  // A short answer would desynchronise the stream, because the decompiler reads exactly twice what
  // it asked for. Unmapped bytes are refused instead, which it reports as DataUnavailError.
  const past = callbacks.answer(askAddress(P.QUERY.getBytes, { offset: 0x401000, size: 99 }));
  assert.deepEqual(outline(past), [P.BURST.QUERY_RESPONSE, P.BURST.QUERY_RESPONSE_END]);
});

test('a query whose caller decodes without checking gets a real element, never a refusal', () => {
  // ContextGhidra::getTrackedDefault discards the boolean from getTrackedRegisters and calls
  // openElement unconditionally. Answering nothing leaves it decoding a decoder that was never
  // fed: a segmentation fault, reported as bare exit 1 by the handler that keeps the OS quiet.
  const callbacks = createCallbacks({ language: language(), spaceIndex });
  const answer = callbacks.answer(askAddress(P.QUERY.getTrackedRegisters, {}));
  // Four payload bytes, not two: element 125 does not fit in five bits, so its open and its close
  // each carry an extend byte.
  assert.deepEqual(outline(answer),
    [P.BURST.QUERY_RESPONSE, P.BURST.STRING, 4, P.BURST.STRING_END, P.BURST.QUERY_RESPONSE_END]);

  const decoded = answeredElement(answer);
  assert.equal(decoded.element, P.ELEM.TRACKED_POINTSET);
  assert.equal(decoded.attributes.size, 0, 'an empty point set, but present');
});

test('a query this module does not model is answered with nothing, and counted', () => {
  const callbacks = createCallbacks({ language: language(), spaceIndex });
  const answer = callbacks.answer(ask(P.QUERY.getCpoolRef));
  assert.deepEqual(outline(answer), [P.BURST.QUERY_RESPONSE, P.BURST.QUERY_RESPONSE_END]);
  // Reported rather than silently absorbed: a decompilation missing constant pool data should say
  // so, and refusing outright would abort one that is perfectly possible without it.
  assert.deepEqual(callbacks.unanswered(), [{ query: 'getCpoolRef', count: 1 }]);
  assert.deepEqual(callbacks.asked(), [{ query: 'getCpoolRef', count: 1 }]);
});

test('the register and userop tables are read from the language, not assumed', () => {
  const callbacks = createCallbacks({ language: language(), spaceIndex });
  assert.deepEqual(callbacks.counts(), { registers: 2, userops: 2 });
  // No language at all still answers rather than throwing, because a missing table is a weaker
  // decompilation and not a protocol failure.
  const bare = createCallbacks({});
  assert.deepEqual(bare.counts(), { registers: 0, userops: 0 });
  assert.equal(answeredString(bare.answer(ask(P.QUERY.getUserOpName, (w) => w.writeSignedInteger(P.ATTRIB.INDEX, 0)))), '');
});

// ---------------------------------------------------------------------------------------------
// The symbol model
// ---------------------------------------------------------------------------------------------

test('a function with a known extent is declared in full, with a distinct id', () => {
  const callbacks = createCallbacks({
    language: language(), spaceIndex,
    findFunction: (offset) => (BigInt(offset) === 0x401000n ? { name: 'answer', entry: 0x401000n, size: 6 } : null),
  });
  const decoded = answeredElement(callbacks.answer(askAddress(P.QUERY.getMappedSymbols, { offset: 0x401000 })));

  assert.equal(decoded.element, P.ELEM.PARENT);
  assert.equal(decoded.attributes.get(P.ATTRIB.ID), 0n, 'scope 0 is the global cache, so no namespace lookup');
  const mapsym = decoded.children[0];
  assert.equal(mapsym.element, P.ELEM.MAPSYM);
  const fn = mapsym.children[0];
  assert.equal(fn.element, P.ELEM.FUNCTION);
  assert.equal(fn.attributes.get(P.ATTRIB.NAME), 'answer');
  // Funcdata::decode throws "Missing function size" without this, and the analysis then has no
  // bound on the function it is recovering.
  assert.equal(fn.attributes.get(P.ATTRIB.SIZE), 6n);
  // Left unwritten the id defaults to zero and the function's scope collides, which surfaces as
  // "DuplicateFunctionError, but could not recover original symbol".
  assert.equal(fn.attributes.get(P.ATTRIB.ID), 0x401000n);
  // The mapping: where the symbol lives, then the range over which that mapping holds.
  assert.deepEqual(mapsym.children.slice(1).map((child) => child.element), [P.ELEM.ADDR, P.ELEM.RANGELIST]);
});

test('a function whose extent is unknown is a shell rather than a guessed size', () => {
  const callbacks = createCallbacks({
    language: language(), spaceIndex,
    findFunction: () => ({ name: 'thunk', entry: 0x401000n }),
  });
  const decoded = answeredElement(callbacks.answer(askAddress(P.QUERY.getMappedSymbols, {})));
  const shell = decoded.children[0].children[0];
  assert.equal(shell.element, P.ELEM.FUNCTIONSHELL);
  assert.equal(shell.attributes.get(P.ATTRIB.NAME), 'thunk');
});

test('where there is no function, a hole is reported so the probing terminates', () => {
  // An empty answer caches nothing, so ScopeGhidra re-probes the same addresses forever: measured
  // at 355 repeated queries on one function, with neither a result nor an error.
  const callbacks = createCallbacks({
    language: language(), spaceIndex,
    findFunction: () => null,
    holeAround: () => ({ first: 0x400000n, last: 0x400fffn }),
  });
  const decoded = answeredElement(callbacks.answer(askAddress(P.QUERY.getMappedSymbols, { offset: 0x400500 })));
  assert.equal(decoded.element, P.ELEM.HOLE);
  assert.equal(decoded.attributes.get(P.ATTRIB.FIRST), 0x400000n);
  assert.equal(decoded.attributes.get(P.ATTRIB.LAST), 0x400fffn);

  // A caller that cannot name a true range says nothing rather than claiming a wider hole, which
  // would hide a real function from the decompiler.
  const unsure = createCallbacks({ language: language(), spaceIndex, findFunction: () => null });
  assert.deepEqual(outline(unsure.answer(askAddress(P.QUERY.getMappedSymbols, {}))),
    [P.BURST.QUERY_RESPONSE, P.BURST.QUERY_RESPONSE_END]);
});

// ---------------------------------------------------------------------------------------------
// P-code
// ---------------------------------------------------------------------------------------------

test('lifted p-code becomes an instruction with its length, its address and its operations', () => {
  const callbacks = createCallbacks({
    language: language(), spaceIndex,
    lift: () => ({
      decoded: true, lifted: true, length: 5,
      pcode: [{ op: 'COPY', code: 1, output: { space: 'register', offset: '0x0', size: 8 }, inputs: [{ space: 'const', offset: '0x2a', size: 8 }] }],
    }),
  });
  const decoded = answeredElement(callbacks.answer(askAddress(P.QUERY.getPcode, { offset: 0x401000 })));

  assert.equal(decoded.element, P.ELEM.INST);
  // The offset attribute on <inst> is the instruction's LENGTH; its address is the <addr> child.
  // Conflating them advances the decompiler by the wrong amount and desynchronises what follows.
  assert.equal(decoded.attributes.get(P.ATTRIB.OFFSET), 5n);
  assert.equal(decoded.children[0].element, P.ELEM.ADDR);
  assert.equal(decoded.children[0].attributes.get(P.ATTRIB.OFFSET), 0x401000n);

  const op = decoded.children[1];
  assert.equal(op.element, P.ELEM.OP);
  assert.equal(op.attributes.get(P.ATTRIB.SIZE), 1n, 'size is the input count');
  assert.equal(op.attributes.get(P.ATTRIB.CODE), 1n, 'the raw CPUI opcode number');
  assert.deepEqual(op.children.map((child) => child.element), [P.ELEM.ADDR, P.ELEM.ADDR]);
  // A constant lives in the space the language calls const, which is index 0 and is absent from
  // the declared space list because decodeSpaces inserts it implicitly.
  assert.equal(op.children[1].attributes.get(P.ATTRIB.SPACE), 0n);
});

test('an operation with no output carries an explicit void, not an absent child', () => {
  const callbacks = createCallbacks({
    language: language(), spaceIndex,
    lift: () => ({ decoded: true, lifted: true, length: 1,
      pcode: [{ op: 'RETURN', code: 10, output: null, inputs: [{ space: 'register', offset: '0x288', size: 8 }] }] }),
  });
  const op = answeredElement(callbacks.answer(askAddress(P.QUERY.getPcode, {}))).children[1];
  assert.deepEqual(op.children.map((child) => child.element), [P.ELEM.VOID, P.ELEM.ADDR]);
});

test('LOAD takes an address space as its first operand, which is not a varnode', () => {
  // PcodeOpRaw::decode expects <spaceid> there and converts it with (uintb)(uintp)readSpace(...) —
  // a pointer to the AddrSpace, not an index. A plain constant decodes silently and then cannot be
  // analysed, so the function never completes and the result comes back empty.
  const callbacks = createCallbacks({
    language: language(), spaceIndex,
    lift: () => ({ decoded: true, lifted: true, length: 1,
      pcode: [{ op: 'LOAD', code: 2, output: { space: 'register', offset: '0x288', size: 8 },
        inputs: [{ space: 'const', offset: '0x3', size: 8 }, { space: 'register', offset: '0x20', size: 8 }] }] }),
  });
  const op = answeredElement(callbacks.answer(askAddress(P.QUERY.getPcode, {}))).children[1];
  assert.deepEqual(op.children.map((child) => child.element), [P.ELEM.ADDR, P.ELEM.SPACEID, P.ELEM.ADDR]);
  assert.equal(op.children[1].attributes.get(P.ATTRIB.NAME), 3n, 'the space, by index');
});

test('an instruction the table decodes but does not model is unimplemented, not absent', () => {
  // UnimplError carries the length so the decompiler can step past it. An empty answer means "no
  // p-code could be generated", which aborts the function — a different statement entirely.
  const callbacks = createCallbacks({
    language: language(), spaceIndex,
    lift: () => ({ decoded: true, lifted: false, length: 3, pcode: null }),
  });
  const decoded = answeredElement(callbacks.answer(askAddress(P.QUERY.getPcode, {})));
  assert.equal(decoded.element, P.ELEM.UNIMPL);
  assert.equal(decoded.attributes.get(P.ATTRIB.OFFSET), 3n);

  const nothing = createCallbacks({ language: language(), spaceIndex, lift: () => null });
  assert.deepEqual(outline(nothing.answer(askAddress(P.QUERY.getPcode, {}))),
    [P.BURST.QUERY_RESPONSE, P.BURST.QUERY_RESPONSE_END]);
});

// ---------------------------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------------------------

const respond = (...parts) => Buffer.concat([P.burst(P.BURST.RESPONSE), ...parts, P.burst(P.BURST.RESPONSE_END)]);
const resultString = (text) => Buffer.concat([P.burst(P.BURST.STRING), Buffer.from(text, 'latin1'), P.burst(P.BURST.STRING_END)]);
const queryFor = (element, build) => {
  const writer = new P.PackedWriter();
  writer.openElement(element);
  build?.(writer);
  writer.closeElement(element);
  return Buffer.concat([
    P.burst(P.BURST.QUERY), P.burst(P.BURST.STRING), writer.toBuffer(),
    P.burst(P.BURST.STRING_END), P.burst(P.BURST.QUERY_END),
  ]);
};

test('a command sends its name, its parameters, and the terminator that makes it run', async () => {
  const scripted = scriptedChild();
  const session = createSession({ spawn: () => scripted.child, callbacks: { answer: () => P.answerNothing() } });
  const pending = session.registerProgram({ processorSpec: 'p', compilerSpec: 'c', sleighSpec: 's', coreTypes: 't' });
  scripted.feed(respond(resultString('0')));
  const result = await pending;

  assert.equal(result.archId, '0');
  // Without the type 3 terminator, GhidraCommand::doit blocks on a read forever having already
  // emitted its response header, which reads exactly like a hang in the decompiler.
  assert.deepEqual(outline(scripted.writes[0]), [
    P.BURST.COMMAND,
    P.BURST.STRING, 15, P.BURST.STRING_END,
    P.BURST.STRING, 1, P.BURST.STRING_END,
    P.BURST.STRING, 1, P.BURST.STRING_END,
    P.BURST.STRING, 1, P.BURST.STRING_END,
    P.BURST.STRING, 1, P.BURST.STRING_END,
    P.BURST.COMMAND_END,
  ]);
});

test('a query inside the result frame does not cost the result', async () => {
  // The regression that cost the most. DecompileAt::rawAction opens the result string, encodes the
  // function, then calls print->docFunction, which fetches comments — so a query arrives with the
  // result frame still open and the C continues into that same frame afterwards. A reader holding
  // one current frame and clearing it on a query discarded 468 bytes of C, ignored the remaining
  // 241, and reported a successful decompilation with an empty result.
  const scripted = scriptedChild();
  const answered = [];
  const session = createSession({
    spawn: () => scripted.child,
    callbacks: { answer: (query) => { answered.push(query.element); return P.answerNothing(); } },
  });
  const pending = session.decompileAt({ space: 3, offset: 0x401000n });
  scripted.feed(Buffer.concat([
    P.burst(P.BURST.RESPONSE),
    P.burst(P.BURST.STRING), Buffer.from('BEFORE-', 'latin1'),
    queryFor(P.QUERY.getComments),
    Buffer.from('-AFTER', 'latin1'), P.burst(P.BURST.STRING_END),
    P.burst(P.BURST.RESPONSE_END),
  ]));

  const result = await pending;
  assert.deepEqual(answered, [P.QUERY.getComments], 'the nested query is still answered');
  assert.equal(result.text, 'BEFORE--AFTER', 'and both halves of the result survive it');
});

test('the reader recovers the same result however the stream is chunked', async () => {
  const source = 'undefined8 answer(void) { return 0x2a; }';
  const stream = Buffer.concat([
    P.burst(P.BURST.RESPONSE),
    queryFor(P.QUERY.getUserOpName, (w) => w.writeSignedInteger(P.ATTRIB.INDEX, 0)),
    P.burst(P.BURST.STRING), Buffer.from(source, 'latin1'), P.burst(P.BURST.STRING_END),
    P.burst(P.BURST.WARNING), Buffer.from('a warning', 'latin1'), P.burst(P.BURST.WARNING_END),
    P.burst(P.BURST.RESPONSE_END),
  ]);

  // Every split point, because a marker is four bytes and a chunk boundary can fall inside one.
  for (let split = 1; split < stream.length; split++) {
    const scripted = scriptedChild();
    const warned = [];
    const session = createSession({
      spawn: () => scripted.child,
      callbacks: { answer: () => P.answerString('LOCK') },
      onWarning: (warning) => warned.push(warning),
    });
    const pending = session.decompileAt({ space: 3, offset: 0n });
    scripted.feed(stream.subarray(0, split));
    scripted.feed(stream.subarray(split));
    const result = await pending;
    assert.equal(result.text, source, `split at ${split}`);
    assert.deepEqual(warned, ['a warning'], `split at ${split}`);
  }
});

test('a zero byte outside a marker is refused rather than resynchronised on a guess', async () => {
  const scripted = scriptedChild();
  const session = createSession({ spawn: () => scripted.child, callbacks: { answer: () => P.answerNothing() } });
  const pending = session.decompileAt({ space: 3, offset: 0n });
  scripted.feed(Buffer.concat([P.burst(P.BURST.RESPONSE), Buffer.from([0x41, 0x00, 0x00, 0x42, 0x43])]));
  await assert.rejects(pending, (error) => error.code === 'DECOMPILE_PROTOCOL');
});

test('setAction refuses a rejection rather than reporting an action it did not get', async () => {
  const scripted = scriptedChild();
  const session = createSession({ spawn: () => scripted.child, callbacks: { answer: () => P.answerNothing() } });
  const pending = session.setAction({ action: 'decompile', print: 'c' });
  scripted.feed(respond(resultString('f')));
  await assert.rejects(pending, (error) => error.code === 'DECOMPILE_SETACTION');
});

test('an exit without an answer names the segv handler that hides the reason', async () => {
  const scripted = scriptedChild();
  const session = createSession({ spawn: () => scripted.child, callbacks: { answer: () => P.answerNothing() } });
  const pending = session.decompileAt({ space: 3, offset: 0n });
  scripted.exit(1);
  await assert.rejects(pending, (error) => error.code === 'DECOMPILE_EXITED' && /segv handler/.test(error.message));
});

test('a decompiler that never answers fails at its deadline rather than hanging', async () => {
  const scripted = scriptedChild();
  const session = createSession({ spawn: () => scripted.child, callbacks: { answer: () => P.answerNothing() }, timeoutMs: 40 });
  await assert.rejects(session.decompileAt({ space: 3, offset: 0n }), (error) => error.code === 'DECOMPILE_TIMEOUT');
});

test('two commands at once is refused, because one response cannot answer both', async () => {
  const scripted = scriptedChild();
  const session = createSession({ spawn: () => scripted.child, callbacks: { answer: () => P.answerNothing() }, timeoutMs: 500 });
  const first = session.decompileAt({ space: 3, offset: 0n });
  await assert.rejects(session.decompileAt({ space: 3, offset: 8n }), (error) => error.code === 'DECOMPILE_BUSY');
  scripted.feed(respond(resultString('x')));
  await first;
});

test('a query that cannot be parsed is still answered, or the decompiler deadlocks on a read', async () => {
  const scripted = scriptedChild();
  const session = createSession({ spawn: () => scripted.child, callbacks: { answer: () => { throw new Error('unparseable'); } } });
  const pending = session.decompileAt({ space: 3, offset: 0n });
  scripted.feed(Buffer.concat([
    P.burst(P.BURST.RESPONSE),
    queryFor(P.QUERY.getUserOpName, (w) => w.writeSignedInteger(P.ATTRIB.INDEX, 0)),
    resultString('done'),
    P.burst(P.BURST.RESPONSE_END),
  ]));
  const result = await pending;
  assert.equal(result.text, 'done');
  // writes[0] is the command; writes[1] must be an answer rather than nothing at all.
  assert.deepEqual(outline(scripted.writes[1]), [P.BURST.QUERY_RESPONSE, P.BURST.QUERY_RESPONSE_END]);
});

test('a session cannot be started without a transport or a way to answer', () => {
  assert.throws(() => createSession({ callbacks: { answer: () => P.answerNothing() } }), (error) => error.code === 'DECOMPILE_CONFIG');
  assert.throws(() => createSession({ spawn: () => scriptedChild().child }), (error) => error.code === 'DECOMPILE_CONFIG');
});

// ---------------------------------------------------------------------------------------------
// Recovering the source from the document
// ---------------------------------------------------------------------------------------------

/** A markup token, hand-encoded from marshal.hh: <syntax XMLcontent="..."/>. */
const token = (text) => Buffer.concat([
  Buffer.from([0x40 | 24, 0xc0 | 1, (7 << 4) | 1, 0x80 | text.length]),
  Buffer.from(text, 'latin1'),
  Buffer.from([0x80 | 24]),
]);

/** <break indent=N/>, which is a newline followed by N spaces. */
const lineBreak = (indent) => Buffer.from(
  indent === 0
    ? [0x40 | 17, 0xe0, 0xa6, (2 << 4) | 0, 0x80 | 17]
    : [0x40 | 17, 0xe0, 0xa6, (2 << 4) | 1, 0x80 | indent, 0x80 | 17],
);

test('C is recovered from markup, which is how the decompiler actually emits it', () => {
  // Hand-encoded rather than written with PackedWriter, so this does not merely confirm that my
  // encoder and my extractor agree with each other.
  const document = Buffer.concat([
    token('undefined8 answer(void)'),
    lineBreak(0), token('{'),
    lineBreak(2), token('return 0x2a;'),
    lineBreak(0), token('}'),
  ]);
  assert.equal(extractSource(document), 'undefined8 answer(void)\n{\n  return 0x2a;\n}');
});

test('extraction skips records it does not model instead of derailing on them', () => {
  // The document mixes several vocabularies — function data, prototypes, print markup — so an
  // unrecognised element must cost nothing. Here an <addr> with attributes sits between tokens.
  const writer = new P.PackedWriter();
  writer.openElement(P.ELEM.ADDR).writeSpace(P.ATTRIB.SPACE, 3).writeUnsignedInteger(P.ATTRIB.OFFSET, 0x401000).closeElement(P.ELEM.ADDR);
  assert.equal(extractSource(Buffer.concat([token('int '), writer.toBuffer(), token('x;')])), 'int x;');
  assert.equal(extractSource(Buffer.alloc(0)), '');
});

test('only a content attribute is source text, and only inside break is indent a newline', () => {
  // A name attribute carries a string too, and treating every string as source would splice symbol
  // names into the output.
  const named = new P.PackedWriter();
  named.openElement(P.ELEM.FUNCTIONSHELL).writeString(P.ATTRIB.NAME, 'not source').closeElement(P.ELEM.FUNCTIONSHELL);
  assert.equal(extractSource(named.toBuffer()), '');

  // An indent attribute outside a break element is an ordinary number, not a line.
  const elsewhere = new P.PackedWriter();
  elsewhere.openElement(P.ELEM.OP).writeSignedInteger(P.ATTRIB.INDENT, 4).closeElement(P.ELEM.OP);
  assert.equal(extractSource(elsewhere.toBuffer()), '');
});

test('the core types are a real type system, because an empty one is fatal', () => {
  // TypeFactory::decodeCoreTypes calls cacheCoreTypes, which fills a table indexed by size and
  // metatype. With nothing declared every slot stays null and the first request for a four byte
  // integer dereferences one.
  assert.match(CORE_TYPES, /^<coretypes>/);
  assert.match(CORE_TYPES, /<void\/>/);
  for (const size of [1, 2, 4, 8]) {
    assert.ok(CORE_TYPES.includes(`name="int${size}" size="${size}" metatype="int"`), `int${size} must be declared`);
    assert.ok(CORE_TYPES.includes(`name="uint${size}" size="${size}" metatype="uint"`), `uint${size} must be declared`);
    assert.ok(CORE_TYPES.includes(`name="undefined${size}"`), `undefined${size} must be declared`);
  }
  assert.ok(CORE_TYPES.includes('metatype="bool"'));
  assert.ok(CORE_TYPES.includes('metatype="code"'));
});
