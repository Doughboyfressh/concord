import test from 'node:test';
import assert from 'node:assert/strict';
import { loadLanguage, decodeInstruction, decodeRange, contextFields, liftInstruction } from '../src/sleigh.mjs';
import { canonical } from '../src/value.mjs';
import { buildDecodableSla, buildSla } from './ghidra-fixtures.mjs';

/**
 * The SLEIGH decode engine.
 *
 * The decisive evidence for this engine is not here and cannot be: it is 29 instruction encodings
 * across 6502, JVM, x86-32, x86-64, ARM, AARCH64, MIPS, 8051, Z80 and PowerPC, decoded from the
 * shipped tables and checked against disassembly known independently. That needs an 876 MB
 * distribution, so what is checked here are the properties that hold for a language of three
 * instructions and would still have caught the mistakes that mattered: bit-indexed descent,
 * operand offsets, length accumulation, and a refusal where no constructor matches.
 */

const language = () => loadLanguage(buildDecodableSla());
const bytes = (...values) => Buffer.from(values);

test('a compiled table becomes a language with its root table and spaces', () => {
  const toy = language();
  assert.equal(toy.formatVersion, 4);
  assert.equal(toy.bigEndian, false);
  assert.equal(toy.alignment, 1);
  assert.equal(toy.defaultSpace, 'ram');
  assert.equal(toy.root.name, 'instruction');
  assert.equal(toy.root.constructors.length, 7);
  // The root is found by name, as sleighbase.cc does after decoding, rather than by assuming an id.
  assert.equal(toy.root.kind, 'subtable');
  assert.deepEqual(toy.spaces.map((space) => space.name), ['unique', 'ram', 'register']);
  // The constant space is index 0 and is never serialised: sleighbase.cc re-inserts it before
  // reading, so a template naming space 0 means a literal rather than an unknown space.
  assert.equal(toy.spaceByIndex.get(0).name, 'const');
  assert.equal(toy.spaceByIndex.get(3).name, 'register');
  assert.deepEqual(toy.sourceFiles, ['toy.slaspec']);
});

test('an instruction with no operands decodes to its mnemonic and its own length', () => {
  const toy = language();
  const halt = decodeInstruction(toy, bytes(0x00, 0xff, 0xff), { address: 0x1000n });
  assert.equal(halt.decoded, true);
  assert.equal(halt.mnemonic, 'halt');
  assert.equal(halt.body, null);
  assert.equal(halt.text, 'halt');
  assert.equal(halt.length, 1);
  assert.equal(halt.address, 0x1000n);
  // The constructor that matched is reported, so a decode can be traced back to the line of
  // SLEIGH that produced it rather than being taken on trust.
  assert.deepEqual(halt.constructors, [{ table: 'instruction', constructorIndex: 0, source: 0, line: 1 }]);

  const inc = decodeInstruction(toy, bytes(0x01), { address: 0n });
  assert.equal(inc.text, 'inc');
  assert.equal(inc.length, 1);
});

test('an operand extends the instruction length and prints its decoded value', () => {
  const toy = language();
  const decoded = decodeInstruction(toy, bytes(0x02, 0x42), { address: 0x2000n });
  assert.equal(decoded.decoded, true);
  assert.equal(decoded.mnemonic, 'ld');
  assert.equal(decoded.body, '0x42');
  assert.equal(decoded.text, 'ld 0x42');
  // The constructor itself consumes one byte; the operand sits at offset 1 and is one byte long,
  // so the instruction is two. Lengths are relative to their constructor and offsets are absolute
  // from the start of the instruction, and conflating the two is how variable length decode breaks.
  assert.equal(decoded.length, 2);

  // The operand really is read from the second byte, not from a fixed position or the first.
  assert.equal(decodeInstruction(toy, bytes(0x02, 0x00), {}).body, '0x0');
  assert.equal(decodeInstruction(toy, bytes(0x02, 0xff), {}).body, '0xff');
});

test('an opcode no constructor claims is refused rather than rounded to a neighbour', () => {
  const toy = language();
  // The eighth branch of the decision tree is deliberately empty. Reporting the nearest match
  // would turn an unknown encoding into a confident wrong answer.
  const unmatched = decodeInstruction(toy, bytes(0x07), { address: 0n });
  assert.equal(unmatched.decoded, false);
  assert.equal(unmatched.reason, 'no_matching_constructor');
  assert.equal(unmatched.length, 0);
  assert.equal(unmatched.mnemonic, null);
  assert.equal(unmatched.text, null);
  assert.deepEqual(unmatched.constructors, []);
});

test('a truncated operand does not throw: the bytes that are missing read as zero', () => {
  const toy = language();
  // A one byte buffer for a two byte instruction. Ghidra's buffer is filled past the end of
  // available memory too, so the honest behaviour is to decode what the table says and let the
  // caller see the length exceed what was supplied.
  const short = decodeInstruction(toy, bytes(0x02), { address: 0n });
  assert.equal(short.decoded, true);
  assert.equal(short.length, 2);
  assert.equal(short.body, '0x0');
});

test('a sequence decodes one instruction after another, advancing by each length', () => {
  const toy = language();
  const run = decodeRange(toy, bytes(0x00, 0x01, 0x02, 0x7f, 0x00), { address: 0x400000n });
  assert.equal(run.bytesDecoded, 5);
  assert.deepEqual(run.instructions.map((instruction) => instruction.text), ['halt', 'inc', 'ld 0x7f', 'halt']);
  assert.deepEqual(run.instructions.map((instruction) => instruction.offset), [0, 1, 2, 4]);
  // Addresses advance by the decoded length, so the two byte `ld` moves the next address by two.
  assert.deepEqual(run.instructions.map((instruction) => instruction.address),
    [0x400000n, 0x400001n, 0x400002n, 0x400004n]);
});

test('a sequence stops at the first encoding it cannot decode rather than resynchronising', () => {
  const toy = language();
  const run = decodeRange(toy, bytes(0x00, 0x07, 0x00), { address: 0n });
  assert.equal(run.instructions.length, 2);
  assert.equal(run.instructions[0].text, 'halt');
  assert.equal(run.instructions[1].decoded, false);
  // One byte was decoded and the rest was never reached. Guessing a resynchronisation point would
  // invent instruction boundaries the table does not support.
  assert.equal(run.bytesDecoded, 1);
});

test('the decode is a pure function of its inputs, which is what replay would verify', () => {
  const toy = language();
  const once = decodeInstruction(toy, bytes(0x02, 0x42), { address: 0x1000n });
  const twice = decodeInstruction(toy, bytes(0x02, 0x42), { address: 0x1000n });
  // BigInt is outside the JSON domain, so the address is compared separately and the rest
  // canonically; canonical() would reject an undefined key, so this also proves there is none.
  assert.equal(once.address, twice.address);
  assert.equal(canonical({ ...once, address: String(once.address) }), canonical({ ...twice, address: String(twice.address) }));
});

test('a table with no constructors loads but decodes nothing, rather than appearing to work', () => {
  // buildSla carries symbol names and spaces but no decision tree. A decoder handed it must not
  // pretend: there is genuinely nothing to match.
  const described = loadLanguage(buildSla());
  assert.equal(described.root.name, 'instruction');
  assert.equal(described.root.constructors, undefined);
  const attempt = decodeInstruction(described, bytes(0x00), {});
  assert.equal(attempt.decoded, false);
  assert.equal(attempt.reason, 'no_matching_constructor');
});

test('a file that is not a compiled table is refused by code, not by crashing', () => {
  assert.throws(() => loadLanguage(Buffer.from('not a sleigh table')), (error) => error.code === 'SLEIGH_TABLE');
  // Version 4 is asserted: a later format would still inflate and still produce element ids, so
  // the ids would be read against a table that may have been renumbered.
  const wrongVersion = Buffer.concat([Buffer.from('sla'), Buffer.from([9]), buildDecodableSla().subarray(4)]);
  assert.throws(() => loadLanguage(wrongVersion), (error) => error.code === 'SLEIGH_TABLE');
});

test('an instruction lifts to the p-code its template declares', () => {
  const toy = language();
  const lifted = liftInstruction(toy, bytes(0x01), { address: 0x1000n });
  assert.equal(lifted.lifted, true);
  assert.equal(lifted.text, 'inc');
  // r0 = r0 + 1. The space names come from the table's own space list, and a literal lands in the
  // constant space, which is index 0 because sleighbase.cc re-inserts it rather than serialising it.
  assert.deepEqual(lifted.pcode, [{
    op: 'INT_ADD', code: 19,
    output: { space: 'register', offset: '0x0', size: 4 },
    inputs: [{ space: 'register', offset: '0x0', size: 4 }, { space: 'const', offset: '0x1', size: 4 }],
    synthetic: null,
  }]);
});

test('an operand value reaches p-code through the handle its constructor exported', () => {
  const toy = language();
  // This is the whole reason lifting needs a second pass: the COPY's input names operand 0's
  // handle, and that handle is only known once the operand itself has been resolved.
  const lifted = liftInstruction(toy, bytes(0x02, 0x42), { address: 0n });
  assert.equal(lifted.text, 'ld 0x42');
  assert.equal(lifted.pcode.length, 1);
  assert.equal(lifted.pcode[0].op, 'COPY');
  assert.deepEqual(lifted.pcode[0].output, { space: 'register', offset: '0x0', size: 4 });
  assert.deepEqual(lifted.pcode[0].inputs, [{ space: 'const', offset: '0x42', size: 4 }]);
  // The value really came from the instruction bytes rather than a fixed constant.
  assert.deepEqual(liftInstruction(toy, bytes(0x02, 0x07), {}).pcode[0].inputs,
    [{ space: 'const', offset: '0x7', size: 4 }]);
});

test('a constructor with no semantics is reported as unimplemented, not as doing nothing', () => {
  const toy = language();
  const lifted = liftInstruction(toy, bytes(0x00), { address: 0n });
  assert.equal(lifted.lifted, true);
  assert.deepEqual(lifted.pcode, []);
  // An empty p-code list and an absent template mean different things: one is an instruction with
  // no effect, the other is an effect this table does not model. Only the directive distinguishes them.
  assert.deepEqual(lifted.directives, [{ directive: 'UNIMPLEMENTED', detail: 'This constructor declares no semantics' }]);
  assert.ok(lifted.liftLimitations.some((line) => /incomplete rather than complete/.test(line)));
});

test('a delay slot is reported as part of the effect that is missing', () => {
  const toy = language();
  const lifted = liftInstruction(toy, bytes(0x01), { address: 0n });
  // `inc` declares a delay slot, so the following instruction executes as part of it. The p-code
  // here is therefore not the whole effect, and saying so is the difference between a partial
  // answer and a wrong one.
  assert.equal(lifted.delaySlotBytes, 1);
  assert.ok(lifted.liftLimitations.some((line) => /delay slot/.test(line)));
});

test('lifting an undecodable instruction reports why instead of returning empty p-code', () => {
  const toy = language();
  const lifted = liftInstruction(toy, bytes(0x07), { address: 0n });
  assert.equal(lifted.lifted, false);
  assert.equal(lifted.liftReason, 'no_matching_constructor');
  assert.deepEqual(lifted.pcode, []);
  assert.deepEqual(lifted.directives, []);
});

test('a lift is canonical and repeatable, and never leaks the parse tree', () => {
  const toy = language();
  const once = liftInstruction(toy, bytes(0x02, 0x42), { address: 0x1000n });
  const twice = liftInstruction(toy, bytes(0x02, 0x42), { address: 0x1000n });
  // The walker is an internal object with parent cycles; if it escaped into the result, canonical
  // would reject it and every lifted run would be unrepresentable rather than merely unequal.
  assert.equal(Object.hasOwn(once, 'walker'), false);
  assert.equal(canonical({ ...once, address: String(once.address) }),
    canonical({ ...twice, address: String(twice.address) }));
});

test('a sequence can be lifted instruction by instruction', () => {
  const toy = language();
  const run = decodeRange(toy, bytes(0x01, 0x02, 0x7f, 0x00), { address: 0x500n, pcode: true });
  assert.deepEqual(run.instructions.map((instruction) => instruction.text), ['inc', 'ld 0x7f', 'halt']);
  assert.deepEqual(run.instructions.map((instruction) => instruction.pcode.length), [1, 1, 0]);
  assert.equal(run.instructions[1].pcode[0].inputs[0].offset, '0x7f');
});

test('context fields are named by the language, and an unknown name is refused', () => {
  const toy = language();
  // The toy language declares no context register, so there is nothing to set and asking to set
  // something is a mistake worth raising. Dropping it silently would decode in the wrong mode and
  // still look like a correct answer, which is exactly what happened with x86 operand size.
  assert.equal(contextFields(toy).size, 0);
  assert.throws(() => decodeInstruction(toy, bytes(0x00), { contextValues: { opsize: 1 } }),
    (error) => error.code === 'SLEIGH_CONTEXT');
});
