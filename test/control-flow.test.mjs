import test from 'node:test';
import assert from 'node:assert/strict';
import { loadLanguage } from '../src/sleigh.mjs';
import { recoverControlFlow } from '../src/control-flow.mjs';
import { canonical } from '../src/value.mjs';
import { buildDecodableSla } from './ghidra-fixtures.mjs';

/**
 * Control flow recovered from p-code.
 *
 * Everything asserted here is architecture-independent by construction: the analysis reads only
 * BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND and RETURN, and the toy language emits exactly those.
 * The cases chosen are the ones where a plausible-looking implementation is wrong — a join point
 * losing its edge, a call being treated as a jump, a delay slot being treated as a successor.
 *
 * It has also been checked against real code on three architectures, which cannot live here
 * because it needs the Ghidra distribution: an x86 if/join, an x86 loop with a call, an x86
 * indirect jump, a MIPS branch with a delay slot, and an ARM backward loop.
 */

const toy = () => loadLanguage(buildDecodableSla());
const program = (...values) => Buffer.from(values);
const blockAt = (result, start) => result.blocks.find((block) => block.start === start);

test('a conditional branch yields both edges, and the join point keeps its fallthrough', () => {
  //   0x00  brc 0x05   -> 0x05 and 0x02
  //   0x02  ld 0x01    -> 0x04
  //   0x04  halt       -> 0x05
  //   0x05  ret
  const result = recoverControlFlow(toy(), program(0x05, 0x05, 0x02, 0x01, 0x00, 0x03), { address: 0n });
  assert.equal(result.counts.blocks, 3);
  assert.equal(result.counts.instructions, 4);

  const head = blockAt(result, '0x0');
  assert.equal(head.kind, 'conditional');
  assert.deepEqual(head.successors, [{ to: '0x5', kind: 'branch' }, { to: '0x2', kind: 'fallthrough' }]);

  // The middle block ends only because 0x5 is a branch target, not because its last instruction
  // stops flowing. Deciding successors while partitioning loses this edge, and the block then
  // reads as unreachable code rather than as the path into a join.
  const middle = blockAt(result, '0x2');
  assert.equal(middle.instructions, 2);
  assert.deepEqual(middle.successors, [{ to: '0x5', kind: 'fallthrough' }]);

  const tail = blockAt(result, '0x5');
  assert.equal(tail.kind, 'return');
  assert.deepEqual(tail.successors, []);
});

test('an unconditional branch has no fallthrough, and what follows it is not decoded', () => {
  //   0x00  br 0x04    -> 0x04 only
  //   0x02  ld 0x01    unreachable: nothing branches here and the branch above does not fall through
  //   0x04  ret
  const result = recoverControlFlow(toy(), program(0x04, 0x04, 0x02, 0x01, 0x03), { address: 0n });
  const head = blockAt(result, '0x0');
  assert.equal(head.kind, 'branch');
  assert.deepEqual(head.successors, [{ to: '0x4', kind: 'branch' }]);
  // Following flow rather than sweeping linearly is the whole point: the bytes at 0x2 are never
  // reached, so they are never decoded and never reported as instructions.
  assert.deepEqual(result.instructions.map((instruction) => instruction.address), ['0x0', '0x4']);
  assert.equal(result.counts.instructions, 2);
});

test('a call is a call edge, not a control-flow edge, and the block continues through it', () => {
  //   0x00  call 0x40  -> a call edge, and flow continues to 0x02
  //   0x02  ret
  const result = recoverControlFlow(toy(), program(0x06, 0x40, 0x03), { address: 0n });
  // flow.cc sets startbasic for CBRANCH, BRANCH, BRANCHIND and RETURN only, so a call does not
  // end a block. Treating a call as a jump would split this into two and lose the return.
  assert.equal(result.counts.blocks, 1);
  assert.equal(result.blocks[0].instructions, 2);
  assert.equal(result.blocks[0].kind, 'return');
  assert.deepEqual(result.calls, [{ from: '0x0', to: '0x40', kind: 'direct' }]);
  // The call target is outside the range and is not traced: a called address begins its own
  // region, and following it would merge two functions into one graph.
  assert.ok(result.limitations.some((line) => /not traced/.test(line)));
  assert.deepEqual(result.instructions[0].callTargets, ['0x40']);
  assert.deepEqual(result.instructions[0].branchTargets, []);
});

test('a backward branch is a back edge rather than a new region', () => {
  //   0x00  ld 0x01   -> 0x02
  //   0x02  brc 0x00  -> back to 0x00, and falls through to 0x04
  //   0x04  ret
  const result = recoverControlFlow(toy(), program(0x02, 0x01, 0x05, 0x00, 0x03), { address: 0n });
  // Two blocks, not three. The target 0x0 is already this block's own start, so the back edge
  // needs no split: the loop body is one block whose successors are itself and the exit.
  assert.equal(result.counts.blocks, 2);
  const body = blockAt(result, '0x0');
  assert.equal(body.instructions, 2);
  assert.deepEqual(body.successors, [{ to: '0x0', kind: 'branch' }, { to: '0x4', kind: 'fallthrough' }]);
  assert.equal(body.successors[0].to, body.start, 'the back edge targets the block it leaves');
  // The loop header is reached twice and decoded once.
  assert.equal(result.counts.instructions, 3);
  assert.equal(blockAt(result, '0x4').kind, 'return');
});

test('a delay slot belongs to its branch rather than being its successor', () => {
  //   0x00  inc        declares a delay slot, so the next instruction executes as part of it
  //   0x01  ld 0x01    consumed as the delay slot
  //   0x03  ret
  const result = recoverControlFlow(toy(), program(0x01, 0x02, 0x01, 0x03), { address: 0n });
  const first = result.instructions[0];
  assert.equal(first.delaySlotBytes, 1);
  // The delay slot instruction is named as belonging to this one, and flow resumes past it.
  assert.deepEqual(first.delaySlots.map((slot) => slot.address), ['0x1']);
  assert.equal(first.fallThrough, '0x3');
  // It is not reported as a separate instruction in the graph, because it is not a separate step.
  assert.deepEqual(result.instructions.map((instruction) => instruction.address), ['0x0', '0x3']);
});

test('an opcode nothing claims is reported unresolved rather than skipped', () => {
  //   0x00  brc 0x02  -> 0x02 and 0x02
  //   0x02  (0x07, which no constructor claims)
  const result = recoverControlFlow(toy(), program(0x05, 0x02, 0x07), { address: 0n });
  assert.equal(result.counts.unresolved, 1);
  assert.deepEqual(result.unresolved[0], { address: '0x2', kind: 'undecodable', reason: 'no_matching_constructor' });
  // An undecodable address is not an instruction, so it does not appear in the instruction list.
  assert.deepEqual(result.instructions.map((instruction) => instruction.address), ['0x0']);
});

test('reachability starts only from the entry points that were given', () => {
  //   0x00  ret        a region that ends immediately
  //   0x01  ld 0x01    only reachable if named as an entry
  const code = program(0x03, 0x02, 0x01);
  const fromStart = recoverControlFlow(toy(), code, { address: 0n });
  assert.deepEqual(fromStart.instructions.map((instruction) => instruction.address), ['0x0']);

  const both = recoverControlFlow(toy(), code, { address: 0n, entries: [0n, 1n] });
  assert.deepEqual(both.instructions.map((instruction) => instruction.address), ['0x0', '0x1']);
  assert.deepEqual(both.entries, ['0x0', '0x1']);
  assert.ok(fromStart.limitations.some((line) => /from the supplied entry points only/.test(line)));
});

test('the recovery is canonical and repeatable, which is what replay would verify', () => {
  const code = program(0x05, 0x05, 0x02, 0x01, 0x00, 0x03);
  const once = recoverControlFlow(toy(), code, { address: 0n });
  const twice = recoverControlFlow(toy(), code, { address: 0n });
  // Every address leaves as a hex string, so the whole result is inside the JSON domain; a BigInt
  // would make canonical reject it outright and no run could be recorded.
  assert.equal(canonical(once), canonical(twice));
  assert.ok(once.instructions.every((instruction) => typeof instruction.address === 'string'));
  assert.ok(once.blocks.every((block) => typeof block.start === 'string'));
});

test('the instruction budget is reported rather than quietly truncating the graph', () => {
  // A single-instruction budget against a program with more than one reachable instruction.
  const result = recoverControlFlow(toy(), program(0x02, 0x01, 0x02, 0x01, 0x03), { address: 0n, limit: 1 });
  assert.equal(result.counts.instructions, 1);
  assert.ok(result.limitations.some((line) => /instruction limit/.test(line)));
});
