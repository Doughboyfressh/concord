import test from 'node:test';
import assert from 'node:assert/strict';
import { loadLanguage } from '../src/sleigh.mjs';
import { recoverControlFlow, recoverCallGraph } from '../src/control-flow.mjs';
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
  //   0x02  (0x08, which no constructor claims)
  const result = recoverControlFlow(toy(), program(0x05, 0x02, 0x08), { address: 0n });
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

test('a call graph grows one entry into every region a call can reach', () => {
  //   0x00  call 0x04     main
  //   0x02  ret
  //   0x04  call 0x08     helper
  //   0x06  ret
  //   0x08  ret           leaf
  const result = recoverCallGraph(toy(), program(0x06, 0x04, 0x03, 0x00, 0x06, 0x08, 0x03, 0x00, 0x03), { address: 0n });
  assert.equal(result.counts.regions, 3);
  assert.equal(result.counts.callEdges, 2);
  assert.equal(result.counts.leaves, 1);
  assert.deepEqual(result.regions.map((region) => region.entry), ['0x0', '0x4', '0x8']);
  // Each region is only its own body: following a call would merge the callee into the caller.
  assert.deepEqual(result.regions.map((region) => region.instructions), [2, 2, 1]);
  assert.deepEqual(result.edges.map((edge) => [edge.from, edge.to, edge.kind]),
    [['0x0', '0x4', 'call'], ['0x4', '0x8', 'call']]);
  // A node records how many call sites reach it, which is not the same as how many callers it has.
  assert.equal(result.nodes.find((node) => node.address === '0x4').calledBy, 1);
  assert.equal(result.nodes.find((node) => node.address === '0x0').calledBy, 0);
});

test('two call sites to one callee are two edges, because the sites are different facts', () => {
  //   0x00  call 0x06 ; 0x02 call 0x06 ; 0x04 ret ; 0x06 ret
  const result = recoverCallGraph(toy(), program(0x06, 0x06, 0x06, 0x06, 0x03, 0x00, 0x03), { address: 0n });
  assert.equal(result.counts.edges, 2);
  assert.deepEqual(result.edges.map((edge) => edge.site), ['0x0', '0x2']);
  // Collapsing them would lose the call sites, which is where a caller looks to find the arguments.
  assert.equal(result.nodes.find((node) => node.address === '0x6').calledBy, 2);
  assert.equal(result.counts.regions, 2);
});

test('mutual recursion is reported on both regions, not just on a self-call', () => {
  //   0x00  call 0x04 ; 0x02 ret ; 0x04 call 0x00 ; 0x06 ret
  const result = recoverCallGraph(toy(), program(0x06, 0x04, 0x03, 0x00, 0x06, 0x00, 0x03), { address: 0n });
  assert.equal(result.counts.recursive, 2);
  assert.ok(result.nodes.every((node) => node.recursive));
  // Reachability, not a self-edge test: neither region calls itself directly.
  assert.ok(result.edges.every((edge) => edge.from !== edge.to));
});

test('a branch into another region is a tail candidate, and does not swallow that region', () => {
  //   0x00  call 0x06
  //   0x02  call 0x08
  //   0x04  ret
  //   0x05  halt        padding, unreachable
  //   0x06  br 0x08     a tail jump into a known entry
  //   0x08  ret
  // 0x08 is a known entry because 0x00 calls it, so the branch at 0x06 leaves its region.
  const result = recoverCallGraph(toy(),
    program(0x06, 0x06, 0x06, 0x08, 0x03, 0x00, 0x04, 0x08, 0x03), { address: 0n });
  assert.equal(result.counts.regions, 3);
  assert.equal(result.counts.tailCandidates, 1);

  const tail = result.edges.find((edge) => edge.kind === 'tail');
  assert.deepEqual([tail.from, tail.to, tail.via, tail.candidate], ['0x6', '0x8', 'branch', true]);
  // The jumping region is one instruction and does not contain the callee's body. Without the
  // second pass it would have absorbed 0x08 and this edge would not exist at all.
  const jumper = result.regions.find((region) => region.entry === '0x6');
  assert.equal(jumper.instructions, 1);
  assert.deepEqual(jumper.overlaps, []);
  assert.equal(result.regions.find((region) => region.entry === '0x8').instructions, 1);
  // The intent is not asserted, only the structure, and the output says so.
  assert.ok(result.limitations.some((line) => /marked candidate/.test(line)));
});

test('falling through into the next region is reported too, by the same rule', () => {
  //   0x00  call 0x04
  //   0x02  ld 0x00     and then no return, so flow runs on into 0x04
  //   0x04  ret
  // A function that ends without a return and runs into its neighbour is the same structural fact
  // as a tail jump, reached by fallthrough instead of a branch, so it is reported the same way
  // rather than silently merging the two regions into one.
  const result = recoverCallGraph(toy(), program(0x06, 0x04, 0x02, 0x00, 0x03), { address: 0n });
  assert.equal(result.counts.regions, 2);
  const tail = result.edges.find((edge) => edge.kind === 'tail');
  assert.deepEqual([tail.from, tail.to, tail.via], ['0x0', '0x4', 'fallthrough']);
  // The caller stops at the boundary: two instructions, not three.
  assert.equal(result.regions.find((region) => region.entry === '0x0').instructions, 2);
});

test('a call outside the range is an external node, not a dangling edge', () => {
  //   0x00  call 0x40  (outside a four byte range) ; 0x02 ret
  const result = recoverCallGraph(toy(), program(0x06, 0x40, 0x03, 0x00), { address: 0n });
  assert.deepEqual(result.external, ['0x40']);
  assert.equal(result.counts.regions, 1);
  const node = result.nodes.find((entry) => entry.address === '0x40');
  assert.equal(node.kind, 'external');
  assert.equal(node.calledBy, 1);
  // The edge is real even though the callee was never read, so it is kept and the node is marked.
  assert.deepEqual(result.edges.map((edge) => edge.to), ['0x40']);
  assert.ok(result.limitations.some((line) => /outside the analysed range/.test(line)));
});

test('the region budget is reported rather than silently returning a partial graph', () => {
  const code = program(0x06, 0x04, 0x03, 0x00, 0x06, 0x08, 0x03, 0x00, 0x03);
  const result = recoverCallGraph(toy(), code, { address: 0n, regionLimit: 1 });
  assert.equal(result.counts.regions, 1);
  assert.ok(result.limitations.some((line) => /region budget/.test(line)));
});

test('a call graph is a lower bound when a call target is computed at run time', () => {
  const full = recoverCallGraph(toy(), program(0x06, 0x04, 0x03, 0x00, 0x03), { address: 0n });
  // Nothing here is indirect, so the claim to check is that the limitation is always present:
  // every call graph this produces names the calls it resolved, never all the calls that exist.
  assert.ok(full.limitations.some((line) => /absence from this graph is not evidence/.test(line)));
});

test('the instruction budget is reported rather than quietly truncating the graph', () => {
  // A single-instruction budget against a program with more than one reachable instruction.
  const result = recoverControlFlow(toy(), program(0x02, 0x01, 0x02, 0x01, 0x03), { address: 0n, limit: 1 });
  assert.equal(result.counts.instructions, 1);
  assert.ok(result.limitations.some((line) => /instruction limit/.test(line)));
});
