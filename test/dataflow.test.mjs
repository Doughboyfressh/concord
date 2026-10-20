import test from 'node:test';
import assert from 'node:assert/strict';
import { loadLanguage } from '../src/sleigh.mjs';
import { analyseDataflow, sliceDataflow } from '../src/dataflow.mjs';
import { canonical } from '../src/value.mjs';
import { buildDecodableSla } from './ghidra-fixtures.mjs';

/**
 * Reaching definitions over p-code.
 *
 * The property that decides whether this layer is right or merely plausible is the kill rule: a
 * definition kills a previous one only when it **fully covers** it. The toy language has `setlow`,
 * which writes one byte of r0, precisely so that rule can be tested here rather than only against
 * x86 — a kill rule based on "overlaps" would pass every other test in this file.
 *
 * Checked against real x86 as well, which cannot live here because it needs the Ghidra
 * distribution: `mov eax,0x2a; ret` recovers ESP as its only input and EAX, ESP and EIP as its
 * outputs; `mov al,1; inc eax` leaves EAX external and partially overwritten; and a conditional
 * that defines EAX on two paths produces a read with both definitions reaching it.
 */

const toy = () => loadLanguage(buildDecodableSla());
const program = (...values) => Buffer.from(values);
const r0 = (use) => use.varnode.space === 'register' && use.varnode.offset === '0x0';

test('storage read before anything writes it is reported as an input', () => {
  //   0x00  ret   RETURN reads r0 and defines nothing
  // `inc` would have been the natural read-modify-write here, but the toy gives it a delay slot,
  // which swallows the following instruction and makes the region one instruction long.
  const analysis = analyseDataflow(toy(), program(0x03), { address: 0n });
  assert.deepEqual(analysis.summary.inputs, [{ space: 'register', offset: '0x0', size: 4 }]);
  // RETURN has no output varnode, so this region writes nothing: an input without an output.
  assert.deepEqual(analysis.summary.outputs, []);
  assert.equal(analysis.counts.externalReads, 1);
  assert.deepEqual(analysis.uses[0].reaching, []);
  assert.equal(analysis.uses[0].external, true);
});

test('storage written before it is read is not an input', () => {
  //   0x00  ld 0x42   writes r0 from a constant
  //   0x02  inc       reads r0, which the write above supplies
  //   0x03  ret
  const analysis = analyseDataflow(toy(), program(0x02, 0x42, 0x01, 0x03), { address: 0n });
  // Nothing is read that was not first written here, so the region takes no register input.
  assert.deepEqual(analysis.summary.inputs, []);
  assert.deepEqual(analysis.summary.defined, [{ space: 'register', offset: '0x0', size: 4 }]);

  const reads = analysis.uses.filter((use) => r0(use) && use.varnode.size === 4);
  assert.ok(reads.length >= 1);
  for (const read of reads) {
    assert.equal(read.external, false);
    assert.deepEqual(read.reaching, ['0x0:0'], 'the constant written at 0x0 is what the read observes');
  }
});

test('a narrow write does not kill a wider definition: it partially overwrites it', () => {
  //   0x00  ld 0x42   defines r0, all four bytes
  //   0x02  setlow    writes only the low byte of r0
  //   0x03  inc       reads all four bytes of r0
  //   0x04  ret
  const analysis = analyseDataflow(toy(), program(0x02, 0x42, 0x07, 0x01, 0x03), { address: 0n });
  const wide = analysis.uses.filter((use) => r0(use) && use.varnode.size === 4 && use.address === '0x3');
  assert.ok(wide.length >= 1, 'the inc at 0x3 reads four bytes of r0');
  for (const read of wide) {
    // The four byte definition at 0x0 survives the one byte write at 0x2, because that write does
    // not cover it. A kill rule based on overlap would have discarded it and reported this read as
    // having no definition at all — the value would appear to come from outside the region.
    assert.deepEqual(read.reaching, ['0x0:0']);
    assert.equal(read.external, false);
    assert.deepEqual(read.partiallyOverwritten, ['0x2:0'],
      'the narrow write is reported as partially overwriting what the read observes');
  }
});

test('a wide write does kill a narrower definition it covers', () => {
  //   0x00  setlow    defines one byte of r0
  //   0x01  ld 0x42   defines all four bytes, which covers the byte above
  //   0x03  brc 0x05  reads one byte of r0
  //   0x05  ret
  const analysis = analyseDataflow(toy(), program(0x07, 0x02, 0x42, 0x05, 0x05, 0x03), { address: 0n });
  const narrow = analysis.uses.filter((use) => r0(use) && use.varnode.size === 1 && use.address === '0x3');
  assert.ok(narrow.length >= 1);
  for (const read of narrow) {
    // Only the wide definition reaches: the byte written at 0x0 was fully covered and is gone.
    assert.deepEqual(read.reaching, ['0x1:0']);
    assert.deepEqual(read.partiallyOverwritten, []);
  }
});

test('a value defined on two paths reaches its read as two definitions, not one guess', () => {
  //   0x00  brc 0x06   conditional: branch to 0x06, fall through to 0x02
  //   0x02  ld 0x01    defines r0 on the fallthrough path
  //   0x04  br 0x08    and jumps over the other definition
  //   0x06  ld 0x02    defines r0 on the branch path
  //   0x08  ret        reads r0 where the two paths meet
  // The two definitions have to be on genuinely disjoint paths: a third definition at the merge
  // point would cover both and the read would see only that one.
  const analysis = analyseDataflow(toy(),
    program(0x05, 0x06, 0x02, 0x01, 0x04, 0x08, 0x02, 0x02, 0x03), { address: 0n });
  const merged = analysis.uses.filter((use) => use.reaching.length > 1);
  assert.ok(merged.length >= 1, 'the read after the merge sees both definitions');
  assert.deepEqual(merged[0].reaching, ['0x2:0', '0x6:0'], 'one definition from each path');
  // Both, not one: a meet by union is what makes a join honest. Picking either would assert a
  // path was taken, and inventing a phi node would imply an analysis nothing here performed.
  for (const use of merged) assert.equal(use.reaching.length, 2);
  assert.ok(analysis.counts.joins >= 1);
  assert.ok(analysis.limitations.some((line) => /not static single assignment/.test(line)));
});

test('a loop reaches a fixpoint rather than iterating forever', () => {
  //   0x00  ld 0x01    defines all four bytes of r0
  //   0x02  setlow     defines the low byte, inside the loop
  //   0x03  brc 0x02   reads the low byte and loops back to 0x02
  //   0x05  ret        reads all four bytes
  const analysis = analyseDataflow(toy(), program(0x02, 0x01, 0x07, 0x05, 0x02, 0x03), { address: 0n });
  assert.ok(analysis.counts.fixpointRounds >= 2, 'a back edge needs more than one round to settle');
  assert.ok(analysis.counts.fixpointRounds < 10, 'and it settles quickly');
  // The narrow read inside the loop sees the wide definition from before the loop and the narrow
  // one from the previous iteration. Both reach it, which is what iterating to a fixpoint is for.
  const narrow = analysis.uses.find((use) => r0(use) && use.varnode.size === 1 && use.address === '0x3');
  assert.deepEqual(narrow.reaching, ['0x0:0', '0x2:0']);
  // And the wide read after the loop sees the wide definition, with the loop's narrow write
  // recorded as having partially overwritten it rather than having replaced it.
  const wide = analysis.uses.find((use) => r0(use) && use.varnode.size === 4 && use.address === '0x5');
  assert.deepEqual(wide.reaching, ['0x0:0']);
  assert.deepEqual(wide.partiallyOverwritten, ['0x2:0']);
});

test('a branch target is not a read of the memory at that address', () => {
  //   0x00  br 0x02 ; 0x02 ret
  const analysis = analyseDataflow(toy(), program(0x04, 0x02, 0x03), { address: 0n });
  // BRANCH's first input is a destination address, not a value fetched from it. Counting it as a
  // read reported every branch as reading four bytes of code, which showed up as phantom ram
  // inputs on a region that touches no memory at all.
  assert.ok(!analysis.summary.inputs.some((input) => input.space === 'ram'),
    'no ram input: this region reads no memory');
  assert.ok(!analysis.uses.some((use) => use.op === 'BRANCH' && use.inputIndex === 0));
});

test('adjacent but distinct storage is not merged into one location', () => {
  // r0 is register:0x0:4 and the toy declares r1 at register:0x4:4. A summary that merged ranges
  // which merely touch would report one eight byte location nothing reads — which is what it did
  // for x86, gluing ESP at register:0x10 and EBP at register:0x14 into register:0x10:8.
  const analysis = analyseDataflow(toy(), program(0x01, 0x03), { address: 0n });
  for (const entry of [...analysis.summary.inputs, ...analysis.summary.outputs]) {
    assert.ok(entry.size <= 4, `storage of size ${entry.size} is wider than any register the toy declares`);
  }
});

test('a backward slice gives the derivation and stops where the value came from outside', () => {
  //   0x00  ld 0x42 ; 0x02 ret
  const defined = analyseDataflow(toy(), program(0x02, 0x42, 0x03), { address: 0n });
  const read = defined.uses.find((use) => use.op === 'RETURN');
  const derivation = sliceDataflow(defined, { from: read.id, direction: 'backward' });
  assert.equal(derivation.direction, 'backward');
  // The returned value came from the COPY at 0x0, whose own input is a constant and so has no
  // definition to follow: the derivation is complete and nothing is left unexplained.
  assert.deepEqual(derivation.steps.map((step) => [step.kind, step.op]),
    [['use', 'RETURN'], ['definition', 'COPY']]);
  assert.deepEqual(derivation.boundaries, []);

  //   0x00  ret alone: the value is read with nothing in the region defining it.
  const external = analyseDataflow(toy(), program(0x03), { address: 0n });
  const open = sliceDataflow(external, { from: external.uses[0].id, direction: 'backward' });
  // Here the derivation genuinely cannot continue, and the slice names where it stopped rather
  // than returning a short answer that looks finished.
  assert.equal(open.steps.length, 1);
  assert.deepEqual(open.boundaries.map((boundary) => boundary.reason), ['defined_outside_region']);
});

test('a forward slice gives the influence of a definition', () => {
  //   0x00  ld 0x42   defines r0 from a constant
  //   0x02  inc       reads r0 and defines it again
  // The inc carries a delay slot that consumes the byte after it, so the region is these two.
  const analysis = analyseDataflow(toy(), program(0x02, 0x42, 0x01, 0x03), { address: 0n });
  const slice = sliceDataflow(analysis, { from: '0x0:0', direction: 'forward' });
  assert.equal(slice.direction, 'forward');
  // Influence crosses an operation: the constant written at 0x0 is read by the add at 0x2, and
  // because the add defines something from it, that definition is influenced too. A forward slice
  // that stopped at the read would miss everything downstream of the first operation.
  assert.deepEqual(slice.steps.map((step) => [step.kind, step.address, step.op]),
    [['definition', '0x0', 'COPY'], ['use', '0x2', 'INT_ADD'], ['definition', '0x2', 'INT_ADD']]);
});

test('a slice from an identifier that is not in the analysis is refused, not answered emptily', () => {
  const analysis = analyseDataflow(toy(), program(0x01, 0x03), { address: 0n });
  assert.throws(() => sliceDataflow(analysis, { from: '0xdead:9', direction: 'backward' }),
    (error) => error.code === 'DATAFLOW_SLICE');
  assert.throws(() => sliceDataflow(analysis, { from: '0xdead:9', direction: 'forward' }),
    (error) => error.code === 'DATAFLOW_SLICE');
});

test('the analysis is canonical and repeatable, which is what replay would verify', () => {
  const code = program(0x02, 0x42, 0x07, 0x01, 0x03);
  const once = analyseDataflow(toy(), code, { address: 0n });
  const twice = analyseDataflow(toy(), code, { address: 0n });
  assert.equal(canonical(once), canonical(twice));
  // Every offset leaves as a hex string, so the whole result is inside the JSON domain.
  assert.ok(once.summary.defined.every((entry) => typeof entry.offset === 'string'));
});

test('the bounds of the analysis are always stated, not only when convenient', () => {
  const analysis = analyseDataflow(toy(), program(0x02, 0x42, 0x03), { address: 0n });
  assert.equal(analysis.counts.loads, 0);
  assert.equal(analysis.counts.stores, 0);
  // The kill rule and the no-SSA caveat bound every result here, so both are always present.
  assert.ok(analysis.limitations.some((line) => /fully covers it/.test(line)));
  assert.ok(analysis.limitations.some((line) => /reaching definitions, not static single assignment/.test(line)));
});
