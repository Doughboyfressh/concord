import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { deflateSync } from 'node:zlib';
import { makeGhidraTools } from '../src/ghidra.mjs';
import { canonical } from '../src/value.mjs';
import { tempDir } from './temp-workspace.mjs';
import { writeGhidraFixtures, buildSla, SLASPEC } from './ghidra-fixtures.mjs';

/**
 * The Ghidra specification readers.
 *
 * Checking that a reader returns its declared keys is done centrally in core.test.mjs; what is
 * checked here is that the values are right, because every one of these tools exists to answer a
 * question another tool will build on. A reader that decodes the wrong endianness is worse than
 * one that refuses, so the refusals are tested as carefully as the successes.
 */

const tools = new Map(makeGhidraTools().map((tool) => [tool.name, tool]));
const setup = (prefix) => {
  const temp = tempDir(prefix);
  const inputs = writeGhidraFixtures(temp);
  return { temp, inputs, context: { workspaceRoot: temp, policy: { maxOutputBytes: 1000000 } } };
};
const run = (name, input, context) => tools.get(name).execute(input, context);

test('a language definition is read with its compiler list in order and its mixed endianness kept', () => {
  const { context } = setup('concord-ghidra-ldefs-');
  const output = run('artifact.ghidraLanguages', { path: 'toy.ldefs' }, context);
  assert.equal(output.supported, true);
  // Two languages, not three: one is commented out, and a reader that counted it would agree with
  // a grep and disagree with Ghidra.
  assert.equal(output.counts.languages, 2);
  assert.ok(!output.languages.some((language) => language.variant === 'commented'));

  const first = output.languages[0];
  assert.equal(first.id, 'Toy:LE:32:default');
  assert.equal(first.size, 32);
  assert.deepEqual(first.truncateSpace, { space: 'ram', size: 4 });
  // The first compiler element is the default. Order carries that meaning, so it is both preserved
  // and named, rather than left for a caller to infer from position.
  assert.equal(first.defaultCompiler, 'default');
  assert.deepEqual(first.compilers.map((c) => c.id), ['default', 'windows']);
  assert.equal(first.instructionEndian, null);

  // LEBE: big endian data, little endian instructions. This is the case that makes a language id
  // impossible to rebuild from processor, size and variant, so it must survive the read.
  const mixed = output.languages[1];
  assert.equal(mixed.endian, 'big');
  assert.equal(mixed.instructionEndian, 'little');
  assert.equal(mixed.id, 'Toy:LEBE:32:mixed');
});

test('a processor spec reports entry points, context fields and the registers it does not fold together', () => {
  const { context } = setup('concord-ghidra-pspec-');
  const output = run('artifact.ghidraProcessorSpec', { path: 'toy.pspec' }, context);
  assert.equal(output.supported, true);
  assert.equal(output.programCounter, 'PC');

  // Three different declarations all spell their members <register>, and they mean different
  // things: allocatable registers, memory-mapped volatile ranges, and copies that are not real
  // dataflow. Folding them into one list would report x86's eight x87 slots as general registers.
  assert.deepEqual(output.registers.map((r) => r.name), ['r0', 'oldname']);
  assert.deepEqual(output.incidentalCopy.map((entry) => entry.register), ['ST0']);
  assert.equal(output.volatileRanges.length, 1);
  assert.deepEqual(output.volatileRanges[0], { kind: 'range', space: 'SFR', first: 0x80, last: 0xff, register: null });

  assert.deepEqual(output.registers[0].vectorLaneSizes, [1, 2, 4]);
  assert.ok(output.limitations.some((line) => /renamed/.test(line)), 'a rename changes every later reference, so it is disclosed');

  // An address offset is hex with or without the 0x, and `SFR:80` means 128. Reading it as decimal
  // would place the 8051 SFR map at the wrong addresses.
  const reset = output.symbols.find((s) => s.name === 'Reset');
  assert.deepEqual(reset.address, { space: 'ram', offset: 0, text: 'ram:0x0' });
  assert.equal(reset.entry, true);
  const port = output.symbols.find((s) => s.name === 'P0');
  assert.equal(port.address.offset, 0x80);
  assert.equal(port.entry, false);
  assert.equal(output.counts.entryPoints, 1);

  assert.equal(output.contextFields.length, 2);
  assert.equal(output.contextFields.find((f) => f.name === 'TMode').kind, 'context');
  assert.equal(output.contextFields.find((f) => f.name === 'spsr').kind, 'tracked');
  assert.equal(output.memoryBlocks[0].mapping.kind, 'initialized');
  assert.equal(output.memoryBlocks[0].initialized, false);
});

test('a compiler spec yields the calling conventions with allocation order and the default named', () => {
  const { context } = setup('concord-ghidra-cspec-');
  const output = run('artifact.ghidraCompilerSpec', { path: 'toy.cspec' }, context);
  assert.equal(output.supported, true);
  assert.equal(output.defaultConvention, '__stdcall');
  assert.deepEqual(output.conventions.map((c) => c.name), ['__stdcall', '__fastcall']);
  assert.equal(output.conventions[0].isDefault, true);
  assert.equal(output.conventions[1].isDefault, false);

  const stdcall = output.conventions[0];
  assert.equal(stdcall.extraPop, 4);
  assert.equal(stdcall.stackShift, 4);
  // pentry order is the argument allocation order, so the list must not be sorted or deduplicated.
  assert.deepEqual(stdcall.inputs.map((entry) => entry.location.register), ['r0', null]);
  // A join space address concatenates registers to carry a value wider than one of them; the piece
  // order is the layout.
  assert.equal(stdcall.inputs[1].location.kind, 'join');
  assert.deepEqual(stdcall.inputs[1].location.pieces, ['r1', 'r0']);
  assert.deepEqual(stdcall.unaffected, ['SP']);
  assert.deepEqual(stdcall.killedByCall, ['r1']);

  assert.equal(output.dataOrganization.pointer_size, 4);
  assert.equal(output.dataOrganization.charSigned, false);
  // use_MS_convention is the MSVC/GCC bitfield discriminator and the one field here that identifies
  // a toolchain rather than a width.
  assert.equal(output.dataOrganization.bitfieldPacking.use_MS_convention, 1);
  assert.deepEqual(output.stackPointer, { register: 'SP', space: 'ram', growth: 'negative', reverseJustify: false });
  assert.equal(output.returnAddress.kind, 'varnode');
  assert.deepEqual(output.callFixups.map((f) => f.name).sort(), ['alloca_probe', 'toyHalt']);
});

test('an opinion file flattens to the decision table a loader matches, with attributes inherited', () => {
  const { context } = setup('concord-ghidra-opinion-');
  const output = run('artifact.ghidraLoaderOpinion', { path: 'toy.opinion' }, context);
  assert.equal(output.supported, true);
  assert.equal(output.counts.constraints, 4);
  // Inheritance is the whole semantics: `loader` is set once on the outermost constraint and
  // `compilerSpecID` on the middle one, and every leaf row must carry both.
  for (const row of output.constraints) assert.equal(row.loader, 'Portable Executable (PE)');
  assert.deepEqual(output.constraints.map((row) => row.compilerSpecID), ['windows', 'windows', 'default', 'default']);
  assert.deepEqual(output.loaders, ['Portable Executable (PE)']);
});

test('the loader decision resolves only to languages that exist, and reports a row that resolves to none', () => {
  const { context } = setup('concord-ghidra-match-');
  const hit = run('artifact.ghidraLanguageMatch', { opinion: 'toy.opinion', languages: 'toy.ldefs', loader: 'Portable Executable (PE)', primary: '332' }, context);
  assert.equal(hit.supported, true);
  assert.equal(hit.counts.matched, 1);
  assert.equal(hit.counts.resolved, 1);
  assert.deepEqual(hit.matched[0].languages.map((l) => l.id), ['Toy:LE:32:default']);
  assert.equal(hit.matched[0].languages[0].compilerSpecKnown, true);

  // primary 334 names variant "absent", which no language declares. The row matched, so saying
  // nothing matched would be wrong, and inventing Toy:BE:64:absent would be worse: the honest
  // answer is a matched row that resolved to nothing.
  const unresolved = run('artifact.ghidraLanguageMatch', { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '334' }, context);
  assert.equal(unresolved.counts.matched, 1);
  assert.equal(unresolved.counts.resolved, 0);
  assert.equal(unresolved.matched[0].resolved, false);
  assert.deepEqual(unresolved.matched[0].languages, []);
  assert.ok(unresolved.limitations.some((line) => /none names a language present/.test(line)));

  const miss = run('artifact.ghidraLanguageMatch', { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '9999' }, context);
  assert.equal(miss.counts.matched, 0);
  assert.deepEqual(miss.matched, []);
});

test('a secondary key is matched the three ways the format documents and no fourth way', () => {
  const { context } = setup('concord-ghidra-secondary-');
  // 0b0000.01.. with dots as wildcards. 0x05 is 00000101: bits 0-3 zero, bit 4 zero, bit 5 one.
  const bits = run('artifact.ghidraLanguageMatch', { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '400', secondary: '0x05' }, context);
  assert.equal(bits.counts.resolved, 1);
  assert.equal(bits.matched[0].secondaryMatch, 'bits');

  const wrongBits = run('artifact.ghidraLanguageMatch', { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '400', secondary: '0xff' }, context);
  assert.equal(wrongBits.counts.matched, 0);

  const named = run('artifact.ghidraLanguageMatch', { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '333', secondary: 'clang' }, context);
  assert.equal(named.counts.resolved, 1);
  assert.equal(named.matched[0].secondaryMatch, 'string');

  // A row constrains `secondary` and the query supplies none. Treating an absent key as a wildcard
  // would resolve a clang-only row for a binary that never claimed to be clang.
  const noKey = run('artifact.ghidraLanguageMatch', { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '333' }, context);
  assert.equal(noKey.counts.matched, 0);
});

test('a compiled table decodes to the facts the SLEIGH compiler recorded', () => {
  const { context } = setup('concord-ghidra-sla-');
  const output = run('artifact.sleighCompiled', { path: 'toy.sla' }, context);
  assert.equal(output.supported, true);
  assert.deepEqual(output.format, { magic: 'sla', version: 4 });
  assert.equal(output.sleigh.bigEndian, false);
  assert.equal(output.sleigh.alignment, 1);
  assert.equal(output.sleigh.uniqueBase, 0x1000);
  assert.equal(output.sleigh.defaultSpace, 'ram');
  // maxdelay, uniqmask and numsections are only written when nonzero, so an absent one is zero and
  // not unknown.
  assert.equal(output.sleigh.maxDelaySlotBytes, 0);
  assert.equal(output.sleigh.sectionCount, 0);

  // The constant, fspec, iop and join spaces are never serialized; what is written is the unique
  // space, any OTHER space, and the addressable ones.
  assert.deepEqual(output.spaces.map((s) => [s.name, s.kind]), [['unique', 'unique'], ['ram', 'addressable'], ['register', 'addressable']]);
  assert.equal(output.spaces.find((s) => s.name === 'ram').size, 4);
  assert.equal(output.spaces.find((s) => s.name === 'ram').wordSize, 1);

  assert.deepEqual(output.sourceFiles.map((f) => f.name), ['toy.slaspec']);
  assert.deepEqual(output.registers.map((r) => r.name), ['r0', 'r1', 'PC', 'SP', 'SWI_VECTOR']);
  assert.deepEqual(output.userops.map((u) => u.name), ['toyHalt']);
  assert.deepEqual(output.subtables.map((s) => s.name), ['instruction']);
  assert.equal(output.elementCounts.sleigh, 1);
});

test('a big endian table is not read as a little endian one', () => {
  const { temp, context } = setup('concord-ghidra-sla-be-');
  writeFileSync(path.join(temp, 'be.sla'), buildSla({ bigEndian: true, alignment: 4, defaultSpace: 'code' }));
  const output = run('artifact.sleighCompiled', { path: 'be.sla' }, context);
  assert.equal(output.sleigh.bigEndian, true);
  assert.equal(output.sleigh.alignment, 4);
  assert.equal(output.sleigh.defaultSpace, 'code');
});

test('a compiled table is refused rather than misread when the header is not one this reader decodes', () => {
  const { temp, context } = setup('concord-ghidra-sla-bad-');
  writeFileSync(path.join(temp, 'plain.bin'), Buffer.from('not a sleigh table at all'));
  const notSla = run('artifact.sleighCompiled', { path: 'plain.bin' }, context);
  assert.equal(notSla.supported, false);
  assert.equal(notSla.reason, 'not_a_sla');
  assert.equal(notSla.sleigh, null);
  assert.deepEqual(notSla.spaces, []);

  // sleighbase.cc rejects any version but 4. A future format would still inflate and would still
  // produce element ids, which is exactly why guessing is worse than refusing: the ids would be
  // read against the wrong table.
  writeFileSync(path.join(temp, 'v5.sla'), Buffer.concat([Buffer.from('sla'), Buffer.from([5]), deflateSync(Buffer.from([0x60, 0xa1]))]));
  const wrongVersion = run('artifact.sleighCompiled', { path: 'v5.sla' }, context);
  assert.equal(wrongVersion.supported, false);
  assert.equal(wrongVersion.reason, 'unsupported_format_version');
  assert.deepEqual(wrongVersion.format, { magic: 'sla', version: 5 });

  writeFileSync(path.join(temp, 'torn.sla'), Buffer.concat([Buffer.from('sla'), Buffer.from([4]), Buffer.from('not zlib data')]));
  const torn = run('artifact.sleighCompiled', { path: 'torn.sla' }, context);
  assert.equal(torn.supported, false);
  assert.equal(torn.reason, 'inflate_failed');
});

test('SLEIGH source keeps the preprocessor stack instead of evaluating it', () => {
  const { context } = setup('concord-ghidra-source-');
  const output = run('artifact.sleighSource', { path: 'toy.slaspec' }, context);
  assert.equal(output.supported, true);
  assert.equal(output.endian.value, 'little');
  assert.equal(output.endian.macro, null);
  assert.deepEqual(output.endian.guards, []);
  assert.equal(output.alignment.value, 1);

  // A `;` inside a constructor pattern and inside a [ ... ] action block is not a statement
  // terminator. Treating it as one chopped constructors into fragments and glued the following
  // declaration onto one, which lost 4,843 of the corpus's 7,082 pcodeop declarations.
  assert.deepEqual(output.pcodeops.filter((op) => !op.guards.length).map((op) => op.name), ['toyHalt', 'toy.add.s']);
  // A dotted name is a legal SLEIGH identifier (slghscan.l:514) and Loongarch relies on it.
  assert.ok(output.pcodeops.some((op) => op.name === 'toy.add.s'));

  // The guarded declaration is reported, and reported as guarded. Dropping it would hide a
  // capability; reporting it as unconditional would claim a variant has it when only some do.
  const guarded = output.pcodeops.find((op) => op.name === 'toyExtended');
  assert.deepEqual(guarded.guards, ['defined(EXTENDED)']);
  assert.ok(output.counts.guardedDeclarations >= 1);
  assert.ok(output.limitations.some((line) => /conditional block/.test(line)));

  assert.deepEqual(output.spaces.map((s) => s.name), ['ram', 'register']);
  assert.equal(output.spaces.find((s) => s.name === 'ram').default, true);
  assert.equal(output.spaces.find((s) => s.name === 'register').default, false);

  // `define register` is not special: the production is `define <spacename> offset= size= [names]`,
  // and `_` is a declared gap that still consumes its slot, so SP sits at 0x10 and not 0x0c.
  const registers = new Map(output.registers.map((r) => [r.name, r]));
  assert.deepEqual([...registers.keys()], ['r0', 'r1', 'PC', 'SP', 'SWI_VECTOR']);
  assert.equal(registers.get('r1').offset, 4);
  assert.equal(registers.get('PC').offset, 12);
  assert.equal(registers.get('SP').offset, 16);
  assert.equal(registers.get('SWI_VECTOR').space, 'RAM');

  assert.deepEqual(output.tokens.map((t) => [t.name, t.bits]), [['opbyte', 8]]);
  assert.deepEqual(output.tokens[0].fields.map((f) => [f.name, f.low, f.high]), [['op', 0, 7], ['aaa', 5, 7]]);
  assert.deepEqual(output.contextFields.map((f) => f.name), ['TMode', 'LRset']);
  assert.deepEqual(output.contextFields.find((f) => f.name === 'LRset').qualifiers, ['noflow']);

  assert.deepEqual(output.attaches.map((a) => a.kind), ['variables', 'names', 'values']);
  assert.deepEqual(output.attaches[1].values, ['zero', 'one']);
  assert.deepEqual(output.attaches[2].values, ['-1', '1', '2', '3', '4', '5', '6', '7']);
  assert.deepEqual(output.macros.map((m) => m.name), ['setFlags']);
  assert.deepEqual(output.subtables, ['REL']);
  assert.deepEqual(output.mnemonics.map((m) => m.mnemonic), ['halt', 'add']);
  assert.equal(output.counts.unterminatedDeclarations, 0);
});

test('an unresolved endianness macro is reported as the macro it is, not as a value', () => {
  const { temp, context } = setup('concord-ghidra-macro-');
  writeFileSync(path.join(temp, 'inc.sinc'), 'define endian=$(ENDIAN);\ndefine alignment=2;\n@ifdef T_VARIANT\ndefine space ram type=ram_space size=4 default;\n@endif\n');
  const output = run('artifact.sleighSource', { path: 'inc.sinc' }, context);
  assert.equal(output.endian.macro, '$(ENDIAN)');
  assert.equal(output.endian.value, '$(ENDIAN)');
  assert.ok(output.limitations.some((line) => /\$\(ENDIAN\)/.test(line)));
  // A guarded space declaration is still a declaration, with its guard attached.
  assert.deepEqual(output.spaces[0].guards, ['defined(T_VARIANT)']);
});

test('an XML specification type is refused by the source reader rather than scraped', () => {
  const { context } = setup('concord-ghidra-wrongtype-');
  const output = run('artifact.sleighSource', { path: 'toy.ldefs' }, context);
  assert.equal(output.supported, false);
  assert.equal(output.reason, 'not_sleigh_source');
  assert.deepEqual(output.pcodeops, []);
  assert.equal(output.endian, null);
});

test('a wrong root element is refused rather than read as the type that was asked for', () => {
  const { context } = setup('concord-ghidra-root-');
  const output = run('artifact.ghidraProcessorSpec', { path: 'toy.cspec' }, context);
  assert.equal(output.supported, false);
  assert.equal(output.reason, 'unexpected_root_element');
  assert.equal(output.programCounter, null);
  assert.deepEqual(output.registers, []);
});

test('an XML entity declaration is refused, because expansion is the one cost not bounded by file length', () => {
  const { temp, context } = setup('concord-ghidra-entity-');
  writeFileSync(path.join(temp, 'bomb.ldefs'), [
    '<?xml version="1.0"?>',
    '<!DOCTYPE language_definitions [',
    '  <!ENTITY a "aaaaaaaaaa">',
    '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">',
    ']>',
    '<language_definitions><language id="&b;"/></language_definitions>',
  ].join('\n'));
  const output = run('artifact.ghidraLanguages', { path: 'bomb.ldefs' }, context);
  assert.equal(output.supported, false);
  assert.equal(output.reason, 'entity_declaration');
  assert.deepEqual(output.languages, []);
});

test('comparing a compiled table with its source separates disagreement from silence', () => {
  const { temp, context } = setup('concord-ghidra-compare-');
  const agreeing = run('artifact.compareSleighSource', { compiled: 'toy.sla', source: 'toy.slaspec' }, context);
  assert.equal(agreeing.supported, true);
  assert.deepEqual(agreeing.disagreements, []);
  const agreedFields = agreeing.agreements.map((a) => a.field);
  assert.ok(agreedFields.includes('endian'));
  assert.ok(agreedFields.includes('alignment'));
  assert.ok(agreedFields.includes('defaultSpace'));

  // A source that states endianness as a macro has not disagreed with the table — it has not
  // spoken. Recording that as a mismatch would manufacture a finding out of the preprocessor.
  writeFileSync(path.join(temp, 'macro.slaspec'), 'define endian=$(ENDIAN);\ndefine alignment=1;\n');
  const silent = run('artifact.compareSleighSource', { compiled: 'toy.sla', source: 'macro.slaspec' }, context);
  assert.deepEqual(silent.disagreements, []);
  assert.equal(silent.unstated.find((entry) => entry.field === 'endian').reason, 'unresolved_macro');
  assert.ok(silent.agreements.some((a) => a.field === 'alignment'));

  // A real disagreement is still reported as one: this source says big endian and the table says
  // little, which is evidence the pair does not belong together.
  writeFileSync(path.join(temp, 'wrong.slaspec'), 'define endian=big;\ndefine alignment=8;\ndefine space nowhere type=ram_space size=4 default;\n');
  const conflicting = run('artifact.compareSleighSource', { compiled: 'toy.sla', source: 'wrong.slaspec' }, context);
  assert.deepEqual(conflicting.disagreements.find((d) => d.field === 'endian'), { field: 'endian', sourceValue: 'big', tableValue: 'little' });
  assert.deepEqual(conflicting.disagreements.find((d) => d.field === 'alignment'), { field: 'alignment', sourceValue: 8, tableValue: 1 });
  assert.ok(conflicting.disagreements.some((d) => d.field === 'spaces'));
});

test('every reader is a read effect over bytes and returns a canonical, repeatable result', () => {
  const { inputs, context } = setup('concord-ghidra-determinism-');
  for (const tool of tools.values()) {
    // Nothing here spawns a process or reaches the network, so none of these needs an approval.
    assert.equal(tool.effect, 'read', `${tool.name} reads bytes already in the workspace`);
    assert.ok(Object.isFrozen(tool), `${tool.name} is frozen`);
    const input = inputs[tool.name];
    assert.ok(input, `${tool.name} has a fixture`);
    const first = canonical(tool.execute(input, context));
    const second = canonical(tool.execute(input, context));
    assert.equal(first, second, `${tool.name} is a pure function of its input, which is what replay verifies`);
    // canonical() rejects undefined, so this also proves no key is set to undefined: JSON.stringify
    // would have dropped such a key silently and the replay would have failed later instead.
    assert.ok(first.length > 2);
  }
});

test('a file that is not the expected format is refused without throwing, for every reader', () => {
  const { temp, context } = setup('concord-ghidra-refusal-');
  writeFileSync(path.join(temp, 'empty.bin'), Buffer.alloc(0));
  writeFileSync(path.join(temp, 'junk.bin'), Buffer.from([0x00, 0xff, 0x00, 0xff, 0x7f, 0x80]));
  for (const name of ['artifact.ghidraLanguages', 'artifact.ghidraProcessorSpec',
    'artifact.ghidraCompilerSpec', 'artifact.ghidraLoaderOpinion', 'artifact.sleighCompiled',
    'artifact.sleighSource']) {
    for (const file of ['empty.bin', 'junk.bin']) {
      const output = run(name, { path: file }, context);
      assert.equal(output.supported, false, `${name} refuses ${file}`);
      assert.equal(typeof output.reason, 'string', `${name} says why it refused ${file}`);
      for (const key of tools.get(name).outputKeys) {
        assert.ok(Object.hasOwn(output, key), `${name} still returns ${key} when refusing ${file}`);
      }
    }
  }
});

test('a declaration that opens and never closes is counted rather than absorbed', () => {
  const { temp, context } = setup('concord-ghidra-unterminated-');
  writeFileSync(path.join(temp, 'truncated.slaspec'), `${SLASPEC}\ndefine pcodeop neverClosed`);
  const output = run('artifact.sleighSource', { path: 'truncated.slaspec' }, context);
  assert.equal(output.counts.unterminatedDeclarations, 1);
  assert.ok(!output.pcodeops.some((op) => op.name === 'neverClosed'));
  assert.ok(output.limitations.some((line) => /never terminated/.test(line)));
});
