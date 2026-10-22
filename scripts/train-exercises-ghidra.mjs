import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { writeGhidraFixtures, buildSla } from '../test/ghidra-fixtures.mjs';

/**
 * The Ghidra specification family.
 *
 * Eight readers over a corpus that is pure data, so every prediction here is about meaning rather
 * than parseability. The fixtures are the same ones the test suite uses, which is deliberate: a
 * second set would drift, and the `.sla` among them is written by an encoder built independently
 * from the decoder under test, so decoding it at all is already a round trip.
 *
 * What makes this family worth training on is that three of its lessons were learned by being
 * wrong first, and each time the mistake was the same shape — treating a character as having one
 * meaning when SLEIGH gives it two. `;` terminates a declaration and also sequences tokens inside
 * a pattern. `#` starts a comment and is also the immediate marker, quoted, in 68000 and ARM
 * display sections. `{` opens a semantic body and also appears quoted in an ARM register list.
 * Each wrong reading silently lost thousands of declarations while still answering
 * `supported: true`, which is the failure mode these exercises exist to pin down: a reader that
 * refuses is safe, and a reader that answers confidently from a misparse is not.
 *
 * The corpus itself is the strongest evidence and it does not live here — 745 shipped files read
 * with zero failures, and counts that match an independent measurement exactly. These exercises
 * record the properties that would still hold for a corpus of one file, so they stay meaningful
 * without the 876 MB distribution present.
 */

const task = (tool, input) => ({ version: 1, name: 't', tasks: [{ id: 'a', tool, input }] });

/**
 * The installed Ghidra distribution, or null.
 *
 * Everything above this line is deliberately independent of it and stays that way: the synthetic
 * fixtures keep this family meaningful on a machine that has never seen Ghidra. What an install
 * adds is the other half of the claim — that these readers hold against the real corpus, where a
 * table is half a megabyte of packed binary rather than something an encoder in this repository
 * wrote. Absent rather than failing, like the browser exercises: a machine without Ghidra should
 * report fewer exercises, not a finding about its own installation.
 *
 * CONCORD_GHIDRA overrides the search. Otherwise a short list of literal roots is tried and then
 * the download directory is scanned one level deep, because that is where an unpacked
 * distribution actually tends to sit — and assuming it was not installed because it is not at
 * C:/ghidra is how this was got wrong once already.
 */
const GHIDRA = (() => {
  const marker = 'Ghidra/Processors/x86/data/languages/x86-64.sla';
  const holds = (root) => {
    try { return typeof root === 'string' && fs.statSync(path.join(root, marker)).isFile() ? root : null; }
    catch { return null; }
  };
  const home = process.env.USERPROFILE ?? process.env.HOME ?? '';
  for (const candidate of [process.env.CONCORD_GHIDRA, 'C:/ghidra', '/opt/ghidra', path.join(home, 'ghidra')]) {
    const found = holds(candidate);
    if (found) return found;
  }
  for (const parent of [path.join(home, 'Downloads'), home]) {
    let names = [];
    try { names = fs.readdirSync(parent).filter((name) => name.toLowerCase().startsWith('ghidra')).sort(); }
    catch { continue; }
    for (const name of names) {
      // An unpacked archive usually nests one directory deep, with the date suffix dropped.
      const found = holds(path.join(parent, name)) ?? holds(path.join(parent, name, name.replace(/_\d{8}$/, '')));
      if (found) return found;
    }
  }
  return null;
})();

/** x86-64's real table and specs, plus a real 76 KB PE, copied into the scratch workspace. */
const REAL_FILES = {
  'x86-64.sla': 'Ghidra/Processors/x86/data/languages/x86-64.sla',
  'x86.ldefs': 'Ghidra/Processors/x86/data/languages/x86.ldefs',
  'x86-64.pspec': 'Ghidra/Processors/x86/data/languages/x86-64.pspec',
  'x86-64-win.cspec': 'Ghidra/Processors/x86/data/languages/x86-64-win.cspec',
  'x86.slaspec': 'Ghidra/Processors/x86/data/languages/x86.slaspec',
  'program.exe': 'Ghidra/Features/PDB/os/win_x86_64/pdb.exe',
};
const realFixture = (dir) => {
  for (const [name, relative] of Object.entries(REAL_FILES)) fs.copyFileSync(path.join(GHIDRA, relative), path.join(dir, name));
};
/** The digest of an installed file, computed here so a reader's sha256 is checked independently. */
/** A SHA-256-shaped string: used where the fixture's own bytes are written by the test helper. */
const hex64 = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const realDigest = (name) => createHash('sha256').update(fs.readFileSync(path.join(GHIDRA, REAL_FILES[name]))).digest('hex');
/** x86-64 decodes as 64-bit only when the context says so; the defaults describe a 16-bit machine. */
const LONG_MODE = { addrsize: 2, opsize: 1, rexprefix: 0, longMode: 1 };
const realTask = (tool, input) => ({ version: 1, name: 'real-corpus', tasks: [{ id: 'a', tool, input }] });

export function ghidraExercises() {
  return [
    {
      family: 'composition', tool: 'artifact.sleighCompiled', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: { version: 1, name: 'four-specification-readers-over-one-fixture-set', tasks: [
        { id: 'opinion', tool: 'artifact.ghidraLoaderOpinion', input: { path: 'toy.opinion' } },
        { id: 'match', tool: 'artifact.ghidraLanguageMatch', input: { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '334' } },
        { id: 'compiled', tool: 'artifact.sleighCompiled', input: { path: 'toy.sla' } },
        { id: 'agreement', tool: 'artifact.compareSleighSource', input: { compiled: 'toy.sla', source: 'toy.slaspec' } },
      ] },
      expect: (r) => r.results.opinion.supported === true && r.results.opinion.counts.constraints === 4
        && r.results.match.counts.matched === 1 && r.results.match.counts.resolved === 0
        && r.results.compiled.supported === true && hex64(r.results.compiled.sha256)
        && r.results.agreement.supported === true
        && [r.results.opinion, r.results.compiled].every((value) => value.untrusted === true)
        && Array.isArray(r.results.agreement.limitations),
      lesson: 'The four specification readers in one plan over one fixture set, which is how they are actually used: a loader opinion says which languages could apply, the match resolves those rows against the declarations that exist, the compiled table is what the processor really does, and the comparison checks the table against its source. Running them together is the point — each answers a different question about the same language, and the interesting failure is disagreement between them rather than any one of them refusing. Here the match resolves nothing while still reporting a matched row, which is the honest shape: a loader row that names a language nobody declared is a fact about the opinion file, not a parse failure.',
    },
    {
      family: 'ghidra', tool: 'artifact.ghidraLanguages', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.ghidraLanguages', { path: 'toy.ldefs' }),
      // Two languages are declared and a third sits inside an XML comment. The count is the
      // assertion because agreeing with a grep here would be agreeing with the wrong number.
      expect: (r) => r.results.a.counts.languages === 2
        && !r.results.a.languages.some((language) => language.variant === 'commented')
        && r.results.a.languages[0].defaultCompiler === 'default'
        && r.results.a.languages[1].endian === 'big' && r.results.a.languages[1].instructionEndian === 'little',
      lesson: 'artifact.ghidraLanguages reads a .ldefs and counts only the languages the file actually declares: one inside an XML comment is skipped, which is why a parser reports 189 languages for the shipped corpus where a text search reports 190. The first compiler element is the default and is named rather than left to be inferred from list position, and a language whose instruction endianness differs from its data endianness keeps both — that LEBE case is exactly why a language id cannot be rebuilt from processor, size and variant.',
    },
    {
      family: 'ghidra', tool: 'artifact.ghidraProcessorSpec', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.ghidraProcessorSpec', { path: 'toy.pspec' }),
      expect: (r) => {
        const out = r.results.a;
        return out.programCounter === 'PC'
          && out.registers.length === 2 && out.incidentalCopy.length === 1 && out.volatileRanges.length === 1
          && out.symbols.find((s) => s.name === 'P0').address.offset === 0x80
          && out.counts.entryPoints === 1
          && out.limitations.some((line) => /renamed/.test(line));
      },
      lesson: 'artifact.ghidraProcessorSpec keeps three different declarations apart even though all three spell their members <register>: allocatable registers from register_data, memory-mapped ranges from volatile, and copies that are not real dataflow from incidentalcopy. Folding them together would report x86 eight x87 stack slots as general registers. An address offset is hex whether or not it carries 0x, so SFR:80 is 128 and reading it as decimal would place a whole SFR map at the wrong addresses, and a renamed register is disclosed because every later reference in that file and in any compiler spec uses the new name.',
    },
    {
      family: 'ghidra', tool: 'artifact.ghidraCompilerSpec', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.ghidraCompilerSpec', { path: 'toy.cspec' }),
      expect: (r) => {
        const out = r.results.a;
        const first = out.conventions[0];
        return out.defaultConvention === '__stdcall' && first.isDefault === true
          && out.conventions[1].isDefault === false
          && first.inputs[0].location.register === 'r0'
          && first.inputs[1].location.kind === 'join'
          && first.inputs[1].location.pieces.join(',') === 'r1,r0'
          && first.unaffected.join(',') === 'SP' && first.killedByCall.join(',') === 'r1'
          && out.dataOrganization.bitfieldPacking.use_MS_convention === 1;
      },
      lesson: 'artifact.ghidraCompilerSpec preserves pentry order because that order is the argument allocation order: the first entry takes the first argument, so sorting or deduplicating the list would destroy the fact. A pentry in the join space concatenates registers to carry a value wider than one of them, and the piece order is the layout. The default convention comes from default_proto and is named explicitly rather than taken from position, and use_MS_convention is the one field in the data model that identifies a toolchain rather than a width: it is the MSVC against GCC bitfield discriminator.',
    },
    {
      family: 'ghidra', tool: 'artifact.ghidraLoaderOpinion', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.ghidraLoaderOpinion', { path: 'toy.opinion' }),
      expect: (r) => {
        const out = r.results.a;
        return out.counts.constraints === 4
          && out.constraints.every((row) => row.loader === 'Portable Executable (PE)')
          && out.constraints.filter((row) => row.compilerSpecID === 'windows').length === 2
          // The envelope: the path asked for, a digest of the bytes read, understood with no
          // reason to give, somebody else's data, and a limitations list.
          && out.path === 'toy.opinion' && hex64(out.sha256) && out.supported === true
          && out.reason === null && out.untrusted === true && Array.isArray(out.limitations)
          && out.loaders.length >= 1;
      },
      lesson: 'artifact.ghidraLoaderOpinion flattens the constraint tree, because the nesting exists only to share attributes: an inner constraint inherits everything its ancestors set, so the leaf rows with ancestor attributes merged in are the decision table a loader actually matches against. A .opinion file also carries no XML declaration — none of the 29 shipped ones does — so requiring a prolog would reject every real file of this type.',
    },
    {
      family: 'ghidra', tool: 'artifact.ghidraLanguageMatch', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.ghidraLanguageMatch', { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '334' }),
      // The row matches and names variant "absent", which no language declares. Reporting nothing
      // matched would be false, and assembling Toy:BE:64:absent would be worse.
      expect: (r) => r.results.a.counts.matched === 1 && r.results.a.counts.resolved === 0
        && r.results.a.matched[0].resolved === false && r.results.a.matched[0].languages.length === 0
        && r.results.a.limitations.some((line) => /none names a language present/.test(line))
        && r.results.a.supported === true && r.results.a.reason === null
        && r.results.a.query.primary === '334' && r.results.a.rows >= 1,
      lesson: 'artifact.ghidraLanguageMatch resolves a loader row only against languages the .ldefs really declares, and reports a row that matched but resolved to nothing as exactly that. Assembling an identifier of the form processor:LE:32:variant would produce a plausible answer for every matching row, including rows whose language is not installed, and an id that resolves to nothing is worse than a row openly reported as unresolved. The reverse matters too: a row that constrains the secondary key is not matched by a query that supplies none, because treating an absent key as a wildcard would select a clang-only row for a binary that never claimed to be clang.',
    },
    {
      family: 'ghidra', tool: 'artifact.sleighCompiled', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.sleighCompiled', { path: 'toy.sla' }),
      expect: (r) => {
        const out = r.results.a;
        return out.format.version === 4 && out.sleigh.bigEndian === false && out.sleigh.alignment === 1
          && out.sleigh.defaultSpace === 'ram' && out.sleigh.maxDelaySlotBytes === 0
          && out.spaces.some((space) => space.kind === 'unique')
          && out.sourceFiles.length === 1 && out.userops.length === 1 && out.subtables.length === 1
          && out.counts.inflatedBytes > 0;
      },
      lesson: 'artifact.sleighCompiled decodes a .sla with built-ins only: the file is the bytes "sla", a one-byte format version, then a single zlib stream wrapping Ghidra PackedFormat, which is three record types discriminated by the top two bits and seven bits of integer payload per byte. The element and attribute id tables are not stored in the file, so the reader carries them, and that is precisely why format version 4 is asserted rather than assumed — a later version would still inflate and still yield element ids, so the ids would be read against the wrong table and every fact would come back confidently wrong. A compiled table also records which source files built it, which is provenance the source files cannot give about themselves.',
    },
    {
      family: 'ghidra', tool: 'artifact.sleighCompiled', workspace: 'temp',
      fixture: (dir) => {
        writeGhidraFixtures(dir);
        fs.writeFileSync(path.join(dir, 'v9.sla'), Buffer.concat([
          Buffer.from('sla'), Buffer.from([9]), buildSla().subarray(4),
        ]));
      },
      plan: task('artifact.sleighCompiled', { path: 'v9.sla' }),
      expect: (r) => r.results.a.supported === false
        && r.results.a.reason === 'unsupported_format_version'
        && r.results.a.format.version === 9 && r.results.a.sleigh === null,
      lesson: 'artifact.sleighCompiled refuses a .sla whose declared format version is not the one it decodes, and still reports the version it found. The stream after the header is a perfectly valid zlib payload in this fixture, so the refusal is not a decode failure: it is the reader declining to interpret ids against a table that may have been renumbered. Reporting the version rather than only the refusal is what lets a caller tell "this is a newer Ghidra" apart from "this is not a Ghidra file".',
    },
    {
      family: 'ghidra', tool: 'artifact.sleighSource', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.sleighSource', { path: 'toy.slaspec' }),
      expect: (r) => {
        const out = r.results.a;
        const unguarded = out.pcodeops.filter((op) => !op.guards.length).map((op) => op.name);
        const guarded = out.pcodeops.find((op) => op.name === 'toyExtended');
        const registers = new Map(out.registers.map((reg) => [reg.name, reg]));
        return unguarded.length === 2 && unguarded.includes('toy.add.s')
          && guarded && guarded.guards[0] === 'defined(EXTENDED)'
          && out.mnemonics.map((m) => m.mnemonic).join(',') === 'halt,add'
          && registers.get('SP').offset === 16
          && out.counts.unterminatedDeclarations === 0;
      },
      lesson: 'artifact.sleighSource reports each SLEIGH declaration with the @if conditions guarding it and never evaluates them, because a .slaspec does not state its own meaning: define endian=$(ENDIAN) is how the ARM family declares endianness and one ARM source tree describes 22 languages, so resolving the preprocessor would attribute one variant registers to all of them. Three parsing facts had to be measured rather than assumed, and each was a character with two meanings: a semicolon also sequences tokens inside a constructor pattern and separates assignments inside a bracketed action block, a hash is also the quoted immediate marker in 68000 and ARM display sections, and a brace also appears quoted in an ARM register list. Reading any of them the single-meaning way still answered supported:true while silently losing thousands of declarations. An underscore in a register name list is a declared gap that still consumes its slot, and a dot is a legal identifier character, which Loongarch and the MIPS DSP extension rely on.',
    },
    {
      family: 'ghidra', tool: 'artifact.compareSleighSource', workspace: 'temp',
      fixture: (dir) => {
        writeGhidraFixtures(dir);
        fs.writeFileSync(path.join(dir, 'macro.slaspec'), 'define endian=$(ENDIAN);\ndefine alignment=1;\n');
      },
      plan: task('artifact.compareSleighSource', { compiled: 'toy.sla', source: 'macro.slaspec' }),
      expect: (r) => {
        const out = r.results.a;
        return out.disagreements.length === 0
          && out.unstated.find((entry) => entry.field === 'endian').reason === 'unresolved_macro'
          && out.agreements.some((entry) => entry.field === 'alignment');
      },
      family: 'ghidra', tool: 'artifact.disassemble', workspace: 'temp',
      fixture: (dir) => {
        writeGhidraFixtures(dir);
        fs.writeFileSync(path.join(dir, 'code.bin'), Buffer.from([0x00, 0x02, 0x7f, 0x08, 0x00]));
      },
      plan: task('artifact.disassemble', { table: 'toy-decode.sla', path: 'code.bin', address: '0x400000', limit: 8 }),
      expect: (r) => {
        const out = r.results.a;
        const texts = out.instructions.map((instruction) => instruction.text);
        return out.supported === true
          && texts[0] === 'halt' && texts[1] === 'ld 0x7f'
          && out.instructions[1].length === 2
          && out.instructions[1].address === '0x400001'
          && out.instructions[2].decoded === false
          && out.counts.decoded === 2 && out.counts.undecoded === 1
          && out.counts.bytesDecoded === 3 && out.counts.bytesSelected === 5
          && out.limitations.some((line) => /No initial context was supplied/.test(line));
      },
      lesson: 'artifact.disassemble decodes instructions from a compiled SLEIGH table and a byte range, as a read effect over two files already in the workspace: it needs no approval and is a pure function of its input, so a recorded run replays. Each line reports the constructors that matched, which is what lets a disassembly be traced back to the SLEIGH that produced it rather than taken on trust. Addresses leave as hex strings because a 64-bit address exceeds the safe integer range and canonical rejects a BigInt outright, so a numeric address would either round silently or fail the kernel encoding check. Decoding stops at the first position no constructor claims rather than resynchronising at a guessed boundary, and the byte counts make that visible. Supplying no initial context is disclosed, because a language whose decode depends on context decodes in whatever its zeroed context selects: x86 without opsize from the .pspec reports PUSH BP where the 32-bit language means PUSH EBP, which is correct for the bits it was given and wrong about the program.',
    },
    {
      family: 'ghidra', tool: 'artifact.disassemble', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.disassemble', { table: 'toy-decode.sla', path: 'toy-code.bin', pcode: true, limit: 4 }),
      expect: (r) => {
        const out = r.results.a;
        const [halt, inc, ld] = out.instructions;
        return halt.text === 'halt' && halt.pcode.length === 0
          && halt.directives[0].directive === 'UNIMPLEMENTED'
          && inc.text === 'inc' && inc.pcode[0].op === 'INT_ADD'
          && inc.pcode[0].output.space === 'register'
          && inc.pcode[0].inputs[1].space === 'const'
          && ld.text === 'ld 0x42' && ld.pcode[0].op === 'COPY'
          && ld.pcode[0].inputs[0].offset === '0x42'
          && out.limitations.some((line) => /no dataflow/.test(line));
      },
      lesson: 'artifact.disassemble with pcode:true lifts each instruction to p-code, which is Ghidra own intermediate representation of what the instruction does: an operation, an optional output varnode and its input varnodes, each naming an address space, an offset and a size. A literal lands in the constant space, which is index 0 because the decoder re-inserts it rather than reading it from the file. The lift is a second pass over the same parse, and it has to be: a varnode template can name another operand handle space, offset or size, and that handle is only known once the operand own constructor has resolved. Two distinctions in the output carry real weight. An empty p-code list with an UNIMPLEMENTED directive is not an instruction that does nothing; it is an effect the table does not model, and conflating them would report a halt as a no-op. And a delay slot means the following instruction executes as part of this one, so the p-code shown is not the whole effect and the omission is stated rather than left to be noticed.',
    },
    {
      family: 'ghidra', tool: 'artifact.disassemble', workspace: 'temp',
      fixture: (dir) => {
        writeGhidraFixtures(dir);
        fs.writeFileSync(path.join(dir, 'described.sla'), buildSla());
      },
      plan: task('artifact.disassemble', { table: 'described.sla', path: 'toy-code.bin' }),
      // A table with symbol names and spaces but no decision tree has nothing to match. Reporting
      // a decode would be inventing one.
      expect: (r) => r.results.a.supported === true && r.results.a.counts.decoded === 0
        && r.results.a.instructions[0].decoded === false
        && r.results.a.instructions[0].reason === 'no_matching_constructor',
      lesson: 'artifact.disassemble distinguishes a table it cannot read from a table that matches nothing. A compiled table carrying symbol names and address spaces but no constructors loads successfully and then decodes nothing, which is reported as an undecoded position with reason no_matching_constructor rather than as a failure to read the table. The distinction matters because the two call for different actions: one means the wrong file was supplied, the other means these bytes are not instructions in this language.',
    },
    {
      family: 'ghidra', tool: 'artifact.controlFlow', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.controlFlow', { table: 'toy-decode.sla', path: 'toy-flow.bin', address: '0x0' }),
      expect: (r) => {
        const out = r.results.a;
        const head = out.blocks.find((block) => block.start === '0x0');
        const join = out.blocks.find((block) => block.start === '0x2');
        return out.supported === true && out.counts.blocks === 3
          && head.kind === 'conditional' && head.successors.length === 2
          && head.successors.some((edge) => edge.kind === 'branch' && edge.to === '0x5')
          && head.successors.some((edge) => edge.kind === 'fallthrough' && edge.to === '0x2')
          && join.successors.length === 1 && join.successors[0].kind === 'fallthrough'
          && out.calls.length === 1 && out.calls[0].to === '0x8'
          && out.instructions.every((instruction) => typeof instruction.address === 'string');
      },
      lesson: 'artifact.controlFlow recovers basic blocks and call edges from lifted p-code, and because it reads only BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND and RETURN it is one implementation for every architecture rather than one per architecture. Three of its rules come from Ghidra flow.cc and each is the opposite of a plausible guess. A call is a call edge and not a control-flow edge: it does not end a basic block and it does fall through, so treating it as a jump would split a block and lose the return after it. A branch whose target varnode sits in the constant space is not an address but a p-code-relative branch inside that single instruction, and reading it as an address would invent a jump to a tiny number. And a delay slot belongs to its branch rather than being its successor, so those bytes are attributed to the branch and flow resumes past them. A block that ends only because the next instruction is a branch target still carries its fallthrough edge, which is the join after a conditional; deciding successors while partitioning loses that edge and the block then reads as unreachable code. Reachability is followed from entry points rather than swept linearly, so an address that appears is one the analysis can explain, and an indirect branch is reported unresolved rather than omitted because a missing edge reads as dead code.',
    },
    {
      family: 'ghidra', tool: 'artifact.controlFlow', workspace: 'temp',
      fixture: (dir) => {
        writeGhidraFixtures(dir);
        // br to 0x40, in a program two bytes long: the target is not in the bytes supplied.
        fs.writeFileSync(path.join(dir, 'toy-away.bin'), Buffer.from([0x04, 0x40]));
      },
      plan: task('artifact.controlFlow', { table: 'toy-decode.sla', path: 'toy-away.bin', address: '0x0' }),
      expect: (r) => {
        const out = r.results.a;
        return out.supported === true && out.counts.instructions === 1 && out.counts.blocks === 1
          && out.blocks[0].successors.length === 1 && out.blocks[0].successors[0].to === '0x40'
          && out.unresolved.length === 1 && out.unresolved[0].kind === 'out_of_range'
          && out.unresolved[0].address === '0x40'
          && out.unresolved[0].reason.includes('Flow from 0x0')
          && out.limitations.some((line) => line.includes('outside the bytes supplied'));
      },
      lesson: 'artifact.controlFlow reports a flow target outside the bytes it was given instead of dropping it. The edge is still listed, because a missing edge reads as dead code, and the target is also recorded as unresolved with kind out_of_range naming the instruction it came from, because an edge pointing at an address nothing decoded is otherwise indistinguishable in the output from a block that was analysed. Skipping it silently is the failure this prevents, and it is not hypothetical: analysing a window of a real 2.5MB executable produced sixteen such targets, every one of them a genuine call or branch into code the window did not cover. recoverCallGraph already reported the same situation as an external node, so this makes the two layers agree rather than inventing a new convention.',
    },
    {
      family: 'ghidra', tool: 'artifact.controlFlow', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.controlFlow', { table: 'toy-decode.sla', path: 'toy-flow.bin', address: 'not-hex' }),
      expect: (r) => r.results.a.supported === false && r.results.a.reason === 'invalid_address'
        && r.results.a.blocks.length === 0,
      lesson: 'artifact.controlFlow refuses a malformed base address rather than defaulting it to zero, because a wrong base silently relocates every branch target and call edge it reports. The check lives in execute rather than in the input schema deliberately: the kernel schema subset is explicit and validateSchema refuses any keyword outside it, so declaring a pattern constraint would make every plan using the tool fail with INVALID_SCHEMA at compile time instead of producing a refusal that names what was wrong.',
    },
    {
      family: 'ghidra', tool: 'artifact.dataflow', workspace: 'temp',
      fixture: (dir) => {
        writeGhidraFixtures(dir);
        //   0x00  ld 0x42   defines all four bytes of r0
        //   0x02  setlow    writes only the low byte
        //   0x03  ret       reads all four bytes
        fs.writeFileSync(path.join(dir, 'partial.bin'), Buffer.from([0x02, 0x42, 0x07, 0x03]));
      },
      plan: task('artifact.dataflow', { table: 'toy-decode.sla', path: 'partial.bin', address: '0x0', detail: true }),
      expect: (r) => {
        const out = r.results.a;
        const wide = out.uses.find((use) => use.varnode.size === 4 && use.op === 'RETURN');
        return out.supported === true
          && wide && wide.reaching.length === 1 && wide.reaching[0] === '0x0:0'
          && wide.partiallyOverwritten.length === 1 && wide.partiallyOverwritten[0] === '0x2:0'
          && wide.external === false
          && out.summary.inputs.length === 0
          && out.limitations.some((line) => /fully covers it/.test(line));
      },
      lesson: 'artifact.dataflow computes reaching definitions over p-code varnodes, so it answers which write supplies the value each read observes, and because it reads only p-code it behaves the same on every architecture. The rule that decides whether it is right rather than merely plausible is the kill rule, taken from Varnode::contains in varnode.cc: a definition kills a previous one only when it fully covers it. A write to one byte of a register therefore leaves a wider definition alive and reports it as partially overwritten, which is the difference between tracking a value correctly and claiming it came from the wrong place — on x86 a write to AL must not discard EAX, because three of its bytes still hold what they held before. Two things are deliberately outside the analysis and declared rather than approximated: the constant space is not storage because a literal has no definition to reach, and memory through a computed pointer is not resolved, so no load is attributed to any store. And this is reaching definitions rather than static single assignment, so a read with several reaching definitions is a join reported as it is rather than merged behind a phi node that nothing here computed.',
    },
    {
      family: 'ghidra', tool: 'artifact.dataflow', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.dataflow', { table: 'toy-decode.sla', path: 'toy-flow.bin', address: '0x0' }),
      expect: (r) => {
        const out = r.results.a;
        return out.supported === true
          && out.definitions.length === 0 && out.uses.length === 0
          && out.counts.definitions > 0
          && out.limitations.some((line) => /detail:true/.test(line));
      },
      lesson: 'artifact.dataflow returns the definition and use chains only when detail:true is asked for, and says so when it does not. The summary — which storage a region reads before writing, and which it writes — is the answer most questions want and is small enough to always return, while the chains over a few hundred instructions are large enough to crowd out everything else in an output budget. The counts describe the whole analysis either way, so the omission is visible rather than looking like an analysis that found nothing.',
    },
    {
      family: 'ghidra', tool: 'artifact.callGraph', workspace: 'temp',
      fixture: (dir) => writeGhidraFixtures(dir),
      plan: task('artifact.callGraph', { table: 'toy-decode.sla', path: 'toy-calls.bin', address: '0x0' }),
      expect: (r) => {
        const out = r.results.a;
        return out.supported === true
          && out.counts.regions === 3 && out.counts.callEdges === 2 && out.counts.leaves === 1
          && out.regions.map((region) => region.entry).join(',') === '0x0,0x4,0x8'
          && out.regions.map((region) => region.instructions).join(',') === '2,2,1'
          && out.edges.every((edge) => edge.kind === 'call')
          && out.nodes.find((node) => node.address === '0x4').calledBy === 1
          && out.counts.recursive === 0;
      },
      lesson: 'artifact.callGraph grows one entry point into every region a call can reach, where a region is all code reachable from an entry without following a call. Each region stays its own body rather than absorbing its callees, and a call site is kept per edge because two calls to one address are two facts and the site is where a caller looks for the arguments. Recursion is detected by reachability rather than by self-edges, so mutual recursion between two regions that never call themselves is still reported. The hard part is where a region stops: a tail jump is indistinguishable from an ordinary branch by inspecting the instruction, and Ghidra resolves that in its Java function-boundary analysis which is not shipped as source, so there is no rule to port. Rather than invent a heuristic that silently reclassifies a jump as a call, this uses evidence — an address that is called from somewhere is a function entry — in a second pass that treats those addresses as region boundaries. Flow arriving at one by a branch or a fallthrough is then reported as a tail edge marked candidate: the structure is certain, the intent is not. Without that pass one tail call swallows its callee and the graph comes back nearly empty, which is the wrong answer in the shape of a plausible one. A call target outside the range becomes an external node so the edge survives without a body, and an indirect call creates no node at all, which makes every graph a lower bound rather than a census.',
    },
    {
      family: 'ghidra', tool: 'artifact.compareSleighSource', workspace: 'temp',
      fixture: (dir) => {
        writeGhidraFixtures(dir);
        fs.writeFileSync(path.join(dir, 'macro.slaspec'), 'define endian=$(ENDIAN);\ndefine alignment=1;\n');
      },
      plan: task('artifact.compareSleighSource', { compiled: 'toy.sla', source: 'macro.slaspec' }),
      expect: (r) => {
        const out = r.results.a;
        return out.disagreements.length === 0
          && out.unstated.find((entry) => entry.field === 'endian').reason === 'unresolved_macro'
          && out.agreements.some((entry) => entry.field === 'alignment');
      },
      lesson: 'artifact.compareSleighSource has three outcomes rather than two, and the third is the point: a source file that writes its endianness as an unresolved macro has not disagreed with the compiled table, it has not spoken. Recording that as a mismatch would manufacture a finding out of the preprocessor, so it lands in unstated with the reason it could not be compared, while a fact the source does state unconditionally is still compared normally in the same call. Across the 137 shipped table and source pairs this reports agreements and no disagreements at all, which is a joint check: the binary decoder and the text reader are verified against each other rather than each only against its own format.',
    },

    // ---- the installed distribution, where the files are not ours ------------------------
    ...(GHIDRA ? [
      {
        family: 'composition', tool: 'artifact.disassemble', workspace: 'temp', fixture: realFixture,
        plan: { version: 1, name: 'read-a-real-binary-with-a-real-table', tasks: [
          { id: 'seen', tool: 'artifact.inspect', input: { path: 'program.exe' } },
          // Every later task takes the file offset from the inspection rather than restating it.
          { id: 'code', tool: 'artifact.disassemble', dependsOn: ['seen'], input: {
            table: 'x86-64.sla', path: 'program.exe', offset: { $task: 'seen', path: '/pe/entryPointOffset' },
            length: 64, limit: 8, pcode: true, context: LONG_MODE } },
          { id: 'flow', tool: 'artifact.controlFlow', dependsOn: ['seen'], input: {
            table: 'x86-64.sla', path: 'program.exe', offset: { $task: 'seen', path: '/pe/entryPointOffset' },
            length: 128, limit: 32, context: LONG_MODE } },
          { id: 'graph', tool: 'artifact.callGraph', dependsOn: ['seen'], input: {
            table: 'x86-64.sla', path: 'program.exe', offset: { $task: 'seen', path: '/pe/entryPointOffset' },
            length: 128, limit: 32, regionLimit: 4, context: LONG_MODE } },
          { id: 'values', tool: 'artifact.dataflow', dependsOn: ['seen'], input: {
            table: 'x86-64.sla', path: 'program.exe', offset: { $task: 'seen', path: '/pe/entryPointOffset' },
            length: 64, limit: 32, detail: true, context: LONG_MODE } },
        ] },
        expect: (r) => {
          const pe = r.results.seen.pe;
          const code = r.results.code;
          const first = code.instructions[0];
          return r.results.seen.format === 'pe'
            // The three entry points are three different numbers, and the gap is a real section gap.
            && pe.entryPoint !== pe.entryPointOffset
            && pe.entryPoint - pe.entryPointOffset === 3072
            && pe.entryPointAddress === pe.imageBase + pe.entryPoint
            && code.supported === true && code.language.formatVersion === 4
            && code.language.defaultSpace === 'ram' && code.language.bigEndian === false
            && code.language.sourceFiles.includes('ia.sinc')
            // A real entry point begins by making stack room. Decoding the RVA instead would land
            // three kilobytes away and still disassemble into something plausible.
            && first.offset === pe.entryPointOffset && first.decoded === true
            && first.mnemonic === 'SUB' && first.text === 'SUB RSP,0x28' && first.bytes === '4883ec28'
            && first.pcode.some((op) => op.op === 'INT_SUB') && first.constructors.length > 0
            && r.results.flow.supported === true && r.results.flow.counts.instructions === 4
            && r.results.flow.counts.blocks === 1 && r.results.flow.counts.calls === 1
            && r.results.flow.entries.join(',') === '0x0'
            && r.results.graph.counts.nodes === 2 && r.results.graph.counts.edges === 1
            && r.results.graph.counts.external === 1 && r.results.graph.counts.regions === 1
            && r.results.values.counts.definitions === 19 && r.results.values.counts.uses === 20
            && r.results.values.counts.fixpointRounds === 1 && r.results.values.counts.stores === 1
            && r.results.values.summary.inputs.length === 1 && r.results.values.slice === null
            && [code, r.results.flow, r.results.graph, r.results.values].every((value) =>
              value.untrusted === true && value.table === 'x86-64.sla' && value.path === 'program.exe'
              && value.sha256 === realDigest('program.exe') && value.supported === true
              && value.reason === null && Array.isArray(value.limitations))
            && r.results.flow.entries.length === 1 && r.results.graph.entries.length === 1
            && r.results.values.entries.length === 1
            && r.results.graph.external.length === 1 && r.results.graph.unresolved.length === 1;
        },
        lesson: 'The whole reading chain composes in one plan against the installed distribution: identify a real PE, then disassemble, recover control flow, build a call graph and track values at its entry point using Ghidra\'s own half-megabyte x86-64 table. Every later task takes the file offset from the inspection by reference, which makes the entry-point lesson structural instead of advisory — measured here, the RVA is 43324 and the bytes live at offset 40252, a gap of exactly 3072 from the section layout, and the image base plus the RVA is the address the code believes it runs at. All three numbers appear in the same result and none of them substitutes for another. The proof that the conversion was right is the decode itself: the first instruction is SUB RSP,0x28, the stack-room prologue a real entry point begins with, where feeding the RVA to the disassembler would have landed three kilobytes away and still produced plausible instructions, because a stream of x86 bytes almost always decodes as something. Four readers over the same bytes then agree: four instructions, one block, one call, two nodes with one edge to one external target, and nineteen definitions against twenty uses settled in a single fixpoint round.',
      },
      {
        family: 'ghidra', tool: 'artifact.sleighCompiled', workspace: 'temp', fixture: realFixture,
        plan: realTask('artifact.sleighCompiled', { path: 'x86-64.sla' }),
        expect: (r) => r.results.a.supported === true
          && r.results.a.registers.length > 1000
          && r.results.a.registers.some((entry) => entry.name === 'RSP')
          && r.results.a.elementCounts.length > 20
          // Ordered by descending count, which only survives because this is a list.
          && r.results.a.elementCounts[0].count >= r.results.a.elementCounts[1].count
          && r.results.a.elementCounts.find((entry) => entry.element === 'const_real').count > 100_000
          && r.results.a.elementCounts.find((entry) => entry.element === 'op_tpl').count > 10_000
          // The element whose name is why this is a list and not an object.
          && r.results.a.elementCounts.some((entry) => entry.element === 'constructor')
          && r.results.a.counts.constructors > 1000
          && r.results.a.untrusted === true,
        lesson: 'The real x86-64 table decodes end to end: 1440 register varnodes in Ghidra 12.1.4 and an element tally in the hundreds of thousands, with const_real past 136,000 and 39,870 op templates. That scale is the argument for reading the compiled table rather than the source, and it is why the elements are reported as a tally rather than as elements: returning them all would hand back a structure larger than the file. The tally is a list of pairs and not an object, which this exercise is the reason for — every real SLEIGH table contains constructor elements, canonical() refuses that key outright, and as an object the entire read of a 490 KB table failed with OUTPUT_REJECTED naming only "Unsafe object key: constructor" and nothing about which field held it. A name read out of a file must never become an object key. The same change rescued an ordering that was already lost: the tally was sorted by descending count and then canonicalised into an object, which re-sorts keys lexicographically, so the order the code computed never reached a caller. The synthetic fixture beside this one has no constructor element, which is exactly why the suite could not have found either problem.',
      },
      {
        family: 'ghidra', tool: 'artifact.ghidraLanguages', workspace: 'temp', fixture: realFixture,
        plan: realTask('artifact.ghidraLanguages', { path: 'x86.ldefs' }),
        expect: (r) => r.results.a.supported === true
          && r.results.a.languages.length >= 4
          && r.results.a.languages[0].id === 'x86:LE:32:default'
          && r.results.a.languages[0].processor === 'x86' && r.results.a.languages[0].size === 32
          && r.results.a.languages[0].endian === 'little'
          && r.results.a.languages[0].defaultCompiler === 'windows'
          && r.results.a.languages[0].compilers.length >= 2
          && r.results.a.languages.some((entry) => entry.id.includes('64')),
        lesson: 'Ghidra\'s own x86 language definitions parse into six declared languages, each naming the table file, processor spec and manual index it depends on, with its compiler list and the default named explicitly rather than inferred from list position. This is the file a loader consults to answer "which language is this binary", so a reader that dropped the compiler list or guessed the default would make that answer unreproducible — and the ids are not reconstructible from processor, size and variant, which is exactly why they are read rather than assembled.',
      },
      {
        family: 'ghidra', tool: 'artifact.ghidraCompilerSpec', workspace: 'temp', fixture: realFixture,
        plan: realTask('artifact.ghidraCompilerSpec', { path: 'x86-64-win.cspec' }),
        expect: (r) => r.results.a.supported === true
          && r.results.a.stackPointer.register === 'RSP'
          && r.results.a.stackPointer.growth === 'negative'
          && r.results.a.returnAddress.space === 'stack' && r.results.a.returnAddress.size === 8
          && r.results.a.counts.conventions >= 2 && r.results.a.counts.callFixups >= 3
          && r.results.a.globals.length >= 2 && r.results.a.untrusted === true,
        lesson: 'The real Windows x86-64 compiler spec reports RSP growing downward, a return address eight bytes wide in the stack space, two calling conventions, three call fixups and two global ranges. Those are the facts that make a decompiled signature mean anything: the stack direction decides which side of the frame an argument is on, and the return-address width and space decide where the frame ends. A reader that folded the conventions together or inferred the stack direction from the architecture would produce a plausible prototype for the wrong ABI — which is the same failure the pentry-ordering lesson beside this one is about, met on the shipped file rather than a fixture.',
      },
      {
        family: 'ghidra', tool: 'artifact.sleighSource', workspace: 'temp', fixture: realFixture,
        plan: realTask('artifact.sleighSource', { path: 'x86.slaspec' }),
        expect: (r) => r.results.a.supported === true
          && r.results.a.includes.length >= 20
          && r.results.a.tokens.length === 0 && r.results.a.subtables.length === 0
          && r.results.a.spaces.length === 0 && r.results.a.endian === null
          && r.results.a.untrusted === true,
        lesson: 'x86.slaspec is 491 bytes and declares almost nothing: no tokens, no subtables, no spaces, not even an endianness — just 21 includes. The entire instruction set lives in the included .sinc files, so a reader of the top-level source alone would report an empty language and be exactly right about the file while being useless about x86. That is worth knowing before trusting any single-file answer about a SLEIGH language, and it is the reason the compiled table is the thing to read when the question is what the processor does. An empty answer here is correct rather than a parse failure, which is why supported is true with every list empty rather than a reason being set.',
      },
      {
        family: 'composition', tool: 'artifact.ghidraProcessorSpec', workspace: 'temp', fixture: realFixture,
        plan: { version: 1, name: 'four-real-specs-in-one-plan', tasks: [
          { id: 'languages', tool: 'artifact.ghidraLanguages', input: { path: 'x86.ldefs' } },
          { id: 'processor', tool: 'artifact.ghidraProcessorSpec', input: { path: 'x86-64.pspec' } },
          { id: 'compiler', tool: 'artifact.ghidraCompilerSpec', input: { path: 'x86-64-win.cspec' } },
          { id: 'source', tool: 'artifact.sleighSource', input: { path: 'x86.slaspec' } },
        ] },
        expect: (r) => {
          const names = { languages: 'x86.ldefs', processor: 'x86-64.pspec', compiler: 'x86-64-win.cspec', source: 'x86.slaspec' };
          return Object.entries(names).every(([id, file]) => {
            const value = r.results[id];
            // The envelope every reader here shares, checked rather than assumed: the path it was
            // asked for, the digest of exactly those bytes computed independently from the
            // installed file, no reason because it is supported, and untrusted bytes.
            return value.path === file && value.sha256 === realDigest(file)
              && value.supported === true && value.reason === null
              && value.untrusted === true && Array.isArray(value.limitations);
          })
            // And the four together are the set a loader needs to pick a language and read it.
            && r.results.processor.contextFields.length === 5
            && r.results.compiler.counts.conventions >= 2
            && r.results.languages.languages.length >= 4
            && r.results.source.includes.length >= 20;
        },
        lesson: 'Four readers over four real specification files in one plan, and the useful part is the envelope they share: each reports the path it was asked for, the SHA-256 of exactly those bytes — matched here against a digest computed independently from the installed distribution — a null reason because the file was understood, an untrusted flag because a specification is still somebody else\'s data, and a limitations list. That uniformity is what lets a caller treat eight different readers as one kind of answer. The four together are also exactly the set a loader needs: the language definitions to choose an id, the processor spec for its context fields, the compiler spec for its calling conventions, and the source for what it defers to its includes.',
      },
    ] : []),
  ];
}
