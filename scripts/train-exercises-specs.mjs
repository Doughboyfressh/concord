import fs from 'node:fs';
import path from 'node:path';
import { GHIDRA, REAL_FILES } from './train-exercises-ghidra.mjs';

/**
 * The readers that describe a processor, an assembly, or a bundle - on real inputs.
 *
 * Second batch of readers that had only ever seen `notmine.bin`. The inputs here divide into
 * three kinds, and the reason for each is worth stating because it is the choice that makes the
 * evidence mean anything:
 *
 *   the real Ghidra corpus   x86-64.pspec, x86-64.sla and x86.slaspec are already here and are
 *                            what these readers were written for. 201 registers, 5791
 *                            constructors, 24 source files - numbers no fixture would invent.
 *   a real .NET assembly     System.Linq.dll from the framework on this machine. It is 14 KB
 *                            because it is a type-forwarding facade, which turns out to be the
 *                            more interesting fixture: one type, no members, no P/Invoke. A
 *                            reader that cannot tell a facade from an empty assembly would
 *                            report the same thing for both.
 *   written to spec          an XML property list, a JavaScript module, and a SLEIGH source that
 *                            declares one of every kind of declaration. The last exists because
 *                            x86's own ia.sinc is 551 KB and the read budget at a 4 MB policy is
 *                            524 KB - the file that declares the tokens, macros and attaches is
 *                            larger than this reader may read, which is itself worth knowing.
 *
 * Everything asserted below was measured first. Where a number is a property of this machine's
 * framework rather than of the format, the assertion is on the name and the shape instead - an
 * assembly's own name is stable in a way its table row counts are not.
 */

/** A SLEIGH source carrying one of each declaration the reader names. Written to the spec. */
const DECLARING_SLASPEC = [
  '# A minimal SLEIGH source that declares one of every kind, so a reader of declarations has',
  '# one of each to find. Not a processor anyone would want: a processor nobody has to have.',
  'define endian=little;',
  'define alignment=1;',
  'define space ram type=ram_space size=4 default;',
  'define space register type=register_space size=4;',
  'define register offset=0 size=4 [ r0 r1 r2 r3 ];',
  'define register offset=0x100 size=4 [ contextreg ];',
  'define token instruction(8)',
  '  op = (0,7)',
  '  regfield = (0,1)',
  ';',
  'define context contextreg',
  '  mode = (0,0)',
  '  wide = (1,1)',
  ';',
  'define pcodeop sideEffect;',
  'attach variables [ regfield ] [ r0 r1 r2 r3 ];',
  '@define ZERO "0x00"',
  '@define ONE "0x01"',
  'macro setZero(target) {',
  '  target = $(ZERO);',
  '}',
  ':NOP is op=0x90 { }',
  ':CLR regfield is op=0x10 & regfield { setZero(regfield); }',
  '',
].join('\n');

const INFO_PLIST = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
  '<plist version="1.0">', '<dict>',
  '  <key>CFBundleIdentifier</key><string>com.example.concord</string>',
  '  <key>CFBundleVersion</key><string>1.0.3</string>',
  '  <key>LSMinimumSystemVersion</key><string>13.0</string>',
  '  <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>',
  '  <key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>concord</string></array></dict></array>',
  '</dict>', '</plist>', '',
].join('\n');

const JS_MODULE = [
  "import { readFile } from 'node:fs/promises';",
  "import helper from './helper.mjs';",
  '',
  'export const VERSION = 3;',
  'export async function load(name) {',
  "  const text = await readFile(name, 'utf8');",
  '  return helper(JSON.parse(text));',
  '}',
  'export default load;',
  'const secret = eval("1 + 1");',
  'new Function("return 2")();',
  '',
].join('\n');

/** One real managed assembly, if this machine has the framework that ships it. */
const ASSEMBLY = (() => {
  const candidate = 'C:/Windows/Microsoft.NET/Framework64/v4.0.30319/System.Linq.dll';
  try { return fs.statSync(candidate).isFile() ? candidate : null; } catch { return null; }
})();

const one = (tool, input) => ({ version: 1, name: 'real-spec', tasks: [{ id: 'a', tool, input }] });

const write = (dir, name, content) => {
  const target = path.join(dir, name);
  if (!fs.existsSync(target)) fs.writeFileSync(target, content);
};
const copyReal = (dir, name) => {
  const target = path.join(dir, name);
  if (!fs.existsSync(target)) fs.copyFileSync(path.join(GHIDRA, REAL_FILES[name]), target);
};

const declaringFixture = (dir) => write(dir, 'declaring.slaspec', DECLARING_SLASPEC);
const plistFixture = (dir) => write(dir, 'Info.plist', INFO_PLIST);
const jsFixture = (dir) => write(dir, 'semantics.mjs', JS_MODULE);
const pspecFixture = (dir) => copyReal(dir, 'x86-64.pspec');
const cspecFixture = (dir) => copyReal(dir, 'x86-64-win.cspec');
const compiledFixture = (dir) => copyReal(dir, 'x86-64.sla');
const comparisonFixture = (dir) => { copyReal(dir, 'x86-64.sla'); copyReal(dir, 'x86.slaspec'); };
const assemblyFixture = (dir) => {
  const target = path.join(dir, 'assembly.dll');
  if (!fs.existsSync(target)) fs.copyFileSync(ASSEMBLY, target);
};

export function specExercises() {
  return [
    {
      family: 'specs', tool: 'artifact.sleighSource', workspace: 'temp', fixture: declaringFixture,
      plan: one('artifact.sleighSource', { path: 'declaring.slaspec' }),
      expect: (r) => r.results.a.supported === true
        // endian and alignment are objects rather than scalars, because every declaration in a
        // SLEIGH source carries the @if conditions in force where it was written: the same file
        // can declare a different endianness under a different guard.
        && r.results.a.endian.value === 'little' && r.results.a.alignment.value === 1
        && r.results.a.counts.spaces === 2 && r.results.a.counts.registers === 5
        && r.results.a.counts.tokens === 1 && r.results.a.counts.pcodeops === 1
        && r.results.a.counts.mnemonics === 2
        && r.results.a.counts.contextFields === 2 && r.results.a.contextFields.length === 2
        && r.results.a.contextFields.some((field) => field.name === 'mode' && field.varnode === 'contextreg' && field.low === 0 && field.high === 0)
        && r.results.a.counts.attaches === 1 && r.results.a.attaches.length === 1
        && r.results.a.attaches[0].kind === 'variables' && r.results.a.attaches[0].fields[0] === 'regfield'
        && r.results.a.attaches[0].values.length === 4
        && r.results.a.counts.macros === 1 && r.results.a.macros.length === 1
        && r.results.a.macros[0].name === 'setZero' && r.results.a.macros[0].parameters[0] === 'target'
        && r.results.a.counts.defines === 2 && r.results.a.defines.length === 2
        && r.results.a.defines.some((entry) => entry.name === 'ZERO' && entry.value === '0x00' && entry.flag === false),
      lesson: 'A SLEIGH source is read as declarations rather than compiled, so each kind is counted where it was written - and endianness and alignment come back as objects rather than scalars, because every declaration carries the @if conditions in force where it was written and one file can declare a different endianness under a different guard. Then spaces, registers, tokens, context fields, pcodeops, attaches, macros and @defines as lists. The reader is lexical on purpose - it answers for a file that does not compile and for one that is an @include fragment of a larger language, both of which a compiler would simply refuse. x86 shows why that matters: its top-level slaspec declares nothing at all and is 21 includes, and the file that does declare the tokens is 551 KB, which is larger than this reader may read at a 4 MB policy.',
    },
    {
      family: 'specs', tool: 'artifact.ghidraProcessorSpec', workspace: 'temp', fixture: pspecFixture,
      plan: one('artifact.ghidraProcessorSpec', { path: 'x86-64.pspec' }),
      expect: (r) => r.results.a.supported === true && r.results.a.programCounter === 'RIP'
        && r.results.a.counts.registers === 201 && r.results.a.registers.length === 201
        && r.results.a.memoryBlocks.length === 0 && r.results.a.counts.memoryBlocks === 0
        && r.results.a.properties.length === 3 && r.results.a.counts.properties === 3
        && r.results.a.properties.every((entry) => typeof entry.key === 'string' && typeof entry.value === 'string')
        && r.results.a.contextFields.some((field) => field.name === 'addrsize' && field.value === 2)
        && r.results.a.limitations.length === 1,
      lesson: 'A processor spec is where the facts a disassembler needs before it can read a single byte are written down: which register is the program counter, what the context fields start at, and 201 named registers with their groups. The context default this reader reports is the same addrsize=2 that an x86-64 decode has to be given by hand - so the spec and the decoder agree on paper, and the exercise that reads both is what makes that checkable. memoryBlocks is empty here and that is a fact about x86-64 rather than a gap: a spec that declared memory would be describing a device.',
    },
    {
      family: 'specs', tool: 'artifact.ghidraCompilerSpec', workspace: 'temp', fixture: cspecFixture,
      plan: one('artifact.ghidraCompilerSpec', { path: 'x86-64-win.cspec' }),
      expect: (r) => r.results.a.supported === true
        && r.results.a.callFixups.length === 3
        && r.results.a.callFixups.every((entry) => entry.kind === 'callfixup' && typeof entry.name === 'string')
        && r.results.a.callFixups.some((entry) => entry.name === 'alloca_probe' && entry.targets.length === 5)
        && r.results.a.callFixups.some((entry) => entry.name === 'guard_dispatch_icall')
        && r.results.a.callFixups.some((entry) => entry.name === 'security_check_cookie'),
      lesson: 'A compiler spec declares the call fixups a decompiler must apply, and the Windows x86-64 spec names three: the stack probe, the control-flow-guard dispatch, and the security cookie check. Each lists the symbols it applies to - alloca_probe covers five, because the same probe ships under five names across compiler versions. These matter more than their obscurity suggests: a decompilation that did not elide a stack probe would show it as a real call in every function that allocates, and the reader that can list them is what makes checking that possible.',
    },
    {
      family: 'specs', tool: 'artifact.sleighCompiled', workspace: 'temp', fixture: compiledFixture,
      plan: one('artifact.sleighCompiled', { path: 'x86-64.sla' }),
      expect: (r) => r.results.a.supported === true && r.results.a.path === 'x86-64.sla'
        && r.results.a.format.magic === 'sla' && r.results.a.format.version === 4
        && r.results.a.sleigh.bigEndian === false && r.results.a.sleigh.defaultSpace === 'ram'
        && r.results.a.counts.constructors === 5791 && r.results.a.counts.registers === 1440
        && r.results.a.counts.subtables === 242 && r.results.a.counts.sourceFiles === 24
        && r.results.a.counts.inflatedBytes === 4475469
        && r.results.a.elementCounts.some((entry) => entry.element === 'const_real')
        && r.results.a.limitations.length === 2,
      lesson: 'The compiled table reports what it contains rather than what it can do: 5791 constructors, 1440 registers, 242 subtables, 24 source files and the 4475469 bytes it inflates to. Those numbers are the table\u2019s identity in a way its digest is not - a digest says two files differ, these say how. The element counts are an array of pairs rather than an object keyed by element name, because a real table contains an element called `constructor` and an object with that key is refused by the kernel\u2019s own canonicaliser.',
    },
    {
      family: 'specs', tool: 'artifact.compareSleighSource', workspace: 'temp', fixture: comparisonFixture,
      plan: one('artifact.compareSleighSource', { compiled: 'x86-64.sla', source: 'x86.slaspec' }),
      expect: (r) => r.results.a.supported === true && r.results.a.reason === null
        && r.results.a.counts.disagreements === 0 && r.results.a.disagreements.length === 0
        && r.results.a.counts.unstated === 5 && r.results.a.unstated.length === 5
        && r.results.a.counts.sourceFilesInTable === 24
        && r.results.a.unstated.some((entry) => entry.field === 'endian' && entry.tableValue === 'little' && entry.sourceValue === null)
        && r.results.a.limitations.some((note) => note.includes('@includes')),
      lesson: 'Comparing a compiled table against its own source separates three outcomes rather than two: agreements, disagreements, and facts the table states that the source file does not. All five comparable fields land in that third category for x86, because the top-level slaspec declares none of them and the compiler got them from 21 includes this reader deliberately does not follow. Saying "unstated" rather than "mismatch" is the whole value: a disagreement would be a real finding about a table built from different source, and reporting one here would cry wolf on every language with an include.',
    },
    {
      family: 'specs', tool: 'artifact.plist', workspace: 'temp', fixture: plistFixture,
      plan: one('artifact.plist', { path: 'Info.plist' }),
      expect: (r) => r.results.a.supported === true && r.results.a.format === 'xml'
        && r.results.a.root.CFBundleIdentifier === 'com.example.concord'
        && r.results.a.root.CFBundleVersion === '1.0.3'
        && r.results.a.root.NSAppTransportSecurity.nested === 'dict'
        && r.results.a.root.CFBundleURLTypes.nested === 'array'
        && r.results.a.limitations.length === 1,
      lesson: 'An XML property list is read as its top-level keys, with a nested container reported as a marker naming its kind rather than being walked. That bound is stated in limitations instead of being silent, which matters because a plist is where an application declares the things a reviewer cares about - its identifier, its minimum system, its URL schemes, whether it allows arbitrary loads - and a reader that quietly flattened a nested dictionary would make a setting look top-level when it is not.',
    },
    {
      family: 'specs', tool: 'artifact.jsSemantics', workspace: 'temp', fixture: jsFixture,
      plan: one('artifact.jsSemantics', { path: 'semantics.mjs' }),
      expect: (r) => r.results.a.supported === true
        && r.results.a.counts.eval === 1 && r.results.a['counts']['function-constructor'] === 1
        && r.results.a.findings.length === 2
        && r.results.a.findings.some((entry) => entry.construct === 'eval' && entry.line === 10)
        && r.results.a.limitations.length === 2
        && r.results.a.limitations.some((note) => note.includes('lexical')),
      lesson: 'artifact.jsSemantics names the constructs that turn data into code - eval and the Function constructor - with the line each was found on, and counts them by kind. It says in its own limitations that it is a lexical scan rather than a parse, which is the honest form of a scanner: a construct assembled at runtime from string pieces is invisible to it, and a tool that did not say so would be read as a clean bill of health.',
    },
    {
      family: 'specs', tool: 'artifact.reconstructionCoverage',
      plan: one('artifact.reconstructionCoverage', {
        boundaryId: 'managed-to-native',
        obligations: [
          { id: 'o1', status: 'verified', boundaryId: 'managed-to-native' },
          { id: 'o2', status: 'open', boundaryId: 'managed-to-native' },
          { id: 'o3', status: 'verified', boundaryId: 'somewhere-else' },
        ],
      }),
      expect: (r) => r.results.a.boundaryId === 'managed-to-native'
        && r.results.a.status === 'uncovered' && r.results.a.reasons.length === 2
        && r.results.a.probes.length === 2
        && r.results.a.reasons.some((note) => note.includes('o1') && note.includes('verified rather than closed'))
        && r.results.a.probes.some((note) => note.includes('replay-authority'))
        && r.results.a.limitations.some((note) => note.includes('replay')),
      lesson: 'Coverage of a boundary is answered against the obligations scoped to that boundary and nothing else, so an obligation closed somewhere else does not help. The distinction it insists on is between verified and closed: an obligation someone marked verified is not covered, because covered means closed by a replay observation, and the reader says which of the two it saw. It also answers with probes - the specific thing that would close each gap - which is the difference between a score and a next step.',
    },
    ...(ASSEMBLY ? [
      {
        family: 'specs', tool: 'artifact.managed', workspace: 'temp', fixture: assemblyFixture,
        plan: one('artifact.managed', { path: 'assembly.dll' }),
        expect: (r) => r.results.a.supported === true
          && r.results.a.assembly.name === 'System.Linq' && r.results.a.assembly.version === '4.0.0.0'
          && r.results.a.assembly.culture === null
          && Number.isInteger(r.results.a.assembly.hashAlgorithm)
          && r.results.a.tables.length >= 5
          && r.results.a.tables.some((entry) => entry.name === 'Module' && entry.rows === 1)
          && r.results.a.tables.every((entry) => Number.isInteger(entry.table) && Number.isInteger(entry.rows)),
        lesson: 'A managed assembly is read as its metadata tables plus the assembly row that names it, so the identity a runtime would bind against - name, version, culture, hash algorithm - is reported as the file states it rather than as the filename suggests. Exactly one Module row is not a quirk: the format allows one per file, so a reader finding two is reading something that is not an assembly. The tables are named as well as numbered because the numbers are the format and the names are this reader\u2019s interpretation of them.',
      },
      {
        family: 'specs', tool: 'artifact.managedMembers', workspace: 'temp', fixture: assemblyFixture,
        // No limit field: the declared schema is {path, type} and a plan carrying anything else is
        // refused SCHEMA_MISMATCH at compile. Found the hard way - a direct call to execute skips
        // schema validation entirely, so verifying an exercise that way cannot catch an input the
        // plan would reject.
        plan: one('artifact.managedMembers', { path: 'assembly.dll' }),
        expect: (r) => r.results.a.supported === true
          && r.results.a.types.length === 1 && r.results.a.types[0].fullName === '<Module>'
          && r.results.a.types[0].nested === false && r.results.a.types[0].enclosing === null
          && r.results.a.members.length === 0
          && r.results.a.limitations.some((note) => note.includes('blob heap')),
        lesson: 'This assembly has one type and no members, and that is the finding rather than an empty result: System.Linq in this framework is a type-forwarding facade, so every name it appears to provide is defined somewhere else and the file itself declares only the synthetic <Module> type. A reader that reported nothing for a facade and nothing for an empty assembly would make a dependency that resolves elsewhere indistinguishable from one that resolves nowhere. The reader also states that member signatures live in the blob heap and are not decoded, so overloads cannot be told apart by signature here.',
      },
      {
        family: 'specs', tool: 'artifact.managedGraph', workspace: 'temp', fixture: assemblyFixture,
        plan: one('artifact.managedGraph', { path: 'assembly.dll' }),
        expect: (r) => r.results.a.supported === true
          && r.results.a.edges.length === 0 && r.results.a.roots.length === 1
          && r.results.a.roots[0] === '<Module>',
        lesson: 'A type graph over a facade has one root and no edges, which is the shape of an assembly that inherits from nothing it contains. Roots and edges are separate keys for this reason: a graph reported only as edges would be empty here, and empty reads as "nothing found" rather than as "one type, related to nothing".',
      },
      {
        family: 'specs', tool: 'artifact.managedNativeBoundaries', workspace: 'temp', fixture: assemblyFixture,
        plan: one('artifact.managedNativeBoundaries', { path: 'assembly.dll' }),
        expect: (r) => r.results.a.supported === true
          && r.results.a.boundaries.length === 0 && r.results.a.modules.length === 0
          && r.results.a.limitations.some((note) => note.includes('P/Invoke')),
        lesson: 'An assembly that declares no P/Invoke crosses no native boundary, and the reader says so in its limitations rather than returning two empty lists and leaving the caller to infer it. The two lists are the boundary methods and the native modules they name, and both being empty is a positive statement about this file: everything it does, it does inside the runtime.',
      },
    ] : []),
  ];
}
