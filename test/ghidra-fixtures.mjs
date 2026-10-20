import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { deflateSync } from 'node:zlib';

/**
 * Ghidra specification fixtures, small enough to read and real enough to exercise the main path.
 *
 * The readers in src/ghidra.mjs all have a not-this-format branch, so a fixture of the wrong shape
 * would check nothing: every tool would report `supported: false` and the test would pass without
 * having decoded anything. These files are therefore valid against the shipped RelaxNG schemas in
 * `Ghidra/Framework/SoftwareModeling/data/languages/`, and the `.sla` is a real compressed
 * PackedFormat stream rather than a stub.
 *
 * The encoder below is the interesting part. src/ghidra.mjs only decodes, so writing the bytes here
 * from the format description in `marshal.hh` is an independent implementation: if the two
 * disagreed about the id extension bit or the 7-bits-per-byte payload, these fixtures would not
 * decode. That makes the fixture a round-trip check and not just an input.
 */

// Element and attribute ids from Ghidra/Features/Decompiler/src/decompile/cpp/slaformat.cc.
const ELEM = { sleigh: 33, spaces: 34, sourcefiles: 35, sourcefile: 36, space: 37, space_unique: 46,
  symbol_table: 38, scope: 22, varnode_sym_head: 24, varnode_sym: 23, userop_head: 26,
  subtable_sym_head: 72, subtable_sym: 71, operand_sym_head: 14, operand_sym: 13,
  constructor: 20, oper: 15, print: 8, opprint: 17, decision: 16, pair: 9, instruct_pat: 18,
  pat_block: 7, mask_word: 6, operand_exp: 12, tokenfield: 27,
  construct_tpl: 21, op_tpl: 5, varnode_tpl: 2, handle_tpl: 30, null_: 11,
  const_real: 1, const_spaceid: 3, const_handle: 4 };
const ATTR = { val: 2, id: 3, space: 4, s: 5, off: 6, code: 7, mask: 8, index: 9, nonzero: 10, piece: 11, name: 12,
  scope: 13, startbit: 14, size: 15, table: 16, ct: 17, minlen: 18, base: 19, number: 20,
  context: 21, parent: 22, line: 24, source: 25, length: 26, first: 27, shift: 29, endbit: 30,
  signbit: 31, endbyte: 32, startbyte: 33, version: 34, bigendian: 35, align: 36, uniqbase: 37,
  defaultspace: 41, delay: 42, wordsize: 43, physical: 44, scopesize: 45, symbolsize: 46,
  numct: 53 };

/** 7 bits of payload per byte, most significant first, with the unused bit always set. */
const payload = (value) => {
  const out = [];
  let remaining = BigInt(value);
  while (remaining > 0n) { out.unshift(0x80 | Number(remaining & 0x7fn)); remaining >>= 7n; }
  return out;
};
// An id up to 0x1f rides in the header; beyond that the header carries the high bits and sets the
// extend bit, and one more byte carries the low seven.
const header = (kind, id) => (id <= 0x1f ? [kind | id] : [kind | 0x20 | (id >> 7), 0x80 | (id & 0x7f)]);
const open = (id) => header(0x40, id);
const close = (id) => header(0x80, id);
const attribute = (id, type, body = []) => [...header(0xc0, id), (type << 4) | body.length, ...body];

const attrBool = (id, value) => [...header(0xc0, id), (1 << 4) | (value ? 1 : 0)];
// A negative integer has its own type code and is stored negated — marshal.hh's
// TYPECODE_SIGNEDINT_NEGATIVE. Encoding one as a positive with an empty payload writes zero
// instead, which is how `firstWhitespace: -1` silently became 0 and rendered an empty mnemonic.
const attrSigned = (id, value) => (value < 0 ? attribute(id, 3, payload(-value)) : attribute(id, 2, payload(value)));
const attrUnsigned = (id, value) => attribute(id, 4, payload(value));
// An address space travels as its index under its own type code, which is how a decoder knows to
// look the value up in the space table rather than treat it as a number.
const attrSpace = (id, index) => attribute(id, 5, payload(index));
const attrString = (id, value) => {
  const bytes = [...Buffer.from(value, 'utf8')];
  return [...attribute(id, 7, payload(bytes.length)), ...bytes];
};

/** One address space, written the way SleighBase::encodeSlaSpace does. */
const space = (element, { name, index, size, delay = 0, physical = true }) => [
  ...open(element), ...attrString(ATTR.name, name), ...attrSigned(ATTR.index, index),
  ...attrBool(ATTR.bigendian, false), ...attrSigned(ATTR.delay, delay),
  ...attrSigned(ATTR.size, size), ...attrBool(ATTR.physical, physical), ...close(element),
];

/**
 * A compiled table carrying exactly the facts artifact.sleighCompiled reports.
 *
 * The attribute order follows SleighBase::encode, because a decoder that depended on order would
 * pass a hand-ordered fixture and fail on a real file; the shipped 137 files are the check that it
 * does not, and this one is the check that the smallest valid table also decodes.
 */
export function buildSla({ bigEndian = false, alignment = 1, defaultSpace = 'ram' } = {}) {
  const bytes = [
    ...open(ELEM.sleigh),
    ...attrSigned(ATTR.version, 4), ...attrBool(ATTR.bigendian, bigEndian),
    ...attrSigned(ATTR.align, alignment), ...attrUnsigned(ATTR.uniqbase, 0x1000),
    ...open(ELEM.sourcefiles),
    ...open(ELEM.sourcefile), ...attrString(ATTR.name, 'toy.slaspec'), ...attrSigned(ATTR.index, 0), ...close(ELEM.sourcefile),
    ...close(ELEM.sourcefiles),
    ...open(ELEM.spaces), ...attrString(ATTR.defaultspace, defaultSpace),
    ...space(ELEM.space_unique, { name: 'unique', index: 1, size: 4 }),
    ...space(ELEM.space, { name: defaultSpace, index: 2, size: 4, delay: 1 }),
    ...space(ELEM.space, { name: 'register', index: 3, size: 4 }),
    ...close(ELEM.spaces),
    ...open(ELEM.symbol_table), ...attrSigned(ATTR.scope, 0),
    ...open(ELEM.scope), ...attrSigned(ATTR.id, 0),
    // Every register the .slaspec declares, because artifact.compareSleighSource compares the two
    // and an inconsistent pair of fixtures would make the agreeing case not actually agree. The
    // first version of this fixture listed only r0 and r1, and the comparison correctly reported
    // PC, SP and SWI_VECTOR as declared in source but missing from the table.
    ...['r0', 'r1', 'PC', 'SP', 'SWI_VECTOR'].flatMap((name, index) => [
      ...open(ELEM.varnode_sym_head), ...attrString(ATTR.name, name), ...attrSigned(ATTR.id, index + 1),
      ...attrSigned(ATTR.scope, 0), ...close(ELEM.varnode_sym_head),
    ]),
    ...open(ELEM.userop_head), ...attrString(ATTR.name, 'toyHalt'), ...attrSigned(ATTR.id, 6), ...close(ELEM.userop_head),
    ...open(ELEM.subtable_sym_head), ...attrString(ATTR.name, 'instruction'), ...attrSigned(ATTR.id, 7), ...close(ELEM.subtable_sym_head),
    ...close(ELEM.scope),
    ...close(ELEM.symbol_table),
    ...close(ELEM.sleigh),
  ];
  // "sla" plus the one byte format version, then a zlib stream — not gzip and not raw deflate.
  return Buffer.concat([Buffer.from('sla'), Buffer.from([4]), deflateSync(Buffer.from(bytes))]);
}

/**
 * A table that can actually be decoded, not just described.
 *
 * `buildSla` above carries the facts a reader reports — endianness, spaces, symbol names — but no
 * constructors and no decision tree, so a decoder given it would correctly find nothing to match.
 * This one is a complete miniature language, which is what it takes to exercise the engine without
 * shipping an 876 MB distribution:
 *
 *   op=0x00  ->  halt            a mnemonic with no operands
 *   op=0x01  ->  inc             a second leaf, so the decision tree must discriminate
 *   op=0x02  ->  ld 0xNN         one immediate operand in a second byte, so length is 2
 *
 * The root decision reads two bits rather than scanning a list, which exercises the bit-indexed
 * descent in `DecisionNode::resolve`; the fourth branch is deliberately empty so an unmatched
 * opcode is reported rather than mistaken for the nearest neighbour.
 *
 * Bit numbering here is Ghidra's: bit 0 is the most significant bit of the first instruction byte,
 * so the low two bits of the opcode are bits 6 and 7. Getting that backwards is the easiest way to
 * write a fixture that passes against a decoder which is wrong in the same direction, which is why
 * the engine is also checked against real shipped tables.
 */
const INSTRUCTION_SYMBOL = 0;
const OPERAND_SYMBOL = 1;
// Space indices. 0 is the constant space, which sleighbase.cc re-inserts rather than serialising.
const CONST_SPACE = 0;
const UNIQUE_SPACE = 1;
const RAM_SPACE = 2;
const REGISTER_SPACE = 3;
const R0 = 0;   // register space offset, 4 bytes wide
const OP_COPY = 1;
const OP_INT_ADD = 19;

// A mask/value pair over the first instruction byte, already normalized the way PatternBlock
// writes it: the leading mask byte is nonzero, so the offset stays 0.
const opcodePattern = (opcode) => [
  ...open(ELEM.instruct_pat),
  ...open(ELEM.pat_block), ...attrSigned(ATTR.off, 0), ...attrSigned(ATTR.nonzero, 1),
  ...open(ELEM.mask_word), ...attrUnsigned(ATTR.mask, 0xff000000), ...attrUnsigned(ATTR.val, opcode << 24), ...close(ELEM.mask_word),
  ...close(ELEM.pat_block),
  ...close(ELEM.instruct_pat),
];
const terminal = (number, pairs) => [
  ...open(ELEM.decision), ...attrSigned(ATTR.number, number), ...attrBool(ATTR.context, false),
  ...attrSigned(ATTR.startbit, 0), ...attrSigned(ATTR.size, 0),
  ...pairs.flatMap(({ id, opcode }) => [
    ...open(ELEM.pair), ...attrSigned(ATTR.id, id), ...opcodePattern(opcode), ...close(ELEM.pair),
  ]),
  ...close(ELEM.decision),
];
// --- semantic templates ------------------------------------------------------------------------
// A ConstTpl is one slot of a varnode template. `real` is a literal, `handle` names an operand's
// resolved handle and which part of it to take, and `spaceid` names an address space.
const constReal = (value) => [...open(ELEM.const_real), ...attrUnsigned(ATTR.val, value), ...close(ELEM.const_real)];
const constSpaceId = (index) => [...open(ELEM.const_spaceid), ...attrSpace(ATTR.space, index), ...close(ELEM.const_spaceid)];
const constHandle = (index, select) => [
  ...open(ELEM.const_handle), ...attrSigned(ATTR.val, index), ...attrSigned(ATTR.s, select), ...close(ELEM.const_handle),
];
const varnodeTpl = (space, offset, size) => [...open(ELEM.varnode_tpl), ...space, ...offset, ...size, ...close(ELEM.varnode_tpl)];
/** A register varnode: a literal space, offset and size. */
const regTpl = (spaceIndex, offset, size) => varnodeTpl(constSpaceId(spaceIndex), constReal(offset), constReal(size));
/** The value an operand exports, taken from its handle's offset. */
const operandValueTpl = (index, size) => varnodeTpl(constSpaceId(CONST_SPACE), constHandle(index, 1), constReal(size));
const opTpl = (code, output, inputs) => [
  ...open(ELEM.op_tpl), ...attrSigned(ATTR.code, code),
  ...(output ?? [...open(ELEM.null_), ...close(ELEM.null_)]),
  ...inputs.flat(),
  ...close(ELEM.op_tpl),
];
const constructTpl = (ops, { delay = 0 } = {}) => [
  ...open(ELEM.construct_tpl),
  ...(delay ? attrSigned(ATTR.delay, delay) : []),
  ...open(ELEM.null_), ...close(ELEM.null_), // exports nothing
  ...ops.flat(),
  ...close(ELEM.construct_tpl),
];

const constructor = (pieces, { length, firstWhitespace, operands = [], template = null }) => [
  ...open(ELEM.constructor), ...attrUnsigned(ATTR.parent, INSTRUCTION_SYMBOL),
  ...attrSigned(ATTR.first, firstWhitespace), ...attrSigned(ATTR.length, length),
  ...attrSigned(ATTR.source, 0), ...attrSigned(ATTR.line, 1),
  ...operands.flatMap((id) => [...open(ELEM.oper), ...attrUnsigned(ATTR.id, id), ...close(ELEM.oper)]),
  ...pieces.flatMap((piece) => (typeof piece === 'string'
    ? [...open(ELEM.print), ...attrString(ATTR.piece, piece), ...close(ELEM.print)]
    : [...open(ELEM.opprint), ...attrSigned(ATTR.id, piece.operand), ...close(ELEM.opprint)])),
  ...(template ?? []),
  ...close(ELEM.constructor),
];

export function buildDecodableSla() {
  const bytes = [
    ...open(ELEM.sleigh),
    ...attrSigned(ATTR.version, 4), ...attrBool(ATTR.bigendian, false),
    ...attrSigned(ATTR.align, 1), ...attrUnsigned(ATTR.uniqbase, 0x1000),
    ...open(ELEM.sourcefiles),
    ...open(ELEM.sourcefile), ...attrString(ATTR.name, 'toy.slaspec'), ...attrSigned(ATTR.index, 0), ...close(ELEM.sourcefile),
    ...close(ELEM.sourcefiles),
    ...open(ELEM.spaces), ...attrString(ATTR.defaultspace, 'ram'),
    ...space(ELEM.space_unique, { name: 'unique', index: UNIQUE_SPACE, size: 4 }),
    ...space(ELEM.space, { name: 'ram', index: RAM_SPACE, size: 4, delay: 1 }),
    ...space(ELEM.space, { name: 'register', index: REGISTER_SPACE, size: 4 }),
    ...close(ELEM.spaces),

    ...open(ELEM.symbol_table), ...attrSigned(ATTR.scopesize, 1), ...attrSigned(ATTR.symbolsize, 2),
    ...open(ELEM.scope), ...attrUnsigned(ATTR.id, 0), ...attrUnsigned(ATTR.parent, 0), ...close(ELEM.scope),
    // Shells first: a constructor names its operands by id, so both symbols must exist before any
    // content is read. SymbolTable::decode does the same in the same order.
    ...open(ELEM.subtable_sym_head), ...attrString(ATTR.name, 'instruction'),
    ...attrUnsigned(ATTR.id, INSTRUCTION_SYMBOL), ...attrSigned(ATTR.scope, 0), ...close(ELEM.subtable_sym_head),
    ...open(ELEM.operand_sym_head), ...attrString(ATTR.name, 'imm8'),
    ...attrUnsigned(ATTR.id, OPERAND_SYMBOL), ...attrSigned(ATTR.scope, 0), ...close(ELEM.operand_sym_head),

    // The immediate: one byte at constructor-relative offset 1, read as an unsigned 8-bit token.
    // The local expression names the operand's own slot; the defining expression is what produces
    // its value, which is the field in the second byte.
    ...open(ELEM.operand_sym), ...attrUnsigned(ATTR.id, OPERAND_SYMBOL),
    ...attrSigned(ATTR.index, 0), ...attrSigned(ATTR.off, 1), ...attrSigned(ATTR.base, -1),
    ...attrSigned(ATTR.minlen, 1),
    ...open(ELEM.operand_exp), ...attrSigned(ATTR.index, 0),
    ...attrUnsigned(ATTR.table, INSTRUCTION_SYMBOL), ...attrUnsigned(ATTR.ct, 2), ...close(ELEM.operand_exp),
    ...open(ELEM.tokenfield), ...attrBool(ATTR.bigendian, false), ...attrBool(ATTR.signbit, false),
    ...attrSigned(ATTR.startbit, 0), ...attrSigned(ATTR.endbit, 7),
    ...attrSigned(ATTR.startbyte, 0), ...attrSigned(ATTR.endbyte, 0), ...attrSigned(ATTR.shift, 0),
    ...close(ELEM.tokenfield),
    ...close(ELEM.operand_sym),

    ...open(ELEM.subtable_sym), ...attrUnsigned(ATTR.id, INSTRUCTION_SYMBOL), ...attrSigned(ATTR.numct, 3),
    // `halt` has no template at all, which is how a constructor that declares no semantics
    // appears: the lifter must say so rather than report an empty effect.
    ...constructor(['halt'], { length: 1, firstWhitespace: -1 }),
    // `inc` is r0 = r0 + 1, with a delay slot so the directive and the byte count are exercised.
    ...constructor(['inc'], { length: 1, firstWhitespace: -1,
      template: constructTpl([
        opTpl(OP_INT_ADD, regTpl(REGISTER_SPACE, R0, 4), [
          regTpl(REGISTER_SPACE, R0, 4),
          varnodeTpl(constSpaceId(CONST_SPACE), constReal(1), constReal(4)),
        ]),
      ], { delay: 1 }) }),
    // "ld", then a whitespace piece, then the operand slot. firstWhitespace is the index of that
    // separator, which is how Ghidra splits a mnemonic from its body. Its semantics copy the
    // operand's exported value into r0, which only works if the operand's handle resolved.
    ...constructor(['ld', ' ', { operand: 0 }], { length: 1, firstWhitespace: 1, operands: [OPERAND_SYMBOL],
      template: constructTpl([
        opTpl(OP_COPY, regTpl(REGISTER_SPACE, R0, 4), [operandValueTpl(0, 4)]),
      ]) }),
    // Two bits at bits 6 and 7 — the low two bits of the opcode byte — select the branch.
    ...open(ELEM.decision), ...attrSigned(ATTR.number, 0), ...attrBool(ATTR.context, false),
    ...attrSigned(ATTR.startbit, 6), ...attrSigned(ATTR.size, 2),
    ...terminal(1, [{ id: 0, opcode: 0x00 }]),
    ...terminal(2, [{ id: 1, opcode: 0x01 }]),
    ...terminal(3, [{ id: 2, opcode: 0x02 }]),
    ...terminal(4, []),
    ...close(ELEM.decision),
    ...close(ELEM.subtable_sym),
    ...close(ELEM.symbol_table),
    ...close(ELEM.sleigh),
  ];
  return Buffer.concat([Buffer.from('sla'), Buffer.from([4]), deflateSync(Buffer.from(bytes))]);
}

export const LDEFS = `<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="Toy" endian="little" size="32" variant="default" version="1.0"
            slafile="toy.sla" processorspec="toy.pspec" id="Toy:LE:32:default">
    <description>A toy processor used only to exercise the readers</description>
    <truncate_space space="ram" size="4"/>
    <compiler name="default" spec="toy.cspec" id="default"/>
    <compiler name="Visual Studio" spec="toywin.cspec" id="windows"/>
    <external_name tool="gnu" name="toy"/>
  </language>
  <!-- A commented language must not be counted: CR16.ldefs really does this, and counting it is
       what made a grep of the corpus report 190 languages where a parser reports 189. -->
  <!--
  <language processor="Toy" endian="big" size="16" variant="commented" version="1.0"
            slafile="nope.sla" processorspec="nope.pspec" id="Toy:BE:16:commented">
    <description>Never parsed</description>
    <compiler name="default" spec="nope.cspec" id="default"/>
  </language>
  -->
  <language processor="Toy" endian="big" instructionEndian="little" size="32" variant="mixed"
            version="1.0" slafile="toybe.sla" processorspec="toy.pspec" id="Toy:LEBE:32:mixed">
    <description>Big endian data with little endian instructions</description>
    <compiler name="default" spec="toy.cspec" id="default"/>
  </language>
</language_definitions>
`;

export const PSPEC = `<?xml version="1.0" encoding="UTF-8"?>
<processor_spec>
  <properties>
    <property key="useropLibs" value="toy"/>
  </properties>
  <programcounter register="PC"/>
  <incidentalcopy>
    <register name="ST0"/>
  </incidentalcopy>
  <volatile outputop="write_volatile" inputop="read_volatile">
    <range space="SFR" first="0x80" last="0xFF"/>
  </volatile>
  <context_data>
    <context_set space="ram">
      <set name="TMode" val="0" description="0 for wide decode"/>
    </context_set>
    <tracked_set space="ram">
      <set name="spsr" val="0"/>
    </tracked_set>
  </context_data>
  <register_data>
    <register name="r0" group="general" vector_lane_sizes="1,2,4"/>
    <register name="oldname" rename="newname"/>
  </register_data>
  <default_symbols>
    <symbol name="Reset" address="ram:0x0" entry="true" type="code_ptr"/>
    <symbol name="P0" address="SFR:80"/>
  </default_symbols>
  <default_memory_blocks>
    <memory_block name="IO" start_address="io:0" length="0xFF" initialized="false"/>
  </default_memory_blocks>
</processor_spec>
`;

export const CSPEC = `<?xml version="1.0" encoding="UTF-8"?>
<compiler_spec>
  <data_organization>
    <machine_alignment value="2"/>
    <default_alignment value="1"/>
    <pointer_size value="4"/>
    <wchar_size value="2"/>
    <integer_size value="4"/>
    <long_size value="4"/>
    <double_size value="8"/>
    <char_type signed="false"/>
    <size_alignment_map>
      <entry size="1" alignment="1"/>
      <entry size="4" alignment="4"/>
    </size_alignment_map>
    <bitfield_packing>
      <use_MS_convention value="1"/>
    </bitfield_packing>
  </data_organization>
  <global>
    <range space="ram"/>
    <register name="MXCSR"/>
  </global>
  <stackpointer register="SP" space="ram" growth="negative"/>
  <returnaddress>
    <varnode space="stack" offset="0" size="4"/>
  </returnaddress>
  <default_proto>
    <prototype name="__stdcall" extrapop="4" stackshift="4">
      <input>
        <pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
        <pentry minsize="5" maxsize="8"><addr space="join" piece1="r1" piece2="r0"/></pentry>
      </input>
      <output>
        <pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
      </output>
      <unaffected>
        <register name="SP"/>
      </unaffected>
      <killedbycall>
        <register name="r1"/>
      </killedbycall>
    </prototype>
  </default_proto>
  <prototype name="__fastcall" extrapop="0" stackshift="4" strategy="register">
    <input>
      <pentry minsize="1" maxsize="4"><register name="r1"/></pentry>
    </input>
    <output>
      <pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
    </output>
  </prototype>
  <callfixup name="alloca_probe">
    <target name="_alloca_probe"/>
    <pcode>
      <body><![CDATA[ SP = SP - r0; ]]></body>
    </pcode>
  </callfixup>
  <callotherfixup targetop="toyHalt">
    <pcode>
      <body><![CDATA[ return; ]]></body>
    </pcode>
  </callotherfixup>
</compiler_spec>
`;

// No XML declaration, exactly as all 29 shipped .opinion files are written.
export const OPINION = `<opinions>
  <constraint loader="Portable Executable (PE)">
    <constraint compilerSpecID="windows">
      <constraint primary="332" processor="Toy" endian="little" size="32" variant="default"/>
      <constraint primary="400" secondary="0b0000.01.." processor="Toy" endian="little" size="32" variant="default"/>
    </constraint>
    <constraint compilerSpecID="default">
      <constraint primary="333" secondary="clang" processor="Toy" endian="little" size="32" variant="default"/>
      <constraint primary="334" processor="Toy" endian="big" size="64" variant="absent"/>
    </constraint>
  </constraint>
</opinions>
`;

/**
 * SLEIGH source for the same toy processor.
 *
 * Deliberately exercises the three things that were wrong in the first implementation: a `;` inside
 * a constructor pattern and inside a `[ ... ]` action block, a dotted userop name, and a
 * declaration inside an `@if` block that must be reported as conditional rather than as fact.
 */
export const SLASPEC = `# A toy SLEIGH specification.
define endian=little;
define alignment=1;

define space ram     type=ram_space      size=4  default;
define space register type=register_space size=4;

define register offset=0x00 size=4 [ r0 r1 _ PC SP ];
define RAM offset=0x3ffc size=2 [ SWI_VECTOR ];

define token opbyte (8)
   op   = (0,7)
   aaa  = (5,7)
;

define context contextreg
   TMode = (0,0)
   LRset = (1,1) noflow
;

define pcodeop toyHalt;
define pcodeop toy.add.s;

@ifdef EXTENDED
define pcodeop toyExtended;
@endif

attach variables [ aaa ] [ r0 r1 ];
attach names op [ "zero" "one" ];
attach values aaa [ -1 1 2 3 4 5 6 7 ];

macro setFlags(result) {
  TMode = result;
}

REL: reloc is op [ reloc = inst_next + op; ] { export *:4 reloc; }

:halt is op=0x00 { toyHalt(); }
:add r0, REL is op=0x01 ; REL [ TMode = 0; LRset = 1; ] {
  r0 = r0 + REL;
  setFlags(r0);
}
`;

/** Write every fixture into `dir` and return the input each tool should be exercised with. */
export function writeGhidraFixtures(dir) {
  writeFileSync(path.join(dir, 'toy.ldefs'), LDEFS);
  writeFileSync(path.join(dir, 'toy.pspec'), PSPEC);
  writeFileSync(path.join(dir, 'toy.cspec'), CSPEC);
  writeFileSync(path.join(dir, 'toy.opinion'), OPINION);
  writeFileSync(path.join(dir, 'toy.slaspec'), SLASPEC);
  writeFileSync(path.join(dir, 'toy.sla'), buildSla());
  // A decodable table and some bytes written in its language, so artifact.disassemble is exercised
  // on the path that actually decodes rather than on its table-unreadable branch.
  writeFileSync(path.join(dir, 'toy-decode.sla'), buildDecodableSla());
  writeFileSync(path.join(dir, 'toy-code.bin'), Buffer.from([0x00, 0x01, 0x02, 0x42, 0x00]));
  return {
    'artifact.disassemble': { table: 'toy-decode.sla', path: 'toy-code.bin' },
    'artifact.ghidraLanguages': { path: 'toy.ldefs' },
    'artifact.ghidraProcessorSpec': { path: 'toy.pspec' },
    'artifact.ghidraCompilerSpec': { path: 'toy.cspec' },
    'artifact.ghidraLoaderOpinion': { path: 'toy.opinion' },
    'artifact.ghidraLanguageMatch': { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '332' },
    'artifact.sleighSource': { path: 'toy.slaspec' },
    'artifact.sleighCompiled': { path: 'toy.sla' },
    'artifact.compareSleighSource': { compiled: 'toy.sla', source: 'toy.slaspec' },
  };
}
