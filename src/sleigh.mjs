import { createHash } from 'node:crypto';
import { openSla, slaEvents } from './ghidra.mjs';
import { HarnessError } from './value.mjs';
import { readWorkspaceFile } from './workspace-fs.mjs';

/**
 * A SLEIGH instruction decoder, in Node, with no dependency of any kind.
 *
 * This is the part of Ghidra that turns bytes into instructions, and it is the part worth porting:
 * roughly 12,000 lines of the decompiler's C++ against ~157,000 for the decompiler proper. It is
 * also the part that pays for itself, because it is table-driven. One engine plus the 137 compiled
 * tables Concord already reads is instruction decode for 189 language variants across 59 processor
 * families — not 59 hand-written backends.
 *
 * It stops at the instruction. A decoded instruction here is its mnemonic, its operand text, its
 * length and the constructors that matched; it is not lifted p-code and it is certainly not C.
 * That boundary is deliberate and is where the honest line falls: the decode tables are data that
 * can be read, while Ghidra's simplification rules are 11,000 lines of accumulated judgement that
 * cannot be shortened and do not degrade gracefully.
 *
 * Faithfulness is the whole requirement, so the algorithms below follow Ghidra's own:
 *
 *   `DecisionNode::resolve`      slghsymbol.cc:2344 — bit-indexed tree, linear scan at the leaf
 *   `PatternBlock::isInstructionMatch`  slghpattern.cc:464 — (mask & data) == val, 32 bits at a time
 *   `Sleigh::resolve`            sleigh.cc:609 — the iterative operand walk
 *   `ParserWalkerChange::calcCurrentLength`  context.cc — absolute offsets, relative lengths
 *   `TokenField::getValue`       slghpatexpress.cc — big-endian read, then byte-swap if little
 *   `Constructor::printMnemonic` slghsymbol.cc — `\n`+letter marks an operand slot
 *
 * Two facts about the format shape everything. The instruction buffer is filled with raw memory
 * bytes and never byte-swapped — `loadFill` in sleigh.cc does no swapping — so pattern matching
 * always reads the stream big-endian-wise, and a language's endianness lives entirely in token
 * field extraction. And operand offsets are absolute from the start of the instruction while
 * lengths are relative to their constructor, which is the one piece of bookkeeping that cannot be
 * simplified without breaking variable-length decode.
 *
 * Ghidra is Apache 2.0; this file is a derivative work of its decoder. See docs/ghidra-internal.md.
 */

/**
 * P-code operations, indexed by the value a template stores.
 *
 * Index 0 is unused. Five slots carry a different meaning inside a compiled table than they do in
 * the decompiler's own IR, and `semantics.hh:26-30` is why:
 *
 *   #define BUILD      CPUI_MULTIEQUAL   // 60
 *   #define DELAY_SLOT CPUI_INDIRECT     // 61
 *   #define MACROBUILD CPUI_CAST         // 64
 *   #define LABELBUILD CPUI_PTRADD       // 65
 *   #define CROSSBUILD CPUI_PTRSUB       // 66
 *
 * So in a `.sla`, opcode 60 is "build this operand's p-code here", not a phi node. Taking the
 * names from the OpCode enum instead would emit MULTIEQUAL and INDIRECT operations that no
 * instruction ever performs, and the output would look like p-code while describing nothing. The
 * directives are consumed by the builder and never appear in a result.
 */
const OPCODES = [
  null, 'COPY', 'LOAD', 'STORE', 'BRANCH', 'CBRANCH', 'BRANCHIND', 'CALL', 'CALLIND', 'CALLOTHER',
  'RETURN', 'INT_EQUAL', 'INT_NOTEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL', 'INT_LESS',
  'INT_LESSEQUAL', 'INT_ZEXT', 'INT_SEXT', 'INT_ADD', 'INT_SUB', 'INT_CARRY', 'INT_SCARRY',
  'INT_SBORROW', 'INT_2COMP', 'INT_NEGATE', 'INT_XOR', 'INT_AND', 'INT_OR', 'INT_LEFT',
  'INT_RIGHT', 'INT_SRIGHT', 'INT_MULT', 'INT_DIV', 'INT_SDIV', 'INT_REM', 'INT_SREM',
  'BOOL_NEGATE', 'BOOL_XOR', 'BOOL_AND', 'BOOL_OR', 'FLOAT_EQUAL', 'FLOAT_NOTEQUAL', 'FLOAT_LESS',
  'FLOAT_LESSEQUAL', 'UNUSED1', 'FLOAT_NAN', 'FLOAT_ADD', 'FLOAT_DIV', 'FLOAT_MULT', 'FLOAT_SUB',
  'FLOAT_NEG', 'FLOAT_ABS', 'FLOAT_SQRT', 'FLOAT_INT2FLOAT', 'FLOAT_FLOAT2FLOAT', 'FLOAT_TRUNC',
  'FLOAT_CEIL', 'FLOAT_FLOOR', 'FLOAT_ROUND',
  'BUILD', 'DELAY_SLOT', 'PIECE', 'SUBPIECE', 'MACROBUILD', 'LABELBUILD', 'CROSSBUILD',
  'SEGMENTOP', 'CPOOLREF', 'NEW', 'INSERT', 'ZPULL', 'POPCOUNT', 'LZCOUNT', 'SPULL',
];
const OP_BUILD = 60;
const OP_DELAY_SLOT = 61;
const OP_LABELBUILD = 65;
const OP_CROSSBUILD = 66;
const OP_LOAD = 2;
const OP_STORE = 3;

const MAX_INSTRUCTION_BYTES = 16; // ParserContext::buf is 16 bytes and throws past it.
const MAX_PCODE_OPS = 4096;
const MAX_CONTEXT_WORDS = 16;
const MAX_WALK_STEPS = 4096;      // A malformed table must terminate rather than recurse forever.
const MAX_OPERAND_DEPTH = 32;     // ParserWalker::breadcrumb is 32 deep.
const MAX_TREE_NODES = 4_000_000;

const fail = (code, message, detail) => { throw new HarnessError(code, message, detail); };

// 64-bit two's complement, because an immediate can be a full machine word and Number would
// silently round one. Masks stay Numbers: a PatternBlock word is 32 bits by construction.
const MASK64 = (1n << 64n) - 1n;
const toSigned = (value) => ((value & MASK64) ^ (1n << 63n)) - (1n << 63n);
const signExtend = (value, bits) => {
  if (bits <= 0 || bits >= 64) return toSigned(value);
  const sign = 1n << BigInt(bits - 1);
  const masked = value & ((1n << BigInt(bits)) - 1n);
  return (masked ^ sign) - sign;
};
const zeroExtend = (value, bits) => (bits <= 0 || bits >= 64 ? value & MASK64 : value & ((1n << BigInt(bits)) - 1n));

/**
 * Build the whole decoded tree.
 *
 * The streaming walk in ghidra.mjs is right for reporting facts about a table, but a decoder needs
 * random access to the symbol table, so here the events become nodes. The largest shipped table is
 * x86-64 at 2.23M events, which is the reason nodes are three short fields and attributes are a
 * plain object rather than a Map.
 */
function decodeTree(flat) {
  const root = { name: '#root', attributes: {}, children: [] };
  const stack = [root];
  let nodes = 0;
  for (const event of slaEvents(flat)) {
    if (event.kind === 'overflow' || event.kind === 'truncated' || event.kind === 'invalid') {
      fail('SLEIGH_TABLE', 'The compiled table ended or became invalid while being decoded', { at: event.kind });
    }
    if (event.kind === 'open') {
      if (++nodes > MAX_TREE_NODES) fail('SLEIGH_TABLE', 'The compiled table exceeds the decode node budget');
      const node = { name: event.name, attributes: {}, children: [] };
      stack[stack.length - 1].children.push(node);
      stack.push(node);
      continue;
    }
    if (event.kind === 'close') {
      if (stack.length < 2) fail('SLEIGH_TABLE', 'The compiled table closes an element that was never opened');
      stack.pop();
      continue;
    }
    stack[stack.length - 1].attributes[event.name] = event.value;
  }
  if (stack.length !== 1) fail('SLEIGH_TABLE', 'The compiled table leaves an element unclosed');
  const sleigh = root.children.find((child) => child.name === 'sleigh');
  if (!sleigh) fail('SLEIGH_TABLE', 'The compiled table has no sleigh root element');
  return sleigh;
}

const childrenNamed = (node, name) => node.children.filter((child) => child.name === name);
const childNamed = (node, name) => node.children.find((child) => child.name === name) ?? null;
const asNumber = (value, fallback = 0) => {
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && /^0x[0-9a-f]+$/.test(value)) return Number(BigInt(value));
  return fallback;
};
const asBig = (value, fallback = 0n) => {
  if (typeof value === 'number') return BigInt(value);
  if (typeof value === 'string' && /^0x[0-9a-f]+$/.test(value)) return BigInt(value);
  return fallback;
};

// ---------------------------------------------------------------------------------------------
// Pattern expressions
// ---------------------------------------------------------------------------------------------

const BINARY_EXPRESSIONS = {
  plus_exp: (l, r) => l + r,
  sub_exp: (l, r) => l - r,
  mult_exp: (l, r) => l * r,
  // Ghidra divides and shifts on int64. A zero divisor would be a malformed table, and returning
  // zero rather than throwing keeps one bad constructor from failing the whole instruction.
  div_exp: (l, r) => (r === 0n ? 0n : l / r),
  lshift_exp: (l, r) => (r < 0n || r > 63n ? 0n : l << r),
  rshift_exp: (l, r) => (r < 0n || r > 63n ? 0n : l >> r),
  and_exp: (l, r) => l & r,
  or_exp: (l, r) => l | r,
  xor_exp: (l, r) => l ^ r,
};
const UNARY_EXPRESSIONS = { minus_exp: (v) => -v, not_exp: (v) => ~v };

/** Parse an expression node into a closure-free description the evaluator walks. */
function buildExpression(node) {
  switch (node.name) {
    case 'tokenfield':
      return { kind: 'tokenfield', bigEndian: node.attributes.bigendian === true,
        signBit: node.attributes.signbit === true,
        bitStart: asNumber(node.attributes.startbit), bitEnd: asNumber(node.attributes.endbit),
        byteStart: asNumber(node.attributes.startbyte), byteEnd: asNumber(node.attributes.endbyte),
        shift: asNumber(node.attributes.shift) };
    case 'contextfield':
      return { kind: 'contextfield', signBit: node.attributes.signbit === true,
        bitStart: asNumber(node.attributes.startbit), bitEnd: asNumber(node.attributes.endbit),
        byteStart: asNumber(node.attributes.startbyte), byteEnd: asNumber(node.attributes.endbyte),
        shift: asNumber(node.attributes.shift) };
    case 'intb':
      return { kind: 'constant', value: asBig(node.attributes.val) };
    case 'operand_exp':
      return { kind: 'operand', index: asNumber(node.attributes.index),
        table: asNumber(node.attributes.table), constructor: asNumber(node.attributes.ct) };
    case 'start_exp': return { kind: 'start' };
    case 'end_exp': return { kind: 'end' };
    case 'next2_exp': return { kind: 'next2' };
    default: break;
  }
  if (Object.hasOwn(BINARY_EXPRESSIONS, node.name)) {
    const operands = node.children;
    if (operands.length < 2) fail('SLEIGH_TABLE', 'A binary pattern expression needs two operands', { element: node.name });
    return { kind: 'binary', op: node.name, left: buildExpression(operands[0]), right: buildExpression(operands[1]) };
  }
  if (Object.hasOwn(UNARY_EXPRESSIONS, node.name)) {
    const operands = node.children;
    if (!operands.length) fail('SLEIGH_TABLE', 'A unary pattern expression needs an operand', { element: node.name });
    return { kind: 'unary', op: node.name, operand: buildExpression(operands[0]) };
  }
  fail('SLEIGH_TABLE', 'Unsupported pattern expression element', { element: node.name });
  return null;
}

/** The first child that is an expression, which is how a symbol carries its pattern value. */
const EXPRESSION_ELEMENTS = new Set(['tokenfield', 'contextfield', 'intb', 'operand_exp', 'start_exp',
  'end_exp', 'next2_exp', ...Object.keys(BINARY_EXPRESSIONS), ...Object.keys(UNARY_EXPRESSIONS)]);
const firstExpression = (node) => {
  const child = node.children.find((candidate) => EXPRESSION_ELEMENTS.has(candidate.name));
  return child ? buildExpression(child) : null;
};

// ---------------------------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------------------------

function buildPatternBlock(node) {
  const words = childrenNamed(node, 'mask_word').map((word) => ({
    mask: asNumber(word.attributes.mask) >>> 0, value: asNumber(word.attributes.val) >>> 0,
  }));
  return { offset: asNumber(node.attributes.off), nonZeroSize: asNumber(node.attributes.nonzero), words };
}

function buildPattern(node) {
  if (node.name === 'instruct_pat') return { kind: 'instruction', block: buildPatternBlock(childNamed(node, 'pat_block')) };
  if (node.name === 'context_pat') return { kind: 'context', block: buildPatternBlock(childNamed(node, 'pat_block')) };
  if (node.name === 'combine_pat') {
    // A combine pattern carries a context block and an instruction block, matching
    // CombinePattern::encode; both must match.
    const parts = node.children.filter((child) => child.name === 'context_pat' || child.name === 'instruct_pat');
    return { kind: 'combine', parts: parts.map(buildPattern) };
  }
  if (node.name === 'or_pat') return { kind: 'or', options: node.children.map(buildPattern) };
  fail('SLEIGH_TABLE', 'Unsupported pattern element', { element: node.name });
  return null;
}

// ---------------------------------------------------------------------------------------------
// Semantic templates
// ---------------------------------------------------------------------------------------------

/**
 * A ConstTpl: one slot of a varnode template, which may be a literal or a reference.
 *
 * `handle` is the interesting case. It names one of the constructor's operands and which part of
 * that operand's resolved handle to take — its space, its offset, its size, or its offset shifted
 * or adjusted by a truncation amount. That indirection is why lifting needs a second pass: an
 * operand's handle is not known until its own constructor has been resolved.
 */
const CONST_SELECT = ['space', 'offset', 'size', 'offset_plus'];

function buildConstTpl(node) {
  switch (node.name) {
    case 'const_real': return { kind: 'real', value: asBig(node.attributes.val) };
    case 'const_handle': return { kind: 'handle', index: asNumber(node.attributes.val),
      select: CONST_SELECT[asNumber(node.attributes.s)] ?? 'space',
      plus: asBig(node.attributes.plus, 0n) };
    case 'const_spaceid': return { kind: 'spaceid', space: node.attributes.space ?? null };
    case 'const_relative': return { kind: 'relative', value: asBig(node.attributes.val) };
    case 'const_start': return { kind: 'start' };
    case 'const_next': return { kind: 'next' };
    case 'const_next2': return { kind: 'next2' };
    case 'const_curspace': return { kind: 'curspace' };
    case 'const_curspace_size': return { kind: 'curspace_size' };
    case 'const_flowref': return { kind: 'flowref' };
    case 'const_flowref_size': return { kind: 'flowref_size' };
    case 'const_flowdest': return { kind: 'flowdest' };
    case 'const_flowdest_size': return { kind: 'flowdest_size' };
    default:
      fail('SLEIGH_TABLE', 'Unsupported constant template element', { element: node.name });
      return null;
  }
}

/** A varnode template: space, offset and size, in that order. */
const buildVarnodeTpl = (node) => ({
  space: buildConstTpl(node.children[0]),
  offset: buildConstTpl(node.children[1]),
  size: buildConstTpl(node.children[2]),
});

/** What a constructor exports to its parent operand: seven slots, in HandleTpl::decode order. */
const buildHandleTpl = (node) => ({
  space: buildConstTpl(node.children[0]),
  size: buildConstTpl(node.children[1]),
  ptrSpace: buildConstTpl(node.children[2]),
  ptrOffset: buildConstTpl(node.children[3]),
  ptrSize: buildConstTpl(node.children[4]),
  tempSpace: buildConstTpl(node.children[5]),
  tempOffset: buildConstTpl(node.children[6]),
});

function buildOpTpl(node) {
  const code = asNumber(node.attributes.code);
  // The first child is the output, and a `null` element means there is none. The remaining
  // children are the inputs, in order.
  const [first, ...rest] = node.children;
  return {
    code, name: OPCODES[code] ?? `OP${code}`,
    output: first && first.name === 'varnode_tpl' ? buildVarnodeTpl(first) : null,
    inputs: (first && first.name === 'null' ? rest : rest).map(buildVarnodeTpl),
  };
}

const buildConstructTpl = (node) => {
  const result = node.children.find((child) => child.name === 'handle_tpl');
  return {
    delaySlot: asNumber(node.attributes.delay, 0),
    labelCount: asNumber(node.attributes.labels, 0),
    section: asNumber(node.attributes.section, -1),
    result: result ? buildHandleTpl(result) : null,
    ops: childrenNamed(node, 'op_tpl').map(buildOpTpl),
  };
};

// ---------------------------------------------------------------------------------------------
// The language model
// ---------------------------------------------------------------------------------------------

function buildDecision(node) {
  return {
    contextDecision: node.attributes.context === true,
    startBit: asNumber(node.attributes.startbit),
    bitSize: asNumber(node.attributes.size),
    pairs: childrenNamed(node, 'pair').map((pair) => ({
      constructorId: asNumber(pair.attributes.id),
      pattern: buildPattern(pair.children[0]),
    })),
    children: childrenNamed(node, 'decision').map(buildDecision),
  };
}

function buildConstructor(node) {
  const printPieces = [];
  for (const child of node.children) {
    if (child.name === 'print') printPieces.push({ literal: child.attributes.piece ?? '' });
    // An opprint is an operand slot. Ghidra encodes it as the two characters "\n"+('A'+index) in
    // the same list as the literals; carrying the index directly is the same information without
    // the sentinel, and leaves a literal free to begin with a newline.
    else if (child.name === 'opprint') printPieces.push({ operand: asNumber(child.attributes.id) });
  }
  return {
    parent: asNumber(node.attributes.parent),
    firstWhitespace: asNumber(node.attributes.first, -1),
    minimumLength: asNumber(node.attributes.length),
    sourceIndex: asNumber(node.attributes.source, -1),
    lineNumber: asNumber(node.attributes.line, -1),
    operandIds: childrenNamed(node, 'oper').map((oper) => asNumber(oper.attributes.id)),
    printPieces,
    contextOps: childrenNamed(node, 'context_op').map((op) => ({
      word: asNumber(op.attributes.i), shift: asNumber(op.attributes.shift),
      mask: asNumber(op.attributes.mask) >>> 0, expression: firstExpression(op),
    })),
    // A commit writes context forward to a later address through the context database. There is no
    // database here, so a commit is recorded and not applied: a decode of one instruction in
    // isolation cannot honour a value meant for a different address, and silently applying it to
    // the current instruction would be a different behaviour wearing the same name.
    commits: childrenNamed(node, 'commit').map((commit) => ({
      symbolId: asNumber(commit.attributes.id), word: asNumber(commit.attributes.number),
      mask: asNumber(commit.attributes.mask) >>> 0, flow: commit.attributes.flow === true,
    })),
    // The main semantic section, and any named sections. A constructor with no template has no
    // p-code at all, which is normal for one that only exports a value.
    template: (() => {
      const main = node.children.filter((child) => child.name === 'construct_tpl')
        .map(buildConstructTpl).find((tpl) => tpl.section < 0);
      return main ?? null;
    })(),
  };
}

const SYMBOL_HEADS = {
  userop_head: 'userop', epsilon_sym_head: 'epsilon', value_sym_head: 'value',
  valuemap_sym_head: 'valuemap', name_sym_head: 'name', varnode_sym_head: 'varnode',
  context_sym_head: 'context', varlist_sym_head: 'varlist', operand_sym_head: 'operand',
  start_sym_head: 'start', end_sym_head: 'end', next2_sym_head: 'next2', subtable_sym_head: 'subtable',
};

/**
 * Read the symbol table: scopes, then one shell per symbol, then the contents keyed by id.
 *
 * The two-pass shape is the format's, not a convenience — a subtable's constructors reference
 * operands whose defining symbol may be a subtable declared later, so the shells have to exist
 * before any content is read. `SymbolTable::decode` does the same for the same reason.
 */
function buildSymbols(tableNode) {
  const symbols = new Map();
  const register = (node) => {
    const kind = SYMBOL_HEADS[node.name];
    if (!kind) return;
    const id = asNumber(node.attributes.id);
    symbols.set(id, {
      id, kind,
      name: typeof node.attributes.name === 'string' ? node.attributes.name : null,
      scope: asNumber(node.attributes.scope),
    });
  };
  for (const child of tableNode.children) {
    if (child.name === 'scope') for (const head of child.children) register(head);
    else register(child);
  }

  for (const node of tableNode.children) {
    if (!node.name.endsWith('_sym') && node.name !== 'userop') continue;
    const id = asNumber(node.attributes.id);
    const symbol = symbols.get(id);
    if (!symbol) continue;
    switch (node.name) {
      case 'varnode_sym':
        symbol.space = node.attributes.space ?? null;
        symbol.offset = asBig(node.attributes.off);
        symbol.size = asNumber(node.attributes.size);
        break;
      case 'value_sym':
        symbol.expression = firstExpression(node);
        break;
      case 'context_sym':
        symbol.expression = firstExpression(node);
        symbol.varnodeId = asNumber(node.attributes.varnode);
        symbol.low = asNumber(node.attributes.low);
        symbol.high = asNumber(node.attributes.high);
        symbol.flow = node.attributes.flow === true;
        break;
      case 'valuemap_sym':
        symbol.expression = firstExpression(node);
        symbol.values = childrenNamed(node, 'valuetab').map((entry) => asBig(entry.attributes.val));
        break;
      case 'name_sym':
        symbol.expression = firstExpression(node);
        symbol.names = childrenNamed(node, 'nametab').map((entry) => (typeof entry.attributes.name === 'string' ? entry.attributes.name : null));
        break;
      case 'varlist_sym':
        symbol.expression = firstExpression(node);
        // A null element is a hole in the list: that index is not a legal value, and must stay a
        // hole rather than shifting every later register down one.
        symbol.varnodeIds = node.children
          .filter((child) => child.name === 'var' || child.name === 'null')
          .map((child) => (child.name === 'null' ? null : asNumber(child.attributes.id)));
        break;
      case 'operand_sym': {
        symbol.index = asNumber(node.attributes.index);
        symbol.relativeOffset = asNumber(node.attributes.off);
        symbol.offsetBase = asNumber(node.attributes.base, -1);
        symbol.minimumLength = asNumber(node.attributes.minlen);
        symbol.definingSymbolId = Object.hasOwn(node.attributes, 'subsym') ? asNumber(node.attributes.subsym) : null;
        symbol.codeAddress = node.attributes.code === true;
        // The first expression is the operand's own local expression; a second, when present, is
        // the defining expression used when the operand has no defining symbol.
        const expressions = node.children.filter((child) => EXPRESSION_ELEMENTS.has(child.name));
        symbol.localExpression = expressions[0] ? buildExpression(expressions[0]) : null;
        symbol.definingExpression = expressions[1] ? buildExpression(expressions[1]) : null;
        break;
      }
      case 'subtable_sym': {
        symbol.constructors = childrenNamed(node, 'constructor').map(buildConstructor);
        const decision = childNamed(node, 'decision');
        symbol.decision = decision ? buildDecision(decision) : null;
        break;
      }
      default: break;
    }
  }
  return symbols;
}

/**
 * Load a compiled SLEIGH table into a decoder-ready language.
 *
 * `bytes` is a whole `.sla` file. The result is inert data: no file is read after this call and
 * nothing here is executed, so a language can be loaded once and used for many decodes.
 */
export function loadLanguage(bytes) {
  const opened = openSla(bytes);
  if (!opened.ok) fail('SLEIGH_TABLE', opened.detail, { reason: opened.reason });
  const sleigh = decodeTree(opened.flat);

  const spacesNode = childNamed(sleigh, 'spaces');
  const spaces = [];
  if (spacesNode) {
    for (const node of spacesNode.children) {
      if (!['space', 'space_other', 'space_unique'].includes(node.name)) continue;
      spaces.push({
        name: node.attributes.name ?? null, index: asNumber(node.attributes.index),
        size: asNumber(node.attributes.size), wordSize: asNumber(node.attributes.wordsize, 1),
        kind: node.name === 'space_unique' ? 'unique' : node.name === 'space_other' ? 'other' : 'addressable',
      });
    }
  }

  const tableNode = childNamed(sleigh, 'symbol_table');
  if (!tableNode) fail('SLEIGH_TABLE', 'The compiled table has no symbol table');
  const symbols = buildSymbols(tableNode);

  // The root table is named `instruction`, and is found by name exactly as sleighbase.cc does
  // after decoding rather than by assuming an id.
  const root = [...symbols.values()].find((symbol) => symbol.kind === 'subtable' && symbol.name === 'instruction');
  if (!root) fail('SLEIGH_TABLE', 'The compiled table declares no instruction subtable');

  // Context is a word array. Its length comes from what the table actually addresses — the widest
  // context word any symbol or context operation names — rather than from a fixed guess.
  let contextWords = 1;
  for (const symbol of symbols.values()) {
    if (symbol.kind === 'context') contextWords = Math.max(contextWords, Math.floor(symbol.high / 32) + 1);
    if (symbol.kind !== 'subtable') continue;
    for (const constructor of symbol.constructors ?? []) {
      for (const op of constructor.contextOps) contextWords = Math.max(contextWords, op.word + 1);
      for (const commit of constructor.commits) contextWords = Math.max(contextWords, commit.word + 1);
    }
  }
  if (contextWords > MAX_CONTEXT_WORDS) fail('SLEIGH_TABLE', 'The compiled table addresses more context words than this decoder allocates', { contextWords });

  // A space attribute on the wire is an index, and the constant space is index 0 because
  // sleighbase.cc re-inserts it before reading rather than serialising it. The special spaces —
  // stack, join, fspec, iop, spacebase — arrive as names instead of indices.
  const spaceByIndex = new Map([[0, { name: 'const', index: 0, size: 8, wordSize: 1, kind: 'constant' }]]);
  for (const space of spaces) spaceByIndex.set(space.index, space);

  return Object.freeze({
    spaceByIndex,
    bigEndian: sleigh.attributes.bigendian === true,
    alignment: asNumber(sleigh.attributes.align, 1),
    uniqueBase: sleigh.attributes.uniqbase ?? null,
    maxDelaySlotBytes: asNumber(sleigh.attributes.maxdelay, 0),
    formatVersion: asNumber(sleigh.attributes.version),
    defaultSpace: spacesNode?.attributes.defaultspace ?? null,
    spaces,
    sourceFiles: childrenNamed(childNamed(sleigh, 'sourcefiles') ?? { children: [] }, 'sourcefile')
      .map((file) => file.attributes.name ?? null),
    symbols, root, contextWords,
  });
}

// ---------------------------------------------------------------------------------------------
// The walker
// ---------------------------------------------------------------------------------------------

/**
 * The parse state for one instruction.
 *
 * `offset` on a state is absolute from the start of the instruction and `length` is relative to
 * the constructor that owns it. Mixing those up is the classic way to get variable-length decode
 * subtly wrong, so the conversion happens in exactly one place, in `calcCurrentLength`.
 */
class Walker {
  constructor(language, bytes, { address = 0n, context, contextValues } = {}) {
    this.language = language;
    this.bytes = bytes;
    this.address = address;
    this.context = new Uint32Array(language.contextWords);
    if (context) for (let i = 0; i < Math.min(context.length, this.context.length); i++) this.context[i] = context[i] >>> 0;
    if (contextValues) {
      const fields = contextFields(language);
      for (const [name, value] of Object.entries(contextValues)) {
        const field = fields.get(name);
        // A name the language does not declare is refused rather than ignored: silently dropping
        // it would decode in the wrong mode and look like a correct answer.
        if (!field) fail('SLEIGH_CONTEXT', 'The language declares no context field by that name', { field: name });
        writeContextField(this.context, field, value);
      }
    }
    this.root = { constructor: null, symbolId: null, offset: 0, length: 0, parent: null, resolved: [] };
    this.point = this.root;
    this.depth = 0;
    this.breadcrumb = new Int32Array(MAX_OPERAND_DEPTH + 2);
    this.commits = [];
  }

  /** Raw instruction bytes, read big-endian, exactly as ParserContext::getInstructionBytes does. */
  instructionBytes(byteOffset, count) {
    const start = this.point.offset + byteOffset;
    if (start >= MAX_INSTRUCTION_BYTES) fail('SLEIGH_DECODE', 'The instruction reads past the 16 byte window Ghidra allows');
    let result = 0n;
    for (let i = 0; i < count; i++) {
      const at = start + i;
      // Reading past the supplied bytes yields zero, which is what a short buffer means here: the
      // pattern simply fails to match rather than the decode raising.
      result = (result << 8n) | BigInt(at < this.bytes.length ? this.bytes[at] : 0);
    }
    return result;
  }

  instructionBits(startBit, size) {
    const byteOffset = this.point.offset + Math.floor(startBit / 8);
    if (byteOffset >= MAX_INSTRUCTION_BYTES) fail('SLEIGH_DECODE', 'The instruction reads past the 16 byte window Ghidra allows');
    const bitStart = startBit % 8;
    const byteSize = Math.floor((bitStart + size - 1) / 8) + 1;
    let result = 0n;
    for (let i = 0; i < byteSize; i++) {
      const at = byteOffset + i;
      result = (result << 8n) | BigInt(at < this.bytes.length ? this.bytes[at] : 0);
    }
    // Move the starting bit to the top of a 32-bit word, then down to the bottom, which is how
    // Ghidra extracts an unaligned field.
    result = (result << BigInt(8 * (4 - byteSize) + bitStart)) & 0xffffffffn;
    return Number(result >> BigInt(32 - size));
  }

  contextBytes(byteStart, count) {
    let result = 0n;
    for (let i = 0; i < count; i++) {
      const at = byteStart + i;
      const word = this.context[Math.floor(at / 4)] ?? 0;
      result = (result << 8n) | BigInt((word >>> (8 * (3 - (at % 4)))) & 0xff);
    }
    return result;
  }

  contextBits(startBit, size) {
    let result = 0n;
    for (let i = 0; i < 4; i++) {
      const at = Math.floor(startBit / 8) + i;
      const word = this.context[Math.floor(at / 4)] ?? 0;
      result = (result << 8n) | BigInt((word >>> (8 * (3 - (at % 4)))) & 0xff);
    }
    const bitStart = startBit % 8;
    return Number(((result << BigInt(bitStart)) & 0xffffffffn) >> BigInt(32 - size));
  }

  pushOperand(index) {
    if (this.depth >= MAX_OPERAND_DEPTH) fail('SLEIGH_DECODE', 'Operand nesting exceeds the depth Ghidra allows');
    this.breadcrumb[this.depth++] = index + 1;
    this.point = this.point.resolved[index];
    this.breadcrumb[this.depth] = 0;
  }

  popOperand() {
    this.point = this.point.parent;
    this.depth -= 1;
  }

  allocateOperand(index) {
    if (this.depth >= MAX_OPERAND_DEPTH) fail('SLEIGH_DECODE', 'Operand nesting exceeds the depth Ghidra allows');
    const state = { constructor: null, symbolId: null, offset: 0, length: 0, parent: this.point, resolved: [] };
    this.point.resolved[index] = state;
    this.breadcrumb[this.depth++] += 1;
    this.point = state;
    this.breadcrumb[this.depth] = 0;
  }

  /** An operand's end offset, or the constructor's own start when the base is negative. */
  offsetFor(index) {
    if (index < 0) return this.point.offset;
    const operand = this.point.resolved[index];
    if (!operand) return this.point.offset;
    return operand.offset + operand.length;
  }

  calcCurrentLength(length, operandCount) {
    let absolute = length + this.point.offset;
    for (let i = 0; i < operandCount; i++) {
      const operand = this.point.resolved[i];
      if (!operand) continue;
      const end = operand.length + operand.offset;
      if (end > absolute) absolute = end;
    }
    this.point.length = absolute - this.point.offset;
  }
}

/**
 * Set a named context field before decoding.
 *
 * This is the piece that lives outside the compiled table, and it is not optional. x86 chooses its
 * operand size from the `opsize` and `addrsize` context fields, so a table decoded with context
 * left at zero reports `PUSH BP` where the 32-bit language means `PUSH EBP` — correct for the bits
 * it was given and wrong for the program. Those defaults are declared in the `.pspec`
 * `context_data` block, which `artifact.ghidraProcessorSpec` already reads, so the honest shape is
 * for the caller to supply them rather than for this decoder to invent them.
 *
 * The write mirrors how a context field is read: bytes big-endian within 32-bit words, the value
 * shifted into place and masked to its declared width, so setting one field cannot disturb another
 * packed into the same word.
 */
export function contextFields(language) {
  const fields = new Map();
  for (const symbol of language.symbols.values()) {
    if (symbol.kind !== 'context' || !symbol.name || symbol.expression?.kind !== 'contextfield') continue;
    fields.set(symbol.name, symbol.expression);
  }
  return fields;
}

function writeContextField(context, field, value) {
  const size = field.byteEnd - field.byteStart + 1;
  const width = field.bitEnd - field.bitStart + 1;
  if (size <= 0 || width <= 0) return;
  const limit = (1n << BigInt(width)) - 1n;
  const raw = (BigInt(value) & limit) << BigInt(field.shift);
  const mask = limit << BigInt(field.shift);
  for (let i = 0; i < size; i++) {
    const byteIndex = field.byteStart + i;
    const word = Math.floor(byteIndex / 4);
    if (word >= context.length) continue;
    const down = BigInt(8 * (size - 1 - i));
    const byteValue = Number((raw >> down) & 0xffn);
    const byteMask = Number((mask >> down) & 0xffn);
    if (!byteMask) continue;
    const position = 8 * (3 - (byteIndex % 4));
    const clear = ~(byteMask << position) >>> 0;
    context[word] = (((context[word] & clear) >>> 0) | (((byteValue & byteMask) << position) >>> 0)) >>> 0;
  }
}

// ---------------------------------------------------------------------------------------------
// Evaluation and matching
// ---------------------------------------------------------------------------------------------

function evaluate(expression, walker, language) {
  if (!expression) return 0n;
  switch (expression.kind) {
    case 'constant': return expression.value;
    case 'start': return walker.address;
    // inst_next is the address past this instruction, so it is only right once the length is
    // known. Display therefore runs after the walk, never during it.
    case 'end': return walker.address + BigInt(walker.root.length);
    case 'next2': return walker.address + BigInt(walker.root.length);
    case 'tokenfield': {
      const size = expression.byteEnd - expression.byteStart + 1;
      let raw = walker.instructionBytes(expression.byteStart, size);
      if (!expression.bigEndian) {
        // A little-endian token is read big-endian and then swapped, which is exactly what
        // slghpatexpress.cc does; the pattern words were laid out for the unswapped read.
        let swapped = 0n;
        for (let i = 0; i < size; i++) swapped = (swapped << 8n) | ((raw >> BigInt(8 * i)) & 0xffn);
        raw = swapped;
      }
      raw >>= BigInt(expression.shift);
      return expression.signBit ? signExtend(raw, expression.bitEnd - expression.bitStart + 1)
        : zeroExtend(raw, expression.bitEnd - expression.bitStart + 1);
    }
    case 'contextfield': {
      let raw = walker.contextBytes(expression.byteStart, expression.byteEnd - expression.byteStart + 1);
      raw >>= BigInt(expression.shift);
      return expression.signBit ? signExtend(raw, expression.bitEnd - expression.bitStart + 1)
        : zeroExtend(raw, expression.bitEnd - expression.bitStart + 1);
    }
    case 'operand': {
      // An operand expression is evaluated against the operand's own position, which may not be
      // built yet when a context operation runs. setOutOfBandState in context.cc constructs that
      // offset explicitly for exactly this case, and so does this.
      const table = language.symbols.get(expression.table);
      const constructor = table?.constructors?.[expression.constructor];
      if (!constructor) return 0n;
      const operand = language.symbols.get(constructor.operandIds[expression.index]);
      if (!operand) return 0n;
      let inner = operand.definingExpression;
      if (!inner && operand.definingSymbolId !== null) {
        inner = language.symbols.get(operand.definingSymbolId)?.expression ?? null;
      }
      if (!inner) return 0n;
      const savedPoint = walker.point;
      const savedDepth = walker.depth;
      let base = walker.point;
      let depth = walker.depth;
      while (base && base.constructor !== constructor) {
        if (depth <= 0) { base = null; break; }
        depth -= 1;
        base = base.parent;
      }
      if (!base) return 0n;
      const offset = operand.offsetBase < 0
        ? base.offset + operand.relativeOffset
        : (base.resolved[expression.index]?.offset ?? base.offset + operand.relativeOffset);
      walker.point = { constructor, symbolId: null, offset, length: base.length, parent: null, resolved: [] };
      walker.depth = 0;
      const value = evaluate(inner, walker, language);
      walker.point = savedPoint;
      walker.depth = savedDepth;
      return value;
    }
    case 'binary':
      return toSigned(BINARY_EXPRESSIONS[expression.op](
        evaluate(expression.left, walker, language), evaluate(expression.right, walker, language)));
    case 'unary':
      return toSigned(UNARY_EXPRESSIONS[expression.op](evaluate(expression.operand, walker, language)));
    default:
      return 0n;
  }
}

/** `(mask & data) == value`, 32 bits at a time, over instruction or context bytes. */
function blockMatches(block, walker, context) {
  if (block.nonZeroSize <= 0) return block.nonZeroSize === 0;
  let offset = block.offset;
  for (const word of block.words) {
    const data = Number(context ? walker.contextBytes(offset, 4) : walker.instructionBytes(offset, 4)) >>> 0;
    if (((word.mask & data) >>> 0) !== word.value) return false;
    offset += 4;
  }
  return true;
}

function patternMatches(pattern, walker) {
  switch (pattern.kind) {
    case 'instruction': return blockMatches(pattern.block, walker, false);
    case 'context': return blockMatches(pattern.block, walker, true);
    case 'combine': return pattern.parts.every((part) => patternMatches(part, walker));
    case 'or': return pattern.options.some((option) => patternMatches(option, walker));
    default: return false;
  }
}

/** DecisionNode::resolve: index down by bits, then scan the leaf in order. */
function resolveConstructor(decision, walker, table) {
  let node = decision;
  for (let step = 0; step < MAX_WALK_STEPS; step++) {
    if (!node) return null;
    if (node.bitSize === 0) {
      for (const pair of node.pairs) {
        if (patternMatches(pair.pattern, walker)) {
          return { constructor: table.constructors[pair.constructorId], id: pair.constructorId };
        }
      }
      return null;
    }
    const value = node.contextDecision
      ? walker.contextBits(node.startBit, node.bitSize)
      : walker.instructionBits(node.startBit, node.bitSize);
    node = node.children[value];
  }
  fail('SLEIGH_DECODE', 'The decision tree did not terminate');
  return null;
}

// ---------------------------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------------------------

const hex = (value) => (value >= 0n ? `0x${value.toString(16)}` : `-0x${(-value).toString(16)}`);

/** Render one symbol's text, which is how an operand that resolves to a value or a name prints. */
function printSymbol(symbol, walker, language) {
  switch (symbol.kind) {
    case 'varnode': return symbol.name ?? '';
    case 'value': return hex(evaluate(symbol.expression, walker, language));
    case 'valuemap': {
      const index = Number(evaluate(symbol.expression, walker, language));
      const value = symbol.values?.[index];
      return value === undefined ? '' : hex(value);
    }
    case 'name': {
      const index = Number(evaluate(symbol.expression, walker, language));
      return symbol.names?.[index] ?? '';
    }
    case 'varlist': {
      const index = Number(evaluate(symbol.expression, walker, language));
      const id = symbol.varnodeIds?.[index];
      if (id === undefined || id === null) return '';
      return language.symbols.get(id)?.name ?? '';
    }
    case 'context': return hex(evaluate(symbol.expression, walker, language));
    case 'start': return hex(walker.address);
    case 'end': return hex(walker.address + BigInt(walker.root.length));
    case 'next2': return hex(walker.address + BigInt(walker.root.length));
    case 'epsilon': return '0';
    case 'userop': return symbol.name ?? '';
    default: return '';
  }
}

function printOperand(operandSymbol, walker, language, pieces, mnemonicOnly) {
  walker.pushOperand(operandSymbol.index);
  const defining = operandSymbol.definingSymbolId === null ? null : language.symbols.get(operandSymbol.definingSymbolId);
  if (defining && defining.kind === 'subtable') {
    printConstructor(walker.point.constructor, walker, language, pieces, mnemonicOnly);
  } else if (defining) pieces.push(printSymbol(defining, walker, language));
  else pieces.push(hex(evaluate(operandSymbol.definingExpression ?? operandSymbol.localExpression, walker, language)));
  walker.popOperand();
}

/**
 * Assemble a constructor's display text.
 *
 * `firstWhitespace` is the index that splits the mnemonic from the body. A nested constructor
 * reached while printing the mnemonic prints only its own mnemonic, which is what printMnemonic
 * and printBody do by recursing separately.
 */
function printConstructor(constructor, walker, language, pieces, mnemonicOnly) {
  if (!constructor) return;
  const split = constructor.firstWhitespace === -1 ? constructor.printPieces.length : constructor.firstWhitespace;
  const to = mnemonicOnly ? split : constructor.printPieces.length;
  for (let i = 0; i < to; i++) {
    const piece = constructor.printPieces[i];
    if (piece.literal !== undefined) { pieces.push(piece.literal); continue; }
    const operand = language.symbols.get(constructor.operandIds[piece.operand]);
    if (operand) printOperand(operand, walker, language, pieces, mnemonicOnly);
  }
}

function applyContext(constructor, walker, language) {
  for (const op of constructor.contextOps) {
    const value = Number(evaluate(op.expression, walker, language) & 0xffffffffn) >>> 0;
    const shifted = (value << op.shift) >>> 0;
    const word = walker.context[op.word] ?? 0;
    walker.context[op.word] = (((word & ~op.mask) >>> 0) | ((op.mask & shifted) >>> 0)) >>> 0;
  }
  // A commit targets a different address through a context database this decoder does not have,
  // so it is reported rather than applied. Applying it here would change the current instruction
  // using a value intended for a later one.
  for (const commit of constructor.commits) {
    walker.commits.push({ symbol: language.symbols.get(commit.symbolId)?.name ?? null,
      word: commit.word, mask: commit.mask, flow: commit.flow });
  }
}

const EMPTY = { mnemonic: null, body: null, text: null, constructors: [], delaySlotBytes: 0, commits: [] };

/**
 * Decode one instruction.
 *
 * `Sleigh::resolve`, iteratively: resolve the root constructor, then walk its operands, descending
 * into any whose defining symbol is itself a table. The loop is the original's because the order
 * matters — a context operation runs when its constructor is entered, before that constructor's
 * operands are built, which is why operand expressions construct their own offsets.
 */
export function decodeInstruction(language, bytes, options = {}) {
  const address = options.address === undefined ? 0n : BigInt(options.address);
  const walker = new Walker(language, bytes, { address, context: options.context, contextValues: options.contextValues });
  const matched = [];

  const rootMatch = resolveConstructor(language.root.decision, walker, language.root);
  if (!rootMatch) {
    return { ...EMPTY, decoded: false, reason: 'no_matching_constructor', address, length: 0 };
  }
  walker.point.constructor = rootMatch.constructor;
  walker.point.symbolId = language.root.id;
  applyContext(rootMatch.constructor, walker, language);
  matched.push({ table: language.root.name, constructorIndex: rootMatch.id,
    source: rootMatch.constructor.sourceIndex, line: rootMatch.constructor.lineNumber });

  let steps = 0;
  let delaySlotBytes = 0;
  while (walker.point) {
    if (++steps > MAX_WALK_STEPS) fail('SLEIGH_DECODE', 'The operand walk did not terminate');
    const constructor = walker.point.constructor;
    const operandCount = constructor.operandIds.length;
    let index = walker.breadcrumb[walker.depth];
    let descended = false;
    while (index < operandCount) {
      const operand = language.symbols.get(constructor.operandIds[index]);
      if (!operand) fail('SLEIGH_TABLE', 'A constructor names an operand the symbol table does not hold');
      const offset = walker.offsetFor(operand.offsetBase) + operand.relativeOffset;
      walker.allocateOperand(index);
      walker.point.offset = offset;
      const defining = operand.definingSymbolId === null ? null : language.symbols.get(operand.definingSymbolId);
      if (defining && defining.kind === 'subtable') {
        const sub = resolveConstructor(defining.decision, walker, defining);
        // A subtable operand that resolves to nothing fails the whole instruction, as Ghidra's
        // DecisionNode::resolve does by raising BadDataError. Carrying on with the operand's
        // minimum length would drop it from the display and still report a successful decode —
        // an instruction missing an operand, presented as if it were complete.
        if (!sub) return { ...EMPTY, decoded: false, reason: 'unresolved_subtable',
          detail: `No constructor in subtable ${defining.name ?? defining.id} matches these bytes`,
          address, length: 0 };
        walker.point.constructor = sub.constructor;
        walker.point.symbolId = defining.id;
        applyContext(sub.constructor, walker, language);
        matched.push({ table: defining.name, constructorIndex: sub.id,
          source: sub.constructor.sourceIndex, line: sub.constructor.lineNumber });
        descended = true;
        break;
      }
      walker.point.length = operand.minimumLength;
      walker.popOperand();
      index += 1;
    }
    if (descended) continue;
    walker.calcCurrentLength(constructor.minimumLength, operandCount);
    // A constructor that declares a delay slot says how many bytes of the following instruction
    // execute as part of this one. Sleigh::resolve records it the same way, and it is a fact about
    // the instruction's effect: reporting a length without it would understate what runs.
    if (constructor.template?.delaySlot > 0) delaySlotBytes = constructor.template.delaySlot;
    const isRoot = walker.point === walker.root;
    walker.popOperand();
    if (isRoot) break;
  }

  const length = walker.root.length;
  // Display runs after the walk, because inst_next is the address past this instruction and a
  // relative branch target would otherwise print against a length of zero.
  const render = (mnemonicOnly) => {
    walker.point = walker.root;
    walker.depth = 0;
    walker.breadcrumb[0] = 0;
    const pieces = [];
    printConstructor(walker.root.constructor, walker, language, pieces, mnemonicOnly);
    return pieces.join('');
  };
  const mnemonicText = render(true);
  const fullText = render(false);
  const mnemonic = mnemonicText.trim();
  const body = fullText.slice(mnemonicText.length).trim();

  const result = {
    decoded: true, reason: null, address, length,
    mnemonic, body: body || null, text: body ? `${mnemonic} ${body}` : mnemonic,
    constructors: matched, delaySlotBytes, commits: walker.commits,
  };
  // The lifter needs the parse tree, and nothing else does. It is handed back only when asked
  // for, so an ordinary decode stays a plain data result with no live object hanging off it.
  if (options.keepWalker) result.walker = walker;
  return result;
}

/** Decode instructions in sequence until the bytes run out, the limit is hit, or a decode fails. */
export function decodeRange(language, bytes, options = {}) {
  const limit = options.limit ?? 256;
  const start = options.address === undefined ? 0n : BigInt(options.address);
  const step = options.pcode ? liftInstruction : decodeInstruction;
  const instructions = [];
  let offset = 0;
  while (offset < bytes.length && instructions.length < limit) {
    const window = bytes.subarray(offset, Math.min(bytes.length, offset + MAX_INSTRUCTION_BYTES));
    let decoded;
    try {
      decoded = step(language, window, { address: start + BigInt(offset), context: options.context, contextValues: options.contextValues });
    } catch (error) {
      instructions.push({ ...EMPTY, decoded: false, reason: 'decode_failed', detail: error?.code ?? 'unknown',
        address: start + BigInt(offset), length: 0, offset });
      break;
    }
    instructions.push({ ...decoded, offset });
    if (!decoded.decoded || decoded.length <= 0) break;
    offset += decoded.length;
  }
  return { instructions, bytesDecoded: offset };
}

// ---------------------------------------------------------------------------------------------
// P-code lifting
// ---------------------------------------------------------------------------------------------

/**
 * Resolve the handles each operand exports, in a second pass over the parse tree.
 *
 * `Sleigh::resolveHandles`, and it has to be a separate pass for a structural reason: a varnode
 * template can name another operand's space, offset or size, and that operand's handle is not
 * known until its own constructor has finished. So decode resolves the tree, this fills in what
 * each node exports, and only then can the templates be built.
 */
function resolveHandles(walker, language) {
  const constSpace = language.spaceByIndex.get(0);
  const curSpace = language.spaceByIndex.get(0) && language.spaces.find((space) => space.name === language.defaultSpace);
  walker.point = walker.root;
  walker.depth = 0;
  walker.breadcrumb[0] = 0;

  let steps = 0;
  while (walker.point) {
    if (++steps > MAX_WALK_STEPS) fail('SLEIGH_DECODE', 'Handle resolution did not terminate');
    const constructor = walker.point.constructor;
    // Every state reached here was resolved during decode, because an operand whose subtable did
    // not resolve fails the instruction outright. A null here would mean the two walks disagree,
    // which is worth a named refusal rather than a TypeError from the next property read.
    if (!constructor) fail('SLEIGH_DECODE', 'A parse state reached handle resolution without a constructor');
    const operandCount = constructor.operandIds.length;
    let index = walker.breadcrumb[walker.depth];
    let descended = false;
    while (index < operandCount) {
      const operand = language.symbols.get(constructor.operandIds[index]);
      walker.pushOperand(index);
      const defining = operand.definingSymbolId === null ? null : language.symbols.get(operand.definingSymbolId);
      if (defining && defining.kind === 'subtable') { descended = true; break; }
      if (defining) walker.point.handle = fixedHandleFor(defining, walker, language, constSpace, curSpace);
      else {
        // No defining symbol means the operand is an expression, and the result of an expression
        // is a constant. Size 0 records that the expression cannot say how wide its value is.
        const value = evaluate(operand.definingExpression ?? operand.localExpression, walker, language);
        walker.point.handle = { space: constSpace, offsetSpace: null, offsetOffset: value & MASK64, size: 0 };
      }
      walker.popOperand();
      index += 1;
    }
    if (descended) continue;
    // A finished constructor exports its result into the operand slot that holds it.
    const template = constructor.template;
    if (template?.result) {
      const exported = fixHandleTemplate(template.result, walker, language, constSpace, curSpace);
      walker.point.handle = exported;
    }
    const isRoot = walker.point === walker.root;
    walker.popOperand();
    if (isRoot) break;
  }
}

/** A handle for an operand whose defining symbol is not a table. */
function fixedHandleFor(symbol, walker, language, constSpace, curSpace) {
  const constant = (value, size = 0) => ({ space: constSpace, offsetSpace: null, offsetOffset: value & MASK64, size });
  switch (symbol.kind) {
    case 'varnode':
      return { space: language.spaceByIndex.get(symbol.space) ?? { name: String(symbol.space), index: -1 },
        offsetSpace: null, offsetOffset: symbol.offset, size: symbol.size };
    case 'varlist': {
      const index = Number(evaluate(symbol.expression, walker, language));
      const id = symbol.varnodeIds?.[index];
      const target = id === undefined || id === null ? null : language.symbols.get(id);
      if (!target) return constant(0n);
      return { space: language.spaceByIndex.get(target.space) ?? { name: String(target.space), index: -1 },
        offsetSpace: null, offsetOffset: target.offset, size: target.size };
    }
    case 'valuemap': {
      const index = Number(evaluate(symbol.expression, walker, language));
      return constant(symbol.values?.[index] ?? 0n);
    }
    // NameSymbol extends ValueSymbol in Ghidra and does not override getFixedHandle, so a name
    // resolves to the value of its pattern rather than to its text.
    case 'value':
    case 'name':
    case 'context':
      return constant(evaluate(symbol.expression, walker, language));
    case 'start': return { space: curSpace, offsetSpace: null, offsetOffset: walker.address, size: curSpace?.size ?? 0 };
    case 'end':
    case 'next2':
      return { space: curSpace, offsetSpace: null, offsetOffset: walker.address + BigInt(walker.root.length), size: curSpace?.size ?? 0 };
    case 'epsilon': return constant(0n);
    default: return constant(0n);
  }
}

/** ConstTpl::fix — the value of one template slot in context. */
function fixConst(slot, walker, language, constSpace, curSpace) {
  switch (slot.kind) {
    case 'real':
    case 'relative':
      return slot.value;
    case 'start': return walker.address;
    case 'next':
    case 'next2':
      return walker.address + BigInt(walker.root.length);
    case 'curspace_size': return BigInt(curSpace?.size ?? 0);
    case 'curspace': return BigInt(curSpace?.index ?? 0);
    case 'spaceid': return BigInt(resolveSpace(slot.space, language)?.index ?? 0);
    case 'handle': {
      const handle = walker.point.resolved[slot.index]?.handle;
      if (!handle) return 0n;
      switch (slot.select) {
        case 'space': return BigInt((handle.offsetSpace ? handle.tempSpace?.index : handle.space?.index) ?? 0);
        case 'offset': return handle.offsetSpace ? (handle.tempOffset ?? 0n) : handle.offsetOffset;
        case 'size': return BigInt(handle.size ?? 0);
        case 'offset_plus': {
          const base = handle.offsetSpace ? (handle.tempOffset ?? 0n) : handle.offsetOffset;
          // A constant is shifted; anything else is adjusted by a truncation amount. The two cases
          // pack different things into the same field, which is why the space is checked first.
          if (handle.space === constSpace) return base >> BigInt(8 * Number(slot.plus >> 16n));
          return base + (slot.plus & 0xffffn);
        }
        default: return 0n;
      }
    }
    // A flow reference only has a value inside an injection, where a call or jump supplied it.
    // There is no such context in a plain decode, so it is zero and the caller is told.
    default: return 0n;
  }
}

const resolveSpace = (value, language) => (typeof value === 'number'
  ? language.spaceByIndex.get(value) ?? null
  : { name: String(value), index: -1, size: 0, wordSize: 1, kind: 'special' });

/** ConstTpl::fixSpace — the same slot, when it must name a space. */
function fixSpace(slot, walker, language, curSpace) {
  switch (slot.kind) {
    case 'curspace': return curSpace;
    case 'spaceid': return resolveSpace(slot.space, language);
    case 'handle': {
      const handle = walker.point.resolved[slot.index]?.handle;
      if (!handle) return null;
      return slot.select === 'space' ? (handle.offsetSpace ? handle.tempSpace : handle.space) : null;
    }
    default: return null;
  }
}

/** HandleTpl::fix — what a constructor exports, resolved. */
function fixHandleTemplate(template, walker, language, constSpace, curSpace) {
  const size = Number(fixConst(template.size, walker, language, constSpace, curSpace));
  if (template.ptrSpace.kind === 'real') {
    // An unstarred export. The space and offset come straight through, but the offset may still
    // be dynamic, which fillinOffset carries over from the handle it refers to.
    const space = fixSpace(template.space, walker, language, curSpace);
    const handle = { space, size, offsetSpace: null, offsetOffset: 0n };
    if (template.ptrOffset.kind === 'handle') {
      const other = walker.point.resolved[template.ptrOffset.index]?.handle;
      if (other) {
        handle.offsetSpace = other.offsetSpace;
        handle.offsetOffset = other.offsetOffset;
        handle.offsetSize = other.offsetSize;
        handle.tempSpace = other.tempSpace;
        handle.tempOffset = other.tempOffset;
      }
    } else handle.offsetOffset = fixConst(template.ptrOffset, walker, language, constSpace, curSpace) & MASK64;
    return handle;
  }
  const space = fixSpace(template.space, walker, language, curSpace);
  const offsetSpace = fixSpace(template.ptrSpace, walker, language, curSpace);
  const handle = { space, size, offsetSpace, offsetOffset: fixConst(template.ptrOffset, walker, language, constSpace, curSpace) & MASK64 };
  if (!offsetSpace || offsetSpace.kind === 'constant') {
    // The handle could have been dynamic and was not. Ghidra converts the address to bytes by the
    // space's word size here, which matters for a word-addressed space.
    handle.offsetSpace = null;
    handle.offsetOffset = handle.offsetOffset * BigInt(space?.wordSize ?? 1);
  } else {
    handle.offsetSize = Number(fixConst(template.ptrSize, walker, language, constSpace, curSpace));
    handle.tempSpace = fixSpace(template.tempSpace, walker, language, curSpace);
    handle.tempOffset = fixConst(template.tempOffset, walker, language, constSpace, curSpace) & MASK64;
  }
  return handle;
}

const renderVarnode = (varnode) => ({
  space: varnode.space?.name ?? null,
  offset: `0x${(varnode.offset & MASK64).toString(16)}`,
  size: varnode.size,
});

/** Resolve one varnode template to a concrete varnode. */
function fixVarnode(template, walker, language, constSpace, curSpace) {
  return {
    space: fixSpace(template.space, walker, language, curSpace),
    offset: fixConst(template.offset, walker, language, constSpace, curSpace),
    size: Number(fixConst(template.size, walker, language, constSpace, curSpace)),
    dynamic: template.offset.kind === 'handle'
      && Boolean(walker.point.resolved[template.offset.index]?.handle?.offsetSpace),
    template,
  };
}

/**
 * Lift one instruction to p-code.
 *
 * `PcodeBuilder::build` walks the constructor's template; a BUILD directive recurses into an
 * operand's own template, which is how a nested constructor's semantics are spliced in at the
 * point the parent asked for them. A dynamic varnode — one whose offset lives in another address
 * space — becomes an explicit LOAD before the operation, or a STORE after it, exactly as
 * `SleighBuilder::dump` generates them.
 */
export function liftInstruction(language, bytes, options = {}) {
  const decoded = decodeInstruction(language, bytes, { ...options, keepWalker: true });
  if (!decoded.decoded) return { ...decoded, pcode: [], lifted: false, liftReason: decoded.reason, directives: [] };
  const walker = decoded.walker;
  delete decoded.walker;

  const constSpace = language.spaceByIndex.get(0);
  const curSpace = language.spaces.find((space) => space.name === language.defaultSpace) ?? null;
  resolveHandles(walker, language);

  const pcode = [];
  const directives = [];
  const limitations = [];
  let steps = 0;

  const emit = (op) => {
    if (pcode.length >= MAX_PCODE_OPS) fail('SLEIGH_DECODE', 'The instruction lifts to more p-code than this decoder emits');
    pcode.push(op);
  };

  const dump = (op) => {
    const inputs = op.inputs.map((input) => fixVarnode(input, walker, language, constSpace, curSpace));
    const output = op.output ? fixVarnode(op.output, walker, language, constSpace, curSpace) : null;
    const resolved = [];
    for (const input of inputs) {
      if (!input.dynamic) { resolved.push(renderVarnode(input)); continue; }
      // The operand is really a pointer into another space, so the value has to be loaded first.
      const handle = walker.point.resolved[input.template.offset.index].handle;
      const temporary = { space: handle.tempSpace?.name ?? 'unique', offset: `0x${(handle.tempOffset ?? 0n).toString(16)}`, size: input.size };
      emit({ op: 'LOAD', code: OP_LOAD, output: temporary,
        inputs: [{ space: 'const', offset: `0x${BigInt(handle.offsetSpace?.index ?? 0).toString(16)}`, size: 8 },
          { space: handle.offsetSpace?.name ?? null, offset: `0x${handle.offsetOffset.toString(16)}`, size: handle.offsetSize ?? 0 }],
        synthetic: 'dynamic-input' });
      resolved.push(temporary);
    }
    if (output?.dynamic) {
      const handle = walker.point.resolved[output.template.offset.index].handle;
      const temporary = { space: handle.tempSpace?.name ?? 'unique', offset: `0x${(handle.tempOffset ?? 0n).toString(16)}`, size: output.size };
      emit({ op: op.name, code: op.code, output: temporary, inputs: resolved, synthetic: null });
      emit({ op: 'STORE', code: OP_STORE, output: null,
        inputs: [{ space: 'const', offset: `0x${BigInt(handle.offsetSpace?.index ?? 0).toString(16)}`, size: 8 },
          { space: handle.offsetSpace?.name ?? null, offset: `0x${handle.offsetOffset.toString(16)}`, size: handle.offsetSize ?? 0 },
          temporary],
        synthetic: 'dynamic-output' });
      return;
    }
    emit({ op: op.name, code: op.code, output: output ? renderVarnode(output) : null, inputs: resolved, synthetic: null });
  };

  const build = (template) => {
    if (++steps > MAX_WALK_STEPS) fail('SLEIGH_DECODE', 'The template build did not terminate');
    if (!template) { directives.push({ directive: 'UNIMPLEMENTED', detail: 'This constructor declares no semantics' }); return; }
    for (const op of template.ops) {
      if (op.code === OP_BUILD) {
        const index = Number(op.inputs[0] ? fixConst(op.inputs[0].offset, walker, language, constSpace, curSpace) : 0n);
        const operand = language.symbols.get(walker.point.constructor.operandIds[index]);
        const defining = operand?.definingSymbolId === null ? null : language.symbols.get(operand.definingSymbolId);
        if (!defining || defining.kind !== 'subtable') continue;
        walker.pushOperand(index);
        build(walker.point.constructor?.template ?? null);
        walker.popOperand();
        continue;
      }
      if (op.code === OP_DELAY_SLOT) {
        // A delay slot splices in the p-code of the instruction that follows, which needs that
        // instruction parsed. One instruction in isolation cannot supply it, so the directive is
        // reported and the gap is explicit rather than silently absent.
        directives.push({ directive: 'DELAY_SLOT', detail: 'The following instruction executes in this slot and is not lifted here' });
        continue;
      }
      if (op.code === OP_LABELBUILD) {
        directives.push({ directive: 'LABEL', detail: `Branch target label ${Number(op.inputs[0] ? fixConst(op.inputs[0].offset, walker, language, constSpace, curSpace) : 0n)}` });
        continue;
      }
      if (op.code === OP_CROSSBUILD) {
        directives.push({ directive: 'CROSSBUILD', detail: 'Semantics are woven in from an instruction at another address, which is not lifted here' });
        continue;
      }
      dump(op);
    }
  };

  walker.point = walker.root;
  walker.depth = 0;
  walker.breadcrumb[0] = 0;
  build(walker.root.constructor.template);

  // A delay slot is recorded two ways — the template's `delay` attribute and a DELAY_SLOT op — and
  // a real table carries both. Either one is enough to make the omission worth stating, because
  // the p-code below is then not the whole effect of this instruction.
  if (decoded.delaySlotBytes > 0 || directives.some((entry) => entry.directive === 'DELAY_SLOT')) {
    limitations.push('This instruction has a delay slot, so the p-code of the following instruction is part of its effect and is not included');
  }
  if (directives.some((entry) => entry.directive === 'UNIMPLEMENTED')) {
    limitations.push('A constructor involved in this instruction declares no semantics, so the p-code below is incomplete rather than complete');
  }
  return { ...decoded, lifted: true, liftReason: null, pcode, directives, liftLimitations: limitations };
}

// ---------------------------------------------------------------------------------------------
// The tool
// ---------------------------------------------------------------------------------------------

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const MAX_INSTRUCTIONS = 512;

/**
 * Disassembly as a Concord tool.
 *
 * A `read` effect over two files already in the workspace: the compiled table and the bytes. It
 * spawns nothing and reaches nothing, so it needs no approval, and it is a pure function of its
 * declared input, which is what makes a recorded run replayable.
 *
 * Addresses leave as hex strings rather than numbers. An address can exceed the safe integer range
 * on a 64-bit target, and `canonical` rejects a BigInt outright as outside the JSON domain, so a
 * number here would either round silently or fail the kernel's own encoding check.
 */
export function makeSleighTools() {
  const readBytes = (context, relative, divisor) =>
    readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / divisor));

  return [Object.freeze({
    name: 'artifact.disassemble', version: '1.0.0', effect: 'read',
    outputKeys: ['table', 'path', 'sha256', 'supported', 'reason', 'language', 'instructions', 'counts', 'limitations', 'untrusted'],
    inputSchema: object({
      table: string, path: string,
      offset: { type: 'integer', minimum: 0 },
      length: { type: 'integer', minimum: 1, maximum: 1048576 },
      address: string,
      limit: { type: 'integer', minimum: 1, maximum: MAX_INSTRUCTIONS },
      context: { type: 'object', additionalProperties: { type: 'integer' } },
      pcode: { type: 'boolean' },
    }, ['table', 'path']),
    execute(input, context) {
      const limitations = [];
      const tableBytes = readBytes(context, input.table, 2);
      const targetBytes = readBytes(context, input.path, 4);
      const base = { table: input.table, path: input.path, sha256: sha256(targetBytes), untrusted: true };
      const empty = { language: null, instructions: [], counts: {} };

      let language;
      try { language = loadLanguage(tableBytes); }
      catch (error) {
        return { ...base, supported: false, reason: 'table_unreadable', detail: error?.message ?? null, ...empty, limitations };
      }

      const offset = input.offset ?? 0;
      if (offset >= targetBytes.length) {
        return { ...base, supported: false, reason: 'offset_past_end',
          detail: 'The requested offset lies past the end of the file', ...empty, limitations };
      }
      const end = input.length === undefined ? targetBytes.length : Math.min(targetBytes.length, offset + input.length);
      if (input.length !== undefined && offset + input.length > targetBytes.length) {
        limitations.push('The requested length ran past the end of the file, so a shorter region was decoded');
      }
      const slice = targetBytes.subarray(offset, end);
      // An address that does not parse is refused rather than defaulted to zero: a wrong base
      // address silently relocates every branch target this reports.
      let address = 0n;
      if (input.address !== undefined) {
        if (!/^(0x)?[0-9a-fA-F]{1,16}$/.test(input.address)) {
          return { ...base, supported: false, reason: 'invalid_address',
            detail: 'An address must be up to 16 hexadecimal digits, optionally prefixed with 0x', ...empty, limitations };
        }
        address = BigInt(input.address.startsWith('0x') ? input.address : `0x${input.address}`);
      }

      let run;
      try {
        run = decodeRange(language, slice, { address, limit: input.limit ?? 64, contextValues: input.context, pcode: input.pcode === true });
      } catch (error) {
        return { ...base, supported: false, reason: 'context_rejected', detail: error?.message ?? null, ...empty, limitations };
      }

      const instructions = run.instructions.map((instruction) => ({
        ...(input.pcode === true
          ? { pcode: instruction.pcode ?? [], directives: instruction.directives ?? [] }
          : {}),
        offset: offset + instruction.offset,
        address: `0x${instruction.address.toString(16)}`,
        length: instruction.length,
        decoded: instruction.decoded,
        reason: instruction.reason,
        mnemonic: instruction.mnemonic,
        body: instruction.body,
        text: instruction.text,
        // The constructors that matched, so a line of disassembly can be traced to the SLEIGH that
        // produced it instead of being taken on trust.
        constructors: instruction.constructors,
        bytes: slice.subarray(instruction.offset, instruction.offset + Math.max(instruction.length, 1)).toString('hex'),
      }));
      const undecoded = instructions.filter((instruction) => !instruction.decoded).length;

      if (!input.context) {
        limitations.push('No initial context was supplied. A language whose decode depends on context — x86 operand size, ARM instruction set mode — will decode in whatever its zeroed context selects, which may not be the mode the program runs in; the defaults are declared in the .pspec and readable with artifact.ghidraProcessorSpec');
      }
      if (undecoded) limitations.push(`${undecoded} position(s) matched no constructor and decoding stopped there rather than resynchronising at a guessed boundary`);
      if (run.bytesDecoded < slice.length) limitations.push(`${slice.length - run.bytesDecoded} of ${slice.length} selected bytes were not reached`);
      if (input.pcode === true) {
        const delayed = run.instructions.filter((instruction) => instruction.delaySlotBytes > 0).length;
        if (delayed) {
          limitations.push(`${delayed} instruction(s) have a delay slot, so the p-code of the instruction that follows is part of their effect and is reported as a DELAY_SLOT directive rather than included`);
        }
        if (run.instructions.some((instruction) => (instruction.directives ?? []).some((entry) => entry.directive === 'CROSSBUILD'))) {
          limitations.push('A CROSSBUILD directive weaves in semantics from an instruction at another address, which decoding one range cannot supply, so that p-code is named and not included');
        }
        if (run.instructions.some((instruction) => (instruction.directives ?? []).some((entry) => entry.directive === 'UNIMPLEMENTED'))) {
          limitations.push('A constructor involved here declares no semantics, so its p-code is absent rather than empty: the instruction does something this table does not model');
        }
        limitations.push('P-code is the lifted meaning of each instruction and nothing further: no dataflow, no type inference, no control-flow structuring, and not decompiled source');
      } else {
        limitations.push('This is instruction decode only: a mnemonic and its operands. Pass pcode:true for the lifted p-code of each instruction');
      }
      limitations.push('A disassembly is an interpretation of bytes under one chosen language; selecting the wrong table produces confident output about the wrong machine');

      return { ...base, supported: true, reason: null,
        language: { bigEndian: language.bigEndian, alignment: language.alignment,
          defaultSpace: language.defaultSpace, formatVersion: language.formatVersion,
          sourceFiles: language.sourceFiles, contextFields: [...contextFields(language).keys()].sort() },
        instructions,
        counts: { instructions: instructions.length, decoded: instructions.length - undecoded,
          undecoded, bytesSelected: slice.length, bytesDecoded: run.bytesDecoded },
        limitations };
    },
  })];
}
