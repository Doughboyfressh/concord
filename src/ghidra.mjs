import { createHash } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { readWorkspaceFile } from './workspace-fs.mjs';

/**
 * Ghidra's language corpus, read natively.
 *
 * Ghidra decides how to disassemble a binary from a specification corpus, not from code: 51
 * `.ldefs` name 190 languages, 86 `.pspec` describe each processor, 105 `.cspec` describe each
 * compiler's calling conventions, 29 `.opinion` map a binary's header fields onto a language, and
 * 137 `.sla` carry the compiled decode tables. All of it is data, which means all of it is
 * provable from bytes — so it belongs here rather than behind a process boundary.
 *
 * The split this module draws is the one the format itself draws. A `.sla` is the SLEIGH compiler's
 * output: endianness, alignment, the address space table, every register varnode, every userop and
 * subtable are recorded facts, and this module reports them. A `.slaspec` is the input, and its
 * meaning depends on a preprocessor — `define endian=$(ENDIAN)` says nothing on its own. So the
 * source reader never evaluates a condition it was not given: it reports each declaration together
 * with the exact `@if` stack guarding it, and lets the caller see that a register block is gated on
 * `T_VARIANT` rather than pretending it is unconditional.
 *
 * What this module does not do is run the decompiler. Lifting p-code to C is 189,941 lines of C++
 * shipped as an executable; reading the tables it would consult is a different and much smaller
 * problem, and conflating the two would be the dishonest move. `decompile.exe` and
 * `analyzeHeadless` are reached the way every other foreign engine is reached: as a reviewed
 * provider with a pinned digest and a fixed argv, which `src/reverse.mjs` already compiles.
 *
 * Ghidra is Apache 2.0. The element and attribute id tables below are transcribed from
 * `Ghidra/Features/Decompiler/src/decompile/cpp/slaformat.cc`, and the wire encoding from
 * `marshal.hh`'s `PackedFormat` namespace. They are not stored in the file, so a reader has to
 * carry them; `FORMAT_VERSION` 4 is asserted rather than assumed because the decoder in
 * `sleighbase.cc` rejects anything else and a silently misread table is worse than a refusal.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const MAX_LISTED = 2000;
// Four times the largest shipped .sla inflates to (x86-64, 4.48MB). A zlib stream can claim any
// expansion it likes, so the bound is passed to inflateSync rather than checked afterwards.
const MAX_INFLATED = 16 * 1024 * 1024;
// x86-64.sla, the largest, walks in 2.23M events. The cap exists so a crafted stream terminates,
// not to limit real input, and being hit is reported rather than silently truncating.
const MAX_EVENTS = 8_000_000;
const MAX_XML_NODES = 400_000;
const MAX_XML_DEPTH = 64;

/** Element ids, FORMAT_SCOPE 1, transcribed from slaformat.cc. Index is the on-wire id. */
const SLA_ELEMENTS = ['', 'const_real', 'varnode_tpl', 'const_spaceid', 'const_handle', 'op_tpl',
  'mask_word', 'pat_block', 'print', 'pair', 'context_pat', 'null', 'operand_exp', 'operand_sym',
  'operand_sym_head', 'oper', 'decision', 'opprint', 'instruct_pat', 'combine_pat', 'constructor',
  'construct_tpl', 'scope', 'varnode_sym', 'varnode_sym_head', 'userop', 'userop_head',
  'tokenfield', 'var', 'contextfield', 'handle_tpl', 'const_relative', 'context_op', 'sleigh',
  'spaces', 'sourcefiles', 'sourcefile', 'space', 'symbol_table', 'value_sym', 'value_sym_head',
  'context_sym', 'context_sym_head', 'end_sym', 'end_sym_head', 'space_other', 'space_unique',
  'and_exp', 'div_exp', 'lshift_exp', 'minus_exp', 'mult_exp', 'not_exp', 'or_exp', 'plus_exp',
  'rshift_exp', 'sub_exp', 'xor_exp', 'intb', 'end_exp', 'next2_exp', 'start_exp', 'epsilon_sym',
  'epsilon_sym_head', 'name_sym', 'name_sym_head', 'nametab', 'next2_sym', 'next2_sym_head',
  'start_sym', 'start_sym_head', 'subtable_sym', 'subtable_sym_head', 'valuemap_sym',
  'valuemap_sym_head', 'valuetab', 'varlist_sym', 'varlist_sym_head', 'or_pat', 'commit',
  'const_start', 'const_next', 'const_next2', 'const_curspace', 'const_curspace_size',
  'const_flowref', 'const_flowref_size', 'const_flowdest', 'const_flowdest_size'];

/** Attribute ids. Index 1 is the universal XMLcontent attribute from marshal.cc, not a sla id. */
const SLA_ATTRIBUTES = ['', 'XMLcontent', 'val', 'id', 'space', 's', 'off', 'code', 'mask', 'index',
  'nonzero', 'piece', 'name', 'scope', 'startbit', 'size', 'table', 'ct', 'minlen', 'base',
  'number', 'context', 'parent', 'subsym', 'line', 'source', 'length', 'first', 'plus', 'shift',
  'endbit', 'signbit', 'endbyte', 'startbyte', 'version', 'bigendian', 'align', 'uniqbase',
  'maxdelay', 'uniqmask', 'numsections', 'defaultspace', 'delay', 'wordsize', 'physical',
  'scopesize', 'symbolsize', 'varnode', 'low', 'high', 'flow', 'contain', 'i', 'numct', 'section',
  'labels'];

/** PackedFormat special address space codes, by length code. */
const SLA_SPECIAL_SPACES = ['stack', 'join', 'fspec', 'iop', 'spacebase'];

const SLA_FORMAT_VERSION = 4;

const readBytes = (context, relative, divisor = 4) =>
  readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / divisor));

const listed = (items, limitations, label) => {
  if (items.length <= MAX_LISTED) return items;
  limitations.push(`Only the first ${MAX_LISTED} of ${items.length} ${label} are listed; the count above each list is the true total`);
  return items.slice(0, MAX_LISTED);
};

/** A boolean as the Ghidra schemas spell it: language_common.rxg accepts all six spellings. */
const bool = (value) => {
  if (value === undefined || value === null) return null;
  const text = String(value).trim().toLowerCase();
  if (text === 'true' || text === 'yes' || text === '1') return true;
  if (text === 'false' || text === 'no' || text === '0') return false;
  return null;
};

/**
 * An integer as the corpus writes it: `0x1000`, bare hex after a space name (`SFR:80`), or decimal.
 *
 * The ambiguity is real and not resolvable from the token alone — `80` is 128 in `SFR:80` and 80 in
 * `length="80"`. So the caller says which it is, and a value that does not parse comes back null
 * rather than as a guess.
 */
const integer = (value, { hex = false } = {}) => {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  if (/^[+-]?0[xX][0-9a-fA-F]+$/.test(text)) return Number.parseInt(text.replace(/0[xX]/, ''), 16) * (text.startsWith('-') ? -1 : 1);
  if (hex && /^[0-9a-fA-F]+$/.test(text)) return Number.parseInt(text, 16);
  if (/^[+-]?[0-9]+$/.test(text)) return Number.parseInt(text, 10);
  return null;
};

/** A `space:offset` address, where the offset is hex with or without the prefix. */
const address = (value) => {
  if (typeof value !== 'string') return null;
  const match = /^([A-Za-z_][A-Za-z0-9_]*):(.+)$/.exec(value.trim());
  if (!match) return { space: null, offset: null, text: value };
  return { space: match[1], offset: integer(match[2], { hex: true }), text: value };
};

// ---------------------------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------------------------

/**
 * A reader for the XML dialect this corpus actually uses, and nothing wider.
 *
 * The four XML types carry no namespaces, no DTD and no entity declarations — verified across all
 * 271 of them — so the parser handles elements, attributes, text, CDATA and comments, and refuses
 * anything else rather than growing to meet it. An internal entity declaration is refused by name:
 * entity expansion is the one XML feature whose cost is not bounded by the file's length, and a
 * reader that declines to expand entities cannot be made to expand them.
 *
 * `.opinion` files carry no XML declaration (0 of 29 do), so a prolog is optional, not required.
 */
function parseXml(text, limitations) {
  if (/<!DOCTYPE/i.test(text)) {
    if (/<!ENTITY/i.test(text)) return { ok: false, reason: 'entity_declaration', detail: 'The file declares an XML entity, which this reader does not expand' };
    limitations.push('A DOCTYPE declaration is present and was skipped: no external definition is fetched and no entity is expanded');
  }
  const entities = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
  const decode = (raw) => raw.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body) => {
    if (body.startsWith('#x') || body.startsWith('#X')) return String.fromCodePoint(Number.parseInt(body.slice(2), 16));
    if (body.startsWith('#')) return String.fromCodePoint(Number.parseInt(body.slice(1), 10));
    return Object.hasOwn(entities, body) ? entities[body] : whole;
  });

  const root = { name: '#document', attributes: {}, children: [], text: '' };
  const stack = [root];
  let nodes = 0;
  let index = 0;
  while (index < text.length) {
    const open = text.indexOf('<', index);
    if (open < 0) break;
    if (open > index) {
      const chunk = text.slice(index, open);
      if (chunk.trim()) stack[stack.length - 1].text += decode(chunk);
    }
    if (text.startsWith('<!--', open)) {
      const end = text.indexOf('-->', open + 4);
      if (end < 0) return { ok: false, reason: 'unterminated_comment', detail: 'A comment is not closed' };
      index = end + 3; continue;
    }
    if (text.startsWith('<![CDATA[', open)) {
      const end = text.indexOf(']]>', open + 9);
      if (end < 0) return { ok: false, reason: 'unterminated_cdata', detail: 'A CDATA section is not closed' };
      // CDATA is verbatim: a p-code body is kept exactly as written, never decoded a second time.
      stack[stack.length - 1].text += text.slice(open + 9, end);
      index = end + 3; continue;
    }
    if (text.startsWith('<?', open) || text.startsWith('<!', open)) {
      const end = text.indexOf('>', open);
      if (end < 0) return { ok: false, reason: 'unterminated_declaration', detail: 'A declaration is not closed' };
      index = end + 1; continue;
    }
    const end = (() => {
      // A `>` inside a quoted attribute value is content, not the end of the tag.
      let quote = null;
      for (let i = open + 1; i < text.length; i++) {
        const ch = text[i];
        if (quote) { if (ch === quote) quote = null; continue; }
        if (ch === '"' || ch === "'") { quote = ch; continue; }
        if (ch === '>') return i;
      }
      return -1;
    })();
    if (end < 0) return { ok: false, reason: 'unterminated_tag', detail: 'An element tag is not closed' };
    const body = text.slice(open + 1, end);
    index = end + 1;
    if (body.startsWith('/')) {
      const name = body.slice(1).trim();
      if (stack.length < 2) return { ok: false, reason: 'unbalanced_tag', detail: 'A closing tag has no matching open tag' };
      const closing = stack.pop();
      if (closing.name !== name) return { ok: false, reason: 'mismatched_tag', detail: `Closing tag ${name} does not match open tag ${closing.name}` };
      continue;
    }
    const selfClosing = body.endsWith('/');
    const inner = selfClosing ? body.slice(0, -1) : body;
    const nameMatch = /^([A-Za-z_][A-Za-z0-9_.:-]*)/.exec(inner);
    if (!nameMatch) return { ok: false, reason: 'invalid_element_name', detail: 'An element name is not a valid XML name' };
    if (++nodes > MAX_XML_NODES) return { ok: false, reason: 'too_many_elements', detail: `The file declares more than ${MAX_XML_NODES} elements` };
    const node = { name: nameMatch[1], attributes: {}, children: [], text: '' };
    const attributePattern = /([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
    let attribute;
    while ((attribute = attributePattern.exec(inner.slice(nameMatch[1].length))) !== null) {
      node.attributes[attribute[1]] = decode(attribute[3] ?? attribute[4] ?? '');
    }
    stack[stack.length - 1].children.push(node);
    if (!selfClosing) {
      if (stack.length >= MAX_XML_DEPTH) return { ok: false, reason: 'too_deep', detail: `Element nesting exceeds ${MAX_XML_DEPTH}` };
      stack.push(node);
    }
  }
  if (stack.length !== 1) return { ok: false, reason: 'unbalanced_tag', detail: `Element ${stack[stack.length - 1].name} is never closed` };
  const element = root.children.find((child) => child.name);
  if (!element) return { ok: false, reason: 'no_root_element', detail: 'The file contains no XML element' };
  return { ok: true, root: element, nodes };
}

const kids = (node, name) => node.children.filter((child) => child.name === name);
const kid = (node, name) => node.children.find((child) => child.name === name) ?? null;

/** Every `<x value="N"/>` child, which is how data_organization spells a scalar. */
function valueChildren(node, names) {
  const out = {};
  for (const name of names) {
    const child = kid(node, name);
    out[name] = child ? integer(child.attributes.value) : null;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// .sla, the compiled form
// ---------------------------------------------------------------------------------------------

/**
 * Walk a PackedFormat stream as events, without building a tree.
 *
 * The largest shipped table is 2.23M events and would be a multi-million node object; nothing here
 * needs the whole tree at once, so the walk hands out open/attribute/close and the callers keep the
 * little state they need. The 7 attribute type codes and the two-byte id extension come from
 * `marshal.hh`; a header whose top two bits are 00 cannot occur in a valid stream, because every
 * byte of the encoding is non-zero and carries one of the three record headers.
 */
function* slaEvents(bytes) {
  let position = 0;
  let steps = 0;
  while (position < bytes.length) {
    if (++steps > MAX_EVENTS) { yield { kind: 'overflow' }; return; }
    const header = bytes[position++];
    const record = header & 0xc0;
    let id = header & 0x1f;
    if (header & 0x20) {
      if (position >= bytes.length) { yield { kind: 'truncated' }; return; }
      id = (id << 7) | (bytes[position++] & 0x7f);
    }
    if (record === 0x40) { yield { kind: 'open', id, name: SLA_ELEMENTS[id] ?? `element${id}` }; continue; }
    if (record === 0x80) { yield { kind: 'close', id, name: SLA_ELEMENTS[id] ?? `element${id}` }; continue; }
    if (record !== 0xc0) { yield { kind: 'invalid', offset: position - 1, byte: header }; return; }
    if (position >= bytes.length) { yield { kind: 'truncated' }; return; }
    const typeByte = bytes[position++];
    const type = typeByte >> 4;
    const lengthCode = typeByte & 0x0f;
    const name = SLA_ATTRIBUTES[id] ?? `attribute${id}`;
    if (type === 1) { yield { kind: 'attribute', id, name, value: lengthCode === 1 }; continue; }
    if (type === 6) { yield { kind: 'attribute', id, name, value: SLA_SPECIAL_SPACES[lengthCode] ?? `special${lengthCode}` }; continue; }
    if (type < 2 || type > 7) { yield { kind: 'invalid', offset: position - 1, byte: typeByte }; return; }
    if (position + lengthCode > bytes.length) { yield { kind: 'truncated' }; return; }
    // Seven bits of payload per byte, most significant first. A length code of zero encodes zero.
    let raw = 0n;
    for (let i = 0; i < lengthCode; i++) raw = (raw << 7n) | BigInt(bytes[position + i] & 0x7f);
    position += lengthCode;
    if (type === 7) {
      const length = Number(raw);
      if (position + length > bytes.length) { yield { kind: 'truncated' }; return; }
      yield { kind: 'attribute', id, name, value: bytes.subarray(position, position + length).toString('utf8') };
      position += length;
      continue;
    }
    // A uniqbase or uniqmask can exceed the safe integer range, and a silently rounded mask is a
    // wrong fact. Anything past 2^53-1 is reported as a hex string, which stays exact.
    const value = type === 3 ? -Number(raw) : (raw <= 9007199254740991n ? Number(raw) : `0x${raw.toString(16)}`);
    yield { kind: 'attribute', id, name, value };
  }
}

/** Inflate the zlib stream a `.sla` wraps, after checking the four byte header. */
function openSla(bytes) {
  if (bytes.length < 6 || bytes[0] !== 0x73 || bytes[1] !== 0x6c || bytes[2] !== 0x61) {
    return { ok: false, reason: 'not_a_sla', detail: 'A compiled SLEIGH table starts with the bytes "sla"' };
  }
  if (bytes[3] !== SLA_FORMAT_VERSION) {
    return { ok: false, reason: 'unsupported_format_version', detail: `This reader decodes .sla format version ${SLA_FORMAT_VERSION}; the file declares ${bytes[3]}`, version: bytes[3] };
  }
  try {
    return { ok: true, flat: inflateSync(bytes.subarray(4), { maxOutputLength: MAX_INFLATED }), version: bytes[3] };
  } catch (error) {
    const tooLarge = error?.code === 'ERR_BUFFER_TOO_LARGE';
    return { ok: false, version: bytes[3],
      reason: tooLarge ? 'inflated_too_large' : 'inflate_failed',
      detail: tooLarge ? `The compressed stream expands past the ${MAX_INFLATED} byte decode budget` : 'The compressed stream could not be inflated' };
  }
}

/**
 * The facts a compiled table records about itself.
 *
 * Walked once, collecting the root attributes, the address space table, the contributing source
 * files, and the named symbols whose names live on the `*_head` elements the symbol table writes
 * before each full symbol. Element counts come along because they are the cheapest honest measure
 * of what else is in the file that this reader is not reporting.
 */
function readSlaTables(flat) {
  const counts = new Map();
  const spaces = [];
  const sourceFiles = [];
  const registers = [];
  const userops = [];
  const subtables = [];
  const stack = [];
  const root = {};
  let current = null;
  let defaultSpace = null;
  let truncated = null;
  let maxDepth = 0;

  for (const event of slaEvents(flat)) {
    if (event.kind === 'overflow') { truncated = 'event_budget'; break; }
    if (event.kind === 'truncated') { truncated = 'stream_ended_mid_record'; break; }
    if (event.kind === 'invalid') { truncated = 'invalid_record'; break; }
    if (event.kind === 'open') {
      counts.set(event.name, (counts.get(event.name) ?? 0) + 1);
      current = { element: event.name, attributes: {} };
      stack.push(current);
      if (stack.length > maxDepth) maxDepth = stack.length;
      continue;
    }
    if (event.kind === 'close') {
      const closed = stack.pop();
      current = stack[stack.length - 1] ?? null;
      if (!closed) { truncated = 'unbalanced_element'; break; }
      const a = closed.attributes;
      if (closed.element === 'sleigh') Object.assign(root, a);
      else if (closed.element === 'spaces' && a.defaultspace !== undefined) defaultSpace = a.defaultspace;
      else if (closed.element === 'space' || closed.element === 'space_other' || closed.element === 'space_unique') {
        spaces.push({ name: a.name ?? null, index: a.index ?? null, size: a.size ?? null,
          wordSize: a.wordsize ?? 1, delay: a.delay ?? null, physical: a.physical ?? null,
          kind: closed.element === 'space_unique' ? 'unique' : closed.element === 'space_other' ? 'other' : 'addressable' });
      } else if (closed.element === 'sourcefile' && typeof a.name === 'string') sourceFiles.push({ name: a.name, index: a.index ?? null });
      else if (closed.element === 'varnode_sym_head' && typeof a.name === 'string') registers.push({ name: a.name, id: a.id ?? null, scope: a.scope ?? null });
      else if (closed.element === 'userop_head' && typeof a.name === 'string') userops.push({ name: a.name, id: a.id ?? null });
      else if (closed.element === 'subtable_sym_head' && typeof a.name === 'string') subtables.push({ name: a.name, id: a.id ?? null });
      continue;
    }
    if (current) current.attributes[event.name] = event.value;
  }

  return { root, defaultSpace, spaces, sourceFiles, registers, userops, subtables, counts, truncated, maxDepth };
}

// ---------------------------------------------------------------------------------------------
// SLEIGH source
// ---------------------------------------------------------------------------------------------

/**
 * SLEIGH source, read with its preprocessor stack intact rather than evaluated.
 *
 * A `.slaspec` is not self-describing: `define endian=$(ENDIAN);` is the normal way the ARM family
 * states endianness, and the value arrives from whichever thin variant file did the `@include`.
 * Evaluating that would mean choosing a variant and presenting the result as the file's meaning,
 * when the file has 22 meanings. So every declaration carries the `@if` conditions in force where
 * it was written, and a value that is still a `$(MACRO)` is reported as the macro it is.
 *
 * Directives are recognised only at the start of a line, which is what the SLEIGH preprocessor
 * requires, and a `#` comment runs to end of line. Statements end at `;` and may span lines, so a
 * declaration is matched against the joined statement rather than a single line.
 */
function readSleighSource(text) {
  const defines = [];
  const includes = [];
  const spaces = [];
  const registers = [];
  const tokens = [];
  const contextFields = [];
  const pcodeops = [];
  const attaches = [];
  const mnemonics = [];
  const subtables = new Set();
  const macros = [];
  let endian = null;
  let alignment = null;
  const guards = [];
  const conditionalCount = { directives: 0, guardedDeclarations: 0 };

  /**
   * A `#` starts a comment only outside a quoted literal.
   *
   * The display section of a constructor quotes literal punctuation, and `#` is the immediate
   * marker in 68000, ARM and MSP430 assembly: `:addq.b "#"^quick,eab is ...`. Cutting from the
   * first `#` therefore truncated the line to `:addq.b "`, which lost the `is` and with it the
   * constructor — 214 of them across the corpus, concentrated in exactly the processors whose
   * syntax uses `#`.
   */
  const stripComment = (line) => {
    let quoted = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') quoted = !quoted;
      else if (ch === '#' && !quoted) return line.slice(0, i);
    }
    return line;
  };

  // Lines first. A directive moves the guard stack and contributes no statement; every other line
  // carries the stack that was in force where it was written. The snapshot is shared until the
  // stack actually changes, and is never mutated afterwards, so a statement can hold a reference.
  const lines = text.split(/\r?\n/);
  const body = [];
  let snapshot = [];
  for (const line of lines) {
    const directive = /^@(define|undef|include|if|ifdef|ifndef|elif|else|endif)\b[ \t]*(.*)$/.exec(line);
    if (directive) {
      conditionalCount.directives++;
      const [, keyword, rest] = directive;
      const argument = stripComment(rest).trim();
      if (keyword === 'define') {
        const named = /^([A-Za-z_][A-Za-z0-9_]*)[ \t]*(?:"([^"]*)"|(\S+))?$/.exec(argument);
        if (named) defines.push({ name: named[1], value: named[2] ?? named[3] ?? '', flag: named[2] === '' || (named[2] === undefined && named[3] === undefined), guards: snapshot });
      } else if (keyword === 'undef') defines.push({ name: argument, value: null, flag: false, removed: true, guards: snapshot });
      else if (keyword === 'include') {
        const quoted = /^"([^"]*)"/.exec(argument);
        if (quoted) includes.push({ file: quoted[1], guards: snapshot });
      } else {
        if (keyword === 'if' || keyword === 'ifdef' || keyword === 'ifndef') {
          guards.push(keyword === 'ifdef' ? `defined(${argument})` : keyword === 'ifndef' ? `!defined(${argument})` : argument);
        } else if (keyword === 'elif') { guards.pop(); guards.push(argument); }
        else if (keyword === 'else') { const previous = guards.pop(); guards.push(`!(${previous ?? 'unknown'})`); }
        else guards.pop();
        snapshot = [...guards];
      }
      continue;
    }
    body.push({ text: stripComment(line), guards: snapshot });
  }

  /**
   * A `;` only ends a statement outside a bracketed list.
   *
   * This is the correction that matters most here. SLEIGH spends `;` twice: it terminates a
   * declaration, and inside a constructor it is the sequential-token operator — `is ... &
   * evexV5_XmmReg; byte=0x58; ...` — and it separates assignments inside a `[ ... ]` disassembly
   * action. Splitting the file on every `;` therefore chopped constructors into fragments and
   * glued the next declaration onto the tail of one, which silently lost 4,843 of the corpus's
   * 7,082 `define pcodeop` declarations: only a declaration with nothing before it still matched.
   * Statements are instead anchored at a line that opens one, and a bracketed list is skipped
   * over when looking for the terminator.
   */
  const terminatorAt = (candidate) => {
    let depth = 0;
    let quoted = false;
    for (let i = 0; i < candidate.length; i++) {
      const ch = candidate[i];
      // A literal is confined to one line, so a newline closes an unbalanced quote rather than
      // letting it swallow the rest of the statement.
      if (ch === '\n') { quoted = false; continue; }
      if (ch === '"') { quoted = !quoted; continue; }
      if (quoted) continue;
      if (ch === '[') depth++;
      else if (ch === ']') { if (depth > 0) depth--; }
      else if (ch === ';' && depth === 0) return i;
    }
    return -1;
  };
  // A name list or token field list runs over many lines; past this a statement is malformed
  // rather than long, and those are counted instead of being absorbed silently.
  const MAX_STATEMENT_LINES = 512;
  const OPENS_DECLARATION = /^[ \t]*(?:define|attach)\b/;
  const statements = [];
  let unterminated = 0;
  for (let index = 0; index < body.length; index++) {
    if (!OPENS_DECLARATION.test(body[index].text)) continue;
    const guardsHere = body[index].guards;
    let buffer = body[index].text;
    let line = index;
    for (;;) {
      let cut = terminatorAt(buffer);
      while (cut < 0 && line + 1 < body.length && line - index < MAX_STATEMENT_LINES) {
        line++;
        buffer += `\n${body[line].text}`;
        cut = terminatorAt(buffer);
      }
      if (cut < 0) { unterminated++; break; }
      statements.push({ text: buffer.slice(0, cut), guards: guardsHere });
      // Two declarations can share a line, so the tail is re-examined rather than dropped.
      buffer = buffer.slice(cut + 1);
      if (!OPENS_DECLARATION.test(buffer)) break;
    }
    index = line;
  }

  // A SLEIGH identifier is `[a-zA-Z_.][a-zA-Z0-9_.]*` — slghscan.l:514. The dot is not decoration:
  // Loongarch, the MIPS DSP extension and the RISC-V custom sets name userops `xvfmadd.s` and the
  // like, and a pattern without it silently drops 1,777 of the corpus's declarations.
  const note = (guardList) => { if (guardList.length) conditionalCount.guardedDeclarations++; };

  for (const statement of statements) {
    const body = statement.text.replace(/\s+/g, ' ').trim();
    if (!body) continue;
    let match;
    if ((match = /^define endian\s*=\s*(\S+)$/.exec(body)) !== null) {
      note(statement.guards);
      const value = match[1];
      endian = { value, macro: /^\$\(/.test(value) ? value : null, guards: statement.guards };
    } else if ((match = /^define alignment\s*=\s*(\S+)$/.exec(body)) !== null) {
      note(statement.guards);
      alignment = { value: integer(match[1]), text: match[1], macro: /^\$\(/.test(match[1]) ? match[1] : null, guards: statement.guards };
    } else if ((match = /^define space ([A-Za-z_.][A-Za-z0-9_.]*) (.*)$/.exec(body)) !== null) {
      note(statement.guards);
      const attributes = {};
      for (const pair of match[2].matchAll(/([a-z]+)\s*=\s*(\S+)/g)) attributes[pair[1]] = pair[2];
      spaces.push({ name: match[1], type: attributes.type ?? null, size: integer(attributes.size),
        wordSize: integer(attributes.wordsize) ?? 1, default: /\bdefault\b/.test(match[2]), guards: statement.guards });
    } else if ((match = /^define ([A-Za-z_.][A-Za-z0-9_.]*) offset\s*=\s*(\S+) size\s*=\s*(\S+) \[(.*)\]$/.exec(body)) !== null) {
      // `define register` is not special: the production is `define <spacename> offset= size= [names]`,
      // and the corpus really does use RAM, mem, sysreg and csreg as the space.
      note(statement.guards);
      const offset = integer(match[2]);
      const size = integer(match[3]);
      const names = match[4].trim().split(/\s+/).filter(Boolean);
      let cursor = 0;
      for (const name of names) {
        // `_` is a declared gap in the name list, and still consumes its slot.
        if (name !== '_') registers.push({ name, space: match[1], offset: offset === null || size === null ? null : offset + cursor * size, size, guards: statement.guards });
        cursor++;
      }
      if (offset === null) registers.push({ name: null, space: match[1], offset: null, size, unresolvedOffset: match[2], guards: statement.guards });
    } else if ((match = /^define token ([A-Za-z_.][A-Za-z0-9_.]*) ?\( ?(\d+) ?\)(.*)$/.exec(body)) !== null) {
      note(statement.guards);
      const fields = [...match[3].matchAll(/([A-Za-z_.][A-Za-z0-9_.]*)\s*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)((?:\s+(?:signed|hex|dec|noflow))*)/g)];
      tokens.push({ name: match[1], bits: integer(match[2]), guards: statement.guards,
        fields: fields.map((field) => ({ name: field[1], low: integer(field[2]), high: integer(field[3]), qualifiers: field[4].trim().split(/\s+/).filter(Boolean) })) });
    } else if ((match = /^define context ([A-Za-z_.][A-Za-z0-9_.]*)(.*)$/.exec(body)) !== null) {
      note(statement.guards);
      for (const field of match[2].matchAll(/([A-Za-z_.][A-Za-z0-9_.]*)\s*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)((?:\s+(?:signed|hex|dec|noflow))*)/g)) {
        contextFields.push({ name: field[1], varnode: match[1], low: integer(field[2]), high: integer(field[3]),
          qualifiers: field[4].trim().split(/\s+/).filter(Boolean), guards: statement.guards });
      }
    } else if ((match = /^define pcodeop ([A-Za-z_.][A-Za-z0-9_.]*)$/.exec(body)) !== null) {
      note(statement.guards);
      pcodeops.push({ name: match[1], guards: statement.guards });
    } else if ((match = /^define bitrange (.*)$/.exec(body)) !== null) {
      note(statement.guards);
      for (const entry of match[1].matchAll(/([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\[\s*(\d+)\s*,\s*(\d+)\s*\]/g)) {
        registers.push({ name: entry[1], space: 'bitrange', offset: null, size: null,
          basedOn: entry[2], startBit: integer(entry[3]), bitCount: integer(entry[4]), guards: statement.guards });
      }
    } else if ((match = /^attach (variables|names|values) \[?([^\]]*?)\]? ?\[(.*)\]$/.exec(body)) !== null) {
      note(statement.guards);
      attaches.push({ kind: match[1], fields: match[2].trim().split(/\s+/).filter(Boolean),
        values: match[3].trim().split(/\s+/).filter(Boolean).map((entry) => entry.replace(/^"|"$/g, '')), guards: statement.guards });
    }
  }

  // Constructors and macros are not `;`-terminated, so they are matched against lines. A line
  // beginning `:` defines an instruction and the first display token is its mnemonic; `TABLE:`
  // defines or extends a subtable. Both are matched before `is`, because everything after it is a
  // pattern, and a `{ ... }` semantic body is skipped so a brace-nested line is never taken for a
  // new constructor.
  /**
   * How much a line changes semantic-body depth.
   *
   * A `with` block groups constructors under a shared pattern — `with : TMode=0 { ... }` — so its
   * brace is a container and not a body. Counting it as a body hid every constructor inside one,
   * and x86, ARM and AARCH64 all use them, which cost 4,915 of the corpus's 27,774 constructors.
   *
   * A brace inside a quoted literal is display text, not a delimiter: ARM and THUMB write a
   * register list as `"{"^reglist^"}"`, and counting those unbalanced the depth and swallowed the
   * constructors that followed.
   */
  const braceDelta = (line) => {
    let delta = 0;
    let quoted = false;
    for (const ch of line) {
      if (ch === '"') quoted = !quoted;
      else if (quoted) continue;
      else if (ch === '{') delta++;
      else if (ch === '}') delta--;
    }
    return /^with\b/.test(line) ? delta - 1 : delta;
  };
  let inBlock = 0;
  for (let index = 0; index < body.length; index++) {
    const stripped = body[index].text;
    const macro = /^macro\s+([A-Za-z_.][A-Za-z0-9_.]*)\s*\(([^)]*)\)/.exec(stripped);
    if (inBlock === 0 && macro) {
      note(body[index].guards);
      macros.push({ name: macro[1], parameters: macro[2].split(',').map((p) => p.trim()).filter(Boolean), guards: body[index].guards });
    }
    if (inBlock > 0) {
      inBlock = Math.max(0, inBlock + braceDelta(stripped));
      continue;
    }
    const head = /^([A-Za-z_.][A-Za-z0-9_.]*)?:[ \t]*([^ \t,]*)/.exec(stripped);
    if (head) {
      // `is` can sit on a later line than the display section. AARCH64sve.sinc writes all 7,405 of
      // its constructors that way, so requiring the two on one line found none of them and made a
      // file of nothing but constructors look like a file with no SLEIGH in it at all. The
      // lookahead stops at a body or action block, so it cannot run past the constructor it is
      // confirming and pick up an `is` belonging to the next one.
      let confirmed = /\bis\b/.test(stripped);
      for (let ahead = index + 1; !confirmed && ahead < body.length && ahead - index <= 8; ahead++) {
        const next = body[ahead].text;
        // `is` is tested before the stop condition, because the `is` line normally carries the
        // opening brace of the semantic body or the bracket of an action block. Stopping on those
        // first rejected the constructor whose `is` was on the very line being examined.
        if (/\bis\b/.test(next)) { confirmed = true; break; }
        if (/[{[]/.test(next) || /^[A-Za-z_.]*:/.test(next.trimStart())) break;
      }
      if (confirmed) {
        if (head[1]) subtables.add(head[1]);
        else if (head[2]) mnemonics.push({ mnemonic: head[2].replace(/\^$/, ''), line: stripped.trim().slice(0, 192) });
      }
    }
    inBlock = Math.max(0, inBlock + braceDelta(stripped));
  }

  return { endian, alignment, defines, includes, spaces, registers, tokens, contextFields, pcodeops,
    attaches, macros, mnemonics, subtables: [...subtables].sort(), conditionalCount, unterminated };
}

// ---------------------------------------------------------------------------------------------
// .opinion matching, which is the loader's language decision
// ---------------------------------------------------------------------------------------------

/**
 * Flatten an opinion tree into the constraint rows a loader actually matches against.
 *
 * The file is a tree only to share attributes: an inner `constraint` inherits everything its
 * ancestors set, and the leaf rows are the decision table. Flattening is therefore the whole
 * semantics, and once flattened a row says plainly which processor a PE machine type selects.
 */
function flattenOpinions(root) {
  const rows = [];
  const walk = (node, inherited, depth) => {
    if (depth > MAX_XML_DEPTH) return;
    const merged = { ...inherited };
    for (const [key, value] of Object.entries(node.attributes)) merged[key] = value;
    const children = kids(node, 'constraint');
    if (!children.length) rows.push(merged);
    else for (const child of children) walk(child, merged, depth + 1);
  };
  for (const child of kids(root, 'constraint')) walk(child, {}, 1);
  return rows;
}

/**
 * Match a secondary key the three ways the format documents, and no fourth way.
 *
 * `0b` is a bit pattern where `.` is a wildcard and spaces and underscores are formatting; `0x` is
 * an exact hex value; anything else is a literal string. The documentation is inline in
 * `ARM.opinion`, and a key that does not parse as its prefix claims is reported unmatched rather
 * than falling back to a string compare that would match for the wrong reason.
 */
function secondaryMatches(constraint, query) {
  if (constraint === undefined || constraint === null) return { matched: true, how: 'unconstrained' };
  if (query === undefined || query === null) return { matched: false, how: 'no_query_key' };
  const pattern = String(constraint).trim();
  if (/^0b/i.test(pattern)) {
    const bits = pattern.slice(2).replace(/[ _]/g, '');
    if (!/^[01.]+$/.test(bits)) return { matched: false, how: 'invalid_bit_pattern' };
    const value = integer(query, { hex: true });
    if (value === null) return { matched: false, how: 'query_not_numeric' };
    const text = value.toString(2).padStart(bits.length, '0');
    if (text.length > bits.length) return { matched: false, how: 'bits' };
    for (let i = 0; i < bits.length; i++) if (bits[i] !== '.' && bits[i] !== text[i]) return { matched: false, how: 'bits' };
    return { matched: true, how: 'bits' };
  }
  if (/^0x/i.test(pattern)) {
    const left = integer(pattern), right = integer(query, { hex: true });
    return { matched: left !== null && left === right, how: 'hex' };
  }
  return { matched: pattern === String(query), how: 'string' };
}

// ---------------------------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------------------------

export function makeGhidraTools() {
  const pathOnly = object({ path: string });
  const base = (relative, bytes) => ({ path: relative, sha256: sha256(bytes), untrusted: true });
  const decoder = new TextDecoder('utf-8', { fatal: false });

  /** Shared preamble for the four XML types: read, decode, parse, or refuse without throwing. */
  const xml = (context, relative, divisor, expectedRoot) => {
    const bytes = readBytes(context, relative, divisor);
    const limitations = [];
    const parsed = parseXml(decoder.decode(bytes), limitations);
    if (!parsed.ok) return { bytes, limitations, failure: { reason: parsed.reason, detail: parsed.detail } };
    if (parsed.root.name !== expectedRoot) {
      return { bytes, limitations, failure: { reason: 'unexpected_root_element', detail: `Expected a <${expectedRoot}> root element and found <${parsed.root.name}>` } };
    }
    return { bytes, limitations, root: parsed.root };
  };

  return [
    {
      name: 'artifact.ghidraLanguages', version: '1.0.0', effect: 'read', inputSchema: pathOnly,
      outputKeys: ['path', 'sha256', 'supported', 'reason', 'languages', 'counts', 'limitations', 'untrusted'],
      execute({ path: relative }, context) {
        const { bytes, limitations, failure, root } = xml(context, relative, 8, 'language_definitions');
        if (failure) return { ...base(relative, bytes), supported: false, ...failure, languages: [], counts: { languages: 0, compilers: 0 }, limitations };
        const languages = kids(root, 'language').map((node) => {
          const a = node.attributes;
          const compilers = kids(node, 'compiler').map((c) => ({ name: c.attributes.name ?? null, spec: c.attributes.spec ?? null, id: c.attributes.id ?? null }));
          const truncate = kid(node, 'truncate_space');
          return {
            id: a.id ?? null, processor: a.processor ?? null, endian: a.endian ?? null,
            // An instruction endianness that differs from the data endianness is the LEBE case, and
            // it is the reason an id cannot be rebuilt from processor, size and variant alone.
            instructionEndian: a.instructionEndian ?? null,
            size: integer(a.size), variant: a.variant ?? null, version: a.version ?? null,
            slaFile: a.slafile ?? null, processorSpec: a.processorspec ?? null,
            manualIndex: a.manualindexfile ?? null,
            hidden: bool(a.hidden) ?? false, deprecated: bool(a.deprecated) ?? false,
            description: (kid(node, 'description')?.text ?? '').trim() || null,
            truncateSpace: truncate ? { space: truncate.attributes.space ?? null, size: integer(truncate.attributes.size) } : null,
            // The first compiler element is the default; order is load-bearing, so it is preserved
            // and the default is named rather than left to be inferred from position.
            defaultCompiler: compilers.length ? compilers[0].id : null,
            compilers,
            externalNames: kids(node, 'external_name').map((e) => ({ tool: e.attributes.tool ?? null, name: e.attributes.name ?? null })),
          };
        });
        const counts = { languages: languages.length, compilers: languages.reduce((sum, l) => sum + l.compilers.length, 0) };
        limitations.push('A language entry names the .sla, .pspec and .cspec files it needs; those files are not read here, and this tool does not check that they exist');
        return { ...base(relative, bytes), supported: true, reason: null,
          languages: listed(languages, limitations, 'languages'), counts, limitations };
      },
    },
    {
      name: 'artifact.ghidraProcessorSpec', version: '1.0.0', effect: 'read', inputSchema: pathOnly,
      outputKeys: ['path', 'sha256', 'supported', 'reason', 'programCounter', 'registers', 'symbols', 'memoryBlocks', 'contextFields', 'volatileRanges', 'incidentalCopy', 'properties', 'counts', 'limitations', 'untrusted'],
      execute({ path: relative }, context) {
        const { bytes, limitations, failure, root } = xml(context, relative, 4, 'processor_spec');
        const empty = { programCounter: null, registers: [], symbols: [], memoryBlocks: [], contextFields: [], volatileRanges: [], incidentalCopy: [], properties: [] };
        if (failure) return { ...base(relative, bytes), supported: false, ...failure, ...empty, counts: {}, limitations };
        const registerData = kid(root, 'register_data') ?? { children: [] };
        const registers = kids(registerData, 'register').map((node) => {
          const a = node.attributes;
          return { name: a.name ?? null, rename: a.rename ?? null, alias: a.alias ?? null, group: a.group ?? null,
            hidden: bool(a.hidden) ?? false, volatile: bool(a.volatile) ?? false,
            vectorLaneSizes: a.vector_lane_sizes ? a.vector_lane_sizes.split(',').map((s) => integer(s)) : [] };
        });
        const symbols = kids(kid(root, 'default_symbols') ?? { children: [] }, 'symbol').map((node) => {
          const a = node.attributes;
          return { name: a.name ?? null, address: address(a.address), size: integer(a.size),
            entry: bool(a.entry) ?? false, volatile: bool(a.volatile) ?? false,
            type: a.type ?? null, description: a.description ?? null };
        });
        const memoryBlocks = kids(kid(root, 'default_memory_blocks') ?? { children: [] }, 'memory_block').map((node) => {
          const a = node.attributes;
          const mapping = a.bit_mapped_address !== undefined ? { kind: 'bit_mapped', target: a.bit_mapped_address }
            : a.byte_mapped_address !== undefined ? { kind: 'byte_mapped', target: a.byte_mapped_address }
              : { kind: 'initialized', target: null };
          return { name: a.name ?? null, start: address(a.start_address), length: integer(a.length),
            mapping, initialized: bool(a.initialized), mode: a.mode ?? null, overlay: bool(a.overlay) ?? false };
        });
        const contextData = kid(root, 'context_data') ?? { children: [] };
        const contextFields = [];
        for (const group of [...kids(contextData, 'context_set'), ...kids(contextData, 'tracked_set')]) {
          for (const set of kids(group, 'set')) {
            contextFields.push({ kind: group.name === 'context_set' ? 'context' : 'tracked',
              space: group.attributes.space ?? null, first: integer(group.attributes.first), last: integer(group.attributes.last),
              name: set.attributes.name ?? null, value: integer(set.attributes.val), description: set.attributes.description ?? null });
          }
        }
        const volatileNode = kid(root, 'volatile');
        const volatileRanges = volatileNode ? [
          ...kids(volatileNode, 'range').map((node) => ({ kind: 'range', space: node.attributes.space ?? null, first: integer(node.attributes.first), last: integer(node.attributes.last), register: null })),
          ...kids(volatileNode, 'register').map((node) => ({ kind: 'register', space: null, first: null, last: null, register: node.attributes.name ?? null })),
        ] : [];
        const properties = kids(kid(root, 'properties') ?? { children: [] }, 'property').map((node) => ({ key: node.attributes.key ?? null, value: node.attributes.value ?? null }));
        // incidentalcopy registers are the ones a copy through them should not be treated as real
        // dataflow — x86's eight x87 stack slots are the whole corpus population. They are a
        // separate declaration from register_data, so they are reported separately rather than
        // folded into the register list or left out of the output entirely.
        const incidentalNode = kid(root, 'incidentalcopy');
        const incidentalCopy = incidentalNode ? [
          ...kids(incidentalNode, 'register').map((node) => ({ kind: 'register', register: node.attributes.name ?? null, space: null, offset: null, size: null })),
          ...kids(incidentalNode, 'varnode').map((node) => ({ kind: 'varnode', register: null, space: node.attributes.space ?? null, offset: integer(node.attributes.offset), size: integer(node.attributes.size) })),
        ] : [];

        const counts = { registers: registers.length, symbols: symbols.length, entryPoints: symbols.filter((s) => s.entry).length,
          memoryBlocks: memoryBlocks.length, contextFields: contextFields.length, volatileRanges: volatileRanges.length,
          incidentalCopy: incidentalCopy.length, properties: properties.length };
        if (registers.some((r) => r.rename)) limitations.push('A register is renamed here, so later references in this file and in any compiler spec use the new name');
        limitations.push('A p-code body inside a segmentop or jumpassist is not interpreted: it is SLEIGH semantic text, and this tool reports structure rather than executing it');
        return { ...base(relative, bytes), supported: true, reason: null,
          programCounter: kid(root, 'programcounter')?.attributes.register ?? null,
          registers: listed(registers, limitations, 'registers'),
          symbols: listed(symbols, limitations, 'default symbols'),
          memoryBlocks: listed(memoryBlocks, limitations, 'memory blocks'),
          contextFields: listed(contextFields, limitations, 'context fields'),
          volatileRanges, incidentalCopy, properties, counts, limitations };
      },
    },
    {
      name: 'artifact.ghidraCompilerSpec', version: '1.0.0', effect: 'read', inputSchema: pathOnly,
      outputKeys: ['path', 'sha256', 'supported', 'reason', 'dataOrganization', 'stackPointer', 'returnAddress', 'conventions', 'defaultConvention', 'globals', 'callFixups', 'counts', 'limitations', 'untrusted'],
      execute({ path: relative }, context) {
        const { bytes, limitations, failure, root } = xml(context, relative, 4, 'compiler_spec');
        const empty = { dataOrganization: null, stackPointer: null, returnAddress: null, conventions: [], defaultConvention: null, globals: [], callFixups: [] };
        if (failure) return { ...base(relative, bytes), supported: false, ...failure, ...empty, counts: {}, limitations };

        const organizationNode = kid(root, 'data_organization');
        const dataOrganization = organizationNode ? (() => {
          const scalars = valueChildren(organizationNode, ['absolute_max_alignment', 'machine_alignment',
            'default_alignment', 'default_pointer_alignment', 'pointer_size', 'pointer_shift', 'char_size',
            'wchar_size', 'short_size', 'integer_size', 'long_size', 'long_long_size', 'float_size',
            'double_size', 'long_double_size']);
          const packingNode = kid(organizationNode, 'bitfield_packing');
          return {
            ...scalars,
            charSigned: bool(kid(organizationNode, 'char_type')?.attributes.signed),
            sizeAlignmentMap: kids(kid(organizationNode, 'size_alignment_map') ?? { children: [] }, 'entry')
              .map((node) => ({ size: integer(node.attributes.size), alignment: integer(node.attributes.alignment) })),
            // use_MS_convention is the discriminator between the MSVC and GCC bitfield layouts, and
            // is the one field here that identifies a toolchain rather than a width.
            bitfieldPacking: packingNode ? valueChildren(packingNode, ['use_MS_convention', 'type_alignment_enabled', 'zero_length_boundary']) : null,
          };
        })() : null;

        const readStorage = (node) => {
          const register = kid(node, 'register');
          if (register) return { kind: 'register', register: register.attributes.name ?? null, space: null, offset: null, size: null, pieces: [] };
          const varnode = kid(node, 'varnode');
          if (varnode) return { kind: 'varnode', register: null, space: varnode.attributes.space ?? null, offset: integer(varnode.attributes.offset), size: integer(varnode.attributes.size), pieces: [] };
          const addr = kid(node, 'addr');
          if (addr) {
            // A join space address concatenates registers, which is how a value wider than one
            // register is returned; the piece order is the layout and is kept.
            const pieces = Object.keys(addr.attributes).filter((key) => /^piece[1-9]$/.test(key)).sort()
              .map((key) => addr.attributes[key]);
            return { kind: addr.attributes.space === 'join' ? 'join' : 'address', register: null,
              space: addr.attributes.space ?? null, offset: integer(addr.attributes.offset), size: null, pieces };
          }
          return { kind: 'unknown', register: null, space: null, offset: null, size: null, pieces: [] };
        };
        const readGroup = (node) => kids(node, 'pentry').map((entry) => ({
          minSize: integer(entry.attributes.minsize), maxSize: integer(entry.attributes.maxsize),
          align: integer(entry.attributes.align), storage: entry.attributes.storage ?? null,
          extension: entry.attributes.extension ?? null, location: readStorage(entry),
        }));
        const readPrototype = (node) => {
          const a = node.attributes;
          const input = kid(node, 'input'), output = kid(node, 'output');
          const registerNames = (name) => kids(kid(node, name) ?? { children: [] }, 'register').map((r) => r.attributes.name ?? null);
          return {
            name: a.name ?? null, extraPop: integer(a.extrapop), stackShift: integer(a.stackshift),
            strategy: a.strategy ?? 'standard', hasThis: bool(a.hasthis) ?? false, isConstructor: bool(a.constructor) ?? false,
            // pentry order is the allocation order: the first entry takes the first argument.
            inputs: input ? readGroup(input) : [],
            outputs: output ? readGroup(output) : [],
            unaffected: registerNames('unaffected'),
            killedByCall: registerNames('killedbycall'),
            likelyTrash: registerNames('likelytrash'),
            rules: [...(input ? kids(input, 'rule') : []), ...(output ? kids(output, 'rule') : [])].map((rule) => {
              const datatype = kid(rule, 'datatype');
              const actions = ['consume', 'convert_to_ptr', 'goto_stack', 'join', 'hidden_return', 'join_per_primitive', 'join_dual_class'];
              return { datatype: datatype?.attributes.name ?? null,
                sizes: datatype?.attributes.sizes ?? null,
                action: actions.find((name) => kid(rule, name)) ?? null };
            }),
          };
        };

        const defaultNode = kid(root, 'default_proto');
        const defaultPrototype = defaultNode ? kid(defaultNode, 'prototype') : null;
        const conventions = [
          ...(defaultPrototype ? [{ ...readPrototype(defaultPrototype), isDefault: true }] : []),
          ...kids(root, 'prototype').map((node) => ({ ...readPrototype(node), isDefault: false })),
        ];
        const globalNode = kid(root, 'global') ?? { children: [] };
        const globals = [
          ...kids(globalNode, 'range').map((node) => ({ kind: 'range', space: node.attributes.space ?? null, first: integer(node.attributes.first), last: integer(node.attributes.last), register: null })),
          ...kids(globalNode, 'register').map((node) => ({ kind: 'register', space: null, first: null, last: null, register: node.attributes.name ?? null })),
        ];
        const callFixups = [
          ...kids(root, 'callfixup').map((node) => ({ kind: 'callfixup', name: node.attributes.name ?? null,
            targets: kids(node, 'target').map((t) => t.attributes.name ?? null) })),
          ...kids(root, 'callotherfixup').map((node) => ({ kind: 'callotherfixup', name: node.attributes.targetop ?? null, targets: [] })),
        ];

        const stackNode = kid(root, 'stackpointer');
        const returnNode = kid(root, 'returnaddress');
        const counts = { conventions: conventions.length, callFixups: callFixups.length, globals: globals.length,
          modelAliases: kids(root, 'modelalias').length, resolvePrototypes: kids(root, 'resolveprototype').length };
        if (!defaultPrototype) limitations.push('No default_proto prototype is present, which the compiler spec schema requires: the convention list may be incomplete');
        limitations.push('A callfixup body is the p-code that replaces a call and is reported by name only, not interpreted');
        limitations.push('A convention describes how the compiler was expected to pass arguments; it is a claim about the toolchain, not an observation of any particular binary');
        return { ...base(relative, bytes), supported: true, reason: null, dataOrganization,
          stackPointer: stackNode ? { register: stackNode.attributes.register ?? null, space: stackNode.attributes.space ?? null,
            growth: stackNode.attributes.growth ?? 'negative', reverseJustify: bool(stackNode.attributes.reversejustify) ?? false } : null,
          returnAddress: returnNode ? readStorage(returnNode) : null,
          conventions: listed(conventions, limitations, 'conventions'),
          defaultConvention: defaultPrototype?.attributes.name ?? null,
          globals, callFixups: listed(callFixups, limitations, 'call fixups'), counts, limitations };
      },
    },
    {
      name: 'artifact.ghidraLoaderOpinion', version: '1.0.0', effect: 'read', inputSchema: pathOnly,
      outputKeys: ['path', 'sha256', 'supported', 'reason', 'constraints', 'loaders', 'counts', 'limitations', 'untrusted'],
      execute({ path: relative }, context) {
        const { bytes, limitations, failure, root } = xml(context, relative, 8, 'opinions');
        if (failure) return { ...base(relative, bytes), supported: false, ...failure, constraints: [], loaders: [], counts: {}, limitations };
        const rows = flattenOpinions(root).map((row) => ({
          loader: row.loader ?? null, primary: row.primary ?? null, secondary: row.secondary ?? null,
          processor: row.processor ?? null, endian: row.endian ?? null, size: integer(row.size),
          variant: row.variant ?? null, compilerSpecID: row.compilerSpecID ?? null,
        }));
        const loaders = [...new Set(rows.map((row) => row.loader).filter(Boolean))].sort();
        limitations.push('Rows are the leaves of the constraint tree with ancestor attributes merged in, which is how a loader reads the file: an inner constraint inherits whatever its ancestors set');
        limitations.push('A row names a processor, endianness, size and variant but not a language id; artifact.ghidraLanguageMatch resolves a row against a .ldefs rather than assembling an id that may not exist');
        return { ...base(relative, bytes), supported: true, reason: null,
          constraints: listed(rows, limitations, 'constraint rows'), loaders,
          counts: { constraints: rows.length, loaders: loaders.length }, limitations };
      },
    },
    {
      name: 'artifact.ghidraLanguageMatch', version: '1.0.0', effect: 'read',
      outputKeys: ['supported', 'reason', 'query', 'matched', 'rows', 'counts', 'limitations'],
      inputSchema: object({
        opinion: string, languages: string,
        loader: string, primary: string, secondary: string,
      }, ['opinion', 'languages']),
      execute({ opinion: opinionPath, languages: languagePath, loader, primary, secondary }, context) {
        const limitations = [];
        const query = { loader: loader ?? null, primary: primary ?? null, secondary: secondary ?? null };
        const opinionRead = xml(context, opinionPath, 8, 'opinions');
        if (opinionRead.failure) {
          return { supported: false, ...opinionRead.failure, query, matched: [], rows: 0, counts: {}, limitations: opinionRead.limitations };
        }
        const languageRead = xml(context, languagePath, 8, 'language_definitions');
        if (languageRead.failure) {
          return { supported: false, ...languageRead.failure, query, matched: [], rows: 0, counts: {}, limitations: languageRead.limitations };
        }
        limitations.push(...opinionRead.limitations, ...languageRead.limitations);

        const defined = kids(languageRead.root, 'language').map((node) => ({
          id: node.attributes.id ?? null, processor: node.attributes.processor ?? null,
          endian: node.attributes.endian ?? null, size: integer(node.attributes.size),
          variant: node.attributes.variant ?? null, deprecated: bool(node.attributes.deprecated) ?? false,
          compilers: kids(node, 'compiler').map((c) => c.attributes.id ?? null),
        }));
        const rows = flattenOpinions(opinionRead.root);
        const matched = [];
        for (const row of rows) {
          if (loader !== undefined && row.loader !== undefined && String(row.loader) !== loader) continue;
          if (primary !== undefined && row.primary !== undefined) {
            const left = integer(row.primary), right = integer(primary);
            if (left === null || right === null || left !== right) continue;
          }
          const secondaryCheck = secondaryMatches(row.secondary, secondary);
          if (!secondaryCheck.matched) continue;
          // A row is only resolved against languages that exist. Assembling processor:LE:32:variant
          // would produce an id for every row, including rows whose language is not installed, and
          // an id that resolves to nothing is worse than a row reported as unresolved.
          const candidates = defined.filter((language) => (row.processor === undefined || language.processor === row.processor)
            && (row.endian === undefined || language.endian === row.endian)
            && (row.size === undefined || language.size === integer(row.size))
            && (row.variant === undefined || language.variant === row.variant));
          matched.push({
            row: { loader: row.loader ?? null, primary: row.primary ?? null, secondary: row.secondary ?? null,
              processor: row.processor ?? null, endian: row.endian ?? null, size: integer(row.size),
              variant: row.variant ?? null, compilerSpecID: row.compilerSpecID ?? null },
            secondaryMatch: secondaryCheck.how,
            languages: candidates.map((language) => ({ id: language.id, variant: language.variant, deprecated: language.deprecated,
              compilerSpecKnown: row.compilerSpecID === undefined ? null : language.compilers.includes(row.compilerSpecID) })),
            resolved: candidates.length > 0,
          });
        }
        const resolved = matched.filter((entry) => entry.resolved);
        if (matched.length && !resolved.length) limitations.push('Rows matched the query but none names a language present in this .ldefs, so nothing is resolved');
        limitations.push('This is the loader-side half of the decision: it maps header fields onto a language, and does not read the binary whose header those fields came from');
        return { supported: true, reason: null, query,
          matched: listed(matched, limitations, 'matched rows'), rows: rows.length,
          counts: { rows: rows.length, matched: matched.length, resolved: resolved.length,
            languages: defined.length, candidateIds: new Set(resolved.flatMap((e) => e.languages.map((l) => l.id))).size },
          limitations };
      },
    },
    {
      name: 'artifact.sleighSource', version: '1.0.0', effect: 'read', inputSchema: pathOnly,
      outputKeys: ['path', 'sha256', 'supported', 'reason', 'endian', 'alignment', 'spaces', 'registers', 'tokens', 'contextFields', 'pcodeops', 'attaches', 'macros', 'mnemonics', 'subtables', 'includes', 'defines', 'counts', 'limitations', 'untrusted'],
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 2);
        const limitations = [];
        const text = decoder.decode(bytes);
        const refuse = (reason, detail) => ({ ...base(relative, bytes), supported: false, reason, detail,
          endian: null, alignment: null, spaces: [], registers: [], tokens: [], contextFields: [],
          pcodeops: [], attaches: [], macros: [], mnemonics: [], subtables: [], includes: [], defines: [], counts: {}, limitations });
        if (/^\s*</.test(text)) {
          return refuse('not_sleigh_source', 'The file starts with an XML tag, so it is one of the XML specification types rather than SLEIGH source');
        }
        const read = readSleighSource(text);
        // A file with no SLEIGH construct of any kind is not SLEIGH source, and saying `supported`
        // with every list empty would let a caller believe a specification had been read. The
        // check counts `@define` and `@include` too, because a thin variant file such as
        // ARM7_le.slaspec is nothing but those and is still real source.
        if (!read.defines.length && !read.includes.length && !read.spaces.length && !read.registers.length
          && !read.tokens.length && !read.contextFields.length && !read.pcodeops.length && !read.attaches.length
          && !read.macros.length && !read.mnemonics.length && !read.subtables.length && read.endian === null
          && read.alignment === null) {
          return refuse('no_sleigh_declarations', 'The file holds no SLEIGH declaration, directive or constructor, so it is not SLEIGH source');
        }
        const counts = { spaces: read.spaces.length, registers: read.registers.length, tokens: read.tokens.length,
          contextFields: read.contextFields.length, pcodeops: read.pcodeops.length, attaches: read.attaches.length,
          macros: read.macros.length, mnemonics: read.mnemonics.length, subtables: read.subtables.length,
          includes: read.includes.length, defines: read.defines.length,
          directives: read.conditionalCount.directives, guardedDeclarations: read.conditionalCount.guardedDeclarations,
          unterminatedDeclarations: read.unterminated };

        limitations.push('Each declaration carries the @if conditions in force where it was written; this reader does not evaluate them, so a guarded declaration is reported as conditional rather than as a fact about any one variant');
        if (read.includes.length) limitations.push(`This file @includes ${read.includes.length} other file(s), which are not followed: the declarations below are this file's own`);
        if (read.endian?.macro) limitations.push(`Endianness is written as ${read.endian.macro} and is supplied by whichever file includes this one, so it is unresolved here`);
        if (counts.guardedDeclarations) limitations.push(`${counts.guardedDeclarations} declaration(s) sit inside a conditional block and hold only for the variants their guards select`);
        if (counts.unterminatedDeclarations) limitations.push(`${counts.unterminatedDeclarations} statement(s) opened with define or attach and were never terminated within ${512} lines, so they are not reported`);
        limitations.push('Instruction semantics are not parsed: the mnemonic list is the display section of each constructor, not what it does');
        return { ...base(relative, bytes), supported: true, reason: null,
          endian: read.endian, alignment: read.alignment,
          spaces: listed(read.spaces, limitations, 'spaces'),
          registers: listed(read.registers, limitations, 'registers'),
          tokens: listed(read.tokens, limitations, 'tokens'),
          contextFields: listed(read.contextFields, limitations, 'context fields'),
          pcodeops: listed(read.pcodeops, limitations, 'pcodeops'),
          attaches: listed(read.attaches, limitations, 'attach tables'),
          macros: listed(read.macros, limitations, 'macros'),
          mnemonics: listed(read.mnemonics, limitations, 'constructors'),
          subtables: listed(read.subtables, limitations, 'subtables'),
          includes: listed(read.includes, limitations, 'includes'),
          defines: listed(read.defines, limitations, 'defines'),
          counts, limitations };
      },
    },
    {
      name: 'artifact.sleighCompiled', version: '1.0.0', effect: 'read', inputSchema: pathOnly,
      outputKeys: ['path', 'sha256', 'supported', 'reason', 'format', 'sleigh', 'spaces', 'sourceFiles', 'registers', 'userops', 'subtables', 'elementCounts', 'counts', 'limitations', 'untrusted'],
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 2);
        const limitations = [];
        const empty = { sleigh: null, spaces: [], sourceFiles: [], registers: [], userops: [], subtables: [], elementCounts: {} };
        const opened = openSla(bytes);
        if (!opened.ok) {
          return { ...base(relative, bytes), supported: false, reason: opened.reason, detail: opened.detail,
            ...empty, format: opened.version === undefined ? null : { magic: 'sla', version: opened.version }, counts: {}, limitations };
        }
        const read = readSlaTables(opened.flat);
        if (read.truncated) {
          limitations.push(`The decode stopped early (${read.truncated}), so every list below is partial and the counts describe only what was read`);
        }
        const elementCounts = Object.fromEntries([...read.counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])));
        const counts = { spaces: read.spaces.length, sourceFiles: read.sourceFiles.length,
          registers: read.registers.length, userops: read.userops.length, subtables: read.subtables.length,
          constructors: read.counts.get('constructor') ?? 0, inflatedBytes: opened.flat.length, maxDepth: read.maxDepth };
        limitations.push('Decode tables, patterns and p-code templates are counted but not reported: the element counts say how much structure the file holds beyond the names listed here');
        limitations.push('This is the compiled form, so the facts here are what the SLEIGH compiler recorded, with the preprocessor already resolved for this one language variant');
        return { ...base(relative, bytes), supported: true, reason: null,
          format: { magic: 'sla', version: opened.version },
          sleigh: { version: read.root.version ?? null, bigEndian: read.root.bigendian ?? null,
            alignment: read.root.align ?? null, uniqueBase: read.root.uniqbase ?? null,
            maxDelaySlotBytes: read.root.maxdelay ?? 0, uniqueMask: read.root.uniqmask ?? 0,
            sectionCount: read.root.numsections ?? 0, defaultSpace: read.defaultSpace },
          spaces: read.spaces,
          sourceFiles: listed(read.sourceFiles, limitations, 'source files'),
          registers: listed(read.registers, limitations, 'register varnodes'),
          userops: listed(read.userops, limitations, 'userops'),
          subtables: listed(read.subtables, limitations, 'subtables'),
          elementCounts, counts, limitations };
      },
    },
    {
      name: 'artifact.compareSleighSource', version: '1.0.0', effect: 'read',
      outputKeys: ['supported', 'reason', 'agreements', 'disagreements', 'unstated', 'counts', 'limitations'],
      inputSchema: object({ compiled: string, source: string }, ['compiled', 'source']),
      execute({ compiled: compiledPath, source: sourcePath }, context) {
        const limitations = [];
        const compiledBytes = readBytes(context, compiledPath, 4);
        const opened = openSla(compiledBytes);
        if (!opened.ok) {
          return { supported: false, reason: opened.reason, detail: opened.detail, agreements: [], disagreements: [], unstated: [], counts: {}, limitations };
        }
        const table = readSlaTables(opened.flat);
        const sourceBytes = readBytes(context, sourcePath, 4);
        const source = readSleighSource(decoder.decode(sourceBytes));

        const agreements = [];
        const disagreements = [];
        const unstated = [];
        /**
         * Three outcomes, not two. A source file that says `define endian=$(ENDIAN)` has not
         * disagreed with the table — it has not spoken, and recording that as a mismatch would
         * manufacture a finding out of the preprocessor. So an unresolved or guarded declaration
         * lands in `unstated` with the reason it could not be compared.
         */
        const compare = (field, declared, tableValue, why) => {
          if (declared === null || declared === undefined) { unstated.push({ field, reason: 'not_declared_in_this_file', tableValue, sourceValue: null }); return; }
          if (why) { unstated.push({ field, reason: why, tableValue, sourceValue: declared.text ?? declared.value ?? null }); return; }
          const value = declared.value ?? null;
          if (value === tableValue) agreements.push({ field, value });
          else disagreements.push({ field, sourceValue: value, tableValue });
        };
        compare('endian', source.endian === null ? null : { value: source.endian.value },
          table.root.bigendian === true ? 'big' : table.root.bigendian === false ? 'little' : null,
          source.endian?.macro ? 'unresolved_macro' : source.endian?.guards.length ? 'conditional' : null);
        compare('alignment', source.alignment, table.root.align ?? null,
          source.alignment?.macro ? 'unresolved_macro' : source.alignment?.guards.length ? 'conditional' : null);
        const defaultSpace = source.spaces.find((space) => space.default);
        compare('defaultSpace', defaultSpace ? { value: defaultSpace.name } : null, table.defaultSpace,
          defaultSpace?.guards.length ? 'conditional' : null);

        // Space and register agreement is set-shaped rather than scalar: the source states a space
        // once and the table records it once, so a name present in one and absent from the other is
        // the finding. Only unguarded source declarations take part, for the same reason as above.
        const tableSpaces = new Set(table.spaces.filter((space) => space.kind === 'addressable').map((space) => space.name));
        const sourceSpaces = source.spaces.filter((space) => !space.guards.length).map((space) => space.name);
        const missingSpaces = sourceSpaces.filter((name) => !tableSpaces.has(name));
        if (missingSpaces.length) disagreements.push({ field: 'spaces', sourceValue: missingSpaces.join(' '), tableValue: [...tableSpaces].sort().join(' ') });
        else if (sourceSpaces.length) agreements.push({ field: 'spaces', value: `all ${sourceSpaces.length} unguarded source spaces appear in the table` });
        else unstated.push({ field: 'spaces', reason: 'no_unguarded_space_declared_in_this_file', tableValue: [...tableSpaces].sort().join(' '), sourceValue: null });

        const tableRegisters = new Set(table.registers.map((register) => register.name));
        const sourceRegisters = source.registers.filter((register) => register.name && !register.guards.length).map((register) => register.name);
        const missingRegisters = sourceRegisters.filter((name) => !tableRegisters.has(name));
        if (missingRegisters.length) disagreements.push({ field: 'registers', sourceValue: missingRegisters.slice(0, 32).join(' '), tableValue: `${tableRegisters.size} register varnodes in the table` });
        else if (sourceRegisters.length) agreements.push({ field: 'registers', value: `all ${sourceRegisters.length} unguarded source registers appear in the table` });
        else unstated.push({ field: 'registers', reason: 'no_unguarded_register_declared_in_this_file', tableValue: `${tableRegisters.size} register varnodes in the table`, sourceValue: null });

        if (source.includes.length) {
          limitations.push(`The source file @includes ${source.includes.length} other file(s), which are not followed: a fact declared in an included file is reported as unstated here rather than as a disagreement`);
        }
        limitations.push('A compiled table is built for one variant and the source may describe many, so agreement is evidence that this pair belongs together and disagreement is evidence that it does not');
        return { supported: true, reason: null, agreements, disagreements, unstated,
          counts: { agreements: agreements.length, disagreements: disagreements.length, unstated: unstated.length,
            sourceFilesInTable: table.sourceFiles.length }, limitations };
      },
    },
  ].map((tool) => Object.freeze(tool));
}
