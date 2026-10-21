import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { isAbsolute, resolve as resolvePath } from 'node:path';
import { HarnessError } from './value.mjs';
import { readWorkspaceFile } from './workspace-fs.mjs';
import { loadLanguage, liftInstruction } from './sleigh.mjs';
import { recoverCallGraph } from './control-flow.mjs';
import { makeArtifactTools } from './artifacts.mjs';

/**
 * Speaking to Ghidra's decompiler directly.
 *
 * `decompile.exe` is a native C++ binary — it imports only KERNEL32 and links no JVM. What it is,
 * is a slave: `main()` in ghidra_process.cc loops on `readCommand(cin, cout)` and never speaks
 * first. The Java side is merely the only thing that has ever spoken to it. This module is the
 * other speaker, so "Concord cannot decompile without a Java runtime" stops being true.
 *
 * The leverage that makes this tractable rather than a rewrite: `ArchitectureGhidra::buildTranslator`
 * returns a `GhidraTranslate`, which is a *callback* translator. The decompiler never loads a
 * `.sla` and never decodes an instruction itself — it asks the master, one instruction at a time,
 * for p-code. So the inputs it needs are exactly what Concord already computes: bytes from a mapped
 * image, and lifted p-code. Nothing here reimplements the decompiler; it answers its questions.
 *
 * Everything below was read out of the shipped C++ and then verified against the running binary,
 * because this is a protocol with no specification and three separate framing layers.
 */

const fail = (code, message, details) => { throw new HarnessError(code, message, details); };

// ---------------------------------------------------------------------------------------------
// Layer 1: burst framing
// ---------------------------------------------------------------------------------------------

/**
 * `ArchitectureGhidra::readToAnyBurst` (ghidra_arch.cc:79) skips every byte above zero, consumes a
 * run of zeros, and then expects 0x01 followed by a type byte. Writers always emit exactly four:
 * `00 00 01 <type>`. The consequence worth knowing is that payload bytes may be anything except a
 * zero run followed by 0x01, which is why bytes travel nibble-encoded (see answerBytes).
 */
const BURST = {
  COMMAND: 2, COMMAND_END: 3,
  QUERY: 4, QUERY_END: 5,
  RESPONSE: 6, RESPONSE_END: 7,
  QUERY_RESPONSE: 8, QUERY_RESPONSE_END: 9,
  EXCEPTION: 10,
  BYTES: 12,
  STRING: 14, STRING_END: 15,
  WARNING: 16, WARNING_END: 17,
};

const burst = (type) => Buffer.from([0, 0, 1, type]);

/**
 * A string frame carries either text or raw bytes.
 *
 * Both occur: a command name is text, and `decompileAt` takes a PackedEncode-encoded address
 * inside the same frame type. Accepting a Buffer directly avoids a latin1 round trip whose only
 * job would be to survive being decoded and re-encoded.
 */
const stringFrame = (value) => Buffer.concat([
  burst(BURST.STRING),
  Buffer.isBuffer(value) ? value : Buffer.from(value, 'latin1'),
  burst(BURST.STRING_END),
]);

/**
 * A command: start, the function name, its parameters, then the terminator.
 *
 * The terminator is not optional and its absence is invisible. `GhidraCommand::doit` writes its
 * response header, calls `loadParameters()`, and only then reads a burst expecting type 3; without
 * it the process blocks on a read forever, having already emitted the header. That reads exactly
 * like a hang in the decompiler and is actually four missing bytes.
 */
const command = (name, parameters = []) => Buffer.concat([
  burst(BURST.COMMAND), stringFrame(name), ...parameters.map(stringFrame), burst(BURST.COMMAND_END),
]);

/** Split a stream into burst-delimited records, keeping the bytes between them. */
function splitFrames(buffer) {
  const frames = [];
  let payloadStart = 0;
  let index = 0;
  while (index < buffer.length) {
    if (buffer[index] === 0 && buffer[index + 1] === 0 && buffer[index + 2] === 1 && index + 3 < buffer.length) {
      if (index > payloadStart) frames.push({ type: null, payload: buffer.subarray(payloadStart, index) });
      frames.push({ type: buffer[index + 3], payload: null });
      index += 4;
      payloadStart = index;
    } else index += 1;
  }
  if (buffer.length > payloadStart) frames.push({ type: null, payload: buffer.subarray(payloadStart) });
  return frames;
}

// ---------------------------------------------------------------------------------------------
// Layer 2: PackedFormat, the encoding inside a query
// ---------------------------------------------------------------------------------------------

/**
 * The same format `.sla` files use, from marshal.hh.
 *
 * Deliberately not shared with the reader in ghidra.mjs. That one resolves ids eagerly against the
 * `.sla` attribute table, and the protocol uses the global AttributeId/ElementId registry — the
 * same wire format over a different id space, so sharing the decoder would mean one of the two
 * resolving names from the wrong table. This keeps raw numeric ids throughout.
 */
const HEADER_MASK = 0xc0;
const ELEMENT_START = 0x40;
const ELEMENT_END = 0x80;
const ATTRIBUTE = 0xc0;
const HEADEREXTEND = 0x20;
const ELEMENTID_MASK = 0x1f;
const RAWDATA_MASK = 0x7f;
const RAWDATA_MARKER = 0x80;
const RAWDATA_BITS = 7;
const TYPECODE_SHIFT = 4;
const LENGTHCODE_MASK = 0xf;

const TYPE = { BOOLEAN: 1, SIGNED_POSITIVE: 2, SIGNED_NEGATIVE: 3, UNSIGNED: 4, SPACE: 5, SPECIALSPACE: 6, STRING: 7 };

// CPUI_LOAD and CPUI_STORE, the only two ops whose first operand is an address space rather than
// a varnode. The numbering is the shared CPUI enum, the same one src/sleigh.mjs reports.
const OPCODE_LOAD = 2;
const OPCODE_STORE = 3;

/** An id that does not fit in five bits continues into one follow-on byte. */
function headerBytes(header, id) {
  if (id <= ELEMENTID_MASK) return [header | id];
  return [header | HEADEREXTEND | ((id >> RAWDATA_BITS) & ELEMENTID_MASK), RAWDATA_MARKER | (id & RAWDATA_MASK)];
}

/** Big-endian 7-bits-per-byte, each byte carrying the marker bit. Zero needs no bytes at all. */
function rawData(value) {
  let remaining = BigInt(value);
  if (remaining === 0n) return [];
  const out = [];
  while (remaining > 0n) {
    out.unshift(RAWDATA_MARKER | Number(remaining & 0x7fn));
    remaining >>= 7n;
  }
  return out;
}

class PackedWriter {
  constructor() { this.bytes = []; }

  openElement(id) { this.bytes.push(...headerBytes(ELEMENT_START, id)); return this; }
  closeElement(id) { this.bytes.push(...headerBytes(ELEMENT_END, id)); return this; }

  attribute(id, typeCode, data) {
    this.bytes.push(...headerBytes(ATTRIBUTE, id));
    this.bytes.push((typeCode << TYPECODE_SHIFT) | (data.length & LENGTHCODE_MASK));
    this.bytes.push(...data);
    return this;
  }

  writeSignedInteger(id, value) {
    return value < 0
      ? this.attribute(id, TYPE.SIGNED_NEGATIVE, rawData(-value))
      : this.attribute(id, TYPE.SIGNED_POSITIVE, rawData(value));
  }

  writeUnsignedInteger(id, value) { return this.attribute(id, TYPE.UNSIGNED, rawData(value)); }

  writeBool(id, value) { return this.attribute(id, TYPE.BOOLEAN, rawData(value ? 1 : 0)); }

  writeSpace(id, index) { return this.attribute(id, TYPE.SPACE, rawData(index)); }

  /** A string's length is the raw data; the characters follow unencoded. */
  writeString(id, text) {
    const encoded = Buffer.from(text, 'latin1');
    this.bytes.push(...headerBytes(ATTRIBUTE, id));
    const length = rawData(encoded.length);
    this.bytes.push((TYPE.STRING << TYPECODE_SHIFT) | (length.length & LENGTHCODE_MASK));
    this.bytes.push(...length, ...encoded);
    return this;
  }

  toBuffer() { return Buffer.from(this.bytes); }
}

/**
 * Decode a query element: its id, its attributes, and its children, as raw numbers.
 *
 * Children are not optional to handle, which cost a bug. Three of the queries put their address in
 * attributes on the query element itself (`getRegister` writes `name`, `getUserOpName` writes
 * `index`), but `getBytes`, `getPcode` and `getMappedSymbols` all call `Address::encode`, which
 * emits a nested `<addr>` element instead. A decoder that stopped at the first child read those
 * three as having no address at all — and the handler then answered about address `undefined`,
 * which is the confidently-wrong shape rather than a crash.
 */
function decodePacked(buffer) {
  let index = 0;
  const readId = () => {
    const header = buffer[index];
    if ((header & HEADEREXTEND) === 0) { index += 1; return header & ELEMENTID_MASK; }
    const id = ((header & ELEMENTID_MASK) << RAWDATA_BITS) | (buffer[index + 1] & RAWDATA_MASK);
    index += 2;
    return id;
  };
  const readRaw = (count) => {
    let value = 0n;
    for (let i = 0; i < count; i++) value = (value << 7n) | BigInt(buffer[index + i] & RAWDATA_MASK);
    index += count;
    return value;
  };

  const readElement = () => {
    if ((buffer[index] & HEADER_MASK) !== ELEMENT_START) fail('DECOMPILE_PROTOCOL', 'Expected an element');
    const element = readId();
    const attributes = new Map();
    while (index < buffer.length && (buffer[index] & HEADER_MASK) === ATTRIBUTE) {
      const id = readId();
      const typeByte = buffer[index];
      index += 1;
      const typeCode = typeByte >> TYPECODE_SHIFT;
      const length = typeByte & LENGTHCODE_MASK;
      if (typeCode === TYPE.STRING) {
        const size = Number(readRaw(length));
        attributes.set(id, buffer.toString('latin1', index, index + size));
        index += size;
      } else if (typeCode === TYPE.SIGNED_NEGATIVE) {
        attributes.set(id, -readRaw(length));
      } else if (typeCode === TYPE.BOOLEAN) {
        attributes.set(id, readRaw(length) !== 0n);
      } else {
        attributes.set(id, readRaw(length));
      }
    }
    const children = [];
    while (index < buffer.length && (buffer[index] & HEADER_MASK) === ELEMENT_START) children.push(readElement());
    // The close record. Its id repeats the element's, and a mismatch means the stream is misread
    // rather than merely unexpected, so it is checked.
    if (index < buffer.length && (buffer[index] & HEADER_MASK) === ELEMENT_END) {
      const closing = readId();
      if (closing !== element) fail('DECOMPILE_PROTOCOL', 'A query element closed with a different id', { element, closing });
    }
    return { element, attributes, children };
  };

  return readElement();
}

/**
 * The address a query is about, wherever it put it.
 *
 * Returns `{ space, offset, size }` with offset as a BigInt, or null when the query carries no
 * address. Looking in both places is deliberate rather than tidy: the two encodings are both real
 * and which one a given query uses is not guessable from its name.
 */
function addressOf(query) {
  const child = query.children?.find((entry) => entry.element === 11); // ELEM_ADDR
  const source = child ?? query;
  const offset = source.attributes.get(16); // ATTRIB_OFFSET
  if (offset === undefined) return null;
  return {
    space: Number(source.attributes.get(20) ?? 0), // ATTRIB_SPACE
    offset: typeof offset === 'bigint' ? offset : BigInt(offset),
    size: source.attributes.get(19) === undefined ? null : Number(source.attributes.get(19)), // ATTRIB_SIZE
  };
}

// ---------------------------------------------------------------------------------------------
// Layer 3: the protocol vocabulary
// ---------------------------------------------------------------------------------------------

/** Query elements, from ghidra_arch.cc:30-48. These are the questions the decompiler can ask. */
const QUERY = {
  isNameUsed: 239, getBytes: 240, getCallFixup: 241, getCallMech: 242, getCallOtherFixup: 243,
  getCodeLabel: 244, getComments: 245, getCpoolRef: 246, getDataType: 247, getExternalRef: 248,
  getMappedSymbols: 249, getNamespacePath: 250, getPcode: 251, getPcodeExecutable: 252,
  getRegister: 253, getRegisterName: 254, getStringData: 255, getTrackedRegisters: 256,
  getUserOpName: 257,
};
const QUERY_NAME = new Map(Object.entries(QUERY).map(([name, id]) => [id, name]));

/** Global attribute and element ids (marshal.cc). Not the FORMAT_SCOPE duplicates. */
const ATTRIB = {
  CONTENT: 1, ID: 9, INDEX: 10, NAME: 14, OFFSET: 16, SIZE: 19, SPACE: 20, VALUE: 25,
  FIRST: 27, LAST: 28, CODE: 43, INDENT: 38,
};
const ELEM = {
  VOID: 10, ADDR: 11, RANGELIST: 13, REGISTER: 14, BREAK: 17, OP: 27, SPACEID: 30,
  FUNCTIONSHELL: 72, HOLE: 74, MAPSYM: 76, PARENT: 77, INST: 98, UNIMPL: 114, FUNCTION: 116,
  TRACKED_POINTSET: 125, TRACKED_SET: 126,
};

/**
 * Queries whose caller decodes the reply without checking whether there was one.
 *
 * A third category, and the most dangerous. `answerNothing` is legal for a query read through
 * `readAll`, which returns false. But `ContextGhidra::getTrackedDefault` (ghidra_context.cc:25)
 * discards that boolean and calls `decoder.openElement(ELEM_TRACKED_POINTSET)` unconditionally, so
 * a refusal leaves it decoding a decoder that was never fed. The result is not an exception — it is
 * a segmentation fault, reported as exit 1 with no message by the handler the decompiler installs
 * to keep the operating system quiet.
 *
 * This cost a long hunt: p-code removed entirely, every instruction answered `<unimpl>`, core types
 * supplied in full, and the crash stayed exactly where it was. What localised it was noticing that
 * getTrackedRegisters was the last query before death in every failing run.
 */
const MUST_DECODE = new Map([[QUERY.getTrackedRegisters, ELEM.TRACKED_POINTSET]]);

// ---------------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------------

/**
 * "I have no answer for that."
 *
 * Type 9 is both the response terminator and, because it is odd, the negative answer:
 * `readStringStream(istream,Decoder)` returns false for any odd type, and `getBytes` raises
 * DataUnavailError on one. So a bare start-then-end is a well-formed "nothing", which is the
 * honest reply for every query Concord cannot answer rather than an invented empty structure.
 */
const answerNothing = () => Buffer.concat([burst(BURST.QUERY_RESPONSE), burst(BURST.QUERY_RESPONSE_END)]);

/**
 * The queries that are read as a plain string, for which `answerNothing` is a protocol violation.
 *
 * There are two string readers and only one of them tolerates a refusal. The Decoder overload,
 * `readStringStream(istream&,Decoder&)`, returns false for any odd type — that is what makes a
 * bare start-then-end a legal "nothing". The plain overload, `readStringStream(istream&,string&)`,
 * **throws** `JavaError("alignment","Expecting string")` on anything that is not type 14. So these
 * must always receive a string frame, empty when the answer is unknown.
 *
 * Learned from the decompiler rather than from reading: answering getUserOpName with nothing
 * aborted the whole registerProgram with an alignment error, after the query itself had been
 * answered apparently successfully.
 */
const STRING_VALUED = new Set([257, 254, 244]); // getUserOpName, getRegisterName, getCodeLabel

const answerString = (text) => Buffer.concat([
  burst(BURST.QUERY_RESPONSE), stringFrame(text), burst(BURST.QUERY_RESPONSE_END),
]);

const answerPacked = (writer) => Buffer.concat([
  burst(BURST.QUERY_RESPONSE),
  burst(BURST.STRING), writer.toBuffer(), burst(BURST.STRING_END),
  burst(BURST.QUERY_RESPONSE_END),
]);

/**
 * Bytes, nibble-encoded.
 *
 * Each byte becomes two, the high nibble then the low, each offset by 'A' (ghidra_arch.cc:744:
 * `((dblbuf[i*2]-'A') << 4) | (dblbuf[i*2+1]-'A')`). This is not compression or obfuscation — it
 * keeps payload bytes inside 'A'..'P' so a run of zeros followed by 0x01 can never appear in data
 * and be mistaken for a burst marker. The length is implied: the decompiler reads exactly twice
 * what it asked for, so a short answer desynchronises the stream rather than erroring.
 */
function answerBytes(bytes) {
  const encoded = Buffer.alloc(bytes.length * 2);
  for (let i = 0; i < bytes.length; i++) {
    encoded[i * 2] = 0x41 + ((bytes[i] >> 4) & 0xf);
    encoded[i * 2 + 1] = 0x41 + (bytes[i] & 0xf);
  }
  return Buffer.concat([burst(BURST.QUERY_RESPONSE), burst(BURST.BYTES), encoded, burst(BURST.QUERY_RESPONSE_END)]);
}

// ---------------------------------------------------------------------------------------------
// The callbacks
// ---------------------------------------------------------------------------------------------

/**
 * Answer the decompiler's questions from what Concord already knows.
 *
 * `language` is a loaded `.sla` (src/sleigh.mjs) and supplies registers and user-defined p-code op
 * names. `readImage(offset, size)` returns bytes from the mapped program image, or null where
 * nothing is mapped — which is a real answer, not a failure: a decompiler asking for bytes outside
 * any section should be told they are absent rather than handed zeros it will decode as code.
 *
 * Every handler that cannot answer returns `answerNothing()`. That is the whole design: an empty
 * symbol table produces a decompilation with generated names, while a fabricated one produces a
 * decompilation that is wrong about the program and says nothing about it.
 */
export function createCallbacks({ language, readImage, spaceIndex, lift, findFunction, holeAround } = {}) {
  const registersByName = new Map();
  const registersByLocation = new Map();
  const userops = [];

  for (const symbol of language?.symbols?.values?.() ?? []) {
    if (symbol.kind === 'varnode' && typeof symbol.name === 'string' && symbol.space !== undefined) {
      registersByName.set(symbol.name, symbol);
      registersByLocation.set(`${symbol.offset}:${symbol.size}`, symbol);
    }
  }
  for (const entry of language?.userops ?? []) {
    if (typeof entry === 'string') userops.push(entry);
    else if (typeof entry?.name === 'string') userops.push(entry.name);
  }

  const registerSpace = () => spaceIndex?.('register') ?? 0;

  const handlers = new Map([
    // The first question the decompiler ever asks, during architecture initialization.
    [QUERY.getUserOpName, (query) => {
      const index = Number(query.attributes.get(ATTRIB.INDEX) ?? -1);
      // Always a string: see STRING_VALUED. An unknown userop is the empty string, which Ghidra
      // treats as 'no name available' rather than as a broken reply.
      return answerString(userops[index] ?? '');
    }],

    // A register by name, answered as its storage location.
    [QUERY.getRegister, (query) => {
      const symbol = registersByName.get(String(query.attributes.get(ATTRIB.NAME) ?? ''));
      if (!symbol) return answerNothing();
      const writer = new PackedWriter();
      writer.openElement(ELEM.ADDR);
      writer.writeSpace(ATTRIB.SPACE, registerSpace());
      writer.writeUnsignedInteger(ATTRIB.OFFSET, symbol.offset);
      writer.writeSignedInteger(ATTRIB.SIZE, symbol.size);
      writer.closeElement(ELEM.ADDR);
      return answerPacked(writer);
    }],

    // The reverse: a storage location back to a name. Ghidra permits the name to cover a range
    // larger than the one asked about, but reporting a register that merely overlaps would name
    // the wrong storage, so only an exact match answers.
    [QUERY.getRegisterName, (query) => {
      const at = addressOf(query);
      const symbol = at && registersByLocation.get(`0x${at.offset.toString(16)}:${at.size}`);
      return answerString(symbol ? symbol.name : '');
    }],

    // Bytes from the program image.
    [QUERY.getBytes, (query) => {
      const at = addressOf(query);
      const size = at?.size ?? 0;
      if (!at || size <= 0) return answerNothing();
      const bytes = readImage?.(at.offset, size) ?? null;
      return bytes && bytes.length === size ? answerBytes(bytes) : answerNothing();
    }],

    /**
     * Is there a function here?
     *
     * `DecompileAt::rawAction` starts with `queryFunction(addr)`, and if that finds nothing it
     * refuses with "Bad decompile address" — so without this answer nothing can be decompiled at
     * all. The reply is a symbol in a scope, and the minimal useful one is a `functionshell`: a
     * declaration that a function exists here under some name, with no body. The decompiler then
     * recovers the body itself by asking for bytes and p-code, which is exactly the division of
     * labour that makes this arrangement work.
     *
     * Scope id 0 is the global cache (`ScopeGhidra::reresolveScope` returns `cache` for 0), which
     * avoids a getNamespacePath round trip for a namespace Concord does not model.
     *
     * `findFunction` is injected rather than assumed, and that is the whole honesty of this
     * handler. Answering "yes, a function" for every address asked would fabricate functions
     * wherever the decompiler happened to look — including in data — and the decompilation would
     * be confidently wrong about the program's shape. Concord's own region discovery supplies the
     * real list; where it knows of no function, this says so and the decompiler declines.
     */
    [QUERY.getMappedSymbols, (query) => {
      const at = addressOf(query);
      if (!at) return answerNothing();
      const { offset, space } = at;
      const found = findFunction?.(offset, space) ?? null;
      if (!found) {
        /**
         * No symbol here — but saying only that does not terminate.
         *
         * getMappedSymbolsXML is documented to return a symbol *or a hole describing a memory
         * region free of symbols*, and ScopeGhidra::decodeHole records that range in `holes` so the
         * same addresses are never asked about again. An empty answer caches nothing, so the
         * decompiler re-probes and never converges: measured at 355 repeated getMappedSymbols
         * queries on a single function, producing neither a result nor an error.
         *
         * The range has to be true rather than convenient, so it comes from the caller, which
         * knows which addresses lie between two functions it actually discovered. Claiming a wider
         * hole than that would hide a real function from the decompiler.
         */
        const hole = holeAround?.(offset, space) ?? null;
        if (!hole) return answerNothing();
        const empty = new PackedWriter();
        empty.openElement(ELEM.HOLE);
        empty.writeSpace(ATTRIB.SPACE, space);
        empty.writeUnsignedInteger(ATTRIB.FIRST, hole.first);
        empty.writeUnsignedInteger(ATTRIB.LAST, hole.last);
        empty.closeElement(ELEM.HOLE);
        return answerPacked(empty);
      }

      const writer = new PackedWriter();
      writer.openElement(ELEM.PARENT);
      writer.writeUnsignedInteger(ATTRIB.ID, 0);
      writer.openElement(ELEM.MAPSYM);
      /**
       * A full function when its extent is known, a shell when it is not.
       *
       * `Funcdata::decode` requires both a name and a size and throws "Missing function size"
       * without one, so `<function>` can only be claimed when the caller actually knows how far
       * the function runs — which Concord does, from the region it discovered. A `functionshell`
       * declares existence without extent; it is enough for `queryFunction` to succeed, and the
       * analysis then has no bound on the function it is recovering.
       */
      if (Number.isInteger(found.size) && found.size > 0) {
        writer.openElement(ELEM.FUNCTION);
        writer.writeString(ATTRIB.NAME, found.name);
        writer.writeSignedInteger(ATTRIB.SIZE, found.size);
        // A function needs a distinct id. Left unwritten it defaults to zero, and the scope the
        // decompiler creates for the function then collides with the one for any other function,
        // surfacing as RecovError inside Funcdata::decode and then as
        // "DuplicateFunctionError, but could not recover original symbol". The entry address is
        // unique by construction and stable across runs, which replay depends on.
        writer.writeUnsignedInteger(ATTRIB.ID, found.id ?? (found.entry ?? offset));
        writer.openElement(ELEM.ADDR);
        writer.writeSpace(ATTRIB.SPACE, space);
        writer.writeUnsignedInteger(ATTRIB.OFFSET, found.entry ?? offset);
        writer.closeElement(ELEM.ADDR);
        writer.closeElement(ELEM.FUNCTION);
      } else {
        writer.openElement(ELEM.FUNCTIONSHELL);
        writer.writeString(ATTRIB.NAME, found.name);
        writer.closeElement(ELEM.FUNCTIONSHELL);
      }
      // The symbol's mapping: where it lives, then the range over which that mapping is valid.
      // An empty rangelist means "everywhere", which is correct for a global function.
      writer.openElement(ELEM.ADDR);
      writer.writeSpace(ATTRIB.SPACE, space);
      writer.writeUnsignedInteger(ATTRIB.OFFSET, found.entry ?? offset);
      writer.closeElement(ELEM.ADDR);
      writer.openElement(ELEM.RANGELIST);
      writer.closeElement(ELEM.RANGELIST);
      writer.closeElement(ELEM.MAPSYM);
      writer.closeElement(ELEM.PARENT);
      return answerPacked(writer);
    }],

    /**
     * P-code for one instruction — the callback the whole arrangement exists for.
     *
     * `GhidraTranslate::oneInstruction` asks for this per instruction and never decodes anything
     * itself, so this is where Concord's SLEIGH lifter becomes the decompiler's front end. The
     * `offset` attribute on `<inst>` is the instruction's *length*, not its address: the address
     * travels as the `<addr>` child, and conflating the two would advance the decompiler by the
     * wrong amount and desynchronise every following instruction.
     *
     * An instruction the table models as having no p-code is reported as `<unimpl>`, which raises
     * UnimplError on the far side carrying the length so it can still step past it. That is a
     * different statement from "no p-code could be generated", which is what an empty answer means
     * and which aborts the function — the distinction between an instruction with no modelled
     * effect and bytes that are not an instruction at all.
     */
    [QUERY.getPcode, (query) => {
      const at = addressOf(query);
      if (!at) return answerNothing();
      const { offset, space } = at;
      const lifted = lift?.(offset, space) ?? null;
      if (!lifted) return answerNothing();

      const writer = new PackedWriter();
      // The lifter reports decode and lift separately: bytes can be a known instruction whose
      // semantics the table does not model. Both must hold before any op is claimed.
      if (!lifted.decoded || !lifted.lifted || !Array.isArray(lifted.pcode)) {
        writer.openElement(ELEM.UNIMPL);
        writer.writeSignedInteger(ATTRIB.OFFSET, lifted.length ?? 1);
        writer.closeElement(ELEM.UNIMPL);
        return answerPacked(writer);
      }

      // A varnode names its space as a string. The constant space is deliberately absent from the
      // language's own space list — decodeSpaces inserts it implicitly as index 0 before reading
      // any declared space — so it is mapped explicitly rather than left to a lookup miss that
      // would happen to return the right answer.
      const indexOfSpace = (name) => (name === 'const' || name === 'constant' ? 0 : spaceIndex?.(name) ?? 0);
      const varnode = (node) => {
        writer.openElement(ELEM.ADDR);
        writer.writeSpace(ATTRIB.SPACE, indexOfSpace(node.space));
        writer.writeUnsignedInteger(ATTRIB.OFFSET, node.offset);
        writer.writeSignedInteger(ATTRIB.SIZE, node.size);
        writer.closeElement(ELEM.ADDR);
      };

      writer.openElement(ELEM.INST);
      writer.writeSignedInteger(ATTRIB.OFFSET, lifted.length);
      writer.openElement(ELEM.ADDR);
      writer.writeSpace(ATTRIB.SPACE, space);
      writer.writeUnsignedInteger(ATTRIB.OFFSET, offset);
      writer.closeElement(ELEM.ADDR);

      for (const op of lifted.pcode) {
        const inputs = op.inputs ?? [];
        // LOAD and STORE take an address space as their first operand, and it does not travel as
        // a varnode. `PcodeOpRaw::decode` expects a `<spaceid>` element there and converts it with
        // `(uintb)(uintp)decoder.readSpace(...)` — the offset becomes a *pointer to the AddrSpace
        // object*, not a space index. Sending a plain constant instead produces a LOAD whose space
        // operand is the integer 3, which decodes without complaint and then cannot be analysed,
        // so the function never completes and the result comes back empty.
        const spaceOperand = (op.code === OPCODE_LOAD || op.code === OPCODE_STORE) ? 0 : -1;
        writer.openElement(ELEM.OP);
        // `size` is the number of inputs, and `code` is the raw CPUI opcode number — the same
        // numbering src/sleigh.mjs already uses, because both come from the same enum.
        writer.writeSignedInteger(ATTRIB.SIZE, inputs.length);
        writer.writeSignedInteger(ATTRIB.CODE, op.code);
        if (op.output) varnode(op.output);
        else { writer.openElement(ELEM.VOID); writer.closeElement(ELEM.VOID); }
        inputs.forEach((input, position) => {
          if (position !== spaceOperand) { varnode(input); return; }
          // The constant the lifter put here is the space index; it becomes a space reference.
          writer.openElement(ELEM.SPACEID);
          writer.writeSpace(ATTRIB.NAME, Number(input.offset));
          writer.closeElement(ELEM.SPACEID);
        });
        writer.closeElement(ELEM.OP);
      }
      writer.closeElement(ELEM.INST);
      return answerPacked(writer);
    }],
  ]);

  /**
   * Dispatch one decoded query.
   *
   * An unknown query is answered with nothing rather than refused, because the decompiler asks
   * about far more than Concord models — comments, namespaces, constant pools — and a refusal
   * would abort a decompilation that is perfectly possible without them. Each one is counted, so
   * what was skipped is reported rather than silently absorbed.
   */
  const unanswered = new Map();
  const seen = new Map();
  const answer = (query) => {
    const name = QUERY_NAME.get(query.element) ?? `element ${query.element}`;
    seen.set(name, (seen.get(name) ?? 0) + 1);
    const handler = handlers.get(query.element);
    if (handler) return handler(query);
    unanswered.set(name, (unanswered.get(name) ?? 0) + 1);
    // A string-valued query must still get a string, or refusing it desynchronises the stream
    // instead of simply leaving the decompiler less informed.
    if (STRING_VALUED.has(query.element)) return answerString('');
    // And a query whose caller decodes without checking must get a real element, empty but
    // present, or it segfaults the process rather than proceeding with less information.
    const required = MUST_DECODE.get(query.element);
    if (required !== undefined) {
      const writer = new PackedWriter();
      writer.openElement(required);
      writer.closeElement(required);
      return answerPacked(writer);
    }
    return answerNothing();
  };

  const tally = (map) => [...map].map(([query, count]) => ({ query, count })).sort((a, b) => b.count - a.count);

  return {
    answer,
    counts: () => ({ registers: registersByName.size, userops: userops.length }),
    asked: () => tally(seen),
    unanswered: () => tally(unanswered),
  };
}

/**
 * The core data types the decompiler cannot run without.
 *
 * `registerProgram` takes a `<coretypes>` document, and an empty one is accepted without complaint
 * and then kills the process. `TypeFactory::decodeCoreTypes` calls `cacheCoreTypes`, which fills a
 * table indexed by size and metatype from whatever was declared; with nothing declared every slot
 * stays null, and the first time the analysis wants "a four byte integer" it dereferences one.
 * That presents as a segmentation fault with no message, because the decompiler installs a handler
 * that calls `_Exit(1)` precisely so the operating system shows no dialog — which is how this cost
 * a long time to find: 98 instructions of p-code consumed, then silence.
 *
 * `decodeTypeNoRef` is passed forcecore, so no `core` attribute is needed. Void is its own element
 * rather than a metatype. The set below mirrors the one Ghidra itself sends.
 */
export const CORE_TYPES = [
  '<coretypes>',
  '  <void/>',
  '  <type name="bool" size="1" metatype="bool"/>',
  '  <type name="char" size="1" metatype="int"/>',
  '  <type name="code" size="1" metatype="code"/>',
  ...[1, 2, 4, 8].map((size) => `  <type name="int${size}" size="${size}" metatype="int"/>`),
  ...[1, 2, 4, 8].map((size) => `  <type name="uint${size}" size="${size}" metatype="uint"/>`),
  ...[1, 2, 4, 8].map((size) => `  <type name="undefined${size}" size="${size}" metatype="unknown"/>`),
  ...[4, 8, 10, 16].map((size) => `  <type name="float${size}" size="${size}" metatype="float"/>`),
  '</coretypes>',
].join('\n');

/**
 * Recover C source text from the document `decompileAt` returns.
 *
 * The decompiler does not emit C as text. `print->docFunction` writes *markup* — the same
 * structured form the Ghidra GUI consumes to get clickable, colourised output — so the result
 * frame holds a PackedFormat document whose tokens carry the source in content attributes
 * (`XMLcontent`, id 1), interleaved with the encoded function data. Reading it as text shows
 * recognisable fragments like `__fastcall` and `undefined8` surrounded by binary, which is what
 * makes it tempting to conclude the output is corrupt rather than encoded.
 *
 * Reconstruction is deliberately a flat walk rather than a tree parse: the document mixes several
 * vocabularies (function data, prototypes, print markup) and only two records matter for source
 * text — a content attribute, and `<break indent=N>` (element 17), which is a newline followed by
 * N spaces. Everything else is skipped by length, so an unrecognised element cannot derail it.
 */
export function extractSource(buffer) {
  let index = 0;
  const out = [];

  const readId = () => {
    const header = buffer[index];
    if ((header & HEADEREXTEND) === 0) { index += 1; return header & ELEMENTID_MASK; }
    const id = ((header & ELEMENTID_MASK) << RAWDATA_BITS) | (buffer[index + 1] & RAWDATA_MASK);
    index += 2;
    return id;
  };
  const readRaw = (count) => {
    let value = 0n;
    for (let i = 0; i < count; i++) value = (value << 7n) | BigInt(buffer[index + i] & RAWDATA_MASK);
    index += count;
    return value;
  };

  let inBreak = false;
  while (index < buffer.length) {
    const kind = buffer[index] & HEADER_MASK;
    if (kind === ELEMENT_START) { inBreak = readId() === ELEM.BREAK; continue; }
    if (kind === ELEMENT_END) { readId(); inBreak = false; continue; }
    if (kind !== ATTRIBUTE) { index += 1; continue; }   // not a record this walk understands

    const id = readId();
    const typeByte = buffer[index];
    index += 1;
    const typeCode = typeByte >> TYPECODE_SHIFT;
    const length = typeByte & LENGTHCODE_MASK;
    if (typeCode === TYPE.STRING) {
      const size = Number(readRaw(length));
      const text = buffer.toString('latin1', index, index + size);
      index += size;
      if (id === ATTRIB.CONTENT) out.push(text);
    } else {
      const value = readRaw(length);
      if (inBreak && id === ATTRIB.INDENT) out.push('\n' + ' '.repeat(Number(value)));
    }
  }
  return out.join('');
}

// ---------------------------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------------------------

/**
 * Read the stream strictly in order, rather than searching it for markers.
 *
 * The first driver for this protocol searched the accumulated buffer with indexOf and spliced
 * answered queries out of it. That worked for a handshake and became unreliable at scale: three
 * identical runs answered 572, 241 and 0 queries. Splicing concatenates the bytes on either side of
 * a removed region, which can fabricate a marker that was never sent, and searching for a specific
 * type can match one belonging to a later frame.
 *
 * Sequential parsing has no such failure. A marker is one or more zero bytes, then 0x01, then a
 * type; everything else is payload. Incoming payloads never contain a zero byte — PackedFormat
 * headers are 0x40 or above, its type bytes 0x10 or above, its raw data always carries 0x80, and
 * result text is ASCII — so the delimiter is unambiguous. A partial marker at the end of a chunk is
 * simply left in the buffer until the rest of it arrives.
 */
function createStreamReader({ onMarker, onPayload }) {
  let buffer = Buffer.alloc(0);
  return (chunk) => {
    buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
    let index = 0;
    for (;;) {
      if (index >= buffer.length) break;
      if (buffer[index] !== 0) {
        // Payload up to the next zero byte, which can only begin a marker.
        let end = index;
        while (end < buffer.length && buffer[end] !== 0) end += 1;
        onPayload(buffer.subarray(index, end));
        index = end;
        continue;
      }
      let zeros = index;
      while (zeros < buffer.length && buffer[zeros] === 0) zeros += 1;
      if (zeros + 1 >= buffer.length) break;      // need 0x01 and the type byte
      if (buffer[zeros] !== 1) {
        // Not a marker after all. Zero bytes outside a marker are not part of this protocol, so
        // this refuses rather than resynchronising on a guess.
        fail('DECOMPILE_PROTOCOL', 'A zero run was not followed by a marker byte');
      }
      onMarker(buffer[zeros + 1]);
      index = zeros + 2;
    }
    buffer = index >= buffer.length ? Buffer.alloc(0) : buffer.subarray(index);
  };
}

/**
 * A live decompiler: send commands, answer the questions they provoke, collect the result.
 *
 * The caller provides `spawn` rather than this module importing child_process, so a session can be
 * driven against a scripted transport in a test without a process. stderr is drained
 * unconditionally: an unread pipe fills and blocks the child, which presents as a decompiler that
 * has stopped responding for no visible reason.
 */
export function createSession({ spawn, callbacks, timeoutMs = 120_000, onWarning } = {}) {
  if (typeof spawn !== 'function') fail('DECOMPILE_CONFIG', 'A session needs a way to start the decompiler');
  if (!callbacks?.answer) fail('DECOMPILE_CONFIG', 'A session needs callbacks to answer queries');

  const child = spawn();
  child.stderr?.resume();

  let pending = null;          // the command awaiting its response
  /**
   * Open frames, innermost last.
   *
   * A stack rather than one current frame, because **a query can arrive inside the result frame**.
   * `DecompileAt::rawAction` opens the result string, encodes the function, and calls
   * `print->docFunction`, which fetches comments — so a getComments query is issued with the
   * result frame still open, and the printed C continues into that same frame afterwards.
   *
   * The first version of this reader kept a single `frameType`/`chunks` pair and cleared both when
   * a query started. The effect was the worst possible one: 468 bytes of decompiled C accumulated,
   * were discarded by the nested query, the remaining 241 bytes were dropped because no frame
   * looked open, and the session reported a successful decompilation with an empty result. The
   * decompiler had been right the whole time.
   */
  const frames = [];
  let queryBody = null;        // the most recently closed frame that belongs to a query
  let queryDepth = 0;
  const strings = [];
  const warnings = [];
  let exited = null;

  const settle = (error, value) => {
    const waiting = pending;
    pending = null;
    if (!waiting) return;
    clearTimeout(waiting.timer);
    if (error) waiting.reject(error); else waiting.resolve(value);
  };

  // Payload always belongs to the innermost open frame. Bytes outside any frame are protocol
  // padding and are dropped.
  const onPayload = (payload) => {
    const frame = frames[frames.length - 1];
    if (frame) frame.chunks.push(Buffer.from(payload));
  };

  const onMarker = (type) => {
    switch (type) {
      case BURST.RESPONSE: strings.length = 0; warnings.length = 0; break;

      case BURST.QUERY: queryDepth += 1; queryBody = null; break;

      case BURST.STRING: case BURST.WARNING:
        frames.push({ type, chunks: [] });
        break;

      case BURST.STRING_END: case BURST.WARNING_END: {
        const frame = frames.pop();
        if (!frame) break;
        const body = Buffer.concat(frame.chunks);
        // Inside a query, the closed frame is that query's payload rather than part of the result.
        if (queryDepth > 0) { queryBody = body; break; }
        if (frame.type === BURST.WARNING) warnings.push(body.toString('latin1'));
        else strings.push(body);
        break;
      }

      case BURST.QUERY_END: {
        queryDepth = Math.max(0, queryDepth - 1);
        const body = queryBody ?? Buffer.alloc(0);
        queryBody = null;
        let answer;
        // A query this module cannot even parse is still answered, because leaving it unanswered
        // deadlocks the decompiler on a read instead of degrading the decompilation.
        try { answer = callbacks.answer(decodePacked(body)); }
        catch { answer = answerNothing(); }
        child.stdin.write(answer);
        break;
      }

      case BURST.RESPONSE_END:
        frames.length = 0;
        queryDepth = 0;
        settle(null, { strings: [...strings], warnings: [...warnings] });
        break;
      case BURST.EXCEPTION:
        // The two strings that follow are the exception type and message; they land in `strings`
        // and the response terminator resolves the command, so the caller sees them as a result
        // rather than as a hang.
        break;
      default: break;
    }
  };

  const feed = createStreamReader({ onMarker, onPayload });
  child.stdout.on('data', (chunk) => {
    try { feed(chunk); }
    catch (error) { settle(error); }
  });
  child.on('exit', (code) => {
    exited = code;
    settle(new HarnessError('DECOMPILE_EXITED',
      code === 1
        ? 'The decompiler exited without answering. Exit 1 with no message is its own segv handler, which calls _Exit(1) so the operating system shows no dialog'
        : `The decompiler exited with code ${code}`, { code }));
  });

  const send = (name, parameters) => new Promise((resolve, reject) => {
    if (exited !== null) { reject(new HarnessError('DECOMPILE_EXITED', 'The decompiler has already exited', { code: exited })); return; }
    if (pending) { reject(new HarnessError('DECOMPILE_BUSY', 'A command is already awaiting its response')); return; }
    const timer = setTimeout(() => {
      settle(new HarnessError('DECOMPILE_TIMEOUT', `The decompiler did not finish ${name} within the deadline`, { command: name }));
    }, timeoutMs);
    timer.unref?.();
    pending = { resolve, reject, timer };
    try { child.stdin.write(command(name, parameters)); }
    catch { settle(new HarnessError('DECOMPILE_TRANSPORT', 'The decompiler could not be written')); }
  });

  return {
    /** Returns the architecture id the decompiler assigned, as a string. */
    async registerProgram({ processorSpec, compilerSpec, sleighSpec, coreTypes }) {
      const result = await send('registerProgram', [processorSpec, compilerSpec, sleighSpec, coreTypes]);
      for (const warning of result.warnings) if (warning.trim()) onWarning?.(warning.trim());
      return { archId: (result.strings[0] ?? Buffer.alloc(0)).toString('latin1').trim(), warnings: result.warnings };
    },

    /**
     * Choose what the decompiler does and what it sends back.
     *
     * Not optional, and silently so. `DecompileAt::rawAction` emits C only when
     * `getSendCCode()` is true *and* the current action is named "decompile"; neither holds by
     * default, so a session that never calls this completes successfully and returns an empty
     * result. `print` sets exactly one flag per call ("c", "tree", "parammeasures", or their "no"
     * forms), and an unrecognised value is an error rather than a no-op.
     */
    async setAction({ action = 'decompile', print = 'c', archId = '0' } = {}) {
      const result = await send('setAction', [archId, action, print]);
      const ok = (result.strings[0] ?? Buffer.alloc(0)).toString('latin1').trim() === 't';
      if (!ok) fail('DECOMPILE_SETACTION', 'The decompiler refused the action', { action, print });
      return { action, print };
    },

    /** Decompile at an address. The C, when there is any, is the longest string in the response. */
    async decompileAt({ archId = '0', space, offset }) {
      const addr = new PackedWriter();
      addr.openElement(ELEM.ADDR).writeSpace(ATTRIB.SPACE, space).writeUnsignedInteger(ATTRIB.OFFSET, offset).closeElement(ELEM.ADDR);
      const result = await send('decompileAt', [archId, addr.toBuffer()]);
      for (const warning of result.warnings) if (warning.trim()) onWarning?.(warning.trim());
      const text = result.strings.map((entry) => entry.toString('latin1')).sort((a, b) => b.length - a.length)[0] ?? '';
      return { text, warnings: result.warnings, strings: result.strings.length };
    },

    close() { try { child.stdin.end(); } catch { /* already closed */ } },
  };
}

// ---------------------------------------------------------------------------------------------
// The kernel tool
// ---------------------------------------------------------------------------------------------

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const DEFAULT_TIMEOUT = 120_000;
const DEFAULT_OUTPUT = 33_554_432;
const DEFAULT_WINDOW = 0x8000;
const TOOL_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const HEX_ADDRESS = /^0x[0-9a-fA-F]{1,16}$/;

const positive = (value, fallback, label) => {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 2_147_483_647) {
    fail('DECOMPILE_CONFIG', `${label} must be a positive bounded integer`);
  }
  return result;
};

/**
 * Reviewed configuration, shaped exactly like the browser tool's.
 *
 * The executable is an absolute path from configuration an operator reviewed, never from a plan,
 * and `executableSha256` pins which build runs. That matters more here than for most process
 * tools: this one hands a decompiler bytes from an untrusted binary and then treats what comes
 * back as program structure, so which binary is doing the parsing is part of what the receipt
 * attests to.
 */
function decompilerSettings(value) {
  const config = { ...value };
  config.name = config.name ?? 'artifact.decompile';
  if (typeof config.name !== 'string' || !TOOL_NAME.test(config.name)) fail('DECOMPILE_CONFIG', 'Invalid decompiler tool name');
  if (typeof config.executable !== 'string' || !config.executable || config.executable.includes('\0')) {
    fail('DECOMPILE_CONFIG', 'Decompiler executable must be a nonempty string');
  }
  if (!isAbsolute(config.executable)) fail('DECOMPILE_CONFIG', 'Decompiler executable must be an absolute path');
  if (config.executableSha256 !== undefined && !/^[a-f0-9]{64}$/.test(config.executableSha256)) {
    fail('DECOMPILE_CONFIG', 'Invalid decompiler executable digest');
  }
  config.timeoutMs = positive(config.timeoutMs, DEFAULT_TIMEOUT, 'timeoutMs');
  config.maxOutputBytes = positive(config.maxOutputBytes, DEFAULT_OUTPUT, 'maxOutputBytes');
  const allowed = ['name', 'executable', 'executableSha256', 'timeoutMs', 'maxOutputBytes'];
  if (Object.keys(value).some((key) => !allowed.includes(key))) fail('DECOMPILE_CONFIG', 'Unsupported decompiler configuration field');
  return config;
}

/** Policy narrows configuration and never widens it, as everywhere else. */
function limits(config, context, name) {
  const policy = context?.policy ?? {};
  if (Array.isArray(policy.allowedTools) && !policy.allowedTools.includes(name)) fail('DECOMPILE_POLICY', 'Decompiler tool is not allowlisted');
  if (Array.isArray(policy.allowedEffects) && !policy.allowedEffects.includes('process')) fail('DECOMPILE_POLICY', 'Decompiler effect is not allowlisted');
  if (context?.signal?.aborted) fail('DECOMPILE_ABORTED', 'Decompilation was cancelled');
  return {
    timeoutMs: Math.min(config.timeoutMs, positive(policy.timeoutMs, config.timeoutMs, 'policy timeoutMs')),
    maxOutputBytes: Math.min(config.maxOutputBytes, positive(policy.maxOutputBytes, config.maxOutputBytes, 'policy maxOutputBytes')),
  };
}

/**
 * The stripped-down SLEIGH spec, generated from the language rather than written by hand.
 *
 * The constant space is omitted deliberately: `AddrSpaceManager::decodeSpaces` inserts it before
 * reading any declared space, so listing it produces two.
 */
function sleighSpecFor(language) {
  const element = { other: 'space_other', unique: 'space_unique', addressable: 'space' };
  const spaces = (language.spaces ?? []).map((space) => `    <${element[space.kind] ?? 'space'} name="${space.name}"`
    + ` index="${space.index}" size="${space.size}" wordsize="${space.wordSize}"`
    + ` bigendian="${Boolean(language.bigEndian)}" delay="${space.name === 'ram' ? 1 : 0}"/>`).join('\n');
  return `<sleigh bigendian="${Boolean(language.bigEndian)}" uniqbase="0x100000" uniqmask="${language.uniqueMask ?? 0}">\n`
    + `  <spaces defaultspace="ram">\n${spaces}\n  </spaces>\n</sleigh>`;
}

/**
 * Decompilation as a kernel tool.
 *
 * A `process` effect, so a plan cannot reach it without an approval hash bound to the exact
 * resolved input, and the C it returns is journaled and replayed from the receipt rather than
 * re-derived. Unconfigured, it registers nothing at all — an operator who has not reviewed a
 * decompiler binary gets no tool, not a tool that always refuses.
 *
 * The function list comes from this harness's own region discovery, never from the decompiler's
 * curiosity. Claiming a function wherever it happens to ask would invent them in data, and every
 * name in the output would then be evidence of nothing.
 */
export function makeDecompilerTools(config) {
  if (config === undefined) return [];
  const settings = decompilerSettings(config);
  const inspect = makeArtifactTools().find((tool) => tool.name === 'artifact.inspect');

  const inputSchema = {
    type: 'object', additionalProperties: false,
    required: ['path', 'table', 'processorSpec', 'compilerSpec', 'address'],
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 4096, description: 'The binary to decompile, in the workspace' },
      table: { type: 'string', minLength: 1, maxLength: 4096, description: 'The compiled SLEIGH table (.sla) for its language' },
      processorSpec: { type: 'string', minLength: 1, maxLength: 4096, description: 'The .pspec for that language' },
      compilerSpec: { type: 'string', minLength: 1, maxLength: 4096, description: 'The .cspec for the calling convention' },
      // Validated in execute rather than here: the kernel's schema subset has no pattern keyword,
      // and declaring one fails every plan using this tool with INVALID_SCHEMA at compile time.
      address: { type: 'string', minLength: 3, maxLength: 18, description: 'Loaded virtual address, as 0x-prefixed hex' },
      window: { type: 'integer', minimum: 256, maximum: 1048576, description: 'Bytes of code analysed to discover functions' },
      context: { type: 'object', additionalProperties: { type: 'integer' }, description: 'Initial SLEIGH context values from the .pspec' },
    },
  };

  return [{
    name: settings.name, version: '1', effect: 'process', config: settings, inputSchema,
    outputKeys: ['supported', 'reason', 'source', 'address', 'functionName', 'counts', 'warnings', 'path', 'sha256', 'untrusted', 'limitations'],

    async execute(input, context) {
      const bound = limits(settings, context, settings.name);
      if (!HEX_ADDRESS.test(input.address)) fail('DECOMPILE_INPUT', 'address must be 0x-prefixed hexadecimal');
      const target = BigInt(input.address);

      const limitations = [
        'The C below was produced by a decompiler this harness does not implement, from p-code this harness lifted. It is an interpretation of bytes under one chosen language, and selecting the wrong table produces confident nonsense rather than a refusal',
        'Function names are generated from the addresses this harness discovered, not read from the binary. A name is a label for a region, not a claim about what the code was called',
        'Only functions reachable from the given address were discovered, so a call to an address outside that set is reported by address and is not evidence that nothing is there',
      ];
      const refuse = (reason, bytes) => ({
        supported: false, reason, source: '', address: input.address, functionName: null,
        counts: {}, warnings: [], path: input.path, sha256: bytes ? sha256(bytes) : null, untrusted: true, limitations,
      });

      const image = readWorkspaceFile(context.workspaceRoot, input.path, bound.maxOutputBytes);
      // The header comes from artifact.inspect rather than a private copy of the section logic, so
      // the mapping this tool uses is the same one every other caller sees.
      const header = inspect.execute({ path: input.path }, context);
      const layout = header.pe ?? header.elf ?? null;
      if (!layout) return refuse('unsupported_format', image);
      const sections = layout.sections ?? layout.segments ?? [];
      const base = BigInt(layout.imageBase ?? 0);
      if (!sections.length) return refuse('no_section_table', image);

      const sectionOf = (address) => {
        const relative = Number(BigInt(address) - base);
        return sections.find((entry) => {
          const start = entry.virtualAddress ?? entry.vaddr;
          const size = Math.max(entry.virtualSize ?? 0, entry.fileSize ?? 0);
          return relative >= start && relative < start + size;
        }) ?? null;
      };
      const fileOffsetOf = (address) => {
        const section = sectionOf(address);
        if (!section) return null;
        return Number(BigInt(address) - base) - (section.virtualAddress ?? section.vaddr) + section.fileOffset;
      };
      if (fileOffsetOf(target) === null) return refuse('address_not_mapped', image);

      let language;
      try { language = loadLanguage(readWorkspaceFile(context.workspaceRoot, input.table, bound.maxOutputBytes)); }
      catch (error) { return { ...refuse('table_unreadable', image), reason: 'table_unreadable', warnings: [error?.message ?? 'unreadable'] }; }

      const spaceIndex = (name) => (name === 'const' || name === 'constant' ? 0
        : (language.spaces ?? []).find((space) => space.name === (typeof name === 'string' ? name : name?.name))?.index ?? 0);
      const ram = spaceIndex('ram');
      const readImage = (offset, size) => {
        const at = fileOffsetOf(offset);
        if (at === null || at < 0 || at + size > image.length) return null;
        return image.subarray(at, at + size);
      };
      const lift = (offset) => {
        const at = fileOffsetOf(offset);
        if (at === null) return null;
        try { return liftInstruction(language, image.subarray(at, Math.min(image.length, at + 16)), { address: BigInt(offset), contextValues: input.context ?? {} }); }
        catch { return null; }
      };

      // Region discovery, bounded by the window, over the section holding the target.
      const section = sectionOf(target);
      const window = input.window ?? DEFAULT_WINDOW;
      const start = Math.max(section.fileOffset, fileOffsetOf(target) - Math.floor(window / 8));
      const startAddress = base + BigInt(start - section.fileOffset + (section.virtualAddress ?? section.vaddr));
      let discovered;
      try {
        discovered = recoverCallGraph(language, image.subarray(start, Math.min(image.length, start + window)), {
          address: startAddress, entries: [target], contextValues: input.context ?? {}, limit: 4096, regionLimit: 128,
        });
      } catch (error) { return { ...refuse('flow_failed', image), warnings: [error?.message ?? 'flow failed'] }; }

      const functions = new Map();
      for (const region of discovered.regions ?? []) {
        const entry = BigInt(region.entry);
        functions.set(entry.toString(), {
          name: `FUN_${entry.toString(16)}`, entry,
          size: Math.max(1, Number(BigInt(region.end) - BigInt(region.start))),
        });
      }
      const ordered = [...functions.values()].map((entry) => entry.entry).sort((a, b) => (a < b ? -1 : 1));
      if (!functions.has(target.toString())) return refuse('no_function_at_address', image);

      /** The true gap between two discovered functions, or a whole non-code section. */
      const holeAround = (offset, space) => {
        const at = BigInt(offset);
        if (space !== ram) return { first: 0n, last: 0xffffffffn };
        if (functions.has(at.toString())) return null;
        const holding = sectionOf(at);
        if (!holding) return { first: at, last: at };
        const low = base + BigInt(holding.virtualAddress ?? holding.vaddr);
        const high = low + BigInt(Math.max(holding.virtualSize ?? 0, holding.fileSize ?? 0)) - 1n;
        if (holding !== section) return { first: low, last: high };
        let first = low;
        let last = high;
        for (const entry of ordered) {
          if (entry <= at && entry > first) first = entry;
          if (entry > at && entry - 1n < last) last = entry - 1n;
        }
        return { first, last };
      };

      const callbacks = createCallbacks({
        language, spaceIndex, readImage, lift, holeAround,
        findFunction: (offset, space) => (space === ram ? functions.get(BigInt(offset).toString()) ?? null : null),
      });

      let executable;
      try {
        executable = await realpath(settings.executable);
        if (resolvePath(executable) !== resolvePath(settings.executable) || !(await stat(executable)).isFile()) {
          fail('DECOMPILE_EXECUTABLE', 'Decompiler executable must be an existing regular file without path aliases');
        }
        if (settings.executableSha256 && createHash('sha256').update(await readFile(executable)).digest('hex') !== settings.executableSha256) {
          fail('DECOMPILE_EXECUTABLE', 'Decompiler executable digest does not match');
        }
      } catch (error) {
        if (error instanceof HarnessError) throw error;
        fail('DECOMPILE_PATH', 'Decompiler executable is unavailable');
      }

      const warnings = [];
      const session = createSession({
        spawn: () => spawn(executable, [], { env: {}, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }),
        callbacks, timeoutMs: bound.timeoutMs, onWarning: (warning) => warnings.push(warning),
      });
      try {
        const registered = await session.registerProgram({
          processorSpec: readWorkspaceFile(context.workspaceRoot, input.processorSpec, bound.maxOutputBytes).toString('latin1'),
          compilerSpec: readWorkspaceFile(context.workspaceRoot, input.compilerSpec, bound.maxOutputBytes).toString('latin1'),
          sleighSpec: sleighSpecFor(language), coreTypes: CORE_TYPES,
        });
        // Without this the decompiler completes and returns nothing: rawAction emits C only when
        // getSendCCode() holds and the current action is named decompile.
        await session.setAction({ archId: registered.archId, action: 'decompile', print: 'c' });
        const result = await session.decompileAt({ archId: registered.archId, space: ram, offset: target });
        const source = extractSource(Buffer.from(result.text, 'latin1'));
        if (!source) return { ...refuse('analysis_incomplete', image), warnings: [...warnings, ...result.warnings] };
        if (Buffer.byteLength(source) > bound.maxOutputBytes) return { ...refuse('output_limit', image), warnings };
        return {
          supported: true, reason: null, source, address: input.address,
          functionName: functions.get(target.toString()).name,
          counts: {
            functions: functions.size,
            queries: callbacks.asked().reduce((total, entry) => total + entry.count, 0),
            sourceBytes: Buffer.byteLength(source),
          },
          warnings: [...warnings, ...result.warnings].filter((entry) => entry.trim()),
          path: input.path, sha256: sha256(image), untrusted: true, limitations,
        };
      } finally { session.close(); }
    },
  }];
}

export const protocol = {
  BURST, QUERY, QUERY_NAME, ATTRIB, ELEM, TYPE,
  burst, stringFrame, command, splitFrames,
  PackedWriter, decodePacked,
  answerNothing, answerString, answerPacked, answerBytes,
};
