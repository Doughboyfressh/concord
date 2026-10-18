import { createHash } from 'node:crypto';
import { readWorkspaceFile } from './workspace-fs.mjs';

/**
 * Android DEX, APK and binary XML, read from the documented layouts.
 *
 * REA reaches these through apktool and JEB. The formats are fully specified, so they are read
 * here from the bytes with no dependency and nothing executed. Every table walk is bounded, and a
 * structure that does not fit the file is reported as a limitation rather than guessed at: a
 * partially recovered class list is indistinguishable from a complete one once it is output.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const MAX_STRINGS = 200000;
const MAX_TYPES = 65536;
const MAX_CLASSES = 65536;
const MAX_METHODS = 200000;
const MAX_FIELDS = 200000;
const MAX_MEMBERS_PER_CLASS = 4096;
const MAX_STRING_CHARS = 4096;
const MAX_LISTED = 2000;
const MAX_XML_NODES = 20000;
const MAX_ZIP_ENTRIES = 20000;

const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a];
const ACCESS_FLAGS = [
  [0x00001, 'public'], [0x00002, 'private'], [0x00004, 'protected'], [0x00008, 'static'],
  [0x00010, 'final'], [0x00020, 'synchronized'], [0x00040, 'volatile'], [0x00080, 'transient'],
  [0x00100, 'native'], [0x00200, 'interface'], [0x00400, 'abstract'], [0x00800, 'strict'],
  [0x01000, 'synthetic'], [0x02000, 'annotation'], [0x04000, 'enum'],
  [0x10000, 'constructor'], [0x20000, 'declared-synchronized'],
];
const PRIMITIVES = { V: 'void', Z: 'boolean', B: 'byte', S: 'short', C: 'char', I: 'int', J: 'long', F: 'float', D: 'double' };

const u32 = (b, o) => (o < 0 || o + 4 > b.length ? undefined : b.readUInt32LE(o));
const u16 = (b, o) => (o < 0 || o + 2 > b.length ? undefined : b.readUInt16LE(o));

/** Unsigned LEB128, as DEX uses for sizes and index deltas. */
function uleb(b, o) {
  let value = 0;
  for (let i = 0; i < 5; i++) {
    if (o + i >= b.length) return undefined;
    const byte = b[o + i];
    value |= (byte & 0x7f) << (i * 7);
    if ((byte & 0x80) === 0) return { value: value >>> 0, offset: o + i + 1 };
  }
  return undefined;
}

/**
 * MUTF-8, which is not UTF-8: U+0000 is two bytes and characters above the BMP arrive as two
 * three-byte sequences holding surrogates. Decoding to UTF-16 code units handles both, where a
 * plain UTF-8 decoder would reject the surrogates outright.
 */
function mutf8(b, o, limit) {
  const units = [];
  let at = o;
  while (at < b.length && units.length <= limit) {
    const byte = b[at];
    if (byte === 0) return { value: String.fromCharCode(...units), offset: at + 1 };
    if ((byte & 0x80) === 0) { units.push(byte); at += 1; continue; }
    if ((byte & 0xe0) === 0xc0) {
      if (at + 1 >= b.length) return undefined;
      units.push(((byte & 0x1f) << 6) | (b[at + 1] & 0x3f));
      at += 2;
      continue;
    }
    if ((byte & 0xf0) === 0xe0) {
      if (at + 2 >= b.length) return undefined;
      units.push(((byte & 0x0f) << 12) | ((b[at + 1] & 0x3f) << 6) | (b[at + 2] & 0x3f));
      at += 3;
      continue;
    }
    return undefined;
  }
  return undefined;
}

/** `Lcom/example/Foo;` becomes `com.example.Foo`; `[I` becomes `int[]`. */
function readableType(descriptor) {
  if (typeof descriptor !== 'string' || !descriptor.length) return null;
  let depth = 0;
  let at = 0;
  while (at < descriptor.length && descriptor[at] === '[') { depth += 1; at += 1; }
  const rest = descriptor.slice(at);
  let base;
  if (rest.startsWith('L') && rest.endsWith(';')) base = rest.slice(1, -1).replaceAll('/', '.');
  else if (rest.length === 1 && PRIMITIVES[rest]) base = PRIMITIVES[rest];
  else return null;
  return base + '[]'.repeat(depth);
}

const flagNames = (value) => ACCESS_FLAGS.filter(([bit]) => (value & bit) !== 0).map(([, name]) => name);

/**
 * Parse one DEX file into its index tables.
 *
 * Strings, types, methods and fields are read eagerly because every later lookup resolves through
 * them; class member lists are read per class on demand, since a large application DEX would
 * otherwise produce an output no policy budget would accept.
 */
export function parseDex(buffer) {
  const limitations = [];
  if (buffer.length < 112 || !DEX_MAGIC.every((byte, i) => buffer[i] === byte)) {
    return { supported: false, reason: 'not_dex', detail: 'The file carries no DEX magic', limitations };
  }
  const versionText = buffer.toString('latin1', 4, 7);
  if (!/^0[0-9]{2}$/.test(versionText)) {
    return { supported: false, reason: 'version_unreadable', detail: 'The DEX version field is not three digits', limitations };
  }
  const endianTag = u32(buffer, 40);
  if (endianTag !== 0x12345678) {
    return { supported: false, reason: 'byte_order_unsupported',
      detail: 'Only little-endian DEX files are read; the reverse-endian tag is not handled', limitations };
  }
  const header = {
    version: Number(versionText), headerSize: u32(buffer, 36), fileSize: u32(buffer, 32),
    checksum: u32(buffer, 8), signature: buffer.toString('hex', 12, 32),
    mapOffset: u32(buffer, 52),
    stringIds: { size: u32(buffer, 56), offset: u32(buffer, 60) },
    typeIds: { size: u32(buffer, 64), offset: u32(buffer, 68) },
    protoIds: { size: u32(buffer, 72), offset: u32(buffer, 76) },
    fieldIds: { size: u32(buffer, 80), offset: u32(buffer, 84) },
    methodIds: { size: u32(buffer, 88), offset: u32(buffer, 92) },
    classDefs: { size: u32(buffer, 96), offset: u32(buffer, 100) },
    dataSection: { size: u32(buffer, 104), offset: u32(buffer, 108) },
  };
  if (header.fileSize !== buffer.length) {
    limitations.push('The header declares a file size that differs from the bytes read, so the file is truncated or padded');
  }

  const bounded = (table, max, label) => {
    if (typeof table.size !== 'number' || typeof table.offset !== 'number') { limitations.push(`The ${label} table header is unreadable`); return 0; }
    if (table.size > max) { limitations.push(`The ${label} table exceeds the read bound, so it was cut short`); return max; }
    return table.size;
  };

  // Strings first: every other table resolves names through them.
  const strings = [];
  const stringCount = bounded(header.stringIds, MAX_STRINGS, 'string id');
  for (let i = 0; i < stringCount; i++) {
    const dataOffset = u32(buffer, header.stringIds.offset + i * 4);
    if (dataOffset === undefined) { limitations.push('A string id lies outside the file'); break; }
    const size = uleb(buffer, dataOffset);
    if (!size) { limitations.push('A string length is malformed'); strings.push(null); continue; }
    const decoded = mutf8(buffer, size.offset, MAX_STRING_CHARS);
    if (!decoded) { limitations.push('A string could not be decoded as MUTF-8'); strings.push(null); continue; }
    strings.push(decoded.value);
  }

  const types = [];
  const typeCount = bounded(header.typeIds, MAX_TYPES, 'type id');
  for (let i = 0; i < typeCount; i++) {
    const index = u32(buffer, header.typeIds.offset + i * 4);
    types.push(index === undefined ? null : strings[index] ?? null);
  }
  const typeName = (index) => (typeof index === 'number' && index < types.length ? types[index] : null);

  const protos = [];
  const protoCount = bounded(header.protoIds, MAX_TYPES, 'prototype id');
  for (let i = 0; i < protoCount; i++) {
    const at = header.protoIds.offset + i * 12;
    const returnTypeIdx = u32(buffer, at + 4);
    const parametersOffset = u32(buffer, at + 8);
    const parameters = [];
    if (parametersOffset) {
      const size = u32(buffer, parametersOffset);
      if (size !== undefined && size <= MAX_MEMBERS_PER_CLASS) {
        for (let p = 0; p < size; p++) parameters.push(typeName(u16(buffer, parametersOffset + 4 + p * 2)));
      } else limitations.push('A prototype parameter list is unreadable or too long');
    }
    protos.push({ shorty: strings[u32(buffer, at)] ?? null, returnType: typeName(returnTypeIdx), parameters });
  }

  const fields = [];
  const fieldCount = bounded(header.fieldIds, MAX_FIELDS, 'field id');
  for (let i = 0; i < fieldCount; i++) {
    const at = header.fieldIds.offset + i * 8;
    fields.push({ class: typeName(u16(buffer, at)), type: typeName(u16(buffer, at + 2)), name: strings[u32(buffer, at + 4)] ?? null });
  }

  const methods = [];
  const methodCount = bounded(header.methodIds, MAX_METHODS, 'method id');
  for (let i = 0; i < methodCount; i++) {
    const at = header.methodIds.offset + i * 8;
    const protoIndex = u16(buffer, at + 2);
    methods.push({ class: typeName(u16(buffer, at)), name: strings[u32(buffer, at + 4)] ?? null,
      proto: protoIndex !== undefined && protoIndex < protos.length ? protos[protoIndex] : null });
  }

  const classes = [];
  const classCount = bounded(header.classDefs, MAX_CLASSES, 'class definition');
  for (let i = 0; i < classCount; i++) {
    const at = header.classDefs.offset + i * 32;
    const classIdx = u32(buffer, at);
    if (classIdx === undefined) { limitations.push('A class definition lies outside the file'); break; }
    const interfacesOffset = u32(buffer, at + 12);
    const interfaces = [];
    if (interfacesOffset) {
      const size = u32(buffer, interfacesOffset);
      if (size !== undefined && size <= MAX_MEMBERS_PER_CLASS) {
        for (let k = 0; k < size; k++) interfaces.push(typeName(u16(buffer, interfacesOffset + 4 + k * 2)));
      } else limitations.push('An interface list is unreadable or too long');
    }
    const sourceFileIdx = u32(buffer, at + 16);
    classes.push({
      index: i, descriptor: typeName(classIdx), readable: readableType(typeName(classIdx)),
      accessFlags: u32(buffer, at + 4),
      access: flagNames(u32(buffer, at + 4) ?? 0),
      superclass: typeName(u32(buffer, at + 8)), interfaces,
      sourceFile: sourceFileIdx === 0xffffffff ? null : strings[sourceFileIdx] ?? null,
      classDataOffset: u32(buffer, at + 24),
    });
  }

  return { supported: true, reason: null, header, versionText, strings, types, protos, fields, methods, classes, limitations };
}

/** Members of one class, from its class_data_item. Indices are stored as deltas. */
function classMembers(buffer, dex, classDataOffset) {
  const limitations = [];
  const empty = { staticFields: [], instanceFields: [], directMethods: [], virtualMethods: [], limitations };
  if (!classDataOffset) return empty;
  let cursor = classDataOffset;
  const counts = [];
  for (let i = 0; i < 4; i++) {
    const got = uleb(buffer, cursor);
    if (!got) { limitations.push('A class data header is malformed'); return empty; }
    counts.push(got.value);
    cursor = got.offset;
  }
  if (counts.some((count) => count > MAX_MEMBERS_PER_CLASS)) {
    limitations.push('A class declares more members than the read bound permits');
    return empty;
  }
  const readFields = (count) => {
    const out = [];
    let index = 0;
    for (let i = 0; i < count; i++) {
      const delta = uleb(buffer, cursor);
      if (!delta) { limitations.push('A field index delta is malformed'); return out; }
      const flags = uleb(buffer, delta.offset);
      if (!flags) { limitations.push('A field access value is malformed'); return out; }
      index += delta.value;
      cursor = flags.offset;
      const field = dex.fields[index];
      out.push({ index, name: field ? field.name : null, type: field ? field.type : null,
        declaringClass: field ? field.class : null, access: flagNames(flags.value) });
    }
    return out;
  };
  const readMethods = (count) => {
    const out = [];
    let index = 0;
    for (let i = 0; i < count; i++) {
      const delta = uleb(buffer, cursor);
      if (!delta) { limitations.push('A method index delta is malformed'); return out; }
      const flags = uleb(buffer, delta.offset);
      if (!flags) { limitations.push('A method access value is malformed'); return out; }
      const codeOffset = uleb(buffer, flags.offset);
      if (!codeOffset) { limitations.push('A method code offset is malformed'); return out; }
      index += delta.value;
      cursor = codeOffset.offset;
      const method = dex.methods[index];
      out.push({ index, name: method ? method.name : null, declaringClass: method ? method.class : null,
        returnType: method && method.proto ? method.proto.returnType : null,
        parameters: method && method.proto ? method.proto.parameters : [],
        access: flagNames(flags.value), hasCode: codeOffset.value !== 0,
        registerCount: codeOffset.value ? u16(buffer, codeOffset.value) ?? null : null });
    }
    return out;
  };
  const staticFields = readFields(counts[0]);
  const instanceFields = readFields(counts[1]);
  const directMethods = readMethods(counts[2]);
  const virtualMethods = readMethods(counts[3]);
  return { staticFields, instanceFields, directMethods, virtualMethods, limitations };
}

// ---- Android binary XML (AXML) ----
const AXML_CHUNK_STRING_POOL = 0x0001;
const AXML_CHUNK_START_TAG = 0x0102;
const AXML_CHUNK_END_TAG = 0x0103;
const AXML_CHUNK_TEXT = 0x0104;

/** The AXML string pool: UTF-16LE by default, UTF-8 when the pool says so. */
function axmlStringPool(buffer, start, limitations) {
  const stringCount = u32(buffer, start + 8);
  const stringsStart = u32(buffer, start + 20);
  const flags = u32(buffer, start + 16);
  if (stringCount === undefined || stringsStart === undefined || stringCount > MAX_STRINGS) {
    limitations.push('The string pool header is unreadable');
    return [];
  }
  const utf8 = (flags & 0x00000100) !== 0;
  const pool = [];
  for (let i = 0; i < stringCount; i++) {
    const offset = u32(buffer, start + 28 + i * 4);
    if (offset === undefined) { pool.push(null); continue; }
    const at = start + stringsStart + offset;
    if (at + 2 > buffer.length) { pool.push(null); continue; }
    if (utf8) {
      // Two lengths: characters then bytes, each one or two bytes.
      let cursor = at;
      const skip = (b) => ((b & 0x80) !== 0 ? 2 : 1);
      cursor += skip(buffer[cursor]);
      const byteLengthFirst = buffer[cursor];
      let byteLength = byteLengthFirst;
      if ((byteLengthFirst & 0x80) !== 0) { byteLength = ((byteLengthFirst & 0x7f) << 8) | buffer[cursor + 1]; cursor += 2; }
      else cursor += 1;
      if (cursor + byteLength > buffer.length || byteLength > MAX_STRING_CHARS * 4) { pool.push(null); continue; }
      try { pool.push(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(cursor, cursor + byteLength))); }
      catch { pool.push(null); }
    } else {
      let length = u16(buffer, at);
      let cursor = at + 2;
      if (length !== undefined && (length & 0x8000) !== 0) { length = ((length & 0x7fff) << 16) | u16(buffer, cursor); cursor += 2; }
      if (length === undefined || cursor + length * 2 > buffer.length || length > MAX_STRING_CHARS) { pool.push(null); continue; }
      try { pool.push(new TextDecoder('utf-16le', { fatal: true }).decode(buffer.subarray(cursor, cursor + length * 2))); }
      catch { pool.push(null); }
    }
  }
  return pool;
}

const AXML_TYPES = { 0x03: 'string', 0x10: 'int', 0x11: 'hex', 0x12: 'boolean', 0x04: 'float', 0x01: 'reference', 0x02: 'attribute' };

/** Decode AndroidManifest-style binary XML into an element tree. */
export function parseAxml(buffer) {
  const limitations = [];
  if (buffer.length < 8 || u16(buffer, 0) !== 0x0003 || u16(buffer, 2) !== 8) {
    return { supported: false, reason: 'not_axml', detail: 'The file carries no AXML resource header', elements: [], limitations };
  }
  const fileSize = u32(buffer, 4);
  if (fileSize !== undefined && fileSize > buffer.length) limitations.push('The AXML header declares more bytes than the file contains');
  let pool = [];
  const stack = [];
  const roots = [];
  let offset = 8;
  for (let i = 0; i < MAX_XML_NODES && offset + 8 <= buffer.length; i++) {
    const type = u16(buffer, offset);
    const size = u32(buffer, offset + 4);
    if (size === undefined || size < 8 || offset + size > buffer.length) { limitations.push('A chunk size is malformed'); break; }
    if (type === AXML_CHUNK_STRING_POOL) pool = axmlStringPool(buffer, offset, limitations);
    else if (type === AXML_CHUNK_START_TAG) {
      const nameIndex = u32(buffer, offset + 20);
      const attributeCount = u16(buffer, offset + 28);
      const attributesStart = u16(buffer, offset + 24);
      const element = { name: pool[nameIndex] ?? null, attributes: [], children: [] };
      if (attributeCount !== undefined && attributeCount <= MAX_MEMBERS_PER_CLASS) {
        for (let a = 0; a < attributeCount; a++) {
          const at = offset + 16 + attributesStart + a * 20;
          if (at + 20 > buffer.length) { limitations.push('An attribute lies outside its chunk'); break; }
          const valueType = buffer[at + 15];
          const data = u32(buffer, at + 16);
          element.attributes.push({
            namespace: pool[u32(buffer, at)] ?? null,
            name: pool[u32(buffer, at + 4)] ?? null,
            type: AXML_TYPES[valueType] ?? null,
            value: valueType === 0x03 ? pool[data] ?? null
              : valueType === 0x12 ? data !== 0
                : valueType === 0x11 ? '0x' + (data ?? 0).toString(16)
                  : data ?? null,
          });
        }
      } else limitations.push('An element declares more attributes than the read bound permits');
      if (stack.length) stack[stack.length - 1].children.push(element); else roots.push(element);
      stack.push(element);
    } else if (type === AXML_CHUNK_END_TAG) {
      if (!stack.length) { limitations.push('An end tag appeared with no matching start tag'); break; }
      stack.pop();
    } else if (type === AXML_CHUNK_TEXT) {
      const text = pool[u32(buffer, offset + 16)] ?? null;
      if (stack.length && text !== null) stack[stack.length - 1].children.push({ text });
    }
    offset += size;
  }
  if (stack.length) limitations.push('The document ended with unclosed elements');
  return { supported: true, reason: null, elements: roots, stringCount: pool.length, limitations };
}

const listed = (items, limitations, label) => {
  if (items.length <= MAX_LISTED) return items;
  limitations.push(`Only the first ${MAX_LISTED} ${label} are listed`);
  return items.slice(0, MAX_LISTED);
};

const readFor = (context, relative) => readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / 4));

/** DEX, APK and AXML readers. Nothing here executes bytecode or launches a tool. */
export function makeDexTools() {
  const pathOnly = object({ path: string });
  return [
    { name: 'artifact.dex', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'classes', 'counts', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readFor(context, relative);
        const dex = parseDex(bytes);
        const base = { path: relative, sha256: sha256(bytes), untrusted: true };
        if (!dex.supported) return { ...base, supported: false, reason: dex.reason, detail: dex.detail, classes: [], counts: null, limitations: dex.limitations };
        const limitations = [...dex.limitations];
        return { ...base, supported: true, reason: null, version: dex.header.version, signature: dex.header.signature,
          counts: { strings: dex.strings.length, types: dex.types.length, protos: dex.protos.length,
            fields: dex.fields.length, methods: dex.methods.length, classes: dex.classes.length },
          classes: listed(dex.classes.map((entry) => ({ index: entry.index, descriptor: entry.descriptor,
            readable: entry.readable, access: entry.access, superclass: entry.superclass,
            interfaces: entry.interfaces, sourceFile: entry.sourceFile })), limitations, 'classes'),
          limitations };
      } },
    { name: 'artifact.dexClass', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'class', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, descriptor: string }, ['path', 'descriptor']),
      execute({ path: relative, descriptor }, context) {
        const bytes = readFor(context, relative);
        const dex = parseDex(bytes);
        const base = { path: relative, sha256: sha256(bytes), untrusted: true };
        if (!dex.supported) return { ...base, supported: false, reason: dex.reason, detail: dex.detail, class: null, limitations: dex.limitations };
        const found = dex.classes.find((entry) => entry.descriptor === descriptor);
        if (!found) {
          return { ...base, supported: true, reason: 'class_absent',
            detail: 'The DEX declares no class with that descriptor', class: null, limitations: dex.limitations };
        }
        const members = classMembers(bytes, dex, found.classDataOffset);
        return { ...base, supported: true, reason: null,
          class: { descriptor: found.descriptor, readable: found.readable, access: found.access, superclass: found.superclass,
            interfaces: found.interfaces, sourceFile: found.sourceFile,
            staticFields: members.staticFields, instanceFields: members.instanceFields,
            directMethods: members.directMethods, virtualMethods: members.virtualMethods },
          limitations: [...dex.limitations, ...members.limitations] };
      } },
    { name: 'artifact.dexMethod', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'methods', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, descriptor: string, name: string }, ['path', 'descriptor']),
      execute({ path: relative, descriptor, name }, context) {
        const bytes = readFor(context, relative);
        const dex = parseDex(bytes);
        const base = { path: relative, sha256: sha256(bytes), untrusted: true };
        if (!dex.supported) return { ...base, supported: false, reason: dex.reason, detail: dex.detail, methods: [], limitations: dex.limitations };
        const found = dex.classes.find((entry) => entry.descriptor === descriptor);
        if (!found) return { ...base, supported: true, reason: 'class_absent', detail: 'The DEX declares no class with that descriptor', methods: [], limitations: dex.limitations };
        const members = classMembers(bytes, dex, found.classDataOffset);
        const all = [...members.directMethods.map((m) => ({ ...m, kind: 'direct' })), ...members.virtualMethods.map((m) => ({ ...m, kind: 'virtual' }))];
        const matched = name === undefined ? all : all.filter((m) => m.name === name);
        const limitations = [...dex.limitations, ...members.limitations];
        return { ...base, supported: true, reason: null, descriptor, methods: listed(matched, limitations, 'methods'), limitations };
      } },
    { name: 'artifact.dexSearch', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'matches', 'totalMatches', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, query: { type: 'string', minLength: 1, maxLength: 512 }, limit: { type: 'integer', minimum: 1, maximum: MAX_LISTED } }, ['path', 'query']),
      execute({ path: relative, query, limit = 100 }, context) {
        const bytes = readFor(context, relative);
        const dex = parseDex(bytes);
        const base = { path: relative, sha256: sha256(bytes), untrusted: true };
        if (!dex.supported) return { ...base, supported: false, reason: dex.reason, detail: dex.detail, matches: [], totalMatches: 0, limitations: dex.limitations };
        // Substring matching over descriptors. Deliberately not a regular expression: a caller
        // supplied pattern would make the cost of this read depend on the input.
        const needle = query.toLowerCase();
        const hits = dex.classes.filter((entry) => typeof entry.descriptor === 'string' && entry.descriptor.toLowerCase().includes(needle));
        return { ...base, supported: true, reason: null, query, totalMatches: hits.length,
          matches: hits.slice(0, limit).map((entry) => ({ index: entry.index, descriptor: entry.descriptor, readable: entry.readable, access: entry.access, superclass: entry.superclass })),
          limitations: dex.limitations };
      } },
    { name: 'artifact.dexReferences', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'methods', 'fields', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, type: string, limit: { type: 'integer', minimum: 1, maximum: MAX_LISTED } }, ['path', 'type']),
      execute({ path: relative, type, limit = 200 }, context) {
        const bytes = readFor(context, relative);
        const dex = parseDex(bytes);
        const base = { path: relative, sha256: sha256(bytes), untrusted: true };
        if (!dex.supported) return { ...base, supported: false, reason: dex.reason, detail: dex.detail, methods: [], fields: [], limitations: dex.limitations };
        // Reference here means a declared relationship in the index tables, not a call site:
        // call sites live in bytecode, which this reader does not decode.
        const methodHits = dex.methods.filter((m) => m.class === type || (m.proto && (m.proto.returnType === type || m.proto.parameters.includes(type))));
        const fieldHits = dex.fields.filter((f) => f.class === type || f.type === type);
        const limitations = [...dex.limitations,
          'References come from the declared index tables; call sites inside bytecode are not decoded'];
        return { ...base, supported: true, reason: null, type,
          methods: methodHits.slice(0, limit).map((m) => ({ class: m.class, name: m.name, returnType: m.proto ? m.proto.returnType : null, parameters: m.proto ? m.proto.parameters : [] })),
          fields: fieldHits.slice(0, limit).map((f) => ({ class: f.class, name: f.name, type: f.type })),
          totalMethods: methodHits.length, totalFields: fieldHits.length, limitations };
      } },
    { name: 'artifact.dexGraph', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'edges', 'roots', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, prefix: string }, ['path']),
      execute({ path: relative, prefix }, context) {
        const bytes = readFor(context, relative);
        const dex = parseDex(bytes);
        const base = { path: relative, sha256: sha256(bytes), untrusted: true };
        if (!dex.supported) return { ...base, supported: false, reason: dex.reason, detail: dex.detail, edges: [], roots: [], limitations: dex.limitations };
        const selected = dex.classes.filter((entry) => !prefix || (typeof entry.descriptor === 'string' && entry.descriptor.startsWith(prefix)));
        const declared = new Set(dex.classes.map((entry) => entry.descriptor));
        const edges = [];
        for (const entry of selected) {
          if (entry.superclass) edges.push({ from: entry.descriptor, to: entry.superclass, kind: 'extends', resolved: declared.has(entry.superclass) });
          for (const iface of entry.interfaces) edges.push({ from: entry.descriptor, to: iface, kind: 'implements', resolved: declared.has(iface) });
        }
        const limitations = [...dex.limitations];
        // A type the DEX names but does not define is outside this file, not missing from it.
        const unresolved = edges.filter((edge) => !edge.resolved).length;
        if (unresolved) limitations.push('Some edges name types this DEX does not define, which are framework or other-DEX types rather than gaps');
        return { ...base, supported: true, reason: null, prefix: prefix ?? null,
          roots: selected.filter((entry) => !entry.superclass || !declared.has(entry.superclass)).map((entry) => entry.descriptor).slice(0, MAX_LISTED),
          edges: listed(edges, limitations, 'edges'), edgeCount: edges.length, unresolvedEdges: unresolved, limitations };
      } },
    { name: 'artifact.androidManifest', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'elements', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readFor(context, relative);
        const parsed = parseAxml(bytes);
        const base = { path: relative, sha256: sha256(bytes), untrusted: true };
        if (!parsed.supported) return { ...base, supported: false, reason: parsed.reason, detail: parsed.detail, elements: [], limitations: parsed.limitations };
        // The common questions about a manifest, answered from the tree rather than re-walked by
        // every caller. Absent is reported as null, never as a default.
        const manifest = parsed.elements.find((element) => element.name === 'manifest') ?? null;
        const attribute = (element, name) => {
          const found = element ? element.attributes.find((a) => a.name === name) : null;
          return found ? found.value : null;
        };
        const application = manifest ? manifest.children.find((child) => child.name === 'application') ?? null : null;
        const collect = (element, name) => (element ? element.children.filter((child) => child.name === name) : []);
        return { ...base, supported: true, reason: null, elements: parsed.elements, stringCount: parsed.stringCount,
          summary: {
            package: attribute(manifest, 'package'),
            versionCode: attribute(manifest, 'versionCode'),
            versionName: attribute(manifest, 'versionName'),
            permissions: collect(manifest, 'uses-permission').map((element) => attribute(element, 'name')).filter((name) => name !== null),
            activities: collect(application, 'activity').map((element) => attribute(element, 'name')).filter((name) => name !== null),
            services: collect(application, 'service').map((element) => attribute(element, 'name')).filter((name) => name !== null),
            receivers: collect(application, 'receiver').map((element) => attribute(element, 'name')).filter((name) => name !== null),
            debuggable: attribute(application, 'debuggable'),
          },
          limitations: parsed.limitations };
      } },
    { name: 'artifact.apk', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'entries', 'summary', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readFor(context, relative);
        const base = { path: relative, sha256: sha256(bytes), untrusted: true };
        if (bytes.length < 4 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) {
          return { ...base, supported: false, reason: 'not_a_zip', detail: 'An APK is a ZIP container and this file is not one', entries: [], summary: null, limitations: [] };
        }
        // An APK is a ZIP; its structure is read through the existing archive reader so there is
        // one implementation of central-directory walking rather than two.
        const limitations = [];
        const archive = parseApkEntries(bytes, limitations);
        const names = archive.map((entry) => entry.name);
        const dexEntries = names.filter((name) => /^classes[0-9]*\.dex$/.test(name));
        const libs = names.filter((name) => name.startsWith('lib/'));
        const abis = [...new Set(libs.map((name) => name.split('/')[1]).filter(Boolean))].sort();
        return { ...base, supported: true, reason: null,
          entries: listed(archive, limitations, 'archive entries'),
          summary: {
            entryCount: archive.length, dexFiles: dexEntries.sort(),
            hasManifest: names.includes('AndroidManifest.xml'),
            hasResources: names.includes('resources.arsc'),
            signatureSchemes: ['META-INF/MANIFEST.MF', 'META-INF/CERT.RSA', 'META-INF/CERT.SF'].filter((name) => names.includes(name)),
            nativeAbis: abis, nativeLibraryCount: libs.length,
          },
          limitations };
      } },
  ];
}

/**
 * ZIP central-directory walk for APK structure.
 *
 * Deliberately separate from artifact.inspect's archive reader: this one reports only names,
 * sizes and methods, which is what APK structure needs, and it tolerates the APK signing block
 * that sits between the entries and the central directory.
 */
function parseApkEntries(buffer, limitations) {
  const entries = [];
  // Locate the end-of-central-directory record by scanning back from the end.
  let eocd = -1;
  const earliest = Math.max(0, buffer.length - (65535 + 22));
  for (let i = buffer.length - 22; i >= earliest; i--) {
    if (buffer[i] === 0x50 && buffer[i + 1] === 0x4b && buffer[i + 2] === 0x05 && buffer[i + 3] === 0x06) { eocd = i; break; }
  }
  if (eocd < 0) { limitations.push('No end-of-central-directory record was found'); return entries; }
  const count = u16(buffer, eocd + 10);
  let at = u32(buffer, eocd + 16);
  if (count === undefined || at === undefined) { limitations.push('The end-of-central-directory record is unreadable'); return entries; }
  if (count > MAX_ZIP_ENTRIES) limitations.push('The archive declares more entries than the read bound permits');
  for (let i = 0; i < Math.min(count, MAX_ZIP_ENTRIES); i++) {
    if (at + 46 > buffer.length || buffer[at] !== 0x50 || buffer[at + 1] !== 0x4b || buffer[at + 2] !== 0x01 || buffer[at + 3] !== 0x02) {
      limitations.push('A central directory header is missing or malformed, so the walk stopped');
      break;
    }
    const nameLength = u16(buffer, at + 28);
    const extraLength = u16(buffer, at + 30);
    const commentLength = u16(buffer, at + 32);
    if (nameLength === undefined || at + 46 + nameLength > buffer.length) { limitations.push('An entry name lies outside the file'); break; }
    let name;
    try { name = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(at + 46, at + 46 + nameLength)); }
    catch { name = null; limitations.push('An entry name is not valid UTF-8'); }
    entries.push({
      name, method: u16(buffer, at + 10),
      compressedSize: u32(buffer, at + 20), uncompressedSize: u32(buffer, at + 24),
      crc32: u32(buffer, at + 16),
    });
    at += 46 + nameLength + (extraLength ?? 0) + (commentLength ?? 0);
  }
  return entries;
}
