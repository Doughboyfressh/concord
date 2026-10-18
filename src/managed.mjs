import { createHash } from 'node:crypto';
import { readWorkspaceFile } from './workspace-fs.mjs';

/**
 * .NET managed metadata, read from the ECMA-335 layout.
 *
 * REA reaches this through its managed provider. The format is specified, so it is read here from
 * the bytes with no dependency and nothing loaded into a runtime.
 *
 * The part that cannot be skipped is row sizing. Metadata table rows are variable width: heap
 * index widths come from the `HeapSizes` byte, simple table indices widen past 65535 rows, and a
 * coded index widens based on the largest row count among the tables it can point at. So every
 * table's row size must be computed, including tables this reader does not decode, because the
 * only way to reach table N is to step over the N-1 before it. A schema that omitted a table
 * would silently misread every table after it rather than fail.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const MAX_ROWS = 500000;
const MAX_LISTED = 2000;
const MAX_NAME_CHARS = 1024;

const u8 = (b, o) => (o < 0 || o >= b.length ? undefined : b[o]);
const u16 = (b, o) => (o < 0 || o + 2 > b.length ? undefined : b.readUInt16LE(o));
const u32 = (b, o) => (o < 0 || o + 4 > b.length ? undefined : b.readUInt32LE(o));

// Coded index definitions: the tables an index may point at, in tag order. A null entry is a
// reserved tag that no table corresponds to.
const CODED = {
  TypeDefOrRef: [0x02, 0x01, 0x1b],
  HasConstant: [0x04, 0x08, 0x17],
  HasCustomAttribute: [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11,
    0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b],
  HasFieldMarshal: [0x04, 0x08],
  HasDeclSecurity: [0x02, 0x06, 0x20],
  MemberRefParent: [0x02, 0x01, 0x1a, 0x06, 0x1b],
  HasSemantics: [0x14, 0x17],
  MethodDefOrRef: [0x06, 0x0a],
  MemberForwarded: [0x04, 0x06],
  Implementation: [0x26, 0x23, 0x27],
  CustomAttributeType: [null, null, 0x06, 0x0a, null],
  ResolutionScope: [0x00, 0x1a, 0x23, 0x01],
  TypeOrMethodDef: [0x02, 0x06],
};
const tagBits = (name) => Math.ceil(Math.log2(CODED[name].length));

// Every metadata table, in order, with its columns. Required in full for row stepping.
const TABLES = {
  0x00: ['u2', 'string', 'guid', 'guid', 'guid'],
  0x01: ['coded:ResolutionScope', 'string', 'string'],
  0x02: ['u4', 'string', 'string', 'coded:TypeDefOrRef', 'table:0x04', 'table:0x06'],
  0x03: ['table:0x04'],
  0x04: ['u2', 'string', 'blob'],
  0x05: ['table:0x06'],
  0x06: ['u4', 'u2', 'u2', 'string', 'blob', 'table:0x08'],
  0x07: ['table:0x08'],
  0x08: ['u2', 'u2', 'string'],
  0x09: ['table:0x02', 'coded:TypeDefOrRef'],
  0x0a: ['coded:MemberRefParent', 'string', 'blob'],
  0x0b: ['u1', 'u1', 'coded:HasConstant', 'blob'],
  0x0c: ['coded:HasCustomAttribute', 'coded:CustomAttributeType', 'blob'],
  0x0d: ['coded:HasFieldMarshal', 'blob'],
  0x0e: ['u2', 'coded:HasDeclSecurity', 'blob'],
  0x0f: ['u2', 'u4', 'table:0x02'],
  0x10: ['u4', 'table:0x04'],
  0x11: ['blob'],
  0x12: ['table:0x02', 'table:0x14'],
  0x13: ['table:0x14'],
  0x14: ['u2', 'string', 'coded:TypeDefOrRef'],
  0x15: ['table:0x02', 'table:0x17'],
  0x16: ['table:0x17'],
  0x17: ['u2', 'string', 'blob'],
  0x18: ['u2', 'table:0x06', 'coded:HasSemantics'],
  0x19: ['table:0x02', 'coded:MethodDefOrRef', 'coded:MethodDefOrRef'],
  0x1a: ['string'],
  0x1b: ['blob'],
  0x1c: ['u2', 'coded:MemberForwarded', 'string', 'table:0x1a'],
  0x1d: ['u4', 'table:0x04'],
  0x1e: ['u4', 'u4'],
  0x1f: ['u4'],
  0x20: ['u4', 'u2', 'u2', 'u2', 'u2', 'u4', 'blob', 'string', 'string'],
  0x21: ['u4'],
  0x22: ['u4', 'u4', 'u4'],
  0x23: ['u2', 'u2', 'u2', 'u2', 'u4', 'blob', 'string', 'string', 'blob'],
  0x24: ['u4', 'table:0x23'],
  0x25: ['u4', 'u4', 'u4', 'table:0x23'],
  0x26: ['u4', 'string', 'blob'],
  0x27: ['u4', 'u4', 'string', 'string', 'coded:Implementation'],
  0x28: ['u4', 'u4', 'string', 'coded:Implementation'],
  0x29: ['table:0x02', 'table:0x02'],
  0x2a: ['u2', 'u2', 'coded:TypeOrMethodDef', 'string'],
  0x2b: ['coded:MethodDefOrRef', 'blob'],
  0x2c: ['table:0x2a', 'coded:TypeDefOrRef'],
};

const TYPE_VISIBILITY = ['not-public', 'public', 'nested-public', 'nested-private',
  'nested-family', 'nested-assembly', 'nested-family-and-assembly', 'nested-family-or-assembly'];
const MEMBER_ACCESS = ['compiler-controlled', 'private', 'family-and-assembly', 'assembly',
  'family', 'family-or-assembly', 'public', 'reserved'];

function typeAttributes(flags) {
  const out = [TYPE_VISIBILITY[flags & 0x07] ?? 'unknown'];
  if ((flags & 0x20) !== 0) out.push('interface');
  if ((flags & 0x80) !== 0) out.push('abstract');
  if ((flags & 0x100) !== 0) out.push('sealed');
  if ((flags & 0x400) !== 0) out.push('special-name');
  if ((flags & 0x1000) !== 0) out.push('import');
  if ((flags & 0x2000) !== 0) out.push('serializable');
  return out;
}
function methodAttributes(flags) {
  const out = [MEMBER_ACCESS[flags & 0x07] ?? 'unknown'];
  if ((flags & 0x10) !== 0) out.push('static');
  if ((flags & 0x20) !== 0) out.push('final');
  if ((flags & 0x40) !== 0) out.push('virtual');
  if ((flags & 0x400) !== 0) out.push('abstract');
  if ((flags & 0x2000) !== 0) out.push('pinvoke-impl');
  return out;
}
function fieldAttributes(flags) {
  const out = [MEMBER_ACCESS[flags & 0x07] ?? 'unknown'];
  if ((flags & 0x10) !== 0) out.push('static');
  if ((flags & 0x20) !== 0) out.push('init-only');
  if ((flags & 0x40) !== 0) out.push('literal');
  return out;
}

/** Section mapping, so a metadata RVA can be turned into a file offset. */
function peMap(buffer) {
  const signatureOffset = u32(buffer, 0x3c);
  if (signatureOffset === undefined || buffer.toString('latin1', signatureOffset, signatureOffset + 4) !== 'PE\0\0') return null;
  const sizeOfOptionalHeader = u16(buffer, signatureOffset + 20);
  const sectionCount = u16(buffer, signatureOffset + 6);
  if (!sizeOfOptionalHeader || sectionCount === undefined) return null;
  const optionalAt = signatureOffset + 24;
  const magic = u16(buffer, optionalAt);
  const directoriesAt = optionalAt + (magic === 0x20b ? 112 : 96);
  const sections = [];
  const tableStart = optionalAt + sizeOfOptionalHeader;
  for (let i = 0; i < Math.min(sectionCount, 96); i++) {
    const at = tableStart + i * 40;
    const virtualSize = u32(buffer, at + 8);
    const virtualAddress = u32(buffer, at + 12);
    const sizeOfRawData = u32(buffer, at + 16);
    const pointerToRawData = u32(buffer, at + 20);
    if ([virtualSize, virtualAddress, sizeOfRawData, pointerToRawData].some((v) => v === undefined)) break;
    sections.push({ virtualSize, virtualAddress, sizeOfRawData, pointerToRawData });
  }
  const toOffset = (rva) => {
    if (typeof rva !== 'number') return undefined;
    for (const section of sections) {
      const size = Math.max(section.virtualSize, section.sizeOfRawData);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + size) return section.pointerToRawData + (rva - section.virtualAddress);
    }
    return undefined;
  };
  return { signatureOffset, pe32Plus: magic === 0x20b, directoriesAt, sections, toOffset };
}

/** Read the metadata root, its streams, and the `#~` table header. */
export function parseManaged(buffer) {
  const limitations = [];
  const map = peMap(buffer);
  if (!map) return { supported: false, reason: 'not_pe', detail: 'The file carries no PE signature', limitations };
  // Data directory 14 is the CLI header; a native PE leaves it empty.
  const cliRva = u32(buffer, map.directoriesAt + 14 * 8);
  const cliSize = u32(buffer, map.directoriesAt + 14 * 8 + 4);
  if (!cliRva || !cliSize) {
    return { supported: false, reason: 'not_managed', detail: 'The PE declares no CLI header, so it is a native binary', limitations };
  }
  const cliAt = map.toOffset(cliRva);
  if (cliAt === undefined || cliAt + 72 > buffer.length) {
    return { supported: false, reason: 'cli_header_unmapped', detail: 'The CLI header address falls outside every section', limitations };
  }
  const flags = u32(buffer, cliAt + 16);
  const cli = {
    runtimeVersion: u16(buffer, cliAt + 4) + '.' + u16(buffer, cliAt + 6),
    flags,
    ilOnly: (flags & 0x01) !== 0,
    requires32Bit: (flags & 0x02) !== 0,
    strongNameSigned: (flags & 0x08) !== 0,
    nativeEntryPoint: (flags & 0x10) !== 0,
    entryPointToken: u32(buffer, cliAt + 20),
  };
  const metadataAt = map.toOffset(u32(buffer, cliAt + 8));
  if (metadataAt === undefined || metadataAt + 20 > buffer.length || u32(buffer, metadataAt) !== 0x424a5342) {
    return { supported: false, reason: 'metadata_absent', detail: 'The CLI header does not address a BSJB metadata root', cli, limitations };
  }
  const versionLength = u32(buffer, metadataAt + 12);
  if (versionLength === undefined || versionLength > 256) {
    return { supported: false, reason: 'metadata_malformed', detail: 'The metadata version length is unreasonable', cli, limitations };
  }
  const versionEnd = metadataAt + 16 + versionLength;
  const versionText = buffer.toString('latin1', metadataAt + 16, versionEnd).replace(/\0.*$/, '');
  const streamCount = u16(buffer, versionEnd + 2);
  const streams = new Map();
  let cursor = versionEnd + 4;
  for (let i = 0; i < Math.min(streamCount ?? 0, 16); i++) {
    const offset = u32(buffer, cursor);
    const size = u32(buffer, cursor + 4);
    if (offset === undefined || size === undefined) { limitations.push('A stream header is unreadable'); break; }
    let end = cursor + 8;
    while (end < buffer.length && buffer[end] !== 0) end += 1;
    const name = buffer.toString('latin1', cursor + 8, end);
    streams.set(name, { offset, size, fileOffset: metadataAt + offset });
    cursor = cursor + 8 + Math.ceil((end - (cursor + 8) + 1) / 4) * 4;
  }
  const tableStream = streams.get('#~') ?? streams.get('#-');
  if (!tableStream) {
    return { supported: false, reason: 'tables_absent', detail: 'The metadata root declares no table stream', cli, versionText, streams: [...streams.keys()], limitations };
  }
  if (streams.has('#-')) limitations.push('This assembly uses an uncompressed table stream, whose pointer tables are read but not followed');

  const base = tableStream.fileOffset;
  const heapSizes = u8(buffer, base + 6);
  if (heapSizes === undefined || base + 24 > buffer.length) {
    return { supported: false, reason: 'tables_malformed', detail: 'The table stream header is truncated', cli, versionText, limitations };
  }
  const valid = buffer.readBigUInt64LE(base + 8);
  const sorted = buffer.readBigUInt64LE(base + 16);
  const rowCounts = new Map();
  let at = base + 24;
  for (let table = 0; table < 64; table++) {
    if ((valid & (1n << BigInt(table))) === 0n) continue;
    const count = u32(buffer, at);
    if (count === undefined) { limitations.push('A table row count is unreadable'); break; }
    if (count > MAX_ROWS) limitations.push(`Table 0x${table.toString(16)} declares more rows than the read bound permits`);
    rowCounts.set(table, Math.min(count, MAX_ROWS));
    at += 4;
  }

  const stringWide = (heapSizes & 0x01) !== 0;
  const guidWide = (heapSizes & 0x02) !== 0;
  const blobWide = (heapSizes & 0x04) !== 0;
  const rows = (table) => rowCounts.get(table) ?? 0;
  const columnWidth = (column) => {
    if (column === 'u1') return 1;
    if (column === 'u2') return 2;
    if (column === 'u4') return 4;
    if (column === 'u8') return 8;
    if (column === 'string') return stringWide ? 4 : 2;
    if (column === 'guid') return guidWide ? 4 : 2;
    if (column === 'blob') return blobWide ? 4 : 2;
    if (column.startsWith('table:')) return rows(Number(column.slice(6))) > 0xffff ? 4 : 2;
    const name = column.slice(6);
    const bits = tagBits(name);
    const widest = Math.max(0, ...CODED[name].filter((t) => t !== null).map((t) => rows(t)));
    return widest > (0xffff >> bits) ? 4 : 2;
  };
  const rowSize = (table) => (TABLES[table] ?? []).reduce((total, column) => total + columnWidth(column), 0);

  // Row start offsets: reaching table N means stepping over every present table before it.
  const tableAt = new Map();
  let rowCursor = at;
  for (let table = 0; table < 64; table++) {
    if (!rowCounts.has(table)) continue;
    if (!TABLES[table]) { limitations.push(`Table 0x${table.toString(16)} is not in this reader's schema, so later tables were not located`); break; }
    tableAt.set(table, rowCursor);
    rowCursor += rowSize(table) * rows(table);
  }
  if (rowCursor > buffer.length) limitations.push('The computed table extent runs past the end of the file');

  const stringsStream = streams.get('#Strings');
  const readString = (index) => {
    if (!stringsStream || typeof index !== 'number') return null;
    const start = stringsStream.fileOffset + index;
    if (start >= buffer.length) return null;
    let end = start;
    while (end < buffer.length && buffer[end] !== 0 && end - start < MAX_NAME_CHARS * 4) end += 1;
    try { return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(start, end)); }
    catch { return null; }
  };

  /** One row as an array of raw column values, with heap indices left unresolved. */
  const readRow = (table, index) => {
    const columns = TABLES[table];
    const start = tableAt.get(table);
    if (!columns || start === undefined || index < 0 || index >= rows(table)) return null;
    let offset = start + rowSize(table) * index;
    const values = [];
    for (const column of columns) {
      const width = columnWidth(column);
      const raw = width === 1 ? u8(buffer, offset) : width === 2 ? u16(buffer, offset) : u32(buffer, offset);
      if (raw === undefined) return null;
      if (column.startsWith('coded:')) {
        const name = column.slice(6);
        const bits = tagBits(name);
        const tag = raw & ((1 << bits) - 1);
        values.push({ table: CODED[name][tag] ?? null, index: raw >>> bits });
      } else values.push(raw);
      offset += width;
    }
    return values;
  };

  return { supported: true, reason: null, cli, versionText, streams: [...streams.keys()],
    tableVersion: u8(buffer, base + 4) + '.' + u8(buffer, base + 5),
    heapSizes: { stringWide, guidWide, blobWide },
    rowCounts, sortedMask: sorted.toString(), readRow, readString, rows, limitations };
}

const TABLE_NAMES = { 0x00: 'Module', 0x01: 'TypeRef', 0x02: 'TypeDef', 0x04: 'Field', 0x06: 'MethodDef',
  0x08: 'Param', 0x09: 'InterfaceImpl', 0x0a: 'MemberRef', 0x1a: 'ModuleRef', 0x1b: 'TypeSpec',
  0x1c: 'ImplMap', 0x20: 'Assembly', 0x23: 'AssemblyRef', 0x29: 'NestedClass' };

const fullName = (namespace, name) => (namespace ? namespace + '.' + name : name);

/** Types, with the member ranges each TypeDef row declares. */
function managedTypes(meta) {
  const types = [];
  const typeCount = meta.rows(0x02);
  for (let i = 0; i < typeCount; i++) {
    const row = meta.readRow(0x02, i);
    if (!row) break;
    const [flags, nameIndex, namespaceIndex, extendsRef, fieldStart, methodStart] = row;
    types.push({ index: i, name: meta.readString(nameIndex), namespace: meta.readString(namespaceIndex) || null,
      flags, attributes: typeAttributes(flags), extends: extendsRef, fieldStart, methodStart });
  }
  // A member list runs to the next type's start, so the last type runs to the end of the table.
  for (let i = 0; i < types.length; i++) {
    types[i].fieldEnd = i + 1 < types.length ? types[i + 1].fieldStart : meta.rows(0x04) + 1;
    types[i].methodEnd = i + 1 < types.length ? types[i + 1].methodStart : meta.rows(0x06) + 1;
  }
  // A nested type carries an empty namespace and names its parent only through the NestedClass
  // table, so without this pass it would be reported by its bare name as though it were top level.
  const enclosing = new Map();
  for (let i = 0; i < meta.rows(0x29); i++) {
    const row = meta.readRow(0x29, i);
    if (!row) break;
    enclosing.set(row[0] - 1, row[1] - 1);
  }
  const nameOf = (index, seen) => {
    const entry = types[index];
    if (!entry) return null;
    const parentIndex = enclosing.get(index);
    // A cycle cannot occur in valid metadata; guard anyway rather than recurse without bound.
    if (parentIndex === undefined || seen.has(index)) return fullName(entry.namespace, entry.name);
    const parent = nameOf(parentIndex, new Set([...seen, index]));
    return parent === null ? fullName(entry.namespace, entry.name) : parent + '.' + entry.name;
  };
  for (let i = 0; i < types.length; i++) {
    types[i].fullName = nameOf(i, new Set());
    types[i].nested = enclosing.has(i);
    types[i].enclosing = enclosing.has(i) ? nameOf(enclosing.get(i), new Set()) : null;
  }
  return types;
}

/** Resolve a TypeDefOrRef coded index to a readable name. */
function resolveTypeRef(meta, ref, types) {
  if (!ref || ref.index === 0 || ref.table === null) return null;
  if (ref.table === 0x02) {
    const found = types[ref.index - 1];
    return found ? found.fullName : null;
  }
  if (ref.table === 0x01) {
    const row = meta.readRow(0x01, ref.index - 1);
    return row ? fullName(meta.readString(row[2]) || null, meta.readString(row[1])) : null;
  }
  return null; // TypeSpec carries a blob signature, which this reader does not decode.
}

const listed = (items, limitations, label) => {
  if (items.length <= MAX_LISTED) return items;
  limitations.push(`Only the first ${MAX_LISTED} ${label} are listed`);
  return items.slice(0, MAX_LISTED);
};
const readFor = (context, relative) => readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / 4));
const memberKey = (member) => member.declaringType + '::' + member.name + '(' + member.kind + ')';

/** .NET managed metadata readers, plus the pure comparisons that consume their output. */
export function makeManagedTools() {
  const pathOnly = object({ path: string });
  const memberList = {
    type: 'object', additionalProperties: true, required: ['members'],
    properties: { members: { type: 'array', maxItems: MAX_LISTED * 2, items: {
      type: 'object', additionalProperties: true, required: ['declaringType', 'name', 'kind'],
      properties: { declaringType: { type: 'string', maxLength: 1024 }, name: { type: 'string', maxLength: 1024 },
        kind: { enum: ['field', 'method'] }, attributes: { type: 'array', items: { type: 'string', maxLength: 64 } } } } } },
  };

  const base = (relative, bytes) => ({ path: relative, sha256: sha256(bytes), untrusted: true });

  return [
    { name: 'artifact.managed', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'tables', 'assembly', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readFor(context, relative);
        const meta = parseManaged(bytes);
        if (!meta.supported) return { ...base(relative, bytes), supported: false, reason: meta.reason, detail: meta.detail, tables: [], assembly: null, limitations: meta.limitations };
        const limitations = [...meta.limitations];
        const assemblyRow = meta.rows(0x20) ? meta.readRow(0x20, 0) : null;
        const moduleRow = meta.rows(0x00) ? meta.readRow(0x00, 0) : null;
        const references = [];
        for (let i = 0; i < meta.rows(0x23); i++) {
          const row = meta.readRow(0x23, i);
          if (!row) break;
          references.push({ name: meta.readString(row[6]), version: [row[0], row[1], row[2], row[3]].join('.'), culture: meta.readString(row[7]) || null });
        }
        return { ...base(relative, bytes), supported: true, reason: null,
          cli: meta.cli, metadataVersion: meta.versionText, tableVersion: meta.tableVersion,
          streams: meta.streams, heapSizes: meta.heapSizes,
          module: moduleRow ? meta.readString(moduleRow[1]) : null,
          assembly: assemblyRow ? { name: meta.readString(assemblyRow[7]),
            version: [assemblyRow[1], assemblyRow[2], assemblyRow[3], assemblyRow[4]].join('.'),
            culture: meta.readString(assemblyRow[8]) || null, hashAlgorithm: assemblyRow[0] } : null,
          assemblyReferences: listed(references, limitations, 'assembly references'),
          tables: [...meta.rowCounts].filter(([, count]) => count > 0)
            .map(([table, count]) => ({ table, name: TABLE_NAMES[table] ?? null, rows: count })),
          limitations };
      } },
    { name: 'artifact.managedMembers', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'types', 'members', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, type: string }, ['path']),
      execute({ path: relative, type }, context) {
        const bytes = readFor(context, relative);
        const meta = parseManaged(bytes);
        if (!meta.supported) return { ...base(relative, bytes), supported: false, reason: meta.reason, detail: meta.detail, types: [], members: [], limitations: meta.limitations };
        const limitations = [...meta.limitations];
        const types = managedTypes(meta);
        const selected = type === undefined ? types : types.filter((entry) => entry.fullName === type);
        if (type !== undefined && !selected.length) {
          return { ...base(relative, bytes), supported: true, reason: 'type_absent',
            detail: 'The assembly declares no type with that name', types: [], members: [], limitations };
        }
        const members = [];
        for (const entry of selected) {
          for (let f = entry.fieldStart; f < entry.fieldEnd; f++) {
            const row = meta.readRow(0x04, f - 1);
            if (!row) break;
            members.push({ declaringType: entry.fullName, name: meta.readString(row[1]), kind: 'field', attributes: fieldAttributes(row[0]) });
          }
          for (let m = entry.methodStart; m < entry.methodEnd; m++) {
            const row = meta.readRow(0x06, m - 1);
            if (!row) break;
            members.push({ declaringType: entry.fullName, name: meta.readString(row[3]), kind: 'method',
              attributes: methodAttributes(row[2]), hasBody: row[0] !== 0 });
          }
        }
        // Signatures live in the blob heap and are not decoded, so an overload set collapses to
        // one name: said plainly rather than letting a caller read the count as a member count.
        limitations.push('Member signatures live in the blob heap and are not decoded, so overloads share a name');
        return { ...base(relative, bytes), supported: true, reason: null,
          types: listed(selected.map((entry) => ({ fullName: entry.fullName, attributes: entry.attributes,
            nested: entry.nested, enclosing: entry.enclosing,
            extends: resolveTypeRef(meta, entry.extends, types) })), limitations, 'types'),
          members: listed(members, limitations, 'members'), memberCount: members.length, limitations };
      } },
    { name: 'artifact.compareManagedMembers', version: '1.0.0', outputKeys: ['changes', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({ left: memberList, right: memberList }, ['left', 'right']),
      execute({ left, right }) {
        const index = (side) => {
          const map = new Map();
          for (const member of side.members) {
            const key = memberKey(member);
            if (!map.has(key)) map.set(key, []);
            map.get(key).push(member);
          }
          return map;
        };
        const a = index(left);
        const b = index(right);
        const changes = [];
        for (const key of [...new Set([...a.keys(), ...b.keys()])].sort()) {
          const mine = a.get(key) ?? [];
          const theirs = b.get(key) ?? [];
          const shape = { member: key };
          // Overloads collapse to one key because signatures are not decoded, so a duplicated key
          // has no established correspondence: unknown rather than an invented pairing.
          if (mine.length > 1 || theirs.length > 1) {
            changes.push({ ...shape, state: 'unknown', reason: 'The member name occurs more than once, so no correspondence between occurrences is established' });
            continue;
          }
          if (!theirs.length) { changes.push({ ...shape, state: 'removed', reason: null }); continue; }
          if (!mine.length) { changes.push({ ...shape, state: 'added', reason: null }); continue; }
          const sameAttributes = JSON.stringify((mine[0].attributes ?? []).slice().sort()) === JSON.stringify((theirs[0].attributes ?? []).slice().sort());
          changes.push({ ...shape, state: sameAttributes ? 'unchanged' : 'changed',
            left: mine[0].attributes ?? [], right: theirs[0].attributes ?? [], reason: null });
        }
        const tally = (state) => changes.filter((change) => change.state === state).length;
        return { changes, summary: { added: tally('added'), removed: tally('removed'), changed: tally('changed'), unchanged: tally('unchanged'), unknown: tally('unknown') },
          limitations: ['Comparison is by declaring type, name and kind; signatures are not part of the key'] };
      } },
    { name: 'artifact.managedNativeBoundaries', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'boundaries', 'modules', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readFor(context, relative);
        const meta = parseManaged(bytes);
        if (!meta.supported) return { ...base(relative, bytes), supported: false, reason: meta.reason, detail: meta.detail, boundaries: [], modules: [], limitations: meta.limitations };
        const limitations = [...meta.limitations];
        const types = managedTypes(meta);
        // ImplMap is the P/Invoke table: each row forwards a managed member to a native export.
        const modules = [];
        for (let i = 0; i < meta.rows(0x1a); i++) {
          const row = meta.readRow(0x1a, i);
          if (!row) break;
          modules.push(meta.readString(row[0]));
        }
        const declaringTypeOf = (methodIndex) => {
          const found = types.find((entry) => methodIndex >= entry.methodStart && methodIndex < entry.methodEnd);
          return found ? found.fullName : null;
        };
        const boundaries = [];
        for (let i = 0; i < meta.rows(0x1c); i++) {
          const row = meta.readRow(0x1c, i);
          if (!row) break;
          const [mappingFlags, forwarded, importName, importScope] = row;
          const member = forwarded.table === 0x06 ? meta.readRow(0x06, forwarded.index - 1) : null;
          boundaries.push({
            importName: meta.readString(importName),
            module: modules[importScope - 1] ?? null,
            moduleResolved: importScope >= 1 && importScope <= modules.length,
            managedMember: member ? meta.readString(member[3]) : null,
            declaringType: forwarded.table === 0x06 ? declaringTypeOf(forwarded.index) : null,
            forwardedKind: forwarded.table === 0x06 ? 'method' : forwarded.table === 0x04 ? 'field' : null,
            charSet: (mappingFlags & 0x06) === 0x02 ? 'ansi' : (mappingFlags & 0x06) === 0x04 ? 'unicode' : 'not-specified',
            exactSpelling: (mappingFlags & 0x01) !== 0,
          });
        }
        if (!boundaries.length) limitations.push('The assembly declares no P/Invoke entries, so it crosses no native boundary this way');
        limitations.push('Only declared P/Invoke entries are reported; a call made through a function pointer or a runtime import is not visible here');
        return { ...base(relative, bytes), supported: true, reason: null,
          boundaries: listed(boundaries, limitations, 'boundaries'), modules, limitations };
      } },
    { name: 'artifact.verifyManagedNativeBoundaries', version: '1.0.0', outputKeys: ['findings', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({
        boundaries: { type: 'array', maxItems: MAX_LISTED, items: { type: 'object', additionalProperties: true, required: ['importName'],
          properties: { importName: { anyOf: [{ type: 'string', maxLength: 1024 }, { type: 'null' }] },
            module: { anyOf: [{ type: 'string', maxLength: 1024 }, { type: 'null' }] },
            moduleResolved: { type: 'boolean' } } } },
        available: { type: 'array', maxItems: MAX_LISTED, items: { type: 'string', maxLength: 1024 } },
      }, ['boundaries']),
      execute({ boundaries, available = [] }) {
        // A module name is matched case-insensitively and without extension, because a declared
        // `user32` and a shipped `user32.dll` are the same dependency.
        const normalise = (name) => (typeof name === 'string' ? name.toLowerCase().replace(/\.(dll|so|dylib)$/, '') : null);
        const present = new Set(available.map(normalise).filter((name) => name !== null));
        const findings = boundaries.map((boundary) => {
          const module = normalise(boundary.module);
          if (boundary.module === null || module === null) return { ...boundary, state: 'unknown', reason: 'The boundary names no module, so nothing can be checked against it' };
          if (boundary.moduleResolved === false) return { ...boundary, state: 'unresolved-scope', reason: 'The import scope does not address a declared module reference' };
          if (!available.length) return { ...boundary, state: 'unknown', reason: 'No available module list was supplied, so presence cannot be decided' };
          return { ...boundary, state: present.has(module) ? 'satisfied' : 'missing', reason: null };
        });
        const tally = (state) => findings.filter((finding) => finding.state === state).length;
        return { findings,
          summary: { satisfied: tally('satisfied'), missing: tally('missing'), unresolvedScope: tally('unresolved-scope'), unknown: tally('unknown') },
          limitations: ['A satisfied boundary means the module name was listed as available, not that the named export exists in it'] };
      } },
    { name: 'artifact.managedGraph', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'edges', 'roots', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, namespace: string }, ['path']),
      execute({ path: relative, namespace }, context) {
        const bytes = readFor(context, relative);
        const meta = parseManaged(bytes);
        if (!meta.supported) return { ...base(relative, bytes), supported: false, reason: meta.reason, detail: meta.detail, edges: [], roots: [], limitations: meta.limitations };
        const limitations = [...meta.limitations];
        const types = managedTypes(meta);
        const declared = new Set(types.map((entry) => entry.fullName));
        const selected = types.filter((entry) => !namespace || (entry.namespace ?? '') === namespace);
        const edges = [];
        for (const entry of selected) {
          const parent = resolveTypeRef(meta, entry.extends, types);
          if (parent) edges.push({ from: entry.fullName, to: parent, kind: 'extends', resolved: declared.has(parent) });
        }
        for (let i = 0; i < meta.rows(0x09); i++) {
          const row = meta.readRow(0x09, i);
          if (!row) break;
          const owner = types[row[0] - 1];
          if (!owner || (namespace && (owner.namespace ?? '') !== namespace)) continue;
          const iface = resolveTypeRef(meta, row[1], types);
          if (iface) edges.push({ from: owner.fullName, to: iface, kind: 'implements', resolved: declared.has(iface) });
        }
        const unresolved = edges.filter((edge) => !edge.resolved).length;
        if (unresolved) limitations.push('Some edges name types from referenced assemblies, which are external rather than gaps');
        return { ...base(relative, bytes), supported: true, reason: null, namespace: namespace ?? null,
          roots: selected.filter((entry) => !resolveTypeRef(meta, entry.extends, types)).map((entry) => entry.fullName).slice(0, MAX_LISTED),
          edges: listed(edges, limitations, 'edges'), edgeCount: edges.length, unresolvedEdges: unresolved, limitations };
      } },
    { name: 'artifact.importManagedReconstruction', version: '1.0.0', outputKeys: ['accepted', 'rejected', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({
        observed: memberList,
        reconstruction: { type: 'array', maxItems: MAX_LISTED * 2, items: { type: 'object', additionalProperties: true, required: ['declaringType', 'name', 'kind'],
          properties: { declaringType: { type: 'string', maxLength: 1024 }, name: { type: 'string', maxLength: 1024 },
            kind: { enum: ['field', 'method'] }, source: { type: 'string', maxLength: 4096 } } } },
      }, ['observed', 'reconstruction']),
      execute({ observed, reconstruction }) {
        // A reconstruction is accepted only for members the artifact actually declares. Anything
        // else is rejected by name rather than imported, so a reconstruction cannot introduce a
        // member the evidence does not support.
        const declared = new Set(observed.members.map(memberKey));
        const accepted = [];
        const rejected = [];
        const seen = new Set();
        for (const entry of reconstruction) {
          const key = memberKey(entry);
          if (seen.has(key)) { rejected.push({ member: key, reason: 'The reconstruction names this member more than once' }); continue; }
          seen.add(key);
          if (declared.has(key)) accepted.push({ member: key, hasSource: typeof entry.source === 'string' && entry.source.length > 0 });
          else rejected.push({ member: key, reason: 'The observed artifact declares no such member' });
        }
        const covered = accepted.length;
        return { accepted, rejected,
          summary: { observed: declared.size, accepted: covered, rejected: rejected.length,
            uncovered: declared.size - covered,
            coverage: declared.size === 0 ? null : Math.round((covered / declared.size) * 1000) / 1000 },
          limitations: ['Coverage counts members by name and kind; it says nothing about whether a reconstruction is behaviourally correct'] };
      } },
  ];
}
