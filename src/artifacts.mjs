import { createHash } from 'node:crypto';
import { readWorkspaceFile } from './workspace-fs.mjs';

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function magicMatch(buffer, offset, bytes) {
  if (buffer.length < offset + bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) if (buffer[offset + i] !== bytes[i]) return false;
  return true;
}

// Checked in order; the first matching entry wins. Identification only — no format
// here is executed or trusted as anything but data; bounded structural parsing follows.
const MAGIC_TABLE = [
  { format: 'elf', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { format: 'mz-dos', bytes: [0x4d, 0x5a] },
  { format: 'mach-o-32-be', bytes: [0xfe, 0xed, 0xfa, 0xce] },
  { format: 'mach-o-32-le', bytes: [0xce, 0xfa, 0xed, 0xfe] },
  { format: 'mach-o-64-be', bytes: [0xfe, 0xed, 0xfa, 0xcf] },
  { format: 'mach-o-64-le', bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { format: 'zip', bytes: [0x50, 0x4b, 0x03, 0x04] },
  { format: 'zip-empty', bytes: [0x50, 0x4b, 0x05, 0x06] },
  { format: 'zip-spanned', bytes: [0x50, 0x4b, 0x07, 0x08] },
  { format: 'png', bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { format: 'gzip', bytes: [0x1f, 0x8b] },
  { format: 'pdf', bytes: [0x25, 0x50, 0x44, 0x46] },
  { format: 'wasm', bytes: [0x00, 0x61, 0x73, 0x6d] },
];

function identifyFormat(buffer) {
  for (const entry of MAGIC_TABLE) if (magicMatch(buffer, 0, entry.bytes)) return entry.format;
  return 'unknown';
}

// Every read is bounds-checked against the real remaining buffer length before use;
// returns undefined (never throws) when a header is truncated, so a crafted or cut
// file degrades to a partial result instead of an uncaught RangeError.
function readUint(buffer, offset, size, littleEndian) {
  if (offset < 0 || offset + size > buffer.length) return undefined;
  if (size === 2) return littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
  if (size === 4) return littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
  const big = littleEndian ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
  return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big.toString();
}

// Bounds on header-table iteration counts and string lengths: a crafted or truncated file
// must degrade to an empty list, never an unbounded loop or a read past the buffer.
const MAX_PROGRAM_HEADERS = 64;
const MAX_DYNAMIC_ENTRIES = 500;
const MAX_NEEDED_LIBRARIES = 200;
const MAX_SECTIONS = 96;
const MAX_IMPORT_DESCRIPTORS = 200;
const MAX_NAME_CHARS = 260;
const MAX_MACHO_LOAD_COMMANDS = 512;
const MAX_MACHO_DYLIBS = 200;
const MAX_MACHO_SEGMENTS = 64;
const MAX_ZIP_ENTRIES = 10000;
const MAX_ZIP_NAME_CHARS = 1024;
const MAX_EOCD_SEARCH_BYTES = 65535 + 22; // uint16 comment length, plus the fixed record
const MAX_WASM_SECTIONS = 128;

// Bounds-checked like readUint: returns undefined (never throws) on a missing terminator,
// an out-of-range offset, or an empty string, rather than reading past the buffer.
function readCString(buffer, offset, maxLength) {
  if (typeof offset !== 'number' || offset < 0 || offset >= buffer.length) return undefined;
  let end = offset;
  while (end < buffer.length && end - offset < maxLength && buffer[end] !== 0) end++;
  // The loop exits for three reasons: an empty string, the maxLength bound, or running off the
  // real end of the buffer without ever finding a NUL — only a genuine terminator (buffer[end]
  // === 0, i.e. end < buffer.length) makes this a real, complete string; the third case must
  // not be accepted as if it were, or a truncated file could pass off a fabricated partial name.
  if (end === offset || end - offset >= maxLength || end >= buffer.length) return undefined;
  return buffer.toString('latin1', offset, end);
}

// Unlike readCString, ZIP names are length-prefixed, not NUL-terminated — a literal NUL byte
// inside the declared length is valid and must not end the read early. Bounds-checked the same
// way: undefined (never a thrown RangeError) on any offset/length that would run past the buffer.
function readFixedString(buffer, offset, length, maxLength) {
  if (typeof offset !== 'number' || typeof length !== 'number' || offset < 0 || length < 0) return undefined;
  if (offset + length > buffer.length) return undefined;
  return buffer.toString('utf-8', offset, offset + Math.min(length, maxLength));
}

// Static only: this reads the already-located ELF Program Header Table and Dynamic section to
// list DT_NEEDED entries (linked shared library names) — the same bytes the dynamic linker
// itself would read, never executed or loaded. Spec verified independently against a real
// ELF64 shared library before this was written.
function elfNeededLibraries(buffer, is64, littleEndian) {
  const phOff = is64 ? readUint(buffer, 32, 8, littleEndian) : readUint(buffer, 28, 4, littleEndian);
  const phEntSize = is64 ? readUint(buffer, 54, 2, littleEndian) : readUint(buffer, 42, 2, littleEndian);
  const phNum = is64 ? readUint(buffer, 56, 2, littleEndian) : readUint(buffer, 44, 2, littleEndian);
  if (typeof phOff !== 'number' || typeof phEntSize !== 'number' || typeof phNum !== 'number') return [];

  let dynamicOffset;
  const loadSegments = [];
  for (let i = 0; i < Math.min(phNum, MAX_PROGRAM_HEADERS); i++) {
    const off = phOff + i * phEntSize;
    const type = readUint(buffer, off, 4, littleEndian);
    if (typeof type !== 'number') break;
    const segOffset = is64 ? readUint(buffer, off + 8, 8, littleEndian) : readUint(buffer, off + 4, 4, littleEndian);
    const vaddr = is64 ? readUint(buffer, off + 16, 8, littleEndian) : readUint(buffer, off + 8, 4, littleEndian);
    const filesz = is64 ? readUint(buffer, off + 32, 8, littleEndian) : readUint(buffer, off + 16, 4, littleEndian);
    if (typeof segOffset !== 'number' || typeof vaddr !== 'number' || typeof filesz !== 'number') continue;
    if (type === 2) dynamicOffset = segOffset; // PT_DYNAMIC
    if (type === 1) loadSegments.push({ offset: segOffset, vaddr, filesz }); // PT_LOAD
  }
  if (typeof dynamicOffset !== 'number') return [];

  function vaddrToOffset(vaddr) {
    if (typeof vaddr !== 'number') return undefined;
    for (const seg of loadSegments) if (vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.filesz) return seg.offset + (vaddr - seg.vaddr);
    return undefined;
  }

  const entrySize = is64 ? 16 : 8;
  const neededOffsets = [];
  let strtabVaddr;
  for (let i = 0; i < MAX_DYNAMIC_ENTRIES; i++) {
    const off = dynamicOffset + i * entrySize;
    const tag = is64 ? readUint(buffer, off, 8, littleEndian) : readUint(buffer, off, 4, littleEndian);
    const val = is64 ? readUint(buffer, off + 8, 8, littleEndian) : readUint(buffer, off + 4, 4, littleEndian);
    if (typeof tag !== 'number' || typeof val !== 'number') break;
    if (tag === 0) break; // DT_NULL
    if (tag === 1) neededOffsets.push(val); // DT_NEEDED
    if (tag === 5) strtabVaddr = val; // DT_STRTAB
  }
  const strtabOffset = vaddrToOffset(strtabVaddr);
  if (typeof strtabOffset !== 'number') return [];

  const libraries = [];
  for (const rel of neededOffsets.slice(0, MAX_NEEDED_LIBRARIES)) {
    const name = readCString(buffer, strtabOffset + rel, MAX_NAME_CHARS);
    if (name) libraries.push(name);
  }
  return libraries;
}

function parseElf(buffer) {
  const classByte = buffer[4];
  const dataByte = buffer[5];
  const is64 = classByte === 2;
  const littleEndian = dataByte === 1;
  const klass = classByte === 1 ? '32-bit' : classByte === 2 ? '64-bit' : 'unknown';
  const dataEncoding = dataByte === 1 ? 'little-endian' : dataByte === 2 ? 'big-endian' : 'unknown';
  const headerSize = is64 ? 64 : 52;
  if (buffer.length < headerSize) return { class: klass, dataEncoding, truncatedHeader: true };
  return {
    class: klass, dataEncoding,
    type: readUint(buffer, 16, 2, littleEndian),
    machine: readUint(buffer, 18, 2, littleEndian),
    entryPoint: is64 ? readUint(buffer, 24, 8, littleEndian) : readUint(buffer, 24, 4, littleEndian),
    sectionCount: is64 ? readUint(buffer, 60, 2, littleEndian) : readUint(buffer, 48, 2, littleEndian),
    neededLibraries: elfNeededLibraries(buffer, is64, littleEndian),
  };
}

function peRvaToOffset(sections, rva) {
  if (typeof rva !== 'number') return undefined;
  for (const section of sections) {
    const size = Math.max(section.virtualSize, section.sizeOfRawData);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + size) return section.pointerToRawData + (rva - section.virtualAddress);
  }
  return undefined;
}

function peSections(buffer, sectionTableOffset, sectionCount) {
  const sections = [];
  for (let i = 0; i < Math.min(sectionCount ?? 0, MAX_SECTIONS); i++) {
    const off = sectionTableOffset + i * 40;
    const virtualSize = readUint(buffer, off + 8, 4, true);
    const virtualAddress = readUint(buffer, off + 12, 4, true);
    const sizeOfRawData = readUint(buffer, off + 16, 4, true);
    const pointerToRawData = readUint(buffer, off + 20, 4, true);
    if ([virtualSize, virtualAddress, sizeOfRawData, pointerToRawData].some((v) => typeof v !== 'number')) break;
    sections.push({ virtualSize, virtualAddress, sizeOfRawData, pointerToRawData });
  }
  return sections;
}

// Static only: walks the PE Optional Header's Data Directory to the Import Directory Table
// and lists the imported DLL names — the same bytes the Windows loader itself would read,
// never executed or loaded. Spec verified independently against a real PE64 executable
// before this was written.
function peImports(buffer, signatureOffset, sizeOfOptionalHeader, sectionCount) {
  const magic = readUint(buffer, signatureOffset + 24, 2, true);
  if (typeof magic !== 'number') return [];
  const isPe32Plus = magic === 0x20b;
  const dataDirOffset = signatureOffset + 24 + (isPe32Plus ? 112 : 96);
  const importRva = readUint(buffer, dataDirOffset + 8, 4, true); // data directory index 1: Import Table
  if (typeof importRva !== 'number' || importRva === 0) return [];
  const sectionTableOffset = signatureOffset + 24 + sizeOfOptionalHeader;
  const sections = peSections(buffer, sectionTableOffset, sectionCount);
  const importTableOffset = peRvaToOffset(sections, importRva);
  if (typeof importTableOffset !== 'number') return [];

  const names = [];
  for (let i = 0; i < MAX_IMPORT_DESCRIPTORS; i++) {
    const off = importTableOffset + i * 20;
    const originalFirstThunk = readUint(buffer, off, 4, true);
    const nameRva = readUint(buffer, off + 12, 4, true);
    const firstThunk = readUint(buffer, off + 16, 4, true);
    if (typeof originalFirstThunk !== 'number' || typeof nameRva !== 'number' || typeof firstThunk !== 'number') break;
    if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break; // zero descriptor terminates the array
    const name = readCString(buffer, peRvaToOffset(sections, nameRva), MAX_NAME_CHARS);
    if (name) names.push(name);
  }
  return names;
}

function parsePe(buffer) {
  const signatureOffset = readUint(buffer, 0x3c, 4, true);
  if (signatureOffset === undefined || !magicMatch(buffer, signatureOffset, [0x50, 0x45, 0x00, 0x00])) return undefined;
  const sizeOfOptionalHeader = readUint(buffer, signatureOffset + 20, 2, true);
  const sectionCount = readUint(buffer, signatureOffset + 6, 2, true);
  return {
    machine: readUint(buffer, signatureOffset + 4, 2, true),
    sectionCount,
    timestamp: readUint(buffer, signatureOffset + 8, 4, true),
    entryPoint: sizeOfOptionalHeader ? readUint(buffer, signatureOffset + 40, 4, true) : undefined,
    imports: sizeOfOptionalHeader ? peImports(buffer, signatureOffset, sizeOfOptionalHeader, sectionCount) : [],
  };
}

// Static only: walks the Mach-O load command list right after the fixed header to collect
// LC_LOAD_DYLIB/LC_LOAD_WEAK_DYLIB names, the LC_UUID bytes, and LC_SEGMENT(_64) names — the
// same bytes dyld itself would read, never executed or loaded. Spec verified independently
// against a real 64-bit little-endian Mach-O bundle before this was written; the 32-bit
// LC_SEGMENT branch is structurally identical (segname sits at the same +8 offset in both the
// 32-bit and 64-bit command structs) but was not separately verified against a real 32-bit file.
function parseMachoLoadCommands(buffer, headerSize, commandCount, commandBytes, littleEndian, is64) {
  const dylibs = [];
  const segments = [];
  let uuid;
  let offset = headerSize;
  const declaredEnd = headerSize + commandBytes;
  const tableEnd = Math.min(declaredEnd, buffer.length);
  let truncated = declaredEnd > buffer.length;
  let malformed = false;
  for (let i = 0; i < Math.min(commandCount, MAX_MACHO_LOAD_COMMANDS); i++) {
    if (offset + 8 > tableEnd) { truncated = true; break; }
    const cmd = readUint(buffer, offset, 4, littleEndian);
    const cmdsize = readUint(buffer, offset + 4, 4, littleEndian);
    if (cmdsize < 8 || cmdsize % (is64 ? 8 : 4) !== 0) { malformed = true; break; }
    const commandEnd = offset + cmdsize;
    if (commandEnd > tableEnd) { truncated = true; break; }
    if ((cmd === 0xc || cmd === 0x80000018) && dylibs.length < MAX_MACHO_DYLIBS) { // LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB
      if (cmdsize < 24) { malformed = true; break; }
      const nameOffset = readUint(buffer, offset + 8, 4, littleEndian);
      if (nameOffset >= 24 && nameOffset < cmdsize) {
        const name = readCString(buffer.subarray(offset, commandEnd), nameOffset, MAX_NAME_CHARS);
        if (name) dylibs.push(name);
        else malformed = true;
      } else malformed = true;
    } else if (cmd === 0x1b) { // LC_UUID
      if (cmdsize < 24) { malformed = true; break; }
      uuid = buffer.toString('hex', offset + 8, offset + 24);
    } else if (((is64 && cmd === 0x19) || (!is64 && cmd === 0x1)) && segments.length < MAX_MACHO_SEGMENTS) { // LC_SEGMENT_64 / LC_SEGMENT
      if (cmdsize >= (is64 ? 72 : 56)) {
        const nameBytes = buffer.subarray(offset + 8, offset + 24);
        const nulIndex = nameBytes.indexOf(0);
        segments.push(nameBytes.toString('latin1', 0, nulIndex === -1 ? 16 : nulIndex));
      } else { malformed = true; break; }
    }
    offset += cmdsize;
  }
  return { dylibs, ...(uuid === undefined ? {} : { uuid }), segments,
    ...(truncated ? { truncated: true } : {}), ...(malformed ? { malformed: true } : {}),
    ...(commandCount > MAX_MACHO_LOAD_COMMANDS && offset < tableEnd ? { limited: true } : {}) };
}

function parseMacho(buffer) {
  const le64 = magicMatch(buffer, 0, [0xcf, 0xfa, 0xed, 0xfe]);
  const be64 = magicMatch(buffer, 0, [0xfe, 0xed, 0xfa, 0xcf]);
  const le32 = magicMatch(buffer, 0, [0xce, 0xfa, 0xed, 0xfe]);
  const is64 = le64 || be64;
  const littleEndian = le64 || le32;
  const headerSize = is64 ? 32 : 28;
  if (buffer.length < headerSize) return { truncatedHeader: true };
  const cpuType = readUint(buffer, 4, 4, littleEndian);
  const fileType = readUint(buffer, 12, 4, littleEndian);
  const commandCount = readUint(buffer, 16, 4, littleEndian);
  const commandBytes = readUint(buffer, 20, 4, littleEndian);
  return { cpuType, fileType, loadCommandCount: commandCount,
    ...parseMachoLoadCommands(buffer, headerSize, commandCount, commandBytes, littleEndian, is64) };
}

// Bounded backward search for the End Of Central Directory record, confined to the last
// 64KB+22 bytes of the file (the largest a ZIP comment can legally make that search window) —
// this cannot degrade into an unbounded scan of an arbitrarily large file.
function findEocd(buffer) {
  const searchStart = Math.max(0, buffer.length - MAX_EOCD_SEARCH_BYTES);
  let zip64Candidate;
  let emptyCandidate;
  for (let offset = buffer.length - 22; offset >= searchStart; offset--) {
    if (!magicMatch(buffer, offset, [0x50, 0x4b, 0x05, 0x06])) continue;
    if (offset + 22 + readUint(buffer, offset + 20, 2, true) !== buffer.length) continue;
    const count = readUint(buffer, offset + 10, 2, true);
    const size = readUint(buffer, offset + 12, 4, true);
    const start = readUint(buffer, offset + 16, 4, true);
    if (typeof count !== 'number' || typeof size !== 'number' || typeof start !== 'number') continue;
    // A signature embedded in a comment is not sufficient evidence of an EOCD.
    if (count === 0xffff || size === 0xffffffff || start === 0xffffffff) {
      // A sentinel in a comment must not outrank a coherent ordinary EOCD.
      zip64Candidate ??= offset;
      continue;
    }
    // The central directory must fit entirely before this record, but need not end flush
    // against it: a spec-legal archive may carry a ZIP64 EOCD record plus its locator
    // (56 + 20 bytes) in the gap between, and real writers emit both even for small
    // archives whose every 32-bit field is valid. Requiring flushness here rejected such
    // archives outright — verified against a real third-party-written .zip.
    if (start + size > offset || (count === 0 && size !== 0)) continue;
    // What actually distinguishes a genuine record from one forged inside an archive comment
    // is that a real non-empty central directory begins with a central-directory file header
    // signature — not that it ends flush against the EOCD.
    if (count > 0) {
      if (magicMatch(buffer, start, [0x50, 0x4b, 0x01, 0x02])) return offset;
      continue;
    }
    emptyCandidate ??= offset;
  }
  return emptyCandidate ?? zip64Candidate;
}

// Static only: lists the ZIP central directory's file entries (name, sizes, compression method)
// — the same records any unzip tool reads to build a listing — without ever inflating/extracting
// an entry's actual data. Spec verified independently against a real archive before this was
// written. Filenames are decoded as UTF-8 regardless of the legacy CP437 flag bit, a deliberate
// simplification consistent with this tool's "best-effort, untrusted" framing elsewhere.
function parseZipEntries(buffer) {
  const eocdOffset = findEocd(buffer);
  if (typeof eocdOffset !== 'number') return { entries: [], truncated: true };
  const totalEntries = readUint(buffer, eocdOffset + 10, 2, true);
  const centralDirOffset = readUint(buffer, eocdOffset + 16, 4, true);
  const centralDirSize = readUint(buffer, eocdOffset + 12, 4, true);
  // Only a sentinel field value means the 32-bit record genuinely cannot carry the real one —
  // the mere presence of a ZIP64 EOCD locator does not, since common writers emit it
  // unconditionally. Every field that would actually overflow is sentinel-checked here and
  // per-entry below, so a listable archive stays listable instead of being refused wholesale.
  if (totalEntries === 0xffff || centralDirOffset === 0xffffffff || centralDirSize === 0xffffffff) return { entries: [], unsupported: 'zip64' };
  if (readUint(buffer, eocdOffset + 4, 2, true) !== 0 || readUint(buffer, eocdOffset + 6, 2, true) !== 0 || readUint(buffer, eocdOffset + 8, 2, true) !== totalEntries) return { entries: [], unsupported: 'multi-disk' };

  const entries = [];
  let offset = centralDirOffset;
  const centralDirEnd = centralDirOffset + centralDirSize;
  let truncated = false;
  for (let i = 0; i < Math.min(totalEntries, MAX_ZIP_ENTRIES); i++) {
    if (offset + 46 > centralDirEnd || !magicMatch(buffer, offset, [0x50, 0x4b, 0x01, 0x02])) { truncated = true; break; }
    const compressionMethod = readUint(buffer, offset + 10, 2, true);
    const compressedSize = readUint(buffer, offset + 20, 4, true);
    const uncompressedSize = readUint(buffer, offset + 24, 4, true);
    const nameLength = readUint(buffer, offset + 28, 2, true);
    const extraLength = readUint(buffer, offset + 30, 2, true);
    const commentLength = readUint(buffer, offset + 32, 2, true);
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || readUint(buffer, offset + 42, 4, true) === 0xffffffff) return { entries, unsupported: 'zip64' };
    if (readUint(buffer, offset + 34, 2, true) !== 0) return { entries, unsupported: 'multi-disk' };
    const entryEnd = offset + 46 + nameLength + extraLength + commentLength;
    if (entryEnd > centralDirEnd) { truncated = true; break; }
    const name = readFixedString(buffer, offset + 46, nameLength, MAX_ZIP_NAME_CHARS);
    if (typeof name !== 'string') break;
    entries.push({ name, compressedSize, uncompressedSize, compressionMethod });
    offset = entryEnd;
  }
  return { entries, ...(truncated ? { truncated: true } : {}), ...(totalEntries > MAX_ZIP_ENTRIES ? { limited: true } : {}) };
}

// Static only: walks the WASM binary format's section sequence (id + ULEB128 size, skipping
// each payload) to list which sections are present — the same records a WASM validator reads
// before any instantiation, never itself instantiated or run. Spec verified independently
// against a real module before this was written. Section accumulation uses plain number
// arithmetic rather than bitwise OR specifically so a maliciously large declared size can't
// wrap through JS's 32-bit bitwise-operator truncation.
function parseWasm(buffer) {
  if (buffer.length < 8) return { sections: [], truncatedHeader: true };
  const version = readUint(buffer, 4, 4, true);
  const sections = [];
  if (version !== 1) return { version, sections, unsupportedVersion: true };
  let offset = 8;
  for (let i = 0; i < MAX_WASM_SECTIONS; i++) {
    if (offset >= buffer.length) break;
    const id = buffer[offset];
    offset += 1;
    let size = 0;
    let shift = 0;
    let more = true;
    let truncated = false;
    for (let b = 0; b < 5 && more; b++) {
      if (offset >= buffer.length) { truncated = true; break; }
      const byte = buffer[offset];
      offset += 1;
      if (b === 4 && (byte & 0x7f) > 15) return { version, sections, truncated: true, malformed: true };
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      more = (byte & 0x80) !== 0;
    }
    if (truncated || more) return { version, sections, truncated: true }; // unterminated or over-length varint
    sections.push({ id, size });
    offset += size;
    if (offset > buffer.length) return { version, sections, truncated: true };
  }
  return { version, sections, ...(offset < buffer.length ? { limited: true } : {}) };
}

/** Pure identification/inspection of acquired local bytes. Never executes, never trusts, content. */
export function makeArtifactTools() {
  return [
    { name: 'artifact.inspect', version: '1.0.0', effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, limit);
        const result = { path: relative, bytes: bytes.length, sha256: sha256(bytes), format: identifyFormat(bytes), untrusted: true };
        if (result.format === 'elf') result.elf = parseElf(bytes);
        if (result.format === 'mz-dos') {
          const pe = parsePe(bytes);
          if (pe) { result.format = 'pe'; result.pe = pe; }
        }
        if (result.format.startsWith('mach-o-')) result.machO = parseMacho(bytes);
        if (result.format === 'zip' || result.format === 'zip-empty' || result.format === 'zip-spanned') result.zip = parseZipEntries(bytes);
        if (result.format === 'wasm') result.wasm = parseWasm(bytes);
        return result;
      } },
  ];
}
