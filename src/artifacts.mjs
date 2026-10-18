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
  { format: 'sqlite', bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00] },
  { format: 'pcapng', bytes: [0x0a, 0x0d, 0x0d, 0x0a] },
  { format: 'pcap-le', bytes: [0xd4, 0xc3, 0xb2, 0xa1] },
  { format: 'pcap-be', bytes: [0xa1, 0xb2, 0xc3, 0xd4] },
  { format: 'pcap-le-nanos', bytes: [0x4d, 0x3c, 0xb2, 0xa1] },
  { format: 'pcap-be-nanos', bytes: [0xa1, 0xb2, 0x3c, 0x4d] },
  { format: 'dex', bytes: [0x64, 0x65, 0x78, 0x0a] },
  { format: 'java-class', bytes: [0xca, 0xfe, 0xba, 0xbe] },
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

const MAX_WASM_TYPES = 4096;
const MAX_WASM_INTERFACE_ENTRIES = 4096;
const MAX_WASM_SIGNATURE_TYPES = 256;
const MAX_WASM_NAME_CHARS = 512;
const MAX_WASM_INDEX_ENTRIES = 65536;

const WASM_VALUE_TYPES = new Map([
  [0x7f, 'i32'], [0x7e, 'i64'], [0x7d, 'f32'], [0x7c, 'f64'],
  [0x7b, 'v128'], [0x70, 'funcref'], [0x6f, 'externref'],
]);
const WASM_IMPORT_KINDS = ['func', 'table', 'memory', 'global', 'tag'];

/** Unsigned LEB128, rejecting over-long encodings and values above 2^32-1. */
function readLeb(buffer, offset) {
  let value = 0;
  let shift = 0;
  for (let i = 0; i < 5; i++) {
    if (offset >= buffer.length) return null;
    const byte = buffer[offset];
    offset += 1;
    if (i === 4 && (byte & 0x7f) > 15) return null;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return { value, offset };
    shift += 7;
  }
  return null;
}

function readWasmName(buffer, offset) {
  const length = readLeb(buffer, offset);
  if (!length) return null;
  const end = length.offset + length.value;
  if (end > buffer.length || length.value > MAX_WASM_NAME_CHARS * 4) return null;
  // Decoded strictly: a malformed name is a parse failure, not a replacement character.
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(length.offset, end)); }
  catch { return null; }
  if (text.length > MAX_WASM_NAME_CHARS) return null;
  return { value: text, offset: end };
}

function readWasmLimits(buffer, offset) {
  if (offset >= buffer.length) return null;
  const flags = buffer[offset];
  offset += 1;
  if ((flags & ~0x07) !== 0) return null;
  const min = readLeb(buffer, offset);
  if (!min) return null;
  offset = min.offset;
  let maximum = null;
  if ((flags & 0x01) !== 0) {
    const max = readLeb(buffer, offset);
    if (!max) return null;
    maximum = String(max.value);
    offset = max.offset;
  }
  return { offset, limits: { minimum: String(min.value), maximum, shared: (flags & 0x02) !== 0,
    address_type: (flags & 0x04) !== 0 ? 'i64' : 'i32' } };
}

function readWasmVector(buffer, offset, limit, readOne) {
  const count = readLeb(buffer, offset);
  if (!count || count.value > limit) return null;
  const items = [];
  offset = count.offset;
  for (let i = 0; i < count.value; i++) {
    const one = readOne(buffer, offset);
    if (!one) return null;
    items.push(one.value);
    offset = one.offset;
  }
  return { value: items, offset };
}

const readValueType = (buffer, offset) => {
  if (offset >= buffer.length) return null;
  const name = WASM_VALUE_TYPES.get(buffer[offset]);
  return name === undefined ? null : { value: name, offset: offset + 1 };
};

const watTypes = (list) => (list.length ? ' ' + list.join(' ') : '');

/** A deterministic WAT-shaped rendering, so a diff of two interfaces reads as text. */
function watForm(entry) {
  const head = entry.direction === 'import'
    ? `(import ${JSON.stringify(entry.module)} ${JSON.stringify(entry.name)} `
    : `(export ${JSON.stringify(entry.name)} `;
  const s = entry.signature;
  let body;
  if (!s) body = `(${entry.kind})`;
  else if (s.kind === 'func' || s.kind === 'tag') {
    body = `(${s.kind}${s.params.length ? ' (param' + watTypes(s.params) + ')' : ''}`
      + `${s.results.length ? ' (result' + watTypes(s.results) + ')' : ''})`;
  } else if (s.kind === 'table') body = `(table ${s.minimum}${s.maximum === null ? '' : ' ' + s.maximum} ${s.element})`;
  else if (s.kind === 'memory') body = `(memory ${s.minimum}${s.maximum === null ? '' : ' ' + s.maximum})`;
  else body = `(global ${s.mutable ? '(mut ' + s.value_type + ')' : s.value_type})`;
  return head + body + ')';
}

/**
 * Typed WASM import/export interface, decoded from the binary directly.
 *
 * REA recovers this through WABT, an external toolkit. The format is fully specified, so it is
 * recovered here from the bytes with no dependency and no execution: the type, import, function,
 * table, memory, global and tag sections are read, and the function index space is reconstructed
 * (imports first, then definitions) so an exported function reports its real signature. Anything
 * the bounds or the encoding prevent reading is reported as `partial` with a stated limitation
 * rather than as an empty or guessed interface.
 */
function parseWasmInterface(buffer) {
  const limitations = [];
  const entries = [];
  const fail = (why) => { limitations.push(why); return { state: 'partial', entries, limitations }; };
  if (buffer.length < 8) return fail('The module is shorter than a WASM header');
  if (readUint(buffer, 4, 4, true) !== 1) return fail('Only WASM binary format version 1 is decoded');

  const raw = new Map();
  let offset = 8;
  for (let i = 0; i < MAX_WASM_SECTIONS && offset < buffer.length; i++) {
    const id = buffer[offset];
    const size = readLeb(buffer, offset + 1);
    if (!size) return fail('A section length is malformed');
    const end = size.offset + size.value;
    if (end > buffer.length) return fail('A section extends past the end of the module');
    // Only the first occurrence of each non-custom section is meaningful.
    if (id !== 0 && !raw.has(id)) raw.set(id, { start: size.offset, end });
    offset = end;
  }
  if (offset < buffer.length) limitations.push('Section scan stopped at the section-count bound');

  const section = (id, limit, readOne) => {
    const found = raw.get(id);
    if (!found) return [];
    const vector = readWasmVector(buffer, found.start, limit, readOne);
    if (!vector) { limitations.push(`Section ${id} could not be decoded`); return null; }
    return vector.value;
  };

  const types = section(1, MAX_WASM_TYPES, (b, o) => {
    if (o >= b.length || b[o] !== 0x60) return null;
    const params = readWasmVector(b, o + 1, MAX_WASM_SIGNATURE_TYPES, readValueType);
    if (!params) return null;
    const results = readWasmVector(b, params.offset, MAX_WASM_SIGNATURE_TYPES, readValueType);
    if (!results) return null;
    return { value: { params: params.value, results: results.value }, offset: results.offset };
  });
  if (types === null) return { state: 'partial', entries, limitations };

  const funcSignature = (typeIndex) => {
    const found = types[typeIndex];
    return found ? { kind: 'func', params: found.params, results: found.results } : null;
  };

  // Imports populate the low end of every index space, so they are read before definitions.
  const importedFuncTypes = [];
  const importedTables = [];
  const importedMemories = [];
  const importedGlobals = [];
  const imports = section(2, MAX_WASM_INTERFACE_ENTRIES, (b, o) => {
    const module = readWasmName(b, o);
    if (!module) return null;
    const name = readWasmName(b, module.offset);
    if (!name) return null;
    let at = name.offset;
    if (at >= b.length) return null;
    const code = b[at];
    at += 1;
    const kind = WASM_IMPORT_KINDS[code];
    if (kind === undefined) return null;
    let signature = null;
    if (kind === 'func' || kind === 'tag') {
      if (kind === 'tag') { if (at >= b.length || b[at] !== 0x00) return null; at += 1; }
      const typeIndex = readLeb(b, at);
      if (!typeIndex) return null;
      at = typeIndex.offset;
      if (kind === 'func') importedFuncTypes.push(typeIndex.value);
      const found = types[typeIndex.value];
      signature = found ? { kind, params: found.params, results: found.results } : null;
    } else if (kind === 'table') {
      const element = readValueType(b, at);
      if (!element || (element.value !== 'funcref' && element.value !== 'externref')) return null;
      const limits = readWasmLimits(b, element.offset);
      if (!limits) return null;
      at = limits.offset;
      signature = { kind: 'table', element: element.value, ...limits.limits };
      importedTables.push(signature);
    } else if (kind === 'memory') {
      const limits = readWasmLimits(b, at);
      if (!limits) return null;
      at = limits.offset;
      signature = { kind: 'memory', page_size: '65536', ...limits.limits };
      importedMemories.push(signature);
    } else {
      const valueType = readValueType(b, at);
      if (!valueType) return null;
      at = valueType.offset;
      if (at >= b.length || b[at] > 1) return null;
      signature = { kind: 'global', value_type: valueType.value, mutable: b[at] === 1 };
      at += 1;
      importedGlobals.push(signature);
    }
    return { value: { direction: 'import', module: module.value, name: name.value, kind, signature }, offset: at };
  });
  if (imports === null) return { state: 'partial', entries, limitations };

  const definedFuncTypes = section(3, MAX_WASM_INDEX_ENTRIES, (b, o) => {
    const typeIndex = readLeb(b, o);
    return typeIndex ? { value: typeIndex.value, offset: typeIndex.offset } : null;
  });
  const definedTables = section(4, MAX_WASM_INDEX_ENTRIES, (b, o) => {
    const element = readValueType(b, o);
    if (!element) return null;
    const limits = readWasmLimits(b, element.offset);
    if (!limits) return null;
    return { value: { kind: 'table', element: element.value, ...limits.limits }, offset: limits.offset };
  });
  const definedMemories = section(5, MAX_WASM_INDEX_ENTRIES, (b, o) => {
    const limits = readWasmLimits(b, o);
    return limits ? { value: { kind: 'memory', page_size: '65536', ...limits.limits }, offset: limits.offset } : null;
  });
  if (definedFuncTypes === null || definedTables === null || definedMemories === null) {
    return { state: 'partial', entries, limitations };
  }

  for (const one of imports) entries.push({ ...one, index: null, issue: null, wat_form: watForm(one) });

  const resolve = (code, index) => {
    if (code === 0) {
      return index < importedFuncTypes.length
        ? funcSignature(importedFuncTypes[index])
        : funcSignature(definedFuncTypes[index - importedFuncTypes.length]);
    }
    if (code === 1) return index < importedTables.length ? importedTables[index] : definedTables[index - importedTables.length] ?? null;
    if (code === 2) return index < importedMemories.length ? importedMemories[index] : definedMemories[index - importedMemories.length] ?? null;
    if (code === 3) return index < importedGlobals.length ? importedGlobals[index] : null;
    return null;
  };

  const exports = section(7, MAX_WASM_INTERFACE_ENTRIES, (b, o) => {
    const name = readWasmName(b, o);
    if (!name) return null;
    let at = name.offset;
    if (at >= b.length) return null;
    const code = b[at];
    at += 1;
    const kind = WASM_IMPORT_KINDS[code];
    if (kind === undefined) return null;
    const index = readLeb(b, at);
    if (!index) return null;
    return { value: { direction: 'export', module: null, name: name.value, kind, index: index.value, code }, offset: index.offset };
  });
  if (exports === null) return { state: 'partial', entries, limitations };

  for (const one of exports) {
    const signature = resolve(one.code, one.index);
    const entry = { direction: 'export', module: null, name: one.name, kind: one.kind, index: one.index, signature,
      issue: signature ? null : 'The defining section for this export index was not decoded' };
    entries.push({ ...entry, wat_form: watForm(entry) });
  }

  const counts = {
    imports: entries.filter(e => e.direction === 'import').length,
    exports: entries.filter(e => e.direction === 'export').length,
    unresolved: entries.filter(e => e.signature === null).length,
  };
  return { state: limitations.length || counts.unresolved ? 'partial' : 'complete', entries, counts, limitations };
}

const INTERFACE_ENTRY_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['direction', 'name', 'kind'],
  properties: {
    direction: { enum: ['import', 'export'] },
    module: { anyOf: [{ type: 'string', maxLength: 512 }, { type: 'null' }] },
    name: { type: 'string', maxLength: 512 },
    kind: { enum: ['func', 'table', 'memory', 'global', 'tag', 'unknown'] },
  },
};
const INTERFACE_SCHEMA = object({
  state: { enum: ['complete', 'partial'] },
  entries: { type: 'array', maxItems: MAX_WASM_INTERFACE_ENTRIES * 2, items: INTERFACE_ENTRY_SCHEMA },
}, ['entries']);

const signatureOf = (entry) => (entry.signature === undefined ? null : entry.signature);
const entryKey = (entry) => JSON.stringify([entry.direction, entry.module ?? null, entry.name]);

/**
 * Compare two decoded interfaces by (direction, module, name).
 *
 * Duplicate keys are reported `unknown` rather than paired arbitrarily: with two same-named
 * imports there is no fact about which corresponds to which, and inventing a pairing would turn
 * an unknown into a confident wrong answer. Every occurrence is still counted.
 */
function compareInterfaces(left, right, select) {
  const wanted = (entry) => select === 'both' || (select === 'imports' ? entry.direction === 'import' : entry.direction === 'export');
  const index = (entries) => {
    const map = new Map();
    for (const entry of entries) {
      if (!wanted(entry)) continue;
      const key = entryKey(entry);
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(entry);
    }
    return map;
  };
  const a = index(left.entries);
  const b = index(right.entries);
  const changes = [];
  for (const key of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    const mine = a.get(key) ?? [];
    const theirs = b.get(key) ?? [];
    const [direction, module, name] = JSON.parse(key);
    const base = { direction, module, name };
    if (mine.length > 1 || theirs.length > 1) {
      changes.push({ ...base, state: 'unknown', left: mine.map(signatureOf), right: theirs.map(signatureOf),
        reason: 'The name occurs more than once, so no correspondence between occurrences is established' });
      continue;
    }
    const one = mine[0];
    const two = theirs[0];
    if (!two) { changes.push({ ...base, state: 'removed', left: [signatureOf(one)], right: [], reason: null }); continue; }
    if (!one) { changes.push({ ...base, state: 'added', left: [], right: [signatureOf(two)], reason: null }); continue; }
    const leftSignature = signatureOf(one);
    const rightSignature = signatureOf(two);
    if (leftSignature === null || rightSignature === null) {
      changes.push({ ...base, state: 'unknown', left: [leftSignature], right: [rightSignature],
        reason: 'A signature on one side was not decoded, so equality cannot be concluded' });
      continue;
    }
    const same = JSON.stringify(leftSignature) === JSON.stringify(rightSignature) && one.kind === two.kind;
    changes.push({ ...base, state: same ? 'unchanged' : 'changed', left: [leftSignature], right: [rightSignature], reason: null });
  }
  const tally = (state) => changes.filter(c => c.state === state).length;
  const limitations = [];
  for (const [label, side] of [['left', left], ['right', right]]) {
    if (side.state === 'partial') limitations.push(`The ${label} interface is partial, so an absence there is not evidence of removal`);
  }
  return { select, changes,
    summary: { added: tally('added'), removed: tally('removed'), changed: tally('changed'),
      unchanged: tally('unchanged'), unknown: tally('unknown') },
    limitations };
}

const MAX_EVM_BYTES = 4 * 1024 * 1024;
const MAX_EVM_SELECTORS = 2048;
const MAX_EVM_UNDEFINED = 256;
const MAX_CBOR_ENTRIES = 64;
const MAX_CBOR_DEPTH = 4;
const MAX_CBOR_TEXT = 1024;

// Assigned EVM opcode ranges. Anything outside them is undefined and would halt execution, so
// its presence is reported rather than silently treated as a no-op.
// 0x5c-0x5e (TLOAD, TSTORE, MCOPY) and 0x5f (PUSH0) are assigned as of Cancun, which makes
// 0x50-0x9f contiguous. Splitting the range here would report live opcodes as undefined.
const EVM_ASSIGNED = [[0x00, 0x0b], [0x10, 0x1d], [0x20, 0x20], [0x30, 0x3f], [0x40, 0x4a],
  [0x50, 0x9f], [0xa0, 0xa4], [0xf0, 0xf5], [0xfa, 0xfa], [0xfd, 0xff]];
const evmAssigned = (op) => EVM_ASSIGNED.some(([low, high]) => op >= low && op <= high);

/**
 * Strict hex decoding, matching REA's stated carrier rules.
 *
 * Outer ASCII whitespace and one optional 0x prefix are permitted. Odd length, interior
 * separators, a BOM and any non-ASCII whitespace are rejected, because a carrier that needs
 * guessing is not a carrier whose digest means anything.
 */
function decodeEvmHex(bytes) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { return { error: 'The hex carrier is not valid UTF-8' }; }
  if (text.charCodeAt(0) === 0xfeff) return { error: 'The hex carrier begins with a byte-order mark' };
  const trimmed = text.replace(/^[ \t\r\n]+/, '').replace(/[ \t\r\n]+$/, '');
  if (/[^0-9a-fA-Fx]/.test(trimmed)) return { error: 'The hex carrier contains interior separators or non-hex characters' };
  const body = /^0x/i.test(trimmed) ? trimmed.slice(2) : trimmed;
  if (!/^[0-9a-fA-F]*$/.test(body)) return { error: 'The hex carrier contains a stray x outside a leading 0x prefix' };
  if (body.length % 2 !== 0) return { error: 'The hex carrier has an odd number of digits' };
  const out = Buffer.alloc(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  return { value: out };
}

/** Minimal CBOR reader for a Solidity metadata trailer: integers as decimal strings, bytes as hex. */
function readCbor(buffer, offset, depth) {
  if (offset >= buffer.length || depth > MAX_CBOR_DEPTH) return null;
  const initial = buffer[offset];
  const major = initial >> 5;
  const minor = initial & 0x1f;
  let at = offset + 1;
  let count = minor;
  if (minor === 24) { if (at >= buffer.length) return null; count = buffer[at]; at += 1; }
  else if (minor === 25) { if (at + 1 >= buffer.length) return null; count = readUint(buffer, at, 2, false); at += 2; }
  else if (minor === 26) { if (at + 3 >= buffer.length) return null; count = readUint(buffer, at, 4, false); at += 4; }
  else if (minor >= 27) return null; // 64-bit and indefinite lengths are not interpreted
  if (major === 0) return { value: String(count), offset: at };
  if (major === 1) return { value: String(-1 - count), offset: at };
  if (major === 2 || major === 3) {
    const end = at + count;
    if (end > buffer.length || count > MAX_CBOR_TEXT) return null;
    const slice = buffer.subarray(at, end);
    if (major === 2) return { value: slice.toString('hex'), offset: end };
    try { return { value: new TextDecoder('utf-8', { fatal: true }).decode(slice), offset: end }; }
    catch { return null; }
  }
  if (major === 4 || major === 5) {
    if (count > MAX_CBOR_ENTRIES) return null;
    const items = [];
    for (let i = 0; i < count * (major === 5 ? 2 : 1); i++) {
      const one = readCbor(buffer, at, depth + 1);
      if (!one) return null;
      items.push(one.value);
      at = one.offset;
    }
    if (major === 4) return { value: items, offset: at };
    const map = {};
    for (let i = 0; i < items.length; i += 2) map[String(items[i])] = items[i + 1];
    return { value: map, offset: at };
  }
  return null;
}

/**
 * Static reading of EVM bytecode.
 *
 * REA recovers selectors with bundled EVMole plus a host prlimit. That dataflow analysis is not
 * reproduced here and is not claimed: what this returns is what the bytes themselves determine.
 * The sweep skips PUSH immediates by width, which is the difference between reading code and
 * reading data that happens to look like opcodes, and PUSH4 immediates are reported as selector
 * CANDIDATES because an ordinary four-byte constant is indistinguishable from a selector without
 * following the dispatcher.
 */
function parseEvmBytecode(bytes) {
  const limitations = [];
  if (bytes.length >= 2 && bytes[0] === 0xef && bytes[1] === 0x00) {
    return { supported: false, reason: 'unsupported_target',
      detail: 'EOF (EF00) containers use a sectioned layout that this reader does not decode',
      selectorCandidates: [], opcodes: null, metadata: null, limitations };
  }

  let metadata = null;
  let codeEnd = bytes.length;
  if (bytes.length > 2) {
    const declared = readUint(bytes, bytes.length - 2, 2, false);
    const start = bytes.length - 2 - declared;
    if (declared > 0 && start >= 0) {
      const parsed = readCbor(bytes, start, 0);
      // Accepted only if the CBOR root map ends exactly where the length prefix says it does.
      if (parsed && parsed.offset === bytes.length - 2 && parsed.value && typeof parsed.value === 'object' && !Array.isArray(parsed.value)) {
        metadata = { offset: start, length: declared, root: parsed.value };
        codeEnd = start;
      } else limitations.push('A terminal length prefix was present but did not address a CBOR root map');
    }
  }

  const selectors = new Map();
  const undefinedOps = [];
  let instructions = 0;
  let pushes = 0;
  let jumpdests = 0;
  let truncatedPush = false;
  for (let i = 0; i < codeEnd;) {
    const op = bytes[i];
    instructions += 1;
    if (!evmAssigned(op) && undefinedOps.length < MAX_EVM_UNDEFINED) undefinedOps.push({ offset: i, opcode: op });
    if (op === 0x5b) jumpdests += 1;
    if (op >= 0x60 && op <= 0x7f) {
      pushes += 1;
      const width = op - 0x5f;
      if (i + 1 + width > codeEnd) { truncatedPush = true; break; }
      if (width === 4 && selectors.size < MAX_EVM_SELECTORS) {
        const hex = bytes.subarray(i + 1, i + 5).toString('hex');
        if (!selectors.has(hex)) selectors.set(hex, i);
      }
      i += 1 + width;
      continue;
    }
    i += 1;
  }
  if (truncatedPush) limitations.push('A PUSH immediate ran past the end of the code region, so the sweep stopped there');
  if (selectors.size >= MAX_EVM_SELECTORS) limitations.push('The selector candidate bound was reached');
  limitations.push('Selector candidates come from a PUSH4 sweep, not from dispatcher dataflow, so an ordinary four-byte constant can appear here');

  return { supported: true, reason: null,
    selectorCandidates: [...selectors].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([selector, offset]) => ({ selector, offset })),
    opcodes: { codeBytes: codeEnd, instructions, pushes, jumpdests,
      undefined: undefinedOps, undefinedCount: undefinedOps.length, truncatedPush },
    metadata, limitations };
}

const SQLITE_MAGIC = 'SQLite format 3\0';
const MAX_SQLITE_OBJECTS = 2048;
const MAX_SQLITE_SQL_CHARS = 8192;
// The reported name is SQLite's own spelling, so it compares equal to `PRAGMA encoding`; the
// second value is the label TextDecoder accepts, which is not the same string.
const SQLITE_ENCODINGS = {
  1: { reported: 'UTF-8', decoder: 'utf-8' },
  2: { reported: 'UTF-16le', decoder: 'utf-16le' },
  3: { reported: 'UTF-16be', decoder: 'utf-16be' },
};

/**
 * Big-endian twos-complement integer of 1..8 bytes, as SQLite serial types 1-6 encode.
 *
 * `readUint` is not usable here: it supports only sizes 2 and 4 and falls through to a 64-bit read
 * for anything else, so asking it for one byte silently reads eight.
 */
function readSignedBe(buffer, offset, size) {
  if (offset < 0 || offset + size > buffer.length) return undefined;
  if (size === 8) {
    const big = buffer.readBigInt64BE(offset);
    const bounded = big <= BigInt(Number.MAX_SAFE_INTEGER) && big >= BigInt(Number.MIN_SAFE_INTEGER);
    return bounded ? Number(big) : big.toString();
  }
  let value = 0;
  for (let i = 0; i < size; i++) value = value * 256 + buffer[offset + i];
  const half = 2 ** (size * 8 - 1);
  return value >= half ? value - 2 ** (size * 8) : value;
}

/** SQLite variable-length integer: up to nine bytes, the ninth contributing all eight bits. */
function readVarint(buffer, offset) {
  let value = 0;
  for (let i = 0; i < 9; i++) {
    if (offset + i >= buffer.length) return null;
    const byte = buffer[offset + i];
    if (i === 8) return { value: value * 256 + byte, offset: offset + 9 };
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) return { value, offset: offset + i + 1 };
  }
  return null;
}

/**
 * Read the schema objects SQLite keeps in `sqlite_master` on page 1.
 *
 * Only a leaf table b-tree is followed, and a cell whose payload does not fit on its page is
 * reported rather than chased through the overflow chain: a partially reassembled record would be
 * indistinguishable from a complete one in the output, which is the failure mode worth avoiding.
 */
function sqliteSchema(buffer, pageSize, encoding, limitations) {
  const objects = [];
  // Page 1 carries the 100-byte file header before its b-tree header.
  const headerAt = 100;
  if (headerAt >= buffer.length) { limitations.push('The file ends before page 1 b-tree header'); return objects; }
  const type = buffer[headerAt];
  if (type !== 0x0d) {
    limitations.push(type === 0x05
      ? 'The schema root is an interior page, so only a single-page schema is read here'
      : 'Page 1 is not a table b-tree leaf');
    return objects;
  }
  const cellCount = readUint(buffer, headerAt + 3, 2, false);
  const pageEnd = Math.min(pageSize, buffer.length);
  if (cellCount > MAX_SQLITE_OBJECTS) limitations.push('The schema object bound was reached');
  for (let i = 0; i < Math.min(cellCount, MAX_SQLITE_OBJECTS); i++) {
    const pointerAt = headerAt + 8 + i * 2;
    if (pointerAt + 1 >= pageEnd) { limitations.push('A cell pointer lies outside page 1'); break; }
    let at = readUint(buffer, pointerAt, 2, false);
    if (at === 0 || at >= pageEnd) { limitations.push('A cell offset lies outside page 1'); continue; }
    const payloadLength = readVarint(buffer, at);
    if (!payloadLength) { limitations.push('A cell payload length is malformed'); continue; }
    const rowid = readVarint(buffer, payloadLength.offset);
    if (!rowid) { limitations.push('A cell rowid is malformed'); continue; }
    at = rowid.offset;
    if (at + payloadLength.value > pageEnd) { limitations.push('A record overflows its page and was not reassembled'); continue; }
    const recordEnd = at + payloadLength.value;
    const headerSize = readVarint(buffer, at);
    if (!headerSize) { limitations.push('A record header is malformed'); continue; }
    const serials = [];
    let cursor = headerSize.offset;
    const headerEnd = at + headerSize.value;
    while (cursor < headerEnd) {
      const serial = readVarint(buffer, cursor);
      if (!serial) break;
      serials.push(serial.value);
      cursor = serial.offset;
    }
    // sqlite_master is (type, name, tbl_name, rootpage, sql).
    let body = headerEnd;
    const values = [];
    for (const serial of serials) {
      if (serial === 0) { values.push(null); continue; }
      // Serial types 1-6 are signed big-endian integers of 1, 2, 3, 4, 6 and 8 bytes.
      const intWidths = { 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8 };
      if (intWidths[serial] !== undefined) {
        const size = intWidths[serial];
        if (body + size > recordEnd) { values.push(null); break; }
        values.push(readSignedBe(buffer, body, size));
        body += size;
        continue;
      }
      if (serial === 7) {
        if (body + 8 > recordEnd) { values.push(null); break; }
        values.push(buffer.readDoubleBE(body));
        body += 8;
        continue;
      }
      if (serial === 8) { values.push(0); continue; }
      if (serial === 9) { values.push(1); continue; }
      if (serial >= 13 && serial % 2 === 1) {
        const size = (serial - 13) / 2;
        if (body + size > recordEnd || size > MAX_SQLITE_SQL_CHARS * 4) { values.push(null); break; }
        const slice = buffer.subarray(body, body + size);
        let text;
        try { text = new TextDecoder(encoding, { fatal: true }).decode(slice); }
        catch { text = null; }
        values.push(text === null || text.length > MAX_SQLITE_SQL_CHARS ? null : text);
        body += size;
        continue;
      }
      if (serial >= 12 && serial % 2 === 0) {
        const size = (serial - 12) / 2;
        if (body + size > recordEnd) { values.push(null); break; }
        values.push({ blobBytes: size });
        body += size;
        continue;
      }
      // 10 and 11 are reserved; their width is unknown, so the record cannot be walked further.
      limitations.push('A record used a reserved serial type, so its remaining columns were not read');
      values.push(null);
      break;
    }
    const [kind, name, tableName, rootPage, sql] = values;
    objects.push({
      type: typeof kind === 'string' ? kind : null,
      name: typeof name === 'string' ? name : null,
      tableName: typeof tableName === 'string' ? tableName : null,
      rootPage: typeof rootPage === 'number' ? rootPage : null,
      sql: typeof sql === 'string' ? sql : null,
    });
  }
  return objects;
}

/** Structure of a SQLite database file, read from its documented header and schema page. */
function parseSqlite(buffer) {
  const limitations = [];
  if (buffer.length < 100 || buffer.toString('latin1', 0, 16) !== SQLITE_MAGIC) {
    return { supported: false, reason: 'not_sqlite', detail: 'The file does not begin with the SQLite format 3 header',
      header: null, objects: [], limitations };
  }
  const rawPageSize = readUint(buffer, 16, 2, false);
  // 1 encodes 65536, the one page size that does not fit the 16-bit field.
  const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;
  const encodingCode = readUint(buffer, 56, 4, false);
  const encoding = SQLITE_ENCODINGS[encodingCode];
  if (!encoding) limitations.push('The text encoding field is not one of the three SQLite encodings');
  const header = {
    pageSize,
    pageSizeValid: pageSize === 65536 || (pageSize >= 512 && (pageSize & (pageSize - 1)) === 0),
    writeVersion: buffer[18] === 2 ? 'wal' : buffer[18] === 1 ? 'legacy' : 'unknown',
    readVersion: buffer[19] === 2 ? 'wal' : buffer[19] === 1 ? 'legacy' : 'unknown',
    reservedBytes: buffer[20],
    changeCounter: readUint(buffer, 24, 4, false),
    pageCount: readUint(buffer, 28, 4, false),
    freelistPages: readUint(buffer, 36, 4, false),
    schemaCookie: readUint(buffer, 40, 4, false),
    schemaFormat: readUint(buffer, 44, 4, false),
    textEncoding: encoding ? encoding.reported : null,
    userVersion: readUint(buffer, 60, 4, false),
    incrementalVacuum: readUint(buffer, 64, 4, false) !== 0,
    applicationId: readUint(buffer, 68, 4, false),
    sqliteVersionNumber: readUint(buffer, 96, 4, false),
  };
  if (!header.pageSizeValid) limitations.push('The declared page size is not a power of two of at least 512');
  // A truncated or sparse file is common for carved artifacts; say so rather than implying a count.
  const expectedBytes = header.pageCount * pageSize;
  if (header.pageSizeValid && expectedBytes > buffer.length) {
    limitations.push('The header declares more pages than the file contains, so the file is truncated or sparse');
  }
  const objects = header.pageSizeValid
    ? sqliteSchema(buffer, pageSize, encoding ? encoding.decoder : 'utf-8', limitations)
    : [];
  const counts = objects.reduce((totals, object) => {
    const key = object.type ?? 'unknown';
    totals[key] = (totals[key] ?? 0) + 1;
    return totals;
  }, {});
  return { supported: true, reason: null, header, objects, counts, limitations };
}

const MAX_PCAP_PACKETS = 10000;
const MAX_PCAPNG_BLOCKS = 4096;
const MAX_DECODED_PACKETS = 512;
const MAX_RESOURCE_ENTRIES = 4096;
const MAX_RESOURCE_DEPTH = 3;

// The four classic pcap magics. The stored byte order decides how every later field is read, so
// it is recovered from the magic rather than assumed, and the timestamp unit rides along with it.
const PCAP_MAGICS = [
  { bytes: [0xd4, 0xc3, 0xb2, 0xa1], littleEndian: true, subUnit: 'microseconds' },
  { bytes: [0xa1, 0xb2, 0xc3, 0xd4], littleEndian: false, subUnit: 'microseconds' },
  { bytes: [0x4d, 0x3c, 0xb2, 0xa1], littleEndian: true, subUnit: 'nanoseconds' },
  { bytes: [0xa1, 0xb2, 0x3c, 0x4d], littleEndian: false, subUnit: 'nanoseconds' },
];
const LINK_TYPES = {
  0: 'null', 1: 'ethernet', 6: 'ieee802', 8: 'slip', 9: 'ppp', 101: 'raw-ip',
  105: 'ieee802-11', 113: 'linux-sll', 127: 'ieee802-11-radiotap', 147: 'user0',
  228: 'ipv4', 229: 'ipv6', 276: 'linux-sll2',
};
const IP_PROTOCOLS = { 1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp', 41: 'ipv6', 47: 'gre', 50: 'esp', 58: 'icmpv6', 132: 'sctp' };
const TCP_FLAGS = [['fin', 0x01], ['syn', 0x02], ['rst', 0x04], ['psh', 0x08], ['ack', 0x10], ['urg', 0x20], ['ece', 0x40], ['cwr', 0x80]];

const RESOURCE_TYPES = {
  1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING', 7: 'FONTDIR',
  8: 'FONT', 9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR',
  14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE', 19: 'PLUGPLAY', 20: 'VXD',
  21: 'ANICURSOR', 22: 'ANIICON', 23: 'HTML', 24: 'MANIFEST',
};

const GO_BUILDINFO_MAGIC = [0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a];

/**
 * Classic pcap and block-level pcapng.
 *
 * A record whose declared capture length runs past the end of the file stops the sweep with a
 * stated limitation: continuing would mean reporting a packet count the file does not support.
 * Timestamps are kept as separate seconds and sub-second fields rather than combined into one
 * float, because the nanosecond variant does not survive that conversion exactly.
 */
function parsePcap(buffer) {
  const limitations = [];
  if (buffer.length >= 4 && magicMatch(buffer, 0, [0x0a, 0x0d, 0x0d, 0x0a])) {
    // pcapng: a sequence of typed blocks. Reported structurally; per-packet decoding of the
    // interface-description/enhanced-packet pairing is not attempted here.
    const little = magicMatch(buffer, 8, [0x4d, 0x3c, 0x2b, 0x1a]);
    const big = magicMatch(buffer, 8, [0x1a, 0x2b, 0x3c, 0x4d]);
    if (!little && !big) return { format: 'pcapng', supported: false, reason: 'byte_order_unknown',
      detail: 'The section header block carries no recognised byte-order magic', blocks: [], packets: [], limitations };
    const le = little;
    const blocks = [];
    let offset = 0;
    for (let i = 0; i < MAX_PCAPNG_BLOCKS && offset + 12 <= buffer.length; i++) {
      const type = readUint(buffer, offset, 4, le);
      const length = readUint(buffer, offset + 4, 4, le);
      if (length < 12 || length % 4 !== 0 || offset + length > buffer.length) {
        limitations.push('A block length is malformed or runs past the end of the file');
        break;
      }
      blocks.push({ type, typeHex: '0x' + type.toString(16).padStart(8, '0'), offset, length });
      offset += length;
    }
    const counts = blocks.reduce((totals, block) => { totals[block.typeHex] = (totals[block.typeHex] ?? 0) + 1; return totals; }, {});
    limitations.push('pcapng is reported at block level; per-packet fields are not decoded from it');
    return { format: 'pcapng', supported: true, reason: null, byteOrder: le ? 'little' : 'big',
      blocks, blockCounts: counts, packets: [], limitations };
  }

  const magic = PCAP_MAGICS.find((candidate) => magicMatch(buffer, 0, candidate.bytes));
  if (!magic) return { format: null, supported: false, reason: 'not_a_capture',
    detail: 'The file carries no pcap or pcapng magic', packets: [], limitations };
  if (buffer.length < 24) return { format: 'pcap', supported: false, reason: 'truncated_header',
    detail: 'The file is shorter than a pcap global header', packets: [], limitations };

  const le = magic.littleEndian;
  const linkType = readUint(buffer, 20, 4, le);
  const header = {
    byteOrder: le ? 'little' : 'big', timestampUnit: magic.subUnit,
    versionMajor: readUint(buffer, 4, 2, le), versionMinor: readUint(buffer, 6, 2, le),
    thisZone: readUint(buffer, 8, 4, le), sigFigs: readUint(buffer, 12, 4, le),
    snapLength: readUint(buffer, 16, 4, le),
    linkType, linkTypeName: LINK_TYPES[linkType] ?? null,
  };
  if (header.linkTypeName === null) limitations.push('The link type is not one this reader names');

  const packets = [];
  let offset = 24;
  let capturedBytes = 0;
  let originalBytes = 0;
  let sliced = 0;
  for (let i = 0; i < MAX_PCAP_PACKETS; i++) {
    if (offset === buffer.length) break;
    if (offset + 16 > buffer.length) { limitations.push('A trailing partial record header was not read'); break; }
    const includedLength = readUint(buffer, offset + 8, 4, le);
    const originalLength = readUint(buffer, offset + 12, 4, le);
    if (offset + 16 + includedLength > buffer.length) {
      limitations.push('A record declares more captured bytes than the file contains, so the sweep stopped');
      break;
    }
    packets.push({
      index: i, offset, dataOffset: offset + 16,
      timestampSeconds: readUint(buffer, offset, 4, le),
      timestampSub: readUint(buffer, offset + 4, 4, le),
      capturedLength: includedLength, originalLength,
      sliced: includedLength < originalLength,
    });
    capturedBytes += includedLength;
    originalBytes += originalLength;
    if (includedLength < originalLength) sliced += 1;
    offset += 16 + includedLength;
  }
  if (packets.length >= MAX_PCAP_PACKETS && offset < buffer.length) limitations.push('The packet bound was reached');
  const first = packets[0];
  const last = packets[packets.length - 1];
  return {
    format: 'pcap', supported: true, reason: null, header, packets,
    summary: {
      packetCount: packets.length, capturedBytes, originalBytes, slicedPackets: sliced,
      firstTimestamp: first ? { seconds: first.timestampSeconds, sub: first.timestampSub } : null,
      lastTimestamp: last ? { seconds: last.timestampSeconds, sub: last.timestampSub } : null,
    },
    limitations,
  };
}

const macAddress = (buffer, offset) => [...buffer.subarray(offset, offset + 6)].map((b) => b.toString(16).padStart(2, '0')).join(':');
const ipv4Address = (buffer, offset) => [...buffer.subarray(offset, offset + 4)].join('.');
const ipv6Address = (buffer, offset) => Array.from({ length: 8 }, (_, i) => readUint(buffer, offset + i * 2, 2, false).toString(16)).join(':');

/** Decode the layered headers of one captured frame. Each layer is attempted only if it fits. */
function decodeFrame(buffer, start, length, linkTypeName) {
  const end = start + length;
  const layers = [];
  let at = start;
  let etherType;
  if (linkTypeName === 'ethernet') {
    if (at + 14 > end) return { layers, truncated: true };
    etherType = readUint(buffer, at + 12, 2, false);
    layers.push({ layer: 'ethernet', destination: macAddress(buffer, at), source: macAddress(buffer, at + 6), etherType });
    at += 14;
    // One VLAN tag is unwrapped; stacked tags are reported rather than walked.
    if (etherType === 0x8100 && at + 4 <= end) {
      const tag = readUint(buffer, at, 2, false);
      etherType = readUint(buffer, at + 2, 2, false);
      layers.push({ layer: 'vlan', id: tag & 0x0fff, priority: tag >> 13, etherType });
      at += 4;
    }
  } else if (linkTypeName === 'raw-ip' || linkTypeName === 'ipv4' || linkTypeName === 'ipv6') {
    etherType = linkTypeName === 'ipv6' ? 0x86dd : 0x0800;
  } else {
    return { layers, unsupportedLink: true };
  }

  let protocol;
  if (etherType === 0x0800) {
    if (at + 20 > end) return { layers, truncated: true };
    const versionIhl = buffer[at];
    const headerWords = versionIhl & 0x0f;
    protocol = buffer[at + 9];
    layers.push({ layer: 'ipv4', version: versionIhl >> 4, headerBytes: headerWords * 4,
      totalLength: readUint(buffer, at + 2, 2, false), ttl: buffer[at + 8],
      protocol, protocolName: IP_PROTOCOLS[protocol] ?? null,
      source: ipv4Address(buffer, at + 12), destination: ipv4Address(buffer, at + 16) });
    if (headerWords < 5) return { layers, malformed: true };
    at += headerWords * 4;
  } else if (etherType === 0x86dd) {
    if (at + 40 > end) return { layers, truncated: true };
    protocol = buffer[at + 6];
    layers.push({ layer: 'ipv6', payloadLength: readUint(buffer, at + 4, 2, false),
      nextHeader: protocol, nextHeaderName: IP_PROTOCOLS[protocol] ?? null, hopLimit: buffer[at + 7],
      source: ipv6Address(buffer, at + 8), destination: ipv6Address(buffer, at + 24) });
    at += 40;
  } else if (etherType === 0x0806) {
    layers.push({ layer: 'arp' });
    return { layers };
  } else {
    return { layers, unsupportedEtherType: etherType };
  }

  if (protocol === 6) {
    if (at + 20 > end) return { layers, truncated: true };
    const flagBits = buffer[at + 13];
    layers.push({ layer: 'tcp', sourcePort: readUint(buffer, at, 2, false), destinationPort: readUint(buffer, at + 2, 2, false),
      sequence: readUint(buffer, at + 4, 4, false), acknowledgement: readUint(buffer, at + 8, 4, false),
      dataOffsetBytes: (buffer[at + 12] >> 4) * 4, window: readUint(buffer, at + 14, 2, false),
      flags: TCP_FLAGS.filter(([, bit]) => (flagBits & bit) !== 0).map(([name]) => name) });
  } else if (protocol === 17) {
    if (at + 8 > end) return { layers, truncated: true };
    layers.push({ layer: 'udp', sourcePort: readUint(buffer, at, 2, false), destinationPort: readUint(buffer, at + 2, 2, false),
      length: readUint(buffer, at + 4, 2, false) });
  }
  return { layers };
}

/** Walk the three-level PE resource tree: type, then name or id, then language. */
function peResourceTree(buffer, sections, baseRva, offset, depth, state, inheritedType) {
  if (depth > MAX_RESOURCE_DEPTH || state.entries.length >= MAX_RESOURCE_ENTRIES) return [];
  if (offset === undefined || offset + 16 > buffer.length) { state.limitations.push('A resource directory lies outside the file'); return []; }
  const namedCount = readUint(buffer, offset + 12, 2, true);
  const idCount = readUint(buffer, offset + 14, 2, true);
  const total = namedCount + idCount;
  const nodes = [];
  for (let i = 0; i < total; i++) {
    if (state.entries.length >= MAX_RESOURCE_ENTRIES) { state.limitations.push('The resource entry bound was reached'); break; }
    const entryAt = offset + 16 + i * 8;
    if (entryAt + 8 > buffer.length) { state.limitations.push('A resource entry lies outside the file'); break; }
    const nameField = readUint(buffer, entryAt, 4, true);
    const dataField = readUint(buffer, entryAt + 4, 4, true);
    const named = (nameField & 0x80000000) !== 0;
    let label = null;
    if (named) {
      // A named entry points at a UTF-16LE counted string, relative to the resource directory.
      const stringAt = peRvaToOffset(sections, baseRva + (nameField & 0x7fffffff));
      if (stringAt !== undefined && stringAt + 2 <= buffer.length) {
        const chars = readUint(buffer, stringAt, 2, true);
        const bytes = Math.min(chars * 2, MAX_NAME_CHARS * 2);
        if (stringAt + 2 + bytes <= buffer.length) {
          try { label = new TextDecoder('utf-16le', { fatal: true }).decode(buffer.subarray(stringAt + 2, stringAt + 2 + bytes)); }
          catch { label = null; }
        }
      }
      if (label === null) state.limitations.push('A resource name string could not be decoded');
    }
    const id = named ? null : nameField;
    const typeName = depth === 1 ? (id === null ? null : RESOURCE_TYPES[id] ?? null) : inheritedType;
    const node = { named, id, name: label, typeName: typeName ?? null };
    if ((dataField & 0x80000000) !== 0) {
      const childAt = peRvaToOffset(sections, baseRva + (dataField & 0x7fffffff));
      node.children = peResourceTree(buffer, sections, baseRva, childAt, depth + 1, state, typeName);
    } else {
      const leafAt = peRvaToOffset(sections, baseRva + dataField);
      if (leafAt === undefined || leafAt + 16 > buffer.length) { state.limitations.push('A resource data entry lies outside the file'); continue; }
      const dataRva = readUint(buffer, leafAt, 4, true);
      node.data = { rva: dataRva, bytes: readUint(buffer, leafAt + 4, 4, true), codePage: readUint(buffer, leafAt + 8, 4, true),
        fileOffset: peRvaToOffset(sections, dataRva) ?? null };
      state.entries.push(node);
    }
    nodes.push(node);
  }
  return nodes;
}

/** The PE resource directory, read through the data directory the optional header declares. */
function parsePeResources(buffer) {
  const limitations = [];
  const signatureOffset = readUint(buffer, 0x3c, 4, true);
  if (signatureOffset === undefined || !magicMatch(buffer, signatureOffset, [0x50, 0x45, 0x00, 0x00])) {
    return { supported: false, reason: 'not_pe', detail: 'The file carries no PE signature', resources: [], entryCount: 0, limitations };
  }
  const sizeOfOptionalHeader = readUint(buffer, signatureOffset + 20, 2, true);
  if (!sizeOfOptionalHeader) return { supported: false, reason: 'no_optional_header',
    detail: 'The file has no optional header, so it declares no data directories', resources: [], entryCount: 0, limitations };
  const optionalAt = signatureOffset + 24;
  const optionalMagic = readUint(buffer, optionalAt, 2, true);
  const directoriesAt = optionalAt + (optionalMagic === 0x20b ? 112 : 96);
  const directoryCount = readUint(buffer, optionalAt + (optionalMagic === 0x20b ? 108 : 92), 4, true);
  if (directoryCount === undefined || directoryCount < 3) {
    return { supported: true, reason: null, pe32Plus: optionalMagic === 0x20b, resources: [], entryCount: 0,
      limitations: ['The optional header declares no resource data directory'] };
  }
  const resourceRva = readUint(buffer, directoriesAt + 16, 4, true);
  const resourceSize = readUint(buffer, directoriesAt + 20, 4, true);
  if (!resourceRva || !resourceSize) {
    return { supported: true, reason: null, pe32Plus: optionalMagic === 0x20b, resources: [], entryCount: 0,
      limitations: ['The binary declares an empty resource directory'] };
  }
  const sections = peSections(buffer, optionalAt + sizeOfOptionalHeader, readUint(buffer, signatureOffset + 6, 2, true));
  const rootAt = peRvaToOffset(sections, resourceRva);
  if (rootAt === undefined) {
    return { supported: false, reason: 'unmapped_directory',
      detail: 'The resource directory address falls outside every section', resources: [], entryCount: 0, limitations };
  }
  const state = { entries: [], limitations };
  const resources = peResourceTree(buffer, sections, resourceRva, rootAt, 1, state, null);
  const byType = state.entries.reduce((totals, entry) => { totals[entry.typeName ?? 'unknown'] = (totals[entry.typeName ?? 'unknown'] ?? 0) + 1; return totals; }, {});
  return { supported: true, reason: null, pe32Plus: optionalMagic === 0x20b,
    directory: { rva: resourceRva, bytes: resourceSize },
    resources, entryCount: state.entries.length, byType, limitations };
}

/**
 * Go build information, from the `\xff Go buildinf:` blob the toolchain embeds.
 *
 * Two layouts exist. Since Go 1.18 the version and module data are stored inline as
 * varint-prefixed strings, which is readable from the bytes alone. The older layout stores
 * pointers into the data section; those are reported as present but unresolved rather than
 * dereferenced, because following them needs the section mapping the pointer was written for.
 */
function parseGoBuildInfo(buffer) {
  const limitations = [];
  let at = -1;
  for (let i = 0; i + GO_BUILDINFO_MAGIC.length <= buffer.length; i++) {
    if (magicMatch(buffer, i, GO_BUILDINFO_MAGIC)) { at = i; break; }
  }
  if (at < 0) return { supported: false, reason: 'no_build_info',
    detail: 'The file contains no Go build information blob', version: null, settings: [], limitations };
  if (at + 16 > buffer.length) return { supported: false, reason: 'truncated_build_info',
    detail: 'The build information blob is truncated', version: null, settings: [], limitations };

  const pointerSize = buffer[at + 14];
  const flags = buffer[at + 15];
  const inline = (flags & 0x02) !== 0;
  const result = { supported: true, reason: null, offset: at, pointerSize,
    endianness: (flags & 0x01) !== 0 ? 'big' : 'little', layout: inline ? 'inline' : 'pointer',
    version: null, moduleInfo: null, settings: [], limitations };
  if (!inline) {
    limitations.push('This binary uses the pointer layout, whose strings live in the data section and are not dereferenced here');
    return result;
  }
  // Inline layout: counted strings begin at blob + 32.
  let cursor = at + 32;
  const readString = () => {
    const length = readLeb(buffer, cursor);
    if (!length) return null;
    const end = length.offset + length.value;
    if (end > buffer.length || length.value > 64 * 1024) return null;
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(length.offset, end)); }
    catch { return null; }
    cursor = end;
    return text;
  };
  result.version = readString();
  if (result.version === null) { limitations.push('The embedded version string could not be read'); return result; }
  const moduleInfo = readString();
  if (moduleInfo === null) { limitations.push('The embedded module information could not be read'); return result; }
  result.moduleInfo = moduleInfo.length;
  // Build settings are tab-separated key/value lines inside the module blob.
  for (const line of moduleInfo.split('\n')) {
    const parts = line.split('\t');
    if (parts[0] === 'build' && parts.length >= 2) {
      const equals = parts[1].indexOf('=');
      if (equals > 0) result.settings.push({ key: parts[1].slice(0, equals), value: parts[1].slice(equals + 1, equals + 1 + 512) });
    } else if ((parts[0] === 'mod' || parts[0] === 'dep') && parts.length >= 3) {
      result.settings.push({ key: parts[0], value: parts[1] + ' ' + parts[2] });
    }
  }
  return result;
}

/** Pure identification/inspection of acquired local bytes. Never executes, never trusts, content. */
export function makeArtifactTools() {
  return [
    { name: 'artifact.inspect', version: '1.0.0', outputKeys: ['bytes', 'format', 'path', 'sha256', 'untrusted'], effect: 'read', inputSchema: object({ path: string }),
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
    { name: 'artifact.wasmInterface', version: '1.0.0', outputKeys: ['state', 'entries', 'counts', 'limitations', 'path', 'sha256'], effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, limit);
        const format = identifyFormat(bytes);
        // Reported rather than thrown: "this is not a WASM module" is an answer about the bytes.
        if (format !== 'wasm') {
          return { path: relative, sha256: sha256(bytes), format, state: 'partial', entries: [],
            counts: { imports: 0, exports: 0, unresolved: 0 },
            limitations: ['The file is not a WASM module, so it declares no WASM interface'], untrusted: true };
        }
        return { path: relative, sha256: sha256(bytes), format, ...parseWasmInterface(bytes), untrusted: true };
      } },
    { name: 'artifact.pcap', version: '1.0.0', outputKeys: ['path', 'sha256', 'format', 'supported', 'packets', 'limitations', 'untrusted'], effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, limit);
        return { path: relative, sha256: sha256(bytes), ...parsePcap(bytes), untrusted: true };
      } },
    { name: 'artifact.packetFields', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'frames', 'decoded', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, offset: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 1, maximum: MAX_DECODED_PACKETS } }, ['path']),
      execute({ path: relative, offset = 0, limit: want = 64 }, context) {
        const cap = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, cap);
        const capture = parsePcap(bytes);
        if (!capture.supported || capture.format !== 'pcap') {
          return { path: relative, sha256: sha256(bytes), format: capture.format, supported: false,
            reason: capture.reason ?? 'fields_unavailable',
            detail: capture.detail ?? 'Per-packet fields are decoded from classic pcap only',
            frames: [], decoded: 0, limitations: capture.limitations, untrusted: true };
        }
        const linkTypeName = capture.header.linkTypeName;
        const selected = capture.packets.slice(offset, offset + want);
        const frames = selected.map((packet) => ({
          index: packet.index, sliced: packet.sliced,
          capturedLength: packet.capturedLength, originalLength: packet.originalLength,
          ...decodeFrame(bytes, packet.dataOffset, packet.capturedLength, linkTypeName),
        }));
        const limitations = [...capture.limitations];
        if (frames.some((frame) => frame.unsupportedLink)) limitations.push('The link type is not one this reader decodes, so no frame layers were read');
        if (frames.some((frame) => frame.sliced)) limitations.push('A sliced packet carries fewer bytes than the wire frame, so later layers may be absent');
        return { path: relative, sha256: sha256(bytes), format: 'pcap', supported: true, reason: null,
          linkTypeName, packetCount: capture.packets.length, offset, frames, decoded: frames.length,
          limitations, untrusted: true };
      } },
    { name: 'artifact.peResources', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'resources', 'entryCount', 'limitations', 'untrusted'], effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, limit);
        return { path: relative, sha256: sha256(bytes), ...parsePeResources(bytes), untrusted: true };
      } },
    { name: 'artifact.goBuildInfo', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'version', 'settings', 'limitations', 'untrusted'], effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, limit);
        return { path: relative, sha256: sha256(bytes), ...parseGoBuildInfo(bytes), untrusted: true };
      } },
    { name: 'artifact.sqlite', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'header', 'objects', 'limitations', 'untrusted'], effect: 'read', inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, limit);
        return { path: relative, sha256: sha256(bytes), ...parseSqlite(bytes), untrusted: true };
      } },
    { name: 'artifact.evmInterface', version: '1.0.0', outputKeys: ['carrierSha256', 'bytecodeSha256', 'bytecodeBytes', 'encoding', 'supported', 'selectorCandidates', 'opcodes', 'metadata', 'limitations'], effect: 'read',
      inputSchema: object({ path: string, encoding: { enum: ['raw', 'hex'] } }, ['path', 'encoding']),
      execute({ path: relative, encoding }, context) {
        const limit = Math.floor(context.policy.maxOutputBytes / 8);
        const carrier = readWorkspaceFile(context.workspaceRoot, relative, limit);
        // Two digests, never conflated: the carrier identifies the exact file including its hex
        // casing and whitespace; the decoded digest identifies the bytes actually analysed.
        // Neither is Ethereum's Keccak code hash.
        const base = { path: relative, encoding, carrierSha256: sha256(carrier), untrusted: true };
        const decoded = encoding === 'hex' ? decodeEvmHex(carrier) : { value: carrier };
        if (decoded.error) {
          return { ...base, bytecodeSha256: null, bytecodeBytes: 0, supported: false, reason: 'carrier_invalid',
            detail: decoded.error, selectorCandidates: [], opcodes: null, metadata: null, limitations: [] };
        }
        if (decoded.value.length > MAX_EVM_BYTES) {
          return { ...base, bytecodeSha256: sha256(decoded.value), bytecodeBytes: decoded.value.length, supported: false,
            reason: 'resource_constraint', detail: 'The decoded bytecode exceeds the analysis bound',
            selectorCandidates: [], opcodes: null, metadata: null, limitations: [] };
        }
        return { ...base, bytecodeSha256: sha256(decoded.value), bytecodeBytes: decoded.value.length, ...parseEvmBytecode(decoded.value) };
      } },
    { name: 'artifact.compareWasmInterfaces', version: '1.0.0', outputKeys: ['select', 'changes', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({ left: INTERFACE_SCHEMA, right: INTERFACE_SCHEMA, select: { enum: ['imports', 'exports', 'both'] } }, ['left', 'right']),
      execute({ left, right, select = 'both' }) {
        return compareInterfaces(left, right, select);
      } },
  ];
}
