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
// here is executed, parsed beyond its fixed header, or trusted as anything but data.
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
        return result;
      } },
  ];
}
