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
  };
}

function parsePe(buffer) {
  const signatureOffset = readUint(buffer, 0x3c, 4, true);
  if (signatureOffset === undefined || !magicMatch(buffer, signatureOffset, [0x50, 0x45, 0x00, 0x00])) return undefined;
  const sizeOfOptionalHeader = readUint(buffer, signatureOffset + 20, 2, true);
  return {
    machine: readUint(buffer, signatureOffset + 4, 2, true),
    sectionCount: readUint(buffer, signatureOffset + 6, 2, true),
    timestamp: readUint(buffer, signatureOffset + 8, 4, true),
    entryPoint: sizeOfOptionalHeader ? readUint(buffer, signatureOffset + 40, 4, true) : undefined,
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
