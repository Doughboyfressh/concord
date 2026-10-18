import { createHash } from 'node:crypto';
import { readWorkspaceFile } from './workspace-fs.mjs';
import { parseZipCentralDirectory } from './dex.mjs';

/**
 * Platform artifacts: firmware images, Rust binaries, Dart and Flutter builds, Electron fuses,
 * Apple property lists and HarmonyOS packages.
 *
 * REA reaches these through its firmware and platform providers. Each format below is read from
 * the bytes: a magic table for firmware, embedded toolchain strings for Rust, documented headers
 * for Dart snapshots and Electron fuses, and the real binary property list layout for Apple.
 *
 * Where a conclusion rests on a string rather than a structure, the tool says so, because a
 * string can be present for reasons other than the one being inferred.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const MAX_LISTED = 2000;
const MAX_REGION_PREVIEW = 512;
const MAX_STRING_HITS = 500;
const MAX_PLIST_OBJECTS = 100000;
const MAX_PLIST_DEPTH = 32;

const u8 = (b, o) => (o < 0 || o >= b.length ? undefined : b[o]);

// Firmware container and payload signatures. Offset-anchored where the format requires it.
const FIRMWARE_MAGICS = [
  ['squashfs-le', [0x68, 0x73, 0x71, 0x73], 'SquashFS filesystem, little-endian'],
  ['squashfs-be', [0x73, 0x71, 0x73, 0x68], 'SquashFS filesystem, big-endian'],
  ['cramfs', [0x45, 0x3d, 0xcd, 0x28], 'CramFS filesystem'],
  ['jffs2', [0x85, 0x19], 'JFFS2 node'],
  ['ubi', [0x55, 0x42, 0x49, 0x23], 'UBI volume'],
  ['ubifs', [0x31, 0x18, 0x10, 0x06], 'UBIFS superblock'],
  ['romfs', [0x2d, 0x72, 0x6f, 0x6d, 0x31, 0x66, 0x73, 0x2d], 'romfs filesystem'],
  ['ext-superblock', [0x53, 0xef], 'ext2/3/4 superblock magic'],
  ['uimage', [0x27, 0x05, 0x19, 0x56], 'U-Boot legacy image header'],
  ['device-tree', [0xd0, 0x0d, 0xfe, 0xed], 'Flattened device tree blob'],
  ['android-boot', [0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21], 'Android boot image'],
  ['gzip', [0x1f, 0x8b, 0x08], 'gzip stream'],
  ['xz', [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], 'xz stream'],
  ['bzip2', [0x42, 0x5a, 0x68], 'bzip2 stream'],
  ['lz4', [0x04, 0x22, 0x4d, 0x18], 'LZ4 frame'],
  ['zstd', [0x28, 0xb5, 0x2f, 0xfd], 'Zstandard frame'],
  ['lzop', [0x89, 0x4c, 0x5a, 0x4f], 'lzop stream'],
  ['zip', [0x50, 0x4b, 0x03, 0x04], 'ZIP archive'],
  ['cpio-newc', [0x30, 0x37, 0x30, 0x37, 0x30, 0x31], 'cpio newc archive'],
  ['tar-ustar', [0x75, 0x73, 0x74, 0x61, 0x72], 'tar ustar header'],
  ['elf', [0x7f, 0x45, 0x4c, 0x46], 'ELF image'],
  ['efi-capsule', [0xbd, 0x86, 0x66, 0x3b], 'EFI capsule header'],
  ['dmg-koly', [0x6b, 0x6f, 0x6c, 0x79], 'Apple DMG trailer'],
];
// A two-byte magic is common enough in arbitrary data to be noise, so it is only trusted where
// the format pins it to a fixed offset.
const ANCHORED = new Map([['ext-superblock', 0x438], ['tar-ustar', 257]]);

const ELECTRON_SENTINEL = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX';
// Fuse order is part of the wire format: position is the only thing that identifies a fuse.
const ELECTRON_FUSES = [
  ['runAsNode', 'honours ELECTRON_RUN_AS_NODE, which turns the app into a Node process'],
  ['enableCookieEncryption', 'encrypts the cookie store on disk'],
  ['enableNodeOptionsEnvironmentVariable', 'honours NODE_OPTIONS'],
  ['enableNodeCliInspectArguments', 'honours --inspect and friends'],
  ['enableEmbeddedAsarIntegrityValidation', 'validates the asar archive against an embedded hash'],
  ['onlyLoadAppFromAsar', 'refuses to load app code from anywhere but the asar'],
  ['loadBrowserProcessSpecificV8Snapshot', 'loads a separate V8 snapshot for the browser process'],
  ['grantFileProtocolExtraPrivileges', 'gives file:// pages extra privileges'],
];
const FUSE_STATES = { 0x30: 'disabled', 0x31: 'enabled', 0x32: 'removed' };

const readBytes = (context, relative, divisor = 4) =>
  readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / divisor));

const listed = (items, limitations, label) => {
  if (items.length <= MAX_LISTED) return items;
  limitations.push(`Only the first ${MAX_LISTED} ${label} are listed`);
  return items.slice(0, MAX_LISTED);
};

const matchAt = (buffer, offset, bytes) => {
  if (offset + bytes.length > buffer.length) return false;
  for (let i = 0; i < bytes.length; i++) if (buffer[offset + i] !== bytes[i]) return false;
  return true;
};

/** Printable ASCII runs, which is how an embedded toolchain string is found. */
function asciiStrings(buffer, minimum, limit) {
  const found = [];
  let start = -1;
  for (let i = 0; i <= buffer.length; i++) {
    const byte = i < buffer.length ? buffer[i] : 0;
    const printable = byte >= 0x20 && byte < 0x7f;
    if (printable) { if (start < 0) start = i; continue; }
    if (start >= 0 && i - start >= minimum) {
      found.push({ offset: start, text: buffer.toString('latin1', start, i) });
      if (found.length >= limit) return found;
    }
    start = -1;
  }
  return found;
}

/** Scan a firmware image for container and payload signatures. */
export function parseFirmware(buffer) {
  const limitations = [];
  const regions = [];
  for (const [name, bytes, meaning] of FIRMWARE_MAGICS) {
    const anchor = ANCHORED.get(name);
    if (anchor !== undefined) {
      if (matchAt(buffer, anchor, bytes)) regions.push({ kind: name, meaning, offset: anchor, anchored: true });
      continue;
    }
    for (let i = 0; i + bytes.length <= buffer.length; i++) {
      if (!matchAt(buffer, i, bytes)) continue;
      regions.push({ kind: name, meaning, offset: i, anchored: false });
      if (regions.length >= MAX_LISTED) { limitations.push('The region bound was reached'); break; }
    }
    if (regions.length >= MAX_LISTED) break;
  }
  regions.sort((a, b) => a.offset - b.offset || (a.kind < b.kind ? -1 : 1));
  // A region's length is the distance to the next signature, which is an upper bound rather than
  // the real payload length: only a format-specific parse could give that.
  for (let i = 0; i < regions.length; i++) {
    regions[i].boundedLength = (i + 1 < regions.length ? regions[i + 1].offset : buffer.length) - regions[i].offset;
  }
  const counts = regions.reduce((totals, region) => { totals[region.kind] = (totals[region.kind] ?? 0) + 1; return totals; }, {});
  limitations.push('A signature match is evidence of a format, not proof: these byte sequences also occur inside compressed data');
  limitations.push('Region lengths are the distance to the next signature, which is an upper bound rather than a decoded payload length');
  return { supported: true, reason: null, bytes: buffer.length, regions, counts, limitations };
}

/** rustc and cargo leave identifying paths and symbol manglings behind. */
export function parseRustBinary(buffer) {
  const limitations = [];
  const strings = asciiStrings(buffer, 8, 200000);
  const versions = new Set();
  const commits = new Set();
  const registries = new Set();
  const panics = [];
  let legacyMangled = 0;
  let v0Mangled = 0;
  for (const { offset, text } of strings) {
    const version = /rustc-(\d+\.\d+\.\d+)/.exec(text);
    if (version) versions.add(version[1]);
    const commit = /\/rustc\/([0-9a-f]{40})\//.exec(text);
    if (commit) commits.add(commit[1]);
    if (text.includes('/.cargo/registry/')) {
      const crate = /registry\/src\/[^/]+\/([^/]+)\//.exec(text);
      if (crate) registries.add(crate[1]);
    }
    // A panic location is a source path and line the compiler embedded.
    const panic = /((?:\/rustc\/[0-9a-f]+\/library|src|\.cargo[^\s]*)\/[A-Za-z0-9_./-]+\.rs)/.exec(text);
    if (panic && panics.length < MAX_STRING_HITS) panics.push({ offset, path: panic[1] });
    if (/_ZN[0-9]+.*17h[0-9a-f]{16}E/.test(text)) legacyMangled += 1;
    if (/_R[NIC][a-zA-Z0-9_]{6,}/.test(text)) v0Mangled += 1;
  }
  const rust = versions.size > 0 || commits.size > 0 || registries.size > 0 || legacyMangled > 0 || v0Mangled > 0;
  if (!rust) {
    return { supported: false, reason: 'no_rust_evidence',
      detail: 'No rustc path, cargo registry path or Rust symbol mangling was found', limitations };
  }
  limitations.push('Every conclusion here rests on an embedded string or a symbol shape, so a stripped binary can be Rust and show none of it');
  if (legacyMangled && v0Mangled) limitations.push('Both mangling schemes are present, which happens when a dependency was built by a different toolchain');
  return { supported: true, reason: null,
    rustcVersions: [...versions].sort(), rustcCommits: [...commits].sort(),
    cargoCrates: [...registries].sort().slice(0, MAX_LISTED),
    mangling: { legacy: legacyMangled, v0: v0Mangled,
      scheme: v0Mangled > legacyMangled ? 'v0' : legacyMangled ? 'legacy' : 'unknown' },
    panicPaths: listed([...new Map(panics.map((entry) => [entry.path, entry])).values()], limitations, 'panic paths'),
    limitations };
}

/** A Dart VM or AOT snapshot header. */
export function parseDartSnapshot(buffer) {
  const limitations = [];
  // The magic is a 32-bit value, so it appears in either byte order depending on the writer.
  const little = matchAt(buffer, 0, [0xdc, 0xdc, 0xf5, 0xf5]);
  const big = matchAt(buffer, 0, [0xf5, 0xf5, 0xdc, 0xdc]);
  let offset = little || big ? 0 : -1;
  if (offset < 0) {
    // An AOT snapshot is often embedded in an ELF or Mach-O rather than standing alone.
    for (let i = 0; i + 4 <= buffer.length && i < 1 << 22; i++) {
      if (matchAt(buffer, i, [0xdc, 0xdc, 0xf5, 0xf5]) || matchAt(buffer, i, [0xf5, 0xf5, 0xdc, 0xdc])) { offset = i; break; }
    }
  }
  if (offset < 0) {
    return { supported: false, reason: 'no_snapshot_magic', detail: 'No Dart snapshot magic was found', limitations };
  }
  const embedded = offset > 0;
  if (embedded) limitations.push('The snapshot magic was found at a nonzero offset, so it is embedded in a host image rather than standing alone');
  const littleEndian = matchAt(buffer, offset, [0xdc, 0xdc, 0xf5, 0xf5]);
  // After the magic come a length and a version hash, then a features string.
  const versionStart = offset + 12;
  const version = buffer.toString('latin1', versionStart, Math.min(versionStart + 32, buffer.length)).replace(/[^0-9a-f].*$/, '');
  const featuresStart = versionStart + 32;
  let featuresEnd = featuresStart;
  while (featuresEnd < buffer.length && buffer[featuresEnd] !== 0 && featuresEnd - featuresStart < 4096) featuresEnd += 1;
  const features = buffer.toString('latin1', featuresStart, featuresEnd);
  const mode = /product/.test(features) ? 'release' : /profile/.test(features) ? 'profile' : /debug/.test(features) ? 'debug' : null;
  const architecture = /\b(x64|arm64|arm|ia32|riscv64)\b/.exec(features);
  if (!/^[0-9a-f]{32}$/.test(version)) limitations.push('The version field is not a 32-character hash, so this may be a different snapshot revision than this reader expects');
  return { supported: true, reason: null, offset, embedded, byteOrder: littleEndian ? 'little' : 'big',
    versionHash: /^[0-9a-f]{32}$/.test(version) ? version : null,
    features: features.length ? features : null,
    buildMode: mode, architecture: architecture ? architecture[1] : null,
    nullSafety: /no-null-safety/.test(features) ? false : /null-safety/.test(features) ? true : null,
    limitations };
}

/** Flutter engine and Dart evidence, from the strings a Flutter build embeds. */
export function parseFlutterBuild(buffer) {
  const limitations = [];
  const strings = asciiStrings(buffer, 6, 200000);
  const engineRevisions = new Set();
  const dartVersions = new Set();
  const markers = new Set();
  for (const { text } of strings) {
    if (/\bflutter\b/i.test(text)) markers.add('flutter-string');
    if (/libflutter\.so|Flutter\.framework|flutter_engine|FlutterEngine/.test(text)) markers.add('engine-reference');
    if (/kDartVmSnapshotData|kDartIsolateSnapshotData|_kDartVmSnapshot/.test(text)) markers.add('snapshot-symbol');
    if (/\bDart_[A-Z][A-Za-z]+/.test(text)) markers.add('dart-api-symbol');
    const engine = /flutter[\/\\]engine[\/\\]src[\/\\]?.*?([0-9a-f]{40})/.exec(text) ?? /engine_revision[^0-9a-f]{0,4}([0-9a-f]{40})/.exec(text);
    if (engine) engineRevisions.add(engine[1]);
    const dart = /Dart(?:\s+VM)?\s+version:?\s*(\d+\.\d+\.\d+)/.exec(text) ?? /\bdart-sdk\/(\d+\.\d+\.\d+)/.exec(text);
    if (dart) dartVersions.add(dart[1]);
  }
  const snapshot = parseDartSnapshot(buffer);
  if (!markers.size && !snapshot.supported) {
    return { supported: false, reason: 'no_flutter_evidence',
      detail: 'No Flutter engine reference, Dart symbol or snapshot magic was found', markers: [], limitations };
  }
  limitations.push('Flutter identification rests on embedded strings and an optional snapshot header, so a stripped or renamed build can show less than it uses');
  return { supported: true, reason: null,
    markers: [...markers].sort(),
    engineRevisions: [...engineRevisions].sort(),
    dartVersions: [...dartVersions].sort(),
    snapshot: snapshot.supported
      ? { offset: snapshot.offset, embedded: snapshot.embedded, versionHash: snapshot.versionHash,
          buildMode: snapshot.buildMode, architecture: snapshot.architecture, nullSafety: snapshot.nullSafety }
      : null,
    buildMode: snapshot.supported ? snapshot.buildMode : null,
    limitations };
}

/** The Electron fuse wire, which is a sentinel followed by one state byte per fuse. */
export function parseElectronFuses(buffer) {
  const limitations = [];
  const sentinel = Buffer.from(ELECTRON_SENTINEL, 'latin1');
  const at = buffer.indexOf(sentinel);
  if (at < 0) {
    return { supported: false, reason: 'no_fuse_wire',
      detail: 'The Electron fuse sentinel was not found, so this binary carries no fuse wire', fuses: [], limitations };
  }
  const versionAt = at + sentinel.length;
  const version = u8(buffer, versionAt);
  const count = u8(buffer, versionAt + 1);
  if (version === undefined || count === undefined) {
    return { supported: false, reason: 'fuse_wire_truncated', detail: 'The fuse wire ends before its length byte', fuses: [], limitations };
  }
  if (count > 64) limitations.push('The fuse wire declares an implausible length, so only the known fuses are reported');
  const fuses = [];
  for (let i = 0; i < Math.min(count, 64); i++) {
    const byte = u8(buffer, versionAt + 2 + i);
    if (byte === undefined) { limitations.push('The fuse wire is shorter than its declared length'); break; }
    const known = ELECTRON_FUSES[i];
    const state = FUSE_STATES[byte] ?? null;
    if (state === null) limitations.push('A fuse byte is not one of the three documented states');
    fuses.push({ index: i, name: known ? known[0] : null, meaning: known ? known[1] : null, state,
      // A fuse beyond the published list exists in the wire but this reader cannot name it.
      recognised: Boolean(known) });
  }
  const byName = Object.fromEntries(fuses.filter((fuse) => fuse.name).map((fuse) => [fuse.name, fuse.state]));
  limitations.push('A fuse state is what the wire declares; whether the running process honours it depends on the Electron build reading it');
  return { supported: true, reason: null, offset: at, wireVersion: version, declaredCount: count,
    fuses, byName,
    // The two that most change what an attacker can do with the binary.
    runAsNodeEnabled: byName.runAsNode === 'enabled',
    asarIntegrityEnforced: byName.enableEmbeddedAsarIntegrityValidation === 'enabled' && byName.onlyLoadAppFromAsar === 'enabled',
    limitations };
}

/** Apple binary property list, plus the XML form. */
export function parsePlist(buffer) {
  const limitations = [];
  if (buffer.length >= 8 && buffer.toString('latin1', 0, 6) === 'bplist') {
    const version = buffer.toString('latin1', 6, 8);
    if (buffer.length < 40) return { supported: false, reason: 'plist_truncated', detail: 'The file is shorter than a binary plist trailer', limitations };
    const trailer = buffer.length - 32;
    const offsetSize = u8(buffer, trailer + 6);
    const refSize = u8(buffer, trailer + 7);
    const count = Number(buffer.readBigUInt64BE(trailer + 8));
    const topObject = Number(buffer.readBigUInt64BE(trailer + 16));
    const tableOffset = Number(buffer.readBigUInt64BE(trailer + 24));
    if (!offsetSize || !refSize || count > MAX_PLIST_OBJECTS || tableOffset + count * offsetSize > buffer.length) {
      return { supported: false, reason: 'plist_malformed', detail: 'The binary plist trailer does not describe this file', limitations };
    }
    const offsets = [];
    for (let i = 0; i < count; i++) {
      let value = 0;
      for (let b = 0; b < offsetSize; b++) value = value * 256 + buffer[tableOffset + i * offsetSize + b];
      offsets.push(value);
    }
    const readRef = (at) => { let value = 0; for (let b = 0; b < refSize; b++) value = value * 256 + buffer[at + b]; return value; };
    const readLength = (at, low) => (low === 0x0f
      ? (() => { const marker = u8(buffer, at + 1); const bytes = 1 << (marker & 0x0f); let value = 0; for (let b = 0; b < bytes; b++) value = value * 256 + buffer[at + 2 + b]; return { value, next: at + 2 + bytes }; })()
      : { value: low, next: at + 1 });
    const seen = new Set();
    const readObject = (index, depth) => {
      if (depth > MAX_PLIST_DEPTH || index >= offsets.length) return null;
      const key = index + ':' + depth;
      if (seen.has(key)) return null;
      seen.add(key);
      const at = offsets[index];
      const marker = u8(buffer, at);
      if (marker === undefined) return null;
      const high = marker >> 4;
      const low = marker & 0x0f;
      if (marker === 0x00) return null;
      if (marker === 0x08) return false;
      if (marker === 0x09) return true;
      if (high === 0x1) { // integer, 2^low bytes, big-endian
        const bytes = 1 << low;
        let value = 0n;
        for (let b = 0; b < bytes && at + 1 + b < buffer.length; b++) value = (value << 8n) | BigInt(buffer[at + 1 + b]);
        // A 16-byte integer and anything past the safe range are reported as text rather than
        // silently losing precision.
        return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
      }
      if (high === 0x2) { const bytes = 1 << low; return bytes === 4 ? buffer.readFloatBE(at + 1) : bytes === 8 ? buffer.readDoubleBE(at + 1) : null; }
      if (high === 0x3) return { appleEpochSeconds: buffer.readDoubleBE(at + 1) };
      if (high === 0x4) { const { value, next } = readLength(at, low); return { dataBytes: value, sha256: sha256(buffer.subarray(next, Math.min(next + value, buffer.length))) }; }
      if (high === 0x5) { const { value, next } = readLength(at, low); return buffer.toString('latin1', next, Math.min(next + value, buffer.length)); }
      if (high === 0x6) {
        // A UTF-16BE string: copied before swapping, because swap16 mutates in place and the
        // buffer is the caller's file contents.
        const { value, next } = readLength(at, low);
        return Buffer.from(buffer.subarray(next, Math.min(next + value * 2, buffer.length))).swap16().toString('utf16le');
      }
      if (high === 0xa || high === 0xc) {
        const { value, next } = readLength(at, low);
        const items = [];
        for (let i = 0; i < value; i++) items.push(readObject(readRef(next + i * refSize), depth + 1));
        return items;
      }
      if (high === 0xd) {
        const { value, next } = readLength(at, low);
        const result = {};
        for (let i = 0; i < value; i++) {
          const keyName = readObject(readRef(next + i * refSize), depth + 1);
          const valueAt = readObject(readRef(next + value * refSize + i * refSize), depth + 1);
          if (typeof keyName === 'string') result[keyName] = valueAt;
        }
        return result;
      }
      limitations.push('A binary plist object used a marker this reader does not decode');
      return null;
    };
    const root = readObject(topObject, 0);
    return { supported: true, reason: null, format: 'binary', version, objectCount: count, root, limitations };
  }

  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buffer); }
  catch { return { supported: false, reason: 'not_a_plist', detail: 'The file is neither a binary plist nor UTF-8 text', limitations }; }
  if (!/<plist\b/.test(text)) {
    return { supported: false, reason: 'not_a_plist', detail: 'The text declares no plist element', limitations };
  }
  // XML plists are read as a flat key/value listing of the top-level dictionary: nested
  // structure is reported as present rather than reconstructed, which a full XML parse would need.
  const root = {};
  // Explicit alternatives rather than one pattern with an optional body: a lazy body followed by
  // an optional closing tag matches a single character, which silently truncates every value.
  const pattern = /<key>([^<]*)<\/key>\s*(?:<(true|false)\s*\/>|<(array|dict)\s*\/>|<(string|integer|real|date|data)>([\s\S]*?)<\/\4>|<(array|dict)>)/g;
  let match;
  let count = 0;
  while ((match = pattern.exec(text)) !== null && count < MAX_LISTED) {
    const key = match[1];
    count += 1;
    if (match[2]) { root[key] = match[2] === 'true'; continue; }
    if (match[3]) { root[key] = { nested: match[3], empty: true }; continue; }
    if (match[6]) { root[key] = { nested: match[6] }; continue; }
    const type = match[4];
    const value = (match[5] ?? '').trim();
    root[key] = type === 'integer' || type === 'real' ? Number(value) : value;
  }
  limitations.push('An XML plist is read as a flat listing of its top-level keys; nested containers are reported as present rather than expanded');
  return { supported: true, reason: null, format: 'xml', version: null, objectCount: count, root, limitations };
}

/** Platform readers. */
export function makePlatformTools() {
  const pathOnly = object({ path: string });
  const base = (relative, bytes) => ({ path: relative, sha256: sha256(bytes), untrusted: true });

  return [
    { name: 'artifact.firmware', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'regions', 'counts', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 8);
        const scan = parseFirmware(bytes);
        const limitations = [...scan.limitations];
        return { ...base(relative, bytes), supported: true, reason: null, bytes: scan.bytes,
          regions: listed(scan.regions, limitations, 'regions'), counts: scan.counts, limitations };
      } },
    { name: 'artifact.firmwareRegion', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'region', 'preview', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, offset: { type: 'integer', minimum: 0 }, length: { type: 'integer', minimum: 1, maximum: 16 * 1024 * 1024 } }, ['path', 'offset']),
      execute({ path: relative, offset, length }, context) {
        const bytes = readBytes(context, relative, 2);
        if (offset >= bytes.length) {
          return { ...base(relative, bytes), supported: false, reason: 'offset_past_end',
            detail: 'The requested offset lies past the end of the file', region: null, preview: null, limitations: [] };
        }
        const limitations = [];
        const end = Math.min(bytes.length, offset + (length ?? bytes.length - offset));
        const slice = bytes.subarray(offset, end);
        if (length !== undefined && offset + length > bytes.length) limitations.push('The requested length ran past the end of the file, so a shorter region is reported');
        const identified = FIRMWARE_MAGICS.find(([, magic]) => matchAt(slice, 0, magic));
        // The region is identified and digested rather than written anywhere: extraction to disk
        // would be a write effect, and this tool holds a read grant only.
        limitations.push('The region is reported and digested, never written: this tool reads and does not extract to disk');
        return { ...base(relative, bytes), supported: true, reason: null,
          region: { offset, length: slice.length, sha256: sha256(slice),
            kind: identified ? identified[0] : null, meaning: identified ? identified[2] : null },
          preview: slice.subarray(0, MAX_REGION_PREVIEW).toString('hex'), limitations };
      } },
    { name: 'artifact.rustBinary', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'rustcVersions', 'mangling', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 4);
        const read = parseRustBinary(bytes);
        if (!read.supported) return { ...base(relative, bytes), supported: false, reason: read.reason, detail: read.detail, rustcVersions: [], mangling: null, limitations: read.limitations };
        return { ...base(relative, bytes), ...read };
      } },
    { name: 'artifact.dartSnapshot', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'versionHash', 'buildMode', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 4);
        const read = parseDartSnapshot(bytes);
        if (!read.supported) return { ...base(relative, bytes), supported: false, reason: read.reason, detail: read.detail, versionHash: null, buildMode: null, limitations: read.limitations };
        return { ...base(relative, bytes), ...read };
      } },
    { name: 'artifact.flutterBuild', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'markers', 'buildMode', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 4);
        const read = parseFlutterBuild(bytes);
        if (!read.supported) return { ...base(relative, bytes), supported: false, reason: read.reason, detail: read.detail, markers: [], buildMode: null, limitations: read.limitations };
        return { ...base(relative, bytes), ...read };
      } },
    { name: 'artifact.electronFuses', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'fuses', 'byName', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 4);
        const read = parseElectronFuses(bytes);
        if (!read.supported) return { ...base(relative, bytes), supported: false, reason: read.reason, detail: read.detail, fuses: [], byName: {}, limitations: read.limitations };
        return { ...base(relative, bytes), ...read };
      } },
    { name: 'artifact.plist', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'format', 'root', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 4);
        const read = parsePlist(bytes);
        if (!read.supported) return { ...base(relative, bytes), supported: false, reason: read.reason, detail: read.detail, format: null, root: null, limitations: read.limitations };
        return { ...base(relative, bytes), ...read };
      } },
    { name: 'artifact.appleGraph', version: '1.0.0', outputKeys: ['supported', 'bundle', 'edges', 'limitations'], effect: 'read',
      inputSchema: object({ plist: string, binary: string }, ['plist']),
      execute({ plist: plistPath, binary }, context) {
        const limitations = [];
        const plistBytes = readBytes(context, plistPath, 8);
        const info = parsePlist(plistBytes);
        if (!info.supported) {
          return { supported: false, reason: info.reason, detail: info.detail, bundle: null, edges: [], limitations: info.limitations };
        }
        const root = info.root && typeof info.root === 'object' ? info.root : {};
        const pick = (key) => (typeof root[key] === 'string' || typeof root[key] === 'number' || typeof root[key] === 'boolean' ? root[key] : null);
        const bundle = {
          identifier: pick('CFBundleIdentifier'), name: pick('CFBundleName'),
          executable: pick('CFBundleExecutable'), version: pick('CFBundleShortVersionString'),
          build: pick('CFBundleVersion'), minimumOS: pick('MinimumOSVersion') ?? pick('LSMinimumSystemVersion'),
          platforms: Array.isArray(root.CFBundleSupportedPlatforms) ? root.CFBundleSupportedPlatforms.filter((entry) => typeof entry === 'string') : [],
          // A URL scheme or an ATS exception is how an app reaches outside itself.
          declaresUrlSchemes: Object.hasOwn(root, 'CFBundleURLTypes'),
          declaresAppTransportSecurity: Object.hasOwn(root, 'NSAppTransportSecurity'),
          plistFormat: info.format,
        };
        const edges = [];
        if (binary !== undefined) {
          // Linked dylibs are the application's outward edges; names come from the load commands.
          let machoBytes;
          try { machoBytes = readBytes(context, binary, 4); }
          catch { machoBytes = null; }
          if (machoBytes === null) limitations.push('The named binary could not be read, so no link edges are reported');
          else {
            const strings = asciiStrings(machoBytes, 6, 200000);
            const libraries = new Set();
            for (const { text } of strings) {
              const match = /^(?:@rpath|@executable_path|@loader_path|\/usr\/lib|\/System\/Library)[A-Za-z0-9_@./+-]*\.(?:dylib|framework\/[A-Za-z0-9_.-]+)$/.exec(text.trim());
              if (match) libraries.add(text.trim());
            }
            for (const library of [...libraries].sort()) {
              edges.push({ from: bundle.executable ?? binary, to: library, kind: 'links',
                system: library.startsWith('/usr/lib') || library.startsWith('/System/Library') });
            }
            limitations.push('Link edges come from dylib path strings in the image rather than from decoded load commands, so an unusual install name may be missed');
          }
        }
        limitations.push(...info.limitations);
        return { supported: true, reason: null, bundle, edges: listed(edges, limitations, 'edges'),
          externalFrameworks: edges.filter((edge) => !edge.system).length, limitations };
      } },
    { name: 'artifact.harmonyGraph', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'module', 'edges', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const bytes = readBytes(context, relative, 4);
        if (bytes.length < 4 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) {
          return { ...base(relative, bytes), supported: false, reason: 'not_a_hap',
            detail: 'A HarmonyOS package is a ZIP container and this file is not one', module: null, edges: [], limitations: [] };
        }
        const limitations = [];
        const entries = parseZipCentralDirectory(bytes, limitations);
        const names = entries.map((entry) => entry.name);
        const abc = names.filter((name) => typeof name === 'string' && name.endsWith('.abc'));
        const libs = names.filter((name) => typeof name === 'string' && /^libs\//.test(name));
        // module.json is stored compressed, so its content is not decompressed here: the graph is
        // built from the package layout, and the descriptor is reported as present.
        limitations.push('Entry contents are not decompressed, so abilities declared inside module.json are not read: the graph is the package layout');
        const module = {
          hasModuleJson: names.includes('module.json') || names.includes('module.json5'),
          hasConfigJson: names.includes('config.json'),
          hasPackInfo: names.includes('pack.info'),
          entryCount: entries.length,
          arkTsBytecode: abc.sort(),
          nativeLibraries: libs.sort(),
          abis: [...new Set(libs.map((name) => name.split('/')[1]).filter(Boolean))].sort(),
          resourceIndex: names.includes('resources.index'),
        };
        const edges = [
          ...abc.map((name) => ({ from: relative, to: name, kind: 'contains-bytecode' })),
          ...libs.map((name) => ({ from: relative, to: name, kind: 'contains-native' })),
        ];
        if (!module.hasModuleJson && !module.hasConfigJson) {
          limitations.push('Neither module.json nor config.json is present, so this may be a ZIP that is not a HarmonyOS package');
        }
        return { ...base(relative, bytes), supported: true, reason: null, module,
          edges: listed(edges, limitations, 'edges'), limitations };
      } },
  ];
}
