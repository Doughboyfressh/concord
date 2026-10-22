import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { GHIDRA, REAL_FILES } from './train-exercises-ghidra.mjs';

/**
 * Readers, given the thing they actually read.
 *
 * Chasing unread output keys turned up something larger than the keys. Twenty-five reader tools
 * had exactly one single-task plan exercise each, and every one of them fed the reader a file that
 * is not its format - `notmine.bin`, asserting `supported: false` and a reason. Coverage said
 * 97/97 tools exercised and that was true of a weaker thing than it sounded like: for these
 * readers only the refusal path had ever run, so `packets`, `objects`, `resources` and `header`
 * were unread because no fixture had ever been the format, not because an assertion was
 * forgotten. A reader proven only against the wrong format has proven that it declines, which is
 * the easy half.
 *
 * So these are real artifacts, built here rather than committed, and three of the four are built
 * from the format's own definition:
 *
 *   a pcap        twenty-four byte global header and three records, each an Ethernet frame
 *                 carrying IPv4 and then TCP or UDP. Written to the spec by hand.
 *   a database    created by node:sqlite, so the file is written by SQLite itself rather than by
 *                 something imitating it. A table, an index, a view and a row.
 *   a source map  version 3 with sourcesContent, which is what makes recovery possible at all.
 *   a PE          the Ghidra install's own pdb.exe, already in the corpus, which carries exactly
 *                 one resource: its manifest.
 *
 * The pcap cost a measurement to get right, and the mistake is worth keeping: the magic is the
 * endianness marker, so a little-endian capture begins with the bytes d4 c3 b2 a1 and not
 * a1 b2 c3 d4. Written the wrong way round the reader does not refuse - it reads the file
 * big-endian, decides the link type is 16777216 rather than 1, notes that it cannot name it, and
 * returns a capture with zero packets. Plausible, complete, and wrong, which is the failure mode
 * every one of these readers exists to make visible.
 */

/** Little-endian scalars, because that is what the magic below declares. */
const u16 = (value) => { const out = Buffer.alloc(2); out.writeUInt16LE(value); return out; };
const u32 = (value) => { const out = Buffer.alloc(4); out.writeUInt32LE(value); return out; };
/** Network order, because everything inside a frame is big-endian. */
const be16 = (value) => { const out = Buffer.alloc(2); out.writeUInt16BE(value); return out; };

const ipv4 = (payload, { source = [10, 0, 0, 1], destination = [10, 0, 0, 2], protocol = 6 } = {}) => Buffer.concat([
  Buffer.from([0x45, 0x00]), be16(20 + payload.length), be16(0x1234), Buffer.from([0x40, 0x00]),
  Buffer.from([64, protocol]), be16(0), Buffer.from(source), Buffer.from(destination), payload,
]);
const tcp = ({ sport, dport, flags }) => Buffer.concat([
  be16(sport), be16(dport), Buffer.from([0, 0, 0, 1]), Buffer.from([0, 0, 0, 0]),
  Buffer.from([0x50, flags]), be16(8192), be16(0), be16(0),
]);
const ethernet = (payload) => Buffer.concat([
  Buffer.from([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]), Buffer.from([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
  be16(0x0800), payload,
]);
const record = (frame, seconds) => Buffer.concat([u32(seconds), u32(0), u32(frame.length), u32(frame.length), frame]);

const CAPTURE = Buffer.concat([
  // magic, version 2.4, no timezone, no sigfigs, 65535 snapshot length, link type 1 (ethernet)
  Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]), u16(2), u16(4), u32(0), u32(0), u32(65535), u32(1),
  record(ethernet(ipv4(tcp({ sport: 51000, dport: 80, flags: 0x02 }))), 1700000000),
  record(ethernet(ipv4(tcp({ sport: 80, dport: 51000, flags: 0x12 }), { source: [10, 0, 0, 2], destination: [10, 0, 0, 1] })), 1700000001),
  record(ethernet(ipv4(Buffer.concat([be16(53000), be16(53), be16(16), be16(0), Buffer.from('abcdefgh')]), { protocol: 17 })), 1700000002),
]);

const GREET = 'export const greet = (who: string) => `hello ${who}`;\n';
const MAIN = 'import { greet } from "./greet";\nconsole.log(greet("world"));\n';
const SOURCE_MAP = JSON.stringify({
  version: 3, file: 'app.js', sourceRoot: '', sources: ['src/greet.ts', 'src/main.ts'],
  sourcesContent: [GREET, MAIN], names: ['greet', 'who', 'console', 'log'],
  mappings: 'AAAA,OAAO,MAAMA,KAAK,GAAG,CAACC,GAAW,KAAK,SAASA,GAAK,EAAE;ACA9C,OAAOD,OAAOE,GAAG,CAACC,IAAI,CAACH,KAAK,CAAC,OAAO,CAAC,CAAC',
});
const GREET_DIGEST = createHash('sha256').update(GREET).digest('hex');

/**
 * SQLite, written by SQLite.
 *
 * Imported at module load and tolerated as absent: `node:sqlite` is a built-in, so this adds no
 * dependency, but a Node without it should skip the exercise rather than fail the round.
 */
let DatabaseSync = null;
try { ({ DatabaseSync } = await import('node:sqlite')); } catch { /* skipped below */ }

const one = (tool, input) => ({ version: 1, name: 'real-format', tasks: [{ id: 'a', tool, input }] });

const captureFixture = (dir) => fs.writeFileSync(path.join(dir, 'three-packets.pcap'), CAPTURE);
const mapFixture = (dir) => fs.writeFileSync(path.join(dir, 'app.js.map'), SOURCE_MAP);
const databaseFixture = (dir) => {
  const file = path.join(dir, 'ledger.sqlite');
  if (fs.existsSync(file)) return;
  const database = new DatabaseSync(file);
  try {
    database.exec('CREATE TABLE lesson (id INTEGER PRIMARY KEY, subject TEXT NOT NULL, proven INTEGER)');
    database.exec('CREATE INDEX lesson_subject ON lesson (subject)');
    database.exec('CREATE VIEW proven AS SELECT subject FROM lesson WHERE proven = 1');
    database.exec("INSERT INTO lesson (subject, proven) VALUES ('a refusal that crosses a socket', 1)");
  } finally { database.close(); }
};
const peFixture = (dir) => {
  const target = path.join(dir, 'program.exe');
  if (!fs.existsSync(target)) fs.copyFileSync(path.join(GHIDRA, REAL_FILES['program.exe']), target);
};

export function formatExercises() {
  return [
    {
      family: 'formats', tool: 'artifact.pcap', workspace: 'temp', fixture: captureFixture,
      plan: one('artifact.pcap', { path: 'three-packets.pcap' }),
      expect: (r) => r.results.a.supported === true && r.results.a.format === 'pcap'
        && r.results.a.limitations.length === 0 && r.results.a.packets.length === 3
        // 24 bytes of global header, then a 16 byte record header before 54 bytes of frame:
        // 14 of Ethernet and 20 of IPv4 put the TCP payload at 40.
        && r.results.a.packets[0].offset === 24 && r.results.a.packets[0].dataOffset === 40
        && r.results.a.packets[0].capturedLength === 54 && r.results.a.packets[0].originalLength === 54
        && r.results.a.packets[0].sliced === false
        && r.results.a.packets[0].timestampSeconds === 1700000000
        && r.results.a.packets[2].index === 2,
      lesson: 'Given a real capture, artifact.pcap reports each record by where it sits rather than only how long it is: the offset of the record and the offset of its payload are separate facts, and both are needed to quote a packet from the file by digest. sliced:false says the whole frame was captured, which is the difference between a packet and a prefix of one - a snapshot length shorter than the frame is the normal way a capture lies by omission, and the reader names it per packet instead of per file.',
    },
    {
      family: 'formats', tool: 'artifact.packetFields', workspace: 'temp', fixture: captureFixture,
      plan: one('artifact.packetFields', { path: 'three-packets.pcap', limit: 8 }),
      expect: (r) => r.results.a.supported === true && r.results.a.decoded === 3
        && r.results.a.frames.length === 3 && r.results.a.frames[0].layers.length === 3
        && r.results.a.frames[0].capturedLength === 54 && r.results.a.frames[0].sliced === false
        && r.results.a.frames[0].index === 0 && r.results.a.limitations.length === 0,
      lesson: 'artifact.packetFields decodes a frame as a stack of layers rather than a flat record, so an Ethernet frame carrying IPv4 carrying TCP is three layers and not one dictionary with the names run together. decoded counts the frames it got all the way through, which is deliberately not the same as the number of frames: a capture whose link type this reader cannot name still lists its frames and decodes none of them, and a caller that read only the frame count would not be able to tell those apart.',
    },
    ...(DatabaseSync ? [{
      family: 'formats', tool: 'artifact.sqlite', workspace: 'temp', fixture: databaseFixture,
      plan: one('artifact.sqlite', { path: 'ledger.sqlite' }),
      expect: (r) => r.results.a.supported === true
        && r.results.a.header.pageSize === 4096 && r.results.a.header.pageSizeValid === true
        && r.results.a.header.pageCount === 3 && r.results.a.header.textEncoding === 'UTF-8'
        && r.results.a.header.schemaFormat === 4 && r.results.a.header.readVersion === 'legacy'
        && r.results.a.header.freelistPages === 0
        && r.results.a.objects.length === 3
        && r.results.a.objects.some((entry) => entry.type === 'table' && entry.name === 'lesson' && entry.rootPage === 2)
        && r.results.a.objects.some((entry) => entry.type === 'index' && entry.tableName === 'lesson')
        && r.results.a.objects.some((entry) => entry.type === 'view' && entry.name === 'proven'),
      lesson: 'Given a database written by SQLite itself, artifact.sqlite reads the header fields that decide how every other byte is interpreted - page size, page count, text encoding, schema format - and then the schema objects with the SQL that defined them. An index and a view are listed beside the table they belong to, each with the root page it lives on, so a claim about a database can name where in the file it came from. The reader is a reader: it never opens the database, which is why a file whose header says 4096 and whose pages are something else is reported as it is rather than refused by an engine.',
    }] : []),
    {
      family: 'formats', tool: 'artifact.sourceMap', workspace: 'temp', fixture: mapFixture,
      plan: one('artifact.sourceMap', { path: 'app.js.map' }),
      expect: (r) => r.results.a.supported === true && r.results.a.sources.length === 2
        && r.results.a.sources[0] === 'src/greet.ts' && r.results.a.mappingCount === 23
        && r.results.a.limitations.length === 0
        && /^[0-9a-f]{64}$/.test(r.results.a.sha256),
      lesson: 'A version 3 source map is read for the two things that can be checked against the bundle: which sources it claims and how many mappings it carries. The count is of decoded segments rather than of lines, because a map with many lines and few segments describes almost nothing - and the digest is of the map file itself, so a recovered source can be traced to the exact map that produced it rather than to a map with the same name.',
    },
    {
      family: 'formats', tool: 'artifact.recoverSources', workspace: 'temp', fixture: mapFixture,
      plan: one('artifact.recoverSources', { path: 'app.js.map' }),
      expect: (r) => r.results.a.supported === true && r.results.a.content === null
        && r.results.a.sources.length === 2
        && r.results.a.sources[0].source === 'src/greet.ts'
        && r.results.a.sources[0].hasContent === true
        && r.results.a.sources[0].chars === 54
        && r.results.a.sources[0].sha256 === GREET_DIGEST,
      lesson: 'artifact.recoverSources lists what a map can give back and digests each one without returning any of it: content is null until a caller names a single source, which keeps a listing of a large bundle from being a copy of it. Each entry carries hasContent, because a map that lists a source and omits its text can name a file it cannot recover - and the digest is computed over the recovered text, so the bytes a plan later quotes are the bytes that were measured here.',
    },
    ...(GHIDRA ? [{
      family: 'formats', tool: 'artifact.peResources', workspace: 'temp', fixture: peFixture,
      plan: one('artifact.peResources', { path: 'program.exe' }),
      expect: (r) => r.results.a.supported === true && r.results.a.entryCount === 1
        && r.results.a.resources.length === 1 && r.results.a.resources[0].id === 24
        && r.results.a.resources[0].typeName === 'MANIFEST'
        && r.results.a.resources[0].named === false && r.results.a.resources[0].name === null
        && r.results.a.resources[0].children.length === 1,
      lesson: 'Given a real PE, artifact.peResources walks the resource directory as the tree it is - type, then name or id, then language - rather than flattening it. Ghidra’s own pdb.exe carries exactly one resource type, id 24, which is the application manifest, and reporting both the numeric id and the name it maps to matters because the id is what is in the file and the name is this reader’s interpretation of it. named:false says this level is addressed by number, which is the usual case and the one a reader that only reported names would silently misrepresent.',
    }] : []),
  ];
}
