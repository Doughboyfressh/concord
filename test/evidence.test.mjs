import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeEvidenceTools } from '../src/evidence.mjs';

const tools = new Map(makeEvidenceTools().map((t) => [t.name, t]));
const policy = { maxOutputBytes: 4 * 1024 * 1024 };

function workspace(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'concord-evidence-')));
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });
  return { dir, context: { workspaceRoot: dir, policy } };
}
const write = (dir, name, bytes) => { fs.writeFileSync(path.join(dir, name), bytes); return name; };

const RIP = 0x401136n;
const RSP = 0x7ffd1234abc0n;
const MAPPINGS = [
  { start: 0x400000n, end: 0x401000n, path: '/usr/bin/crasher' },
  { start: 0x7f0000000000n, end: 0x7f0000021000n, path: '/usr/lib/libc.so.6' },
];

/**
 * An ELF64 little-endian core dump built byte by byte.
 *
 * Register order is part of the x86-64 ABI, so `rip` is index 16 and `rsp` index 19 within
 * `pr_reg`, which itself begins 112 bytes into NT_PRSTATUS. Those positions are written here, so
 * a reader using the wrong profile or the wrong prefix size reports the wrong register.
 */
function buildCore({ machine = 62, type = 4 } = {}) {
  const note = (noteType, descriptor) => {
    const name = Buffer.from('CORE\0', 'latin1');
    const header = Buffer.alloc(12);
    header.writeUInt32LE(name.length, 0);
    header.writeUInt32LE(descriptor.length, 4);
    header.writeUInt32LE(noteType, 8);
    const pad = (buffer) => Buffer.concat([buffer, Buffer.alloc((4 - (buffer.length % 4)) % 4)]);
    return Buffer.concat([header, pad(name), pad(descriptor)]);
  };

  const prpsinfo = Buffer.alloc(136);
  prpsinfo[0] = 0;                        // pr_state
  prpsinfo.writeUInt32LE(1000, 16);       // pr_uid
  prpsinfo.writeUInt32LE(1000, 20);       // pr_gid
  prpsinfo.writeUInt32LE(4242, 24);       // pr_pid
  prpsinfo.writeUInt32LE(4000, 28);       // pr_ppid
  prpsinfo.write('crasher\0', 40, 'latin1');          // pr_fname[16]
  prpsinfo.write('crasher --boom\0', 56, 'latin1');   // pr_psargs[80]

  const prstatus = Buffer.alloc(112 + 27 * 8 + 4);
  prstatus.writeUInt32LE(11, 0);          // si_signo = SIGSEGV
  prstatus.writeUInt32LE(4242, 32);       // pr_pid
  prstatus.writeBigUInt64LE(RIP, 112 + 16 * 8);   // rip
  prstatus.writeBigUInt64LE(RSP, 112 + 19 * 8);   // rsp

  const names = Buffer.concat(MAPPINGS.map((entry) => Buffer.from(entry.path + '\0', 'utf8')));
  const ntfile = Buffer.alloc(16 + MAPPINGS.length * 24 + names.length);
  ntfile.writeBigUInt64LE(BigInt(MAPPINGS.length), 0);
  ntfile.writeBigUInt64LE(4096n, 8);
  MAPPINGS.forEach((entry, i) => {
    const at = 16 + i * 24;
    ntfile.writeBigUInt64LE(entry.start, at);
    ntfile.writeBigUInt64LE(entry.end, at + 8);
    ntfile.writeBigUInt64LE(BigInt(i), at + 16);
  });
  names.copy(ntfile, 16 + MAPPINGS.length * 24);

  const notes = Buffer.concat([note(3, prpsinfo), note(1, prstatus), note(0x46494c45, ntfile)]);
  const headerSize = 64;
  const phnum = 2;
  const noteOffset = headerSize + phnum * 56;
  const loadOffset = noteOffset + notes.length;
  const load = Buffer.alloc(0x100, 0x90);

  const buffer = Buffer.alloc(loadOffset + load.length);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]).copy(buffer, 0);
  buffer.writeUInt16LE(type, 16);
  buffer.writeUInt16LE(machine, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(BigInt(headerSize), 32);  // e_phoff
  buffer.writeUInt16LE(headerSize, 52);             // e_ehsize
  buffer.writeUInt16LE(56, 54);                     // e_phentsize
  buffer.writeUInt16LE(phnum, 56);

  const writePh = (index, pType, offset, size, vaddr) => {
    const at = headerSize + index * 56;
    buffer.writeUInt32LE(pType, at);
    buffer.writeBigUInt64LE(BigInt(offset), at + 8);
    buffer.writeBigUInt64LE(BigInt(vaddr), at + 16);
    buffer.writeBigUInt64LE(BigInt(size), at + 32);
    buffer.writeBigUInt64LE(BigInt(size), at + 40);
  };
  writePh(0, 4, noteOffset, notes.length, 0);       // PT_NOTE
  writePh(1, 1, loadOffset, load.length, 0x400000); // PT_LOAD
  notes.copy(buffer, noteOffset);
  load.copy(buffer, loadOffset);
  return buffer;
}

test('an ELF64 core yields its signal, process identity, registers and mapped files', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'crash.core', buildCore());
  const read = tools.get('artifact.coreDump').execute({ path: 'crash.core' }, context);
  assert.equal(read.supported, true);
  assert.equal(read.architecture, 'x86-64');
  assert.equal(read.loadSegments, 1);
  assert.deepEqual(read.notes.map((note) => note.name), ['NT_PRPSINFO', 'NT_PRSTATUS', 'NT_FILE']);

  assert.deepEqual(read.process, { state: 0, uid: 1000, gid: 1000, pid: 4242, parentPid: 4000,
    command: 'crasher', arguments: 'crasher --boom' });

  assert.equal(read.thread.signal, 11);
  assert.equal(read.thread.signalName, 'SIGSEGV');
  assert.equal(read.thread.pid, 4242);
  // pr_reg begins 112 bytes into NT_PRSTATUS and rip is index 16: a reader using the wrong
  // prefix size or register order reports a different value here, not an error.
  assert.equal(read.thread.programCounter, '0x' + RIP.toString(16).padStart(16, '0'));
  assert.equal(read.thread.stackPointer, '0x' + RSP.toString(16).padStart(16, '0'));
  assert.equal(Object.keys(read.thread.registers).length, 27);
  assert.equal(read.thread.registers.rip, read.thread.programCounter);

  assert.equal(read.mappingCount, 2);
  assert.deepEqual(read.mappings.map((entry) => entry.path), MAPPINGS.map((entry) => entry.path));
  assert.equal(read.mappings[1].start, '0x' + MAPPINGS[1].start.toString(16).padStart(16, '0'));
  assert.ok(read.limitations.some((l) => /no stack is unwound/.test(l)));
  assert.deepEqual(tools.get('artifact.coreDump').execute({ path: 'crash.core' }, context), read);
});

test('a core reader refuses a non-core, a 32-bit image and an architecture it has no profile for', (t) => {
  const { dir, context } = workspace(t);
  const read = (name) => tools.get('artifact.coreDump').execute({ path: name }, context);

  write(dir, 'plain.bin', Buffer.from('not an ELF file at all'));
  assert.equal(read('plain.bin').reason, 'not_elf');

  // ET_EXEC rather than ET_CORE is an executable, which is a different thing entirely.
  write(dir, 'prog.elf', buildCore({ type: 2 }));
  assert.equal(read('prog.elf').reason, 'not_a_core');

  // Register layout is bound per architecture, so an unknown machine is refused by name before
  // any note is interpreted, which is also how REA behaves.
  write(dir, 'riscv.core', buildCore({ machine: 243 }));
  const unsupported = read('riscv.core');
  assert.equal(unsupported.supported, false);
  assert.equal(unsupported.reason, 'unsupported_target');
  assert.equal(unsupported.machine, 243);
  assert.equal(unsupported.thread, null);

  const thirtyTwo = buildCore();
  thirtyTwo[4] = 1;
  write(dir, 'core32.core', thirtyTwo);
  assert.equal(read('core32.core').reason, 'unsupported_target');

  // AArch64 has its own profile, so the same core shape reports that register order.
  write(dir, 'arm.core', buildCore({ machine: 183 }));
  const arm = read('arm.core');
  assert.equal(arm.architecture, 'aarch64');
  assert.equal(Object.keys(arm.thread.registers).length, 34);
  assert.ok(Object.hasOwn(arm.thread.registers, 'pc'));
  assert.ok(Object.hasOwn(arm.thread.registers, 'x30'));
});

test('an analysis view reports internal consistency and says it cannot authenticate', () => {
  const digest = 'a'.repeat(64);
  const view = tools.get('artifact.analysisView').execute({
    view: { records: [
      { id: 'one', kind: 'layout', source: 'artifact.inspect', sha256: digest },
      { id: 'two', kind: 'layout', source: 'artifact.inspect' },
      { id: 'one', kind: 'layout', source: 'artifact.inspect', sha256: 'b'.repeat(64) },
      { id: 'three', kind: 'members', source: 'artifact.managedMembers', sha256: 'not-a-digest' },
    ] },
    references: ['one', 'absent'],
  });
  assert.deepEqual(view.byKind, { layout: 3, members: 1 });
  assert.deepEqual(view.summary, { records: 4, distinctIds: 3, withDigest: 2, references: 2, dangling: 1 });
  const issues = view.issues.map((entry) => entry.issue);
  // Two records sharing an id is only a contradiction when the digests differ.
  assert.ok(issues.includes('duplicate-id-different-digest'));
  assert.ok(issues.includes('no-digest'));
  assert.ok(issues.includes('malformed-digest'));
  assert.ok(issues.includes('reference-not-in-view'));
  assert.ok(view.limitations.some((l) => /cannot authenticate/.test(l)));
});

test('a static fact raises a candidate obligation and no verifier short of replay closes one', () => {
  const ledger = tools.get('artifact.obligationLedger');
  const facts = [
    { id: 'static-1', subject: 'Type A extends B', kind: 'static' },
    { id: 'req-open', subject: 'A writes to disk', kind: 'runtime', required: true, owner: 'o1' },
    { id: 'req-inferred', subject: 'A calls B', kind: 'runtime', required: true, owner: 'o2' },
    { id: 'req-closed', subject: 'A parses C', kind: 'runtime', required: true, owner: 'o3' },
    { id: 'req-nocite', subject: 'A emits D', kind: 'runtime', required: true, owner: 'o4' },
    { id: 'dup', subject: 'first definition', kind: 'runtime', required: true, owner: 'o5' },
    { id: 'dup', subject: 'second definition', kind: 'runtime', required: true, owner: 'o6' },
  ];
  const verifiers = [
    { obligationIds: ['req-inferred'], result: 'pass', authority: 'inferred', evidenceIds: ['e1'] },
    { obligationIds: ['req-closed'], result: 'pass', authority: 'replay', evidenceIds: ['e2'] },
    { obligationIds: ['req-nocite'], result: 'pass', authority: 'replay', evidenceIds: [] },
  ];
  const built = ledger.execute({ facts, verifiers });
  const byId = Object.fromEntries(built.obligations.map((entry) => [entry.id, entry]));

  // A static fact never closes: it does not prove runtime behaviour.
  assert.equal(byId['static-1'].status, 'candidate');
  assert.match(byId['static-1'].reason, /does not prove runtime behaviour/);
  assert.equal(byId['req-open'].status, 'open');
  // An inferred verifier is not comparable to the original observation.
  assert.equal(byId['req-inferred'].status, 'open');
  assert.match(byId['req-inferred'].reason, /inferred authority, which is not comparable/);
  // A passing replay verifier that cites nothing has produced no evidence to close against.
  assert.equal(byId['req-nocite'].status, 'open');
  assert.match(byId['req-nocite'].reason, /cites no evidence record/);
  assert.equal(byId['req-closed'].status, 'closed');
  // Two definitions is a contradiction rather than a merge.
  assert.equal(byId.dup.status, 'contradicted');
  assert.deepEqual(built.summary, { total: 6, candidate: 1, open: 3, closed: 1, contradicted: 1 });
  assert.ok(built.limitations.some((l) => /not mean the reconstruction is behaviourally correct/.test(l)));
});

test('coverage is unknown when the only observation behind a closed obligation is inferred', () => {
  const coverage = tools.get('artifact.reconstructionCoverage');
  const closed = [{ id: 'o1', status: 'closed' }, { id: 'o2', status: 'closed' }];

  const covered = coverage.execute({ boundaryId: 'b1', obligations: closed,
    observations: [{ obligationId: 'o1', authority: 'replay' }, { obligationId: 'o2', authority: 'replay' }] });
  assert.equal(covered.status, 'covered');
  assert.deepEqual(covered.reasons, []);

  // The rule that matters: a passing verifier over inferred evidence cannot promote coverage.
  const inferred = coverage.execute({ boundaryId: 'b1', obligations: closed,
    observations: [{ obligationId: 'o1', authority: 'replay' }, { obligationId: 'o2', authority: 'inferred' }] });
  assert.equal(inferred.status, 'unknown');
  assert.equal(inferred.counts.inferredOnly, 1);
  assert.ok(inferred.reasons.some((reason) => /strongest observation is inferred/.test(reason)));
  assert.ok(inferred.probes.some((probe) => /Replace the inferred observation for o2/.test(probe)));

  // An open obligation is uncovered, which is a stronger statement than unknown.
  const open = coverage.execute({ boundaryId: 'b1', obligations: [{ id: 'o1', status: 'open' }] });
  assert.equal(open.status, 'uncovered');
  assert.ok(open.probes.some((probe) => /replay-authority verifier/.test(probe)));

  // A closed obligation with no observation at all is also unknown, not covered.
  const missing = coverage.execute({ boundaryId: 'b1', obligations: [{ id: 'o1', status: 'closed' }] });
  assert.equal(missing.status, 'unknown');
  assert.equal(missing.counts.unobserved, 1);

  // An empty scope cannot be covered.
  const empty = coverage.execute({ boundaryId: 'b2', obligations: [{ id: 'o1', status: 'closed', boundaryId: 'b1' }] });
  assert.equal(empty.status, 'unknown');
  assert.ok(empty.reasons.some((reason) => /No obligation is scoped/.test(reason)));
});

test('version comparison needs digests on both sides before it will call an entry unchanged', () => {
  const compare = tools.get('artifact.compareApplicationVersions');
  const digest = (char) => char.repeat(64);
  const result = compare.execute({
    left: { version: '1.0.0', entries: [
      { name: 'same', kind: 'module', sha256: digest('a') },
      { name: 'moved', kind: 'module', sha256: digest('b') },
      { name: 'gone', kind: 'module', sha256: digest('c') },
      { name: 'nodigest', kind: 'module' },
      { name: 'dup', kind: 'module', sha256: digest('d') },
      { name: 'dup', kind: 'module', sha256: digest('e') },
    ] },
    right: { version: '1.1.0', entries: [
      { name: 'same', kind: 'module', sha256: digest('a') },
      { name: 'moved', kind: 'module', sha256: digest('f') },
      { name: 'fresh', kind: 'module', sha256: digest('0') },
      { name: 'nodigest', kind: 'module' },
      { name: 'dup', kind: 'module', sha256: digest('d') },
    ] },
  });
  assert.deepEqual(result.summary, { leftVersion: '1.0.0', rightVersion: '1.1.0',
    added: 1, removed: 1, changed: 1, unchanged: 1, presentBoth: 1, unknown: 1 });
  const byEntry = Object.fromEntries(result.changes.map((change) => [change.entry, change]));
  // Without a digest on both sides a shared name is present, not unchanged.
  assert.equal(byEntry['module:nodigest'].state, 'present-both');
  assert.match(byEntry['module:nodigest'].reason, /a change cannot be decided/);
  assert.equal(byEntry['module:dup'].state, 'unknown');
});

test('feature tracing ranks name matches and refuses to call itself a trace', () => {
  const trace = tools.get('artifact.traceFeature');
  const supplied = { entries: [
    { name: 'AuthTokenStore', kind: 'class', source: 'src/auth/token.ts' },
    { name: 'refreshToken', kind: 'method', source: 'src/auth/token.ts' },
    { name: 'renderChart', kind: 'function', source: 'src/ui/chart.ts' },
  ] };
  const result = trace.execute({ feature: 'auth token refresh', inventory: supplied });
  assert.deepEqual(result.terms, ['auth', 'token', 'refresh']);
  // The entry matching all three terms ranks first.
  assert.equal(result.matches[0].name, 'refreshToken');
  assert.equal(result.matches[0].matchedTerms.length, 3);
  assert.equal(result.summary.allTermsMatched, true);
  assert.equal(result.matches.some((entry) => entry.name === 'renderChart'), false);
  assert.equal(result.summary.scanned, 3);
  // A match is a candidate to look at, not evidence that the entry implements the feature.
  assert.ok(result.limitations.some((l) => /not a dataflow or call trace/.test(l)));
  assert.ok(result.limitations.some((l) => /Nothing here establishes/.test(l)));

  const none = trace.execute({ feature: '!!!', inventory: supplied });
  assert.deepEqual(none.matches, []);
  assert.ok(none.limitations.some((l) => /no searchable term/.test(l)));
});
