import { createHash } from 'node:crypto';
import { readWorkspaceFile } from './workspace-fs.mjs';

/**
 * Recorded crashes, and the evidence composition REA builds on top of its readers.
 *
 * The core dump reader is byte parsing: an ELF64 core's notes carry the signal, the process
 * identity, the register file and the mapped files, all in documented layouts.
 *
 * The rest are `pure` tools over records a caller already holds, and they exist to preserve two
 * rules REA states explicitly and that are easy to lose:
 *
 *   - a static fact creates a *candidate* obligation and never closes one, because static
 *     structure does not prove runtime behaviour;
 *   - a passing verifier whose evidence is *inferred* cannot promote coverage to covered, so that
 *     case is `unknown` rather than a pass.
 *
 * Neither tool can authenticate a record against a run ledger, since a pure tool reaches nothing.
 * They check internal consistency and say so.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const MAX_LISTED = 2000;
const MAX_NOTES = 512;
const MAX_MAPPINGS = 4096;
const MAX_TERMS = 32;

const u16 = (b, o) => (o < 0 || o + 2 > b.length ? undefined : b.readUInt16LE(o));
const u32 = (b, o) => (o < 0 || o + 4 > b.length ? undefined : b.readUInt32LE(o));
const u64 = (b, o) => {
  if (o < 0 || o + 8 > b.length) return undefined;
  const value = b.readBigUInt64LE(o);
  // A pointer-width value past the safe integer range is kept as text rather than rounded.
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : '0x' + value.toString(16);
};
const hex64 = (b, o) => (o < 0 || o + 8 > b.length ? null : '0x' + b.readBigUInt64LE(o).toString(16).padStart(16, '0'));

const ET_CORE = 4;
const PT_LOAD = 1;
const PT_NOTE = 4;
const NOTE_TYPES = {
  1: 'NT_PRSTATUS', 2: 'NT_FPREGSET', 3: 'NT_PRPSINFO', 6: 'NT_AUXV',
  0x46494c45: 'NT_FILE', 0x53494749: 'NT_SIGINFO', 0x200: 'NT_X86_XSTATE', 0x400: 'NT_ARM_TLS',
};
// Register order is part of each ABI's layout, so a profile is the only thing that names them.
const REGISTERS = {
  62: { name: 'x86-64', order: ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8',
    'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax', 'rip', 'cs', 'eflags', 'rsp', 'ss',
    'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs'], programCounter: 'rip', stackPointer: 'rsp' },
  183: { name: 'aarch64', order: [...Array.from({ length: 31 }, (_, i) => 'x' + i), 'sp', 'pc', 'pstate'],
    programCounter: 'pc', stackPointer: 'sp' },
};
const SIGNALS = { 2: 'SIGINT', 4: 'SIGILL', 6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE', 9: 'SIGKILL',
  11: 'SIGSEGV', 13: 'SIGPIPE', 15: 'SIGTERM', 31: 'SIGSYS' };

// elf_prstatus prefix on LP64 Linux: elf_siginfo, cursig and padding, pending and held masks,
// four pids, then four timevals. pr_reg begins after all of that.
const PRSTATUS_REG_OFFSET = 112;

/** Read an ELF64 little-endian core dump's notes. */
export function parseCoreDump(buffer) {
  const limitations = [];
  if (buffer.length < 64 || buffer.toString('latin1', 0, 4) !== '\x7fELF') {
    return { supported: false, reason: 'not_elf', detail: 'The file carries no ELF magic', limitations };
  }
  if (buffer[4] !== 2 || buffer[5] !== 1) {
    return { supported: false, reason: 'unsupported_target',
      detail: 'Only 64-bit little-endian ELF cores are interpreted', limitations };
  }
  const type = u16(buffer, 16);
  if (type !== ET_CORE) {
    return { supported: false, reason: 'not_a_core',
      detail: 'The ELF type is not ET_CORE, so this is an executable or object rather than a crash dump', limitations };
  }
  const machine = u16(buffer, 18);
  const profile = REGISTERS[machine];
  if (!profile) {
    // REA refuses an unknown machine before interpreting notes, and so does this.
    return { supported: false, reason: 'unsupported_target',
      detail: 'Register layout is bound per architecture, and this e_machine has no profile here',
      machine, limitations };
  }
  const phoff = u64(buffer, 32);
  const phentsize = u16(buffer, 54);
  const phnum = u16(buffer, 56);
  if (typeof phoff !== 'number' || phentsize !== 56 || !phnum) {
    return { supported: false, reason: 'program_headers_unreadable',
      detail: 'The program header table is missing or not the ELF64 size', limitations };
  }

  const segments = [];
  const noteRanges = [];
  for (let i = 0; i < Math.min(phnum, 4096); i++) {
    const at = phoff + i * phentsize;
    const pType = u32(buffer, at);
    if (pType === undefined) { limitations.push('A program header lies outside the file'); break; }
    const offset = u64(buffer, at + 8);
    const fileSize = u64(buffer, at + 32);
    const entry = { type: pType, offset, virtualAddress: hex64(buffer, at + 16),
      fileSize, memorySize: u64(buffer, at + 40) };
    if (pType === PT_LOAD) segments.push(entry);
    if (pType === PT_NOTE && typeof offset === 'number' && typeof fileSize === 'number') noteRanges.push({ offset, fileSize });
  }

  const notes = [];
  for (const range of noteRanges) {
    let at = range.offset;
    const end = Math.min(range.offset + range.fileSize, buffer.length);
    for (let i = 0; i < MAX_NOTES && at + 12 <= end; i++) {
      const nameSize = u32(buffer, at);
      const descSize = u32(buffer, at + 4);
      const noteType = u32(buffer, at + 8);
      if (nameSize === undefined || descSize === undefined) break;
      const nameAt = at + 12;
      const descAt = nameAt + Math.ceil(nameSize / 4) * 4;
      const descEnd = descAt + descSize;
      if (descEnd > end) { limitations.push('A note runs past the end of its segment'); break; }
      notes.push({ type: noteType, name: NOTE_TYPES[noteType] ?? null,
        owner: buffer.toString('latin1', nameAt, nameAt + Math.max(0, nameSize - 1)),
        descriptorOffset: descAt, descriptorBytes: descSize });
      at = descAt + Math.ceil(descSize / 4) * 4;
    }
  }

  const noteOf = (name) => notes.find((note) => note.name === name);
  let process = null;
  const info = noteOf('NT_PRPSINFO');
  if (info) {
    const at = info.descriptorOffset;
    const zeroEnd = (start, length) => {
      let stop = start;
      while (stop < start + length && stop < buffer.length && buffer[stop] !== 0) stop += 1;
      return buffer.toString('latin1', start, stop);
    };
    process = { state: buffer[at], uid: u32(buffer, at + 16), gid: u32(buffer, at + 20),
      pid: u32(buffer, at + 24), parentPid: u32(buffer, at + 28),
      command: zeroEnd(at + 40, 16), arguments: zeroEnd(at + 56, 80) };
  }

  let thread = null;
  const status = noteOf('NT_PRSTATUS');
  if (status) {
    const at = status.descriptorOffset;
    const registers = {};
    for (let i = 0; i < profile.order.length; i++) {
      const value = hex64(buffer, at + PRSTATUS_REG_OFFSET + i * 8);
      if (value === null) { limitations.push('The register file is shorter than this architecture declares'); break; }
      registers[profile.order[i]] = value;
    }
    const signal = u32(buffer, at);
    thread = { signal, signalName: SIGNALS[signal] ?? null, pid: u32(buffer, at + 32),
      programCounter: registers[profile.programCounter] ?? null,
      stackPointer: registers[profile.stackPointer] ?? null, registers };
  }

  const mappings = [];
  const files = noteOf('NT_FILE');
  if (files) {
    const at = files.descriptorOffset;
    const count = u64(buffer, at);
    const pageSize = u64(buffer, at + 8);
    if (typeof count === 'number' && count <= MAX_MAPPINGS) {
      // Entries come first, then the same number of NUL-terminated names in the same order.
      let nameAt = at + 16 + count * 24;
      for (let i = 0; i < count; i++) {
        const entry = at + 16 + i * 24;
        let stop = nameAt;
        while (stop < buffer.length && buffer[stop] !== 0) stop += 1;
        mappings.push({ start: hex64(buffer, entry), end: hex64(buffer, entry + 8),
          fileOffsetPages: u64(buffer, entry + 16), path: buffer.toString('utf8', nameAt, stop) });
        nameAt = stop + 1;
      }
    } else limitations.push('The mapped-file note declares an implausible count, so mappings were not read');
    if (typeof pageSize === 'number') mappings.pageSize = pageSize;
  }

  limitations.push('Register values and mapped files are what the core recorded; no memory is interpreted and no stack is unwound');
  return { supported: true, reason: null, architecture: profile.name, machine,
    loadSegments: segments.length, notes, process, thread,
    mappings: mappings.slice(0, MAX_LISTED), mappingCount: mappings.length, limitations };
}

const termsOf = (text) => [...new Set(String(text).toLowerCase().match(/[a-z0-9]+/g) ?? [])].slice(0, MAX_TERMS);

const recordList = {
  type: 'object', additionalProperties: true, required: ['records'],
  properties: { records: { type: 'array', maxItems: MAX_LISTED, items: {
    type: 'object', additionalProperties: true, required: ['id'],
    properties: { id: { type: 'string', maxLength: 256 }, kind: { type: 'string', maxLength: 64 },
      source: { type: 'string', maxLength: 256 }, sha256: { type: 'string', maxLength: 64 },
      authority: { enum: ['replay', 'observed', 'inferred'] } } } } },
};

/** Recorded-crash reading plus the pure evidence composition tools. */
export function makeEvidenceTools() {
  const base = (relative, bytes) => ({ path: relative, sha256: sha256(bytes), untrusted: true });
  const inventory = {
    type: 'object', additionalProperties: true, required: ['entries'],
    properties: {
      version: { type: 'string', maxLength: 128 },
      entries: { type: 'array', maxItems: MAX_LISTED * 2, items: {
        type: 'object', additionalProperties: true, required: ['name'],
        properties: { name: { type: 'string', maxLength: 1024 }, kind: { type: 'string', maxLength: 64 },
          source: { type: 'string', maxLength: 1024 }, sha256: { type: 'string', maxLength: 64 } } } },
    },
  };

  return [
    { name: 'artifact.coreDump', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'thread', 'process', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string }),
      execute({ path: relative }, context) {
        const bytes = readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / 4));
        const read = parseCoreDump(bytes);
        if (!read.supported) {
          return { ...base(relative, bytes), supported: false, reason: read.reason, detail: read.detail,
            machine: read.machine ?? null, thread: null, process: null, limitations: read.limitations };
        }
        return { ...base(relative, bytes), ...read };
      } },
    { name: 'artifact.analysisView', version: '1.0.0', outputKeys: ['byKind', 'bySource', 'issues', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({ view: recordList, references: { type: 'array', maxItems: MAX_LISTED, items: { type: 'string', maxLength: 256 } } }, ['view']),
      execute({ view, references = [] }) {
        const byKind = {};
        const bySource = {};
        const digests = new Map();
        const issues = [];
        const seen = new Set();
        for (const record of view.records) {
          const kind = record.kind ?? 'unspecified';
          const source = record.source ?? 'unspecified';
          byKind[kind] = (byKind[kind] ?? 0) + 1;
          bySource[source] = (bySource[source] ?? 0) + 1;
          if (seen.has(record.id)) {
            const previous = digests.get(record.id);
            // Two records sharing an id is a contradiction only when their digests differ.
            issues.push({ id: record.id, issue: previous !== undefined && previous !== record.sha256
              ? 'duplicate-id-different-digest' : 'duplicate-id' });
          }
          seen.add(record.id);
          if (record.sha256 !== undefined) {
            if (!/^[a-f0-9]{64}$/.test(record.sha256)) issues.push({ id: record.id, issue: 'malformed-digest' });
            digests.set(record.id, record.sha256);
          } else issues.push({ id: record.id, issue: 'no-digest' });
        }
        const dangling = references.filter((id) => !seen.has(id)).map((id) => ({ id, issue: 'reference-not-in-view' }));
        return { byKind, bySource, issues: [...issues, ...dangling].slice(0, MAX_LISTED),
          summary: { records: view.records.length, distinctIds: seen.size,
            withDigest: digests.size, references: references.length, dangling: dangling.length },
          limitations: ['This is an internal-consistency view of the records supplied; it cannot authenticate any of them against a run ledger, because a pure tool reaches nothing'] };
      } },
    { name: 'artifact.obligationLedger', version: '1.0.0', outputKeys: ['obligations', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({
        facts: { type: 'array', maxItems: MAX_LISTED, items: {
          type: 'object', additionalProperties: true, required: ['id', 'subject'],
          properties: { id: { type: 'string', maxLength: 256 }, subject: { type: 'string', maxLength: 1024 },
            kind: { enum: ['static', 'runtime'] }, required: { type: 'boolean' },
            owner: { type: 'string', maxLength: 256 }, claim: { type: 'string', maxLength: 2048 } } } },
        verifiers: { type: 'array', maxItems: MAX_LISTED, items: {
          type: 'object', additionalProperties: true, required: ['obligationIds', 'result'],
          properties: { obligationIds: { type: 'array', maxItems: MAX_LISTED, items: { type: 'string', maxLength: 256 } },
            result: { enum: ['pass', 'fail'] }, authority: { enum: ['replay', 'observed', 'inferred'] },
            evidenceIds: { type: 'array', maxItems: MAX_LISTED, items: { type: 'string', maxLength: 256 } } } } },
      }, ['facts']),
      execute({ facts, verifiers = [] }) {
        const byId = new Map();
        const contradictions = [];
        for (const fact of facts) {
          const existing = byId.get(fact.id);
          if (existing) {
            // A duplicate definition or a second owner is a contradiction, not a merge.
            if (existing.subject !== fact.subject || (existing.owner ?? null) !== (fact.owner ?? null)) {
              contradictions.push({ id: fact.id, reason: 'The ledger has two definitions or two owners for this obligation' });
            }
            continue;
          }
          byId.set(fact.id, fact);
        }
        const contradicted = new Set(contradictions.map((entry) => entry.id));
        // Only a passing verifier that enumerates the obligation and carries replay authority can
        // close it: an inferred verifier is not comparable to the original observation.
        const closing = new Map();
        for (const verifier of verifiers) {
          for (const id of verifier.obligationIds) {
            const comparable = verifier.result === 'pass' && verifier.authority === 'replay';
            const current = closing.get(id);
            if (!current || (comparable && !current.comparable)) {
              closing.set(id, { comparable, result: verifier.result, authority: verifier.authority ?? null,
                evidenceIds: verifier.evidenceIds ?? [] });
            }
          }
        }
        const obligations = [...byId.values()].map((fact) => {
          const verifier = closing.get(fact.id) ?? null;
          const isRequired = fact.required === true;
          let status;
          let reason = null;
          if (contradicted.has(fact.id)) { status = 'contradicted'; reason = 'Two definitions or owners exist for this obligation'; }
          else if (!isRequired) {
            // A static fact raises a candidate; it does not prove runtime or process behaviour.
            status = 'candidate';
            reason = (fact.kind ?? 'static') === 'static'
              ? 'A static fact raises a candidate obligation and does not prove runtime behaviour'
              : 'This obligation is not marked required, so it is a candidate';
          } else if (!verifier) { status = 'open'; reason = 'No verifier enumerates this obligation'; }
          else if (verifier.result !== 'pass') { status = 'open'; reason = 'The verifier that enumerates this obligation did not pass'; }
          else if (!verifier.comparable) { status = 'open'; reason = 'The passing verifier has ' + (verifier.authority ?? 'no') + ' authority, which is not comparable to the original observation'; }
          else if (!verifier.evidenceIds.length) { status = 'open'; reason = 'The passing verifier cites no evidence record'; }
          else { status = 'closed'; }
          return { id: fact.id, subject: fact.subject, kind: fact.kind ?? 'static',
            required: isRequired, owner: fact.owner ?? null, status, reason,
            verifierAuthority: verifier ? verifier.authority : null };
        }).sort((a, b) => (a.id < b.id ? -1 : 1));
        const tally = (status) => obligations.filter((entry) => entry.status === status).length;
        return { obligations: obligations.slice(0, MAX_LISTED),
          summary: { total: obligations.length, candidate: tally('candidate'), open: tally('open'),
            closed: tally('closed'), contradicted: tally('contradicted') },
          limitations: ['A closed obligation means a passing replay-authority verifier enumerated it and cited evidence; it does not mean the reconstruction is behaviourally correct',
            'Obligations are built from the facts supplied here, so a fact nobody recorded raises no obligation'] };
      } },
    { name: 'artifact.reconstructionCoverage', version: '1.0.0', outputKeys: ['boundaryId', 'status', 'reasons', 'probes', 'limitations'], effect: 'pure',
      inputSchema: object({
        boundaryId: { type: 'string', minLength: 1, maxLength: 256 },
        obligations: { type: 'array', maxItems: MAX_LISTED, items: {
          type: 'object', additionalProperties: true, required: ['id', 'status'],
          properties: { id: { type: 'string', maxLength: 256 }, status: { type: 'string', maxLength: 64 },
            boundaryId: { type: 'string', maxLength: 256 } } } },
        observations: { type: 'array', maxItems: MAX_LISTED, items: {
          type: 'object', additionalProperties: true, required: ['obligationId'],
          properties: { obligationId: { type: 'string', maxLength: 256 },
            authority: { enum: ['replay', 'observed', 'inferred'] } } } },
      }, ['boundaryId', 'obligations']),
      execute({ boundaryId, obligations, observations = [] }) {
        const scoped = obligations.filter((entry) => (entry.boundaryId ?? boundaryId) === boundaryId);
        if (!scoped.length) {
          return { boundaryId, status: 'unknown', reasons: ['No obligation is scoped to this boundary'],
            probes: ['Build an obligation ledger for this boundary before evaluating its coverage'],
            counts: { obligations: 0 },
            limitations: ['Coverage is evaluated over the obligations supplied; an empty scope is unknown rather than covered'] };
        }
        const authorityOf = new Map();
        for (const observation of observations) {
          const current = authorityOf.get(observation.obligationId);
          const rank = { replay: 3, observed: 2, inferred: 1 };
          if (!current || (rank[observation.authority ?? 'inferred'] ?? 0) > (rank[current] ?? 0)) {
            authorityOf.set(observation.obligationId, observation.authority ?? 'inferred');
          }
        }
        const reasons = [];
        const probes = [];
        const open = scoped.filter((entry) => entry.status !== 'closed');
        // The rule that matters: a passing verifier over inferred evidence cannot promote
        // coverage. That case is unknown, not covered.
        const inferredOnly = scoped.filter((entry) => entry.status === 'closed' && authorityOf.get(entry.id) === 'inferred');
        const unobserved = scoped.filter((entry) => entry.status === 'closed' && !authorityOf.has(entry.id));
        for (const entry of open) {
          reasons.push('Obligation ' + entry.id + ' is ' + entry.status + ' rather than closed');
          probes.push('Supply a passing replay-authority verifier citing evidence for ' + entry.id);
        }
        for (const entry of inferredOnly) {
          reasons.push('Obligation ' + entry.id + ' is closed but its strongest observation is inferred');
          probes.push('Replace the inferred observation for ' + entry.id + ' with a replay observation');
        }
        for (const entry of unobserved) {
          reasons.push('Obligation ' + entry.id + ' is closed but no observation is supplied for it');
          probes.push('Supply the observation that closed ' + entry.id);
        }
        const status = open.length ? 'uncovered' : (inferredOnly.length || unobserved.length) ? 'unknown' : 'covered';
        return { boundaryId, status, reasons: reasons.slice(0, MAX_LISTED), probes: [...new Set(probes)].slice(0, MAX_LISTED),
          counts: { obligations: scoped.length, closed: scoped.length - open.length, open: open.length,
            inferredOnly: inferredOnly.length, unobserved: unobserved.length },
          limitations: ['Covered means every scoped obligation closed with a replay observation; it is a statement about evidence, not about behavioural equivalence',
            'An inferred observation never promotes coverage, so that case is unknown rather than covered'] };
      } },
    { name: 'artifact.compareApplicationVersions', version: '1.0.0', outputKeys: ['changes', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({ left: inventory, right: inventory }, ['left', 'right']),
      execute({ left, right }) {
        const index = (side) => {
          const map = new Map();
          for (const entry of side.entries) {
            const key = (entry.kind ?? 'unspecified') + ':' + entry.name;
            if (!map.has(key)) map.set(key, []);
            map.get(key).push(entry);
          }
          return map;
        };
        const a = index(left);
        const b = index(right);
        const changes = [];
        for (const key of [...new Set([...a.keys(), ...b.keys()])].sort()) {
          const mine = a.get(key) ?? [];
          const theirs = b.get(key) ?? [];
          if (mine.length > 1 || theirs.length > 1) {
            changes.push({ entry: key, state: 'unknown', reason: 'The name occurs more than once on one side, so no correspondence between occurrences is established' });
            continue;
          }
          if (!theirs.length) { changes.push({ entry: key, state: 'removed', reason: null }); continue; }
          if (!mine.length) { changes.push({ entry: key, state: 'added', reason: null }); continue; }
          const digests = mine[0].sha256 !== undefined && theirs[0].sha256 !== undefined;
          if (!digests) {
            changes.push({ entry: key, state: 'present-both', reason: 'Both versions declare this entry, but without digests on both sides a change cannot be decided' });
            continue;
          }
          changes.push({ entry: key, state: mine[0].sha256 === theirs[0].sha256 ? 'unchanged' : 'changed', reason: null });
        }
        const tally = (state) => changes.filter((change) => change.state === state).length;
        return { changes: changes.slice(0, MAX_LISTED),
          summary: { leftVersion: left.version ?? null, rightVersion: right.version ?? null,
            added: tally('added'), removed: tally('removed'), changed: tally('changed'),
            unchanged: tally('unchanged'), presentBoth: tally('present-both'), unknown: tally('unknown') },
          limitations: ['Entries are keyed by kind and name; without a digest on both sides a shared name is reported as present rather than unchanged'] };
      } },
    { name: 'artifact.traceFeature', version: '1.0.0', outputKeys: ['feature', 'matches', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({
        feature: { type: 'string', minLength: 1, maxLength: 1024 },
        inventory,
        limit: { type: 'integer', minimum: 1, maximum: MAX_LISTED },
      }, ['feature', 'inventory']),
      execute({ feature, inventory: supplied, limit = 100 }) {
        const terms = termsOf(feature);
        if (!terms.length) {
          return { feature, matches: [], summary: { terms: 0, matched: 0, scanned: supplied.entries.length },
            limitations: ['The feature description contained no searchable term'] };
        }
        const scored = [];
        for (const entry of supplied.entries) {
          const haystack = (entry.name + ' ' + (entry.source ?? '') + ' ' + (entry.kind ?? '')).toLowerCase();
          const hits = terms.filter((term) => haystack.includes(term));
          if (!hits.length) continue;
          scored.push({ name: entry.name, kind: entry.kind ?? null, source: entry.source ?? null,
            matchedTerms: hits, score: hits.length });
        }
        scored.sort((x, y) => y.score - x.score || (x.name < y.name ? -1 : 1));
        return { feature, terms, matches: scored.slice(0, limit),
          summary: { terms: terms.length, matched: scored.length, scanned: supplied.entries.length,
            allTermsMatched: scored.some((entry) => entry.matchedTerms.length === terms.length) },
          limitations: ['This is a name and source match over the supplied inventory, not a dataflow or call trace: a match names a candidate to look at, and an absence means the inventory does not mention the term',
            'Nothing here establishes that a matched entry implements the feature'] };
      } },
  ];
}
