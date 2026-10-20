import { createHash } from 'node:crypto';
import { loadLanguage, liftInstruction } from './sleigh.mjs';
import { HarnessError } from './value.mjs';
import { readWorkspaceFile } from './workspace-fs.mjs';

/**
 * Control flow recovered from p-code, which is the point of lifting to p-code at all.
 *
 * Everything here reads the lifted operations and nothing else: BRANCH, CBRANCH, BRANCHIND, CALL,
 * CALLIND and RETURN are the same six operations on every architecture, so one implementation
 * recovers basic blocks and a call graph for all 189 language variants. A disassembly-text
 * analysis would need rewriting for each; this does not mention a single architecture.
 *
 * The classification rules are Ghidra's, from `FlowInfo::processInstruction` in flow.cc:270-370,
 * and three of them are easy to get wrong by assumption:
 *
 *   - A branch whose target varnode lives in the **constant space** is not an address. It is a
 *     p-code-relative branch inside one instruction, used for conditional execution and for
 *     string operations, and treating it as an address would invent a jump to a tiny number.
 *   - **CALL and CBRANCH fall through.** Only BRANCH, BRANCHIND and RETURN end flow, and only
 *     when one of them is the *last* operation.
 *   - A **delay slot** means the following instruction executes before the branch takes effect, so
 *     it belongs to the branch rather than being the branch's successor.
 *
 * What it does not do is recover a jump table. An indirect branch has a target this analysis
 * cannot know, and Ghidra defers those to a separate recovery pass over the table structure. They
 * are reported as unresolved rather than dropped, because an unresolved edge is a gap a caller can
 * reason about while a missing one silently looks like dead code.
 */

const MAX_INSTRUCTIONS = 4096;
const MAX_BLOCKS = 2048;
const MAX_ENTRIES = 64;

const fail = (code, message, detail) => { throw new HarnessError(code, message, detail); };

const OP_BRANCH = 'BRANCH';
const OP_CBRANCH = 'CBRANCH';
const OP_BRANCHIND = 'BRANCHIND';
const OP_CALL = 'CALL';
const OP_CALLIND = 'CALLIND';
const OP_RETURN = 'RETURN';
// Only these three end flow, and only as the last operation. flow.cc:361-363.
const TERMINAL_OPS = new Set([OP_BRANCH, OP_BRANCHIND, OP_RETURN]);

const hex = (value) => `0x${value.toString(16)}`;

/**
 * What one instruction does to control flow.
 *
 * Returns the branch targets as absolute addresses, the call targets separately because a call
 * returns and a branch does not, and whether the instruction falls through. An intra-instruction
 * relative branch is counted but contributes no edge: its target is a p-code operation inside this
 * instruction, not an address.
 */
function classifyFlow(lifted) {
  const branchTargets = [];
  const callTargets = [];
  let indirectBranch = false;
  let indirectCall = false;
  let returns = false;
  let relativeBranches = 0;
  let last = null;

  for (const op of lifted.pcode) {
    // A synthetic LOAD or STORE inserted for a dynamic varnode is not the instruction's own
    // operation and must not be mistaken for its last one.
    if (!op.synthetic) last = op.op;
    const target = op.inputs[0] ?? null;
    switch (op.op) {
      case OP_BRANCH:
      case OP_CBRANCH:
        if (!target) break;
        if (target.space === 'const') relativeBranches += 1;
        else branchTargets.push(BigInt(target.offset));
        break;
      case OP_BRANCHIND:
        indirectBranch = true;
        break;
      case OP_CALL:
        if (target && target.space !== 'const') callTargets.push(BigInt(target.offset));
        else indirectCall = true;
        break;
      case OP_CALLIND:
        indirectCall = true;
        break;
      case OP_RETURN:
        returns = true;
        break;
      default:
        break;
    }
  }

  // flow.cc: with no explicit relative branch to the end of the instruction, fallthrough is read
  // off the last operation. A CBRANCH or a CALL therefore falls through; a BRANCH does not.
  const fallsThrough = last === null ? true : !TERMINAL_OPS.has(last);
  return { branchTargets, callTargets, indirectBranch, indirectCall, returns, relativeBranches, fallsThrough, lastOp: last };
}

/**
 * Follow flow from the entry points, decoding only what is reachable.
 *
 * A linear sweep would decode data as instructions wherever it happened to land. Following flow
 * instead means every instruction reported was reached from an entry by a path this analysis can
 * name, which is the difference between a control-flow graph and a guess about where code starts.
 */
function traceReachable(language, bytes, baseAddress, entries, options) {
  const decoded = new Map();
  const queue = [...entries];
  const limit = options.limit ?? 1024;
  const seen = new Set(entries.map(String));
  let truncated = null;

  const offsetOf = (address) => Number(address - baseAddress);
  while (queue.length) {
    if (decoded.size >= limit) { truncated = 'instruction_limit'; break; }
    const address = queue.shift();
    if (decoded.has(String(address))) continue;
    const offset = offsetOf(address);
    if (offset < 0 || offset >= bytes.length) continue;

    let lifted;
    try {
      lifted = liftInstruction(language, bytes.subarray(offset, Math.min(bytes.length, offset + 16)),
        { address, contextValues: options.contextValues });
    } catch (error) {
      decoded.set(String(address), { address, offset, decoded: false, reason: 'decode_failed',
        detail: error?.code ?? 'unknown', length: 0, flow: null });
      continue;
    }
    if (!lifted.decoded) {
      decoded.set(String(address), { address, offset, decoded: false, reason: lifted.reason, length: 0, flow: null });
      continue;
    }

    const flow = classifyFlow(lifted);
    // A delay slot belongs to this instruction: the following bytes execute before the branch
    // takes effect, so they are not a successor and flow resumes past them. The count is a
    // minimum byte count, so whole instructions are consumed until it is covered, which is what
    // SleighBuilder::delaySlot does.
    let delaySlotLength = 0;
    const delaySlots = [];
    if (lifted.delaySlotBytes > 0) {
      let at = offset + lifted.length;
      while (delaySlotLength < lifted.delaySlotBytes && at < bytes.length && delaySlots.length < 4) {
        let slot;
        try {
          slot = liftInstruction(language, bytes.subarray(at, Math.min(bytes.length, at + 16)),
            { address: baseAddress + BigInt(at), contextValues: options.contextValues });
        } catch { break; }
        if (!slot.decoded || slot.length <= 0) break;
        delaySlots.push({ address: baseAddress + BigInt(at), length: slot.length, text: slot.text });
        delaySlotLength += slot.length;
        at += slot.length;
      }
    }

    const record = { address, offset, decoded: true, reason: null, length: lifted.length,
      text: lifted.text, mnemonic: lifted.mnemonic, pcodeOps: lifted.pcode.length,
      delaySlotBytes: lifted.delaySlotBytes, delaySlotLength, delaySlots, flow };
    decoded.set(String(address), record);

    const next = address + BigInt(lifted.length + delaySlotLength);
    record.fallThrough = flow.fallsThrough ? next : null;
    if (flow.fallsThrough && !seen.has(String(next))) { seen.add(String(next)); queue.push(next); }
    for (const target of flow.branchTargets) {
      if (!seen.has(String(target))) { seen.add(String(target)); queue.push(target); }
    }
    // A call target is followed only when asked for: a called address begins its own region, and
    // following it by default would merge two functions into one graph.
    for (const target of flow.callTargets) {
      if (options.followCalls && !seen.has(String(target))) { seen.add(String(target)); queue.push(target); }
    }
  }
  return { decoded, truncated };
}

/** Basic blocks, from the leaders a flow graph implies. */
function buildBlocks(records, entries) {
  const ordered = [...records.values()].filter((record) => record.decoded)
    .sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
  const byAddress = new Map(ordered.map((record) => [String(record.address), record]));

  const leaders = new Set(entries.map(String));
  for (const record of ordered) {
    // After a branch or a return the next instruction begins a block; after a call it does not.
    // flow.cc sets startbasic for CBRANCH, BRANCH, BRANCHIND and RETURN only.
    const ends = record.flow.branchTargets.length || record.flow.indirectBranch || record.flow.returns;
    if (ends) {
      const after = record.address + BigInt(record.length + record.delaySlotLength);
      if (byAddress.has(String(after))) leaders.add(String(after));
    }
    for (const target of record.flow.branchTargets) leaders.add(String(target));
  }

  // Partition first, then read each block's successors off its last instruction. Deciding
  // successors while partitioning misses the case where a block ends only because the next
  // instruction is a leader — the join point after an if — and that block would have been
  // reported with no successors at all, which reads as unreachable code rather than a join.
  const blocks = [];
  let current = null;
  for (const record of ordered) {
    const ends = current ? (() => {
      const flow = current.instructions[current.instructions.length - 1].flow;
      return flow.branchTargets.length || flow.indirectBranch || flow.returns || !flow.fallsThrough;
    })() : true;
    if (!current || ends || leaders.has(String(record.address))) {
      current = { start: record.address, end: record.address, instructions: [], successors: [], kind: 'linear' };
      blocks.push(current);
      if (blocks.length > MAX_BLOCKS) fail('FLOW_LIMIT', 'The region contains more basic blocks than this analysis builds');
    }
    current.instructions.push(record);
    current.end = record.address + BigInt(record.length + record.delaySlotLength);
  }

  for (const block of blocks) {
    const last = block.instructions[block.instructions.length - 1];
    const flow = last.flow;
    if (flow.returns) block.kind = 'return';
    else if (flow.indirectBranch) block.kind = 'indirect';
    else if (flow.branchTargets.length && flow.fallsThrough) block.kind = 'conditional';
    else if (flow.branchTargets.length) block.kind = 'branch';
    for (const target of flow.branchTargets) block.successors.push({ to: target, kind: 'branch' });
    if (flow.fallsThrough && last.fallThrough !== null) block.successors.push({ to: last.fallThrough, kind: 'fallthrough' });
  }
  return blocks;
}

/**
 * Recover basic blocks and call edges for a byte range.
 *
 * `entries` are the addresses to start from. Nothing is decoded that was not reached from one of
 * them, so an address appearing here is an address this analysis can explain.
 */
export function recoverControlFlow(language, bytes, options = {}) {
  const baseAddress = options.address === undefined ? 0n : BigInt(options.address);
  const entries = (options.entries?.length ? options.entries : [baseAddress]).map((entry) => BigInt(entry));
  if (entries.length > MAX_ENTRIES) fail('FLOW_LIMIT', 'More entry points were supplied than this analysis follows');

  const { decoded, truncated } = traceReachable(language, bytes, baseAddress, entries, options);
  const blocks = buildBlocks(decoded, entries);

  const calls = [];
  const unresolved = [];
  let relativeBranches = 0;
  for (const record of decoded.values()) {
    if (!record.decoded) { unresolved.push({ address: hex(record.address), kind: 'undecodable', reason: record.reason }); continue; }
    relativeBranches += record.flow.relativeBranches;
    for (const target of record.flow.callTargets) calls.push({ from: hex(record.address), to: hex(target), kind: 'direct' });
    if (record.flow.indirectCall) unresolved.push({ address: hex(record.address), kind: 'indirect_call', reason: 'The target is computed at run time' });
    if (record.flow.indirectBranch) unresolved.push({ address: hex(record.address), kind: 'indirect_branch', reason: 'The target is computed at run time, which usually means a jump table' });
  }

  const limitations = [];
  if (truncated) limitations.push('Tracing stopped at the instruction limit, so the graph below covers only what was reached first');
  if (unresolved.some((entry) => entry.kind === 'indirect_branch')) {
    limitations.push('An indirect branch has a target this analysis does not recover: reading a jump table needs the table itself, which Ghidra also defers to a separate pass. The edge is reported as unresolved rather than omitted, because a missing edge looks like dead code');
  }
  if (relativeBranches) {
    limitations.push(`${relativeBranches} branch(es) target a p-code operation inside their own instruction rather than an address. They are counted and contribute no edge, and p-code labels are not resolved here, so flow within a single instruction is not modelled`);
  }
  if (!options.followCalls && calls.length) {
    limitations.push('Call targets are reported as edges but not traced: a called address begins its own region, and following it would merge two functions into one graph');
  }
  limitations.push('Reachability is from the supplied entry points only. Code reached solely through an unresolved indirect branch does not appear, and bytes that are data were never decoded');

  const ordered = [...decoded.values()].filter((record) => record.decoded)
    .sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
  return {
    entries: entries.map(hex),
    instructions: ordered.map((record) => ({
      address: hex(record.address), length: record.length, text: record.text,
      pcodeOps: record.pcodeOps,
      fallThrough: record.fallThrough === null ? null : hex(record.fallThrough),
      branchTargets: record.flow.branchTargets.map(hex),
      callTargets: record.flow.callTargets.map(hex),
      indirect: record.flow.indirectBranch ? 'branch' : record.flow.indirectCall ? 'call' : null,
      returns: record.flow.returns,
      delaySlotBytes: record.delaySlotBytes,
      delaySlots: record.delaySlots.map((slot) => ({ address: hex(slot.address), length: slot.length, text: slot.text })),
    })),
    blocks: blocks.map((block) => ({
      start: hex(block.start), end: hex(block.end), kind: block.kind,
      instructions: block.instructions.length,
      successors: block.successors.map((edge) => ({ to: hex(edge.to), kind: edge.kind })),
    })),
    calls, unresolved,
    counts: {
      instructions: ordered.length, blocks: blocks.length, calls: calls.length,
      unresolved: unresolved.length, relativeBranches,
      returnBlocks: blocks.filter((block) => block.kind === 'return').length,
      conditionalBlocks: blocks.filter((block) => block.kind === 'conditional').length,
    },
    limitations,
  };
}

// ---------------------------------------------------------------------------------------------
// The tool
// ---------------------------------------------------------------------------------------------

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
// An address is checked in execute, not by the schema. The kernel's schema subset is deliberately
// explicit — validateSchema refuses any keyword outside it — and `pattern` is not in the set, so
// declaring one would make every plan using this tool fail with INVALID_SCHEMA at compile. The
// shape is still enforced, just where a refusal can say which address was wrong.
const ADDRESS = { type: 'string', maxLength: 18 };
const ADDRESS_RE = /^(0x)?[0-9a-fA-F]{1,16}$/;

export function makeControlFlowTools() {
  const readBytes = (context, relative, divisor) =>
    readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / divisor));
  const parseAddress = (value) => BigInt(value.startsWith('0x') ? value : `0x${value}`);

  return [Object.freeze({
    name: 'artifact.controlFlow', version: '1.0.0', effect: 'read',
    outputKeys: ['table', 'path', 'sha256', 'supported', 'reason', 'entries', 'instructions', 'blocks', 'calls', 'unresolved', 'counts', 'limitations', 'untrusted'],
    inputSchema: object({
      table: string, path: string,
      offset: { type: 'integer', minimum: 0 },
      length: { type: 'integer', minimum: 1, maximum: 1048576 },
      address: ADDRESS,
      entries: { type: 'array', minItems: 1, maxItems: MAX_ENTRIES, items: ADDRESS },
      limit: { type: 'integer', minimum: 1, maximum: MAX_INSTRUCTIONS },
      followCalls: { type: 'boolean' },
      context: { type: 'object', additionalProperties: { type: 'integer' } },
    }, ['table', 'path']),
    execute(input, context) {
      const limitations = [];
      const tableBytes = readBytes(context, input.table, 4);
      const targetBytes = readBytes(context, input.path, 4);
      const base = { table: input.table, path: input.path, sha256: sha256(targetBytes), untrusted: true };
      const empty = { entries: [], instructions: [], blocks: [], calls: [], unresolved: [], counts: {} };

      let language;
      try { language = loadLanguage(tableBytes); }
      catch (error) {
        return { ...base, supported: false, reason: 'table_unreadable', detail: error?.message ?? null, ...empty, limitations };
      }

      const offset = input.offset ?? 0;
      if (offset >= targetBytes.length) {
        return { ...base, supported: false, reason: 'offset_past_end',
          detail: 'The requested offset lies past the end of the file', ...empty, limitations };
      }
      const end = input.length === undefined ? targetBytes.length : Math.min(targetBytes.length, offset + input.length);
      const slice = targetBytes.subarray(offset, end);
      // A malformed address is refused rather than defaulted to zero: a wrong base address
      // silently relocates every branch target and call edge this reports.
      for (const candidate of [input.address, ...(input.entries ?? [])]) {
        if (candidate !== undefined && !ADDRESS_RE.test(candidate)) {
          return { ...base, supported: false, reason: 'invalid_address',
            detail: 'An address must be up to 16 hexadecimal digits, optionally prefixed with 0x', ...empty, limitations };
        }
      }
      const address = input.address === undefined ? 0n : parseAddress(input.address);
      const entries = (input.entries ?? []).map(parseAddress);
      // An entry outside the selected range would silently contribute nothing, which reads as a
      // function with no code rather than as a mistake in the request.
      for (const entry of entries) {
        if (entry < address || entry >= address + BigInt(slice.length)) {
          return { ...base, supported: false, reason: 'entry_outside_range',
            detail: `Entry point ${hex(entry)} is not inside the selected range`, ...empty, limitations };
        }
      }

      let recovered;
      try {
        recovered = recoverControlFlow(language, slice, {
          address, entries, limit: input.limit ?? 512,
          followCalls: input.followCalls === true, contextValues: input.context,
        });
      } catch (error) {
        return { ...base, supported: false, reason: error?.code === 'SLEIGH_CONTEXT' ? 'context_rejected' : 'flow_limit',
          detail: error?.message ?? null, ...empty, limitations };
      }

      if (!input.context) {
        limitations.push('No initial context was supplied, so a language whose decode depends on context decodes in whatever its zeroed context selects; the defaults are declared in the .pspec and readable with artifact.ghidraProcessorSpec');
      }
      limitations.push(...recovered.limitations);
      limitations.push('A control-flow graph is an interpretation of bytes under one chosen language; selecting the wrong table produces a confident graph of a program that does not exist');

      return { ...base, supported: true, reason: null, ...recovered, limitations };
    },
  })];
}
