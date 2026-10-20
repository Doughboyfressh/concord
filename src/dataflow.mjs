import { createHash } from 'node:crypto';
import { loadLanguage, liftInstruction } from './sleigh.mjs';
import { recoverControlFlow } from './control-flow.mjs';
import { HarnessError } from './value.mjs';
import { readWorkspaceFile } from './workspace-fs.mjs';

/**
 * Reaching definitions over p-code varnodes: which write supplies the value each read observes.
 *
 * This is the layer that answers questions about data rather than control — which registers a
 * function reads before writing them, which it clobbers, what a value is built from, what a value
 * goes on to affect. Like everything above it, it reads only p-code, so it is one implementation
 * for all 189 language variants.
 *
 * It is a classic forward fixpoint, not Ghidra's SSA. `heritage.cc` builds static single
 * assignment with phi nodes and does serious work on memory aliasing; this computes reaching
 * definitions and leaves a join as what it is — a use with more than one reaching definition.
 * That is a weaker result, and saying so is the point: a use with three reaching definitions is an
 * honest description of a join, where inventing a phi node would imply an analysis not performed.
 *
 * The rule that decides correctness is the kill rule, and it is Ghidra's, from `Varnode::contains`
 * and `Varnode::characterizeOverlap` in varnode.cc:105-170:
 *
 *   A definition kills a previous one only if it **fully covers** it. Storage that merely overlaps
 *   is left alive and reported as partially overwritten.
 *
 * Getting that wrong is the classic register-dataflow bug. On x86 a write to AL must not kill EAX,
 * because three of EAX's bytes still hold what they held before. A kill rule based on "same space
 * and overlapping" would silently discard the surviving definition and report a value as coming
 * from the wrong place.
 *
 * Two kinds of storage are deliberately outside the analysis, and both are declared rather than
 * quietly approximated:
 *
 *   - **The constant space is not storage.** varnode.cc returns "non-comparable" for it, and a
 *     literal has no definition to reach.
 *   - **Memory reached through a pointer is not resolved.** A STORE whose address is computed can
 *     alias anything, so no LOAD is claimed to read any particular STORE. Ghidra spends a large
 *     part of heritage.cc on exactly this, and pretending to a resolution that was not performed
 *     would be the worst available error here.
 */

const MAX_OPS = 16384;
const MAX_LISTED = 512;
const MAX_FIXPOINT_ROUNDS = 256;
const MAX_SLICE_STEPS = 2048;

const fail = (code, message, detail) => { throw new HarnessError(code, message, detail); };
const hex = (value) => `0x${value.toString(16)}`;

/**
 * One piece of storage: a space, a start and a size. The constant space is excluded because a
 * literal is a value rather than a location, which is what varnode.cc encodes by returning
 * "non-comparable spaces" for it.
 */
const isStorage = (varnode) => Boolean(varnode) && typeof varnode.space === 'string'
  && varnode.space !== 'const' && varnode.size > 0;

const rangeOf = (varnode) => {
  const start = BigInt(varnode.offset);
  return { space: varnode.space, start, end: start + BigInt(varnode.size), size: varnode.size };
};

/** Varnode::contains — does `outer` fully cover `inner`? Only this kills a definition. */
const covers = (outer, inner) => outer.space === inner.space
  && outer.start <= inner.start && inner.end <= outer.end;
/** Varnode::intersects — do they share any byte? A partial overlap is not a kill. */
const intersects = (a, b) => a.space === b.space && a.start < b.end && b.start < a.end;

/**
 * Flatten a region into p-code operations in block order, each tagged with where it came from.
 *
 * Operations inside one instruction are taken in the order the template emitted them, which is
 * their execution order unless the instruction contains a p-code-relative branch. Those are
 * counted by the control-flow pass and reported here, because flow inside a single instruction is
 * not modelled and a conditional sequence would make the straight-line reading optimistic.
 */
function flatten(language, bytes, baseAddress, flow, contextValues) {
  const blocks = [];
  let total = 0;
  let loads = 0;
  let stores = 0;

  for (const block of flow.blocks) {
    const entry = { start: block.start, kind: block.kind, ops: [], successors: block.successors.map((edge) => edge.to) };
    for (const instruction of flow.instructions) {
      if (BigInt(instruction.address) < BigInt(block.start) || BigInt(instruction.address) >= BigInt(block.end)) continue;
      const offset = Number(BigInt(instruction.address) - baseAddress);
      const lifted = liftInstruction(language, bytes.subarray(offset, Math.min(bytes.length, offset + 16)),
        { address: BigInt(instruction.address), contextValues });
      if (!lifted.decoded) continue;
      lifted.pcode.forEach((op, index) => {
        if (++total > MAX_OPS) fail('DATAFLOW_LIMIT', 'The region lifts to more p-code operations than this analysis tracks');
        if (op.op === 'LOAD') loads += 1;
        if (op.op === 'STORE') stores += 1;
        entry.ops.push({ id: `${instruction.address}:${index}`, address: instruction.address, opIndex: index,
          op: op.op, output: op.output, inputs: op.inputs });
      });
    }
    blocks.push(entry);
  }
  return { blocks, total, loads, stores };
}

/**
 * Reaching definitions, as a forward fixpoint over the blocks.
 *
 * `OUT[b] = (IN[b] minus what b kills) union what b generates`, meeting by union over
 * predecessors. The meet is union because a value may arrive along any path, and that is exactly
 * why a use can have several reaching definitions.
 */
function reachingDefinitions(blocks) {
  const definitions = new Map();
  const index = new Map(blocks.map((block, position) => [block.start, position]));
  const predecessors = blocks.map(() => []);
  blocks.forEach((block, position) => {
    for (const successor of block.successors) {
      const target = index.get(successor);
      if (target !== undefined) predecessors[target].push(position);
    }
  });

  // Per block: the definitions it generates, and the ranges it fully overwrites.
  const generated = blocks.map(() => new Map());
  const killRanges = blocks.map(() => []);
  blocks.forEach((block, position) => {
    for (const op of block.ops) {
      if (!isStorage(op.output)) continue;
      const range = rangeOf(op.output);
      // A later definition in the same block replaces an earlier one it fully covers.
      for (const [id, previous] of [...generated[position]]) {
        if (covers(range, previous.range)) generated[position].delete(id);
      }
      const definition = { id: op.id, address: op.address, opIndex: op.opIndex, op: op.op, range, varnode: op.output };
      definitions.set(op.id, definition);
      generated[position].set(op.id, definition);
      killRanges[position].push(range);
    }
  });

  const incoming = blocks.map(() => new Map());
  const outgoing = blocks.map((block, position) => new Map(generated[position]));
  let changed = true;
  let rounds = 0;
  while (changed) {
    if (++rounds > MAX_FIXPOINT_ROUNDS) fail('DATAFLOW_LIMIT', 'Reaching definitions did not converge within the round budget');
    changed = false;
    blocks.forEach((block, position) => {
      const union = new Map();
      for (const predecessor of predecessors[position]) {
        for (const [id, definition] of outgoing[predecessor]) union.set(id, definition);
      }
      incoming[position] = union;
      const result = new Map();
      for (const [id, definition] of union) {
        // Survives the block unless some definition in it fully covers this one.
        if (!killRanges[position].some((range) => covers(range, definition.range))) result.set(id, definition);
      }
      for (const [id, definition] of generated[position]) result.set(id, definition);
      if (result.size !== outgoing[position].size
        || [...result.keys()].some((id) => !outgoing[position].has(id))) {
        outgoing[position] = result;
        changed = true;
      }
    });
  }
  return { definitions, incoming, outgoing, rounds };
}

/**
 * Which operands of an operation are reads of storage, and which are something else.
 *
 * The first input of BRANCH, CBRANCH and CALL is a destination *address*, not a value fetched from
 * that address, so counting it as a read reports every branch as reading four bytes of code. The
 * indirect forms are the opposite: BRANCHIND and CALLIND read a computed target, and RETURN reads
 * the address to return to, so those are genuine reads. LOAD and STORE name their space in input
 * zero as a constant, which `isStorage` already excludes.
 */
const ADDRESS_OPERAND = new Map([['BRANCH', 0], ['CBRANCH', 0], ['CALL', 0]]);

/** Walk each block with its incoming set, recording what reaches every read. */
function buildUses(blocks, incoming) {
  const uses = [];
  blocks.forEach((block, position) => {
    const live = new Map(incoming[position]);
    for (const op of block.ops) {
      op.inputs.forEach((input, inputIndex) => {
        if (ADDRESS_OPERAND.get(op.op) === inputIndex) return;
        if (!isStorage(input)) return;
        const range = rangeOf(input);
        const reaching = [];
        const partial = [];
        for (const definition of live.values()) {
          if (covers(definition.range, range)) reaching.push(definition.id);
          else if (intersects(definition.range, range)) partial.push(definition.id);
        }
        uses.push({ id: `${op.id}:${inputIndex}`, address: op.address, opIndex: op.opIndex,
          op: op.op, inputIndex, varnode: input, range, reaching, partial });
      });
      // The definition this operation makes takes effect after its own reads.
      if (!isStorage(op.output)) continue;
      const range = rangeOf(op.output);
      for (const [id, definition] of [...live]) if (covers(range, definition.range)) live.delete(id);
      live.set(op.id, { id: op.id, address: op.address, opIndex: op.opIndex, op: op.op, range, varnode: op.output });
    }
  });
  return uses;
}

/** Merge storage ranges that touch, so a register read in pieces reports as one input. */
function mergeRanges(ranges) {
  const bySpace = new Map();
  for (const range of ranges) {
    if (!bySpace.has(range.space)) bySpace.set(range.space, []);
    bySpace.get(range.space).push(range);
  }
  const merged = [];
  for (const [space, list] of bySpace) {
    list.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    let current = null;
    for (const range of list) {
      // Overlapping, not merely touching. ESP at register:0x10 and EBP at register:0x14 are
      // adjacent and are different registers; merging them would invent an eight byte location
      // that nothing reads. Ranges that genuinely overlap — AX inside EAX — do collapse.
      if (current && range.start < current.end) {
        if (range.end > current.end) current.end = range.end;
        continue;
      }
      current = { space, start: range.start, end: range.end };
      merged.push(current);
    }
  }
  return merged.map((range) => ({ space: range.space, offset: hex(range.start), size: Number(range.end - range.start) }));
}

const listed = (items, limitations, label) => {
  if (items.length <= MAX_LISTED) return items;
  limitations.push(`Only the first ${MAX_LISTED} of ${items.length} ${label} are listed; the counts are the true totals`);
  return items.slice(0, MAX_LISTED);
};

/**
 * Analyse one region's dataflow.
 *
 * The summary is the part worth having: which storage the region reads before writing — its
 * inputs — and which it writes. That is the evidence a calling convention is recovered from, and
 * it can be checked against what the `.cspec` declares, which is two independently read sources
 * agreeing or not.
 */
export function analyseDataflow(language, bytes, options = {}) {
  const baseAddress = options.address === undefined ? 0n : BigInt(options.address);
  const flow = recoverControlFlow(language, bytes, {
    address: baseAddress, entries: options.entries, limit: options.limit ?? 512,
    followCalls: false, contextValues: options.contextValues,
  });
  const limitations = [];
  const flat = flatten(language, bytes, baseAddress, flow, options.contextValues);
  const { definitions, incoming, outgoing, rounds } = reachingDefinitions(flat.blocks);
  const uses = buildUses(flat.blocks, incoming);

  // An input is storage read with nothing inside the region defining it: the value came from
  // before this region, which is what makes it an argument or an inherited register.
  const external = uses.filter((use) => !use.reaching.length);
  const partiallyExternal = external.filter((use) => use.partial.length > 0);
  const inputs = mergeRanges(external.map((use) => use.range));
  const defined = mergeRanges([...definitions.values()].map((definition) => definition.range));

  // Live at exit: definitions that reach the end of a block that returns, and are therefore this
  // region's observable effect on its caller.
  const liveAtExit = new Map();
  flat.blocks.forEach((block, position) => {
    if (block.kind !== 'return') return;
    for (const [id, definition] of outgoing[position]) liveAtExit.set(id, definition);
  });
  const outputs = mergeRanges([...liveAtExit.values()].map((definition) => definition.range));
  const withoutTemporaries = (list) => list.filter((entry) => entry.space !== 'unique');

  if (flat.loads || flat.stores) {
    limitations.push(`This region has ${flat.loads} LOAD and ${flat.stores} STORE operations. Memory reached through a computed pointer is not resolved, so no load is attributed to any store: the value a load observes is treated as coming from outside the analysis. Ghidra resolves part of this in heritage.cc, and claiming a resolution that was not performed would be worse than reporting none`);
  }
  if (defined.some((entry) => entry.space === 'unique') || inputs.some((entry) => entry.space === 'unique')) {
    limitations.push('Unique-space varnodes are the instruction-local temporaries SLEIGH allocates. A language that needs them distinct across instructions declares a uniqmask and most declare none, so a unique-space definition is not followed past the instruction that made it and is excluded from the input and output summaries');
  }
  if (flow.counts.unresolved) {
    limitations.push(`The control-flow graph this rests on has ${flow.counts.unresolved} unresolved point(s), so a path may exist that was never walked and these reaching sets are a lower bound`);
  }
  if (flow.counts.relativeBranches) {
    limitations.push(`${flow.counts.relativeBranches} instruction(s) branch within their own p-code, so their operations are read in emitted order as though straight-line; a conditional sequence inside one instruction is not modelled`);
  }
  limitations.push('These are reaching definitions, not static single assignment: a use with several reaching definitions is a join reported as it is, rather than merged behind a phi node that nothing here computed');
  limitations.push('A definition kills a previous one only when it fully covers it, so a narrow write leaves a wider definition alive and partially overwritten — writing one byte of a register does not discard the rest');

  return {
    entries: flow.entries,
    summary: {
      inputs: withoutTemporaries(inputs),
      outputs: withoutTemporaries(outputs),
      defined: withoutTemporaries(defined),
      temporaries: defined.filter((entry) => entry.space === 'unique').length,
    },
    definitions: [...definitions.values()].map((definition) => ({
      id: definition.id, address: definition.address, op: definition.op,
      varnode: { space: definition.varnode.space, offset: definition.varnode.offset, size: definition.varnode.size },
    })),
    uses: uses.map((use) => ({
      id: use.id, address: use.address, op: use.op, inputIndex: use.inputIndex,
      varnode: { space: use.varnode.space, offset: use.varnode.offset, size: use.varnode.size },
      reaching: use.reaching, partiallyOverwritten: use.partial,
      external: use.reaching.length === 0,
    })),
    counts: {
      blocks: flat.blocks.length, instructions: flow.counts.instructions, ops: flat.total,
      definitions: definitions.size, uses: uses.length,
      externalReads: external.length, partialReads: partiallyExternal.length,
      joins: uses.filter((use) => use.reaching.length > 1).length,
      loads: flat.loads, stores: flat.stores, fixpointRounds: rounds,
    },
    limitations,
  };
}

/**
 * A slice: everything a value is built from, or everything it goes on to affect.
 *
 * Backward from a read gives the definitions that supply it, then the reads inside those
 * definitions' operations, transitively — the derivation of a value. Forward from a definition
 * gives the reads it reaches and the definitions those reads feed, transitively — its influence.
 * Both stop at the region boundary and at an unresolved memory access, and say which.
 */
export function sliceDataflow(analysis, options = {}) {
  const direction = options.direction === 'forward' ? 'forward' : 'backward';
  const definitionById = new Map(analysis.definitions.map((definition) => [definition.id, definition]));
  const opIdOf = (useId) => useId.slice(0, useId.lastIndexOf(':'));
  const usesByOp = new Map();
  for (const use of analysis.uses) {
    const opId = opIdOf(use.id);
    if (!usesByOp.has(opId)) usesByOp.set(opId, []);
    usesByOp.get(opId).push(use);
  }
  const usesByReachingDefinition = new Map();
  for (const use of analysis.uses) {
    for (const id of use.reaching) {
      if (!usesByReachingDefinition.has(id)) usesByReachingDefinition.set(id, []);
      usesByReachingDefinition.get(id).push(use);
    }
  }

  const steps = [];
  const boundaries = [];
  const seen = new Set();
  const queue = [];

  if (direction === 'backward') {
    const start = analysis.uses.find((use) => use.id === options.from);
    if (!start) fail('DATAFLOW_SLICE', 'No read with that identifier exists in this analysis', { from: options.from ?? null });
    queue.push({ kind: 'use', entry: start });
  } else {
    const start = definitionById.get(options.from);
    if (!start) fail('DATAFLOW_SLICE', 'No definition with that identifier exists in this analysis', { from: options.from ?? null });
    queue.push({ kind: 'definition', entry: start });
  }

  while (queue.length) {
    const item = queue.shift();
    const key = `${item.kind}:${item.entry.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (seen.size > MAX_SLICE_STEPS) { boundaries.push({ at: null, reason: 'slice_budget' }); break; }

    if (item.kind === 'use') {
      const use = item.entry;
      steps.push({ kind: 'use', id: use.id, address: use.address, op: use.op, varnode: use.varnode });
      if (use.external) {
        boundaries.push({ at: use.id, reason: 'defined_outside_region', varnode: use.varnode });
        continue;
      }
      for (const id of use.reaching) {
        const definition = definitionById.get(id);
        if (definition) queue.push({ kind: 'definition', entry: definition });
      }
      continue;
    }

    const definition = item.entry;
    steps.push({ kind: 'definition', id: definition.id, address: definition.address, op: definition.op, varnode: definition.varnode });
    // A loaded value came through memory this analysis does not model, so the derivation stops
    // here rather than silently appearing complete.
    if (definition.op === 'LOAD') {
      boundaries.push({ at: definition.id, reason: 'value_loaded_from_unresolved_memory', varnode: definition.varnode });
    }
    if (direction === 'backward') {
      for (const use of usesByOp.get(definition.id) ?? []) queue.push({ kind: 'use', entry: use });
      continue;
    }
    for (const use of usesByReachingDefinition.get(definition.id) ?? []) {
      queue.push({ kind: 'use', entry: use });
      const next = definitionById.get(opIdOf(use.id));
      if (next) queue.push({ kind: 'definition', entry: next });
    }
  }

  const limitations = [
    'A slice follows reaching definitions, so where a read has several it follows all of them: the result is every path the value could have come from, not the one it took on any particular run',
    'A value loaded from memory ends the slice, because no store is attributed to any load here; the derivation continues through memory this analysis does not model',
  ];
  return {
    direction, from: options.from ?? null,
    steps: steps.slice(0, MAX_LISTED), boundaries,
    counts: { steps: steps.length, boundaries: boundaries.length, truncated: steps.length > MAX_LISTED },
    limitations,
  };
}

// ---------------------------------------------------------------------------------------------
// The tool
// ---------------------------------------------------------------------------------------------

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const ADDRESS_RE = /^(0x)?[0-9a-fA-F]{1,16}$/;

export function makeDataflowTools() {
  const readBytes = (context, relative, divisor) =>
    readWorkspaceFile(context.workspaceRoot, relative, Math.floor(context.policy.maxOutputBytes / divisor));
  const parseAddress = (value) => BigInt(value.startsWith('0x') ? value : `0x${value}`);

  return [Object.freeze({
    name: 'artifact.dataflow', version: '1.0.0', effect: 'read',
    outputKeys: ['table', 'path', 'sha256', 'supported', 'reason', 'entries', 'summary', 'definitions', 'uses', 'slice', 'counts', 'limitations', 'untrusted'],
    inputSchema: object({
      table: string, path: string,
      offset: { type: 'integer', minimum: 0 },
      length: { type: 'integer', minimum: 1, maximum: 1048576 },
      address: { type: 'string', maxLength: 18 },
      entries: { type: 'array', minItems: 1, maxItems: 64, items: { type: 'string', maxLength: 18 } },
      limit: { type: 'integer', minimum: 1, maximum: 4096 },
      detail: { type: 'boolean' },
      context: { type: 'object', additionalProperties: { type: 'integer' } },
      sliceFrom: { type: 'string', maxLength: 128 },
      sliceDirection: { type: 'string', enum: ['backward', 'forward'] },
    }, ['table', 'path']),
    execute(input, context) {
      const limitations = [];
      const tableBytes = readBytes(context, input.table, 4);
      const targetBytes = readBytes(context, input.path, 4);
      const base = { table: input.table, path: input.path, sha256: sha256(targetBytes), untrusted: true };
      const empty = { entries: [], summary: null, definitions: [], uses: [], slice: null, counts: {} };

      let language;
      try { language = loadLanguage(tableBytes); }
      catch (error) {
        return { ...base, supported: false, reason: 'table_unreadable', detail: error?.message ?? null, ...empty, limitations };
      }
      for (const candidate of [input.address, ...(input.entries ?? [])]) {
        if (candidate !== undefined && !ADDRESS_RE.test(candidate)) {
          return { ...base, supported: false, reason: 'invalid_address',
            detail: 'An address must be up to 16 hexadecimal digits, optionally prefixed with 0x', ...empty, limitations };
        }
      }
      const offset = input.offset ?? 0;
      if (offset >= targetBytes.length) {
        return { ...base, supported: false, reason: 'offset_past_end',
          detail: 'The requested offset lies past the end of the file', ...empty, limitations };
      }
      const end = input.length === undefined ? targetBytes.length : Math.min(targetBytes.length, offset + input.length);
      const region = targetBytes.subarray(offset, end);
      const address = input.address === undefined ? 0n : parseAddress(input.address);
      const entries = (input.entries ?? []).map(parseAddress);
      for (const entry of entries) {
        if (entry < address || entry >= address + BigInt(region.length)) {
          return { ...base, supported: false, reason: 'entry_outside_range',
            detail: `Entry point ${hex(entry)} is not inside the selected range`, ...empty, limitations };
        }
      }

      let analysis;
      try {
        analysis = analyseDataflow(language, region, {
          address, entries, limit: input.limit ?? 512, contextValues: input.context,
        });
      } catch (error) {
        return { ...base, supported: false,
          reason: error?.code === 'SLEIGH_CONTEXT' ? 'context_rejected' : 'dataflow_limit',
          detail: error?.message ?? null, ...empty, limitations };
      }

      let sliced = null;
      if (input.sliceFrom !== undefined) {
        try { sliced = sliceDataflow(analysis, { from: input.sliceFrom, direction: input.sliceDirection }); }
        catch (error) {
          // The analysis succeeded and only the slice target was wrong, so the summary is still
          // returned: refusing the whole call would discard work that was correct.
          return { ...base, supported: false, reason: 'slice_target_unknown', detail: error?.message ?? null,
            ...empty, entries: analysis.entries, summary: analysis.summary, counts: analysis.counts, limitations };
        }
      }

      if (!input.context) {
        limitations.push('No initial context was supplied, so a language whose decode depends on context decodes in whatever its zeroed context selects; the defaults are declared in the .pspec and readable with artifact.ghidraProcessorSpec');
      }
      limitations.push(...analysis.limitations);
      if (sliced) limitations.push(...sliced.limitations);
      limitations.push('Dataflow is an interpretation of bytes under one chosen language. The inputs reported are evidence about what this code reads, not a declaration of what it was written to take');

      // The chains are large and the summary answers most questions, so they are returned only
      // when asked for rather than truncated into something that looks complete.
      const detail = input.detail === true;
      if (!detail) {
        limitations.push('Definition and use chains were not requested: pass detail:true for them. The counts describe the whole analysis either way');
      }
      return { ...base, supported: true, reason: null,
        entries: analysis.entries, summary: analysis.summary,
        definitions: detail ? listed(analysis.definitions, limitations, 'definitions') : [],
        uses: detail ? listed(analysis.uses, limitations, 'uses') : [],
        slice: sliced, counts: analysis.counts, limitations };
    },
  })];
}
