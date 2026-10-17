import { openSync, writeFileSync, fsyncSync, closeSync } from 'node:fs';
import path from 'node:path';
import { canonical, digest, clone, deepFreeze, validateSchema, HarnessError } from './value.mjs';

const effects = ['pure', 'read', 'write', 'network', 'process'];
const grantedEffects = ['write', 'network', 'process'];
const idSchema = { type: 'string', minLength: 1, maxLength: 128 };
const objectSchema = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const strings = { type: 'array', items: idSchema, maxItems: 10000 };
const assert = (condition, code, message) => { if (!condition) throw new HarnessError(code, message); };
const hex = (v) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);

export function normalizePolicy(policy) {
  validateSchema(policy, objectSchema({
    version: { const: 1 }, allowedTools: strings,
    allowedEffects: { type: 'array', items: { enum: effects } },
    allowedOrigins: { type: 'array', items: { type: 'string', maxLength: 2048 } },
    maxTasks: { type: 'integer', minimum: 1, maximum: 10000 },
    maxOutputBytes: { type: 'integer', minimum: 1, maximum: 33554432 },
    maxJournalBytes: { type: 'integer', minimum: 1024, maximum: 268435456 },
    timeoutMs: { type: 'integer', minimum: 1, maximum: 300000 }
  }, ['version', 'allowedTools', 'allowedEffects']));
  const result = { allowedOrigins: [], maxTasks: 1000, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 10000, ...clone(policy) };
  for (const k of ['allowedTools', 'allowedEffects', 'allowedOrigins']) {
    assert(new Set(result[k]).size === result[k].length, 'INVALID_POLICY', 'Duplicate policy entry');
    result[k].sort();
  }
  for (const origin of result.allowedOrigins) {
    let u;
    try { u = new URL(origin); } catch { throw new HarnessError('INVALID_POLICY', 'Invalid allowed origin'); }
    assert(u.origin === origin && ['http:', 'https:'].includes(u.protocol) && !u.username && !u.password, 'INVALID_POLICY', 'Allowed origins must be exact HTTP(S) origins');
  }
  return deepFreeze(result);
}

function schemaWellFormed(schema) {
  try { validateSchema(null, schema); } catch (e) { if (e.code !== 'SCHEMA_MISMATCH') throw e; }
}

export function registryManifest(registry) {
  assert(registry instanceof Map, 'INVALID_REGISTRY', 'Expected a Map registry');
  return [...registry].map(([name, tool]) => {
    assert(tool && name === tool.name && typeof name === 'string' && typeof tool.version === 'string' && tool.version.length > 0 && effects.includes(tool.effect) && typeof tool.execute === 'function', 'INVALID_REGISTRY', 'Invalid tool descriptor');
    schemaWellFormed(tool.inputSchema);
    return { name, version: tool.version, effect: tool.effect, inputSchema: clone(tool.inputSchema), config: clone(tool.config ?? {}), implementation: digest(Function.prototype.toString.call(tool.execute)) };
  }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
}

// A reference that was serialised into a string instead of placed as an object is otherwise
// undetectable: it is a valid string, so it passes every schema, executes, and yields a result
// built from the reference's own source text rather than the referenced value — a wrong answer
// with a faithful receipt. Measured repeatedly in round 005, where the model described the correct
// unstringified form in prose and emitted this. The signature is exact (a string whose entire
// content is a JSON object whose only keys are $task and optionally path), so this rejects rather
// than repairs: the harness must never silently reinterpret what a caller actually wrote.
function assertNotStringifiedRef(value) {
  if (typeof value !== 'string') return;
  const text = value.trim();
  if (!text.startsWith('{') || !text.includes('$task')) return;
  let parsed;
  try { parsed = JSON.parse(text); } catch { return; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return;
  const keys = Object.keys(parsed);
  if (!keys.includes('$task') || keys.some(k => k !== '$task' && k !== 'path')) return;
  throw new HarnessError('INVALID_REFERENCE',
    'A task reference was written as a string. Place {"$task": ...} as the value itself, unquoted; the declared type applies to the resolved value');
}

function inspectRefs(input, visit) {
  assertNotStringifiedRef(input);
  if (!input || typeof input !== 'object') return;
  if (!Array.isArray(input) && Object.hasOwn(input, '$task')) {
    validateSchema(input, objectSchema({ $task: idSchema, path: { type: 'string', maxLength: 4096 } }, ['$task']));
    assert(!input.path || (input.path.startsWith('/') && !/~(?![01])/u.test(input.path)), 'INVALID_REFERENCE', 'Expected an RFC 6901 JSON pointer');
    visit(input);
    return;
  }
  // Keys as well as values: a stringified reference has also been observed used as an object key.
  if (!Array.isArray(input)) Object.keys(input).forEach(assertNotStringifiedRef);
  Object.values(input).forEach(v => inspectRefs(v, visit));
}

function resolve(input, results) {
  if (!input || typeof input !== 'object') return input;
  if (!Array.isArray(input) && Object.hasOwn(input, '$task')) {
    assert(Object.hasOwn(results, input.$task), 'INVALID_REFERENCE', 'Dependency has no result');
    let v = results[input.$task];
    const pointer = input.path ?? '';
    for (const token of pointer === '' ? [] : pointer.slice(1).split('/')) {
      const key = token.replaceAll('~1', '/').replaceAll('~0', '~');
      assert(!['__proto__', 'prototype', 'constructor'].includes(key), 'INVALID_REFERENCE', 'Unsafe reference key');
      assert(v !== null && typeof v === 'object' && Object.hasOwn(v, key), 'INVALID_REFERENCE', 'Reference path does not exist');
      if (Array.isArray(v)) assert(/^(0|[1-9]\d*)$/.test(key) && Number(key) < v.length, 'INVALID_REFERENCE', 'Invalid array pointer');
      v = v[key];
    }
    return clone(v);
  }
  if (Array.isArray(input)) return input.map(v => resolve(v, results));
  return Object.fromEntries(Object.entries(input).map(([k, v]) => [k, resolve(v, results)]));
}

function compile({ plan, policy, registry, sourceLock, workspaceRoot }) {
  const normalized = normalizePolicy(policy);
  const p = deepFreeze(clone(plan));
  validateSchema(p, objectSchema({ version: { const: 1 }, name: idSchema, tasks: { type: 'array', minItems: 1, maxItems: normalized.maxTasks, items: objectSchema({ id: idSchema, tool: idSchema, input: true, dependsOn: strings, outputSchema: true }, ['id', 'tool', 'input']) } }, ['version', 'tasks']));
  const qualifiedRoot = typeof workspaceRoot === 'string' && (path.sep === '\\' ? /^(?:[a-zA-Z]:[\\/]|\\\\(?![?.])[^\\/]+[\\/][^\\/]+)/.test(workspaceRoot) : path.posix.isAbsolute(workspaceRoot));
  assert(qualifiedRoot, 'INVALID_WORKSPACE', 'Explicit fully qualified workspaceRoot required; API callers must supply the canonical real path');
  const manifest = registryManifest(registry);
  const tools = new Map(manifest.map(m => [m.name, deepFreeze({ ...clone(m), execute: registry.get(m.name).execute })]));
  const tasks = new Map();
  for (const task of p.tasks) {
    assert(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(task.id), 'INVALID_PLAN', 'Invalid task ID');
    assert(!['__proto__', 'prototype', 'constructor'].includes(task.id), 'INVALID_PLAN', 'Reserved task ID');
    assert(!tasks.has(task.id), 'INVALID_PLAN', 'Duplicate task ID');
    assert(tools.has(task.tool), 'UNKNOWN_TOOL', 'Plan uses an unregistered tool');
    assert(normalized.allowedTools.includes(task.tool), 'POLICY_DENIED', 'Tool is not allowed');
    assert(normalized.allowedEffects.includes(tools.get(task.tool).effect), 'POLICY_DENIED', 'Effect is not allowed');
    assert(new Set(task.dependsOn ?? []).size === (task.dependsOn ?? []).length, 'INVALID_PLAN', 'Duplicate dependency');
    if (task.outputSchema !== undefined) schemaWellFormed(task.outputSchema);
    tasks.set(task.id, task);
  }
  for (const task of tasks.values()) {
    for (const dep of task.dependsOn ?? []) assert(tasks.has(dep) && dep !== task.id, 'INVALID_PLAN', 'Invalid dependency');
    inspectRefs(task.input, ref => assert((task.dependsOn ?? []).includes(ref.$task), 'INVALID_REFERENCE', 'References require a direct declared dependency'));
    let hasRefs = false;
    inspectRefs(task.input, () => { hasRefs = true; });
    if (!hasRefs) validateSchema(task.input, tools.get(task.tool).inputSchema);
  }
  const order = [];
  const remaining = new Set(tasks.keys());
  while (remaining.size) {
    const ready = [...remaining].filter(id => (tasks.get(id).dependsOn ?? []).every(d => order.includes(d))).sort();
    assert(ready.length, 'INVALID_PLAN', 'Dependency cycle');
    const next = ready[0];
    order.push(next); remaining.delete(next);
  }
  const identity = { contract: 'concord/1', planHash: digest(p), policyHash: digest(normalized), registryHash: digest(manifest), sourceHash: digest(sourceLock), workspaceRoot };
  return { plan: p, policy: normalized, tools, tasks, order, identity };
}

export function approvalRequest(identity, task, tool, input) {
  return digest({ contract: 'concord-approval/1', ...identity, taskId: task.id, tool: tool.name, effect: tool.effect, inputHash: digest(input) });
}

export function inspectPlan(options) {
  const c = compile(options);
  return deepFreeze({ identity: c.identity, order: c.order, tools: [...new Set(c.plan.tasks.map(t => t.tool))].sort(), note: 'Structural validation performs no effects. References and their schemas resolve when dependency evidence is available.' });
}

function normalizedApprovals(values = []) {
  assert(Array.isArray(values) && values.every(hex) && new Set(values).size === values.length, 'INVALID_APPROVAL', 'Approvals must be unique SHA-256 request hashes');
  return [...values].sort();
}

function inputFor(c, task, results) {
  const input = resolve(task.input, results);
  const tool = c.tools.get(task.tool);
  validateSchema(input, tool.inputSchema);
  assert(Buffer.byteLength(canonical(input)) <= c.policy.maxOutputBytes, 'INPUT_LIMIT', 'Resolved input exceeds byte budget');
  return { input: deepFreeze(input), tool, requestHash: approvalRequest(c.identity, task, tool, input) };
}

function eventHash(previous, seq, type, data) { return digest({ previous, seq, type, data }); }

export async function runPlan(options) {
  const c = compile(options);
  const approvals = normalizedApprovals(options.approvals);
  const header = { ...c.identity, approvals };
  const events = [];
  let previous = digest(header);
  let journalBytes = Buffer.byteLength(canonical(header));
  let fd;
  if (options.journalPath) {
    fd = openSync(options.journalPath, 'wx');
    writeFileSync(fd, canonical({ header }) + '\n'); fsyncSync(fd);
  }
  function emit(type, data) {
    const event = { seq: events.length, type, data: clone(data), previous, hash: eventHash(previous, events.length, type, data) };
    const bytes = Buffer.byteLength(canonical(event));
    assert(journalBytes + bytes <= c.policy.maxJournalBytes, 'JOURNAL_LIMIT', 'Journal byte budget exhausted; inspect any pending intent before retry');
    journalBytes += bytes;
    if (fd !== undefined) { writeFileSync(fd, canonical(event) + '\n'); fsyncSync(fd); }
    events.push(event); previous = event.hash;
  }
  const results = Object.create(null);
  let outcome;
  try {
    assert(journalBytes + Buffer.byteLength(canonical(c.order)) + 2048 <= c.policy.maxJournalBytes, 'JOURNAL_LIMIT', 'Insufficient journal budget before execution');
    emit('started', { order: c.order });
    for (const id of c.order) {
      const task = c.tasks.get(id);
      let call;
      // `reason` is the supervisor's own diagnostic, recorded because INPUT_INVALID is raised by
      // several distinct rules (a reference path that does not exist, a malformed JSON pointer, an
      // input failing the tool's schema) and the bare code cannot distinguish them, so a caller or
      // a model cannot correct the plan. Deterministic: replayPlan re-runs the same inputFor over
      // the same recorded results and reconstructs the identical message, so both sides must stay
      // in step. The outcome object is deliberately left unchanged.
      try { call = inputFor(c, task, results); }
      catch (error) {
        const reason = error instanceof HarnessError ? error.message : 'Input could not be resolved';
        emit('failed', { taskId: id, code: 'INPUT_INVALID', reason });
        outcome = { status: 'failed', taskId: id, code: 'INPUT_INVALID' }; break;
      }
      const { input, tool, requestHash } = call;
      if (journalBytes + c.policy.maxOutputBytes + 2048 > c.policy.maxJournalBytes) {
        emit('failed', { taskId: id, code: 'BUDGET_EXHAUSTED' }); outcome = { status: 'failed', taskId: id, code: 'BUDGET_EXHAUSTED' }; break;
      }
      if (grantedEffects.includes(tool.effect) && !approvals.includes(requestHash)) {
        const data = { taskId: id, tool: tool.name, effect: tool.effect, requestHash, input };
        emit('blocked', data); outcome = { status: 'blocked', taskId: id, requestHash }; break;
      }
      // Durable intent precedes invocation. No automatic resume of incomplete effects.
      emit('intent', { taskId: id, tool: tool.name, inputHash: digest(input), requestHash });
      const controller = new AbortController();
      let timer;
      try {
        const timeout = new Promise((_, reject) => {
          timer = setTimeout(() => { controller.abort(); reject(new HarnessError('TIMEOUT', 'Tool deadline exceeded')); }, c.policy.timeoutMs);
        });
        const output = await Promise.race([Promise.resolve().then(() => tool.execute(input, { workspaceRoot: c.identity.workspaceRoot, policy: c.policy, signal: controller.signal, requestHash })), timeout]);
        const frozenOutput = deepFreeze(clone(output));
        assert(Buffer.byteLength(canonical(frozenOutput)) <= c.policy.maxOutputBytes, 'OUTPUT_LIMIT', 'Tool output exceeds byte budget');
        if (task.outputSchema !== undefined) validateSchema(frozenOutput, task.outputSchema);
        // Reserve the success receipt and terminal envelope before another effect.
        const reserve = Buffer.byteLength(canonical(frozenOutput)) + 2048;
        assert(journalBytes + reserve <= c.policy.maxJournalBytes, 'JOURNAL_LIMIT', 'Insufficient space for output receipt');
        emit('completed', { taskId: id, output: frozenOutput, outputHash: digest(frozenOutput) });
        results[id] = frozenOutput;
      } catch {
        const code = tool.effect === 'pure' ? 'TOOL_FAILED' : 'EFFECT_INDETERMINATE';
        emit('failed', { taskId: id, code }); outcome = { status: 'failed', taskId: id, code }; break;
      } finally { clearTimeout(timer); }
    }
    if (!outcome) outcome = { status: 'completed' };
    emit('settled', outcome);
    return deepFreeze({ version: 1, header, events, outcome, results: clone(results), root: previous });
  } finally { if (fd !== undefined) closeSync(fd); }
}

// Verifies a complete trace as a legal state-machine execution; never calls execute().
export function replayPlan(options) {
  const c = compile(options);
  const j = clone(options.journal);
  validateSchema(j, objectSchema({ version: { const: 1 }, header: true, events: { type: 'array', minItems: 3 }, outcome: true, results: true, root: { type: 'string' } }));
  const approvals = normalizedApprovals(j.header.approvals);
  assert(canonical(j.header) === canonical({ ...c.identity, approvals }), 'REPLAY_CONTEXT', 'Plan, policy, sources, tools, or workspace changed');
  assert(Buffer.byteLength(canonical(j.header)) + j.events.reduce((n, e) => n + Buffer.byteLength(canonical(e)), 0) <= c.policy.maxJournalBytes, 'REPLAY_LIMIT', 'Journal exceeds replay budget');
  if (options.expectedRoot !== undefined) assert(hex(options.expectedRoot) && options.expectedRoot === j.root, 'REPLAY_ROOT', 'Trusted root does not match');
  let previous = digest(j.header);
  for (const [seq, e] of j.events.entries()) {
    assert(canonical(Object.keys(e).sort()) === canonical(['data', 'hash', 'previous', 'seq', 'type']), 'REPLAY_CHAIN', 'Unexpected event fields');
    assert(e.seq === seq && e.previous === previous && e.hash === eventHash(previous, seq, e.type, e.data), 'REPLAY_CHAIN', 'Event chain mismatch');
    previous = e.hash;
  }
  assert(j.root === previous, 'REPLAY_ROOT', 'Terminal commitment mismatch');
  let index = 0;
  let consumedBytes = Buffer.byteLength(canonical(j.header));
  function take(type, data) {
    const e = j.events[index++];
    assert(e?.type === type && (data === undefined || canonical(e.data) === canonical(data)), 'REPLAY_TRANSITION', 'Illegal journal transition: expected ' + type);
    consumedBytes += Buffer.byteLength(canonical(e));
    return e.data;
  }
  take('started', { order: c.order });
  const results = Object.create(null);
  let outcome;
  for (const id of c.order) {
    const task = c.tasks.get(id);
    let call;
    // Mirrors runPlan's recorded diagnostic exactly; the same validation over the same recorded
    // results reproduces the same message, so the recorded event still verifies byte for byte.
    try { call = inputFor(c, task, results); }
    catch (error) {
      const reason = error instanceof HarnessError ? error.message : 'Input could not be resolved';
      take('failed', { taskId: id, code: 'INPUT_INVALID', reason });
      outcome = { status: 'failed', taskId: id, code: 'INPUT_INVALID' }; break;
    }
    const { input, tool, requestHash } = call;
    if (consumedBytes + c.policy.maxOutputBytes + 2048 > c.policy.maxJournalBytes) {
      take('failed', { taskId: id, code: 'BUDGET_EXHAUSTED' }); outcome = { status: 'failed', taskId: id, code: 'BUDGET_EXHAUSTED' }; break;
    }
    if (grantedEffects.includes(tool.effect) && !approvals.includes(requestHash)) {
      take('blocked', { taskId: id, tool: tool.name, effect: tool.effect, requestHash, input });
      outcome = { status: 'blocked', taskId: id, requestHash }; break;
    }
    take('intent', { taskId: id, tool: tool.name, inputHash: digest(input), requestHash });
    if (j.events[index]?.type === 'failed') {
      const code = tool.effect === 'pure' ? 'TOOL_FAILED' : 'EFFECT_INDETERMINATE';
      take('failed', { taskId: id, code }); outcome = { status: 'failed', taskId: id, code }; break;
    }
    const beforeOutput = consumedBytes;
    const receipt = take('completed');
    assert(canonical(Object.keys(receipt).sort()) === canonical(['output', 'outputHash', 'taskId']) && receipt.taskId === id && receipt.outputHash === digest(receipt.output), 'REPLAY_OUTPUT', 'Invalid output receipt');
    assert(Buffer.byteLength(canonical(receipt.output)) <= c.policy.maxOutputBytes, 'REPLAY_OUTPUT', 'Output exceeds budget');
    assert(beforeOutput + Buffer.byteLength(canonical(receipt.output)) + 2048 <= c.policy.maxJournalBytes, 'REPLAY_LIMIT', 'Output violates execution receipt reserve');
    if (task.outputSchema !== undefined) validateSchema(receipt.output, task.outputSchema);
    results[id] = receipt.output;
  }
  if (!outcome) outcome = { status: 'completed' };
  take('settled', outcome);
  assert(index === j.events.length && canonical(j.outcome) === canonical(outcome) && canonical(j.results) === canonical(results), 'REPLAY_TRANSITION', 'Unexpected terminal state or trailing events');
  return deepFreeze({ ...j, replayed: true });
}
