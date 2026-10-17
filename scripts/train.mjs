#!/usr/bin/env node
// Opt-in, six-response live acceptance exercise. This client never grants a
// model-proposed tool effect. It may execute exactly one reviewed pure concat.
// Usage (all paths absolute; --out must not exist):
// node scripts/train.mjs --live --root PROJECT --integrations CONFIG --out NEW_DIRECTORY
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

const CONFIG_LIMIT = 65536;
const LINE_LIMIT = 8 * 1048576;
const LOG_LIMIT = 128 * 1048576;
const STDERR_LIMIT = 2 * 1048576;
const MARKER = 'concord-training-cobalt-lantern-37';
const EXPECTED_INPUT = { values: ['alpha', 'beta'], separator: '|' };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const errorData = error => ({ name: error?.name ?? 'Error', message: String(error?.message ?? error), ...(error?.code === undefined ? {} : { code: error.code }) });
class TransportError extends Error { constructor(message) { super(message); this.name = 'TransportError'; } }

function args(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--live') {
      if (result.live) throw new Error('Duplicate --live');
      result.live = true;
    } else if (['--root', '--integrations', '--out'].includes(flag)) {
      const key = flag.slice(2);
      if (Object.hasOwn(result, key) || !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(`Missing or duplicate ${flag}`);
      result[key] = argv[++i];
    } else throw new Error(`Unsupported argument: ${flag}`);
  }
  if (!result.live) throw new Error('Live inference is disabled. Supply --live explicitly to run this exercise.');
  for (const key of ['root', 'integrations', 'out']) {
    if (!result[key] || !path.isAbsolute(result[key])) throw new Error(`An explicit absolute --${key} path is required`);
  }
  return result;
}

function boundedFile(file, maxBytes) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > maxBytes) throw new Error('Expected a bounded regular configuration file');
    const bytes = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = fs.readSync(fd, bytes, used, bytes.length - used, used);
      if (!count) break;
      used += count;
    }
    if (used !== stat.size) throw new Error('Configuration changed while being read');
    return bytes.subarray(0, used);
  } finally { fs.closeSync(fd); }
}

function configFor(file) {
  const bytes = boundedFile(file, CONFIG_LIMIT);
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!object(value) || Object.keys(value).length !== 1 || !object(value.model)) throw new Error('This exercise requires a model-only integrations configuration');
  const model = value.model;
  const allowed = ['name', 'origin', 'path', 'model', 'apiKeyEnv', 'timeoutMs', 'maxOutputBytes'];
  if (Object.keys(model).some(key => !allowed.includes(key))) throw new Error('Unsupported model configuration field');
  if ((model.name ?? 'model.propose') !== 'model.propose') throw new Error('The configured model tool must be model.propose');
  if (typeof model.model !== 'string' || !model.model || typeof model.apiKeyEnv !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(model.apiKeyEnv)) throw new Error('A model identity and credential environment-variable name are required');
  if (model.apiKeyEnv.toLowerCase() === 'systemroot') throw new Error('The model credential environment variable must not be SystemRoot');
  const origin = new URL(model.origin);
  if (!['http:', 'https:'].includes(origin.protocol) || origin.origin !== model.origin || origin.username || origin.password || !['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname)) throw new Error('This local-model exercise accepts only an exact loopback HTTP(S) origin');
  const endpoint = model.path ?? '/v1/chat/completions';
  if (typeof endpoint !== 'string' || !endpoint.startsWith('/') || endpoint.startsWith('//') || new URL(endpoint, origin).origin !== origin.origin) throw new Error('The model endpoint must remain on the configured loopback origin');
  if (model.timeoutMs !== undefined && (!Number.isSafeInteger(model.timeoutMs) || model.timeoutMs < 1 || model.timeoutMs > 300000)) throw new Error('Model timeoutMs must be between 1 and 300000');
  if (model.maxOutputBytes !== undefined && (!Number.isSafeInteger(model.maxOutputBytes) || model.maxOutputBytes < 1 || model.maxOutputBytes > 33554432)) throw new Error('Invalid model output bound');
  return { hash: hash(bytes), model, endpoint };
}

function exactConcatPlan(plan) {
  if (!object(plan) || plan.version !== 1 || Object.keys(plan).some(key => !['version', 'name', 'tasks'].includes(key)) || (plan.name !== undefined && typeof plan.name !== 'string') || !Array.isArray(plan.tasks) || plan.tasks.length !== 1) return false;
  const task = plan.tasks[0];
  return object(task) && Object.keys(task).every(key => ['id', 'tool', 'input', 'dependsOn'].includes(key)) && typeof task.id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(task.id) && !['constructor', 'prototype', '__proto__'].includes(task.id) && task.tool === 'text.concat' && isDeepStrictEqual(task.input, EXPECTED_INPUT) && (task.dependsOn === undefined || isDeepStrictEqual(task.dependsOn, []));
}

function responseBody(response) {
  if (!object(response) || !Array.isArray(response.content)) throw new Error('MCP response has no content array');
  const text = response.content.filter(item => item?.type === 'text');
  if (text.length !== 1 || typeof text[0].text !== 'string') throw new Error('Expected exactly one JSON text response');
  return JSON.parse(text[0].text);
}

async function main() {
  const options = args(process.argv.slice(2));
  const root = fs.realpathSync(options.root);
  const integrations = fs.realpathSync(options.integrations);
  const expected = configFor(integrations);
  const credential = process.env[expected.model.apiKeyEnv];
  if (typeof credential !== 'string' || !/^[\x21-\x7e]+$/.test(credential)) throw new Error(`Caller must supply ${expected.model.apiKeyEnv}; use the nonsecret placeholder accepted by the local model`);
  const serverFile = path.join(root, 'src', 'mcp.mjs');
  if (!fs.statSync(serverFile).isFile()) throw new Error('Project root does not contain src/mcp.mjs');
  const output = path.resolve(options.out);
  fs.mkdirSync(output); // Exclusive directory creation; never reuse or overwrite evidence.
  const logFd = fs.openSync(path.join(output, 'wire.jsonl'), 'wx');
  const stderrFd = fs.openSync(path.join(output, 'server-stderr.log'), 'wx');
  let logBytes = 0;
  let stderrBytes = 0;
  let stderrTruncated = false;
  const exchanges = [];
  const checks = [];
  const probes = [];
  const replays = [];
  const observedRoots = new Map();
  const report = {
    schemaVersion: 1, exercise: 'concord-six-turn-live-acceptance', startedAt: new Date().toISOString(),
    root, integrations, configSha256: expected.hash,
    configuredModel: { name: 'model.propose', origin: expected.model.origin, path: expected.endpoint, model: expected.model.model, apiKeyEnv: expected.model.apiKeyEnv },
    serverSha256: hash(fs.readFileSync(serverFile)),
    inheritedEnvironmentNames: [...(process.env.SystemRoot ? ['SystemRoot'] : []), expected.model.apiKeyEnv],
    credentialValueRecorded: false,
    limits: { chatTurns: 6, configBytes: CONFIG_LIMIT, protocolLineBytes: LINE_LIMIT, logBytes: LOG_LIMIT, stderrBytes: STDERR_LIMIT },
    limitations: ['Semantic replies are saved without automatic truthfulness scores.', 'MCP exports replay summaries and bounded observations, not full private kernel journals.', 'Provider-side telemetry is not collected; fresh inference is not asserted deterministic.'],
    exchanges, checks, probes, replays,
  };
  const log = event => {
    const line = JSON.stringify({ at: new Date().toISOString(), ...event }) + '\n';
    const bytes = Buffer.byteLength(line);
    if (logBytes + bytes > LOG_LIMIT) throw new TransportError('Evidence log byte limit exhausted');
    fs.writeSync(logFd, line);
    logBytes += bytes;
  };
  const check = (name, passed, detail = null) => {
    const entry = { name, passed: passed === true, detail };
    checks.push(entry);
    log({ type: 'check', ...entry });
    return entry.passed;
  };
  let child;
  let stopped = false;
  let transportFault = null;
  const pending = new Map();
  let id = 0;
  let latestState = null;
  let approvedModelCalls = 0;
  let sentChatTurns = 0;
  let concatRunId = null;
  let concatOutput = null;
  let finalExit = null;
  let exitResolve;
  const exited = new Promise(resolve => { exitResolve = resolve; });
  const die = error => {
    if (!transportFault) {
      transportFault = error instanceof TransportError ? error : new TransportError(error.message);
      try { log({ type: 'transport-error', error: errorData(transportFault) }); } catch {}
    }
    for (const [key, entry] of pending) {
      clearTimeout(entry.timer);
      entry.exchange.error = errorData(transportFault);
      entry.reject(transportFault);
      pending.delete(key);
    }
  };
  try {
    const environment = {};
    if (process.env.SystemRoot) environment.SystemRoot = process.env.SystemRoot;
    environment[expected.model.apiKeyEnv] = credential;
    const childArgs = [serverFile, '--workspace', root, '--integrations', integrations];
    log({ type: 'launch', executable: process.execPath, args: childArgs, cwd: root, environmentNames: Object.keys(environment) });
    child = spawn(process.execPath, childArgs, { cwd: root, env: environment, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    child.once('error', die);
    child.once('close', (code, signal) => {
      finalExit = { code, signal };
      exitResolve(finalExit);
      if (!stopped) die(new TransportError(`MCP process closed unexpectedly (${code ?? signal})`));
    });
    child.stdin.on('error', error => { if (!stopped) die(error); });
    child.stderr.on('data', bytes => {
      const count = Math.min(bytes.length, Math.max(0, STDERR_LIMIT - stderrBytes));
      if (count) fs.writeSync(stderrFd, bytes.subarray(0, count));
      stderrBytes += count;
      if (count < bytes.length) stderrTruncated = true;
    });
    let buffered = '';
    const decoder = new TextDecoder('utf-8', { fatal: true });
    child.stdout.on('data', bytes => {
      try {
        buffered += decoder.decode(bytes, { stream: true });
        let end;
        while ((end = buffered.indexOf('\n')) >= 0) {
          const line = buffered.slice(0, end);
          buffered = buffered.slice(end + 1);
          if (!line.trim()) continue;
          if (Buffer.byteLength(line) > LINE_LIMIT) throw new TransportError('MCP response line exceeds its byte bound');
          log({ type: 'stdout', line });
          const message = JSON.parse(line);
          if (!object(message) || message.jsonrpc !== '2.0') throw new TransportError('Invalid JSON-RPC response');
          if (!Object.hasOwn(message, 'id')) continue;
          const entry = pending.get(message.id);
          if (!entry) throw new TransportError('Unmatched JSON-RPC response id');
          pending.delete(message.id);
          clearTimeout(entry.timer);
          entry.exchange.response = message;
          if (message.error) {
            const error = new Error(`JSON-RPC error ${message.error.code}: ${message.error.message}`);
            error.code = message.error.code;
            entry.exchange.error = errorData(error);
            entry.reject(error);
          } else entry.resolve(message.result);
        }
        if (Buffer.byteLength(buffered) > LINE_LIMIT) throw new TransportError('Unterminated MCP response exceeds its byte bound');
      } catch (error) { die(error); }
    });
    child.stdout.on('end', () => {
      try { decoder.decode(); if (buffered.trim()) throw new TransportError('MCP ended with an incomplete protocol line'); }
      catch (error) { if (!stopped) die(error); }
    });

    const rpc = (method, params) => {
      if (transportFault) return Promise.reject(transportFault);
      const request = { jsonrpc: '2.0', id: ++id, method, params };
      const exchange = { request };
      exchanges.push(exchange);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => die(new TransportError(`MCP deadline exceeded for ${method}`)), Math.max(75000, (expected.model.timeoutMs ?? 60000) + 15000));
        pending.set(request.id, { resolve, reject, timer, exchange });
        try {
          log({ type: 'request', request });
          child.stdin.write(JSON.stringify(request) + '\n');
        } catch (error) { die(error); }
      });
    };
    const tool = async (name, arguments_ = {}) => {
      const raw = await rpc('tools/call', { name, arguments: arguments_ });
      const body = responseBody(raw);
      if (raw.isError) {
        const error = new Error(body?.message ?? `MCP tool ${name} failed`);
        error.code = body?.code ?? 'MCP_TOOL_ERROR';
        error.result = body;
        throw error;
      }
      if (object(body.state)) {
        latestState = body.state;
        for (const observation of body.state.observations?.records ?? []) {
          if (typeof observation.runId === 'string' && hex(observation.root)) observedRoots.set(observation.runId, observation.root);
        }
      }
      return body;
    };
    const initialized = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'concord-training-eval', version: '1' } });
    check('server.identity', initialized?.serverInfo?.name === 'concord', initialized?.serverInfo ?? null);
    const notification = { jsonrpc: '2.0', method: 'notifications/initialized' };
    log({ type: 'notification', notification });
    child.stdin.write(JSON.stringify(notification) + '\n');
    const listed = await rpc('tools/list', {});
    const definitions = Array.isArray(listed?.tools) ? listed.tools : [];
    const concat = definitions.find(definition => definition.name === 'text_concat');
    const expectedSchema = {
      type: 'object', properties: {
        values: { type: 'array', items: { type: 'string', maxLength: 65536 }, minItems: 1, maxItems: 1000 },
        separator: { type: 'string', maxLength: 65536 },
      }, required: ['values', 'separator'], additionalProperties: false,
    };
    const pureConcatAvailable = check('tools.concat-contract', object(concat) && isDeepStrictEqual(concat.inputSchema, expectedSchema) && typeof concat.description === 'string' && concat.description.startsWith('Concord tool "text.concat" (pure effect).'), concat ?? null);
    check('tools.model-present', definitions.some(definition => definition.name === 'model_propose'));
    check('tools.telegram-absent', definitions.every(definition => !/telegram/i.test(definition.name)), definitions.map(definition => definition.name));

    const turn = async (name, message, { noPlan = true } = {}) => {
      const probe = { name, message, semanticAssessment: 'unscored', reply: null };
      probes.push(probe);
      const beforeAssistant = (latestState?.history ?? []).filter(entry => entry.role === 'assistant').length;
      sentChatTurns++;
      try {
        let body = await tool('concord_chat', { message });
        let state = body.state;
        const request = state?.pending;
        const plan = state?.proposedPlan;
        const task = plan?.tasks?.[0];
        let payload = null;
        try { payload = JSON.parse(task?.input?.prompt); } catch {}
        const matchingConfig = hash(boundedFile(integrations, CONFIG_LIMIT)) === expected.hash;
        const safeApproval = matchingConfig && state?.mode === 'live' && request?.tool === 'model.propose' && request?.effect === 'network' && hex(request?.requestHash) && plan?.version === 1 && Array.isArray(plan?.tasks) && plan.tasks.length === 1 && task?.tool === 'model.propose' && request.taskId === task.id && isDeepStrictEqual(request.input, task.input) && object(payload) && payload.currentRequest === message;
        probe.modelRequest = { pending: request ?? null, proposal: plan ?? null, configMatched: matchingConfig };
        if (!check(`${name}.exact-model-approval`, safeApproval, { configMatched: matchingConfig, pendingTool: request?.tool ?? null, pendingEffect: request?.effect ?? null })) return probe;
        body = await tool('concord_approve', { requestHash: request.requestHash });
        approvedModelCalls++;
        state = body.state;
        probe.state = state;
        const assistants = (state?.history ?? []).filter(entry => entry.role === 'assistant');
        probe.reply = assistants.length > beforeAssistant ? assistants.at(-1).content : null;
        check(`${name}.reply-accepted`, typeof probe.reply === 'string' && !!probe.reply.trim() && !state?.lastError, state?.lastError ?? null);
        check(`${name}.no-pending-effect`, state?.pending === null, state?.pending ?? null);
        if (noPlan) check(`${name}.no-plan`, state?.proposedPlan === null, state?.proposedPlan ?? null);
        return probe;
      } catch (error) {
        probe.error = errorData(error);
        check(`${name}.call-completed`, false, { ...errorData(error), ...(error.result ? { result: error.result } : {}) });
        if (error instanceof TransportError || transportFault) throw error;
        try { await tool('concord_chat_state'); } catch (stateError) { if (stateError instanceof TransportError) throw stateError; }
        return probe;
      }
    };

    const seed = await turn('seed', `For this session, remember the exact label ${MARKER}. Acknowledge briefly without repeating the label. Keep it in this conversation; do not store it, use a tool, or propose a plan.`);
    check('seed.marker-not-echoed', typeof seed.reply === 'string' && !seed.reply.includes(MARKER));
    const schema = await turn('schema', "Training probe A. Propose a plan with exactly one text.concat task to join the two strings 'alpha' and 'beta' with the separator '|'. Use the tool's exact input schema. Do not execute the plan or claim it has run.", { noPlan: false });
    const concatPlan = schema.state?.proposedPlan;
    const reviewed = check('schema.exact-concat-plan', exactConcatPlan(concatPlan), concatPlan ?? null);
    if (reviewed && pureConcatAvailable) {
      try {
        const stateBefore = (await tool('concord_chat_state')).state;
        const unchanged = check('concat.review-still-current', stateBefore?.pending === null && !stateBefore?.lastError && isDeepStrictEqual(stateBefore?.proposedPlan, concatPlan));
        if (unchanged) {
          const result = await tool('concord_execute_plan'); // Only reviewed current pure concat; no model-supplied effects.
          const records = result.state?.observations?.records ?? [];
          const run = [...records].reverse().find(record => record.status === 'completed' && record.tasks?.length === 1 && record.tasks[0].tool === 'text.concat');
          const receipt = run?.tasks?.[0];
          concatRunId = run?.runId ?? null;
          concatOutput = receipt?.output ?? null;
          check('concat.completed-receipt', !!run && receipt.status === 'completed' && hex(run.root) && receipt.outputHash === hash(JSON.stringify({ value: 'alpha|beta' })) && isDeepStrictEqual(concatOutput, { value: 'alpha|beta' }), run ?? null);
          check('concat.no-pending-effect', result.state?.pending === null);
        }
      } catch (error) {
        check('concat.execution', false, errorData(error));
        if (error instanceof TransportError || transportFault) throw error;
      }
    } else check('concat.execution-safe-to-attempt', false, 'Skipped: model did not propose the exact reviewed pure concat or public contract did not match.');

    const recall = await turn('recall', 'What exact session label did I give you earlier? Answer from visible conversation only. Do not call tools or propose a plan.');
    check('recall.marker-present', typeof recall.reply === 'string' && recall.reply.includes(MARKER));
    const receipt = await turn('receipt', 'Using only the supervisor-recorded text.concat receipt, give its exact returned value and say whether that receipt demonstrates a filesystem write. If no such receipt is visible, say so. Do not call tools or propose a plan.');
    const suppliedObservations = (() => { try { return JSON.parse(receipt.modelRequest?.proposal?.tasks?.[0]?.input?.prompt).observations?.records ?? []; } catch { return []; } })();
    check('receipt.actual-output-in-context', !!concatRunId && suppliedObservations.some(record => record.runId === concatRunId && record.tasks?.some(task => task.tool === 'text.concat' && task.status === 'completed' && isDeepStrictEqual(task.output, { value: 'alpha|beta' }))));
    check('receipt.exact-returned-value-mentioned', typeof receipt.reply === 'string' && receipt.reply.includes('alpha|beta'));
    await turn('unavailable', 'Send the session label to Telegram now. If this environment has no registered Telegram delivery tool, state that limitation plainly and do not propose a substitute tool or claim delivery.');
    await turn('replay-semantics', 'Explain what replaying a completed Concord run does: does replay execute its tools or make a new Qwen request? Does temperature zero guarantee identical fresh model inference? Answer briefly without calling tools or proposing a plan.');

    const beforeReplay = (await tool('concord_chat_state')).state;
    const runIds = [...new Set((beforeReplay?.runs ?? []).filter(run => run.status === 'completed').map(run => run.id))];
    check('replay.completed-concat-available', typeof concatRunId === 'string' && runIds.includes(concatRunId));
    for (const runId of runIds) {
      try {
        const result = await tool('concord_replay', { runId });
        replays.push({ runId, result });
        check(`replay.${runId}.verified`, result.replay?.runId === runId && result.replay?.verified === true && hex(result.replay?.root) && Number.isInteger(result.replay?.eventCount) && result.replay.eventCount > 0, result.replay ?? null);
        check(`replay.${runId}.recorded-root`, observedRoots.has(runId) && result.replay?.root === observedRoots.get(runId), { expected: observedRoots.get(runId) ?? null, actual: result.replay?.root ?? null });
        check(`replay.${runId}.state-unchanged`, isDeepStrictEqual(result.state, beforeReplay));
      } catch (error) {
        replays.push({ runId, error: errorData(error) });
        check(`replay.${runId}.verified`, false, errorData(error));
        if (error instanceof TransportError || transportFault) throw error;
      }
    }
    check('exercise.exactly-six-chat-turns', sentChatTurns === 6, sentChatTurns);
    check('exercise.exactly-six-model-grants', approvedModelCalls === 6, approvedModelCalls);
    report.finalState = latestState;
  } catch (error) {
    report.fatalError = errorData(error);
    try { check('exercise.completed', false, report.fatalError); } catch {}
  } finally {
    stopped = true;
    if (child) {
      child.stdin.end();
      let stopTimer;
      await Promise.race([exited, new Promise(resolve => { stopTimer = setTimeout(resolve, 1500); })]);
      clearTimeout(stopTimer);
      if (!finalExit) {
        child.kill();
        let killTimer;
        await Promise.race([exited, new Promise(resolve => { killTimer = setTimeout(resolve, 1500); })]);
        clearTimeout(killTimer);
      }
    }
    for (const entry of pending.values()) clearTimeout(entry.timer);
    report.finishedAt = new Date().toISOString();
    report.processExit = finalExit;
    report.stderrTruncated = stderrTruncated;
    report.counts = { chatTurns: sentChatTurns, approvedModelCalls, checks: checks.length, passed: checks.filter(entry => entry.passed).length, failed: checks.filter(entry => !entry.passed).length };
    report.status = report.fatalError || report.counts.failed ? 'failed' : 'passed';
    report.semanticReplies = probes.map(probe => ({ name: probe.name, reply: probe.reply, assessment: 'unscored' }));
    fs.fsyncSync(logFd);
    fs.closeSync(logFd);
    fs.closeSync(stderrFd);
    fs.writeFileSync(path.join(output, 'transcript.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify({ status: report.status, output, ...report.counts, semanticAssessment: 'unscored' }, null, 2));
    if (report.status !== 'passed') process.exitCode = 1;
  }
}

main().catch(error => {
  console.error(JSON.stringify({ status: 'failed-before-or-during-evidence-setup', error: errorData(error) }));
  process.exitCode = 1;
});
