import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';
import { canonical, deepFreeze, parseJson as strictParseJson, validateSchema, HarnessError } from './value.mjs';

const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_OUTPUT = 1_048_576;
const MAX_INPUT = 32 * 1_048_576;
const objectSchema = { type: 'object' };
const envName = /^[A-Za-z_][A-Za-z0-9_]*$/;
const toolName = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;

function fail(code, message) { throw new HarnessError(code, message); }
function positive(value, fallback, label) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 2_147_483_647) {
    fail('INTEGRATION_CONFIG', `${label} must be a positive bounded integer`);
  }
  return result;
}
function text(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    fail('INTEGRATION_CONFIG', `${label} must be a nonempty string`);
  }
  return value;
}
function keys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) {
    fail('INTEGRATION_CONFIG', `Unsupported ${label} configuration field`);
  }
}
function origin(value) {
  let parsed;
  try { parsed = new URL(value); } catch { fail('INTEGRATION_CONFIG', 'Invalid integration origin'); }
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.origin !== value ||
      parsed.username || parsed.password) {
    fail('INTEGRATION_CONFIG', 'Origin must be an exact HTTP(S) origin without credentials or a path');
  }
  return parsed.origin;
}
function json(value) { return JSON.parse(canonical(value)); }
function parseJson(value, code = 'INTEGRATION_OUTPUT') {
  try { return strictParseJson(value); } catch { fail(code, 'Integration returned invalid JSON'); }
}
function decodeJson(chunks) {
  try { return parseJson(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { fail('INTEGRATION_OUTPUT', 'Integration returned invalid UTF-8 JSON'); }
}
function rejectSecrets(value, secrets) {
  if (typeof value === 'string' && secrets.some(secret => secret && value.includes(secret))) fail('INTEGRATION_SECRET', 'Integration output echoed a configured credential');
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) { rejectSecrets(key, secrets); rejectSecrets(child, secrets); }
  }
  return value;
}
function limits(config, context, name, effect) {
  const policy = context?.policy ?? {};
  if (Array.isArray(policy.allowedTools) && !policy.allowedTools.includes(name)) {
    fail('INTEGRATION_POLICY', 'Integration tool is not allowlisted');
  }
  if (Array.isArray(policy.allowedEffects) && !policy.allowedEffects.includes(effect)) {
    fail('INTEGRATION_POLICY', 'Integration effect is not allowlisted');
  }
  if (context?.signal?.aborted) fail('INTEGRATION_ABORTED', 'Integration was cancelled');
  return {
    timeoutMs: Math.min(config.timeoutMs, positive(policy.timeoutMs, config.timeoutMs, 'policy timeoutMs')),
    maxOutputBytes: Math.min(config.maxOutputBytes, positive(policy.maxOutputBytes, config.maxOutputBytes, 'policy maxOutputBytes')),
  };
}
function credentials(config) {
  const token = process.env[config.apiKeyEnv];
  if (!token || !/^[\x21-\x7e]+$/.test(token)) fail('INTEGRATION_CREDENTIAL', 'Integration credential is unavailable or invalid');
  return token;
}
function settings(value, defaultName) {
  const result = json(value);
  result.name = result.name ?? defaultName;
  if (typeof result.name !== 'string' || !toolName.test(result.name)) fail('INTEGRATION_CONFIG', 'Invalid integration tool name');
  result.timeoutMs = positive(result.timeoutMs, DEFAULT_TIMEOUT, 'timeoutMs');
  result.maxOutputBytes = positive(result.maxOutputBytes, DEFAULT_OUTPUT, 'maxOutputBytes');
  return result;
}

async function postJson(config, input, context) {
  const bound = limits(config, context, config.name, 'network');
  if (!Array.isArray(context?.policy?.allowedOrigins) ||
      !context.policy.allowedOrigins.includes(config.origin)) {
    fail('INTEGRATION_ORIGIN', 'Integration origin is not allowlisted');
  }
  const encoded = Buffer.from(canonical(input));
  if (encoded.length > MAX_INPUT) fail('INTEGRATION_INPUT_LIMIT', 'Integration input exceeds the byte limit');
  const token = credentials(config);
  const url = new URL(config.path, `${config.origin}/`);
  return new Promise((resolveRequest, reject) => {
    let done = false;
    let timer;
    const finish = (error, result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      context?.signal?.removeEventListener('abort', cancelled);
      if (error) reject(error); else resolveRequest(result);
    };
    const error = (code, message) => new HarnessError(code, message);
    const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
      method: 'POST',
      agent: false, rejectUnauthorized: true, maxHeaderSize: 16_384,
      headers: { 'content-type': 'application/json', 'content-length': encoded.length, authorization: `Bearer ${token}` },
    }, response => {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.destroy();
        finish(error('INTEGRATION_HTTP_STATUS', `Integration HTTP status ${response.statusCode}`));
        return;
      }
      let bytes = 0;
      const chunks = [];
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > bound.maxOutputBytes) {
          finish(error('INTEGRATION_OUTPUT_LIMIT', 'Integration output exceeds the byte limit'));
          response.destroy();
          request.destroy();
        } else chunks.push(chunk);
      });
      response.on('end', () => {
        if (done) return;
        try { finish(null, rejectSecrets(decodeJson(chunks), [token])); }
        catch (caught) { finish(caught); }
      });
      response.on('error', () => finish(error('INTEGRATION_HTTP', 'Integration response failed')));
      response.on('aborted', () => finish(error('INTEGRATION_HTTP', 'Integration response was interrupted')));
    });
    const cancelled = () => {
      finish(error('INTEGRATION_ABORTED', 'Integration was cancelled'));
      request.destroy();
    };
    request.on('error', () => finish(error('INTEGRATION_HTTP', 'Integration request failed')));
    timer = setTimeout(() => {
      finish(error('INTEGRATION_TIMEOUT', 'Integration request timed out'));
      request.destroy();
    }, bound.timeoutMs);
    context?.signal?.addEventListener('abort', cancelled, { once: true });
    if (context?.signal?.aborted) { cancelled(); return; }
    request.end(encoded);
  });
}

function networkSettings(value, defaultName, defaultPath) {
  keys(value, ['name', 'origin', 'model', 'apiKeyEnv', 'path', 'timeoutMs', 'maxOutputBytes'], 'network');
  const config = settings(value, defaultName);
  config.origin = origin(config.origin);
  config.model = text(config.model, 'model');
  config.apiKeyEnv = text(config.apiKeyEnv, 'apiKeyEnv');
  if (!envName.test(config.apiKeyEnv)) fail('INTEGRATION_CONFIG', 'Invalid credential environment variable name');
  config.path = config.path ?? defaultPath;
  if (typeof config.path !== 'string' || !/^\/(?!\/)/.test(config.path) ||
      config.path.includes('\\') || config.path.includes('#') || config.path.includes('?') ||
      new URL(config.path, `${config.origin}/`).origin !== config.origin) {
    fail('INTEGRATION_CONFIG', 'Integration endpoint must be an absolute path on the configured origin');
  }
  return config;
}

function typeSafe(value) {
  const config = networkSettings(value, 'typesafe.evaluate', '/v1/systemone');
  if (!/^jev-\d+\.\d+\.\d+$/.test(config.model)) {
    fail('INTEGRATION_CONFIG', 'TypeSafe requires a versioned Jev model ID');
  }
  const inputSchema = {
    type: 'object', required: ['state', 'questions'], additionalProperties: false,
    properties: { state: { anyOf: [{ type: 'string' }, { type: 'object' }, { type: 'array' }] }, questions: { type: 'object' } },
  };
  return {
    name: config.name, version: '1', effect: 'network', inputSchema, config,
    async execute(input, context) {
      validateSchema(input, inputSchema);
      input = json(input);
      if (!Object.keys(input.questions).length) fail('INTEGRATION_INPUT', 'TypeSafe requires at least one question');
      for (const question of Object.values(input.questions)) {
        if (!question || typeof question !== 'object' || Array.isArray(question) ||
            !['choice', 'score', 'noul'].includes(question.type) || question.instructions === undefined) {
          fail('INTEGRATION_INPUT', 'Unsupported TypeSafe question');
        }
        if (question.type === 'choice' && (!question.criteria || Array.isArray(question.criteria) ||
            typeof question.criteria !== 'object' || Object.keys(question.criteria).length < 2 || Object.keys(question.criteria).length > 255)) {
          fail('INTEGRATION_INPUT', 'TypeSafe Choice requires 2 to 255 options');
        }
        if (question.type === 'score' && (!Array.isArray(question.criteria) || question.criteria.length < 2 || question.criteria.length > 10)) {
          fail('INTEGRATION_INPUT', 'TypeSafe Score requires 2 to 10 levels');
        }
      }
      const result = await postJson(config, { model: config.model, state: input.state, questions: input.questions }, context);
      if (!result || result.model !== config.model || !result.answers || typeof result.answers !== 'object' ||
          Array.isArray(result.answers) || Object.keys(result.answers).length !== Object.keys(input.questions).length) {
        fail('INTEGRATION_OUTPUT', 'TypeSafe response does not match the pinned request');
      }
      for (const [id, question] of Object.entries(input.questions)) {
        const answer = result.answers[id];
        if (!answer || answer.type !== question.type) fail('INTEGRATION_OUTPUT', 'TypeSafe answer type does not match its question');
        if (question.type === 'noul' && (typeof answer.noul !== 'number' || answer.noul < 0 || answer.noul > 1)) {
          fail('INTEGRATION_OUTPUT', 'Invalid TypeSafe Noul answer');
        }
        if (question.type === 'choice' && !Object.hasOwn(question.criteria, answer.choice)) {
          fail('INTEGRATION_OUTPUT', 'TypeSafe selected an unknown option');
        }
        if (question.type !== 'noul' && (typeof answer.confidence !== 'number' || answer.confidence < 0 || answer.confidence > 1 ||
            !answer.probabilities || typeof answer.probabilities !== 'object' || Array.isArray(answer.probabilities))) {
          fail('INTEGRATION_OUTPUT', 'Invalid TypeSafe distribution or confidence');
        }
        if (question.type !== 'noul') {
          const expected = question.type === 'choice' ? Object.keys(question.criteria).sort() : question.criteria.map((_, index) => String(index)).sort();
          const probabilities = Object.values(answer.probabilities);
          if (canonical(Object.keys(answer.probabilities).sort()) !== canonical(expected) ||
              probabilities.some(value => typeof value !== 'number' || value < 0 || value > 1) ||
              Math.abs(probabilities.reduce((sum, value) => sum + value, 0) - 1) > 0.001) {
            fail('INTEGRATION_OUTPUT', 'Invalid TypeSafe probability distribution');
          }
        }
        if (question.type === 'score' && (typeof answer.score !== 'number' || answer.score < 0 || answer.score > question.criteria.length - 1)) fail('INTEGRATION_OUTPUT', 'Invalid TypeSafe score');
      }
      return result;
    },
  };
}

function model(value) {
  const config = networkSettings(value, 'model.propose', '/v1/chat/completions');
  const inputSchema = {
    type: 'object', required: ['prompt'], additionalProperties: false,
    properties: { prompt: { type: 'string', minLength: 1 }, system: { type: 'string' } },
  };
  return {
    name: config.name, version: '1', effect: 'network', inputSchema, config,
    async execute(input, context) {
      validateSchema(input, inputSchema);
      const messages = [];
      if (input.system !== undefined) messages.push({ role: 'system', content: input.system });
      messages.push({ role: 'user', content: input.prompt });
      const response = await postJson(config, { model: config.model, messages, response_format: { type: 'json_object' }, temperature: 0 }, context);
      if (response?.model !== undefined && (typeof response.model !== 'string' || !response.model)) fail('INTEGRATION_OUTPUT', 'Model response has an invalid model identity');
      const content = response?.choices?.[0]?.message?.content;
      if (typeof content !== 'string') fail('INTEGRATION_OUTPUT', 'Model response is missing JSON message content');
      const proposal = parseJson(content);
      if (!proposal || typeof proposal !== 'object' || Array.isArray(proposal)) fail('INTEGRATION_OUTPUT', 'Model proposal must be a JSON object');
      return { proposal, model: response.model ?? config.model, usage: response.usage ?? null };
    },
  };
}

function contained(root, target) {
  const path = relative(root, target);
  return path === '' || (path !== '..' && !path.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(path));
}

function worker(value) {
  keys(value, ['name', 'version', 'executable', 'args', 'cwd', 'env', 'allowedEnv', 'executableSha256', 'timeoutMs', 'maxOutputBytes'], 'worker');
  const config = settings(value, undefined);
  config.version = text(config.version, 'worker version');
  config.executable = text(config.executable, 'worker executable');
  if (!isAbsolute(config.executable)) fail('INTEGRATION_CONFIG', 'Worker executable must be an absolute path');
  config.args = config.args ?? [];
  if (!Array.isArray(config.args) || config.args.some(arg => typeof arg !== 'string' || arg.includes('\0'))) fail('INTEGRATION_CONFIG', 'Worker args must be fixed strings');
  config.cwd = text(config.cwd ?? '.', 'worker cwd');
  if (isAbsolute(config.cwd)) fail('INTEGRATION_CONFIG', 'Worker cwd must be relative to the workspace');
  config.env = config.env ?? {};
  config.allowedEnv = config.allowedEnv ?? [];
  if (!config.env || Array.isArray(config.env) || typeof config.env !== 'object' ||
      Object.entries(config.env).some(([key, value]) => !envName.test(key) || typeof value !== 'string' || value.includes('\0') || /token|password|secret|api_?key/i.test(key))) {
    fail('INTEGRATION_CONFIG', 'Worker literal env must contain noncredential string values');
  }
  if (!Array.isArray(config.allowedEnv) || config.allowedEnv.some(key => !envName.test(key))) fail('INTEGRATION_CONFIG', 'Worker allowedEnv must list environment names');
  if (config.executableSha256 !== undefined && !/^[a-f0-9]{64}$/.test(config.executableSha256)) fail('INTEGRATION_CONFIG', 'Invalid worker executable digest');
  return {
    name: config.name, version: config.version, effect: 'process', inputSchema: objectSchema, config,
    async execute(input, context) {
      validateSchema(input, objectSchema);
      const bound = limits(config, context, config.name, 'process');
      const bytes = Buffer.from(`${canonical(input)}\n`);
      if (bytes.length > MAX_INPUT) fail('INTEGRATION_INPUT_LIMIT', 'Worker input exceeds the byte limit');
      let executable, cwd;
      try {
        executable = await realpath(config.executable);
        if (resolve(executable) !== resolve(config.executable) || !(await stat(executable)).isFile()) fail('INTEGRATION_EXECUTABLE', 'Worker executable must be an existing regular file without path aliases');
        const root = await realpath(context.workspaceRoot);
        cwd = await realpath(resolve(root, config.cwd));
        if (!contained(root, cwd) || !(await stat(cwd)).isDirectory()) fail('INTEGRATION_CWD', 'Worker cwd must remain inside the workspace');
        if (config.executableSha256 && createHash('sha256').update(await readFile(executable)).digest('hex') !== config.executableSha256) fail('INTEGRATION_EXECUTABLE', 'Worker executable digest does not match');
      } catch (error) {
        if (error instanceof HarnessError) throw error;
        fail('INTEGRATION_PATH', 'Worker executable or working directory is unavailable');
      }
      if (context?.signal?.aborted) fail('INTEGRATION_ABORTED', 'Worker was cancelled');
      const env = { ...config.env };
      for (const key of config.allowedEnv) if (process.env[key] !== undefined) env[key] = process.env[key];
      const secrets = Object.entries(env).filter(([key]) => /token|password|secret|api_?key/i.test(key)).map(([, value]) => value);
      return new Promise((resolveWorker, reject) => {
        const child = spawn(executable, config.args, { cwd, env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
        let outcome;
        let total = 0;
        const chunks = [];
        let timer;
        const cancelled = () => stop('INTEGRATION_ABORTED', 'Worker was cancelled');
        const stop = (code, message) => {
          outcome ??= new HarnessError(code, message);
          child.kill('SIGKILL');
          child.stdin.destroy();
          child.stdout.destroy();
          child.stderr.destroy();
        };
        const collect = (chunk, stdout) => {
          total += chunk.length;
          if (total > bound.maxOutputBytes) stop('INTEGRATION_OUTPUT_LIMIT', 'Worker output exceeds the combined stdout/stderr byte limit');
          else if (stdout) chunks.push(chunk);
        };
        child.stdout.on('data', chunk => collect(chunk, true));
        child.stderr.on('data', chunk => collect(chunk, false));
        child.stdout.on('error', () => stop('INTEGRATION_IO', 'Worker output failed'));
        child.stderr.on('error', () => stop('INTEGRATION_IO', 'Worker diagnostics failed'));
        child.stdin.on('error', () => stop('INTEGRATION_IO', 'Worker input failed'));
        child.on('error', () => { outcome ??= new HarnessError('INTEGRATION_PROCESS', 'Worker could not start'); });
        child.on('close', code => {
          clearTimeout(timer);
          context?.signal?.removeEventListener('abort', cancelled);
          if (outcome) { reject(outcome); return; }
          if (code !== 0) { reject(new HarnessError('INTEGRATION_EXIT', 'Worker exited unsuccessfully')); return; }
          try { resolveWorker(rejectSecrets(decodeJson(chunks), secrets)); }
          catch (error) { reject(error); }
        });
        timer = setTimeout(() => stop('INTEGRATION_TIMEOUT', 'Worker timed out'), bound.timeoutMs);
        context?.signal?.addEventListener('abort', cancelled, { once: true });
        if (context?.signal?.aborted) cancelled();
        else child.stdin.end(bytes);
      });
    },
  };
}

/** Registration is data-only. Credentials and all effects are deferred until execute. */
export function makeIntegrationTools(config = {}) {
  keys(config, ['typesafe', 'model', 'workers'], 'integration');
  config = json(config);
  const tools = [];
  if (config.typesafe) tools.push(typeSafe(config.typesafe));
  if (config.model) tools.push(model(config.model));
  if (config.workers !== undefined && !Array.isArray(config.workers)) fail('INTEGRATION_CONFIG', 'workers must be an array');
  for (const value of config.workers ?? []) tools.push(worker(value));
  const names = tools.map(tool => tool.name);
  if (new Set(names).size !== names.length) fail('INTEGRATION_CONFIG', 'Integration tool names must be unique');
  for (const tool of tools) {
    // Commit the complete explicit configuration, without resolving environment values.
    deepFreeze(tool.config);
    deepFreeze(tool.inputSchema);
    Object.freeze(tool);
  }
  return tools;
}
