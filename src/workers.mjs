import { spawn } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, digest, parseJson, validateSchema, HarnessError } from './value.mjs';

const protocol = 'dsh-sdk-jsonrpc/86a402200d95fecef4529d969836f1fe13c6cb0d';
const objectSchema = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const text = { type: 'string', minLength: 1 };
const inputSchema = objectSchema({ prompt: text, sessionId: text, workdir: text }, ['prompt', 'sessionId']);
const configSchema = objectSchema({
  binary: text, args: { type: 'array', items: { type: 'string' }, maxItems: 128 }, home: text,
  env: { type: 'object', additionalProperties: { type: 'string' } }, provider: text, model: text,
  reasoningEffort: text, maxTokens: { type: 'integer', minimum: 1 }, version: text,
}, ['binary', 'home', 'provider', 'model']);
const serviceName = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const allowedNotifications = new Set(['session.event', 'session.status', 'subagent.started', 'subagent.finished']);
const forbiddenEnv = /^(?:NODE_OPTIONS|NODE_PATH|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|LD_.*|DYLD_.*|GCONV_PATH|BASH_ENV|ENV|SHELLOPTS|COMSPEC|DSH_HOME)$/i;
const sensitiveName = /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|COOKIE/i;
const own = (object, key) => Object.hasOwn(object, key);
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const ensure = (condition, code, message) => { if (!condition) throw new HarnessError(code, message); };
const freeze = (value) => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const copy = (value) => parseJson(canonical(value));

function normalize(config) {
  validateSchema(config, configSchema);
  const result = copy({ args: ['--profile', 'sdk'], env: {}, version: '1.0.0', ...config });
  ensure(path.isAbsolute(result.binary) && path.isAbsolute(result.home), 'WORKER_CONFIG', 'Worker binary and home must be absolute paths');
  ensure(![result.binary, result.home, ...result.args].some(value => value.includes('\0')), 'WORKER_CONFIG', 'Worker paths and arguments cannot contain NUL');
  const names = new Set();
  for (const [name, value] of Object.entries(result.env)) {
    ensure(/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && !forbiddenEnv.test(name) && !value.includes('\0'), 'WORKER_CONFIG', 'Unsafe worker environment configuration');
    ensure(!names.has(name.toUpperCase()), 'WORKER_CONFIG', 'Environment names must be unique without regard to case');
    names.add(name.toUpperCase());
  }
  return freeze(result);
}

async function workingDirectory(input, workspaceRoot) {
  ensure(typeof workspaceRoot === 'string' && path.isAbsolute(workspaceRoot), 'WORKER_WORKSPACE', 'An absolute workspaceRoot is required');
  let root, cwd;
  try {
    root = await realpath(workspaceRoot);
    cwd = await realpath(path.resolve(root, input.workdir ?? '.'));
  } catch {
    throw new HarnessError('WORKER_WORKSPACE', 'Worker workspace or working directory is unavailable');
  }
  const relative = path.relative(root, cwd);
  ensure(relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative), 'WORKER_WORKSPACE', 'Worker working directory must be inside workspaceRoot');
  return cwd;
}

function redact(value, secrets) {
  if (typeof value === 'string') {
    let result = value;
    for (const secret of secrets) if (secret) result = result.split(secret).join('[redacted]');
    return result.replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '[redacted authorization]');
  }
  if (Array.isArray(value)) return value.map(item => redact(item, secrets));
  if (record(value)) {
    const entries = [], keys = new Set();
    for (const [key, child] of Object.entries(value)) {
      const redactedKey = redact(key, secrets);
      ensure(!keys.has(redactedKey), 'WORKER_REDACTION', 'Worker object keys collide after credential redaction');
      keys.add(redactedKey);
      entries.push([redactedKey, /^(?:authorization|proxy-authorization|cookie|set-cookie)$/i.test(key) ? '[redacted]' : redact(child, secrets)]);
    }
    return Object.fromEntries(entries);
  }
  return value;
}

function validateNotification(method, params) {
  ensure(allowedNotifications.has(method) && record(params), 'WORKER_PROTOCOL', 'Unexpected worker notification');
  if (method === 'session.event') {
    ensure(typeof params.sessionId === 'string' && params.sessionId.length > 0 && record(params.event), 'WORKER_PROTOCOL', 'Invalid session event');
  } else if (method === 'session.status') {
    ensure(typeof params.sessionId === 'string' && ['idle', 'running'].includes(params.status), 'WORKER_PROTOCOL', 'Invalid session status');
  } else {
    ensure(typeof params.parentSessionId === 'string' && typeof params.childSessionId === 'string', 'WORKER_PROTOCOL', 'Invalid subagent notification');
    if (method === 'subagent.finished') ensure(['ok', 'error'].includes(params.status), 'WORKER_PROTOCOL', 'Invalid subagent outcome');
  }
}

function runProtocol(settings, input, context, cwd) {
  const timeoutMs = context.policy?.timeoutMs ?? 30_000;
  const maxOutputBytes = context.policy?.maxOutputBytes ?? 1_048_576;
  ensure(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 2_147_483_647, 'WORKER_POLICY', 'Worker timeout must be a positive bounded integer');
  ensure(Number.isSafeInteger(maxOutputBytes) && maxOutputBytes > 0, 'WORKER_POLICY', 'Worker output budget must be a positive integer');
  ensure(!context.signal?.aborted, 'WORKER_ABORTED', 'Worker invocation was aborted');
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(settings.binary, settings.args, {
        cwd, env: { ...settings.env, DSH_HOME: settings.home }, shell: false,
        windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch {
      reject(new HarnessError('WORKER_START', 'Worker could not be started'));
      return;
    }
    const pending = new Map();
    const notifications = [];
    const transcript = [];
    const stderrHash = createHash('sha256');
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let nextId = 1, buffered = '', stdoutBytes = 0, stderrBytes = 0;
    let failure = null, complete = false, settled = false, killTimer;
    let receipt, serverInfo;
    const timer = setTimeout(() => stop(new HarnessError('WORKER_TIMEOUT', 'Worker deadline exceeded')), timeoutMs);
    const abort = () => stop(new HarnessError('WORKER_ABORTED', 'Worker invocation was aborted'));
    context.signal?.addEventListener('abort', abort, { once: true });

    function finish(error, result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer); clearTimeout(killTimer);
      context.signal?.removeEventListener('abort', abort);
      for (const waiter of pending.values()) waiter.reject(error ?? new HarnessError('WORKER_EXIT', 'Worker transport closed'));
      pending.clear();
      if (error) reject(error); else resolve(result);
    }

    function stop(error) {
      if (settled || failure) return;
      failure = error;
      for (const waiter of pending.values()) waiter.reject(error);
      pending.clear();
      child.stdin.destroy();
      try { child.kill('SIGKILL'); } catch { /* The bounded close check below reports uncertainty. */ }
      // This bounds our wait for the direct child only; descendants are not contained.
      killTimer = setTimeout(() => {
        // A descendant may retain the pipe handles after the direct child exits.
        // Relinquish our transport ownership without claiming descendant termination.
        child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy(); child.unref();
        finish(new HarnessError('WORKER_TERMINATION_UNCONFIRMED', 'Direct worker transport closure could not be confirmed'));
      }, 1_000);
    }

    function frame(message) {
      ensure(record(message) && message.jsonrpc === '2.0', 'WORKER_PROTOCOL', 'Invalid JSON-RPC envelope');
      if (own(message, 'method')) {
        ensure(!own(message, 'id') && typeof message.method === 'string' && Object.keys(message).every(key => ['jsonrpc', 'method', 'params'].includes(key)), 'WORKER_PROTOCOL', 'Worker initiated an unsupported request');
        validateNotification(message.method, message.params);
        notifications.push({ method: message.method, params: message.params });
      } else {
        ensure(own(message, 'id') && pending.has(message.id) && own(message, 'result') !== own(message, 'error') && Object.keys(message).every(key => ['jsonrpc', 'id', 'result', 'error'].includes(key)), 'WORKER_PROTOCOL', 'Unexpected worker response');
        const waiter = pending.get(message.id);
        if (own(message, 'error')) {
          ensure(record(message.error) && Number.isSafeInteger(message.error.code), 'WORKER_PROTOCOL', 'Invalid worker error response');
          // Runtime diagnostics may contain credentials; expose only the numeric code.
          const error = new HarnessError('WORKER_RPC', 'Worker rejected a protocol request', { rpcCode: message.error.code });
          pending.delete(message.id); waiter.reject(error);
        } else {
          pending.delete(message.id); waiter.resolve(message.result);
        }
      }
      transcript.push({ direction: 'received', message });
    }

    function request(method, params) {
      ensure(!failure && !settled, 'WORKER_EXIT', 'Worker transport is unavailable');
      const id = nextId++;
      const message = { jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) };
      const line = canonical(message) + '\n';
      ensure(Buffer.byteLength(line) <= maxOutputBytes, 'WORKER_INPUT_LIMIT', 'Worker request exceeds the byte budget');
      transcript.push({ direction: 'sent', message });
      return new Promise((resolveRequest, rejectRequest) => {
        pending.set(id, { resolve: resolveRequest, reject: rejectRequest });
        child.stdin.write(line, error => { if (error) stop(new HarnessError('WORKER_TRANSPORT', 'Worker input transport failed')); });
      });
    }

    child.on('error', () => stop(new HarnessError('WORKER_START', 'Worker could not be started')));
    child.stdin.on('error', () => stop(new HarnessError('WORKER_TRANSPORT', 'Worker input transport failed')));
    child.stdout.on('error', () => stop(new HarnessError('WORKER_TRANSPORT', 'Worker output transport failed')));
    child.stderr.on('error', () => stop(new HarnessError('WORKER_TRANSPORT', 'Worker diagnostic transport failed')));
    child.stdout.on('data', chunk => {
      if (failure || settled) return;
      stdoutBytes += chunk.length;
      if (stdoutBytes + stderrBytes > maxOutputBytes) return stop(new HarnessError('WORKER_OUTPUT_LIMIT', 'Worker output exceeds the byte budget'));
      try {
        buffered += decoder.decode(chunk, { stream: true });
        let boundary;
        while ((boundary = buffered.indexOf('\n')) >= 0) {
          const line = buffered.slice(0, boundary); buffered = buffered.slice(boundary + 1);
          if (line.trim()) frame(parseJson(line));
        }
      } catch (error) {
        stop(error instanceof HarnessError && error.code === 'WORKER_PROTOCOL' ? error : new HarnessError('WORKER_PROTOCOL', 'Worker emitted invalid JSON-RPC data'));
      }
    });
    child.stderr.on('data', chunk => {
      if (failure || settled) return;
      stderrBytes += chunk.length; stderrHash.update(chunk);
      if (stdoutBytes + stderrBytes > maxOutputBytes) stop(new HarnessError('WORKER_OUTPUT_LIMIT', 'Worker output exceeds the byte budget'));
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      if (failure) return finish(failure);
      try {
        buffered += decoder.decode();
        ensure(!buffered.trim(), 'WORKER_PROTOCOL', 'Worker emitted an unterminated protocol frame');
        ensure(code === 0 && signal === null, 'WORKER_EXIT', 'Worker did not exit successfully');
        ensure(complete, 'WORKER_PROTOCOL', 'Worker exited before completing the session lifecycle');
        const secrets = Object.entries(settings.env).filter(([name]) => sensitiveName.test(name)).map(([, value]) => value).filter(Boolean).sort((a, b) => b.length - a.length);
        const wireMessage = message => ({
          jsonrpc: '2.0', ...(own(message, 'id') ? { id: message.id } : {}),
          ...(own(message, 'method') ? { method: message.method } : {}),
          ...(own(message, 'params') ? { params: redact(message.params, secrets) } : {}),
          ...(own(message, 'result') ? { result: redact(message.result, secrets) } : {}),
          ...(own(message, 'error') ? { error: redact(message.error, secrets) } : {}),
        });
        // Keep fixed protocol identifiers and commitments outside content redaction.
        const result = {
          protocol, sessionId: redact(input.sessionId, secrets), cwd: redact(cwd, secrets),
          serverInfo: { name: 'deepseek-harness-sdk-runtime', version: redact(serverInfo.version, secrets) },
          messageId: redact(receipt.messageId, secrets),
          notifications: notifications.map(({ method, params }) => ({ method, params: redact(params, secrets) })),
          transcript: transcript.map(({ direction, message }) => ({ direction, message: wireMessage(message) })),
          transcriptHash: digest(transcript), stdoutBytes, stderrBytes,
          stderrSha256: stderrHash.digest('hex'), exitCode: code,
        };
        ensure(Buffer.byteLength(canonical(result)) <= maxOutputBytes, 'WORKER_OUTPUT_LIMIT', 'Worker evidence exceeds the byte budget');
        finish(null, result);
      } catch (error) {
        finish(error instanceof HarnessError ? error : new HarnessError('WORKER_PROTOCOL', 'Worker evidence is invalid'));
      }
    });
    child.once('spawn', async () => {
      try {
        const initialized = await request('initialize', {
          cwd, provider: settings.provider, model: settings.model,
          ...(settings.reasoningEffort === undefined ? {} : { reasoningEffort: settings.reasoningEffort }),
          ...(settings.maxTokens === undefined ? {} : { maxTokens: settings.maxTokens }),
        });
        ensure(record(initialized) && record(initialized.serverInfo) && initialized.serverInfo.name === 'deepseek-harness-sdk-runtime' && typeof initialized.serverInfo.version === 'string', 'WORKER_PROTOCOL', 'Worker server identity does not match the DSH SDK');
        serverInfo = { name: initialized.serverInfo.name, version: initialized.serverInfo.version };
        receipt = await request('session/prompt', { sessionId: input.sessionId, contentBlocks: [{ type: 'text', text: input.prompt }] });
        ensure(record(receipt) && typeof receipt.messageId === 'string' && receipt.messageId.length > 0, 'WORKER_PROTOCOL', 'Worker did not provide a prompt receipt');
        const waited = await request('session/wait', { sessionId: input.sessionId });
        ensure(record(waited) && Object.keys(waited).length === 0, 'WORKER_PROTOCOL', 'Invalid worker wait result');
        const shutdown = await request('shutdown');
        ensure(record(shutdown) && Object.keys(shutdown).length === 0, 'WORKER_PROTOCOL', 'Invalid worker shutdown result');
        complete = true;
        child.stdin.end();
      } catch (error) {
        stop(error instanceof HarnessError ? error : new HarnessError('WORKER_PROTOCOL', 'Worker protocol failed'));
      }
    });
    // Handle a signal that changed between the preflight check and listener installation.
    if (context.signal?.aborted) abort();
  });
}

/**
 * One or many named dsh services. A single plain object is the legacy shape and becomes
 * `dsh.run`; an array requires an explicit, unique `name` per entry so several reviewed
 * services can be registered side by side (DeepSeek Harness's own plugin-composition role,
 * done as a fixed, reviewed set at startup rather than runtime hot-swap — see dsh.catalog).
 */
function normalizeServices(dsh) {
  const isArray = Array.isArray(dsh);
  const list = isArray ? dsh : [dsh];
  ensure(list.length > 0, 'WORKER_CONFIG', 'At least one dsh service is required');
  const named = list.map((entry) => {
    ensure(record(entry), 'WORKER_CONFIG', 'Each dsh service must be a configuration object');
    const name = entry.name ?? (isArray ? undefined : 'dsh.run');
    ensure(typeof name === 'string' && serviceName.test(name), 'WORKER_CONFIG', 'Invalid or missing dsh service name');
    const { name: _omit, ...rest } = entry;
    return { name, settings: normalize(rest) };
  });
  ensure(new Set(named.map((n) => n.name)).size === named.length, 'WORKER_CONFIG', 'dsh service names must be unique');
  return named;
}

/** Register optional delegated agent processes. Registration performs no I/O. */
export function makeAgentTools(config = {}) {
  validateSchema(config, objectSchema({ dsh: true }));
  if (!config.dsh) return [];
  const services = normalizeServices(config.dsh);
  const tools = services.map(({ name, settings }) => {
    const { env, ...publicSettings } = settings;
    const binding = freeze({ ...publicSettings, protocol, environmentNames: Object.keys(env).sort(), environmentHash: digest(env), adapterConfigHash: digest(settings) });
    return Object.freeze({
      name, version: settings.version, effect: 'process', inputSchema: freeze(copy(inputSchema)), config: binding,
      async execute(input, context) {
        validateSchema(input, inputSchema);
        const invocation = copy(input);
        ensure(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(invocation.sessionId), 'WORKER_INPUT', 'Session identity must be 1-128 safe identifier characters');
        const cwd = await workingDirectory(invocation, context.workspaceRoot);
        return runProtocol(settings, invocation, context, cwd);
      },
    });
  });
  // Discoverable as inert data only: name/version/provider/model, never binary, home, or env values.
  const catalog = freeze(services.map(({ name, settings }) => copy({ name, version: settings.version, provider: settings.provider, model: settings.model }))
    .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const catalogTool = Object.freeze({
    name: 'dsh.catalog', version: '1.0.0', effect: 'pure', inputSchema: freeze(objectSchema({})), config: freeze({ servicesHash: digest(catalog) }),
    execute() { return { services: catalog }; },
  });
  return [...tools, catalogTool];
}
