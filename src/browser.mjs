import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm, stat } from 'node:fs/promises';
import { isAbsolute, join, resolve as resolvePath } from 'node:path';
import { tmpdir } from 'node:os';
import { parseJson, HarnessError } from './value.mjs';

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const envName = /^[A-Za-z_][A-Za-z0-9_]*$/;
const toolName = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_OUTPUT = 1_048_576;
const MAX_SNAPSHOT_CHARS = 200_000;
const PORT_POLL_INTERVAL_MS = 50;

function fail(code, message) { throw new HarnessError(code, message); }
function text(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) fail('BROWSER_CONFIG', `${label} must be a nonempty string`);
  return value;
}
function positive(value, fallback, label) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 2_147_483_647) fail('BROWSER_CONFIG', `${label} must be a positive bounded integer`);
  return result;
}
function limits(config, context, name) {
  const policy = context?.policy ?? {};
  if (Array.isArray(policy.allowedTools) && !policy.allowedTools.includes(name)) fail('BROWSER_POLICY', 'Browser tool is not allowlisted');
  if (Array.isArray(policy.allowedEffects) && !policy.allowedEffects.includes('process')) fail('BROWSER_POLICY', 'Browser effect is not allowlisted');
  if (context?.signal?.aborted) fail('BROWSER_ABORTED', 'Browser snapshot was cancelled');
  return {
    timeoutMs: Math.min(config.timeoutMs, positive(policy.timeoutMs, config.timeoutMs, 'policy timeoutMs')),
    maxOutputBytes: Math.min(config.maxOutputBytes, positive(policy.maxOutputBytes, config.maxOutputBytes, 'policy maxOutputBytes')),
  };
}

function browserSettings(value) {
  const config = { ...value };
  config.name = config.name ?? 'browser.snapshot';
  if (typeof config.name !== 'string' || !toolName.test(config.name)) fail('BROWSER_CONFIG', 'Invalid browser tool name');
  config.executable = text(config.executable, 'browser executable');
  if (!isAbsolute(config.executable)) fail('BROWSER_CONFIG', 'Browser executable must be an absolute path');
  if (config.executableSha256 !== undefined && !/^[a-f0-9]{64}$/.test(config.executableSha256)) fail('BROWSER_CONFIG', 'Invalid browser executable digest');
  config.timeoutMs = positive(config.timeoutMs, DEFAULT_TIMEOUT, 'timeoutMs');
  config.maxOutputBytes = positive(config.maxOutputBytes, DEFAULT_OUTPUT, 'maxOutputBytes');
  const allowed = ['name', 'executable', 'executableSha256', 'timeoutMs', 'maxOutputBytes'];
  if (Object.keys(value).some((key) => !allowed.includes(key))) fail('BROWSER_CONFIG', 'Unsupported browser configuration field');
  return config;
}

function loopbackHostname(hostname) {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '[::1]' || hostname === '::1';
}

async function waitForDevToolsPort(portFile, deadline, signal) {
  for (;;) {
    if (signal?.aborted) fail('BROWSER_ABORTED', 'Browser snapshot was cancelled');
    if (Date.now() >= deadline) fail('BROWSER_TIMEOUT', 'Browser did not open its DevTools port in time');
    try {
      const content = await readFile(portFile, 'utf8');
      const [portLine] = content.split('\n');
      const port = Number(portLine);
      if (Number.isInteger(port) && port > 0 && port <= 65535) return port;
    } catch { /* The port file is still being created/written; the deadline above bounds this. */ }
    await new Promise((r) => setTimeout(r, PORT_POLL_INTERVAL_MS));
  }
}

/** Exported for direct unit testing of the loopback re-verification; not part of the tool contract. */
export async function discoverPageTarget(port, signal) {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`, { signal });
  if (!response.ok) fail('BROWSER_CDP', 'Browser DevTools target list request failed');
  let targets;
  try { targets = parseJson(await response.text()); }
  catch { fail('BROWSER_CDP', 'Browser DevTools target list was not strict JSON'); }
  if (!Array.isArray(targets)) fail('BROWSER_CDP', 'Browser DevTools target list had an unexpected shape');
  const page = targets.find((t) => t && typeof t === 'object' && t.type === 'page' && typeof t.webSocketDebuggerUrl === 'string');
  if (!page) fail('BROWSER_CDP', 'Browser has no inspectable page target');
  let url;
  try { url = new URL(page.webSocketDebuggerUrl); } catch { fail('BROWSER_CDP', 'Browser returned an invalid DevTools WebSocket URL'); }
  if (url.protocol !== 'ws:' || !loopbackHostname(url.hostname)) fail('BROWSER_CDP', 'Browser DevTools WebSocket endpoint is not loopback');
  return url.toString();
}

/**
 * One bounded CDP session over one WebSocket: connect, navigate, wait for load, extract
 * text, disconnect. `stop()` is the single choke point every failure path funnels
 * through: it rejects every in-flight call, clears the pending map, and closes the
 * socket — so a page whose JS hangs forever (e.g. an infinite loop blocking the
 * renderer's main thread, which never answers a Runtime.evaluate call) cannot leave
 * this function stuck waiting on a response that will never arrive. Without this, the
 * caller's try/finally that kills the browser process and deletes its profile directory
 * would never run, leaking the process and its unauthenticated local CDP port forever.
 */
async function runCdpSession(wsUrl, url, deadline, signal, maxChars) {
  const socket = new WebSocket(wsUrl);
  let nextId = 1;
  const pending = new Map();
  let stopped = null;

  function stop(error) {
    if (stopped) return;
    stopped = error;
    for (const waiter of pending.values()) waiter.reject(error);
    pending.clear();
    try { socket.close(); } catch { /* already closed */ }
  }

  socket.addEventListener('message', (event) => {
    if (stopped) return;
    let data;
    try { data = parseJson(typeof event.data === 'string' ? event.data : ''); }
    catch { return; } // Malformed/unsolicited frames are ignored; only matched command responses matter.
    if (typeof data?.id === 'number' && pending.has(data.id)) {
      const waiter = pending.get(data.id);
      pending.delete(data.id);
      if (data.error) waiter.reject(new HarnessError('BROWSER_CDP', String(data.error.message ?? 'CDP command failed')));
      else waiter.resolve(data.result);
    }
  });
  socket.addEventListener('close', () => stop(new HarnessError('BROWSER_CDP', 'CDP socket closed unexpectedly')), { once: true });
  socket.addEventListener('error', () => stop(new HarnessError('BROWSER_CDP', 'CDP WebSocket connection failed')), { once: true });

  function call(method, params) {
    if (stopped) return Promise.reject(stopped);
    return new Promise((resolve, reject) => {
      if (socket.readyState !== WebSocket.OPEN) { reject(new HarnessError('BROWSER_CDP', 'CDP socket is not open')); return; }
      const id = nextId++;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params: params ?? {} }));
    });
  }

  const remaining = deadline - Date.now();
  if (remaining <= 0) stop(new HarnessError('BROWSER_TIMEOUT', 'Browser snapshot exceeded its time budget'));
  const timer = setTimeout(() => stop(new HarnessError('BROWSER_TIMEOUT', 'Browser snapshot exceeded its time budget')), Math.max(remaining, 0));
  const onAbort = () => stop(new HarnessError('BROWSER_ABORTED', 'Browser snapshot was cancelled'));
  if (signal?.aborted) onAbort(); else signal?.addEventListener('abort', onAbort, { once: true });

  try {
    if (stopped) throw stopped;
    await new Promise((resolveOpen, reject) => {
      if (socket.readyState === WebSocket.OPEN) { resolveOpen(); return; }
      socket.addEventListener('open', resolveOpen, { once: true });
      // The shared close/error listeners above already call stop(); this just gives the
      // open-wait itself a direct path to reject once stop() has recorded the reason.
      const onOpenSettle = () => { if (stopped) reject(stopped); };
      socket.addEventListener('close', onOpenSettle, { once: true });
      socket.addEventListener('error', onOpenSettle, { once: true });
    });
    if (stopped) throw stopped;

    await call('Page.navigate', { url });
    for (;;) {
      if (stopped) throw stopped;
      const ready = await call('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true });
      if (ready?.result?.value === 'complete') break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const extracted = await call('Runtime.evaluate', {
      expression: `(() => ({ title: document.title, url: document.location.href, text: (document.body ? document.body.innerText : '').slice(0, ${maxChars}) }))()`,
      returnByValue: true,
    });
    const value = extracted?.result?.value;
    if (!value || typeof value !== 'object' || typeof value.text !== 'string') fail('BROWSER_CDP', 'Page snapshot had an unexpected shape');
    return { title: typeof value.title === 'string' ? value.title : '', url: typeof value.url === 'string' ? value.url : '', text: value.text };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
    stop(new HarnessError('BROWSER_CDP', 'Session ended')); // No-op if already stopped; otherwise guarantees the socket closes.
  }
}

/**
 * Launches a configured local Chrome/Chromium headless, opens one real page, and returns
 * a bounded text snapshot. One call owns the browser's entire lifetime: launch, discover,
 * navigate, extract, and guaranteed teardown. No click/type/multi-step scripting in v1 —
 * this is one real capability, not a browser-automation framework. The local DevTools port
 * is unauthenticated for the lifetime of this call; any other local process that reaches it
 * during that window could attach. No real user profile or credentials are ever used — a
 * fresh, isolated profile directory is created and deleted for every call.
 */
export function makeBrowserTools(config) {
  if (config === undefined) return [];
  const settings = browserSettings(config);
  const inputSchema = object({ url: { type: 'string', minLength: 1, maxLength: 8192 } });
  const tool = {
    name: settings.name, version: '1', effect: 'process', inputSchema, config: settings,
    async execute(input, context) {
      let parsedUrl;
      try { parsedUrl = new URL(input.url); } catch { fail('BROWSER_INPUT', 'url must be an absolute URL'); }
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) fail('BROWSER_INPUT', 'url must use http or https');
      const bound = limits(settings, context, settings.name);
      const deadline = Date.now() + bound.timeoutMs;
      let executable;
      try {
        executable = await realpath(settings.executable);
        if (resolvePath(executable) !== resolvePath(settings.executable) || !(await stat(executable)).isFile()) fail('BROWSER_EXECUTABLE', 'Browser executable must be an existing regular file without path aliases');
        if (settings.executableSha256 && createHash('sha256').update(await readFile(executable)).digest('hex') !== settings.executableSha256) fail('BROWSER_EXECUTABLE', 'Browser executable digest does not match');
      } catch (error) {
        if (error instanceof HarnessError) throw error;
        fail('BROWSER_PATH', 'Browser executable is unavailable');
      }
      const profileDir = await mkdtemp(join(tmpdir(), 'concord-browser-'));
      let child;
      let snapshot;
      let profileCleanupFailed = false;
      try {
        child = spawn(executable, [
          '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profileDir}`,
          '--no-first-run', '--no-default-browser-check', '--disable-gpu', '--disable-extensions', 'about:blank',
        ], { env: {}, shell: false, windowsHide: true, stdio: 'ignore' });
        const started = new Promise((_, reject) => child.once('error', () => reject(new HarnessError('BROWSER_PROCESS', 'Browser could not start'))));
        const onAbort = () => fail('BROWSER_ABORTED', 'Browser snapshot was cancelled');
        if (context?.signal?.aborted) onAbort();
        const port = await Promise.race([
          waitForDevToolsPort(join(profileDir, 'DevToolsActivePort'), deadline, context?.signal),
          started,
        ]);
        const wsUrl = await discoverPageTarget(port, context?.signal);
        snapshot = await runCdpSession(wsUrl, parsedUrl.toString(), deadline, context?.signal, Math.min(MAX_SNAPSHOT_CHARS, bound.maxOutputBytes));
        const text = JSON.stringify(snapshot);
        if (Buffer.byteLength(text) > bound.maxOutputBytes) fail('BROWSER_OUTPUT_LIMIT', 'Browser snapshot exceeds the output byte limit');
      } finally {
        if (child) {
          const exited = new Promise((r) => child.once('exit', r));
          if (!child.killed) child.kill('SIGKILL');
          // Windows releases a killed process's open file handles asynchronously;
          // wait for the real exit (bounded) before touching its profile directory.
          await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
        }
        profileCleanupFailed = true;
        for (let attempt = 0; attempt < 3; attempt += 1) {
          try { await rm(profileDir, { recursive: true, force: true }); profileCleanupFailed = false; break; }
          catch { if (attempt === 2) break; await new Promise((r) => setTimeout(r, 250)); }
        }
      }
      // Surfaced as evidence rather than silently discarded: a persistent cleanup failure
      // (AV scanning, disk contention, a lingering OS-level handle) means the deleted-every-call
      // profile-directory guarantee did not hold for this one call, even though it still succeeded.
      return profileCleanupFailed ? { ...snapshot, profileCleanupFailed: true } : snapshot;
    },
  };
  Object.freeze(tool.config);
  Object.freeze(tool.inputSchema);
  Object.freeze(tool);
  return [tool];
}
