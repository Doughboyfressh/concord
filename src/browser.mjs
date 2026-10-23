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
// How long discoverPageTarget keeps trying a connection the browser has not opened yet, when no
// caller deadline is supplied. The session path passes its own, which is always the tighter bound.
const PORT_READY_WINDOW_MS = 2000;

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
export async function discoverPageTarget(port, signal, deadline = Date.now() + PORT_READY_WINDOW_MS) {
  let response;
  /**
   * Retried on a transport failure, refused on anything the browser actually answered.
   *
   * Chromium writes DevToolsActivePort before its HTTP endpoint is necessarily accepting
   * connections, so the first fetch after the port appears can be refused by the socket on a
   * loaded machine. Failing then is wrong twice over: the browser is fine, and under repeated
   * runs it made this the flakiest step in the suite — measured, as an automate exercise failing
   * perhaps one round in four. An unguarded await also let that failure escape as a raw TypeError
   * rather than a BROWSER_CDP refusal, so a caller catching HarnessError saw nothing at all.
   * A response the browser did send is never retried: a malformed target list is its answer. The
   * one exception is a *well-formed* list with no page target yet, which is the same race one step
   * later - the endpoint is answering and the page has not been created - so that is retried too.
   * The "no inspectable page target" refusal now means the deadline passed without one appearing.
   */
  let page;
  for (;;) {
    if (signal?.aborted) fail('BROWSER_ABORTED', 'Browser snapshot was cancelled');
    const expired = () => Date.now() >= deadline;
    const wait = () => new Promise((resolve) => setTimeout(resolve, PORT_POLL_INTERVAL_MS));
    try { response = await fetch(`http://127.0.0.1:${port}/json/list`, { signal }); }
    catch {
      if (expired()) fail('BROWSER_CDP', 'Browser DevTools endpoint never accepted a connection');
      await wait();
      continue;
    }
    if (!response.ok) fail('BROWSER_CDP', 'Browser DevTools target list request failed');
    let targets;
    try { targets = parseJson(await response.text()); }
    catch { fail('BROWSER_CDP', 'Browser DevTools target list was not strict JSON'); }
    if (!Array.isArray(targets)) fail('BROWSER_CDP', 'Browser DevTools target list had an unexpected shape');
    page = targets.find((t) => t && typeof t === 'object' && t.type === 'page' && typeof t.webSocketDebuggerUrl === 'string');
    if (page) break;
    // An empty list is the second half of the same race: the endpoint is up and answering, and
    // the page target has not been created yet. Retried for the same reason and under the same
    // deadline, while a list that is malformed or not JSON is still refused on the first answer.
    if (expired()) fail('BROWSER_CDP', 'Browser has no inspectable page target');
    await wait();
  }
  let url;
  try { url = new URL(page.webSocketDebuggerUrl); } catch { fail('BROWSER_CDP', 'Browser returned an invalid DevTools WebSocket URL'); }
  if (url.protocol !== 'ws:' || !loopbackHostname(url.hostname)) fail('BROWSER_CDP', 'Browser DevTools WebSocket endpoint is not loopback');
  return url.toString();
}

/**
 * Opens one bounded CDP session over one WebSocket and exposes its raw `call(method,
 * params)`. `stop()` is the single choke point every failure path funnels through: it
 * rejects every in-flight call, clears the pending map, and closes the socket — so a page
 * whose JS hangs forever (e.g. an infinite loop blocking the renderer's main thread, which
 * never answers a Runtime.evaluate call) cannot leave a caller stuck waiting on a response
 * that will never arrive. Without this, a caller's try/finally that kills the browser
 * process and deletes its profile directory would never run, leaking the process and its
 * unauthenticated local CDP port forever. Shared by every tool built on this session, so
 * every one of them gets this guarantee identically rather than reimplementing it.
 */
function openCdpSession(wsUrl, deadline, signal) {
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

  const ready = new Promise((resolveOpen, reject) => {
    if (socket.readyState === WebSocket.OPEN) { resolveOpen(); return; }
    socket.addEventListener('open', resolveOpen, { once: true });
    // The shared close/error listeners above already call stop(); this just gives the
    // open-wait itself a direct path to reject once stop() has recorded the reason.
    const onOpenSettle = () => { if (stopped) reject(stopped); };
    socket.addEventListener('close', onOpenSettle, { once: true });
    socket.addEventListener('error', onOpenSettle, { once: true });
  });

  async function close() {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
    stop(new HarnessError('BROWSER_CDP', 'Session ended')); // No-op if already stopped; otherwise guarantees the socket closes.
  }

  return { call, ready, close, get stopped() { return stopped; } };
}

/**
 * Open a session, retrying a connection the browser has not accepted yet.
 *
 * discoverPageTarget already retries its HTTP probe, for a stated reason: Chromium writes
 * DevToolsActivePort before its endpoint is necessarily accepting connections, so the first
 * attempt after the port appears can be refused by the socket on a loaded machine. That reason
 * applies in full to the WebSocket opened immediately afterwards, and it was the one step with
 * no retry - which made "CDP WebSocket connection failed" a routine outcome under load. Measured
 * on this machine before the change: two runs of the suite in five failed, every time on a
 * transport error rather than on anything a test asserted.
 *
 * Only the initial open is retried. A socket that drops while carrying a session stays fatal:
 * the browser went away mid-conversation, and reconnecting would resume against a page whose
 * state nobody has established.
 */
async function connectCdpSession(wsUrl, deadline, signal) {
  for (;;) {
    if (signal?.aborted) fail('BROWSER_ABORTED', 'Browser snapshot was cancelled');
    if (Date.now() >= deadline) fail('BROWSER_TIMEOUT', 'Browser did not accept a CDP connection in time');
    const session = openCdpSession(wsUrl, deadline, signal);
    try {
      await session.ready;
      return session;
    } catch (error) {
      await session.close();
      // A deadline or an abort is the answer, not something to attempt again.
      const code = error instanceof HarnessError ? error.code : null;
      if (code === 'BROWSER_ABORTED' || code === 'BROWSER_TIMEOUT') throw error;
      if (Date.now() + PORT_POLL_INTERVAL_MS >= deadline) throw error;
      await new Promise((r) => setTimeout(r, PORT_POLL_INTERVAL_MS));
    }
  }
}

/** Connect, navigate, wait for load, extract a bounded text snapshot, disconnect. */
async function runCdpSession(wsUrl, url, deadline, signal, maxChars) {
  const session = await connectCdpSession(wsUrl, deadline, signal);
  try {
    if (session.stopped) throw session.stopped;
    await session.ready;
    if (session.stopped) throw session.stopped;

    await session.call('Page.navigate', { url });
    for (;;) {
      if (session.stopped) throw session.stopped;
      const ready = await session.call('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true });
      if (ready?.result?.value === 'complete') break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const extracted = await session.call('Runtime.evaluate', {
      expression: `(() => ({ title: document.title, url: document.location.href, text: (document.body ? document.body.innerText : '').slice(0, ${maxChars}) }))()`,
      returnByValue: true,
    });
    const value = extracted?.result?.value;
    if (!value || typeof value !== 'object' || typeof value.text !== 'string') fail('BROWSER_CDP', 'Page snapshot had an unexpected shape');
    return { title: typeof value.title === 'string' ? value.title : '', url: typeof value.url === 'string' ? value.url : '', text: value.text };
  } finally { await session.close(); }
}

const MAX_ACTIONS = 20;
const MAX_EXTRACT_CHARS = 20_000;
const MAX_FORM_FIELDS = 500;
// Fixed function bodies: caller-supplied selector/value always travel as CDP `arguments`
// (JSON values), never interpolated into source text, so a crafted selector or value can
// never break out of the function body (unlike the `maxChars` interpolation above, which
// is safe only because it is a server-controlled integer, never caller text).
const CLICK_FUNCTION = "function(sel){var el=document.querySelector(sel); if(!el) throw new Error('selector not found'); el.scrollIntoView({block:'center'}); el.click();}";
const FILL_FUNCTION = "function(sel,val){var el=document.querySelector(sel); if(!el) throw new Error('selector not found'); el.focus(); el.value=val; el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true}));}";
const EXISTS_FUNCTION = "function(sel){return !!document.querySelector(sel);}";
const EXTRACT_FUNCTION = "function(sel,max){var el=sel?document.querySelector(sel):document.body; if(sel&&!el) throw new Error('selector not found'); return (el?el.innerText:'').slice(0,max);}";
// Bounds (maxFields, maxValueChars) are applied here, inside the browser-side function,
// before CDP ever serializes the return value — not only at the outer maxOutputBytes check
// — so one pathological hidden field can't balloon the CDP response before that check runs.
// A field literally named "__proto__"/"prototype"/"constructor" is skipped outright, matching
// the same reserved-name denylist engine.mjs's resolve() and json.mergeShallow already apply
// elsewhere in this codebase — not just because the naive `fields[node.name] = ...` assignment
// would otherwise hit Object.prototype's accessor and silently vanish with no own key at all,
// but because returning a "__proto__"-keyed value through CDP's own returnByValue appears to
// hang the DevTools protocol response entirely (verified empirically: an otherwise-identical
// page with a differently-named field returns normally; this one makes the call time out).
// The field NAME is bounded by the same maxValueChars cap as the value, not just the value — a
// page can set an arbitrarily long `name` attribute from script, and only the value side was
// bounded before.
const EXTRACT_FORM_FUNCTION = "function(sel,maxFields,maxValueChars){var el=document.querySelector(sel); if(!el) throw new Error('selector not found'); var nodes=el.querySelectorAll('input[name],select[name],textarea[name]'); var unsafe=['__proto__','prototype','constructor']; var fields={}, n=0; for (var i=0;i<nodes.length && n<maxFields;i++){ var node=nodes[i]; var key=String(node.name).slice(0,maxValueChars); if(unsafe.indexOf(key)!==-1) continue; var value=node.value==null?'':String(node.value); fields[key]=value.slice(0,maxValueChars); n++; } return fields;}";

/**
 * Connect, navigate, then run a bounded sequence of click/fill/wait/extract actions over
 * one CDP session — the whole action list is the declared input and the whole result list
 * is the output, so this stays a pure function of its input and replay-safe; nothing is
 * session state held open across separate calls. Attaches to exactly one CDP target for the
 * entire sequence (never re-discovers mid-script), so a hostile page's `window.open()`
 * cannot pull the automation onto a different, unintended target.
 */
async function runCdpAutomation(wsUrl, url, actions, deadline, signal, maxExtractChars) {
  const session = await connectCdpSession(wsUrl, deadline, signal);
  try {
    if (session.stopped) throw session.stopped;
    await session.ready;
    if (session.stopped) throw session.stopped;

    await session.call('Page.navigate', { url });
    for (;;) {
      if (session.stopped) throw session.stopped;
      const ready = await session.call('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true });
      if (ready?.result?.value === 'complete') break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const documentHandle = await session.call('Runtime.evaluate', { expression: 'document', returnByValue: false });
    const documentObjectId = documentHandle?.result?.objectId;
    if (typeof documentObjectId !== 'string') fail('BROWSER_CDP', 'Browser did not return a usable document handle');

    async function callOn(functionDeclaration, args) {
      if (session.stopped) throw session.stopped;
      const result = await session.call('Runtime.callFunctionOn', {
        objectId: documentObjectId, functionDeclaration, arguments: args.map((value) => ({ value })), returnByValue: true,
      });
      if (result?.exceptionDetails) fail('BROWSER_ACTION', String(result.exceptionDetails.exception?.description ?? 'Browser action failed'));
      return result?.result?.value;
    }

    const results = [];
    for (const action of actions) {
      if (action.type === 'click') {
        await callOn(CLICK_FUNCTION, [action.selector]);
        results.push({ type: 'click', selector: action.selector, ok: true });
      } else if (action.type === 'fill') {
        await callOn(FILL_FUNCTION, [action.selector, action.value ?? '']);
        results.push({ type: 'fill', selector: action.selector, ok: true });
      } else if (action.type === 'wait') {
        for (;;) {
          if (session.stopped) throw session.stopped;
          if (Date.now() >= deadline) fail('BROWSER_TIMEOUT', 'Browser session exceeded its time budget');
          if (await callOn(EXISTS_FUNCTION, [action.selector])) break;
          await new Promise((r) => setTimeout(r, 100));
        }
        results.push({ type: 'wait', selector: action.selector, ok: true });
      } else if (action.type === 'extractForm') {
        const fields = await callOn(EXTRACT_FORM_FUNCTION, [action.selector, MAX_FORM_FIELDS, maxExtractChars]);
        results.push({ type: 'extractForm', selector: action.selector, fields: (fields && typeof fields === 'object' && !Array.isArray(fields)) ? fields : {} });
      } else {
        const text = await callOn(EXTRACT_FUNCTION, [action.selector ?? null, maxExtractChars]);
        results.push({ type: 'extract', selector: action.selector ?? null, text: typeof text === 'string' ? text : '' });
      }
    }
    return { url, actions: results };
  } finally { await session.close(); }
}

/**
 * Launches a configured local Chrome/Chromium headless, opens one real page, discovers its
 * CDP endpoint, hands the open WebSocket to `run(wsUrl, deadline)`, then guarantees
 * teardown regardless of outcome. Shared by every `process`-effect browser tool so each one
 * gets the same launch/discover/kill/profile-cleanup discipline identically.
 */
async function launchBrowserSession(settings, bound, context, run) {
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
  let result;
  let profileCleanupFailed = false;
  try {
    child = spawn(executable, [
      '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profileDir}`,
      '--no-first-run', '--no-default-browser-check', '--disable-gpu', '--disable-extensions', 'about:blank',
    ], { env: {}, shell: false, windowsHide: true, stdio: 'ignore' });
    // Asynchronous launch failures only, and on Windows there are none to catch: a missing
    // executable is already refused as BROWSER_PATH by the realpath check above, and a regular
    // file that is not executable makes spawn() throw EFTYPE synchronously — measured — so it
    // never becomes an 'error' event. A browser that starts and then dies is not this code
    // either; the port file simply never appears and the deadline reports BROWSER_TIMEOUT. Kept
    // because the event is real on other platforms and costs nothing here.
    const started = new Promise((_, reject) => child.once('error', () => reject(new HarnessError('BROWSER_PROCESS', 'Browser could not start'))));
    const onAbort = () => fail('BROWSER_ABORTED', 'Browser snapshot was cancelled');
    if (context?.signal?.aborted) onAbort();
    const port = await Promise.race([
      waitForDevToolsPort(join(profileDir, 'DevToolsActivePort'), deadline, context?.signal),
      started,
    ]);
    const wsUrl = await discoverPageTarget(port, context?.signal, deadline);
    result = await run(wsUrl, deadline);
    const text = JSON.stringify(result);
    if (Buffer.byteLength(text) > bound.maxOutputBytes) fail('BROWSER_OUTPUT_LIMIT', 'Browser result exceeds the output byte limit');
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
  return profileCleanupFailed ? { ...result, profileCleanupFailed: true } : result;
}

const actionSchema = {
  type: 'object', additionalProperties: false, required: ['type'],
  properties: {
    type: { enum: ['click', 'fill', 'wait', 'extract', 'extractForm'] },
    selector: { type: 'string', minLength: 1, maxLength: 1024 },
    value: { type: 'string', maxLength: 8192 },
  },
};
const automateInputSchema = object({
  url: { type: 'string', minLength: 1, maxLength: 8192 },
  actions: { type: 'array', minItems: 1, maxItems: MAX_ACTIONS, items: actionSchema },
});

/**
 * Launches a configured local Chrome/Chromium headless, opens one real page, and returns
 * a bounded text snapshot (`browser.snapshot`), or runs a bounded click/fill/wait/extract
 * action sequence over the same page in one session (`browser.automate`, ego-lite's
 * multi-step-interaction role). Each call owns the browser's entire lifetime: launch,
 * discover, act, and guaranteed teardown — no session state is ever held open across two
 * separate calls (see `docs/browser.md` for why: it would break replay). The local DevTools
 * port is unauthenticated for the lifetime of a call; any other local process that reaches
 * it during that window could attach. No real user profile or credentials are ever used — a
 * fresh, isolated profile directory is created and deleted for every call. `fill` values are
 * journaled as ordinary task input like any other tool's input — never type credentials
 * through this tool.
 */
export function makeBrowserTools(config) {
  if (config === undefined) return [];
  const settings = browserSettings(config);
  const snapshotSchema = object({ url: { type: 'string', minLength: 1, maxLength: 8192 } });
  const snapshotTool = {
    name: settings.name, version: '1', effect: 'process', inputSchema: snapshotSchema, config: settings,
    async execute(input, context) {
      let parsedUrl;
      try { parsedUrl = new URL(input.url); } catch { fail('BROWSER_INPUT', 'url must be an absolute URL'); }
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) fail('BROWSER_INPUT', 'url must use http or https');
      const bound = limits(settings, context, settings.name);
      return launchBrowserSession(settings, bound, context, (wsUrl, deadline) =>
        runCdpSession(wsUrl, parsedUrl.toString(), deadline, context?.signal, Math.min(MAX_SNAPSHOT_CHARS, bound.maxOutputBytes)));
    },
  };
  const automateTool = {
    name: 'browser.automate', version: '1', effect: 'process', inputSchema: automateInputSchema, config: settings,
    async execute(input, context) {
      let parsedUrl;
      try { parsedUrl = new URL(input.url); } catch { fail('BROWSER_INPUT', 'url must be an absolute URL'); }
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) fail('BROWSER_INPUT', 'url must use http or https');
      for (const action of input.actions) {
        if (['click', 'fill', 'wait', 'extractForm'].includes(action.type) && typeof action.selector !== 'string') fail('BROWSER_INPUT', `"${action.type}" actions require a selector`);
        if (action.type === 'fill' && typeof action.value !== 'string') fail('BROWSER_INPUT', '"fill" actions require a value');
      }
      const bound = limits(settings, context, 'browser.automate');
      return launchBrowserSession(settings, bound, context, (wsUrl, deadline) =>
        runCdpAutomation(wsUrl, parsedUrl.toString(), input.actions, deadline, context?.signal, Math.min(MAX_EXTRACT_CHARS, bound.maxOutputBytes)));
    },
  };
  for (const tool of [snapshotTool, automateTool]) {
    Object.freeze(tool.config);
    Object.freeze(tool.inputSchema);
    Object.freeze(tool);
  }
  return [snapshotTool, automateTool];
}
