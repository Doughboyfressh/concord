import { spawn } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { HarnessError } from './value.mjs';

/**
 * The desktop shell: a window onto the loopback server, and nothing more.
 *
 * Concord installs no dependencies, so there is no Electron and no Tauri here. What there is
 * instead is an already-installed Chromium opened in application mode, which gives a chromeless
 * window owned by this process and closing with it. The harness, the policy, the approvals and
 * the journal are exactly what `scripts/chat.mjs` already serves; this file adds a frame around
 * that page and no authority whatsoever.
 *
 * Everything deciding what gets launched is a pure function of injected inputs, so the argv a
 * real machine would produce is asserted in tests without launching a browser.
 *
 * Not to be confused with `src/browser.mjs`, which launches headless Chromium with a throwaway
 * profile and a debugging port to implement the `browser.snapshot` tool. That is a page reader
 * under an approval gate. This is a window for a person, and it is not a tool at all.
 */

const fail = (code, message, detail) => { throw new HarnessError(code, message, detail); };

/**
 * Only the literal loopback addresses, and deliberately not `localhost`: the server authorizes a
 * request by exact `Host` match against the interface it bound, so a window pointed at
 * `localhost` would render and then have every request denied. Refusing the URL beats shipping a
 * window that silently cannot talk to its own server.
 */
// `[::1]` carries its brackets: that is what URL.hostname reports for an IPv6 host, and it is the
// form listenServer reports when the server bound ::1, so both spellings have to be here or the
// shell would refuse the URL its own server just printed.
const LOOPBACK = new Set(['127.0.0.1', '::1', '[::1]']);

/** The one URL this shell will open: loopback http, no credentials, no query, no fragment. */
export function checkAppUrl(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) fail('DESKTOP_URL', 'The window needs the URL the local server reported');
  let parsed;
  try { parsed = new URL(value); } catch { return fail('DESKTOP_URL', 'The window URL is not a URL'); }
  if (parsed.protocol !== 'http:') fail('DESKTOP_URL', 'The window opens the local server over http and nothing else', { protocol: parsed.protocol });
  if (!LOOPBACK.has(parsed.hostname)) fail('DESKTOP_URL', 'The window opens a loopback address only, and not localhost, because the server authorizes on an exact Host match', { host: parsed.hostname });
  if (parsed.username || parsed.password) fail('DESKTOP_URL', 'The window URL must carry no credentials');
  // A browser command line is readable by every other process on the machine. Refusing a query
  // and a fragment is what makes a session token structurally incapable of reaching the process
  // table: the page fetches its token from /api/state over the socket instead.
  if (parsed.search || parsed.hash) fail('DESKTOP_URL', 'The window URL must carry no query or fragment, so no secret can reach the process table');
  if (parsed.pathname !== '/') fail('DESKTOP_URL', 'The window opens the application root');
  return parsed.origin + '/';
}

/** Where each platform keeps a Chromium that supports application mode, in preference order. */
export function browserCandidates(platform, env = {}) {
  if (platform === 'win32') {
    const roots = ['LOCALAPPDATA', 'ProgramFiles', 'ProgramFiles(x86)']
      .map((name) => env[name]).filter((value) => typeof value === 'string' && value.length > 0);
    const out = [];
    for (const relative of [
      ['Google', 'Chrome', 'Application', 'chrome.exe'],
      ['Microsoft', 'Edge', 'Application', 'msedge.exe'],
      ['BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'],
      ['Chromium', 'Application', 'chrome.exe'],
    ]) {
      for (const root of roots) out.push({ name: relative[relative.length - 1], executable: path.win32.join(root, ...relative) });
    }
    return out;
  }
  if (platform === 'darwin') {
    return [
      { name: 'Google Chrome', executable: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' },
      { name: 'Microsoft Edge', executable: '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge' },
      { name: 'Brave Browser', executable: '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser' },
      { name: 'Chromium', executable: '/Applications/Chromium.app/Contents/MacOS/Chromium' },
    ];
  }
  return [
    { name: 'google-chrome', executable: '/usr/bin/google-chrome' },
    { name: 'google-chrome-stable', executable: '/usr/bin/google-chrome-stable' },
    { name: 'chromium', executable: '/usr/bin/chromium' },
    { name: 'chromium-browser', executable: '/usr/bin/chromium-browser' },
    { name: 'microsoft-edge', executable: '/usr/bin/microsoft-edge' },
    { name: 'brave-browser', executable: '/usr/bin/brave-browser' },
  ];
}

const isFile = (file) => { try { return existsSync(file) && statSync(file).isFile(); } catch { return false; } };

/**
 * Which browser hosts the window. `CONCORD_BROWSER` is the operator's override; it is still
 * required to exist, and a missing one is an error rather than a silent fall back to a browser
 * they did not name.
 */
export function findAppBrowser({ platform = process.platform, env = process.env, exists = isFile } = {}) {
  const override = env.CONCORD_BROWSER;
  if (typeof override === 'string' && override.length > 0) {
    if (!exists(override)) fail('DESKTOP_BROWSER', 'CONCORD_BROWSER names a file that is not there', { executable: override });
    return { name: path.basename(override), executable: override, configured: true };
  }
  for (const candidate of browserCandidates(platform, env)) {
    if (exists(candidate.executable)) return { ...candidate, configured: false };
  }
  return null;
}

/**
 * The exact command line. Application mode plus a private profile directory is the whole trick:
 * the window has no tab strip and no omnibox, and it reaches none of the user's cookies, history,
 * sessions or extensions, because it is a different profile from the one they browse with.
 *
 * Nothing that weakens the renderer is permitted, which is why the argv is built in one reviewed
 * place: no remote debugging port, no disabled web security, no proxy. A caller supplies only a
 * validated loopback URL, an absolute profile directory, and a window size.
 */
export function appWindowArgv({ url, profileDir, windowSize = '1180,860' } = {}) {
  const target = checkAppUrl(url);
  if (typeof profileDir !== 'string' || !path.isAbsolute(profileDir)) fail('DESKTOP_PROFILE', 'The window needs an absolute private profile directory');
  if (profileDir.includes('\0')) fail('DESKTOP_PROFILE', 'The profile directory is not a usable path');
  if (!/^[1-9][0-9]{2,3},[1-9][0-9]{2,3}$/.test(String(windowSize))) fail('DESKTOP_WINDOW', 'The window size must be two plain pixel counts');
  return [
    '--app=' + target,
    '--user-data-dir=' + profileDir,
    // The window is an application, so none of the browser's own onboarding belongs in it.
    '--no-first-run',
    '--no-default-browser-check',
    // The private profile is empty anyway, so this states the intent rather than changing the
    // outcome: nothing third-party runs in the page.
    '--disable-extensions',
    '--window-size=' + String(windowSize),
  ];
}

/**
 * Open the window and resolve when it closes. The child owns no pipes, and the close is the
 * signal to shut the server down, which is what makes this an application rather than a page
 * that happens to be served.
 *
 * Unlike the headless tool in `src/browser.mjs`, this cannot run with an empty environment: a
 * windowed process needs its platform's display and profile variables to open at all, so the
 * caller passes a curated set rather than inheriting everything.
 */
export function launchAppWindow({ executable, url, profileDir, windowSize, env = {}, signal } = {}) {
  if (typeof executable !== 'string' || executable.length === 0) fail('DESKTOP_BROWSER', 'The window needs the browser executable to run');
  const args = appWindowArgv({ url, profileDir, windowSize });
  const child = spawn(executable, args, { shell: false, stdio: 'ignore', windowsHide: false, env });
  const closed = new Promise((resolve, reject) => {
    let settled = false;
    child.once('error', () => {
      if (settled) return;
      settled = true;
      reject(new HarnessError('DESKTOP_LAUNCH', 'The browser window could not be started', { executable }));
    });
    child.once('exit', (code, exitSignal) => { if (!settled) { settled = true; resolve({ code, signal: exitSignal }); } });
    if (signal) {
      if (signal.aborted) child.kill();
      else signal.addEventListener('abort', () => child.kill(), { once: true });
    }
  });
  return { child, args, closed };
}

/**
 * What to say, and what to supply, about a configured model before anything is called.
 *
 * The model adapter requires a credential to exist for every request. A model server on loopback
 * — llama.cpp, Ollama, LM Studio — accepts any bearer token and checks none, so on that one path
 * the requirement is a formality standing between a user and their own machine. This supplies a
 * token for it, and the limits on when are the point:
 *
 *   - only when the configured origin is loopback, never for a remote one;
 *   - never over a value the operator actually set, so a real key always wins;
 *   - the value is a fixed, obviously non-secret string, not something generated to look like one;
 *   - and the launcher prints that it did, so nobody believes a credential was found.
 *
 * Returns what the caller should report and, when applicable, the variable to set. It sets
 * nothing itself, so the decision can be tested without touching the environment.
 */
export function modelCredentialPlan(model, env = process.env) {
  if (!model || typeof model !== 'object') return { configured: false, summary: 'none configured; turns will refuse' };
  const origin = typeof model.origin === 'string' ? model.origin : '';
  const name = typeof model.apiKeyEnv === 'string' ? model.apiKeyEnv : '';
  const where = `${model.model ?? 'unnamed model'} at ${origin || 'no origin'}`;
  if (!name) return { configured: true, summary: `${where}; no apiKeyEnv configured, so calls will refuse` };
  if (env[name]) return { configured: true, summary: `${where}; credential from ${name}` };

  let loopback = false;
  try {
    const parsed = new URL(origin);
    loopback = LOOPBACK.has(parsed.hostname);
  } catch { loopback = false; }

  if (!loopback) {
    return { configured: true, summary: `${where}; ${name} is not set, so calls will refuse with INTEGRATION_CREDENTIAL` };
  }
  return {
    configured: true,
    setEnv: { name, value: 'loopback-server-ignores-this' },
    summary: `${where}; ${name} is not set, so a placeholder is used for this loopback server, which checks none. Set ${name} to override.`,
  };
}

/**
 * The fallback when no Chromium is installed: hand the URL to whatever the desktop uses. That
 * gives a tab rather than an application window, so the caller reports it as the lesser outcome
 * instead of presenting it as success. Fixed argv, no shell, on every platform.
 */
export function openDefaultBrowser(url, { platform = process.platform } = {}) {
  const target = checkAppUrl(url);
  const [executable, args] = platform === 'win32'
    ? ['rundll32', ['url.dll,FileProtocolHandler', target]]
    : platform === 'darwin' ? ['open', [target]] : ['xdg-open', [target]];
  const child = spawn(executable, args, { shell: false, stdio: 'ignore', windowsHide: true });
  // Nothing to hand it to is not a failure worth crashing the server over; the caller has
  // already printed the URL.
  child.once('error', () => {});
  child.unref();
  return { executable, args };
}
