#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { HarnessError } from '../src/value.mjs';
import { parseFlags, startChatServer, CHAT_FLAGS } from '../src/app.mjs';
import { findAppBrowser, launchAppWindow, openDefaultBrowser, modelCredentialPlan } from '../src/desktop.mjs';

/**
 * Concord as a desktop application.
 *
 * Start the same loopback server `scripts/chat.mjs` starts, open it in a chromeless window, and
 * shut down when that window closes. The lifecycle is the whole difference: a desktop application
 * is something you close, not something you have to remember to stop.
 *
 *   node scripts/desktop.mjs [--port 0] [--policy FILE] [...] [--window-size W,H] [--no-window]
 *
 * Port 0 is the default here rather than 8787: the window is handed its URL directly, so there is
 * no reason to contend for a fixed port or to leave a predictable one listening.
 */

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const USAGE = 'Usage: node scripts/desktop.mjs [--workspace DIR] [--port 0] [--policy FILE] [--integrations FILE] [--workers FILE] [--browser FILE] [--reverse FILE] [--foreign FILE] [--store DIR] [--window-size 1180,860] [--no-window]';

async function start() {
  const argv = process.argv.slice(2);
  // `--no-window` is a switch rather than a pair, so it comes out before the pair parser runs.
  const noWindow = argv.includes('--no-window');
  const flags = parseFlags(argv.filter((value) => value !== '--no-window'), [...CHAT_FLAGS, 'window-size'], USAGE);
  const windowSize = flags['window-size'] ?? '1180,860';
  delete flags['window-size'];
  if (flags.port === undefined) flags.port = '0';

  // Decide the model credential before the harness is built, because the adapter reads the
  // environment at call time and a placeholder decided afterwards would arrive too late. No
  // network call is made here: what is reported is the configuration, never a probe of it.
  let modelPlan = { configured: false, summary: 'none configured; offline deterministic demonstration' };
  if (flags.integrations) {
    const configured = JSON.parse(fs.readFileSync(path.resolve(flags.integrations), 'utf8'));
    modelPlan = modelCredentialPlan(configured?.model);
    if (modelPlan.setEnv) process.env[modelPlan.setEnv.name] = modelPlan.setEnv.value;
  }

  const { url, store, status, mode, toolCount, server, close } = await startChatServer({ flags, entry: 'scripts/desktop.mjs' });
  const report = (how) => console.log(`Concord desktop: ${url}\nWindow: ${how}\nMode: ${mode}\nModel: ${modelPlan.summary}\nTools: ${toolCount}; sources: ${status.sourceCount}; skill files: ${status.skillFiles}\nLocal evidence: ${store}`);
  const stopOnSignal = () => {
    const stop = () => server.close(() => process.exit(0));
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  };

  // One stable profile directory, so the window remembers its size and position between launches
  // while still sharing nothing with the browser the user browses with. It lives under the
  // git-ignored runs/ directory because it is local state, not part of the project.
  const profileDir = path.join(root, 'runs', 'desktop-profile');
  fs.mkdirSync(profileDir, { recursive: true });

  if (noWindow) {
    report('not opened (--no-window); the server stays up until you stop it');
    stopOnSignal();
    return;
  }

  const browser = findAppBrowser();
  if (!browser) {
    // No Chromium to host an application window. Still open the page, and say plainly that this
    // is a tab in the user's own browser rather than quietly calling it the same thing.
    openDefaultBrowser(url);
    report('no Chromium found, so this opened as a tab in your default browser instead of an application window. Install Chrome, Edge, Brave or Chromium, or set CONCORD_BROWSER, for a real window.');
    stopOnSignal();
    return;
  }

  // A windowed process needs its platform's own variables to open a display at all, so this is a
  // curated set rather than the empty environment the headless snapshot tool uses. None of the
  // harness's state is in it: the page authorizes itself over the socket.
  const keep = process.platform === 'win32'
    ? ['SystemRoot', 'windir', 'TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'PROGRAMDATA', 'ProgramFiles', 'ProgramFiles(x86)', 'PATH', 'PATHEXT', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'COMSPEC']
    : ['HOME', 'PATH', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR', 'XDG_SESSION_TYPE', 'DBUS_SESSION_BUS_ADDRESS', 'TMPDIR'];
  const env = {};
  for (const name of keep) if (process.env[name] !== undefined) env[name] = process.env[name];

  const controller = new AbortController();
  const { closed } = launchAppWindow({ executable: browser.executable, url, profileDir, windowSize, env, signal: controller.signal });
  report(`${browser.name}${browser.configured ? ' (from CONCORD_BROWSER)' : ''} in application mode. Close the window to stop Concord.`);

  const stop = () => { controller.abort(); server.close(() => process.exit(0)); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  // Closing the window is the signal to stop serving.
  await closed;
  await close();
  console.log('Window closed; Concord stopped.');
  process.exit(0);
}

start().catch(error => {
  console.error(error instanceof HarnessError ? `${error.code}: ${error.message}` : 'DESKTOP_START_FAILED: Check local configuration and paths.');
  process.exitCode = 1;
});
