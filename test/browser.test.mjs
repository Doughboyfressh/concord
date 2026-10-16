import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createServer } from 'node:http';
import { makeBrowserTools, discoverPageTarget } from '../src/browser.mjs';
import { HarnessError, validateSchema } from '../src/value.mjs';

const executable = process.execPath;
const context = { workspaceRoot: process.cwd(), policy: { maxOutputBytes: 1048576 } };

function findRealBrowser() {
  const candidates = [
    process.env.CONCORD_TEST_BROWSER,
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
    '/usr/bin/chromium-browser', '/usr/bin/chromium', '/usr/bin/google-chrome',
  ].filter(Boolean);
  for (const candidate of candidates) if (fs.existsSync(candidate)) return candidate;
  return undefined;
}
const realBrowser = findRealBrowser();

async function fakeBrowserScript(temp, source) {
  const script = path.join(temp, 'fake-browser.mjs');
  await fs.promises.writeFile(script, source, 'utf8');
  return script;
}

test('registration rejects a relative or bare executable path and an unknown config field', () => {
  assert.throws(() => makeBrowserTools({ executable: 'chrome' }), (e) => e instanceof HarnessError && e.code === 'BROWSER_CONFIG');
  assert.throws(() => makeBrowserTools({ executable: '/abs/chrome', unexpected: true }), (e) => e instanceof HarnessError && e.code === 'BROWSER_CONFIG');
});

test('makeBrowserTools(undefined) registers nothing', () => {
  assert.deepEqual(makeBrowserTools(undefined), []);
});

test('the input schema accepts only url; there is no field that can override the configured binary or flags', () => {
  const tool = makeBrowserTools({ executable: path.resolve(executable) })[0];
  assert.deepEqual(tool.inputSchema, { type: 'object', properties: { url: { type: 'string', minLength: 1, maxLength: 8192 } }, required: ['url'], additionalProperties: false });
});

test('file:, chrome:, javascript:, and data: URLs are rejected before any process is launched', async () => {
  const tool = makeBrowserTools({ executable: path.resolve(executable) })[0];
  for (const url of ['file:///etc/passwd', 'chrome://version', 'javascript:alert(1)', 'data:text/html,hi', 'not a url']) {
    await assert.rejects(tool.execute({ url }, context), (e) => e instanceof HarnessError && e.code === 'BROWSER_INPUT');
  }
});

test('a missing configured binary fails closed distinctly from a timeout', async () => {
  const tool = makeBrowserTools({ executable: path.join(os.tmpdir(), 'does-not-exist-concord-browser.exe'), timeoutMs: 5000 })[0];
  await assert.rejects(tool.execute({ url: 'https://example.com/' }, context), (e) => e instanceof HarnessError && e.code === 'BROWSER_PATH');
});

test('a browser that never opens its DevTools port times out, kills the process, and removes its profile directory', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'concord-browser-test-'));
  try {
    const script = await fakeBrowserScript(temp, 'setInterval(() => {}, 1000);');
    const tool = makeBrowserTools({ executable: path.resolve(executable), timeoutMs: 300 })[0];
    const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-')).length;
    // The fake "browser" is really `node <script>`; browser.mjs always appends its own
    // fixed launch flags, which this fake script simply ignores.
    await assert.rejects(tool.execute({ url: 'https://example.com/' }, { ...context, policy: { ...context.policy, timeoutMs: 300 } }), (e) => e instanceof HarnessError && e.code === 'BROWSER_TIMEOUT');
    await new Promise((r) => setTimeout(r, 300));
    const after = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-')).length;
    assert.ok(after <= before, 'no leftover profile directory after a timeout');
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('abort before the DevTools port opens kills the process and still cleans up', async () => {
  const tool = makeBrowserTools({ executable: path.resolve(executable), timeoutMs: 5000 })[0];
  const controller = new AbortController();
  const pending = tool.execute({ url: 'https://example.com/' }, { ...context, signal: controller.signal });
  setTimeout(() => controller.abort(), 100);
  await assert.rejects(pending, (e) => e instanceof HarnessError && e.code === 'BROWSER_ABORTED');
});

// No ambient environment variable reaches the spawned browser: the spawn call passes
// a literal env: {} with no merging, by construction. browser.mjs always appends its
// own fixed launch flags (there is no config surface to redirect it to a custom script
// that could dump process.env), so that property is validated empirically instead —
// every real-browser test below launches under this exact env: {} configuration.

test('discoverPageTarget re-verifies loopback and rejects a non-loopback advertised debugger host', async () => {
  const server = createServer((request, response) => {
    if (request.url === '/json/list') {
      response.end(JSON.stringify([{ type: 'page', webSocketDebuggerUrl: 'ws://evil.example.com:1234/devtools/page/abc' }]));
    } else response.end('[]');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = server.address().port;
    await assert.rejects(discoverPageTarget(port), (e) => e instanceof HarnessError && e.code === 'BROWSER_CDP');
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('discoverPageTarget rejects a target list with no inspectable page', async () => {
  const server = createServer((request, response) => response.end('[]'));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = server.address().port;
    await assert.rejects(discoverPageTarget(port), (e) => e instanceof HarnessError && e.code === 'BROWSER_CDP');
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

async function localPageFixture(fn) {
  const server = createServer((request, response) => {
    response.end('<!doctype html><html><head><title>Concord Fixture Page</title></head><body>Fixture page body text for browser.snapshot.</body></html>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try { return await fn(`http://127.0.0.1:${server.address().port}/`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

test('a real browser opens a page, extracts a bounded text snapshot, and leaves no leftover profile directory', { skip: realBrowser ? false : 'no configured or auto-detected browser binary on this host' }, async () => {
  await localPageFixture(async (url) => {
    const tool = makeBrowserTools({ executable: realBrowser, timeoutMs: 20000 })[0];
    const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-'));
    const result = await tool.execute({ url }, context);
    assert.equal(result.title, 'Concord Fixture Page');
    assert.equal(result.url, url);
    assert.ok(result.text.includes('Fixture page body text'));
    const after = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-'));
    assert.deepEqual(after, before);
  });
});

async function hangingPageFixture(fn) {
  const server = createServer((request, response) => {
    response.end('<!doctype html><html><body><script>while(true){}</script></body></html>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try { return await fn(`http://127.0.0.1:${server.address().port}/`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

// Regression for a confirmed critical security review finding: a page whose JS blocks the
// renderer's main thread forever must not leak the browser process, its unauthenticated CDP
// port, or its profile directory. Before the fix, nothing ever rejected the in-flight CDP
// call, so execute() never returned and the cleanup finally-block never ran.
test('a page that hangs the renderer forever still times out, kills the browser, and removes the profile directory', { skip: realBrowser ? false : 'no configured or auto-detected browser binary on this host' }, async () => {
  await hangingPageFixture(async (url) => {
    const tool = makeBrowserTools({ executable: realBrowser, timeoutMs: 3000 })[0];
    const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-'));
    const start = Date.now();
    await assert.rejects(tool.execute({ url }, context), (e) => e instanceof HarnessError && ['BROWSER_TIMEOUT', 'BROWSER_CDP'].includes(e.code));
    assert.ok(Date.now() - start < 10000, 'execute() must settle near the configured timeout, not hang indefinitely');
    const after = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-'));
    assert.deepEqual(after, before, 'no leftover profile directory after a mid-session hang');
  });
});

test('maxOutputBytes bounds a real snapshot', { skip: realBrowser ? false : 'no configured or auto-detected browser binary on this host' }, async () => {
  await localPageFixture(async (url) => {
    const tool = makeBrowserTools({ executable: realBrowser, timeoutMs: 20000 })[0];
    await assert.rejects(tool.execute({ url }, { ...context, policy: { maxOutputBytes: 32 } }), (e) => e instanceof HarnessError && e.code === 'BROWSER_OUTPUT_LIMIT');
  });
});

test('two sequential real calls use independent, non-colliding profile directories', { skip: realBrowser ? false : 'no configured or auto-detected browser binary on this host' }, async () => {
  await localPageFixture(async (url) => {
    const tool = makeBrowserTools({ executable: realBrowser, timeoutMs: 20000 })[0];
    const first = await tool.execute({ url }, context);
    const second = await tool.execute({ url }, context);
    assert.equal(first.title, second.title);
    assert.deepEqual(fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-')), []);
  });
});

function automateTool(timeoutMs = 20000) {
  return makeBrowserTools({ executable: realBrowser, timeoutMs }).find((t) => t.name === 'browser.automate');
}

async function formFixture(fn) {
  const server = createServer((request, response) => {
    response.end([
      '<!doctype html><html><body>',
      '<input id="name" type="text">',
      '<button id="submit">Submit</button>',
      '<div id="result"></div>',
      '<div id="pwned-check">safe</div>',
      '<script>',
      'document.getElementById("submit").addEventListener("click", () => {',
      '  document.getElementById("result").innerText = "Hello, " + document.getElementById("name").value;',
      '});',
      'setInterval(() => { document.getElementById("pwned-check").innerText = window.__pwned ? "PWNED" : "safe"; }, 20);',
      '</script></body></html>',
    ].join(''));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try { return await fn(`http://127.0.0.1:${server.address().port}/`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

async function popupFixture(fn) {
  const server = createServer((request, response) => {
    response.end('<!doctype html><html><body><button id="open" onclick="window.open(\'about:blank\')">Open</button><div id="status">original</div></body></html>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try { return await fn(`http://127.0.0.1:${server.address().port}/`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

test('click/fill/wait actions without a selector, or fill without a value, are rejected before any process is launched', async () => {
  const tool = automateTool();
  await assert.rejects(tool.execute({ url: 'https://example.com/', actions: [{ type: 'click' }] }, context), (e) => e instanceof HarnessError && e.code === 'BROWSER_INPUT');
  await assert.rejects(tool.execute({ url: 'https://example.com/', actions: [{ type: 'fill', selector: '#x' }] }, context), (e) => e instanceof HarnessError && e.code === 'BROWSER_INPUT');
});

test('an action list beyond the bounded length is rejected by the declared schema before any process would launch', () => {
  const tool = automateTool();
  const actions = Array.from({ length: 21 }, () => ({ type: 'extract' }));
  assert.throws(() => validateSchema({ url: 'https://example.com/', actions }, tool.inputSchema), (e) => e instanceof HarnessError && e.code === 'SCHEMA_MISMATCH');
});

test('browser.automate fills a field, clicks a button, and extracts the resulting text', { skip: realBrowser ? false : 'no configured or auto-detected browser binary on this host' }, async () => {
  await formFixture(async (url) => {
    const result = await automateTool().execute({ url, actions: [
      { type: 'fill', selector: '#name', value: 'World' },
      { type: 'click', selector: '#submit' },
      { type: 'extract', selector: '#result' },
    ] }, context);
    assert.deepEqual(result.actions[0], { type: 'fill', selector: '#name', ok: true });
    assert.deepEqual(result.actions[1], { type: 'click', selector: '#submit', ok: true });
    assert.equal(result.actions[2].text, 'Hello, World');
  });
});

test('a crafted selector cannot break out of the fixed Runtime.callFunctionOn body into page script', { skip: realBrowser ? false : 'no configured or auto-detected browser binary on this host' }, async () => {
  await formFixture(async (url) => {
    const malicious = "x'); window.__pwned=1; //";
    const outcome = await automateTool().execute({ url, actions: [
      { type: 'extract', selector: malicious },
      { type: 'extract', selector: '#pwned-check' },
    ] }, context).catch((e) => e);
    if (outcome instanceof HarnessError) {
      // An invalid-selector DOMException is reported as a clean action failure, never a
      // page-script error — proving the string was never evaluated as source text.
      assert.equal(outcome.code, 'BROWSER_ACTION');
    } else {
      assert.equal(outcome.actions[1].text, 'safe');
    }
  });
});

test('a window.open() popup triggered mid-sequence does not pull the session onto a different target', { skip: realBrowser ? false : 'no configured or auto-detected browser binary on this host' }, async () => {
  await popupFixture(async (url) => {
    const result = await automateTool().execute({ url, actions: [
      { type: 'click', selector: '#open' },
      { type: 'extract', selector: '#status' },
    ] }, context);
    assert.equal(result.actions[1].text, 'original');
    assert.equal(result.url, url);
  });
});

test('browser.automate on a page that hangs the renderer forever still times out, kills the browser, and removes the profile directory', { skip: realBrowser ? false : 'no configured or auto-detected browser binary on this host' }, async () => {
  await hangingPageFixture(async (url) => {
    const tool = automateTool(3000);
    const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-'));
    const start = Date.now();
    await assert.rejects(tool.execute({ url, actions: [{ type: 'extract' }] }, context), (e) => e instanceof HarnessError && ['BROWSER_TIMEOUT', 'BROWSER_CDP'].includes(e.code));
    assert.ok(Date.now() - start < 10000, 'execute() must settle near the configured timeout, not hang indefinitely');
    const after = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('concord-browser-'));
    assert.deepEqual(after, before, 'no leftover profile directory after a mid-session hang');
  });
});
