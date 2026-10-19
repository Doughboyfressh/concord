import test from 'node:test';
import assert from 'node:assert/strict';
import { checkAppUrl, browserCandidates, findAppBrowser, appWindowArgv, modelCredentialPlan } from '../src/desktop.mjs';
import { CHAT_FLAGS, parseFlags } from '../src/app.mjs';

// Nothing here launches a browser. Every decision the shell makes is a pure function of injected
// inputs, so the argv a real machine would produce is asserted directly.

const WIN_ENV = { LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local', ProgramFiles: 'C:\\Program Files', 'ProgramFiles(x86)': 'C:\\Program Files (x86)' };
const PROFILE = process.platform === 'win32' ? 'C:\\concord\\profile' : '/var/concord/profile';

test('the window opens a loopback application root and nothing else', () => {
  assert.equal(checkAppUrl('http://127.0.0.1:8787'), 'http://127.0.0.1:8787/');
  assert.equal(checkAppUrl('http://127.0.0.1:8787/'), 'http://127.0.0.1:8787/');
  assert.equal(checkAppUrl('http://[::1]:8787/'), 'http://[::1]:8787/');

  for (const [why, url] of [
    ['a remote host', 'http://example.com/'],
    ['a host that merely resolves to loopback', 'http://127.0.0.1.nip.io/'],
    // localhost is refused on purpose: the server authorizes on an exact Host match against the
    // interface it bound, so such a window would render and then be denied every request.
    ['localhost', 'http://localhost:8787/'],
    ['https', 'https://127.0.0.1:8787/'],
    ['a non-http scheme', 'file:///etc/passwd'],
    ['credentials', 'http://user:pw@127.0.0.1:8787/'],
    ['a path below the root', 'http://127.0.0.1:8787/admin'],
    ['not a URL at all', 'concord'],
    ['nothing', ''],
  ]) {
    assert.throws(() => checkAppUrl(url), (e) => e.code === 'DESKTOP_URL', why);
  }
});

test('no secret can reach the process table through the window URL', () => {
  // A browser command line is readable by every process on the machine, so a URL carrying a
  // session token is refused rather than passed along. The page fetches its token over the socket.
  assert.throws(() => checkAppUrl('http://127.0.0.1:8787/?token=s3cret'), (e) => e.code === 'DESKTOP_URL');
  assert.throws(() => checkAppUrl('http://127.0.0.1:8787/#token=s3cret'), (e) => e.code === 'DESKTOP_URL');
  for (const argument of appWindowArgv({ url: 'http://127.0.0.1:8787/', profileDir: PROFILE })) {
    assert.equal(/token|secret|password/i.test(argument), false, argument);
  }
});

test('the command line is exactly the reviewed one', () => {
  assert.deepEqual(appWindowArgv({ url: 'http://127.0.0.1:8787/', profileDir: PROFILE }), [
    '--app=http://127.0.0.1:8787/',
    '--user-data-dir=' + PROFILE,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--window-size=1180,860',
  ]);

  // Nothing that weakens the renderer or opens another control channel may appear, whatever the
  // caller asks for. This is the reason the argv is built in one place.
  const argv = appWindowArgv({ url: 'http://127.0.0.1:8787/', profileDir: PROFILE, windowSize: '900,700' });
  for (const forbidden of ['--remote-debugging-port', '--disable-web-security', '--proxy-server', '--load-extension', '--headless', '--allow-running-insecure-content', '--disable-site-isolation-trials']) {
    assert.equal(argv.some((value) => value.startsWith(forbidden)), false, forbidden);
  }
  assert.ok(argv.includes('--window-size=900,700'));
  // The private profile is what keeps the window out of the user's own cookies and sessions.
  assert.equal(argv.filter((value) => value.startsWith('--user-data-dir=')).length, 1);
});

test('a malformed profile directory or window size is refused', () => {
  const url = 'http://127.0.0.1:8787/';
  for (const profileDir of ['relative/profile', '', null, 'profile']) {
    assert.throws(() => appWindowArgv({ url, profileDir }), (e) => e.code === 'DESKTOP_PROFILE');
  }
  for (const windowSize of ['0,0', '12,12', 'wide', '1180;860', '1180,860 --disable-web-security', '-1,5']) {
    assert.throws(() => appWindowArgv({ url, profileDir: PROFILE, windowSize }), (e) => e.code === 'DESKTOP_WINDOW');
  }
});

test('each platform looks where that platform keeps a Chromium', () => {
  const win = browserCandidates('win32', WIN_ENV);
  assert.ok(win.length >= 8);
  assert.ok(win.every((candidate) => candidate.executable.includes('\\')));
  // Chrome before Edge: on Windows Edge always exists, so probing it first would mean never
  // choosing the browser the user actually installed.
  assert.ok(win.findIndex((c) => c.name === 'chrome.exe') < win.findIndex((c) => c.name === 'msedge.exe'));
  // Nothing is invented from an environment that does not describe this machine.
  assert.deepEqual(browserCandidates('win32', {}), []);

  assert.ok(browserCandidates('darwin').every((c) => c.executable.startsWith('/Applications/')));
  assert.ok(browserCandidates('linux').every((c) => c.executable.startsWith('/usr/bin/')));
});

test('the first browser that is really there is the one used', () => {
  const present = new Set(['C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe']);
  const found = findAppBrowser({ platform: 'win32', env: WIN_ENV, exists: (file) => present.has(file) });
  assert.equal(found.name, 'msedge.exe');
  assert.equal(found.configured, false);

  // No Chromium is not an error: the launcher falls back to the default browser and says so.
  assert.equal(findAppBrowser({ platform: 'win32', env: WIN_ENV, exists: () => false }), null);
});

test('CONCORD_BROWSER selects the browser, and a wrong one is an error rather than a fallback', () => {
  const env = { ...WIN_ENV, CONCORD_BROWSER: 'D:\\brave\\brave.exe' };
  const found = findAppBrowser({ platform: 'win32', env, exists: (file) => file === 'D:\\brave\\brave.exe' });
  assert.equal(found.executable, 'D:\\brave\\brave.exe');
  assert.equal(found.configured, true);

  // Silently using a different browser than the one named would be the wrong kindness.
  assert.throws(
    () => findAppBrowser({ platform: 'win32', env, exists: (file) => file !== 'D:\\brave\\brave.exe' }),
    (e) => e.code === 'DESKTOP_BROWSER',
  );
});

test('every documented launcher flag is accepted, and an unknown one is refused', () => {
  // Regression: --foreign and --reverse were read by the launcher but missing from this list, so
  // the flag the documentation described threw CHAT_USAGE instead of working.
  for (const flag of ['workspace', 'policy', 'integrations', 'workers', 'browser', 'reverse', 'foreign', 'port', 'store']) {
    assert.ok(CHAT_FLAGS.includes(flag), flag);
    assert.deepEqual(parseFlags(['--' + flag, 'value']), { [flag]: 'value' });
  }
  assert.deepEqual(parseFlags([]), {});
  assert.deepEqual(parseFlags(['--port', '0', '--foreign', 'f.json']), { port: '0', foreign: 'f.json' });

  for (const argv of [['--nope', '1'], ['--port'], ['port', '0'], ['--port', '0', '--port', '1'], ['--port', '0', '--no-window']]) {
    assert.throws(() => parseFlags(argv), (e) => e.code === 'CHAT_USAGE');
  }
  // The windowed launcher extends the same list rather than parsing its own way.
  assert.deepEqual(parseFlags(['--window-size', '900,700'], [...CHAT_FLAGS, 'window-size']), { 'window-size': '900,700' });
});

test('a model credential is supplied only for a loopback server, and never over a real one', () => {
  const remote = { model: 'm', origin: 'https://api.example.com', apiKeyEnv: 'KEY' };
  const local = { model: 'qwen3.8-flash', origin: 'http://127.0.0.1:11434', apiKeyEnv: 'KEY' };

  // A model server on loopback checks no bearer token, so the adapter's requirement that one
  // exist is the only thing in the way. Supplying it there is the whole exception.
  const supplied = modelCredentialPlan(local, {});
  assert.equal(supplied.setEnv.name, 'KEY');
  assert.equal(supplied.setEnv.value, 'loopback-server-ignores-this');
  // A fixed, self-describing string: nothing is generated to resemble a real credential.
  assert.match(supplied.summary, /placeholder/);
  assert.deepEqual(modelCredentialPlan({ ...local, origin: 'http://[::1]:11434' }, {}).setEnv, supplied.setEnv);

  // A credential the operator actually set always wins, loopback or not.
  for (const model of [local, remote]) {
    const kept = modelCredentialPlan(model, { KEY: 'a-real-key' });
    assert.equal(kept.setEnv, undefined);
    assert.match(kept.summary, /credential from KEY/);
    assert.equal(kept.summary.includes('a-real-key'), false, 'the value must never be echoed');
  }

  // Off loopback nothing is invented: the call will refuse, and the report says so plainly
  // rather than letting a user discover it as an unexplained failure.
  const refused = modelCredentialPlan(remote, {});
  assert.equal(refused.setEnv, undefined);
  assert.match(refused.summary, /INTEGRATION_CREDENTIAL/);

  // A model with no apiKeyEnv cannot be called at all, and a missing model is simply offline.
  assert.equal(modelCredentialPlan({ model: 'm', origin: 'http://127.0.0.1:1' }, {}).setEnv, undefined);
  assert.equal(modelCredentialPlan(undefined).configured, false);
  assert.match(modelCredentialPlan(undefined).summary, /offline/);

  // A malformed origin is not loopback by accident.
  assert.equal(modelCredentialPlan({ model: 'm', origin: 'not a url', apiKeyEnv: 'KEY' }, {}).setEnv, undefined);
  assert.equal(modelCredentialPlan({ model: 'm', origin: 'http://127.0.0.1.evil.test', apiKeyEnv: 'KEY' }, {}).setEnv, undefined);
});
