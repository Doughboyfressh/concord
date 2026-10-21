import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { makeWebTools, canonicalUrl, mergeAnswers, reduceHtml } from '../src/web.mjs';
import { canonical, HarnessError } from '../src/value.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const code = (expected) => (error) => error instanceof HarnessError && error.code === expected;

const PAGE = [
  '<!doctype html><html><head><title>Concord &amp; the web</title><style>b{color:red}</style></head>',
  '<body><h1>Heading</h1><p>First paragraph.</p><script>var x=1;</script>',
  '<a href="/next">next page</a><a href="https://example.org/out?utm_source=x">out</a><a href="#top">anchor</a>',
  '<p>Second&nbsp;paragraph.</p></body></html>',
].join('\n');

/** A loopback server for the length of one test, plus the request headers it was sent. */
async function withServer(handler, run) {
  const seen = [];
  const server = createServer((request, response) => {
    seen.push({ url: request.url, headers: request.headers });
    handler(request, response);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try { return await run(origin, seen); }
  finally { server.close(); }
}

const policyFor = (origin, over = {}) => ({
  version: 1, allowedTools: ['web.fetch', 'web.search'], allowedEffects: ['network'],
  allowedOrigins: origin === null ? [] : [origin], timeoutMs: 5000, maxOutputBytes: 262_144, ...over,
});
const webFetch = (over = {}) => makeWebTools({ timeoutMs: 5000, maxOutputBytes: 262_144, ...over })[0];

test('makeWebTools(undefined) registers nothing, and search appears only once an engine is configured', () => {
  assert.deepEqual(makeWebTools(undefined), []);
  assert.deepEqual(makeWebTools({}).map((tool) => tool.name), ['web.fetch']);
  const both = makeWebTools({ engines: [{ name: 'one', origin: 'https://search.example' }] });
  assert.deepEqual(both.map((tool) => tool.name), ['web.fetch', 'web.search']);
  assert.deepEqual(both.map((tool) => tool.effect), ['network', 'network']);
});

test('configuration refusals are WEB_CONFIG, one per malformed field', () => {
  const refused = [
    { unexpected: true },
    { fetchName: 'web fetch' },
    { fetchName: 'same', searchName: 'same' },
    { maxRedirects: -1 },
    { maxRedirects: 11 },
    { timeoutMs: 0 },
    { engines: [] },
    { engines: [{ name: 'a', origin: 'https://x.example/path' }] },
    { engines: [{ name: 'a', origin: 'https://user:pw@x.example' }] },
    { engines: [{ name: 'a', origin: 'ftp://x.example' }] },
    { engines: [{ name: 'a', origin: 'https://x.example', path: 'relative' }] },
    { engines: [{ name: 'a', origin: 'https://x.example', path: '/ok?q=1' }] },
    { engines: [{ name: 'a', origin: 'https://x.example', apiKeyEnv: '9bad' }] },
    { engines: [{ name: 'a', origin: 'https://x.example', maxResults: 999 }] },
    { engines: [{ name: 'a', origin: 'https://x.example', resultsPath: ['a', 2] }] },
    { engines: [{ name: 'a', origin: 'https://x.example', extraParams: { q: 'restates the query' } }] },
    { engines: [{ name: 'a', origin: 'https://x.example', unexpected: 1 }] },
    { engines: [{ name: 'a', origin: 'https://x.example' }, { name: 'a', origin: 'https://y.example' }] },
    { engines: Array.from({ length: 9 }, (unused, index) => ({ name: `e${index}`, origin: 'https://x.example' })) },
  ];
  for (const config of refused) assert.throws(() => makeWebTools(config), code('WEB_CONFIG'), canonical(config));
});

test('the fetch input schema accepts only a url: no method, header, body or credential field exists', () => {
  assert.deepEqual(webFetch().inputSchema, {
    type: 'object', properties: { url: { type: 'string', minLength: 1, maxLength: 8192 } },
    required: ['url'], additionalProperties: false,
  });
});

test('a non-http scheme, a relative URL and credentials in a URL are refused before any socket opens', async () => {
  const tool = webFetch();
  for (const url of ['file:///etc/passwd', 'data:text/html,hi', 'ftp://x.example/', 'not a url', '/relative']) {
    await assert.rejects(tool.execute({ url }, { policy: policyFor('http://127.0.0.1:9') }), code('WEB_INPUT'), url);
  }
  await assert.rejects(
    tool.execute({ url: 'http://user:pw@127.0.0.1:9/' }, { policy: policyFor('http://127.0.0.1:9') }),
    code('WEB_INPUT'),
  );
});

test('an origin absent from the policy allowlist is refused WEB_ORIGIN, and an empty allowlist permits nothing', async () => {
  const tool = webFetch();
  await assert.rejects(tool.execute({ url: 'http://127.0.0.1:9/' }, { policy: policyFor('http://127.0.0.2:9') }), code('WEB_ORIGIN'));
  await assert.rejects(tool.execute({ url: 'http://127.0.0.1:9/' }, { policy: policyFor(null) }), code('WEB_ORIGIN'));
  await assert.rejects(tool.execute({ url: 'http://127.0.0.1:9/' }, { policy: { ...policyFor('http://127.0.0.1:9'), allowedOrigins: undefined } }), code('WEB_ORIGIN'));
});

test('policy narrowing refuses the tool, the effect and an already-cancelled call', async () => {
  const tool = webFetch();
  const origin = 'http://127.0.0.1:9';
  await assert.rejects(tool.execute({ url: `${origin}/` }, { policy: policyFor(origin, { allowedTools: ['other'] }) }), code('WEB_POLICY'));
  await assert.rejects(tool.execute({ url: `${origin}/` }, { policy: policyFor(origin, { allowedEffects: ['read'] }) }), code('WEB_POLICY'));
  await assert.rejects(
    tool.execute({ url: `${origin}/` }, { policy: policyFor(origin), signal: AbortSignal.abort() }),
    code('WEB_ABORTED'),
  );
});

test('a page comes back with the digest of exactly the bytes served, resolved links, and what was dropped', async () => {
  await withServer((request, response) => {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(PAGE);
  }, async (origin, seen) => {
    const result = await webFetch().execute({ url: `${origin}/page` }, { policy: policyFor(origin) });
    assert.equal(result.ok, true);
    assert.equal(result.status, 200);
    assert.equal(result.bodySha256, sha256(Buffer.from(PAGE)), 'the digest is of the served bytes, computed independently here');
    assert.equal(result.bytes, Buffer.byteLength(PAGE));
    assert.equal(result.truncated, false);
    assert.equal(result.strategy, 'html-reduction-v1');
    assert.equal(result.title, 'Concord & the web');
    assert.equal(result.droppedScripts, 1);
    assert.equal(result.droppedStyles, 1);
    assert.deepEqual(result.links.map((link) => link.href), [`${origin}/next`, 'https://example.org/out?utm_source=x']);
    assert.deepEqual(result.links.map((link) => link.text), ['next page', 'out']);
    assert.match(result.text, /Second paragraph\./);
    assert.doesNotMatch(result.text, /var x=1/, 'script bodies are removed, not merely hidden');
    assert.doesNotMatch(result.text, /color:red/);
    assert.equal(result.untrusted, true);
    // The one header guarantee worth asserting on the wire: nothing that could carry a credential.
    assert.equal(seen[0].headers.authorization, undefined);
    assert.equal(seen[0].headers.cookie, undefined);
  });
});

test('every declared output key is present on a 200 and on a 404, and a 404 is data rather than a refusal', async () => {
  await withServer((request, response) => {
    if (request.url === '/page') { response.writeHead(200, { 'content-type': 'text/plain' }); response.end('hello'); return; }
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('nope');
  }, async (origin) => {
    const tool = webFetch();
    for (const path of ['/page', '/missing']) {
      const result = await tool.execute({ url: origin + path }, { policy: policyFor(origin) });
      for (const key of tool.outputKeys) assert.notEqual(result[key], undefined, `${path} is missing ${key}`);
      assert.doesNotThrow(() => canonical(result));
    }
    const missing = await tool.execute({ url: `${origin}/missing` }, { policy: policyFor(origin) });
    assert.equal(missing.ok, false);
    assert.equal(missing.status, 404);
    assert.equal(missing.text, 'nope', 'the body of an error response is still evidence about the URL');
    assert.equal(missing.bodySha256, sha256(Buffer.from('nope')));
  });
});

test('a redirect chain is recorded hop by hop and ends at the same bytes as fetching the target directly', async () => {
  await withServer((request, response) => {
    if (request.url === '/one') { response.writeHead(302, { location: '/two' }); response.end(); return; }
    if (request.url === '/two') { response.writeHead(301, { location: '/page' }); response.end(); return; }
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('arrived');
  }, async (origin) => {
    const tool = webFetch();
    const hopped = await tool.execute({ url: `${origin}/one` }, { policy: policyFor(origin) });
    const direct = await tool.execute({ url: `${origin}/page` }, { policy: policyFor(origin) });
    assert.equal(hopped.finalUrl, `${origin}/page`);
    assert.equal(hopped.url, `${origin}/one`, 'the requested URL is kept beside the one that answered');
    assert.deepEqual(hopped.redirects, [
      { status: 302, from: `${origin}/one`, to: `${origin}/two` },
      { status: 301, from: `${origin}/two`, to: `${origin}/page` },
    ]);
    assert.equal(hopped.bodySha256, direct.bodySha256);
  });
});

test('a redirect to an origin outside the allowlist is refused, so a redirect cannot widen the policy', async () => {
  await withServer((request, response) => {
    if (request.url === '/away') { response.writeHead(302, { location: 'http://127.0.0.2:9/elsewhere' }); response.end(); return; }
    if (request.url === '/scheme') { response.writeHead(302, { location: 'file:///etc/passwd' }); response.end(); return; }
    if (request.url === '/nowhere') { response.writeHead(302); response.end(); return; }
    if (request.url === '/creds') { response.writeHead(302, { location: 'http://a:b@127.0.0.1:9/' }); response.end(); return; }
    response.writeHead(302, { location: '/loop' });
    response.end();
  }, async (origin) => {
    const tool = webFetch({ maxRedirects: 2 });
    await assert.rejects(tool.execute({ url: `${origin}/away` }, { policy: policyFor(origin) }), code('WEB_ORIGIN'));
    await assert.rejects(tool.execute({ url: `${origin}/scheme` }, { policy: policyFor(origin) }), code('WEB_REDIRECT'));
    await assert.rejects(tool.execute({ url: `${origin}/nowhere` }, { policy: policyFor(origin) }), code('WEB_REDIRECT'));
    await assert.rejects(tool.execute({ url: `${origin}/creds` }, { policy: policyFor(origin) }), code('WEB_REDIRECT'));
    await assert.rejects(tool.execute({ url: `${origin}/loop` }, { policy: policyFor(origin) }), code('WEB_REDIRECT'));
    const none = makeWebTools({ maxRedirects: 0 })[0];
    await assert.rejects(none.execute({ url: `${origin}/loop` }, { policy: policyFor(origin) }), code('WEB_REDIRECT'));
  });
});

test('a body past the budget is truncated, counted and flagged, and the digest covers only what arrived', async () => {
  const body = 'x'.repeat(5000);
  await withServer((request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end(body);
  }, async (origin) => {
    const result = await webFetch().execute({ url: `${origin}/big` }, { policy: policyFor(origin, { maxOutputBytes: 1000 }) });
    assert.equal(result.truncated, true);
    assert.equal(result.bytes, 1000);
    assert.equal(result.bodySha256, sha256(Buffer.from('x'.repeat(1000))), 'the digest is of the prefix received, which is what truncated:true says it is');
  });
});

test('bytes that are not text are digested and counted but never decoded or guessed at', async () => {
  const bytes = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0xff, 0xfe]);
  await withServer((request, response) => {
    response.writeHead(200, { 'content-type': 'application/octet-stream' });
    response.end(bytes);
  }, async (origin) => {
    const result = await webFetch().execute({ url: `${origin}/binary` }, { policy: policyFor(origin) });
    assert.equal(result.strategy, 'none');
    assert.equal(result.text, '');
    assert.equal(result.title, null);
    assert.deepEqual(result.links, []);
    assert.equal(result.bodySha256, sha256(bytes), 'the retrieval is still attested even though nothing was read');
  });
});

// ---- search: corroboration rather than one engine's ranking --------------------------------

const ALPHA = { results: [
  { url: 'https://example.com/one?utm_source=a', title: 'One from alpha', snippet: 'alpha on one' },
  { url: 'https://example.com/two', title: 'Two from alpha', snippet: 'alpha on two' },
] };
const BETA = { data: { hits: [
  { link: 'https://EXAMPLE.com/two#section', heading: 'Two from beta', body: 'beta on two' },
  { link: 'https://example.com/one', heading: 'One from beta', body: 'beta on one' },
  { link: 'https://example.com/three', heading: 'Three from beta', body: 'only beta' },
] } };
const BETA_SHAPE = { resultsPath: ['data', 'hits'], urlKey: 'link', titleKey: 'heading', snippetKey: 'body' };

function searchServer(extra = {}) {
  return (request, response) => {
    const { pathname } = new URL(request.url, 'http://x');
    const handler = extra[pathname];
    if (handler) { handler(request, response); return; }
    if (pathname === '/alpha') { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(ALPHA)); return; }
    if (pathname === '/beta') { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(BETA)); return; }
    response.writeHead(503);
    response.end('unavailable');
  };
}

test('search merges every engine into one corroboration table ordered by agreement, then rank, then URL', async () => {
  await withServer(searchServer(), async (origin) => {
    const [, search] = makeWebTools({
      timeoutMs: 5000, maxOutputBytes: 262_144,
      engines: [
        { name: 'alpha', origin, path: '/alpha' },
        { name: 'beta', origin, path: '/beta', queryParam: 'query', ...BETA_SHAPE },
        { name: 'down', origin, path: '/down' },
      ],
    });
    const result = await search.execute({ query: 'deterministic harness', limit: 5 }, { policy: policyFor(origin) });
    assert.equal(result.ranking, 'agreement-then-best-rank-v1');
    assert.equal(result.asked, 3);
    assert.equal(result.answered, 2);
    assert.equal(result.agreementMax, 2);
    assert.equal(result.uncorroborated, 1, 'one result came from a single engine while two engines answered');
    assert.deepEqual(result.results.map((row) => [row.canonicalUrl, row.agreement, row.bestRank]), [
      ['https://example.com/one', 2, 1],
      ['https://example.com/two', 2, 1],
      ['https://example.com/three', 1, 3],
    ]);
    // A tracking parameter, a host in a different case and a fragment all describe one page.
    assert.deepEqual(result.results[1].engines, [
      { name: 'alpha', rank: 2, url: 'https://example.com/two' },
      // Recorded as parsed, not byte-identical: the engine sent an upper-case host and the URL
      // parser lower-cases it. The fragment and path survive, so the merge is still auditable.
      { name: 'beta', rank: 1, url: 'https://example.com/two#section' },
    ]);
    assert.equal(result.results[1].title, 'Two from beta', 'the best-ranked engine supplies the wording');
    // A failing engine is a row with a code, not an exception that discards the other answers.
    assert.deepEqual(result.engines.map((entry) => [entry.name, entry.ok, entry.count, entry.code]), [
      ['alpha', true, 2, null], ['beta', true, 3, null], ['down', false, 0, 'WEB_HTTP_STATUS'],
    ]);
    assert.equal(result.engines[0].answerSha256, sha256(Buffer.from(JSON.stringify(ALPHA))));
    for (const key of search.outputKeys) assert.notEqual(result[key], undefined, `missing ${key}`);
  });
});

test('one engine cannot measure corroboration, so uncorroborated is null rather than zero', async () => {
  await withServer(searchServer(), async (origin) => {
    const [, search] = makeWebTools({ engines: [{ name: 'alpha', origin, path: '/alpha' }] });
    const result = await search.execute({ query: 'one source only' }, { policy: policyFor(origin) });
    assert.equal(result.answered, 1);
    assert.equal(result.uncorroborated, null);
    assert.equal(result.agreementMax, 1);
  });
});

test('every engine failing is a refusal, not an empty result list', async () => {
  await withServer(searchServer(), async (origin) => {
    const [, search] = makeWebTools({ engines: [
      { name: 'down', origin, path: '/down' },
      { name: 'alsodown', origin, path: '/alsodown' },
    ] });
    await assert.rejects(search.execute({ query: 'nothing answers' }, { policy: policyFor(origin) }), code('WEB_NO_ENGINE'));
  });
});

test('an engine answer that does not match its declared shape, or echoes the credential, is refused for that engine alone', async () => {
  const previous = process.env.CONCORD_TEST_SEARCH_KEY;
  process.env.CONCORD_TEST_SEARCH_KEY = 'tok-search-credential';
  try {
    await withServer(searchServer({
      '/html': (request, response) => { response.writeHead(200, { 'content-type': 'text/html' }); response.end('<html>not json</html>'); },
      '/wrong': (request, response) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ items: [] })); },
      '/echo': (request, response) => {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ results: [{ url: 'https://example.com/x', title: 'tok-search-credential leaked', snippet: '' }] }));
      },
    }), async (origin) => {
      const [, search] = makeWebTools({ engines: [
        { name: 'alpha', origin, path: '/alpha' },
        { name: 'html', origin, path: '/html' },
        { name: 'wrong', origin, path: '/wrong' },
        { name: 'echo', origin, path: '/echo', apiKeyEnv: 'CONCORD_TEST_SEARCH_KEY' },
      ] });
      const result = await search.execute({ query: 'mixed answers' }, { policy: policyFor(origin) });
      const byName = new Map(result.engines.map((entry) => [entry.name, entry.code]));
      assert.equal(byName.get('alpha'), null);
      assert.equal(byName.get('html'), 'WEB_ENGINE_SHAPE');
      assert.equal(byName.get('wrong'), 'WEB_ENGINE_SHAPE');
      assert.equal(byName.get('echo'), 'WEB_SECRET');
      assert.equal(result.answered, 1);
      assert.equal(result.results.length, 2, 'the one healthy engine still answered');
    });
  } finally {
    if (previous === undefined) delete process.env.CONCORD_TEST_SEARCH_KEY; else process.env.CONCORD_TEST_SEARCH_KEY = previous;
  }
});

test('a missing credential is refused for its engine before the request is made', async () => {
  delete process.env.CONCORD_TEST_ABSENT_KEY;
  await withServer(searchServer(), async (origin) => {
    const [, search] = makeWebTools({ engines: [
      { name: 'alpha', origin, path: '/alpha' },
      { name: 'keyed', origin, path: '/alpha', apiKeyEnv: 'CONCORD_TEST_ABSENT_KEY' },
    ] });
    const result = await search.execute({ query: 'one engine has no key' }, { policy: policyFor(origin) });
    assert.equal(result.engines.find((entry) => entry.name === 'keyed').code, 'WEB_CREDENTIAL');
    assert.equal(result.answered, 1);
  });
});

test('the output budget is divided before any engine is asked, so one engine cannot spend it all', async () => {
  const big = { results: Array.from({ length: 40 }, (unused, index) => ({ url: `https://example.com/${index}`, title: 'x'.repeat(200), snippet: 'y'.repeat(200) })) };
  await withServer(searchServer({
    '/big': (request, response) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(big)); },
  }), async (origin) => {
    const [, search] = makeWebTools({ engines: [
      { name: 'alpha', origin, path: '/alpha' },
      { name: 'big', origin, path: '/big' },
    ] });
    const result = await search.execute({ query: 'one oversized answer' }, { policy: policyFor(origin, { maxOutputBytes: 2000 }) });
    assert.equal(result.engines.find((entry) => entry.name === 'big').code, 'WEB_OUTPUT_LIMIT');
    assert.equal(result.answered, 1, 'the engine inside its share of the budget still answered');
  });
});

// ---- the pure parts, tested without a socket ------------------------------------------------

test('canonicalUrl folds case, fragments, tracking parameters and parameter order into one key', () => {
  assert.equal(canonicalUrl('https://EXAMPLE.com/a#frag'), 'https://example.com/a');
  assert.equal(canonicalUrl('https://example.com/a?utm_source=x&b=2&a=1'), 'https://example.com/a?a=1&b=2');
  assert.equal(canonicalUrl('https://example.com/a?b=2&a=1'), canonicalUrl('https://example.com/a?a=1&b=2'));
  assert.equal(canonicalUrl('https://example.com/'), 'https://example.com/');
  assert.equal(canonicalUrl('https://example.com'), canonicalUrl('https://example.com/'));
  assert.equal(canonicalUrl('https://example.com/a?fbclid=1&gclid=2'), 'https://example.com/a');
  assert.notEqual(canonicalUrl('https://example.com/a'), canonicalUrl('http://example.com/a'), 'scheme is part of the page identity');
});

test('the merge order is total, so the result list does not depend on which engine answered first', () => {
  const answers = [
    { engine: 'a', results: [{ url: 'https://x.example/1', title: 'a1', snippet: null, rank: 1 }, { url: 'https://x.example/2', title: 'a2', snippet: null, rank: 2 }] },
    { engine: 'b', results: [{ url: 'https://x.example/2', title: 'b2', snippet: null, rank: 1 }, { url: 'https://x.example/3', title: 'b3', snippet: null, rank: 2 }] },
    { engine: 'c', results: [{ url: 'https://x.example/3', title: 'c3', snippet: null, rank: 1 }] },
  ];
  const forward = mergeAnswers(answers, 10);
  const reversed = mergeAnswers([...answers].reverse(), 10);
  assert.equal(canonical(forward), canonical(reversed));
  assert.deepEqual(forward.map((row) => [row.canonicalUrl, row.agreement, row.bestRank]), [
    ['https://x.example/2', 2, 1],
    ['https://x.example/3', 2, 1],
    ['https://x.example/1', 1, 1],
  ]);
  assert.equal(forward[0].title, 'b2', 'the engine that ranked it first supplies the wording, whatever the answer order');
  assert.equal(mergeAnswers(answers, 2).length, 2, 'the limit applies after the merge, not per engine');
});

test('reduceHtml keeps text and links and reports what it discarded', () => {
  const reduced = reduceHtml('<title>T</title><script>a</script><script>b</script><style>c</style><p>One</p><a href="x">x</a>', { base: 'https://example.com/dir/page' });
  assert.equal(reduced.title, 'T');
  assert.equal(reduced.droppedScripts, 2);
  assert.equal(reduced.droppedStyles, 1);
  assert.deepEqual(reduced.links, [{ href: 'https://example.com/dir/x', text: 'x' }]);
  assert.equal(reduced.text, 'One\nx');
  const long = reduceHtml(`<p>${'z'.repeat(50)}</p>`, { maxChars: 10 });
  assert.equal(long.text.length, 10);
  assert.equal(long.textTruncated, true);
});
