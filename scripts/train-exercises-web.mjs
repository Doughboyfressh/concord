import http from 'node:http';
import { createHash } from 'node:crypto';
import { makeWebTools, mergeAnswers, canonicalUrl } from '../src/web.mjs';

/**
 * The web half of the write side: retrieving a page, and asking several engines one question.
 *
 * Every exercise here is a direct call rather than a plan, for the same reason the process family
 * is: these tools exist only when an operator has configured them, so they are not in the round's
 * registry and no plan can name them. The price is the same too — a direct-call exercise is
 * proven by being invoked twice with the same answer, instead of by replaying a journal.
 *
 * That repetition is why every success exercise returns a *projection* of the result rather than
 * the result itself. A loopback server gets a fresh ephemeral port on each call, so the URL, the
 * final URL and every resolved link differ between two otherwise identical calls. Asserting on
 * the whole result would report a tool as non-deterministic when the only thing that moved was
 * the port, and that finding would be the instrument's, not the system's. The projections keep
 * the digests, counts and ordering — which is what each lesson is actually about — and drop the
 * port.
 *
 * An exercise against a real site would be worse than no exercise: the answer would change under
 * us, and a lesson earned from a page that has since been edited is a lesson about nothing. The
 * loopback server is what makes "this is how Concord treats an answer it did not compute"
 * checkable at all.
 */

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const PAGE = [
  '<!doctype html><html><head><title>A page with a title</title><style>b{color:red}</style></head>',
  '<body><h1>Heading</h1><p>First paragraph.</p><script>var secret = 1;</script>',
  '<a href="/next">next page</a><a href="https://example.org/out?utm_source=x">off site</a><a href="#top">anchor</a>',
  '<p>Second&nbsp;paragraph.</p></body></html>',
].join('\n');
const PAGE_DIGEST = sha256(Buffer.from(PAGE));

const ALPHA = { results: [
  { url: 'https://example.com/one?utm_source=a', title: 'One from alpha', snippet: 'alpha on one' },
  { url: 'https://example.com/two', title: 'Two from alpha', snippet: 'alpha on two' },
] };
const BETA = { data: { hits: [
  { link: 'https://EXAMPLE.com/two#section', heading: 'Two from beta', body: 'beta on two' },
  { link: 'https://example.com/one', heading: 'One from beta', body: 'beta on one' },
  { link: 'https://example.com/three', heading: 'Three from beta', body: 'only beta knows this one' },
] } };
const BETA_SHAPE = { resultsPath: ['data', 'hits'], urlKey: 'link', titleKey: 'heading', snippetKey: 'body' };

const TOKEN_ENV = 'CONCORD_TRAINING_SEARCH_TOKEN';
const TOKEN = 'tok-training-search-credential';

/** The one server every web exercise runs against, and the only thing it is honest about. */
function handler(request, response) {
  const { pathname } = new URL(request.url, 'http://loopback');
  const json = (body) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(body)); };
  if (pathname === '/page') { response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); response.end(PAGE); return; }
  if (pathname === '/missing') { response.writeHead(404, { 'content-type': 'text/plain' }); response.end('no such page'); return; }
  if (pathname === '/hop') { response.writeHead(302, { location: '/page' }); response.end(); return; }
  if (pathname === '/away') { response.writeHead(302, { location: 'http://127.0.0.2:9/elsewhere' }); response.end(); return; }
  if (pathname === '/loop') { response.writeHead(302, { location: '/loop' }); response.end(); return; }
  if (pathname === '/big') { response.writeHead(200, { 'content-type': 'text/plain' }); response.end('x'.repeat(40_000)); return; }
  if (pathname === '/binary') { response.writeHead(200, { 'content-type': 'application/octet-stream' }); response.end(Buffer.from([0x4d, 0x5a, 0x90, 0x00])); return; }
  if (pathname === '/alpha') { json(ALPHA); return; }
  if (pathname === '/beta') { json(BETA); return; }
  if (pathname === '/notjson') { response.writeHead(200, { 'content-type': 'application/json' }); response.end('<html>not json at all</html>'); return; }
  if (pathname === '/echo') { json({ results: [{ url: 'https://example.com/leak', title: `the token is ${TOKEN}`, snippet: '' }] }); return; }
  response.writeHead(503, { 'content-type': 'text/plain' });
  response.end('this endpoint is deliberately unavailable');
}

/** Start a loopback server, run one call against it, and always shut it down. */
async function againstServer(run, { token = TOKEN } = {}) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const previous = process.env[TOKEN_ENV];
  if (token === null) delete process.env[TOKEN_ENV]; else process.env[TOKEN_ENV] = token;
  try { return await run(origin); }
  finally {
    server.close();
    if (previous === undefined) delete process.env[TOKEN_ENV]; else process.env[TOKEN_ENV] = previous;
  }
}

const policyFor = (origin, over = {}) => ({
  version: 1, allowedTools: ['web.fetch', 'web.search'], allowedEffects: ['pure', 'read', 'write', 'network', 'process'],
  allowedOrigins: origin === null ? [] : [origin], maxTasks: 32, maxOutputBytes: 262_144,
  maxJournalBytes: 16_777_216, timeoutMs: 8000, ...over,
});

const fetchTool = (over = {}) => makeWebTools({ timeoutMs: 5000, maxOutputBytes: 262_144, ...over })[0];
const searchTool = (engines, over = {}) => makeWebTools({ timeoutMs: 5000, maxOutputBytes: 262_144, engines, ...over })[1];
const enginesOn = (origin) => [
  { name: 'alpha', origin, path: '/alpha' },
  { name: 'beta', origin, path: '/beta', queryParam: 'query', ...BETA_SHAPE },
  { name: 'down', origin, path: '/down' },
];

/** Fetch one path and keep only what is the same whatever port the server was given. */
const fetchPath = (path, { policy, config } = {}) => againstServer(async (origin) => {
  const tool = fetchTool(config);
  const result = await tool.execute({ url: origin + path }, { policy: policy ? policy(origin) : policyFor(origin) });
  return {
    ok: result.ok, status: result.status, strategy: result.strategy, title: result.title,
    bytes: result.bytes, bodySha256: result.bodySha256, truncated: result.truncated,
    textTruncated: result.textTruncated, droppedScripts: result.droppedScripts, droppedStyles: result.droppedStyles,
    untrusted: result.untrusted, text: result.text,
    // Paths rather than URLs: the host carries the port, the path does not.
    links: result.links.map((link) => (link.href.startsWith(origin) ? link.href.slice(origin.length) : link.href)),
    hops: result.redirects.map((hop) => [hop.status, hop.to.slice(hop.to.indexOf('/', 8))]),
    arrivedAtRequested: result.finalUrl === origin + path,
    everyDeclaredKeyPresent: tool.outputKeys.every((key) => result[key] !== undefined),
  };
});

export function webExercises() {
  return [
    // ---- what exists at all ----------------------------------------------------------
    {
      family: 'web', tool: 'web.factory',
      call: () => ({
        unconfigured: makeWebTools(undefined).length,
        empty: makeWebTools({}).map((tool) => tool.name),
        withEngine: makeWebTools({ engines: [{ name: 'e', origin: 'https://search.example' }] }).map((tool) => tool.name),
      }),
      expect: (r) => r.unconfigured === 0 && r.empty.length === 1 && r.empty[0] === 'web.fetch' && r.withEngine.length === 2,
      lesson: 'An absent web configuration registers no tool at all, and web.search appears only once at least one engine is configured, while web.fetch appears without any. A harness with no engine cannot search, and saying so by absence is more honest than registering a tool that exists only to decline: a caller listing the tools learns what this deployment can actually do rather than what it could do if someone configured it.',
    },
    {
      family: 'web', tool: 'web.fetch',
      call: () => ({ schema: makeWebTools({})[0].inputSchema }),
      expect: (r) => Object.keys(r.schema.properties).length === 1 && Boolean(r.schema.properties.url) && r.schema.additionalProperties === false,
      lesson: 'web.fetch takes a url and nothing else: there is no method, header, body or credential field in its schema, so no plan and no model can turn a retrieval into a POST or attach an Authorization header. The tool sends no credential and no cookie of its own either, which is what makes a URL that arrived from a page safe to retrieve — there is nothing to exfiltrate through it.',
    },

    // ---- refusals, before anything leaves the machine --------------------------------
    {
      family: 'web', tool: 'web.factory', expectThrow: 'WEB_CONFIG',
      call: () => makeWebTools({ engines: [{ name: 'a', origin: 'https://x.example/path' }] }),
      lesson: 'A search engine origin carrying a path is refused WEB_CONFIG. An origin and a path are separate fields because the origin is what the policy allowlist compares against, and an origin with a path smuggled into it would be allowlisted as a different string than the one the request is actually made to.',
    },
    {
      family: 'web', tool: 'web.factory', expectThrow: 'WEB_CONFIG',
      call: () => makeWebTools({ engines: [{ name: 'a', origin: 'https://x.example', extraParams: { q: 'overrides the query' } }] }),
      lesson: 'An engine whose extraParams restate its own queryParam is refused WEB_CONFIG at registration. A fixed parameter that could overwrite the query would let the configuration silently answer a different question than the one asked, and the result would still be reported under the asked query.',
    },
    {
      family: 'web', tool: 'web.fetch', expectThrow: 'WEB_INPUT',
      call: () => fetchTool().execute({ url: 'file:///etc/passwd' }, { policy: policyFor('http://127.0.0.1:9') }),
      lesson: 'web.fetch refuses WEB_INPUT for any scheme other than http and https, so file:, data: and javascript: URLs are rejected before a socket is opened. A network tool that would read a local path on request is a file reader with no workspace confinement, which is the one thing every read tool here is careful about.',
    },
    {
      family: 'web', tool: 'web.fetch', expectThrow: 'WEB_INPUT',
      call: () => fetchTool().execute({ url: 'http://user:password@127.0.0.1:9/' }, { policy: policyFor('http://127.0.0.1:9') }),
      lesson: 'A URL carrying credentials is refused WEB_INPUT. Credentials in a URL would be journaled in full as ordinary task input, and the fetch path deliberately has no way to authenticate, so accepting them would both record a secret and imply an authentication this tool does not perform.',
    },
    {
      family: 'web', tool: 'web.fetch', expectThrow: 'WEB_ORIGIN',
      call: () => fetchTool().execute({ url: 'http://127.0.0.1:9/' }, { policy: policyFor(null) }),
      lesson: 'An origin absent from the policy allowedOrigins is refused WEB_ORIGIN before any connection is attempted, and an empty allowlist permits nothing rather than everything. The allowlist is the whole of the outbound control: configuring a web tool says retrieval is possible, and the policy says where this run may reach.',
    },
    {
      family: 'web', tool: 'web.fetch', expectThrow: 'WEB_POLICY',
      call: () => fetchTool().execute({ url: 'http://127.0.0.1:9/' }, { policy: policyFor('http://127.0.0.1:9', { allowedTools: ['something.else'] }) }),
      lesson: 'A web tool missing from policy allowedTools is refused WEB_POLICY, and the same code covers a policy that does not allow the network effect. The code is distinct from INTEGRATION_POLICY and BROWSER_POLICY on purpose: three layers here reach the network, and a journal should say which gate refused rather than only that a gate did.',
    },
    {
      family: 'web', tool: 'web.fetch', expectThrow: 'WEB_ABORTED',
      call: () => fetchTool().execute({ url: 'http://127.0.0.1:9/' }, { policy: policyFor('http://127.0.0.1:9'), signal: AbortSignal.abort() }),
      lesson: 'A web call carrying an already-aborted signal is refused WEB_ABORTED before the request is made, and a signal that aborts mid-flight settles the same way through the listener registered for the duration of the call.',
    },

    // ---- a page, as evidence ---------------------------------------------------------
    {
      family: 'web', tool: 'web.fetch',
      call: () => fetchPath('/page'),
      expect: (r) => r.ok === true && r.status === 200 && r.bodySha256 === PAGE_DIGEST && r.bytes === Buffer.byteLength(PAGE)
        && r.strategy === 'html-reduction-v1' && r.title === 'A page with a title'
        && r.droppedScripts === 1 && r.droppedStyles === 1 && !r.text.includes('var secret')
        && r.links.length === 2 && r.links[0] === '/next' && r.links[1] === 'https://example.org/out?utm_source=x'
        && r.untrusted === true && r.everyDeclaredKeyPresent && r.arrivedAtRequested,
      lesson: 'web.fetch returns the SHA-256 of exactly the bytes it received alongside the text it reduced them to, so a claim made from a page can be traced to a digest rather than to a paraphrase — the digest matches one computed independently from the served bytes. The reduction is named in the result (html-reduction-v1) the way skills.rank names its strategy, script and style bodies are removed and counted rather than silently dropped, and relative links are resolved against the URL that actually answered. The page is marked untrusted, which is this kernel\'s existing word for evidence about a thing rather than instructions from it.',
    },
    {
      family: 'web', tool: 'web.fetch',
      call: () => fetchPath('/missing'),
      expect: (r) => r.ok === false && r.status === 404 && r.text === 'no such page'
        && r.bodySha256 === sha256(Buffer.from('no such page')) && r.everyDeclaredKeyPresent,
      lesson: 'A 404 is data, not a refusal: web.fetch reports ok:false with the status and the body it received, and only a transport failure, a timeout or a policy refusal throws. A 404 is a fact about a URL worth recording, and a tool that threw it away would make "this page does not exist" indistinguishable from "the network was down". Every declared key is present on an error response exactly as on a successful one, so a caller never branches on whether a key exists.',
    },
    {
      family: 'web', tool: 'web.fetch',
      call: () => fetchPath('/hop'),
      expect: (r) => r.ok === true && r.bodySha256 === PAGE_DIGEST && r.hops.length === 1
        && r.hops[0][0] === 302 && r.hops[0][1] === '/page' && r.arrivedAtRequested === false,
      lesson: 'A redirect chain is recorded hop by hop with the status and the resolved target of each, and the result keeps both the URL that was asked for and the one that answered. Those are different facts about a retrieval, and a tool reporting only the final URL would make a page that moved indistinguishable from a page that was always there.',
    },
    {
      family: 'web', tool: 'web.fetch', expectThrow: 'WEB_ORIGIN',
      call: () => againstServer((origin) => fetchTool().execute({ url: `${origin}/away` }, { policy: policyFor(origin) })),
      lesson: 'A redirect pointing at an origin outside the policy allowlist is refused WEB_ORIGIN, because every hop is checked against the same allowlist as the first request rather than inheriting its permission. This is the sharpest check on the fetch path: a redirect is the cheapest way to turn one allowlisted retrieval into a request to a host nobody reviewed, and following them blindly is the normal behaviour of an HTTP client.',
    },
    {
      family: 'web', tool: 'web.fetch', expectThrow: 'WEB_REDIRECT',
      call: () => againstServer((origin) => fetchTool({ maxRedirects: 2 }).execute({ url: `${origin}/loop` }, { policy: policyFor(origin) })),
      lesson: 'A redirect loop is refused WEB_REDIRECT once the configured hop limit is reached, and a hop limit of zero refuses the first redirect outright. The limit is configuration rather than input, so a plan cannot ask for a longer chain than the operator reviewed.',
    },
    {
      family: 'web', tool: 'web.fetch',
      call: () => fetchPath('/big', { policy: (origin) => policyFor(origin, { maxOutputBytes: 1000 }) }),
      expect: (r) => r.truncated === true && r.bytes === 1000 && r.bodySha256 === sha256(Buffer.from('x'.repeat(1000))),
      lesson: 'A body larger than the output budget is truncated at exactly the budget, flagged truncated:true, and digested as the prefix that actually arrived — the digest is of what was read, never of what the server intended to send. Measured the hard way: settling the call before destroying the socket is load-bearing, because response.destroy() emits its abort synchronously, so destroying first turned a reachable budget into an unexplained transport failure and discarded the body entirely.',
    },
    {
      family: 'web', tool: 'web.fetch',
      call: () => fetchPath('/binary'),
      expect: (r) => r.strategy === 'none' && r.text === '' && r.title === null && r.links.length === 0
        && r.bodySha256 === sha256(Buffer.from([0x4d, 0x5a, 0x90, 0x00])),
      lesson: 'Bytes whose content type is not textual are digested and counted but never decoded: the strategy is reported as none, the text is empty, and the digest is still there. A retrieval stays attested even when nothing was read from it, which is what lets a caller cite having fetched a binary without the tool having to pretend it understood one.',
    },

    // ---- search: corroboration, not a ranked list -------------------------------------
    {
      family: 'web', tool: 'web.search',
      call: () => againstServer(async (origin) => {
        const tool = searchTool(enginesOn(origin));
        const result = await tool.execute({ query: 'deterministic replay', limit: 5 }, { policy: policyFor(origin) });
        return {
          ranking: result.ranking, asked: result.asked, answered: result.answered,
          agreementMax: result.agreementMax, uncorroborated: result.uncorroborated,
          rows: result.results.map((row) => [row.canonicalUrl, row.agreement, row.bestRank, row.title]),
          engines: result.engines.map((entry) => [entry.name, entry.ok, entry.count, entry.code]),
          alphaDigest: result.engines.find((entry) => entry.name === 'alpha').answerSha256,
          everyDeclaredKeyPresent: tool.outputKeys.every((key) => result[key] !== undefined),
        };
      }),
      expect: (r) => r.ranking === 'agreement-then-best-rank-v1' && r.asked === 3 && r.answered === 2
        && r.agreementMax === 2 && r.uncorroborated === 1
        && r.rows[0][0] === 'https://example.com/one' && r.rows[0][1] === 2
        && r.rows[2][0] === 'https://example.com/three' && r.rows[2][1] === 1
        && r.rows[1][3] === 'Two from beta'
        && r.engines[2][0] === 'down' && r.engines[2][1] === false && r.engines[2][3] === 'WEB_HTTP_STATUS'
        && r.alphaDigest === sha256(Buffer.from(JSON.stringify(ALPHA)))
        && r.everyDeclaredKeyPresent,
      lesson: 'web.search asks every configured engine in one bounded call and returns a corroboration table rather than a ranked list: each row carries which engines returned that page, at what rank each put it, and how many agreed, ordered by agreement before rank. Two engines pointing at the same page through a tracking parameter, a differently-cased host or a fragment merge into one row, and both the merged key and each engine\'s own URL are kept so a merge can be audited rather than only suspected. The wording of a row comes from the engine that ranked it best, and each engine\'s raw answer is digested, so a snippet can be traced to the bytes it came from.',
    },
    {
      family: 'web', tool: 'web.search',
      call: () => againstServer(async (origin) => {
        const result = await searchTool([{ name: 'alpha', origin, path: '/alpha' }]).execute({ query: 'only one source' }, { policy: policyFor(origin) });
        return { answered: result.answered, uncorroborated: result.uncorroborated, agreementMax: result.agreementMax };
      }),
      expect: (r) => r.answered === 1 && r.uncorroborated === null && r.agreementMax === 1,
      lesson: 'With one engine answering, uncorroborated is null rather than 0. Corroboration is not measurable from a single source, and reporting zero would read as "nothing was uncorroborated" — the most convincing kind of wrong answer, because it is the value a caller hopes for. A null forces the question instead of answering it falsely.',
    },
    {
      family: 'web', tool: 'web.search',
      call: () => againstServer(async (origin) => {
        const engines = [
          { name: 'alpha', origin, path: '/alpha' },
          { name: 'notjson', origin, path: '/notjson' },
          { name: 'echo', origin, path: '/echo', apiKeyEnv: TOKEN_ENV },
        ];
        const result = await searchTool(engines).execute({ query: 'mixed answers' }, { policy: policyFor(origin) });
        return { answered: result.answered, codes: Object.fromEntries(result.engines.map((entry) => [entry.name, entry.code])), rows: result.results.length };
      }),
      expect: (r) => r.answered === 1 && r.codes.alpha === null && r.codes.notjson === 'WEB_ENGINE_SHAPE'
        && r.codes.echo === 'WEB_SECRET' && r.rows === 2,
      lesson: 'An engine that fails is a row of data carrying its own refusal code, not an exception that discards every other engine\'s answer: a malformed answer is WEB_ENGINE_SHAPE and one that echoes the configured credential back is WEB_SECRET, while the healthy engine still answers. This is a deliberate departure from the integration layer\'s throw-on-failure contract, for the same reason process.runMany made it — two engines out of three is a weaker answer, not a missing one, and throwing would spend the whole call\'s evidence on its worst participant.',
    },
    {
      family: 'web', tool: 'web.search', expectThrow: 'WEB_NO_ENGINE',
      call: () => againstServer((origin) => searchTool([
        { name: 'down', origin, path: '/down' },
        { name: 'alsodown', origin, path: '/alsodown' },
      ]).execute({ query: 'nothing answers' }, { policy: policyFor(origin) })),
      lesson: 'Every engine failing is refused WEB_NO_ENGINE rather than returning an empty result list. An empty list is a claim — that nothing matches the query — and a total outage is not evidence for it. The refusal names the codes it collected, so an operator can tell a broken configuration from a broken network.',
    },
    {
      family: 'web', tool: 'web.search',
      call: () => againstServer(async (origin) => {
        const result = await searchTool([
          { name: 'alpha', origin, path: '/alpha' },
          { name: 'big', origin, path: '/big' },
        ]).execute({ query: 'one oversized answer' }, { policy: policyFor(origin, { maxOutputBytes: 2000 }) });
        return { answered: result.answered, codes: Object.fromEntries(result.engines.map((entry) => [entry.name, entry.code])) };
      }),
      expect: (r) => r.answered === 1 && r.codes.big === 'WEB_OUTPUT_LIMIT' && r.codes.alpha === null,
      lesson: 'The output budget is divided by the number of configured engines before any request is made, the way files.read and process.runMany divide theirs, so an engine answering at full length can only spend its own share: the oversized engine is refused WEB_OUTPUT_LIMIT and the engine inside its share still answers. Dividing first keeps the worst case structurally inside the kernel\'s own output bound instead of relying on a rejection after the bytes have already been read.',
    },
    {
      family: 'web', tool: 'web.mergeAnswers',
      call: () => {
        const answers = [
          { engine: 'a', results: [{ url: 'https://x.example/1', title: 'a1', snippet: null, rank: 1 }, { url: 'https://x.example/2', title: 'a2', snippet: null, rank: 2 }] },
          { engine: 'b', results: [{ url: 'https://x.example/2', title: 'b2', snippet: null, rank: 1 }, { url: 'https://x.example/3', title: 'b3', snippet: null, rank: 2 }] },
          { engine: 'c', results: [{ url: 'https://x.example/3', title: 'c3', snippet: null, rank: 1 }] },
        ];
        const forward = mergeAnswers(answers, 10);
        const reversed = mergeAnswers([...answers].reverse(), 10);
        return {
          sameEitherWay: JSON.stringify(forward) === JSON.stringify(reversed),
          order: forward.map((row) => row.canonicalUrl), wording: forward[0].title,
          merges: [canonicalUrl('https://EXAMPLE.com/a#f'), canonicalUrl('https://example.com/a?utm_source=x&b=2&a=1')],
        };
      },
      expect: (r) => r.sameEitherWay && r.order[0] === 'https://x.example/2' && r.wording === 'b2'
        && r.merges[0] === 'https://example.com/a' && r.merges[1] === 'https://example.com/a?a=1&b=2',
      lesson: 'The merge order is a total one — agreement, then best rank, then the canonical URL — so the result list is identical whichever engine answers first, and ties in wording break on engine name rather than on completion order. Engines racing is the normal case, so an order that depended on arrival would make the same question give two different answers and no recorded search would replay.',
    },
  ];
}
