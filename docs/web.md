# Retrieving and searching the web

`makeWebTools(config)` in `src/web.mjs` registers `web.fetch` and — only when at least one search
engine is configured — `web.search`. Both are `network`-effect tools, so both block for an exact
approval hash before anything leaves the machine. Registration is skipped entirely when `config`
is `undefined`, and `web.search` is absent rather than present-and-always-refusing when no engine
exists: a caller listing the tools learns what this deployment can do, not what it could do if
someone configured it.

Zero dependencies, like everything else here: `node:https`/`node:http` make the request, and the
HTML reduction, URL canonicalisation and result merge are this module's own.

## web.fetch records the retrieval, not just the page

Input is `{url}` and nothing else. There is no method, header, body or credential field in the
schema, so no plan and no model can turn a retrieval into a POST or attach an `Authorization`
header — and the tool sends no credential and no cookie of its own, ever. That is what makes a URL
which arrived *from a page* safe to pass back in: there is nothing to exfiltrate through it.

One call returns:

- `bodySha256` and `bytes` — the digest of **exactly** the bytes received. When `truncated` is
  true, the digest covers the prefix that arrived, which is what `truncated` says it does. So a
  claim made from a page can be traced to a digest instead of to a paraphrase.
- `status` and `ok`. **A non-2xx response is data, not a refusal.** A 404 comes back with
  `ok: false`, its status and its body; only a transport failure, a timeout, a policy refusal or a
  bad redirect throws. A 404 is a fact about a URL worth recording, and a tool that threw it away
  would make "this page does not exist" indistinguishable from "the network was down".
- `redirects` — every hop, with its status and resolved target — plus both `url` (asked for) and
  `finalUrl` (answered). Reporting only the final URL would make a page that moved
  indistinguishable from a page that was always there.
- `strategy`, `text`, `title`, `links`, `droppedScripts`, `droppedStyles`. The reduction is
  **named** in the result the way `skills.rank` names its scoring strategy: `html-reduction-v1`
  for HTML, `utf8-text` for other textual bodies, and `none` for bytes that are not text. A later
  reduction that reads differently must be a different name, not a silent change in meaning.
  Script and style bodies are removed and *counted* — a page whose visible text is one sentence
  and whose script bodies are forty kilobytes is a different kind of page, and the counts are the
  only way a reader of the text alone could tell. Links are resolved against the URL that actually
  answered, so they are usable as the next fetch.
- `untrusted: true`, always. The kernel's existing word for "evidence about a thing, and nothing
  more". Nothing retrieved here is ever treated as an instruction.

Bytes whose content type is not textual are digested and counted but never decoded: `strategy` is
`none` and `text` is empty, while `bodySha256` is still there. A retrieval stays attested even
when nothing was read from it.

### allowedOrigins is checked at every hop

`policy.allowedOrigins` is the whole of the outbound control, and it is applied to the requested
URL **and to each redirect target**, never inherited from the first request. A redirect is the
cheapest way to turn one allowlisted retrieval into a request to a host nobody reviewed, and
following them blindly is the normal behaviour of an HTTP client. An empty allowlist permits
nothing rather than everything. `maxRedirects` is configuration, not input, so a plan cannot ask
for a longer chain than the operator reviewed; `0` refuses the first redirect outright.

Refusals: `WEB_INPUT` (non-http(s) scheme, relative URL, credentials in the URL), `WEB_ORIGIN`
(origin not allowlisted, including a redirect target), `WEB_REDIRECT` (hop limit, missing or
unusable `location`, a redirect leaving http(s) or carrying credentials), `WEB_POLICY` (tool or
effect not allowlisted), `WEB_ABORTED`, `WEB_TIMEOUT`, `WEB_HTTP`.

## web.search answers with corroboration, not a ranking

Input is `{query, limit?}`. Every configured engine is asked **concurrently inside one bounded
call**, the same shape `process.runMany` and `dsh.run` use — the whole question is the declared
input and the whole table is the output, so nothing is session state held between two separately
approved calls and the result stays replay-safe.

Each result row carries `engines: [{name, rank, url}]`, `agreement` (how many engines returned
that page) and `bestRank`, ordered by **agreement, then best rank, then canonical URL**. That
order is total, so the table is identical whichever engine answers first — engines racing is the
normal case, and an order that depended on arrival would mean the same question gave two different
answers and no recorded search would replay.

Two engines pointing at one page through a tracking parameter, a differently-cased host or a
fragment merge into a single row. The merge key (`canonicalUrl`) drops the fragment, lower-cases
the host, removes `utm_*` and a reviewed list of tracking parameters, and sorts the survivors.
Every one of those rules is a judgement that could be wrong, so each row keeps **both** the merged
key and each engine's own URL: a merge a reader disagrees with can be audited rather than only
suspected. A row's title and snippet come from the engine that ranked it best, with ties broken on
engine name rather than on completion order.

- `asked`, `answered`, `agreementMax`, and `uncorroborated` — the number of results exactly one
  engine returned. **`uncorroborated` is `null`, not `0`, when only one engine answered**, because
  corroboration is not measurable from a single source and `0` would read as "nothing was
  uncorroborated" — the most convincing kind of wrong answer, since it is the value a caller hopes
  for.
- `engines: [{name, ok, count, answerSha256, code}]` — **an engine that fails is data, not an
  exception.** A malformed answer is `WEB_ENGINE_SHAPE`, an engine echoing its own configured
  credential back is `WEB_SECRET`, an HTTP error is `WEB_HTTP_STATUS`, and the healthy engines
  still answer. This is a deliberate departure from the integration layer's throw-on-any-failure
  contract, for the reason `process.runMany` made the same one: two engines out of three is a
  weaker answer, not a missing one. Each engine's raw answer is digested, so a snippet can be
  traced to the bytes it came from.
- **Every** engine failing is refused `WEB_NO_ENGINE`. An empty result list is a claim — that
  nothing matches the query — and a total outage is not evidence for it.

The output budget is divided by the engine count *before* any request is made, exactly as
`files.read` and `process.runMany` divide theirs, so the worst case of every engine answering at
full length is structurally inside the kernel's own output bound rather than rejected after the
bytes have been read. An engine over its share is refused `WEB_OUTPUT_LIMIT` on its own.

## What is and isn't covered

- **Covered, tested against a real loopback server** (`test/web.test.mjs`, 21 tests;
  `scripts/train-exercises-web.mjs`, 22 training exercises): the digest matching independently
  computed bytes, link resolution, script/style counting, a 404 as data, a two-hop redirect chain
  ending at the same bytes as a direct fetch, a redirect to a non-allowlisted origin, a redirect
  loop, truncation at an exact budget, a binary body, the absence of any `authorization` or
  `cookie` header on the wire, the quorum merge and its ordering, a single-engine `null`
  corroboration, mixed engine failures, total engine failure, per-engine budget division, and
  every declared output key being present on both success and error paths.
- **Not covered:** JavaScript execution (a page that renders itself with script returns the text
  its HTML contains — use `browser.snapshot` for a rendered page), POST or any other method,
  authentication on the fetch path, cookies or sessions, content-encoding negotiation (`identity`
  is requested explicitly), robots.txt evaluation, rate limiting across calls, and any form of
  result caching between calls.
- **Residual, disclosed:** an engine's URL is recorded as parsed, so WHATWG normalisation (host
  case, default port) has already been applied and the string is not byte-identical to what the
  engine sent; the path, query and fragment survive. Retrieved text is untrusted input to whatever
  reads it next — the `untrusted` flag is a statement, not an enforcement. And replay reproduces
  the *recorded* bytes, which is the point: it verifies what was retrieved, never that the site
  still says it.

## Configuration

```json
{
  "timeoutMs": 15000,
  "maxOutputBytes": 1048576,
  "maxRedirects": 3,
  "engines": [
    { "name": "searx-local", "origin": "http://127.0.0.1:8888", "path": "/search",
      "queryParam": "q", "extraParams": { "format": "json" },
      "resultsPath": ["results"], "urlKey": "url", "titleKey": "title",
      "snippetKey": "content", "maxResults": 10 },
    { "name": "brave", "origin": "https://api.search.brave.com",
      "path": "/res/v1/web/search", "queryParam": "q",
      "apiKeyEnv": "BRAVE_SEARCH_TOKEN", "resultsPath": ["web", "results"],
      "urlKey": "url", "titleKey": "title", "snippetKey": "description" }
  ]
}
```

An engine declares where it is and how to read its answer; nothing about an engine's response
shape is guessed. `origin` must be an exact HTTP(S) origin with no path and no credentials —
origin and path are separate fields because the origin is what the policy allowlist compares
against, and an origin with a path smuggled into it would be allowlisted as a different string
than the one the request is made to. `extraParams` may not restate `queryParam`: a fixed parameter
able to overwrite the query would let the configuration silently answer a different question while
the result was still reported under the asked one. `apiKeyEnv` names an environment variable, sent
as a bearer token to that engine only, and any answer containing it is refused `WEB_SECRET`.
`web.fetch` has no credential field at all.

See `examples/web.example.json`, `examples/web.plan.json` and `examples/web.policy.json`. Pass the
configuration with `--web FILE` to `src/cli.mjs`, `src/mcp.mjs` or the chat server.
