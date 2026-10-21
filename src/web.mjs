import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash } from 'node:crypto';
import { digest, parseJson as strictParseJson, validateSchema, HarnessError } from './value.mjs';

/**
 * Reading the open web, as evidence rather than as narration.
 *
 * Two tools, both `network`, so both sit behind the approval hash like everything else that
 * leaves this machine. What makes them worth writing rather than wrapping:
 *
 * `web.fetch` records the retrieval, not just the page. Every response carries the SHA-256 of
 * exactly the bytes received, the full redirect chain that led to them, and the name of the
 * reduction that turned those bytes into the text a model will read. So a claim made from a page
 * can be traced to a digest, and a replayed run answers from the recorded bytes rather than from
 * whatever the site serves today — which is the difference between a transcript and a citation.
 * Policy allowedOrigins is re-checked at *every* redirect hop, not only on the URL the plan asked
 * for, because a redirect is the cheapest way to turn an allowlisted fetch into a request
 * somewhere else. No credential, cookie or Authorization header is ever sent by `web.fetch`: a
 * URL that arrived from a page cannot be turned into a way out for a token.
 *
 * `web.search` refuses to treat one engine's ranking as the answer. It queries every configured
 * engine concurrently inside a single bounded call and reports each result as a corroboration
 * row — which engines returned it, at what rank, and how many agreed — then orders by agreement
 * before rank. An engine that fails is data (`engines[].ok === false`), not an exception, because
 * two engines out of three still answer the question; only zero answers is a refusal. The count
 * of results exactly one engine returned is reported as `uncorroborated`, and is null rather than
 * 0 when a single engine answered, because corroboration is not measurable from one source.
 *
 * Neither tool interprets a page as instructions. Both mark their output `untrusted: true`, which
 * is this kernel's existing word for "these bytes are evidence about a thing, and nothing more".
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const envName = /^[A-Za-z_][A-Za-z0-9_]*$/;
const toolName = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const DEFAULT_TIMEOUT = 15_000;
const DEFAULT_OUTPUT = 1_048_576;
const DEFAULT_REDIRECTS = 3;
const MAX_TEXT_CHARS = 200_000;
const MAX_LINKS = 200;
const MAX_ENGINES = 8;
const MAX_RESULTS = 50;

function fail(code, message, details) { throw new HarnessError(code, message, details); }
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function text(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) fail('WEB_CONFIG', `${label} must be a nonempty string`);
  return value;
}
function positive(value, fallback, label) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 2_147_483_647) fail('WEB_CONFIG', `${label} must be a positive bounded integer`);
  return result;
}
function keys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('WEB_CONFIG', `${label} configuration must be an object`);
  const extra = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extra.length) fail('WEB_CONFIG', `Unsupported ${label} configuration field`, { field: extra[0] });
}
function exactOrigin(value) {
  let parsed;
  try { parsed = new URL(value); } catch { fail('WEB_CONFIG', 'Invalid origin'); }
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.origin !== value || parsed.username || parsed.password) {
    fail('WEB_CONFIG', 'Origin must be an exact HTTP(S) origin without credentials or a path');
  }
  return parsed.origin;
}

/**
 * Same shape as integrations.limits and browser.limits, with this module's own codes.
 *
 * Deliberately a third copy rather than a shared import: the code a journal records is how an
 * operator finds which gate refused, and WEB_POLICY in a web task says something
 * INTEGRATION_POLICY does not. All three behave identically — narrow against policy, never widen.
 */
function limits(config, context, name) {
  const policy = context?.policy ?? {};
  if (Array.isArray(policy.allowedTools) && !policy.allowedTools.includes(name)) fail('WEB_POLICY', 'Web tool is not allowlisted');
  if (Array.isArray(policy.allowedEffects) && !policy.allowedEffects.includes('network')) fail('WEB_POLICY', 'Network effect is not allowlisted');
  if (context?.signal?.aborted) fail('WEB_ABORTED', 'Web request was cancelled');
  return {
    timeoutMs: Math.min(config.timeoutMs, positive(policy.timeoutMs, config.timeoutMs, 'policy timeoutMs')),
    maxOutputBytes: Math.min(config.maxOutputBytes, positive(policy.maxOutputBytes, config.maxOutputBytes, 'policy maxOutputBytes')),
  };
}

/** The allowlist is the whole SSRF control, so it is applied to every URL, including each hop. */
function allowOrigin(url, context, where) {
  const allowed = context?.policy?.allowedOrigins;
  if (!Array.isArray(allowed) || !allowed.includes(url.origin)) {
    fail('WEB_ORIGIN', `${where} origin is not allowlisted`, { origin: url.origin });
  }
}

function absoluteUrl(value) {
  let url;
  try { url = new URL(value); } catch { fail('WEB_INPUT', 'url must be an absolute URL'); }
  if (!['http:', 'https:'].includes(url.protocol)) fail('WEB_INPUT', 'url must use http or https');
  if (url.username || url.password) fail('WEB_INPUT', 'url must not carry credentials');
  return url;
}

/**
 * One bounded GET. Returns what arrived, including a non-2xx status: a 404 is a fact about a URL,
 * so it is reported as data and only a transport failure is a refusal. Reads at most maxBytes and
 * says so, which keeps the digest honest — it covers exactly the bytes counted, never the bytes
 * the server intended to send.
 */
function httpGet(url, { timeoutMs, maxBytes, token, accept, signal }) {
  return new Promise((resolveRequest, reject) => {
    let done = false;
    let timer;
    const finish = (error, result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', cancelled);
      if (error) reject(error); else resolveRequest(result);
    };
    const headers = { accept, 'accept-encoding': 'identity', 'user-agent': 'concord-web/1 (+deterministic-harness)' };
    if (token) headers.authorization = `Bearer ${token}`;
    const client = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const outgoing = client(url, { method: 'GET', agent: false, rejectUnauthorized: true, maxHeaderSize: 16_384, headers }, (response) => {
      let bytes = 0;
      let truncated = false;
      const chunks = [];
      response.on('data', (chunk) => {
        if (truncated) return;
        const room = maxBytes - bytes;
        if (chunk.length >= room) {
          if (room > 0) { chunks.push(chunk.subarray(0, room)); bytes += room; }
          truncated = true;
          // Settled *before* the sockets are destroyed. Measured: response.destroy() emits
          // 'aborted' synchronously, so destroying first let the abort handler settle the promise
          // as WEB_HTTP and the truncated body was never returned at all — a reachable budget
          // became an unexplained transport failure. The guard on the 'aborted' handler below is
          // the second half of the same fix.
          finish(null, { status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks), truncated: true });
          response.destroy();
          outgoing.destroy();
          return;
        }
        bytes += chunk.length;
        chunks.push(chunk);
      });
      response.on('end', () => finish(null, { status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks), truncated: false }));
      response.on('error', () => finish(new HarnessError('WEB_HTTP', 'Web response failed')));
      response.on('aborted', () => { if (!truncated) finish(new HarnessError('WEB_HTTP', 'Web response was interrupted')); });
    });
    const cancelled = () => { finish(new HarnessError('WEB_ABORTED', 'Web request was cancelled')); outgoing.destroy(); };
    outgoing.on('error', () => finish(new HarnessError('WEB_HTTP', 'Web request failed')));
    timer = setTimeout(() => { finish(new HarnessError('WEB_TIMEOUT', 'Web request timed out')); outgoing.destroy(); }, timeoutMs);
    signal?.addEventListener('abort', cancelled, { once: true });
    if (signal?.aborted) { cancelled(); return; }
    outgoing.end();
  });
}

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
function decodeEntities(value) {
  return value.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, name) => {
    const key = name.toLowerCase();
    if (Object.hasOwn(ENTITIES, key)) return ENTITIES[key];
    if (key.startsWith('#x')) { const code = Number.parseInt(key.slice(2), 16); return Number.isInteger(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : whole; }
    if (key.startsWith('#')) { const code = Number.parseInt(key.slice(1), 10); return Number.isInteger(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : whole; }
    return whole;
  });
}

/**
 * HTML to text and links, and a count of what was discarded.
 *
 * Named `html-reduction-v1` in the output for the same reason skills.rank names its strategy: a
 * caller reading the text should be able to tell what produced it, and a later version that reads
 * differently should be a different name rather than a silent change in meaning. Script and style
 * bodies are removed and *counted* — a page whose visible text is one sentence and whose script
 * bodies are forty kilobytes is a different kind of page, and the counts are the only way a
 * reader of the text alone could tell.
 */
export function reduceHtml(html, { maxChars = MAX_TEXT_CHARS, maxLinks = MAX_LINKS, base = null } = {}) {
  let scripts = 0;
  let styles = 0;
  let working = html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, () => { scripts += 1; return ' '; })
    .replace(/<style\b[\s\S]*?<\/style\s*>/gi, () => { styles += 1; return ' '; });

  const titleMatch = working.match(/<title[^>]*>([\s\S]*?)<\/title\s*>/i);
  const title = titleMatch ? decodeEntities(titleMatch[1].replace(/\s+/g, ' ')).trim().slice(0, 1024) : null;
  // Removed once captured, so the title is reported in one place instead of also appearing as the
  // first line of the page text. A browser does not render it in the document, and text that
  // repeats a field the caller already has wastes the budget that field was taken from.
  working = working.replace(/<title[^>]*>[\s\S]*?<\/title\s*>/gi, ' ');

  const links = [];
  const seenHref = new Set();
  const anchor = /<a\b[^>]*?href\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi;
  for (let match = anchor.exec(working); match && links.length < maxLinks; match = anchor.exec(working)) {
    const raw = decodeEntities(match[2] ?? match[3] ?? match[4] ?? '').trim();
    if (!raw || raw.startsWith('#')) continue;
    let href;
    try { href = base ? new URL(raw, base).toString() : new URL(raw).toString(); } catch { continue; }
    if (!href.startsWith('http:') && !href.startsWith('https:')) continue;
    if (seenHref.has(href)) continue;
    seenHref.add(href);
    links.push({ href, text: decodeEntities(match[5].replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ')).trim().slice(0, 512) });
  }

  working = working
    .replace(/<\/(p|div|section|article|li|tr|h[1-6]|header|footer|nav|blockquote|pre|table)\s*>/gi, '\n')
    .replace(/<(br|hr)\b[^>]*>/gi, '\n')
    .replace(/<[^>]*>/g, ' ');
  const reduced = decodeEntities(working)
    .replace(/[ \t\f\v ]+/g, ' ')
    .replace(/ ?\n ?/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return {
    text: reduced.slice(0, maxChars), textTruncated: reduced.length > maxChars,
    title, links, droppedScripts: scripts, droppedStyles: styles,
  };
}

const TEXTUAL = /^(text\/|application\/(json|xml|xhtml\+xml|javascript|ld\+json)|application\/[a-z0-9.+-]*\+json)/i;
const NOT_DECODED = { strategy: 'none', text: '', textTruncated: false, title: null, links: [], droppedScripts: 0, droppedStyles: 0 };
function decodeBody(body, contentType, maxChars, base) {
  const type = (contentType ?? '').toLowerCase();
  // Bytes that are not text are digested and counted, never guessed at. The caller still gets the
  // digest, which is what makes "I retrieved this" checkable even when nothing was read.
  if (!TEXTUAL.test(type)) return { ...NOT_DECODED };
  let decoded;
  try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(body); }
  catch { return { ...NOT_DECODED }; }
  if (/html|xml/.test(type)) return { strategy: 'html-reduction-v1', ...reduceHtml(decoded, { maxChars, base }) };
  return {
    strategy: 'utf8-text', text: decoded.slice(0, maxChars), textTruncated: decoded.length > maxChars,
    title: null, links: [], droppedScripts: 0, droppedStyles: 0,
  };
}

/**
 * One URL for one page, so two engines linking the same page merge into one row.
 *
 * Every rule here is a judgement that could be wrong, so a result keeps both this value and the
 * engine's own URL: a merge a reader disagrees with can be audited rather than only suspected.
 * Tracking parameters are dropped from a reviewed list rather than by guessing at parameter
 * meaning, and the surviving parameters are sorted, because two engines emitting the same query
 * string in different orders are still pointing at the same page.
 */
const TRACKING = new Set(['fbclid', 'gclid', 'msclkid', 'ref', 'ref_src', 'ref_url', 'igshid', 'mc_cid', 'mc_eid', 'yclid', 'twclid']);
export function canonicalUrl(value) {
  const url = new URL(value);
  url.hash = '';
  url.username = '';
  url.password = '';
  url.hostname = url.hostname.toLowerCase();
  const params = [...url.searchParams.entries()]
    .filter(([name]) => !name.toLowerCase().startsWith('utm_') && !TRACKING.has(name.toLowerCase()))
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  url.search = '';
  for (const [name, entry] of params) url.searchParams.append(name, entry);
  // No attempt to drop a bare trailing slash: for an http(s) URL the WHATWG parser already gives
  // an empty path as "/" and refuses to take it away again, so `https://example.com` and
  // `https://example.com/` arrive here identical and merge without any help. A line trying to
  // strip it looked like it was doing something and was doing nothing.
  return url.toString();
}

function engineSettings(value, index) {
  keys(value, ['name', 'origin', 'path', 'queryParam', 'extraParams', 'apiKeyEnv', 'resultsPath', 'urlKey', 'titleKey', 'snippetKey', 'maxResults'], 'search engine');
  const engine = {
    name: text(value.name, `engine[${index}] name`),
    origin: exactOrigin(text(value.origin, `engine[${index}] origin`)),
    path: value.path ?? '/',
    queryParam: text(value.queryParam ?? 'q', `engine[${index}] queryParam`),
    resultsPath: value.resultsPath ?? ['results'],
    urlKey: text(value.urlKey ?? 'url', `engine[${index}] urlKey`),
    titleKey: text(value.titleKey ?? 'title', `engine[${index}] titleKey`),
    snippetKey: text(value.snippetKey ?? 'snippet', `engine[${index}] snippetKey`),
    maxResults: positive(value.maxResults, 10, `engine[${index}] maxResults`),
    apiKeyEnv: value.apiKeyEnv === undefined ? null : text(value.apiKeyEnv, `engine[${index}] apiKeyEnv`),
    extraParams: {},
  };
  if (!toolName.test(engine.name)) fail('WEB_CONFIG', 'Invalid search engine name');
  if (typeof engine.path !== 'string' || !engine.path.startsWith('/') || engine.path.startsWith('//') ||
      engine.path.includes('\\') || engine.path.includes('#') || engine.path.includes('?') ||
      new URL(engine.path, `${engine.origin}/`).origin !== engine.origin) {
    fail('WEB_CONFIG', 'Search engine path must be an absolute path on the configured origin');
  }
  if (engine.apiKeyEnv !== null && !envName.test(engine.apiKeyEnv)) fail('WEB_CONFIG', 'Invalid credential environment variable name');
  if (!Array.isArray(engine.resultsPath) || engine.resultsPath.length > 8 || engine.resultsPath.some((step) => typeof step !== 'string' || !step)) {
    fail('WEB_CONFIG', 'Search engine resultsPath must be a bounded array of field names');
  }
  if (engine.maxResults > MAX_RESULTS) fail('WEB_CONFIG', `Search engine maxResults cannot exceed ${MAX_RESULTS}`);
  if (value.extraParams !== undefined) {
    if (!value.extraParams || typeof value.extraParams !== 'object' || Array.isArray(value.extraParams)) fail('WEB_CONFIG', 'Search engine extraParams must be an object');
    for (const [name, entry] of Object.entries(value.extraParams)) {
      if (typeof entry !== 'string' || name === engine.queryParam) fail('WEB_CONFIG', 'Search engine extraParams must be strings and must not restate the query parameter');
      engine.extraParams[name] = entry;
    }
  }
  return engine;
}

function webSettings(value) {
  keys(value, ['fetchName', 'searchName', 'engines', 'timeoutMs', 'maxOutputBytes', 'maxRedirects'], 'web');
  if (value.maxRedirects !== undefined && (!Number.isSafeInteger(value.maxRedirects) || value.maxRedirects < 0 || value.maxRedirects > 10)) {
    fail('WEB_CONFIG', 'maxRedirects must be an integer between 0 and 10');
  }
  const config = {
    fetchName: value.fetchName ?? 'web.fetch',
    searchName: value.searchName ?? 'web.search',
    timeoutMs: positive(value.timeoutMs, DEFAULT_TIMEOUT, 'timeoutMs'),
    maxOutputBytes: positive(value.maxOutputBytes, DEFAULT_OUTPUT, 'maxOutputBytes'),
    maxRedirects: value.maxRedirects ?? DEFAULT_REDIRECTS,
    engines: [],
  };
  if (!toolName.test(config.fetchName) || !toolName.test(config.searchName)) fail('WEB_CONFIG', 'Invalid web tool name');
  if (config.fetchName === config.searchName) fail('WEB_CONFIG', 'Web tool names must be distinct');
  if (value.engines !== undefined) {
    if (!Array.isArray(value.engines) || value.engines.length === 0) fail('WEB_CONFIG', 'engines must be a nonempty array when present');
    if (value.engines.length > MAX_ENGINES) fail('WEB_CONFIG', `At most ${MAX_ENGINES} search engines may be configured`);
    config.engines = value.engines.map(engineSettings);
    const names = config.engines.map((engine) => engine.name);
    if (new Set(names).size !== names.length) fail('WEB_CONFIG', 'Search engine names must be distinct');
  }
  return config;
}

/** A configured credential must never come back out in a result, whoever put it there. */
function rejectSecret(value, secret) {
  if (!secret) return value;
  const seen = JSON.stringify(value);
  if (typeof seen === 'string' && seen.includes(secret)) fail('WEB_SECRET', 'Search engine output echoed a configured credential');
  return value;
}

function walk(value, path) {
  let current = value;
  for (const step of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current) || !Object.hasOwn(current, step)) return undefined;
    current = current[step];
  }
  return current;
}

async function askEngine(engine, query, limit, bound, context) {
  const url = new URL(engine.path, `${engine.origin}/`);
  url.searchParams.set(engine.queryParam, query);
  for (const [name, entry] of Object.entries(engine.extraParams)) url.searchParams.set(name, entry);
  allowOrigin(url, context, 'Search engine');
  let token = null;
  if (engine.apiKeyEnv) {
    token = process.env[engine.apiKeyEnv];
    if (!token || !/^[\x21-\x7e]+$/.test(token)) fail('WEB_CREDENTIAL', 'Search engine credential is unavailable or invalid');
  }
  const response = await httpGet(url, {
    timeoutMs: bound.timeoutMs, maxBytes: bound.maxOutputBytes, token, accept: 'application/json', signal: context?.signal,
  });
  if (response.status < 200 || response.status >= 300) fail('WEB_HTTP_STATUS', `Search engine answered HTTP ${response.status}`, { status: response.status });
  if (response.truncated) fail('WEB_OUTPUT_LIMIT', 'Search engine answer exceeded its share of the byte budget');
  let parsed;
  try { parsed = strictParseJson(new TextDecoder('utf-8', { fatal: true }).decode(response.body)); }
  catch { fail('WEB_ENGINE_SHAPE', 'Search engine answer was not strict UTF-8 JSON'); }
  rejectSecret(parsed, token);
  const rows = walk(parsed, engine.resultsPath);
  if (!Array.isArray(rows)) fail('WEB_ENGINE_SHAPE', 'Search engine answer had no result array at the declared path', { resultsPath: engine.resultsPath.join('.') });
  const results = [];
  for (const row of rows) {
    if (results.length >= Math.min(limit, engine.maxResults)) break;
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    const href = row[engine.urlKey];
    if (typeof href !== 'string' || !href) continue;
    let absolute;
    try { absolute = absoluteUrl(href); } catch { continue; }
    const title = row[engine.titleKey];
    const snippet = row[engine.snippetKey];
    results.push({
      url: absolute.toString(),
      title: typeof title === 'string' ? title.slice(0, 1024) : null,
      snippet: typeof snippet === 'string' ? snippet.slice(0, 4096) : null,
      rank: results.length + 1,
    });
  }
  return { answerSha256: sha256(response.body), results };
}

/**
 * Merge every engine's answer into one corroboration table.
 *
 * Exported and pure, so the ordering can be tested without a socket. The order is a total one —
 * agreement, then best rank, then the canonical URL — because a result list that depends on which
 * engine happened to answer first is not replayable, and engines racing is the normal case.
 */
export function mergeAnswers(answers, limit) {
  const byUrl = new Map();
  for (const { engine, results } of answers) {
    for (const result of results) {
      let key;
      try { key = canonicalUrl(result.url); } catch { key = result.url; }
      if (!byUrl.has(key)) byUrl.set(key, { canonicalUrl: key, entries: [] });
      byUrl.get(key).entries.push({ name: engine, rank: result.rank, url: result.url, title: result.title, snippet: result.snippet });
    }
  }
  const rows = [...byUrl.values()].map((row) => {
    // The best-ranked engine's own wording is the one kept, so a title and snippet always belong
    // to the engine that was most confident about the page rather than to whichever answered
    // last. Ties break on engine name, so the choice never depends on completion order.
    const best = row.entries.slice().sort((a, b) => a.rank - b.rank || (a.name < b.name ? -1 : 1))[0];
    return {
      url: best.url, canonicalUrl: row.canonicalUrl, title: best.title ?? null, snippet: best.snippet ?? null,
      engines: row.entries.map(({ name, rank, url }) => ({ name, rank, url })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
      agreement: new Set(row.entries.map((entry) => entry.name)).size,
      bestRank: best.rank,
    };
  });
  rows.sort((a, b) => b.agreement - a.agreement || a.bestRank - b.bestRank || (a.canonicalUrl < b.canonicalUrl ? -1 : a.canonicalUrl > b.canonicalUrl ? 1 : 0));
  return rows.slice(0, limit);
}

const fetchInputSchema = object({ url: { type: 'string', minLength: 1, maxLength: 8192 } });
const searchInputSchema = object({
  query: { type: 'string', minLength: 1, maxLength: 2048 },
  limit: { type: 'integer', minimum: 1, maximum: MAX_RESULTS },
}, ['query']);

/**
 * `web.fetch` and, when engines are configured, `web.search`.
 *
 * An absent configuration registers nothing: a capability that is missing is easier to reason
 * about than one that is present and always refuses. Search needs engines and so appears only
 * when at least one is configured — a harness with no engine cannot search, and saying so by
 * absence is more honest than a tool that exists to decline.
 */
export function makeWebTools(config) {
  if (config === undefined) return [];
  const settings = webSettings(config);

  const fetchTool = {
    name: settings.fetchName, version: '1', effect: 'network', inputSchema: fetchInputSchema, config: settings,
    outputKeys: ['url', 'finalUrl', 'ok', 'status', 'contentType', 'bytes', 'bodySha256', 'truncated', 'strategy', 'text', 'textTruncated', 'title', 'links', 'droppedScripts', 'droppedStyles', 'redirects', 'untrusted'],
    async execute(input, context) {
      validateSchema(input, fetchInputSchema);
      const bound = limits(settings, context, settings.fetchName);
      let url = absoluteUrl(input.url);
      allowOrigin(url, context, 'Requested');
      const redirects = [];
      let response;
      for (;;) {
        response = await httpGet(url, {
          timeoutMs: bound.timeoutMs, maxBytes: bound.maxOutputBytes, token: null,
          accept: 'text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.5', signal: context?.signal,
        });
        if (![301, 302, 303, 307, 308].includes(response.status)) break;
        if (redirects.length >= settings.maxRedirects) fail('WEB_REDIRECT', 'Too many redirects', { limit: settings.maxRedirects });
        const location = response.headers.location;
        if (typeof location !== 'string' || !location) fail('WEB_REDIRECT', 'Redirect carried no location');
        let next;
        try { next = new URL(location, url); } catch { fail('WEB_REDIRECT', 'Redirect location is not a usable URL'); }
        if (!['http:', 'https:'].includes(next.protocol)) fail('WEB_REDIRECT', 'Redirect left http(s)');
        if (next.username || next.password) fail('WEB_REDIRECT', 'Redirect location carried credentials');
        // The hop is checked against the same allowlist as the first request. A redirect is the
        // cheapest way to turn one permitted origin into a request to another, so permission is
        // asked again rather than inherited.
        allowOrigin(next, context, 'Redirect');
        redirects.push({ status: response.status, from: url.toString(), to: next.toString() });
        url = next;
      }
      const contentType = typeof response.headers['content-type'] === 'string' ? response.headers['content-type'] : null;
      const reduced = decodeBody(response.body, contentType, Math.min(MAX_TEXT_CHARS, bound.maxOutputBytes), url.toString());
      return {
        url: input.url, finalUrl: url.toString(),
        ok: response.status >= 200 && response.status < 300, status: response.status, contentType,
        bytes: response.body.length, bodySha256: sha256(response.body), truncated: response.truncated,
        strategy: reduced.strategy, text: reduced.text, textTruncated: reduced.textTruncated,
        title: reduced.title, links: reduced.links,
        droppedScripts: reduced.droppedScripts, droppedStyles: reduced.droppedStyles,
        redirects, untrusted: true,
      };
    },
  };

  const searchTool = settings.engines.length === 0 ? null : {
    name: settings.searchName, version: '1', effect: 'network', inputSchema: searchInputSchema, config: settings,
    outputKeys: ['query', 'queryHash', 'ranking', 'results', 'engines', 'asked', 'answered', 'agreementMax', 'uncorroborated', 'untrusted'],
    async execute(input, context) {
      validateSchema(input, searchInputSchema);
      const bound = limits(settings, context, settings.searchName);
      const limit = input.limit ?? 10;
      // Divided before any request, the way files.read and process.runMany divide theirs, so the
      // worst case of every engine answering at full length is structurally inside the budget
      // rather than rejected after the fact.
      const perEngine = {
        timeoutMs: bound.timeoutMs,
        maxOutputBytes: Math.max(1, Math.floor(bound.maxOutputBytes / settings.engines.length)),
      };
      const settled = await Promise.allSettled(settings.engines.map((engine) => askEngine(engine, input.query, limit, perEngine, context)));
      const engines = [];
      const answers = [];
      for (const [index, outcome] of settled.entries()) {
        const engine = settings.engines[index];
        if (outcome.status === 'fulfilled') {
          engines.push({ name: engine.name, ok: true, count: outcome.value.results.length, answerSha256: outcome.value.answerSha256, code: null });
          answers.push({ engine: engine.name, results: outcome.value.results });
        } else {
          const error = outcome.reason;
          engines.push({ name: engine.name, ok: false, count: 0, answerSha256: null, code: error instanceof HarnessError ? error.code : 'WEB_HTTP' });
        }
      }
      engines.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      // An engine that failed is data; every engine failing is a refusal. The difference matters:
      // two of three answering is a weaker answer, not a missing one, and silently returning an
      // empty result list for a total outage would read as "the web knows nothing about this".
      if (answers.length === 0) {
        fail('WEB_NO_ENGINE', 'No configured search engine answered', { codes: engines.map((entry) => entry.code).join(',') });
      }
      const results = mergeAnswers(answers, limit);
      return {
        query: input.query, queryHash: digest({ query: input.query, limit }), ranking: 'agreement-then-best-rank-v1',
        results, engines, asked: settings.engines.length, answered: answers.length,
        agreementMax: results.length ? Math.max(...results.map((row) => row.agreement)) : 0,
        // Not measurable from one source, so it is null rather than a zero that would read as
        // "nothing was uncorroborated". A caller comparing against 0 gets no false claim.
        uncorroborated: answers.length > 1 ? results.filter((row) => row.agreement === 1).length : null,
        untrusted: true,
      };
    },
  };

  const tools = searchTool ? [fetchTool, searchTool] : [fetchTool];
  for (const tool of tools) {
    Object.freeze(tool.config);
    Object.freeze(tool.inputSchema);
    Object.freeze(tool.outputKeys);
    Object.freeze(tool);
  }
  return tools;
}

/** Exported for direct unit testing of the parts that need no socket; not part of a tool contract. */
export const internals = { webSettings, limits, decodeBody, canonicalUrl, mergeAnswers, reduceHtml };
