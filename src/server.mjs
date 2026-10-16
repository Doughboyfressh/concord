import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { canonical, parseJson, validateSchema, HarnessError } from './value.mjs';

const settings = new WeakMap();
const maxBodyBytes = 65_536;
const maxResponseBytes = 4_194_304;
const assets = new Map([
  ['/', { file: new URL('../app/index.html', import.meta.url), type: 'text/html; charset=utf-8' }],
  ['/style.css', { file: new URL('../app/style.css', import.meta.url), type: 'text/css; charset=utf-8' }],
  ['/client.mjs', { file: new URL('../app/client.mjs', import.meta.url), type: 'text/javascript; charset=utf-8' }],
]);
const objectSchema = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const routes = new Map([
  ['/api/chat', { method: 'send', schema: objectSchema({ message: { type: 'string', minLength: 1, maxLength: 32768 } }, ['message']) }],
  ['/api/approve', { method: 'approve', schema: objectSchema({ requestHash: { type: 'string', minLength: 64, maxLength: 64 } }, ['requestHash']) }],
  ['/api/execute', { method: 'executePlan', schema: objectSchema({ plan: { type: 'object' } }) }],
  ['/api/replay', { method: 'replay', schema: objectSchema({ runId: { type: 'string', minLength: 1, maxLength: 128 } }, ['runId']) }],
]);
const securityHeaders = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};
class HttpError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
const deny = () => { throw new HttpError(403, 'FORBIDDEN', 'This request is not allowed.'); };
const loopback = address => address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
const headerCount = (request, name) => request.rawHeaders.filter((_, index) => index % 2 === 0 && request.rawHeaders[index].toLowerCase() === name).length;

function safeStatus(status = {}) {
  validateSchema(status, objectSchema({
    sourceCount: { type: 'integer', minimum: 0 }, files: { type: 'integer', minimum: 0 },
    capabilities: { type: 'integer', minimum: 0 }, skillFiles: { type: 'integer', minimum: 0 },
    tools: { type: 'array', items: { type: 'string' }, maxItems: 10000 },
  }));
  return parseJson(canonical(status));
}

function publicState(snapshot) {
  // The chat harness owns message/context sanitation. Do not expose its private
  // properties, provider configuration, credentials, or complete run journals.
  const result = {};
  for (const key of ['mode', 'history', 'selected', 'sourceCoverage', 'pending', 'proposedPlan', 'runs']) {
    if (snapshot && Object.hasOwn(snapshot, key)) result[key] = snapshot[key];
  }
  return parseJson(canonical(result));
}

function json(response, status, body) {
  const content = canonical(body);
  if (Buffer.byteLength(content) > maxResponseBytes) throw new HttpError(503, 'STATE_LIMIT', 'The chat state exceeds the response limit.');
  response.writeHead(status, { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(content) });
  response.end(content);
}

function readJson(request) {
  const contentType = request.headers['content-type'];
  if (typeof contentType !== 'string' || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)) throw new HttpError(415, 'CONTENT_TYPE', 'Send application/json.');
  const length = request.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)) || Number(length) > maxBodyBytes)) throw new HttpError(413, 'BODY_LIMIT', 'The request body is too large.');
  return new Promise((resolve, reject) => {
    let bytes = 0, chunks = [], finished = false;
    const cleanup = () => {
      request.removeListener('data', data); request.removeListener('end', end);
      request.removeListener('aborted', aborted); request.removeListener('error', aborted);
    };
    const fail = error => { if (finished) return; finished = true; cleanup(); chunks = []; request.resume(); reject(error); };
    const data = chunk => {
      bytes += chunk.length;
      if (bytes > maxBodyBytes) return fail(new HttpError(413, 'BODY_LIMIT', 'The request body is too large.'));
      chunks.push(chunk);
    };
    const aborted = () => fail(new HttpError(400, 'INVALID_REQUEST', 'The request body could not be read.'));
    const end = () => {
      if (finished) return;
      finished = true; cleanup();
      try { resolve(parseJson(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
      catch { reject(new HttpError(400, 'INVALID_JSON', 'The request must contain strict JSON.')); }
    };
    request.on('data', data); request.once('end', end); request.once('aborted', aborted); request.once('error', aborted);
  });
}

/** Create an unlistened local chat server. Use listenServer to bind its configured loopback address. */
export function createServer({ harness, status = {}, host = '127.0.0.1', port = 8787 } = {}) {
  if (!['127.0.0.1', '::1'].includes(host) || !Number.isSafeInteger(port) || port < 0 || port > 65535) throw new HarnessError('SERVER_CONFIG', 'The chat server requires a loopback IP and valid port');
  if (!harness || ['snapshot', 'send', 'approve', 'executePlan', 'replay'].some(name => typeof harness[name] !== 'function')) throw new HarnessError('SERVER_CONFIG', 'A complete chat harness is required');
  const publicStatus = safeStatus(status);
  const token = randomBytes(32).toString('base64url');
  const tokenBytes = Buffer.from(token);
  const server = http.createServer({ maxHeaderSize: 16384 }, async (request, response) => {
    try {
      const address = server.address();
      if (!address || typeof address === 'string' || !loopback(address.address) || !loopback(request.socket.remoteAddress)) deny();
      const hostname = host === '::1' ? '[::1]' : host;
      const expectedHost = hostname + (address.port === 80 ? '' : ':' + address.port);
      const origin = 'http://' + expectedHost;
      if (headerCount(request, 'host') !== 1 || request.headers.host !== expectedHost) deny();
      if (request.headers.origin !== undefined && request.headers.origin !== origin) deny();
      if (request.url?.startsWith('/api/') && ['cross-site', 'same-site'].includes(request.headers['sec-fetch-site'])) deny();
      if (request.url === '/api/state') {
        if (request.method !== 'GET') throw new HttpError(405, 'METHOD', 'Use GET for chat state.');
        return json(response, 200, { state: publicState(await harness.snapshot()), status: publicStatus, token });
      }
      const asset = assets.get(request.url);
      if (asset) {
        if (!['GET', 'HEAD'].includes(request.method)) throw new HttpError(405, 'METHOD', 'Use GET or HEAD for app assets.');
        const content = await readFile(asset.file);
        response.writeHead(200, { ...securityHeaders, 'Content-Type': asset.type, 'Content-Length': content.length });
        return response.end(request.method === 'HEAD' ? undefined : content);
      }
      const route = routes.get(request.url);
      if (!route) throw new HttpError(404, 'NOT_FOUND', 'This resource is not available.');
      if (request.method !== 'POST') throw new HttpError(405, 'METHOD', 'Use POST for chat actions.');
      if (request.headers.origin !== origin || headerCount(request, 'x-concord-token') !== 1) deny();
      const suppliedToken = request.headers['x-concord-token'];
      if (typeof suppliedToken !== 'string' || Buffer.byteLength(suppliedToken) !== tokenBytes.length || !timingSafeEqual(Buffer.from(suppliedToken), tokenBytes)) deny();
      const input = await readJson(request);
      try { validateSchema(input, route.schema); }
      catch { throw new HttpError(400, 'INVALID_INPUT', 'The action fields are invalid.'); }
      if (route.method === 'approve' && !/^[a-f0-9]{64}$/.test(input.requestHash)) throw new HttpError(400, 'INVALID_INPUT', 'The approval identity is invalid.');
      if (route.method === 'send' && !input.message.trim()) throw new HttpError(400, 'INVALID_INPUT', 'Enter a message.');
      if (route.method === 'replay') {
        const replay = await harness.replay(input.runId);
        const summary = { runId: input.runId, verified: replay?.replayed === true };
        if (typeof replay?.root === 'string') summary.root = replay.root;
        if (Array.isArray(replay?.events)) summary.eventCount = replay.events.length;
        return json(response, 200, { state: publicState(await harness.snapshot()), replay: summary });
      }
      const argument = route.method === 'send' ? input.message : route.method === 'approve' ? input.requestHash : input.plan;
      return json(response, 200, { state: publicState(await harness[route.method](argument)) });
    } catch (error) {
      if (response.headersSent || response.destroyed) { response.destroy(); return; }
      request.resume();
      response.setHeader('Connection', 'close');
      const known = error instanceof HttpError;
      // Never forward exception messages, stack traces, URLs, provider replies,
      // request headers, or credentials from a backend or adapter.
      try { json(response, known ? error.status : 500, { error: { code: known ? error.code : 'REQUEST_FAILED', message: known ? error.message : 'The action could not be completed. Review the chat state and try again.' } }); }
      catch { response.writeHead(500, securityHeaders); response.end(); }
    }
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  server.keepAliveTimeout = 5000;
  server.maxRequestsPerSocket = 100;
  settings.set(server, { host, port });
  return server;
}

/** Listen on the factory's configured loopback address; port 0 selects an ephemeral test port. */
export async function listenServer(server) {
  const configuration = settings.get(server);
  if (!configuration) throw new HarnessError('SERVER_CONFIG', 'Use a Concord server instance');
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(configuration.port, configuration.host, () => { server.removeListener('error', reject); resolve(); });
  });
  const address = server.address();
  return 'http://' + (configuration.host === '::1' ? '[::1]' : configuration.host) + ':' + address.port;
}
