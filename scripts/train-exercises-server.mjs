import http from 'node:http';
import { createServer, listenServer } from '../src/server.mjs';

/**
 * The desktop server, refused over a real socket.
 *
 * Nine codes here, and every one of them had sat unproven for the same structural reason: this
 * server does not throw its refusals, it answers them. A rejected request becomes a status and a
 * code in a JSON body, which is the only shape a browser could act on - and a round that could
 * only observe exceptions was blind to all of it while the scanner counted each one as declared.
 * So these exercises make the request and read the answer, and the runner now keeps the codes a
 * result carried as well as the ones a call threw.
 *
 * One code here resisted proof, and the reason is the better finding: INVALID_REQUEST fires
 * exactly when there is nobody left to tell. It is raised when a request body ends before the
 * length it declared - but a client that half-closes produces a parse error at EOF, which Node's
 * own connection listener answers with a canned bodiless `400 Bad Request` before the handler's
 * `aborted` listener runs, and a client that destroys the socket is gone before a response could
 * be written at all. The guard is real and it does its job, which is to drop the buffered chunks
 * rather than parse a truncated action; its only reader is the request's own teardown.
 *
 * Every exercise brings up its own server on an ephemeral port and takes it down again, because
 * the runner invokes each call twice and demands identical results: a port cannot appear in what
 * is returned, which is why each projection is exactly `{status, code}`.
 *
 * The harness here is a stub, and deliberately so. The server's contract with it is five method
 * names and a snapshot, which it checks at construction; none of these refusals ever reaches the
 * harness at all, because every one of them fires in front of it. A real chat harness would add a
 * model, a registry and a workspace to prove nothing further. The one case that does lean on the
 * stub is STATE_LIMIT, where the point is a snapshot too large to send - and a stub is the only
 * way to ask for four megabytes of state on purpose.
 */

/** Five method names and a snapshot: the whole of what the server requires of a harness. */
const stubHarness = (snapshot = { mode: 'ready', history: [] }) => ({
  snapshot: async () => snapshot,
  send: async () => snapshot,
  approve: async () => snapshot,
  executePlan: async () => snapshot,
  replay: async () => ({ replayed: true, root: 'a'.repeat(64), events: [] }),
});

/** One server, up for one request and then down, whatever the request did. */
async function onServer(harness, act) {
  const server = createServer({ harness });
  const base = await listenServer(server);
  const port = Number(new URL(base).port);
  try {
    return await act({ port, base });
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
}

/**
 * One request, and the two things about the answer that are the same on every port.
 *
 * `agent: false` so each exercise opens its own connection rather than inheriting a pooled one:
 * a refusal sets `Connection: close`, and a reused socket would carry the previous request's
 * teardown into the next exercise.
 */
const ask = ({ port, method = 'GET', path, headers = {}, body = null }) => new Promise((resolve, reject) => {
  const request = http.request({ host: '127.0.0.1', port, method, path, headers, agent: false }, (response) => {
    const chunks = [];
    response.on('data', (chunk) => chunks.push(chunk));
    response.on('end', () => {
      let parsed = null;
      try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { parsed = null; }
      resolve({ status: response.statusCode, code: parsed?.error?.code ?? null, body: parsed });
    });
    response.on('error', reject);
  });
  request.on('error', reject);
  if (body !== null) request.write(body);
  request.end();
});

/** The token the app is handed with its state, and must present on every action. */
const tokenFrom = async (port) => (await ask({ port, path: '/api/state' })).body?.token;

const refusal = ({ status, code }) => ({ status, code });

const postTo = async ({ port, base, path, body, contentType = 'application/json', extra = {} }) => {
  const token = await tokenFrom(port);
  return ask({
    port, method: 'POST', path, body,
    headers: {
      'content-type': contentType, origin: base, 'x-concord-token': token,
      'content-length': Buffer.byteLength(body), ...extra,
    },
  });
};

export function serverExercises() {
  return [
    {
      family: 'server', tool: 'server.createServer', expectThrow: 'SERVER_CONFIG',
      call: () => createServer({ harness: { snapshot: async () => ({}) } }),
      lesson: 'A server built on an incomplete harness is refused SERVER_CONFIG at construction, before a port exists. The check is for all five method names rather than for one: a server that bound a port and then discovered at request time that it could not approve anything would have published an interface it cannot honour, and the operator would learn which part was missing from a failed click. The same code covers a non-loopback host, because a chat server reachable from the network is a different program.',
    },
    {
      family: 'server', tool: 'server.request', workspace: 'temp',
      call: () => onServer(stubHarness(), ({ port }) => ask({ port, path: '/api/state', headers: { host: 'evil.example' } }).then(refusal)),
      expect: (r) => r.status === 403 && r.code === 'FORBIDDEN',
      lesson: 'A request whose Host header is not the exact address this server bound is answered 403 FORBIDDEN, before any route is considered. This is the defence against DNS rebinding: a page on another origin can resolve a name it controls to 127.0.0.1 and reach a local server, and the one thing it cannot forge is the Host header the browser will send. A duplicated Host header is refused by the same check, counted from the raw header list rather than the parsed object, because a parser that joins duplicates would hand a forged value past a comparison on the first.',
    },
    {
      family: 'server', tool: 'server.request', workspace: 'temp',
      call: () => onServer(
        // Four megabytes is the response bound, so five of history is a state that cannot be sent.
        stubHarness({ mode: 'ready', history: [{ role: 'user', content: 'x'.repeat(5_000_000) }] }),
        ({ port }) => ask({ port, path: '/api/state' }).then(refusal),
      ),
      expect: (r) => r.status === 503 && r.code === 'STATE_LIMIT',
      lesson: 'A chat state larger than the four-megabyte response bound is answered 503 STATE_LIMIT rather than streamed. The bound is on the serialised answer and is checked before a single header is written, so the failure is a complete reply the app can render instead of a truncated body it would have to parse to discover was incomplete. 503 rather than 500 on purpose: the state is too large right now, and a shorter history is a state the same server will serve.',
    },
    {
      family: 'server', tool: 'server.request', workspace: 'temp',
      call: () => onServer(stubHarness(), ({ port, base }) => postTo({
        port, base, path: '/api/chat', body: '{"message":"hello"}', contentType: 'text/plain',
      }).then(refusal)),
      expect: (r) => r.status === 415 && r.code === 'CONTENT_TYPE',
      lesson: 'An action posted as anything but application/json is answered 415 CONTENT_TYPE before its body is read. The accepted set is exactly application/json with an optional utf-8 charset, which is narrow on purpose: text/plain and the form content types are the ones an HTML form can send without JavaScript, so refusing them means a cross-origin form submission cannot reach an action even if every other check were somehow satisfied.',
    },
    {
      family: 'server', tool: 'server.request', workspace: 'temp',
      call: () => onServer(stubHarness(), ({ port, base }) => postTo({
        port, base, path: '/api/chat', body: `{"message":"${'x'.repeat(70_000)}"}`,
      }).then(refusal)),
      expect: (r) => r.status === 413 && r.code === 'BODY_LIMIT',
      lesson: 'A body over 64 KiB is answered 413 BODY_LIMIT from the declared Content-Length, before any of it is buffered, and the same bound is enforced again while the bytes arrive in case the header lied. Two checks for one rule because they fail at different costs: the header check refuses for free, and the counting check is what makes a chunked or mis-declared request cost the same.',
    },
    {
      family: 'server', tool: 'server.request', workspace: 'temp',
      call: () => onServer(stubHarness(), ({ port }) => ask({ port, path: '/api/chat' }).then(refusal)),
      expect: (r) => r.status === 405 && r.code === 'METHOD',
      lesson: 'A route that exists but was asked with the wrong method is answered 405 METHOD, and the check runs before the token is examined. The ordering is deliberate: a GET can be provoked by a link or an image tag and can never carry the token, so answering "wrong method" rather than "forbidden" tells the truth about which rule was broken and reveals nothing - the token check that follows is the one that must stay silent about why it failed.',
    },
    {
      family: 'server', tool: 'server.request', workspace: 'temp',
      call: () => onServer(stubHarness(), ({ port }) => ask({ port, path: '/api/not-a-route' }).then(refusal)),
      expect: (r) => r.status === 404 && r.code === 'NOT_FOUND',
      lesson: 'An unknown path is answered 404 NOT_FOUND after the host and origin checks have already passed. The route table and the asset table are both closed sets - four actions, two reads, three files - so there is no path that falls through to the filesystem and nothing to traverse towards. A server whose 404 is produced by a failed file lookup is a server where the lookup was the security boundary.',
    },
    {
      family: 'server', tool: 'server.request', workspace: 'temp',
      call: () => onServer(stubHarness(), ({ port, base }) => postTo({
        port, base, path: '/api/chat', body: '{"message":"   "}',
      }).then(refusal)),
      expect: (r) => r.status === 400 && r.code === 'INVALID_INPUT',
      lesson: 'A message of nothing but whitespace is answered 400 INVALID_INPUT even though it satisfies the schema, which requires one character and got three. Schema validity and meaning are separate questions: the same code also covers an approval hash that is the right length but not hexadecimal, and a plan field that is not an object. Refusing here rather than passing it on keeps an empty turn out of the history, where it would be a model prompt with nothing in it and a run record proving it.',
    },
  ];
}
