import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { HarnessError, canonical, digest, parseJson } from './value.mjs';

/**
 * Sampling across sessions, which is the part the protocol leaves out.
 *
 * `createClientChannel` in peer.mjs already implements the real thing: `peer.ask` issues an actual
 * `sampling/createMessage` and the client's model answers it. Its limit is stated in its own
 * comment — "the only reachable party is the client already on the other end of this session".
 * MCP over stdio means one server process per client, so Claude's session and Codex's session are
 * two processes that share no memory, and nothing in the protocol introduces them. Two agents on
 * the same machine, each with a working sampling channel to its own client, and no path to each
 * other.
 *
 * The mailbox was that path. It works and it is honest, but it is a dead drop: a file is written
 * and nothing is woken, so a question waits until somebody thinks to look. The message that
 * prompted this module sat for twenty minutes.
 *
 * So: a broker. The first Concord session to start binds a local endpoint and becomes the hub;
 * every later session connects to it and registers what its own client declared at `initialize`.
 * An ask then crosses process boundaries — spoke to hub to the session that owns the named peer —
 * and that session issues a genuine `sampling/createMessage` to its own client. The answer is
 * produced by the target's real model through the real protocol primitive. Concord only carries it.
 *
 * What this deliberately does not do is replace the mailbox. The socket is a doorbell and the file
 * is the record: a brokered exchange is still written to the mailbox by the caller, because an
 * exchange that exists only as two closed sockets is not evidence and cannot be replayed. Latency
 * is the thing being fixed here, not accountability.
 *
 * Its reach is bounded by the same fact as the mailbox: the endpoint belongs to the workspace and
 * is reachable by whatever can read the workspace. This adds no party that could not already read
 * `runs/peer-mailbox`, and the token below guards against a stray process stumbling in rather than
 * claiming to withstand a hostile local user who already holds the directory.
 */

const fail = (code, message, details) => { throw new HarnessError(code, message, details); };
const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const HUB_DIRECTORY = 'peer-hub';
const TOKEN_FILE = 'token';
const SOCKET_FILE = 'sock';
const MAX_LINE_BYTES = 262_144;
const MAX_LINKS = 16;
const CONNECT_TIMEOUT_MS = 2_000;
const DEFAULT_ASK_TIMEOUT_MS = 120_000;

/**
 * Where the endpoint lives.
 *
 * A Windows named pipe is not a filesystem path and cannot sit in the workspace, so its name
 * carries a digest of the workspace root instead: two checkouts of Concord on one machine must not
 * find each other, and a pipe called `concord-peer` alone would introduce them. On every other
 * platform the socket is a real file inside the run directory, which gives the same isolation by
 * construction.
 */
export function hubAddress(root) {
  const stamp = digest(path.resolve(root)).slice(0, 16);
  if (process.platform === 'win32') return { kind: 'pipe', address: `\\\\.\\pipe\\concord-peer-${stamp}`, stamp };
  return { kind: 'socket', address: path.join(root, 'runs', HUB_DIRECTORY, SOCKET_FILE), stamp };
}

const hubDirectory = (root) => path.join(root, 'runs', HUB_DIRECTORY);

/**
 * Frame newline-delimited canonical JSON, refusing a line rather than growing without bound.
 *
 * The cap is not politeness. A peer that never sends a newline would otherwise buffer until the
 * process dies, which is a denial of service reachable by anyone who can open the endpoint.
 */
function createLineReader(onLine, onOverflow) {
  let buffer = '';
  return (chunk) => {
    buffer += chunk;
    if (Buffer.byteLength(buffer) > MAX_LINE_BYTES) { buffer = ''; onOverflow?.(); return; }
    let index = buffer.indexOf('\n');
    while (index !== -1) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (line.trim()) onLine(line);
      index = buffer.indexOf('\n');
    }
  };
}

const writeLine = (socket, value) => {
  let line;
  try { line = canonical(value); }
  catch { fail('PEER_HUB_FRAME', 'A hub message is not representable as JSON'); }
  socket.write(line + '\n');
};

/** The token a spoke must present. Written by the hub, read by everyone else. */
function readToken(root) {
  try { return fs.readFileSync(path.join(hubDirectory(root), TOKEN_FILE), 'utf8').trim() || null; }
  catch { return null; }
}

function writeToken(root) {
  const directory = hubDirectory(root);
  fs.mkdirSync(directory, { recursive: true });
  const token = digest(`${Date.now()}:${process.pid}:${Math.random()}`);
  // 0o600 is advisory on Windows and real elsewhere. Written then renamed so a spoke never reads a
  // half-written token and fails a comparison it should have passed.
  const temporary = path.join(directory, `${TOKEN_FILE}.${process.pid}`);
  fs.writeFileSync(temporary, token + '\n', { mode: 0o600 });
  fs.renameSync(temporary, path.join(directory, TOKEN_FILE));
  return token;
}

/**
 * Comparison for the token that does not short-circuit on the first differing character.
 *
 * Both values are local hex strings of known length, so this is belt and braces rather than a
 * defence against remote timing. A plain `===` on a secret is the kind of thing that turns out to
 * be wrong later, when the context around it has changed.
 */
function tokenMatches(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

/**
 * One identity on the bus.
 *
 * `peerId` is what a caller names in `to`. It is derived from the client's own reported name so
 * that `to: "codex"` means what a person would expect, with a suffix added only when two sessions
 * of the same client are connected — an ambiguous name is worse than an ugly one.
 */
export function peerIdFor(name, taken = new Set()) {
  const base = (typeof name === 'string' && name.trim() ? name.trim() : 'unknown')
    .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32) || 'unknown';
  if (!taken.has(base)) return base;
  for (let i = 2; i < 100; i++) if (!taken.has(`${base}-${i}`)) return `${base}-${i}`;
  return `${base}-${process.pid}`;
}

/**
 * The hub: a registry of links and a router between them.
 *
 * A link is a connected session. The process that binds is itself a session, so it registers a
 * link too — one whose `deliver` is a direct call rather than a socket write. Keeping that case
 * inside the same registry is deliberate: a router with a special path for "me" grows a second set
 * of rules that only one participant exercises, and that path is the one that breaks.
 */
function createHub({ token, server }) {
  const links = new Map(); // peerId -> link
  const inflight = new Map(); // hub-side ask id -> { fromPeerId, toPeerId, replyTo }
  let counter = 0;

  const peerList = () => [...links.values()].map((link) => ({
    peerId: link.peerId, client: link.identity.name, version: link.identity.version ?? null,
    capabilities: [...link.identity.capabilities], local: link.local === true, pid: link.identity.pid ?? null,
  }));

  const broadcast = () => {
    const peers = peerList();
    for (const link of links.values()) {
      try { link.deliver({ kind: 'peers', peers }); }
      catch { /* a dead link is removed by its own close handler */ }
    }
  };

  function register(identity, deliver, { local = false } = {}) {
    if (links.size >= MAX_LINKS) fail('PEER_HUB_FULL', 'The hub already holds as many sessions as it routes');
    const peerId = peerIdFor(identity.name, new Set(links.keys()));
    const link = { peerId, identity, deliver, local };
    links.set(peerId, link);
    broadcast();
    return link;
  }

  function unregister(peerId) {
    if (!links.delete(peerId)) return;
    // Every question this peer was answering now has no answerer. Failing them here is the point:
    // an asker blocked on a session that has gone away would otherwise wait out its whole deadline
    // for a reply that cannot arrive.
    for (const [askId, entry] of [...inflight]) {
      if (entry.toPeerId !== peerId) continue;
      inflight.delete(askId);
      const asker = links.get(entry.fromPeerId);
      asker?.deliver({ kind: 'answer', id: entry.replyTo, error: { code: 'PEER_HUB_GONE', message: `The session for "${peerId}" closed before it answered` } });
    }
    broadcast();
  }

  /** Route an ask to the session that owns the target, or refuse by name. */
  function route(fromLink, message) {
    const reply = (payload) => fromLink.deliver({ kind: 'answer', id: message.id, ...payload });
    const target = links.get(message.to);
    if (!target) {
      reply({ error: { code: 'PEER_HUB_UNKNOWN', message: `No connected session is named "${message.to}"`, details: { peers: peerList().map((peer) => peer.peerId) } } });
      return;
    }
    if (target.peerId === fromLink.peerId) {
      reply({ error: { code: 'PEER_HUB_SELF', message: 'A session cannot ask itself through the hub' } });
      return;
    }
    const askId = `hub-${counter += 1}`;
    inflight.set(askId, { fromPeerId: fromLink.peerId, toPeerId: target.peerId, replyTo: message.id });
    try {
      target.deliver({ kind: 'serve', id: askId, from: fromLink.peerId, fromClient: fromLink.identity.name,
        question: message.question, maxTokens: message.maxTokens ?? null, systemPrompt: message.systemPrompt ?? null });
    } catch {
      inflight.delete(askId);
      reply({ error: { code: 'PEER_HUB_TRANSPORT', message: `The session for "${target.peerId}" could not be written` } });
    }
  }

  /** A served answer on its way back to whoever asked. */
  function complete(message) {
    const entry = inflight.get(message.id);
    if (!entry) return; // a late answer to an ask that already failed; dropping it is correct
    inflight.delete(message.id);
    const asker = links.get(entry.fromPeerId);
    asker?.deliver({ kind: 'answer', id: entry.replyTo, ...(message.error ? { error: message.error } : { result: message.result }) });
  }

  server?.on('connection', (socket) => {
    socket.setNoDelay?.(true);
    let link = null;
    const deliver = (value) => writeLine(socket, value);
    const feed = createLineReader((line) => {
      let message;
      try { message = parseJson(line); }
      catch { socket.destroy(); return; }
      if (!isObject(message)) { socket.destroy(); return; }

      // Nothing is routed before a valid hello. A peer that could ask before authenticating would
      // make the token decorative.
      if (!link) {
        if (message.kind !== 'hello' || !tokenMatches(message.token, token) || !isObject(message.identity)) {
          try { deliver({ kind: 'denied', reason: 'A hello carrying the current hub token is required first' }); } catch { /* closing anyway */ }
          socket.destroy();
          return;
        }
        try {
          link = register({
            name: typeof message.identity.name === 'string' ? message.identity.name : null,
            version: typeof message.identity.version === 'string' ? message.identity.version : null,
            capabilities: Array.isArray(message.identity.capabilities) ? message.identity.capabilities.filter((entry) => typeof entry === 'string').sort() : [],
            pid: Number.isInteger(message.identity.pid) ? message.identity.pid : null,
          }, deliver);
        } catch (error) {
          try { deliver({ kind: 'denied', reason: error?.message ?? 'The hub refused the session' }); } catch { /* closing anyway */ }
          socket.destroy();
          return;
        }
        deliver({ kind: 'welcome', peerId: link.peerId, peers: peerList() });
        return;
      }

      if (message.kind === 'ask') route(link, message);
      else if (message.kind === 'served') complete(message);
    }, () => socket.destroy());

    socket.on('data', (chunk) => feed(chunk.toString('utf8')));
    socket.on('error', () => socket.destroy());
    socket.on('close', () => { if (link) unregister(link.peerId); });
  });

  return { register, unregister, route, complete, peerList, links };
}

/**
 * Bind the endpoint, or find the session that already did.
 *
 * Returns a membership either way, and a caller does not branch on which happened beyond reporting
 * it. A hub that dies is not a catastrophe: the next ask fails by name, a later session binds, and
 * nothing already written to the mailbox is lost.
 */
export async function joinHub({ root, identity, onServe, timeoutMs = DEFAULT_ASK_TIMEOUT_MS } = {}) {
  if (typeof root !== 'string' || !root) fail('PEER_HUB', 'A hub needs a workspace root');
  const { address, kind } = hubAddress(root);
  const asks = new Map();
  let counter = 0;
  let peers = [];
  let selfId = null;

  const settleAll = (error) => {
    for (const [, entry] of [...asks]) { clearTimeout(entry.timer); entry.reject(error); }
    asks.clear();
  };

  /** Shared by both roles: turn a hub-side answer into the resolution of a local promise. */
  const onAnswer = (message) => {
    const entry = asks.get(message.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    asks.delete(message.id);
    if (message.error) entry.reject(new HarnessError(message.error.code ?? 'PEER_HUB_FAILED', message.error.message ?? 'The peer did not answer', message.error.details));
    else entry.resolve(message.result);
  };

  /** One outbound ask, resolved when the hub returns an answer or refuses it. */
  const sendAsk = (to, question, options = {}, dispatch) => {
    const id = `ask-${counter += 1}`;
    const deadline = Math.min(options.timeoutMs ?? timeoutMs, timeoutMs);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        asks.delete(id);
        reject(new HarnessError('PEER_HUB_TIMEOUT', 'The peer did not answer within the deadline', { to }));
      }, deadline);
      timer.unref?.();
      asks.set(id, { resolve, reject, timer });
      const abandon = (error) => {
        const entry = asks.get(id);
        if (!entry) return;
        clearTimeout(entry.timer);
        asks.delete(id);
        reject(error);
      };
      if (options.signal) {
        if (options.signal.aborted) { abandon(new HarnessError('PEER_ABORTED', 'The brokered question was cancelled')); return; }
        options.signal.addEventListener('abort', () => abandon(new HarnessError('PEER_ABORTED', 'The brokered question was cancelled')), { once: true });
      }
      try { dispatch({ kind: 'ask', id, to, question, maxTokens: options.maxTokens ?? null, systemPrompt: options.systemPrompt ?? null }); }
      catch { abandon(new HarnessError('PEER_HUB_TRANSPORT', 'The hub could not be written')); }
    });
  };

  /**
   * Answer a brokered question with this session's own client, or say why it cannot.
   *
   * The details of a failure travel with it. An error rebuilt from code and message alone loses
   * exactly the part a caller can act on — PEER_HUB_UNANSWERED carries the sequence number of the
   * letter it left in the mailbox, and without it the caller is told something went wrong and not
   * where to go and look. Only representable details are forwarded, because an unserialisable one
   * would turn a failed answer into a failed transport.
   */
  const serve = (message, done) => {
    const describe = (error) => {
      const payload = { code: error?.code ?? 'PEER_HUB_UNSERVED', message: error?.message ?? 'The session could not answer' };
      if (error?.details === undefined || error?.details === null) return payload;
      try { canonical(error.details); return { ...payload, details: error.details }; }
      catch { return payload; }
    };
    Promise.resolve()
      .then(() => (onServe ? onServe(message) : Promise.reject(new HarnessError('PEER_HUB_UNSERVED', 'This session cannot answer a brokered question'))))
      .then((result) => done({ result }))
      .catch((error) => done({ error: describe(error) }));
  };

  // --- try to become the hub ------------------------------------------------------------------
  const bind = () => new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref?.();
    server.once('error', reject);
    server.listen(address, () => { server.removeListener('error', reject); resolve(server); });
  });

  let server = null;
  try {
    if (kind === 'socket') fs.mkdirSync(hubDirectory(root), { recursive: true });
    server = await bind();
  } catch (error) {
    // EADDRINUSE means either a live hub or, on a unix socket, a file left behind by a process that
    // died. Telling those apart requires trying to connect, which is what the spoke path does next.
    if (error?.code !== 'EADDRINUSE') throw new HarnessError('PEER_HUB_BIND', 'The hub endpoint could not be bound', { code: error?.code ?? null });
  }

  if (server) {
    const token = writeToken(root);
    const hub = createHub({ token, server });
    const local = hub.register({ ...identity, pid: process.pid }, (message) => {
      // The hub process talking to itself, through the same message shapes as the socket path, so
      // the local session is not a privileged participant with semantics of its own.
      if (message.kind === 'answer') onAnswer(message);
      else if (message.kind === 'serve') serve(message, (payload) => hub.complete({ id: message.id, ...payload }));
      else if (message.kind === 'peers') peers = message.peers ?? [];
    }, { local: true });
    selfId = local.peerId;

    return {
      role: 'hub', peerId: selfId, address,
      peers: () => hub.peerList(),
      ask: (to, question, options) => sendAsk(to, question, options, (value) => hub.route(local, value)),
      close: () => {
        settleAll(new HarnessError('PEER_HUB_CLOSED', 'The hub was closed'));
        try { server.close(); } catch { /* already closing */ }
        try { if (kind === 'socket') fs.rmSync(address, { force: true }); } catch { /* best effort */ }
      },
    };
  }

  // --- otherwise be a spoke -------------------------------------------------------------------
  const token = readToken(root);
  if (!token) fail('PEER_HUB_NO_TOKEN', 'A hub is listening but its token could not be read from the workspace');

  const socket = await new Promise((resolve, reject) => {
    const attempt = net.connect(address);
    attempt.unref?.();
    const timer = setTimeout(() => { attempt.destroy(); reject(new HarnessError('PEER_HUB_TIMEOUT', 'The hub did not accept a connection')); }, CONNECT_TIMEOUT_MS);
    timer.unref?.();
    attempt.once('connect', () => { clearTimeout(timer); attempt.removeListener('error', reject); resolve(attempt); });
    attempt.once('error', (error) => {
      clearTimeout(timer);
      // A socket file whose owner is gone refuses rather than reporting itself in use. Removing it
      // lets the next caller bind, which is the only way a crashed hub is ever replaced.
      if (kind === 'socket' && (error?.code === 'ECONNREFUSED' || error?.code === 'ENOENT')) {
        try { fs.rmSync(address, { force: true }); } catch { /* best effort */ }
      }
      reject(new HarnessError('PEER_HUB_UNREACHABLE', 'The hub endpoint exists but refused a connection', { code: error?.code ?? null }));
    });
  });

  socket.setNoDelay?.(true);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new HarnessError('PEER_HUB_TIMEOUT', 'The hub accepted a connection but sent no welcome')), CONNECT_TIMEOUT_MS);
    timer.unref?.();
    const feed = createLineReader((line) => {
      let message;
      try { message = parseJson(line); } catch { return; }
      if (!isObject(message)) return;
      if (message.kind === 'welcome') { clearTimeout(timer); selfId = message.peerId; peers = message.peers ?? []; resolve(); }
      else if (message.kind === 'denied') { clearTimeout(timer); reject(new HarnessError('PEER_HUB_DENIED', message.reason ?? 'The hub refused this session')); }
      else if (message.kind === 'peers') peers = message.peers ?? [];
      else if (message.kind === 'answer') onAnswer(message);
      else if (message.kind === 'serve') serve(message, (payload) => writeLine(socket, { kind: 'served', id: message.id, ...payload }));
    }, () => socket.destroy());
    socket.on('data', (chunk) => feed(chunk.toString('utf8')));
    socket.on('error', () => { clearTimeout(timer); reject(new HarnessError('PEER_HUB_TRANSPORT', 'The hub connection failed')); });
    socket.on('close', () => settleAll(new HarnessError('PEER_HUB_CLOSED', 'The hub connection closed')));
    writeLine(socket, { kind: 'hello', token, identity: { ...identity, pid: process.pid } });
  });

  return {
    role: 'spoke', peerId: selfId, address,
    peers: () => peers.map((peer) => ({ ...peer })),
    ask: (to, question, options) => sendAsk(to, question, options, (value) => writeLine(socket, value)),
    close: () => {
      settleAll(new HarnessError('PEER_HUB_CLOSED', 'The hub connection closed'));
      try { socket.destroy(); } catch { /* already gone */ }
    },
  };
}
