import fs from 'node:fs';
import path from 'node:path';
import { HarnessError, canonical, digest, parseJson } from './value.mjs';

/**
 * The other direction of the MCP session.
 *
 * A client connects to Concord and calls its tools. That is one direction, and until now it was
 * the only one: `src/mcp.mjs` read a line, answered it, and had no way to say anything first.
 * MCP itself is symmetric — a server may send requests to its client — and this is that half:
 * Concord asking the agent on the other end a question, or telling it something, over the same
 * stdio session the client already opened.
 *
 * Nothing here opens a socket, spawns a process, or reaches any party the client did not already
 * connect. The peer is whoever is on the other end of stdin and stdout, and the only thing that
 * can be reached is them.
 *
 * Two rules shape the whole module. The client's answer is data from an agent Concord does not
 * control, so it is validated and labeled untrusted exactly like any other foreign output. And a
 * client that never declared it can answer is never asked: the request refuses rather than hangs,
 * because a silent wait for a reply that cannot come is the worst of the available failures.
 */

const fail = (code, message, detail) => { throw new HarnessError(code, message, detail); };
const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_PENDING = 8;
const MAX_TEXT = 65_536;
const MAX_TOKENS = 8192;

/**
 * The outbound half of a JSON-RPC session: issue a request, match the response that comes back.
 *
 * `send` is injected rather than taken from `process.stdout`, so the whole protocol can be driven
 * in a test without a transport, and so this module never decides where a line goes.
 */
export function createClientChannel({ send, timeoutMs = DEFAULT_TIMEOUT_MS, maxPending = MAX_PENDING } = {}) {
  if (typeof send !== 'function') fail('PEER_CHANNEL', 'A client channel needs a way to send a line');
  const pending = new Map();
  let counter = 0;
  let client = null;

  /** What the client said it was and could do, from its own initialize parameters. */
  function rememberClient(params) {
    const capabilities = isObject(params?.capabilities) ? Object.keys(params.capabilities).sort() : [];
    client = {
      name: typeof params?.clientInfo?.name === 'string' ? params.clientInfo.name : null,
      version: typeof params?.clientInfo?.version === 'string' ? params.clientInfo.version : null,
      protocolVersion: typeof params?.protocolVersion === 'string' ? params.protocolVersion : null,
      capabilities,
    };
    return client;
  }

  const describeClient = () => (client ? { ...client, capabilities: [...client.capabilities] } : null);
  const supports = (capability) => Boolean(client && client.capabilities.includes(capability));

  function request(method, params, { timeoutMs: deadline = timeoutMs, signal } = {}) {
    // An id the client cannot collide with: its own ids are its business, and a prefix keeps the
    // two numbering schemes from ever meeting.
    const id = 'concord-' + (counter += 1);
    let line;
    // canonical() rejects anything that is not strict JSON, so a malformed outbound request fails
    // here rather than as an unparseable line on the wire.
    try { line = canonical({ jsonrpc: '2.0', id, method, params }); }
    catch { return Promise.reject(new HarnessError('PEER_REQUEST', 'The request to the client is not representable as JSON')); }

    if (pending.size >= maxPending) return Promise.reject(new HarnessError('PEER_BUSY', 'Too many requests to the client are already in flight', { pending: pending.size }));

    return new Promise((resolve, reject) => {
      const settle = (fn, value) => {
        const entry = pending.get(id);
        if (!entry) return;
        clearTimeout(entry.timer);
        pending.delete(id);
        fn(value);
      };
      const timer = setTimeout(() => settle(reject, new HarnessError('PEER_TIMEOUT', 'The client did not answer within the deadline', { method })), deadline);
      // A pending question must never be the reason a process stays alive.
      timer.unref?.();
      pending.set(id, { resolve, reject, timer });

      if (signal) {
        if (signal.aborted) { settle(reject, new HarnessError('PEER_ABORTED', 'The request to the client was cancelled')); return; }
        signal.addEventListener('abort', () => settle(reject, new HarnessError('PEER_ABORTED', 'The request to the client was cancelled')), { once: true });
      }

      try { send(line); }
      catch { settle(reject, new HarnessError('PEER_TRANSPORT', 'The client channel could not be written')); }
    });
  }

  /** One-way: notifications carry no id and are never answered. */
  function notify(method, params) {
    let line;
    try { line = canonical({ jsonrpc: '2.0', method, params }); }
    catch { fail('PEER_REQUEST', 'The notification is not representable as JSON'); }
    try { send(line); }
    catch { fail('PEER_TRANSPORT', 'The client channel could not be written'); }
  }

  /**
   * Route one incoming message if it answers a question Concord asked.
   *
   * Returns false for anything else, so the caller's own dispatch is untouched. This matters more
   * than it looks: a response carries an id and no method, which the request dispatcher would
   * otherwise reject as a malformed request and answer with an error — turning the client's
   * perfectly good reply into protocol noise.
   */
  function deliver(message) {
    if (!isObject(message)) return false;
    if (Object.hasOwn(message, 'method')) return false;
    if (!Object.hasOwn(message, 'id')) return false;
    const entry = pending.get(message.id);
    if (!entry) return false;
    clearTimeout(entry.timer);
    pending.delete(message.id);
    if (isObject(message.error)) {
      const detail = { code: message.error.code };
      entry.reject(new HarnessError('PEER_REFUSED', typeof message.error.message === 'string' ? message.error.message : 'The client refused the request', detail));
    } else {
      entry.resolve(message.result);
    }
    return true;
  }

  return { request, notify, deliver, rememberClient, describeClient, supports, pendingCount: () => pending.size };
}

/**
 * The schema an elicitation may request.
 *
 * MCP restricts this to a flat object of primitives on purpose: the client has to render it, and
 * a nested schema is not something a person can be shown a form for. Building it here from a
 * declared field list, rather than taking a caller's schema whole, is what keeps that true.
 */
function requestedSchema(fields) {
  const properties = {};
  const required = [];
  for (const field of fields) {
    const property = { type: field.type };
    if (field.description !== undefined) property.description = field.description;
    if (field.enum !== undefined) {
      if (field.type !== 'string') fail('PEER_REQUEST', 'Only a string field may offer a fixed set of choices', { field: field.name });
      property.enum = [...field.enum];
    }
    properties[field.name] = property;
    if (field.required !== false) required.push(field.name);
  }
  return { type: 'object', properties, ...(required.length ? { required } : {}) };
}

/** The client's reply to an elicitation, which may legitimately be a refusal. */
function checkElicitation(result, fields) {
  if (!isObject(result)) fail('PEER_RESPONSE', 'The client returned no elicitation result');
  const action = result.action;
  if (!['accept', 'decline', 'cancel'].includes(action)) fail('PEER_RESPONSE', 'The client returned an unknown elicitation action', { action: typeof action === 'string' ? action : null });
  // Declining is an answer, not a failure. Treating "no" as an error would make a refusal look
  // like a broken channel and invite a retry of something a person already turned down.
  if (action !== 'accept') return { action, content: null };

  const content = isObject(result.content) ? result.content : {};
  const answer = {};
  for (const field of fields) {
    const value = content[field.name];
    if (value === undefined) {
      if (field.required === false) continue;
      fail('PEER_RESPONSE', 'The client accepted but left a required field out', { field: field.name });
    }
    const actual = typeof value;
    if (actual !== field.type) fail('PEER_RESPONSE', 'The client returned the wrong type for a field', { field: field.name, expected: field.type, actual });
    if (actual === 'string' && value.length > MAX_TEXT) fail('PEER_RESPONSE', 'The client returned more text than the bound permits', { field: field.name });
    if (field.enum !== undefined && !field.enum.includes(value)) fail('PEER_RESPONSE', 'The client returned a value outside the offered choices', { field: field.name });
    answer[field.name] = value;
  }
  return { action, content: answer };
}

/** The client's reply to a sampling request, checked before any of it is believed. */
function checkSampling(result) {
  if (!isObject(result)) fail('PEER_RESPONSE', 'The client returned no sampling result');
  const content = result.content;
  if (!isObject(content) || content.type !== 'text' || typeof content.text !== 'string') {
    // Image and audio content are legal MCP sampling results and are deliberately not accepted
    // here: this channel carries a question and an answer in text, and silently dropping a
    // non-text part would misreport what the peer said.
    fail('PEER_RESPONSE', 'The client returned a sampling result that is not text', { type: isObject(content) ? content.type : null });
  }
  if (content.text.length > MAX_TEXT) fail('PEER_RESPONSE', 'The client returned more text than the bound permits');
  return {
    text: content.text,
    role: typeof result.role === 'string' ? result.role : 'assistant',
    model: typeof result.model === 'string' ? result.model : null,
    stopReason: typeof result.stopReason === 'string' ? result.stopReason : null,
  };
}

/**
 * The tools that use the channel.
 *
 * Registered only where a client actually exists — the MCP transport. The desktop and terminal
 * launchers serve a browser, which is not an agent that can be asked anything, so they register
 * none of this rather than offering a tool that could only ever refuse.
 */
export function makePeerTools({ channel } = {}) {
  if (!channel) fail('PEER_CONFIG', 'Peer tools need a client channel');

  const askSchema = {
    type: 'object', additionalProperties: false, required: ['question'],
    properties: {
      question: { type: 'string', minLength: 1, maxLength: MAX_TEXT },
      systemPrompt: { type: 'string', maxLength: MAX_TEXT },
      maxTokens: { type: 'integer', minimum: 1, maximum: MAX_TOKENS },
      intent: { type: 'string', maxLength: 256 },
    },
  };

  const tellSchema = {
    type: 'object', additionalProperties: false, required: ['message'],
    properties: {
      message: { type: 'string', minLength: 1, maxLength: MAX_TEXT },
      level: { type: 'string', enum: ['debug', 'info', 'notice', 'warning', 'error'] },
    },
  };

  return [
    {
      name: 'peer.capabilities', version: '1.0.0', effect: 'read',
      outputKeys: ['connected', 'client', 'supports', 'pending', 'limitations'],
      inputSchema: { type: 'object', additionalProperties: false, properties: {} },
      execute() {
        const client = channel.describeClient();
        return {
          connected: client !== null,
          client,
          // Named one by one rather than echoed, so this reports what Concord can actually use
          // rather than whatever the client happened to list.
          supports: {
            sampling: channel.supports('sampling'),
            elicitation: channel.supports('elicitation'),
            roots: channel.supports('roots'),
          },
          pending: channel.pendingCount(),
          limitations: client === null
            ? ['No client has completed initialize on this session, so nothing can be asked yet']
            : [],
        };
      },
    },
    {
      // A network effect: the answer is produced by an agent Concord does not control, it is not
      // reproducible, and it must therefore require its own exact grant and be taken from the
      // journal on replay. There is no origin to allowlist because no socket is opened; the only
      // reachable party is the client already on the other end of this session.
      name: 'peer.ask', version: '1.0.0', effect: 'network',
      outputKeys: ['text', 'role', 'model', 'stopReason', 'source', 'untrusted', 'limitations'],
      inputSchema: askSchema,
      async execute(input, context) {
        if (!channel.describeClient()) fail('PEER_NO_CLIENT', 'No client has completed initialize on this session');
        if (!channel.supports('sampling')) {
          fail('PEER_UNSUPPORTED', 'The connected client did not declare the sampling capability, so it cannot be asked', {
            capabilities: channel.describeClient().capabilities,
          });
        }
        const deadline = Math.min(DEFAULT_TIMEOUT_MS, context?.policy?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
        const params = {
          messages: [{ role: 'user', content: { type: 'text', text: input.question } }],
          maxTokens: input.maxTokens ?? 1024,
          // The client is asked to include none of its own context. Concord states its question in
          // full or not at all; inheriting whatever else that agent is working on would put text
          // Concord never saw into a request it is accountable for.
          includeContext: 'none',
          ...(input.systemPrompt === undefined ? {} : { systemPrompt: input.systemPrompt }),
        };
        const result = await channel.request('sampling/createMessage', params, { timeoutMs: deadline, signal: context?.signal });
        const answer = checkSampling(result);
        return {
          ...answer,
          source: channel.describeClient().name,
          untrusted: true,
          limitations: [
            'This text was written by an agent Concord does not control and is evidence of what that agent said, not that it is true',
            'The client may have shown this question to a person, or answered it with any model it chose; neither is visible from here',
          ],
        };
      },
    },
    {
      /**
       * Ask the client for an answer it has to go and get.
       *
       * Where sampling asks the client's model, elicitation asks the client to obtain input —
       * typically from the person operating it. Both are the server speaking first; which one a
       * given client supports is up to that client, and the two are not interchangeable. Claude
       * Code, measured at its own initialize, declares elicitation and not sampling, so on that
       * client this is the channel that works and peer.ask is the one that refuses.
       */
      name: 'peer.request', version: '1.0.0', effect: 'network',
      outputKeys: ['action', 'answered', 'content', 'source', 'untrusted', 'limitations'],
      inputSchema: {
        type: 'object', additionalProperties: false, required: ['message'],
        properties: {
          message: { type: 'string', minLength: 1, maxLength: 4096 },
          fields: {
            type: 'array', minItems: 1, maxItems: 16,
            items: {
              type: 'object', additionalProperties: false, required: ['name', 'type'],
              properties: {
                // Concord's schema vocabulary has no `pattern`, so the shape of a name is
                // checked in execute() rather than declared here as a keyword the validator
                // would reject outright.
                name: { type: 'string', minLength: 1, maxLength: 64 },
                type: { type: 'string', enum: ['string', 'number', 'boolean'] },
                description: { type: 'string', maxLength: 1024 },
                required: { type: 'boolean' },
                enum: { type: 'array', minItems: 1, maxItems: 32, items: { type: 'string', maxLength: 256 } },
              },
            },
          },
        },
      },
      async execute(input, context) {
        if (!channel.describeClient()) fail('PEER_NO_CLIENT', 'No client has completed initialize on this session');
        if (!channel.supports('elicitation')) {
          fail('PEER_UNSUPPORTED', 'The connected client did not declare the elicitation capability, so it cannot be asked', {
            capabilities: channel.describeClient().capabilities,
          });
        }
        // The default shape is the plain case: a question, and room for an answer in words.
        const fields = input.fields ?? [{ name: 'answer', type: 'string', description: 'Your answer to Concord' }];
        const names = fields.map((field) => field.name);
        if (new Set(names).size !== names.length) fail('PEER_REQUEST', 'Each requested field needs a distinct name');
        // A field name becomes a property key in a schema the client has to render, so it is held
        // to a portable identifier rather than whatever a plan happened to send.
        for (const name of names) {
          if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name)) fail('PEER_REQUEST', 'A requested field name must be a portable identifier', { field: name });
        }

        // A person is on the far end of this one, and people are slower than models. Measured:
        // a first attempt died at the sixty-second default while the prompt was still on screen
        // waiting to be read. So this takes the policy's whole deadline rather than a shorter
        // fixed cap, stopping a moment early only so the failure reads PEER_TIMEOUT — the client
        // did not answer — instead of the kernel's generic TIMEOUT.
        const ceiling = context?.policy?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        const deadline = Math.max(1000, ceiling - 1000);
        const result = await channel.request('elicitation/create', {
          message: input.message,
          requestedSchema: requestedSchema(fields),
        }, { timeoutMs: deadline, signal: context?.signal });

        const reply = checkElicitation(result, fields);
        return {
          action: reply.action,
          // Stated plainly, because "declined" and "answered with nothing" must not read alike.
          answered: reply.action === 'accept',
          content: reply.content,
          source: channel.describeClient().name,
          untrusted: true,
          limitations: reply.action === 'accept'
            ? ['This answer came from the client and whoever operates it; Concord cannot see whether a person typed it or the agent answered on their behalf']
            : ['The client did not answer, and that is a decision it was entitled to make rather than a failure of the channel'],
        };
      },
    },
    {
      // Also a network effect, for the same reason and one more: it is the only tool here that
      // leaves a mark on someone else. A notification cannot be taken back.
      name: 'peer.tell', version: '1.0.0', effect: 'network',
      outputKeys: ['delivered', 'level', 'bytes', 'limitations'],
      inputSchema: tellSchema,
      execute(input) {
        if (!channel.describeClient()) fail('PEER_NO_CLIENT', 'No client has completed initialize on this session');
        const level = input.level ?? 'info';
        channel.notify('notifications/message', { level, logger: 'concord', data: input.message });
        return {
          delivered: true,
          level,
          bytes: Buffer.byteLength(input.message),
          limitations: [
            'A notification has no reply, so this records that the line was written to the session and not that the client read, showed or understood it',
          ],
        };
      },
    },
  ];
}

/**
 * The mailbox: how Concord reaches the agent when the protocol cannot.
 *
 * The channel above is live and needs a client on the other end. Only two of MCP's directions
 * actually reach anyone, and they reach different people: sampling asks the client's model,
 * elicitation asks the person operating it. Measured against Claude Code, which declares
 * elicitation and not sampling, that leaves a real gap — Concord can reach the operator and can
 * log at the client, and has no protocol path into the connected agent's context at all.
 *
 * So this does not use the protocol. A message is a file. Concord writes one when it has
 * something to say to the agent; the agent reads it the next time it looks, over whichever
 * transport it happens to be using. That makes these two tools unlike the rest of this module:
 * they need no live client, they work from the desktop application as readily as from the MCP
 * server, and the two sides can be separate processes that never meet — which they are.
 *
 * It is a mailbox and is described as one. Nothing here notifies anybody; a letter sits until it
 * is collected.
 */

const MAX_MESSAGE = 65_536;
const MAX_SUBJECT = 200;
const MAX_MESSAGES = 10_000;
const MAX_FILE_BYTES = 1_048_576;
const NEWLINE = String.fromCharCode(10);
const FILE_PATTERN = /^(\d{6})-[0-9a-f]{12}\.json$/;

function mailboxFiles(directory) {
  let entries;
  try { entries = fs.readdirSync(directory); }
  catch (error) {
    // An empty mailbox and a mailbox that does not exist yet are the same thing to a reader.
    if (error.code === 'ENOENT') return [];
    throw new HarnessError('PEER_MAILBOX', 'The mailbox directory could not be read');
  }
  return entries.filter((name) => FILE_PATTERN.test(name)).sort();
}

/** Every letter currently in the mailbox, in order. A letter that cannot be read is skipped. */
function loadRecords(directory) {
  const out = [];
  for (const name of mailboxFiles(directory)) {
    const file = path.join(directory, name);
    try {
      if (fs.statSync(file).size > MAX_FILE_BYTES) continue;
      out.push(parseJson(fs.readFileSync(file, 'utf8')));
    } catch { /* unreadable or malformed: skipped rather than failing the whole collection */ }
  }
  return out;
}

/**
 * File one message. Exported because Concord's own chat layer files the operator's prompt here
 * on every turn, and a second implementation of the same record format is how two writers start
 * disagreeing about what a letter looks like.
 */
export function fileMessage(directory, { message, subject, audience = 'agent', replyTo } = {}) {
  if (typeof message !== 'string' || !message || message.length > MAX_MESSAGE) fail('PEER_MAILBOX', 'A message needs text within the bound');
  // Counted and numbered from the file names, not from what parses. A letter nobody can read is
  // still a letter taking up a slot, and a sequence that skipped it would collide with its name.
  const names = mailboxFiles(directory);
  if (names.length >= MAX_MESSAGES) fail('PEER_MAILBOX', 'The mailbox holds as many messages as the bound permits', { messages: names.length });
  const records = loadRecords(directory);
  if (replyTo !== undefined && !records.some((record) => record.seq === replyTo)) {
    fail('PEER_MAILBOX', 'There is no message with that sequence to reply to', { replyTo });
  }
  const seq = (names.length ? Number(names[names.length - 1].slice(0, 6)) : 0) + 1;
  const record = {
    seq, for: audience,
    ...(subject === undefined ? {} : { subject }),
    ...(replyTo === undefined ? {} : { replyTo }),
    message,
  };
  const id = String(seq).padStart(6, '0') + '-' + digest(record).slice(0, 12);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, id + '.json'), canonical(record) + NEWLINE, { flag: 'wx' });
  return { seq, id, record };
}

/** Every letter, each marked with whether anything replies to it. */
export function readMailbox(directory) {
  const records = loadRecords(directory);
  const answered = new Set(records.map((record) => record.replyTo).filter((seq) => Number.isInteger(seq)));
  return records.map((record) => ({
    ...record,
    open: record.replyTo === undefined && !answered.has(record.seq),
  }));
}

export function makeMailboxTools({ directory } = {}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) fail('PEER_CONFIG', 'The mailbox needs an absolute directory');

  return [
    {
      // A write effect: it puts a file on disk that outlives the run, so it takes a grant like
      // any other write. The recipient is named in the message rather than implied, because
      // "for the agent" and "for the operator" are different audiences and a letter that does
      // not say which it is will be read by the wrong one.
      name: 'peer.post', version: '1.0.0', effect: 'write',
      outputKeys: ['seq', 'id', 'for', 'replyTo', 'bytes', 'limitations'],
      inputSchema: {
        type: 'object', additionalProperties: false, required: ['message'],
        properties: {
          message: { type: 'string', minLength: 1, maxLength: MAX_MESSAGE },
          subject: { type: 'string', maxLength: MAX_SUBJECT },
          for: { type: 'string', enum: ['agent', 'operator'] },
          // Naming what this answers is what turns a pile of letters into an exchange. Without
          // it a reply is just another message and nobody can tell which question is still open.
          replyTo: { type: 'integer', minimum: 1, maximum: MAX_MESSAGES },
        },
      },
      execute(input) {
        const filed = fileMessage(directory, {
          message: input.message, subject: input.subject,
          audience: input.for ?? 'agent', replyTo: input.replyTo,
        });
        return {
          seq: filed.seq, id: filed.id, for: filed.record.for, replyTo: filed.record.replyTo ?? null,
          bytes: Buffer.byteLength(input.message),
          limitations: ['A mailbox notifies nobody; this records that the message was filed, not that anyone has read it'],
        };
      },
    },
    {
      name: 'peer.inbox', version: '1.0.0', effect: 'read',
      outputKeys: ['messages', 'returned', 'total', 'latestSeq', 'openQuestions', 'limitations'],
      inputSchema: {
        type: 'object', additionalProperties: false,
        properties: {
          after: { type: 'integer', minimum: 0, maximum: MAX_MESSAGES },
          limit: { type: 'integer', minimum: 1, maximum: 100 },
          for: { type: 'string', enum: ['agent', 'operator'] },
          // The whole point of the exchange: show me only what is still waiting on me.
          unanswered: { type: 'boolean' },
        },
      },
      execute(input) {
        const records = loadRecords(directory);
        const answered = new Set(records.map((record) => record.replyTo).filter((seq) => Number.isInteger(seq)));
        // total counts what is on disk; messages carry what could be read. A gap between them is
        // itself the report that something in the mailbox is damaged.
        const onDisk = mailboxFiles(directory).length;
        const after = input.after ?? 0;
        const limit = input.limit ?? 20;
        const messages = [];
        let latestSeq = 0;
        let openQuestions = 0;

        for (const record of records) {
          latestSeq = Math.max(latestSeq, record.seq);
          // A question is open when nothing replies to it. A reply is never itself a question.
          const open = record.replyTo === undefined && !answered.has(record.seq);
          if (open) openQuestions += 1;
          if (record.seq <= after) continue;
          if (input.for !== undefined && record.for !== input.for) continue;
          if (input.unanswered === true && !open) continue;
          if (messages.length >= limit) continue;
          messages.push({ ...record, answered: !open && record.replyTo === undefined });
        }

        return {
          messages,
          returned: messages.length,
          total: onDisk,
          latestSeq,
          openQuestions,
          // Reading does not remove: the same letter is returned again unless the caller pages
          // past it, because a tool that quietly consumed evidence would make a lost message
          // indistinguishable from one that was never sent.
          limitations: ['Reading leaves the mailbox unchanged; page with "after" using latestSeq, or ask for unanswered only'],
        };
      },
    },
  ];
}
