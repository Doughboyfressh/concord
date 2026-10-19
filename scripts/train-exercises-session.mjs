import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createClientChannel, makePeerTools } from '../src/peer.mjs';
import { makeSourceTools, loadSourceLock } from '../src/sources.mjs';

/**
 * The session half of the system: a live client channel, and reading a reviewed source.
 *
 * Neither fits a plan. The peer tools need a client on the other end of a JSON-RPC session, and
 * the channel is built to be driven without one — `send` is injected rather than taken from
 * stdout, precisely so the protocol can be exercised with no transport. That design is what makes
 * all nine of its refusals reachable here, and leaving them unexercised would have meant the one
 * part of Concord that talks to another agent was also the least tested.
 *
 * The source refusals need a context rather than a channel: a missing workspace root, a nonsensical
 * output budget, an already-aborted signal. A plan cannot supply those, because the engine builds
 * the context and would reject each of them before any tool saw it.
 *
 * Every code below was raised for real first, and three attempts along the way were wrong in ways
 * worth recording. A pending question's deadline timer is unref'd — deliberately, so a question
 * never keeps the process alive — which means awaiting PEER_TIMEOUT in a bare script lets the
 * process exit before it fires; it needs a ref'd keepalive, and the exercises below carry one.
 * Calling peer.request with `prompt` instead of `message` produced PEER_REQUEST rather than a
 * schema error, because a direct call bypasses the engine's validation — the same trap that made
 * skills.rank look broken. And a wrong expectedDigest answered SKILL_INVALID rather than
 * DIGEST_MISMATCH, so that one is deliberately absent rather than guessed at.
 */

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const toolPolicy = { maxOutputBytes: 1048576, timeoutMs: 10000 };
const byName = (tools) => new Map(tools.map((tool) => [tool.name, tool]));

/** A channel with no transport behind it, optionally with a client that has declared itself. */
function channel({ capabilities = null, send = () => {}, timeoutMs = 400, maxPending } = {}) {
  const made = createClientChannel({ send, timeoutMs, ...(maxPending ? { maxPending } : {}) });
  if (capabilities) made.rememberClient({ clientInfo: { name: 'training', version: '1' }, protocolVersion: '2025-06-18', capabilities });
  return made;
}

const peerTool = (made, name) => byName(makePeerTools({ channel: made })).get(name);

/**
 * Await something while holding the event loop open.
 *
 * The channel unrefs its deadline timer so a pending question cannot keep a process alive. Awaiting
 * a timeout without this lets the process exit first and the refusal never arrives.
 */
async function awaiting(promise) {
  const keepalive = setInterval(() => {}, 10);
  try { return await promise; } finally { clearInterval(keepalive); }
}

/** Issue a request, let it reach the channel, then answer it as a client would. */
async function answered(pending, reply, made) {
  pending.catch(() => {});
  await new Promise((resolve) => setTimeout(resolve, 15));
  made.deliver({ jsonrpc: '2.0', id: 'concord-1', result: reply });
  return awaiting(pending);
}

const sourceTools = () => loadSourceLock(path.join(root, 'sources.lock.json'))
  .then((catalog) => ({ tools: byName(makeSourceTools(catalog)), sourceId: catalog.sources[0].id }));

export function sessionExercises() {
  return [
    // ---- the channel itself ------------------------------------------------------------
    {
      family: 'exchange', tool: 'peer.channel', expectThrow: 'PEER_CHANNEL',
      call: () => createClientChannel({}),
      lesson: 'createClientChannel refuses PEER_CHANNEL without a way to send a line. The transport is injected rather than assumed, which is what lets the whole protocol be driven with no process on the other end, and a channel that could not send would be a session that silently never asked anything.',
    },
    {
      family: 'exchange', tool: 'peer.channel', expectThrow: 'PEER_TRANSPORT',
      call: () => channel({ send: () => { throw new Error('the channel is closed'); } }).request('ping', {}),
      lesson: 'A send that throws becomes PEER_TRANSPORT rather than an unhandled error, so a closed pipe is reported as a transport failure and not as the client having refused. The distinction matters because one is worth retrying and the other is not.',
    },
    {
      family: 'exchange', tool: 'peer.channel', expectThrow: 'PEER_REQUEST',
      call: () => channel().request('ping', { unrepresentable: undefined }),
      lesson: 'An outbound request that is not strict JSON is refused PEER_REQUEST before anything is written, because the line is canonicalised first. A malformed request fails here rather than arriving at the client as an unparseable line, which is the difference between a clear refusal and a session that hangs.',
    },
    {
      family: 'exchange', tool: 'peer.channel', expectThrow: 'PEER_BUSY',
      call: () => {
        const made = channel({ maxPending: 1, timeoutMs: 50 });
        made.request('first', {}).catch(() => {});
        return made.request('second', {});
      },
      lesson: 'A second request beyond maxPending is refused PEER_BUSY rather than queued, so the number of questions in flight to a client is bounded by something other than hope. An unbounded queue would turn a slow client into unbounded memory on this side.',
    },
    {
      family: 'exchange', tool: 'peer.channel', expectThrow: 'PEER_TIMEOUT',
      call: () => awaiting(channel({ timeoutMs: 20 }).request('unanswered', {})),
      lesson: 'A client that never answers produces PEER_TIMEOUT at the deadline. The deadline timer is unreffed on purpose, so a pending question never keeps the process alive — which also means code awaiting the refusal must hold the loop open itself, or the process exits before the timeout arrives.',
    },
    {
      family: 'exchange', tool: 'peer.channel', expectThrow: 'PEER_ABORTED',
      call: () => {
        const controller = new AbortController();
        controller.abort();
        return channel({ timeoutMs: 500 }).request('cancelled', {}, { signal: controller.signal });
      },
      lesson: 'A request carrying an already-aborted signal is refused PEER_ABORTED immediately rather than waiting out its deadline. Cancellation is checked before the wait as well as during it, so a question nobody still wants is not asked at all.',
    },

    // ---- what the client declared, and what it answered ---------------------------------
    {
      family: 'exchange', tool: 'peer.ask', expectThrow: 'PEER_NO_CLIENT',
      call: () => peerTool(channel(), 'peer.ask').execute({ question: 'is anyone there' }, { workspaceRoot: root, policy: toolPolicy }),
      lesson: 'peer.ask refuses PEER_NO_CLIENT until a client has completed initialize on the session. Concord cannot call out to an arbitrary endpoint — the only reachable party is whoever is already on the other end — so having no client is a different situation from having one that cannot help.',
    },
    {
      family: 'exchange', tool: 'peer.ask', expectThrow: 'PEER_UNSUPPORTED',
      call: () => peerTool(channel({ capabilities: { roots: {} } }), 'peer.ask').execute({ question: 'can you think for me' }, { workspaceRoot: root, policy: toolPolicy }),
      lesson: 'peer.ask refuses PEER_UNSUPPORTED when the connected client never declared the sampling capability, and reports which capabilities it did declare. Measured against real clients: Claude Code declares roots and elicitation, Claude Desktop declares roots and extensions, and neither declares sampling — so this refusal is the normal case rather than an edge one.',
    },
    {
      family: 'exchange', tool: 'peer.request', expectThrow: 'PEER_UNSUPPORTED',
      call: () => peerTool(channel({ capabilities: { roots: {} } }), 'peer.request').execute({ message: 'please confirm', fields: [{ name: 'answer', type: 'string' }] }, { workspaceRoot: root, policy: toolPolicy }),
      lesson: 'peer.request refuses PEER_UNSUPPORTED without the elicitation capability, by the same rule that governs sampling. Reaching a person and reaching a model are separate capabilities, declared separately, and a client offering one is not assumed to offer the other.',
    },
    {
      family: 'exchange', tool: 'peer.request', expectThrow: 'PEER_REQUEST',
      call: () => peerTool(channel({ capabilities: { elicitation: {} } }), 'peer.request').execute({ message: 'pick one', fields: [{ name: 'count', type: 'number', enum: ['a', 'b'] }] }, { workspaceRoot: root, policy: toolPolicy }),
      lesson: 'Only a string field may offer a fixed set of choices, so a number field with an enum is refused PEER_REQUEST. The schema has to be rendered as a form by the client, and a numeric field with string options is not something a person can be shown.',
    },
    {
      family: 'exchange', tool: 'peer.request', expectThrow: 'PEER_RESPONSE',
      call: () => {
        const made = channel({ capabilities: { elicitation: {} } });
        const pending = peerTool(made, 'peer.request').execute({ message: 'please answer', fields: [{ name: 'answer', type: 'string' }] }, { workspaceRoot: root, policy: toolPolicy });
        return answered(pending, { action: 'nonsense' }, made);
      },
      lesson: 'An elicitation result whose action is not accept, decline or cancel is refused PEER_RESPONSE. Declining is a legitimate answer and is returned as one, so this refusal is reserved for a reply that is not any of the three things a client is allowed to say — treating an unknown action as a decline would turn a broken client into an apparent human refusal.',
    },
    {
      family: 'exchange', tool: 'peer.request', expectThrow: 'PEER_RESPONSE',
      call: () => {
        const made = channel({ capabilities: { elicitation: {} } });
        const pending = peerTool(made, 'peer.request').execute({ message: 'please answer', fields: [{ name: 'answer', type: 'string' }] }, { workspaceRoot: root, policy: toolPolicy });
        return answered(pending, { action: 'accept', content: {} }, made);
      },
      lesson: 'A client that accepts an elicitation and then omits a required field is refused PEER_RESPONSE naming the field. An acceptance missing its content would otherwise read as a person having answered, which is the worst available outcome: a decision recorded that nobody made.',
    },
    {
      family: 'exchange', tool: 'peer.ask', expectThrow: 'PEER_RESPONSE',
      call: () => {
        const made = channel({ capabilities: { sampling: {} } });
        const pending = peerTool(made, 'peer.ask').execute({ question: 'describe this' }, { workspaceRoot: root, policy: toolPolicy });
        return answered(pending, { content: { type: 'image' } }, made);
      },
      lesson: 'A sampling result that is not text is refused PEER_RESPONSE. The answer becomes untrusted text in a journal that has to replay byte for byte, so a content type Concord cannot record is refused rather than coerced into a description of itself.',
    },

    // ---- reading a reviewed source ------------------------------------------------------
    {
      family: 'catalog', tool: 'sources.catalog', expectThrow: 'SOURCE_UNKNOWN',
      call: async () => {
        const { tools } = await sourceTools();
        return tools.get('sources.catalog').execute({ sourceId: 'nobody-at-all' }, { workspaceRoot: root, policy: toolPolicy });
      },
      lesson: 'sources.catalog refuses SOURCE_UNKNOWN for an id the lock does not contain, rather than answering with an empty list. An empty answer would read as a source that exists and offers nothing, which is a different claim from a source that was never reviewed.',
    },
    {
      family: 'catalog', tool: 'skills.snapshot', expectThrow: 'WORKSPACE_INVALID',
      call: async () => {
        const { tools, sourceId } = await sourceTools();
        return tools.get('skills.snapshot').execute({ path: 'x.md', sourceId }, { policy: toolPolicy });
      },
      lesson: 'skills.snapshot refuses WORKSPACE_INVALID when the context carries no workspace root. Every path it accepts is resolved against that root, so without one there is no boundary to enforce and the refusal has to come before any filesystem call.',
    },
    {
      family: 'catalog', tool: 'skills.snapshot', expectThrow: 'POLICY_INVALID',
      call: async () => {
        const { tools, sourceId } = await sourceTools();
        return tools.get('skills.snapshot').execute({ path: 'x.md', sourceId }, { workspaceRoot: root, policy: { maxOutputBytes: 0, timeoutMs: 1000 } });
      },
      lesson: 'A maxOutputBytes that is not a positive safe integer is refused POLICY_INVALID by the tool itself, not only by the engine. A bound of zero permits nothing, so treating it as a default would quietly read a file the policy had forbidden.',
    },
    {
      family: 'catalog', tool: 'skills.snapshot', expectThrow: 'SOURCE_NOT_FOUND',
      call: async () => {
        const { tools, sourceId } = await sourceTools();
        return tools.get('skills.snapshot').execute({ path: 'no/such/file.md', sourceId }, { workspaceRoot: root, policy: toolPolicy });
      },
      lesson: 'A snapshot path that does not exist is refused SOURCE_NOT_FOUND, separately from SOURCE_READ_FAILED for any other filesystem error. A missing file is an ordinary mistake and a permissions or device failure is not, so an operator is told which happened.',
    },
    {
      family: 'catalog', tool: 'skills.snapshot', expectThrow: 'ABORTED',
      call: async () => {
        const { tools, sourceId } = await sourceTools();
        const controller = new AbortController();
        controller.abort();
        return tools.get('skills.snapshot').execute({ path: 'README.md', sourceId }, { workspaceRoot: root, policy: toolPolicy, signal: controller.signal });
      },
      lesson: 'skills.snapshot honours an abort signal with ABORTED, and checks it repeatedly rather than once at the start, so cancelling a walk over a large tree takes effect partway through instead of after it finishes.',
    },
    {
      family: 'catalog', tool: 'skills.snapshot', expectThrow: 'SKILL_INVALID', workspace: 'temp',
      fixture: (dir) => fs.writeFileSync(path.join(dir, 'binary.md'), Buffer.from([0x68, 0x69, 0x00, 0x68, 0x69])),
      call: async ({ workspaceRoot }) => {
        const { tools, sourceId } = await sourceTools();
        return tools.get('skills.snapshot').execute({ path: 'binary.md', sourceId }, { workspaceRoot, policy: toolPolicy });
      },
      lesson: 'A file containing a NUL byte is refused SKILL_INVALID: a skill snapshot holds UTF-8 text, and binary content is rejected rather than captured as mojibake. A snapshot is meant to be read by a person and by a model, and neither can read bytes that are not text.',
    },
  ];
}
