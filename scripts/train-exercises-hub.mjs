import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { joinHub, hubAddress } from '../src/peer-hub.mjs';
import { createHubResponder, makePeerTools } from '../src/peer.mjs';

/**
 * The bus between sessions, and every way it says no.
 *
 * This is the one subsystem in Concord whose failures are nearly all about other processes, and it
 * was also the largest unproven block left in the suite: seventeen refusal codes none of which a
 * single-process round had ever raised. The reason is structural rather than neglectful. A plan
 * cannot reach most of them, because a plan runs in one process and these are the codes that exist
 * precisely because a second process may be absent, mute, full, slow, or unable to answer. So they
 * are driven here directly: a real hub bound to a real endpoint, with real spokes connected to it,
 * inside one round.
 *
 * Two things make that repeatable, which matters because the runner invokes every call exercise
 * twice and demands the same code both times:
 *
 *   a fresh root per invocation   the endpoint name is a digest of the workspace root, so a new
 *                                 root is a new pipe. Reusing one would make the second invocation
 *                                 a spoke of the first and raise something else entirely.
 *   teardown in a finally         a pipe outlives the function that bound it. Every membership and
 *                                 every squatting server is closed on the way out, including on
 *                                 the paths that threw, which is all of them.
 *
 * What the exercises below are careful *not* to do is simulate the hub. The hub is real in every
 * one of them. Only one collaborator is stubbed, the MCP client channel, and only because a client
 * is a thing on the other end of a stdio pipe that no test can conjure: its three methods are
 * `describeClient`, `supports`, and `request`, and the refusals being proven all fire on what the
 * channel *reports* rather than on anything it does. A stubbed decompiler would prove something
 * about the stub; a stubbed client reporting "I did not declare sampling" is the input the refusal
 * reads.
 *
 * Three codes resisted being proven at all, and the reasons are worth more than the proofs would
 * have been:
 *
 *   PEER_HUB_FULL        raised, caught, and erased. The hub throws it inside its own connection
 *                        handler; the handler turns it into a `denied` frame carrying only the
 *                        message, so the joining session sees PEER_HUB_DENIED. The code does not
 *                        survive the boundary it was thrown at. Proven below as DENIED, which is
 *                        what a caller can actually observe.
 *   PEER_HUB_BIND        unreachable on this platform. On win32 the endpoint is a named pipe whose
 *   PEER_HUB_UNREACHABLE name is always valid, so bind fails only with EADDRINUSE - the one code
 *                        that is deliberately not an error - and a listening pipe always accepts.
 *                        Both need the unix-socket path, where a stale socket file refuses a
 *                        connection and a missing directory refuses a bind.
 */

/** Counts invocations, so the root - and therefore the endpoint - is new every time. */
let turn = 0;

const identity = (name) => ({ name, version: '1.0.0', capabilities: ['sampling'] });

/**
 * One bus, taken down afterwards.
 *
 * `join` is handed to the act rather than imported by it so that nothing can be left connected: a
 * membership the act never closed is still closed here, in the order opposite to joining, because
 * a spoke outliving its hub reports a closed connection and not the refusal under test.
 */
async function onBus(context, label, act) {
  const root = path.join(context.workspaceRoot, `hub-${label}-${turn += 1}`);
  fs.mkdirSync(root, { recursive: true });
  const closers = [];
  const join = async (options = {}) => {
    const membership = await joinHub({ root, ...options });
    closers.push(() => membership.close());
    return membership;
  };
  try {
    return await act({ root, join, keep: (close) => closers.push(close) });
  } finally {
    for (const close of closers.reverse()) { try { close(); } catch { /* the pipe is going away regardless */ } }
  }
}

/**
 * A client channel that reports what it was told to report.
 *
 * The real one is an MCP session. These refusals read `describeClient()` and `supports()` and
 * refuse before anything is ever sent, so what the channel would do with a request never matters -
 * `request` is here only so the object is the shape the code destructures.
 */
const clientSaying = (client, declares = []) => ({
  describeClient: () => client,
  supports: (capability) => declares.includes(capability),
  request: async () => ({ content: { type: 'text', text: 'unused' }, model: 'unused', role: 'assistant' }),
});

const askPeerOf = (channel, hub) => makePeerTools({ channel, hub }).find((tool) => tool.name === 'peer.askPeer');

export function hubExercises() {
  return [
    {
      family: 'hub', tool: 'peer-hub.joinHub', expectThrow: 'PEER_HUB',
      call: () => joinHub({}),
      lesson: 'Joining the peer hub without a workspace root is refused PEER_HUB before any endpoint is touched. The root is not a convenience argument: the endpoint name is a digest of it, so a hub with no root would be a hub with a name shared by every checkout on the machine, and two unrelated Concord sessions would find each other. Refusing early is what keeps workspace isolation a property of the address rather than a rule someone has to remember.',
    },
    {
      family: 'hub', tool: 'peer-hub.joinHub', expectThrow: 'PEER_HUB_NO_TOKEN', workspace: 'temp',
      call: (context) => onBus(context, 'notoken', async ({ root, keep }) => {
        // Something is listening on exactly this workspace's endpoint and it is not a Concord hub,
        // so there is no token file beside it. This is the shape a stray process stumbling onto
        // the address takes, and the shape a half-removed hub leaves behind.
        const squatter = net.createServer();
        await new Promise((resolve) => squatter.listen(hubAddress(root).address, resolve));
        keep(() => squatter.close());
        return joinHub({ root, identity: identity('alpha') });
      }),
      lesson: 'A session that cannot bind the endpoint and cannot read a token refuses PEER_HUB_NO_TOKEN rather than connecting and hoping. The token is written by whoever bound the endpoint, so its absence means the listener on the other side did not write it - a stray process on the address, or a hub whose workspace was cleaned underneath it. Connecting anyway would send this session identity to an unidentified listener, which is the one thing the token exists to prevent.',
    },
    {
      family: 'hub', tool: 'peer-hub.ask', expectThrow: 'PEER_HUB_UNSERVED', workspace: 'temp',
      call: (context) => onBus(context, 'unserved', async ({ join }) => {
        const hub = await join({ identity: identity('alpha'), onServe: async () => ({ text: 'unused' }) });
        await join({ identity: identity('beta') });                   // connected, but answers nothing
        return hub.ask('beta', 'who is there?', { timeoutMs: 3000 });
      }),
      lesson: 'Asking a session that joined without a way to answer is refused PEER_HUB_UNSERVED, and the refusal comes back from that session rather than from the hub. Being on the bus and being able to answer are separate facts: a session joins to ask, to be listed, and to be told who else is present, none of which require it to serve. The code travels the whole route back to the asker, so a caller learns the target exists and will not answer - which is actionable in a way that a timeout is not.',
    },
    {
      family: 'hub', tool: 'peer-hub.ask', expectThrow: 'PEER_HUB_TIMEOUT', workspace: 'temp',
      call: (context) => onBus(context, 'timeout', async ({ join }) => {
        const hub = await join({ identity: identity('alpha') });
        await join({ identity: identity('gamma'), onServe: () => new Promise(() => {}) });   // accepts, never answers
        return hub.ask('gamma', 'who is there?', { timeoutMs: 200 });
      }),
      lesson: "A peer that accepts a question and never answers it costs the asker exactly its deadline and then PEER_HUB_TIMEOUT. The deadline is the caller's, clamped to the membership's: a per-ask timeout can only shorten it, so one caller cannot pin a session open past what the session agreed to. This is the failure the mailbox could not express at all - a letter is never late, it is just unread - and it is the reason the socket exists.",
    },
    {
      family: 'hub', tool: 'peer-hub.ask', expectThrow: 'PEER_HUB_UNKNOWN', workspace: 'temp',
      call: (context) => onBus(context, 'unknown', async ({ join }) => {
        const hub = await join({ identity: identity('alpha') });
        return hub.ask('nobody', 'who is there?', { timeoutMs: 2000 });
      }),
      lesson: 'Asking a name no connected session holds is refused PEER_HUB_UNKNOWN immediately, with the names that are present carried in the details. There is no queue of questions waiting for a session that might join later: membership is the live set of connected links, so an unknown name is a mistake now rather than a bet on the future. Naming the alternatives is the difference between a caller fixing a typo and a caller guessing.',
    },
    {
      family: 'hub', tool: 'peer-hub.ask', expectThrow: 'PEER_HUB_SELF', workspace: 'temp',
      call: (context) => onBus(context, 'self', async ({ join }) => {
        const hub = await join({ identity: identity('alpha'), onServe: async () => ({ text: 'unused' }) });
        return hub.ask(hub.peerId, 'who is there?', { timeoutMs: 2000 });
      }),
      lesson: "A session asking itself through the hub is refused PEER_HUB_SELF even though the route would work. It would work, and that is the problem: the hub would hand the question to the same client that asked it, which is a model prompting itself through two sockets and a broker while reporting the answer as another session's. The bus exists to reach a party this process cannot reach on its own, and refusing the degenerate case keeps every answer it carries attributable.",
    },
    {
      family: 'hub', tool: 'peer-hub.ask', expectThrow: 'PEER_HUB_CLOSED', workspace: 'temp',
      call: (context) => onBus(context, 'closed', async ({ join }) => {
        const hub = await join({ identity: identity('alpha') });
        await join({ identity: identity('gamma'), onServe: () => new Promise(() => {}) });
        const pending = hub.ask('gamma', 'left hanging', { timeoutMs: 9000 });
        hub.close();
        return pending;
      }),
      lesson: 'Closing a membership fails every question still in flight with PEER_HUB_CLOSED instead of letting them run out their deadlines. A shutdown is information: the answers cannot arrive now, and a caller told so at close can act nine seconds before a caller left waiting. The same settlement runs when the socket closes from the far side, so a hub that dies and a hub that is shut down look the same to a spoke - which is correct, because to a spoke they are.',
    },
    {
      family: 'hub', tool: 'peer-hub.joinHub', expectThrow: 'PEER_HUB_DENIED', workspace: 'temp',
      call: (context) => onBus(context, 'full', async ({ join }) => {
        // Sixteen joins fill the hub, not fifteen: the first of them is the one that binds the
        // endpoint, and it registers itself as a link like any other. Measured, after predicting
        // fifteen and watching the sixteenth be admitted - the bound held and the count was mine.
        // Joined sequentially on purpose: the bound is on the registry, not on a rate, and a
        // parallel burst would prove the wrong thing.
        for (let index = 0; index < 16; index += 1) await join({ identity: identity('spoke' + index) });
        return join({ identity: identity('one-too-many') });
      }),
      lesson: "A hub already routing its sixteen links refuses the next session, and the refusal arrives as PEER_HUB_DENIED carrying the message - never as PEER_HUB_FULL, which is the code actually thrown. The session that bound the endpoint occupies one of those sixteen, so fifteen others fill it and a sixteenth guest is turned away. The throw happens inside the hub's own connection handler, which converts any registration failure into a denial frame holding only a reason string, so the code does not survive the process boundary it was raised at. Worth knowing in both directions: a bound is enforced where it belongs, and a code that never crosses a socket cannot be the thing a remote caller branches on.",
    },
    {
      family: 'hub', tool: 'peer-hub.ask', expectThrow: 'PEER_HUB_TRANSPORT', workspace: 'temp',
      call: (context) => onBus(context, 'unframeable', async ({ join }) => {
        await join({ identity: identity('alpha'), onServe: async () => ({ text: 'unused' }) });
        const spoke = await join({ identity: identity('beta') });
        // A BigInt is exactly what canonical() refuses, and a spoke frames its own asks.
        return spoke.ask('alpha', 1n, { timeoutMs: 2000 });
      }),
      lesson: 'A question that cannot be represented as JSON is refused PEER_HUB_TRANSPORT by the session trying to send it, before anything reaches the wire. The framing failure is PEER_HUB_FRAME one layer down and is deliberately reported as a transport failure to the caller: from where the caller stands the question did not go anywhere, and which half of the socket write failed is not a distinction it can act on. The hub reports the same code when it cannot write to the session it was routing to, for the same reason.',
    },
    {
      family: 'hub', tool: 'peer-hub.serve', expectThrow: 'PEER_HUB_FRAME', workspace: 'temp',
      call: (context) => onBus(context, 'unframeableanswer', async ({ join }) => {
        const hub = await join({ identity: identity('alpha') });
        await join({ identity: identity('beta'), onServe: async () => ({ text: 1n }) });
        return hub.ask('beta', 'who is there?', { timeoutMs: 3000 });
      }),
      lesson: 'An answer that cannot be represented as JSON comes back to the asker as PEER_HUB_FRAME, because the serving session fails to frame it, describes that failure, and sends the description instead. The recovery is the interesting part: the second frame is small and always representable, so a session whose model returned something unserialisable still answers - with the reason it could not answer - rather than timing out and leaving the asker to guess. Only representable details are ever forwarded, which is what keeps a failed answer from becoming a failed transport.',
    },
    {
      family: 'hub', tool: 'peer.hubResponder', expectThrow: 'PEER_HUB_NO_CLIENT',
      call: () => createHubResponder({ channel: clientSaying(null) })({ question: 'who is there?', from: 'alpha' }),
      lesson: 'A brokered question arriving at a session whose client has not completed initialize is refused PEER_HUB_NO_CLIENT. The session can be on the bus before its client has said anything - tools are registered, the hub is joined, the link is live - and none of that means there is a model behind it yet. Answering would mean inventing the answer, so the asker is told the target is not ready rather than handed something Concord wrote.',
    },
    {
      family: 'hub', tool: 'peer.hubResponder', expectThrow: 'PEER_HUB_NO_SAMPLING',
      call: () => createHubResponder({ channel: clientSaying({ name: 'claude', capabilities: ['elicitation'] }) })({ question: 'who is there?', from: 'alpha' }),
      lesson: "A session whose client never declared sampling cannot be asked, and says so by name with PEER_HUB_NO_SAMPLING and the capabilities it does have. This is the one refusal the broker genuinely cannot route around: there is no way to put text in front of that client's model, and the asymmetry is real rather than hypothetical - Claude Code declares elicitation and not sampling, so it can ask another session and cannot be asked by one. The details carry the capability list because the caller's next move depends on what the target can do instead.",
    },
    {
      family: 'hub', tool: 'peer.hubResponder', expectThrow: 'PEER_HUB_UNANSWERED', workspace: 'temp',
      call: (context) => {
        const mailbox = path.join(context.workspaceRoot, `hub-rendezvous-${turn += 1}`);
        fs.mkdirSync(mailbox, { recursive: true });
        return createHubResponder({
          channel: clientSaying({ name: 'claude', capabilities: ['elicitation'] }),
          mailboxDir: mailbox, rendezvousMs: 250,
        })({ question: 'who is there?', from: 'alpha' });
      },
      lesson: 'Given a mailbox, a session that cannot be sampled falls back to parking the question as a letter and waiting for its own agent to answer it - and when nobody does, PEER_HUB_UNANSWERED carries the sequence number of the letter that is still sitting there. The fallback is why the bus is not one-way for the most common client, and the sequence number is why the failure is recoverable: an error rebuilt from code and message alone would say something went wrong without saying where to go and look.',
    },
    {
      family: 'hub', tool: 'peer.askPeer', expectThrow: 'PEER_HUB_UNJOINED',
      call: () => askPeerOf(clientSaying({ name: 'claude', capabilities: ['sampling'] }, ['sampling']))
        .execute({ to: 'codex', question: 'who is there?' }, { policy: { timeoutMs: 5000 } }),
      lesson: 'peer.askPeer refuses PEER_HUB_UNJOINED when this session is not on the bus, which is the only refusal in this family a plan can reach directly. Membership is resolved at call time rather than at registration, because tools are built before any client has sent initialize and the hub cannot be joined until it has: the tool therefore exists on a session that may join later, and answers honestly about right now.',
    },
    {
      family: 'hub', tool: 'peer.askPeer', expectThrow: 'PEER_HUB_UNKNOWN', workspace: 'temp',
      call: (context) => onBus(context, 'askpeer', async ({ join }) => {
        const hub = await join({ identity: identity('alpha') });
        return askPeerOf(clientSaying({ name: 'claude', capabilities: ['sampling'] }, ['sampling']), () => hub)
          .execute({ to: 'nobody', question: 'who is there?' }, { policy: { timeoutMs: 5000 } });
      }),
      lesson: 'A joined session asking for a name nobody holds is refused PEER_HUB_UNKNOWN by the tool itself, before the hub is written to at all. The hub would refuse the same name a moment later, so the check is a duplicate on purpose: refusing locally lets the error name the connected peers, and spends no round trip on a question that cannot be routed.',
    },
  ];
}
