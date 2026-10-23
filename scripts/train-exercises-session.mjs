import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createClientChannel, makePeerTools } from '../src/peer.mjs';
import { makeSourceTools, loadSourceLock } from '../src/sources.mjs';
import { makeReverseTools } from '../src/reverse.mjs';
import { makeInstructionTools, splitTrained } from '../src/instructions.mjs';
import { buildChatContext } from '../src/chat-context.mjs';
import { main as mcpMain, mcpNameFor } from '../src/mcp.mjs';
import { main as cliMain } from '../src/cli.mjs';
import { startChatServer } from '../src/app.mjs';
import { checkAppUrl, findAppBrowser, appWindowArgv, launchAppWindow } from '../src/desktop.mjs';
import { createChatHarness } from '../src/chat.mjs';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { digest, parseJson } from '../src/value.mjs';

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
 * Every code below was raised for real first, and several attempts along the way were wrong in ways
 * worth recording. A pending question's deadline timer is unref'd — deliberately, so a question
 * never keeps the process alive — which means awaiting PEER_TIMEOUT in a bare script lets the
 * process exit before it fires; it needs a ref'd keepalive, and the exercises below carry one.
 * Calling peer.request with `prompt` instead of `message` produced PEER_REQUEST rather than a
 * schema error, because a direct call bypasses the engine's validation — the same trap that made
 * skills.rank look broken.
 *
 * DIGEST_MISMATCH took four wrong attempts and is worth the detail. A plain markdown file, a
 * README, a bare SKILL.md and a SKILL.md without YAML frontmatter all answer SKILL_INVALID, and
 * the digest is never compared at all. It was briefly written off here as unreachable on that
 * evidence, which was the wrong conclusion from a real observation: the snapshot has to succeed
 * before the digest check is the thing being tested.
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

/** The committed reverse table, for the config refusals that need a valid one. */
const reverseTable = () => parseJson(fs.readFileSync(path.join(root, 'reverse-tools.json'), 'utf8'));

/**
 * Making a file unreadable, so the filesystem catch-all can be reached at all.
 *
 * SOURCE_READ_FAILED sits behind the specific errors — a missing path answers SOURCE_NOT_FOUND, a
 * forbidden character PATH_DENIED, a symlink loop PATH_DENIED — so reaching it needs a fault that
 * is none of those. A denied read is the one such fault that can be arranged without elevation.
 *
 * Whether it can be arranged is checked rather than assumed: chmod is largely advisory for reads
 * on Windows and ACLs do not exist elsewhere, so the capability is probed once at load and the
 * exercise is simply absent where it does not hold. A machine that cannot deny itself a read
 * should report one fewer exercise, not a finding about its own filesystem.
 */
const denyRead = (file) => {
  if (process.platform === 'win32') execFileSync('icacls', [file, '/deny', `${process.env.USERNAME}:(R)`], { stdio: 'pipe' });
  else fs.chmodSync(file, 0o000);
};
const restoreRead = (file) => {
  try {
    if (process.platform === 'win32') execFileSync('icacls', [file, '/remove:d', process.env.USERNAME ?? ''], { stdio: 'pipe' });
    else fs.chmodSync(file, 0o600);
  } catch { /* best effort: the scratch directory is disposable either way */ }
};

const CAN_DENY_READ = (() => {
  let probeDir = null;
  try {
    probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'concord-acl-probe-'));
    const file = path.join(probeDir, 'probe.md');
    fs.writeFileSync(file, 'probe\n');
    denyRead(file);
    let unreadable = false;
    try { fs.readFileSync(file); } catch { unreadable = true; }
    restoreRead(file);
    return unreadable;
  } catch { return false; }
  finally { if (probeDir) { try { fs.rmSync(probeDir, { recursive: true, force: true }); } catch { /* disposable */ } } }
})();

const sourceTools = () => loadSourceLock(path.join(root, 'sources.lock.json'))
  .then((catalog) => ({ tools: byName(makeSourceTools(catalog)), sourceId: catalog.sources[0].id }));

/**
 * The adaptive loop, exercised rather than assumed: a lesson earned, then recalled by a later turn.
 *
 * This is the one claim the round could not previously make about itself. Every other exercise
 * proves something about a tool; this proves that what the round *writes* reaches the next
 * conversation. A promoted lesson is a file in `memory/`, `memory.recall` is a read effect, and
 * chat.mjs fetches the best-scoring lesson for the incoming message and splices it into the turn
 * before any model is asked. If that path broke, the round would keep promoting lessons into a
 * directory nothing reads, and nothing in the suite would notice: coverage, codes and composition
 * would all stay green while the harness quietly stopped learning.
 *
 * Driven with a pure proposal stand-in rather than a model, because this harness has no
 * demonstration mode to fall back to: send() refuses CHAT_NO_MODEL without one. The recalled
 * lesson is therefore observed in the prompt that stand-in records rather than in a model's
 * prose - the only form of this claim that can be checked deterministically, and the same form
 * test/chat-flow.test.mjs checks.
 */
const RECALLED_LESSON = 'When reviewing changes for security vulnerabilities, check the authentication boundaries first.';
const RECALL_QUERY = 'Review this change for security vulnerabilities around authentication.';

function storeLesson(dir) {
  const candidate = { version: 1, lesson: RECALLED_LESSON, evidenceHashes: [digest('a-training-round-earned-this')], status: 'proposed', executable: false };
  const candidateHash = digest(candidate);
  fs.mkdirSync(path.join(dir, 'memory'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'memory', `${candidateHash}.json`), JSON.stringify({ ...candidate, candidateHash }) + '\n');
}

/**
 * The stand-in that lets a turn be exercised at all.
 *
 * There is no demonstration mode in this harness: a turn needs a model to propose, or send()
 * refuses CHAT_NO_MODEL before it mutates anything. The exercises here are about context
 * assembly and enrichment rather than about a model call, so they supply one. Declared `pure`
 * because it reaches no network, which is what keeps these turns from stopping at a grant - the
 * same stand-in, for the same stated reason, as test/chat-flow.test.mjs.
 *
 * It records the prompt it was given. That is the whole instrument: what reached the model is the
 * only place an enrichment can be observed without asking a model to describe its own input.
 */
let lastProposalPrompt = null;
const proposalFixture = {
  name: 'model.propose', version: 'fixture-1', effect: 'pure',
  inputSchema: { type: 'object' }, config: { fixture: true },
  execute(input) {
    lastProposalPrompt = parseJson(input.prompt);
    return { model: 'fixture-1', proposal: {
      reply: 'Proposed a pure-tool plan over the reviewed sources.',
      plan: { version: 1, tasks: [{ id: 'coverage', tool: 'sources.catalog', input: {} }] },
    } };
  },
};

/** A chat harness over the round's own registry plus the proposal stand-in, pointed at the scratch workspace. */
async function chatOver({ registry, policy, workspaceRoot }) {
  const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
  const inventory = parseJson(fs.readFileSync(path.join(root, 'capabilities.lock.json'), 'utf8'));
  // Added rather than substituted, and the policy widened to match: a tool absent from
  // allowedTools is filtered out of the turn entirely, so registering the stand-in without
  // naming it here would leave the session with nothing able to propose.
  const withProposal = new Map([...registry, [proposalFixture.name, proposalFixture]]);
  const turnPolicy = { ...policy, allowedTools: [...new Set([...policy.allowedTools, proposalFixture.name])] };
  const buildContext = ({ message, history, observations, proposedPlan, policy: contextPolicy }) => buildChatContext({
    message, history, observations, proposedPlan, policy: contextPolicy,
    sourceLock: catalog, inventory, registry: withProposal, instructionRoot: path.join(root, 'instructions'),
  });
  return createChatHarness({ registry: withProposal, policy: turnPolicy, sourceLock: catalog, workspaceRoot, buildContext });
}

/**
 * The session's own four refusals, which no plan can reach.
 *
 * These are the chat surface rather than a tool: a malformed hash, a hash nothing is waiting for,
 * an execute with nothing proposed, a replay of a run that does not exist. Each is the boundary
 * between an operator's intent and the kernel, and each is worth proving reachable because the
 * alternative to a named refusal here is a harness that quietly does nothing.
 */
const chatRefusals = () => [
  { code: 'CHAT_INPUT', what: 'a request hash that is not a SHA-256',
    act: (harness) => harness.approve('not-a-hash-at-all'),
    lesson: 'chat refuses CHAT_INPUT for anything that is not a lowercase SHA-256 hex string, before it looks at what is pending. An approval is the one input that carries authority, so its shape is checked first and separately from whether it matches: "that is not a hash" and "no such approval is waiting" are different mistakes and an operator should be told which they made.' },
  { code: 'CHAT_APPROVAL', what: 'a well-formed hash nothing is waiting for',
    act: (harness) => harness.approve('a'.repeat(64)),
    lesson: 'A well-formed hash that does not match the pending request is refused CHAT_APPROVAL rather than stored for later. There is no queue of future approvals: a grant applies to exactly the operation that blocked, so an approval arriving for anything else is a mistake to report and never a permission to keep.' },
  { code: 'CHAT_PLAN', what: 'an execute with nothing proposed',
    act: (harness) => harness.executePlan(),
    lesson: 'Executing with no proposed plan is refused CHAT_PLAN. The session never invents a plan to run, not even an empty one, so "execute" with nothing proposed is a caller error rather than a no-op — which keeps the proposal step visible instead of letting a turn slide into execution.' },
  { code: 'CHAT_REPLAY', what: 'a replay of a run id that does not exist',
    act: (harness) => harness.replay('no-such-run-id'),
    lesson: 'Replaying an unknown run id is refused CHAT_REPLAY rather than answering with an empty result. The run ledger is content-addressed and never truncated, so an id that is absent means it was never recorded here, and saying so is more useful than a successful-looking reply about nothing.' },
];

export function sessionExercises() {
  return [
    {
      family: 'session', tool: 'mcp.main', expectThrow: 'MCP_USAGE',
      call: () => mcpMain(['--not-a-flag', 'value']),
      lesson: 'The MCP server refuses MCP_USAGE for a flag it does not recognise, before it builds a registry or opens stdio. Every flag it does accept names a file of reviewed configuration, so an unrecognised one means the operator intended a capability this build cannot provide - and starting anyway would present a tool surface that silently lacks it. A repeated flag is refused by the same guard, because the second value would otherwise win without anyone saying so.',
    },
    {
      family: 'session', tool: 'chat.buildContext', expectThrow: 'CHAT_CONTEXT', workspace: 'temp',
      fixture: (dir) => {
        const root = path.join(dir, 'oversized-instructions');
        fs.mkdirSync(root, { recursive: true });
        // Larger than the 64 KiB bound the manifest read is given.
        fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({ padding: 'x'.repeat(70_000) }));
      },
      call: ({ registry, policy, workspaceRoot }) => buildChatContext({
        message: 'anything', history: [], observations: [], proposedPlan: null, policy,
        sourceLock: { sources: [] }, inventory: { capabilities: [] }, registry,
        instructionRoot: path.join(workspaceRoot, 'oversized-instructions'),
      }),
      lesson: 'An instruction manifest larger than its 64 KiB bound is refused CHAT_CONTEXT rather than read, and the refusal names the file. The turn context is the one place where reviewed text is assembled into what a model sees, so a bound there is not about memory - it is the limit on how much instruction can enter a turn without anyone having re-reviewed it. Reading the file first and checking afterwards would make the bound advisory.',
    },
    {
      family: 'session', tool: 'instructions.lesson', expectCode: 'INSTRUCTION_LIMIT',
      // 340, measured: one missing id answers in 360 bytes, so the output bound fires here while
      // the input stays small. Sixteen ids tripped the engine's INPUT_INVALID instead, because a
      // request large enough to grow the answer is already too large itself - the two bounds leave
      // only a narrow window, and this is inside it.
      narrow: { maxOutputBytes: 340 },
      plan: { version: 1, name: 'ask-for-a-lesson-under-a-tiny-budget', tasks: [
        { id: 'a', tool: 'instructions.lesson', input: { ids: ['nothing:such-lesson'] } },
      ] },
      lesson: 'A lesson fetch whose own result would exceed the output budget is refused INSTRUCTION_LIMIT by the tool, naming how many were requested - and it is reachable at a budget small enough that even the disclaimer travelling with every answer does not fit. That disclaimer is the reason the check exists: the result always carries the statement that a lesson records an observation and grants no capability, so the tool would rather refuse than return lessons with the caveat trimmed off to make room. The window is narrow and was found by measuring: one missing id answers in 360 bytes, so a 340-byte budget reaches this code, while asking for sixteen ids to grow the answer trips the engine own INPUT_INVALID first - a request big enough to make the output big is already too big itself.',
    },
    /**
     * The desktop window's own refusals, which are decided before anything is launched.
     *
     * None of this is a tool: it is the argv for a Chromium opened in application mode, and every
     * check below exists because that argv ends up in the process table of a machine the operator
     * is sitting at. A plan cannot reach any of it, which is exactly why it is exercised here.
     */
    {
      family: 'session', tool: 'desktop.checkAppUrl', expectThrow: 'DESKTOP_URL',
      call: () => checkAppUrl('http://localhost:7000/'),
      lesson: 'The window URL is refused DESKTOP_URL unless it is http on a loopback *address*, with no credentials, no query, no fragment and the root path - and localhost is refused by name, because the local server authorizes on an exact Host match and a name that resolves differently is a different server. Refusing a query string is not fussiness either: the URL reaches the process table, where anything in it is readable by every other process on the machine.',
    },
    {
      family: 'session', tool: 'desktop.findAppBrowser', expectThrow: 'DESKTOP_BROWSER',
      call: () => findAppBrowser({ platform: 'win32', env: { CONCORD_BROWSER: 'C:/nowhere/chrome.exe' }, exists: () => false }),
      lesson: 'CONCORD_BROWSER naming a file that is not there is refused DESKTOP_BROWSER rather than falling back to a browser the operator did not choose. An override exists so somebody can be specific, so silently searching the usual locations after being told exactly which binary to use would discard the instruction and open a different program than the one named.',
    },
    {
      family: 'session', tool: 'desktop.appWindowArgv', expectThrow: 'DESKTOP_PROFILE',
      call: () => appWindowArgv({ url: 'http://127.0.0.1:7000/', profileDir: 'relative/profile' }),
      lesson: 'A relative profile directory is refused DESKTOP_PROFILE. The window gets a private profile so it shares nothing with the browser the operator browses with, and a relative path would resolve against whatever directory the host process happened to start in - which is not a statement about where the profile is.',
    },
    {
      family: 'session', tool: 'desktop.appWindowArgv', expectThrow: 'DESKTOP_WINDOW',
      call: () => appWindowArgv({ url: 'http://127.0.0.1:7000/', profileDir: 'C:/concord/profile', windowSize: 'as-big-as-possible' }),
      lesson: 'A window size that is not two plain pixel counts is refused DESKTOP_WINDOW. The value becomes a command-line flag, so accepting arbitrary text would let a configuration string become an argument to the browser rather than a size - the same reason every other value on this argv is pattern-checked before it is passed.',
    },
    {
      family: 'session', tool: 'desktop.launchAppWindow', expectThrow: 'DESKTOP_LAUNCH',
      call: async () => {
        const { closed } = launchAppWindow({
          executable: 'C:/nowhere/chrome.exe', url: 'http://127.0.0.1:7000/',
          profileDir: 'C:/concord/profile', windowSize: '1180,860',
        });
        return closed;
      },
      lesson: 'A browser executable that cannot be started rejects DESKTOP_LAUNCH on the promise the caller waits on, rather than resolving as though a window had opened. The distinction matters because the desktop entry point treats that promise as "the window is open until it closes": resolving on a failed spawn would report a window the operator never saw and then exit as if they had closed it.',
    },
    ...chatRefusals().map((entry) => ({
      family: 'session', tool: 'chat.' + entry.code.toLowerCase().replace('chat_', ''),
      expectThrow: entry.code, workspace: 'temp',
      call: async (context) => entry.act(await chatOver(context)),
      lesson: entry.lesson,
    })),
    {
      family: 'session', tool: 'chat.recall', workspace: 'temp', fixture: storeLesson,
      call: async (context) => {
        const harness = await chatOver(context);
        lastProposalPrompt = null;
        const turn = await harness.send(RECALL_QUERY);
        const recalled = lastProposalPrompt?.references?.memory ?? null;
        return {
          mode: turn.mode,
          // Observed where the lesson actually lands: in the prompt the model was given. Reading
          // it back out of the proposed plan would only prove the stand-in copied it forward.
          reachedTheModel: typeof recalled?.lesson === 'string' && recalled.lesson.includes('authentication boundaries'),
          // It travels with its evidence standing, which is what keeps a recalled lesson
          // reference rather than authority: nothing here can ground it, and the turn says so.
          groundedCount: recalled?.evidence?.groundedCount ?? null,
          unverifiedHereCount: recalled?.evidence?.unverifiedHereCount ?? null,
          truncated: recalled?.truncated ?? null,
          // Measured rather than predicted on the first attempt: one of the three runs fails, and
          // asserting "every run completed" turned a healthy turn into a finding.
          statuses: turn.runs.map((run) => run.status).join(','),
          noPendingApproval: !turn.pending,
          replied: turn.history.some((entry) => entry.role === 'assistant' && entry.content.length > 0),
        };
      },
      expect: (r) => r.mode === 'live' && r.reachedTheModel === true
        && r.groundedCount === 0 && r.unverifiedHereCount === 1 && r.truncated === false
        && r.noPendingApproval === true && r.replied === true
        && r.statuses === 'failed,completed,completed',
      lesson: 'A lesson this harness earned in an earlier round is recalled by a later turn and reaches the model as reference data, before the model is asked anything. That is the whole of what makes this harness adaptive without touching a weight: memory.recall scores the stored lessons against the incoming message and the best match travels into the turn under references.memory, as its own read-effect plan that never produces a pending approval - so experience changes the next turn without ever becoming an authority to act. It arrives carrying its evidence standing rather than as a bare sentence: groundedCount 0 and unverifiedHereCount 1 state plainly that nothing in this workspace can verify the lesson, so the model is told what the claim is worth instead of being handed it as established. The turn runs in live mode with a pure proposal stand-in, because this harness has no demonstration mode: send() refuses CHAT_NO_MODEL without a model, so the earlier form of this exercise - which asserted an offline-demo mode and read the recalled text back out of the proposed plan - was asserting a mode that had been removed. Observing the prompt instead is also the stronger claim: a recalled lesson found in the proposed plan only proves the stand-in copied it forward, whereas finding it in the prompt proves it reached whatever is deciding. One turn is three plans, and their statuses here are failed, completed, completed: the skill enrichment fails because this scratch workspace holds no skill corpus, and the turn is entirely unaffected - the memory enrichment completes, the lesson still reaches the model, and the primary run still replies. Predicting that every run completed was the first version of this exercise, and the round reported it as a finding rather than promoting it, which is the discipline working: every number above was measured and only then written down.',
    },
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
    {
      family: 'catalog', tool: 'skills.snapshot', expectThrow: 'DIGEST_MISMATCH', workspace: 'temp',
      // A valid skill is the precondition, and finding that out took four failed attempts: a plain
      // markdown file, a README, a bare SKILL.md and a SKILL.md with no frontmatter all answer
      // SKILL_INVALID long before any digest is compared. The snapshot has to succeed for the
      // digest check to be the thing under test.
      fixture: (dir) => {
        fs.mkdirSync(path.join(dir, 'digest-skill'), { recursive: true });
        fs.writeFileSync(path.join(dir, 'digest-skill', 'SKILL.md'),
          '---\nname: digest-skill\ndescription: A valid skill a training exercise snapshots.\n---\n\n# Digest Skill\n\nDo the thing.\n');
      },
      call: async ({ workspaceRoot }) => {
        const { tools, sourceId } = await sourceTools();
        return tools.get('skills.snapshot').execute(
          { path: 'digest-skill', sourceId, expectedDigest: 'd'.repeat(64) },
          { workspaceRoot, policy: toolPolicy },
        );
      },
      lesson: 'skills.snapshot refuses DIGEST_MISMATCH when the snapshot it captured does not hash to the expectedDigest the caller named, and only reaches that comparison for a snapshot that otherwise succeeded. Passing the digest you already believe is the point: it turns a read into a verification, so a corpus that moved under you is reported rather than returned as though it were what you asked for.',
    },

    /**
     * The reverse family, which needs a provider the operator reviewed.
     *
     * No provider is configured in this deployment, so these build their own table and a dummy
     * executable rather than depending on one being installed. Two things were learned the hard
     * way: providers are declared in the *config* and not in the table, and the resulting tool has
     * to be in allowedTools or limits() refuses it as INTEGRATION_POLICY before any of this is
     * reached. Neither spawns anything — both refusals land before the process would start.
     */
    {
      family: 'catalog', tool: 'reverse.factory', expectThrow: 'REVERSE_CONFIG',
      call: () => makeReverseTools(reverseTable(), { nonsense: true }),
      lesson: 'makeReverseTools refuses REVERSE_CONFIG for a configuration field it does not recognise, naming the field. The configuration decides which executables may run, so an unrecognised key is treated as a reviewer having meant something the code cannot honour rather than as noise to skip.',
    },
    {
      family: 'catalog', tool: 'rea.provider', expectThrow: 'REVERSE_INPUT', workspace: 'temp',
      call: ({ workspaceRoot }) => {
        // workspace: 'temp' is load-bearing. Without it this writes its stand-in executable into
        // the repository root, which is how 512 filler schedules got committed two rounds ago.
        const executable = path.join(workspaceRoot, 'reviewed-tool.bin');
        fs.writeFileSync(executable, 'a stand-in for a reviewed executable');
        const executableSha256 = createHash('sha256').update(fs.readFileSync(executable)).digest('hex');
        const table = {
          schemaVersion: 1, revision: 'a'.repeat(40), sourceId: 'training',
          tools: [{ name: 'training_tool', provider: 'training', effect: 'process', basis: 'runs a reviewed executable', implementedBy: null, internalizable: false, module: 'training' }],
        };
        const tools = makeReverseTools(table, { providers: [{ name: 'training', executable, executableSha256, commands: { training_tool: ['--path', '{path}'] } }] });
        const tool = tools.find((candidate) => candidate.name === 'rea.training_tool');
        return tool.execute({ path: '-not-a-path' }, {
          workspaceRoot,
          policy: { ...toolPolicy, allowedTools: tools.map((candidate) => candidate.name).sort(), allowedEffects: ['pure', 'read', 'write', 'network', 'process'] },
        });
      },
      lesson: 'A value filling an argv template slot may not begin with a dash, and is refused REVERSE_INPUT naming the slot. Argv comes only from a reviewed template, and a slot value that looks like a flag is how a path turns into an option the reviewer never approved — so it is rejected while the command line is being built, before any process exists.',
    },

    /**
     * The race the capture checks exist to catch, induced rather than waited for.
     *
     * snapshotFile stats the path, opens it, stats the handle, reads, then stats both the handle
     * and the path again. The handle's view is pinned to the inode it opened while the path can be
     * rewritten underneath it, and sameFile compares mtime and ctime as well as identity and size —
     * so touching a file during the capture is enough to be caught.
     *
     * Reliability came from the shape of the fixture rather than from luck. One 64 KiB file hit the
     * race 17 times in 20, which is exactly the flakiness that makes an exercise worse than none.
     * Twelve files hit it 25 times out of 25, because each file is its own capture window and the
     * toucher only has to land inside one of them. A file large enough to lengthen the window does
     * not help: anything over the bounded read size is refused OUTPUT_LIMIT before the race begins.
     * The retry below is insurance on a machine faster or slower than this one, and in measurement
     * every run succeeded on its first attempt.
     */
    {
      family: 'catalog', tool: 'skills.snapshot', expectThrow: 'SOURCE_CHANGED', workspace: 'temp',
      call: async ({ workspaceRoot }) => {
        const skill = path.join(workspaceRoot, 'rewritten-skill');
        const build = () => {
          fs.rmSync(skill, { recursive: true, force: true });
          fs.mkdirSync(skill, { recursive: true });
          const files = [path.join(skill, 'SKILL.md')];
          fs.writeFileSync(files[0],
            '---\nname: rewritten-skill\ndescription: A skill rewritten while it is being captured.\n---\n\n# Rewritten\n\n'
            + 'word '.repeat(3200));
          for (let index = 1; index < 12; index += 1) {
            const part = path.join(skill, 'part-' + index + '.md');
            fs.writeFileSync(part, '# part ' + index + '\n' + 'word '.repeat(3200));
            files.push(part);
          }
          return files;
        };

        const { tools, sourceId } = await sourceTools();
        let last = null;
        for (let attempt = 0; attempt < 12; attempt += 1) {
          const files = build();
          const touching = setInterval(() => {
            const now = new Date();
            for (const file of files) {
              try { fs.utimesSync(file, now, now); } catch { /* momentarily unavailable mid-capture */ }
            }
          }, 1);
          try {
            await tools.get('skills.snapshot').execute({ path: 'rewritten-skill', sourceId }, { workspaceRoot, policy: toolPolicy });
          } catch (error) {
            last = error;
            if (error?.code === 'SOURCE_CHANGED') throw error;
          } finally {
            clearInterval(touching);
          }
        }
        // Twelve clean captures in a row would mean the race never happened, which is a finding
        // about the fixture rather than a passing exercise — so say that instead of staying quiet.
        throw last ?? new Error('the capture never raced in twelve attempts');
      },
      lesson: 'A skill file whose timestamps change while it is being captured is refused SOURCE_CHANGED, and the check runs twice: once between stating the path and stating the open handle, and again after the bytes are read, comparing the handle against a fresh stat of the path. The handle stays pinned to the inode it opened while the path can be replaced underneath it, so those two views disagreeing is the only evidence that a file moved mid-capture. A snapshot is a claim that these exact bytes were on disk together, and a file that changed halfway through would make that claim false.',
    },

    /**
     * Compaction and retrieval, checked as one thing rather than two.
     *
     * A declared omission is only honest if the omitted thing can still be reached. These two
     * halves were written in separate commits and could drift apart silently — the selector could
     * change how it builds an id and the store would simply stop finding anything, with both sides
     * looking correct in isolation. So the property asserted is the round trip: every id a real
     * turn declares as omitted resolves to a real lesson.
     */
    {
      family: 'catalog', tool: 'instructions.lesson',
      call: async () => {
        const directory = path.join(root, 'instructions');
        const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
        const inventory = parseJson(fs.readFileSync(path.join(root, 'capabilities.lock.json'), 'utf8'));
        const registry = new Map(makeSourceTools(catalog).map((tool) => [tool.name, tool]));
        const context = buildChatContext({
          message: 'how do I compare two wasm interfaces where one side is partial',
          history: [], sourceLock: catalog, inventory, registry, instructionRoot: directory,
        });
        const store = makeInstructionTools({ directory })[0];
        const asked = context.trained.omittedIds.slice(0, 64);
        const fetched = store.execute({ ids: asked }, { workspaceRoot: root, policy: toolPolicy });
        // Derived independently, so the assertion below compares the fetched text against the
        // module rather than against the store's own view of it.
        const expected = new Map();
        for (const file of fs.readdirSync(directory).filter((name) => name.endsWith('.md'))) {
          for (const lesson of splitTrained(file.replace(/\.md$/, ''), fs.readFileSync(path.join(directory, file), 'utf8')).lessons) {
            expected.set(lesson.id, lesson.text);
          }
        }
        return { declared: context.trained, fetched, asked, expected: [...expected] };
      },
      expect: ({ declared, fetched, asked, expected }) => {
        const texts = new Map(expected);
        return declared.omittedCount > 0 && declared.omittedIds.length === declared.omittedCount
          // Unique ids, which is the assertion that matters. The first version of this id was the
          // source and tool name alone, so several lessons for one tool collided: the store kept
          // whichever it parsed first and returned it for every id in the family. Nothing was ever
          // reported missing, so only comparing the text exposes it.
          && new Set(declared.omittedIds).size === declared.omittedIds.length
          && fetched.missing.length === 0 && fetched.returned === asked.length
          && fetched.lessons.every((lesson) => lesson.text === texts.get(lesson.id));
      },
      lesson: 'Every lesson a turn declares as omitted can be fetched back by the id it was declared under, and the text that comes back is the text that was dropped — not merely some lesson for the same tool. Ids are content-addressed for exactly that reason: a tool may have several lessons, so naming one by its tool alone collided, and the store answered every id in the family with whichever it parsed first while reporting nothing missing. The selecting half and the retrieving half share one parser, so they cannot disagree about what an id means.',
    },
    {
      family: 'catalog', tool: 'instructions.lesson',
      call: () => {
        const directory = path.join(root, 'instructions');
        // Derived, never pinned. An id carries a digest of its lesson's text, so writing one into
        // an exercise would make it stale the next time that lesson is reworded — which is exactly
        // what happened the first time this was written, and the round reported it.
        const [real] = splitTrained('rea', fs.readFileSync(path.join(directory, 'rea.md'), 'utf8')).lessons;
        return makeInstructionTools({ directory })[0]
          .execute({ ids: [real.id, 'rea:not.a.real.tool@000000000000'] }, { workspaceRoot: root, policy: toolPolicy });
      },
      expect: (r) => r.requested === 2 && r.returned === 1 && r.missing.length === 1
        && r.missing[0] === 'rea:not.a.real.tool@000000000000' && r.lessons[0].sourceId === 'rea'
        && r.limitations.some((note) => /grants no capability/.test(note)),
      lesson: 'An id that resolves to nothing is reported in `missing` rather than raised as a refusal, so a batch fetch returns the lessons it found and names the ones it did not. A caller is usually working from an omission record a turn or two old, and failing the whole request because one id went stale would be less useful than saying which. The result also states plainly that a lesson grants no capability: it is an observation about behaviour, not an approval.',
    },
    {
      family: 'catalog', tool: 'instructions.factory', expectThrow: 'INSTRUCTION_CONFIG',
      call: () => makeInstructionTools({ directory: 'instructions' }),
      lesson: 'The instruction store refuses INSTRUCTION_CONFIG for a relative directory, the same rule the mailbox and the workspace root follow. A location that depends on the current working directory is not a location, and this store decides which text is served as reviewed instruction.',
    },
    {
      family: 'catalog', tool: 'instructions.lesson', expectThrow: 'INSTRUCTION_STORE', workspace: 'temp',
      call: ({ workspaceRoot }) => {
        // A module whose bytes no longer match the digest the manifest recorded for it.
        const directory = fs.mkdtempSync(path.join(workspaceRoot, 'tampered-instructions-'));
        const body = '# rea\n\nReviewed text.\n\n<!-- trained:begin -->\n- `artifact.dex` — a proven lesson.\n<!-- trained:end -->\n';
        fs.writeFileSync(path.join(directory, 'rea.md'), body);
        const recorded = createHash('sha256').update(Buffer.from(body)).digest('hex');
        fs.writeFileSync(path.join(directory, 'manifest.json'), JSON.stringify({
          schemaVersion: 1, modules: [{ sourceId: 'rea', file: 'rea.md', sha256: recorded, bytes: Buffer.byteLength(body) }],
        }));
        // Edited after the digest was recorded, which is exactly the case the check exists for.
        fs.writeFileSync(path.join(directory, 'rea.md'), body.replace('a proven lesson', 'something nobody reviewed'));
        return makeInstructionTools({ directory })[0].execute({ ids: ['rea:artifact.dex'] }, { workspaceRoot, policy: toolPolicy });
      },
      lesson: 'The store verifies every module against its manifest digest before returning any text, and refuses INSTRUCTION_STORE when they disagree. This is the check that keeps retrieval from being the weaker of two routes to the same bytes: the turn context already verifies digests, so a retrieval path that did not would be a way to read instruction text no reviewer signed.',
    },

    // ---- the three entry points, each refusing before it builds anything ----------------
    {
      family: 'session', tool: 'cli.main', expectThrow: 'CLI_USAGE',
      call: () => cliMain(['run', '--nope', 'value']),
      lesson: 'The CLI refuses CLI_USAGE for an unknown, duplicated, or incomplete flag before it reads a single file. One guard covers all three because they are the same mistake seen from different sides: a flag this build does not accept, a flag whose second value would silently win, and a flag whose value is missing or is itself another flag. Argument parsing finishes entirely before any input is opened, so a malformed command line can never half-run.',
    },
    {
      family: 'session', tool: 'cli.main', expectThrow: 'INPUT_LIMIT', workspace: 'temp',
      call: ({ workspaceRoot }) => {
        // A directory, given where a plan belongs. Measured rather than assumed: a complete
        // command line is required to get this far at all, because CLI_USAGE fires on the missing
        // --policy and --out long before anything is opened.
        const policy = path.join(workspaceRoot, 'cli-input-limit-policy.json');
        fs.writeFileSync(policy, JSON.stringify({
          version: 1, allowedTools: ['json.value'], allowedEffects: ['pure'],
          maxTasks: 4, maxOutputBytes: 65536, maxJournalBytes: 1048576, timeoutMs: 5000,
        }));
        return cliMain(['run', workspaceRoot, '--policy', policy, '--out', path.join(workspaceRoot, 'cli-input-limit-run.json')]);
      },
      lesson: 'An input that is not a regular file is refused INPUT_LIMIT, and the same guard carries the 256 MiB bound. Opening a directory succeeds on every platform this runs on - it is reading one that fails - so the check is on the fstat rather than on the open, and it is one check rather than two because "not a plain file" and "a plain file too large to hold" are the same answer to the caller: this is not something the harness will read.',
    },
    {
      family: 'session', tool: 'mcp.nameFor', expectThrow: 'MCP_CONFIG',
      call: () => mcpNameFor('not a valid name!'),
      lesson: 'A Concord tool name that cannot be mapped to a valid MCP tool name is refused MCP_CONFIG at startup. Dotted names are not safe across every client function-name validator, so each is rewritten with underscores and then checked against what the protocol actually permits - and a name that still fails is refused rather than mangled further, because a tool silently renamed is a tool a plan can no longer address.',
    },
    {
      family: 'session', tool: 'app.startChatServer', expectThrow: 'CHAT_CONFIG', workspace: 'temp',
      call: ({ workspaceRoot }) => startChatServer({ flags: { policy: workspaceRoot, workspace: workspaceRoot } }),
      lesson: 'The desktop server refuses CHAT_CONFIG for a policy path that is not a regular JSON file, before it opens a port. Its bound is 32 MiB where the CLI allows 256, which is deliberate: the CLI reads plans and artifacts, while this reads configuration a person wrote. The guard also fires when the file changes size during the read, so a configuration edited mid-startup is refused rather than half-applied.',
    },

    // ---- the filesystem catch-all, where a read can actually be denied ------------------
    ...(CAN_DENY_READ ? [{
      family: 'catalog', tool: 'skills.snapshot', expectThrow: 'SOURCE_READ_FAILED', workspace: 'temp',
      call: async ({ workspaceRoot }) => {
        const skill = path.join(workspaceRoot, 'unreadable-skill');
        fs.mkdirSync(skill, { recursive: true });
        fs.writeFileSync(path.join(skill, 'SKILL.md'),
          '---\nname: unreadable-skill\ndescription: A valid skill with one file the reader cannot open.\n---\n\n# Unreadable\n');
        const blocked = path.join(skill, 'blocked.md');
        fs.writeFileSync(blocked, '# this file denies its own reader\n');
        denyRead(blocked);
        try {
          const { tools, sourceId } = await sourceTools();
          return await tools.get('skills.snapshot').execute({ path: 'unreadable-skill', sourceId }, { workspaceRoot, policy: toolPolicy });
        } finally {
          // Restored so the round can delete its own scratch directory afterwards.
          restoreRead(blocked);
        }
      },
      lesson: 'A file the reader is not permitted to open fails the snapshot with SOURCE_READ_FAILED, and the filesystem code is carried in the detail. This is the catch-all behind the specific errors, and the ordering is the point: a missing path answers SOURCE_NOT_FOUND and a symlink loop answers PATH_DENIED, so anything arriving here is a fault nobody anticipated — reported as unanticipated rather than guessed at. A partial snapshot is never returned, because a skill missing one file is not the skill that was asked for.',
    }] : []),
  ];
}
