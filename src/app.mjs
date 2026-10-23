import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseJson, canonical, digest, HarnessError } from './value.mjs';
import { makeBuiltinTools } from './builtins.mjs';
import { makeSourceTools, loadSourceLock } from './sources.mjs';
import { makeCapabilityTools } from './capabilities.mjs';
import { makeIntegrationTools } from './integrations.mjs';
import { makeAgentTools } from './workers.mjs';
import { makeArtifactTools } from './artifacts.mjs';
import { makeBrowserTools } from './browser.mjs';
import { makeDecompilerTools } from './decompiler.mjs';
import { makeWebTools } from './web.mjs';
import { makeBuildTools } from './build.mjs';
import { makeReverseTools } from './reverse.mjs';
import { makeReaderTools } from './readers.mjs';
import { makeForeignTools } from './foreign.mjs';
import { makeMailboxTools, fileMessage, readMailbox } from './peer.mjs';
import { makeSkillStoreTools } from './skillstore.mjs';
import { modelCredentialPlan } from './desktop.mjs';
import { makeInstructionTools } from './instructions.mjs';
import { makeGovernanceTools } from './governance.mjs';
import { buildChatContext } from './chat-context.mjs';
import { createChatHarness } from './chat.mjs';
import { createServer, listenServer } from './server.mjs';

/**
 * One assembly of the whole application: registry, policy, source lock, harness, local server.
 *
 * This used to live inline in `scripts/chat.mjs`. It moved here when the desktop shell arrived so
 * that the terminal launcher and the windowed launcher cannot drift apart: a difference in which
 * tools are registered, which policy is defaulted, or what the source lock records would be a
 * difference in what an approval authorizes. There is one path, and both launchers take it.
 */

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/** Every flag the launchers accept. A flag absent here is rejected rather than ignored. */
export const CHAT_FLAGS = ['workspace', 'policy', 'integrations', 'workers', 'browser', 'decompiler', 'web', 'build', 'reverse', 'foreign', 'port', 'store'];

/** The kernel's own ceiling for a policy deadline, from the policy schema in src/engine.mjs. */
const POLICY_MAX_TIMEOUT_MS = 300_000;

export const USAGE = 'Usage: node scripts/chat.mjs [--workspace DIR] [--port 8787] [--policy FILE] [--integrations FILE] [--workers FILE] [--browser FILE] [--reverse FILE] [--foreign FILE] [--store DIR]';

/** `--key value` pairs only, each key known and given at most once. */
export function parseFlags(argv, allowed = CHAT_FLAGS, usage = USAGE) {
  const flags = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, '');
    if (!argv[i]?.startsWith('--') || !allowed.includes(key) || !argv[i + 1] || flags[key]) throw new HarnessError('CHAT_USAGE', usage);
    flags[key] = argv[i + 1];
  }
  return flags;
}

function readJson(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > 32 * 1048576) throw new HarnessError('CHAT_CONFIG', 'Expected a regular JSON file of at most 32 MiB');
    const bytes = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < bytes.length) { const n = fs.readSync(fd, bytes, used, bytes.length - used, used); if (!n) break; used += n; }
    if (used !== stat.size) throw new HarnessError('CHAT_CONFIG', 'JSON input changed during read');
    return parseJson(new TextDecoder('utf8', { fatal: true }).decode(bytes.subarray(0, used)));
  } finally { fs.closeSync(fd); }
}

/**
 * Build the registry, start the loopback server, and report what was started.
 *
 * `entry` is the launcher that is really running, and it goes into the source lock's runtime file
 * list so a run records which launcher produced it rather than always claiming the terminal one.
 */
export async function startChatServer({ flags = {}, entry = 'scripts/chat.mjs' } = {}) {
  const port = flags.port === undefined ? 8787 : Number(flags.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new HarnessError('CHAT_CONFIG', 'Invalid local port');
  const workspaceRoot = fs.realpathSync(path.resolve(flags.workspace ?? root));
  const store = path.resolve(flags.store ?? path.join(root, 'runs', 'chat-' + new Date().toISOString().replaceAll(/[:.]/g, '-')));
  fs.mkdirSync(store, { recursive: true });
  const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
  const inventory = readJson(path.join(root, 'capabilities.lock.json'));
  // Live by default, for every entrypoint rather than only the windowed one. There is no
  // demonstration mode to fall back to any more, so a launcher that ignored an already-configured
  // model would refuse every turn until the operator remembered a flag. scripts/desktop.mjs has
  // defaulted this for a while and scripts/chat.mjs did not, which is the entire reason a machine
  // with a working model could still report itself as a demo. An explicit --integrations wins.
  if (flags.integrations === undefined) {
    const live = path.join(root, 'config', 'concord-live.json');
    if (fs.existsSync(live)) flags = { ...flags, integrations: live };
  }
  // The same defaulting for the adapters whose configuration is a property of the machine rather
  // than of a workspace. Every one of these factories returns an empty array without a config, so
  // a reviewed browser and a reviewed decompiler sitting on disk still produced a registry with
  // no process effect in it at all -- which is how Concord came to report, accurately about its
  // launch and misleadingly about itself, that it could not run an external program.
  //
  // Deliberately not defaulted: --build and the process entries under --integrations. Those name
  // an exact argv to execute, and inventing one on an operator's behalf is the single thing this
  // kernel's design is most careful to refuse. They stay explicit, per workspace.
  // `build` is here on a narrower basis than the rest. A build target names an exact argv, and a
  // plan must never choose one -- that is the rule. config/build.json is the other side of that
  // rule: argv chosen once, in a file an operator can read, and still unable to run without an
  // exact grant per invocation. It is picked up only because the file exists, so deleting the
  // file removes the capability.
  for (const [flag, file] of [['browser', 'browser.json'], ['decompiler', 'decompiler.json'], ['workers', 'workers.json'], ['web', 'web.json'], ['build', 'build.json']]) {
    if (flags[flag] !== undefined) continue;
    const candidate = path.join(root, 'config', file);
    if (fs.existsSync(candidate)) flags = { ...flags, [flag]: candidate };
  }
  const integrations = flags.integrations ? readJson(flags.integrations) : {};
  // The same credential decision the windowed launcher has always made, moved here so both
  // launchers make it. A loopback model server ignores the key, but the adapter still refuses
  // without one, so a configured local model worked from the desktop app and failed from the
  // terminal with INTEGRATION_CREDENTIAL -- the same split that let a live machine report itself
  // as a demo. Decided from configuration and the environment only; nothing is probed, and an
  // already-set variable is never overwritten.
  const credential = modelCredentialPlan(integrations.model);
  if (credential.setEnv && !process.env[credential.setEnv.name]) {
    process.env[credential.setEnv.name] = credential.setEnv.value;
  }
  const workers = flags.workers ? readJson(flags.workers) : {};
  const browser = flags.browser ? readJson(flags.browser) : undefined;
  const decompiler = flags.decompiler ? readJson(flags.decompiler) : undefined;
  const web = flags.web ? readJson(flags.web) : undefined;
  const build = flags.build ? readJson(flags.build) : undefined;
  const reverseTable = readJson(path.join(root, 'reverse-tools.json'));
  const reverse = flags.reverse ? readJson(flags.reverse) : {};
  const foreignManifest = fs.existsSync(path.join(root, 'foreign-capabilities.json'))
    ? readJson(path.join(root, 'foreign-capabilities.json')) : { schemaVersion: 1, sources: [] };
  const mailboxDir = path.join(root, 'runs', 'peer-mailbox');
  const descriptors = [
    ...makeBuiltinTools(), ...makeSourceTools(catalog), ...makeCapabilityTools(inventory), ...makeArtifactTools(),
    ...makeIntegrationTools(integrations), ...makeAgentTools(workers), ...makeBrowserTools(browser), ...makeDecompilerTools(decompiler),
    ...makeWebTools(web), ...makeBuildTools(build),
    ...makeReverseTools(reverseTable, reverse), ...makeReaderTools(),
    ...makeForeignTools(foreignManifest, flags.foreign ? readJson(flags.foreign) : {}),
    ...makeMailboxTools({ directory: mailboxDir }),
    ...makeSkillStoreTools(inventory),
    ...makeInstructionTools({ directory: path.join(root, 'instructions') }),
  ];
  const registry = new Map(descriptors.map(d => [d.name, d]));
  if (registry.size !== descriptors.length) throw new HarnessError('CHAT_CONFIG', 'Duplicate tool name');
  const runtimeFiles = [...fs.readdirSync(path.join(root, 'src')).filter(f => f.endsWith('.mjs')).map(f => 'src/' + f), entry, 'app/index.html', 'app/style.css', 'app/client.mjs'].sort();
  const sourceLock = { catalog, inventoryHash: digest(inventory), runtime: { node: process.version, platform: process.platform, arch: process.arch, files: runtimeFiles.map(f => ({ path: f, sha256: createHash('sha256').update(fs.readFileSync(path.join(root, f))).digest('hex') })) } };
  // Delegation runs a sub-plan against this very registry under an attenuated policy, so it is
  // registered once the registry and source lock exist and before allowedTools is derived from
  // them — a tool added after that derivation would be filtered straight back out.
  for (const tool of makeGovernanceTools({ registry, sourceLock })) registry.set(tool.name, tool);

  const policy = flags.policy ? readJson(flags.policy) : {
    version: 1, allowedTools: [...registry.keys()].sort(), allowedEffects: ['pure', 'read', 'write', 'network', 'process'],
    allowedOrigins: [...new Set([integrations.model?.origin, integrations.typesafe?.origin].filter(Boolean))].sort(),
    maxTasks: 32, maxOutputBytes: 1048576, maxJournalBytes: 16777216,
    // A policy bound and an adapter bound are both ceilings, and the effective one is the lower.
    // A default of sixty seconds therefore silently overrode every configured adapter timeout
    // above it: a local model given a sixteen-thousand-token prompt took 218 seconds and was
    // killed at 60 by this number, not by its own configuration. The default now never undercuts
    // what the operator configured, and never exceeds what the kernel's policy schema permits —
    // a policy above POLICY_MAX_TIMEOUT_MS is rejected outright, which fails every plan rather
    // than one call.
    timeoutMs: Math.min(POLICY_MAX_TIMEOUT_MS, Math.max(60000, ...[integrations.model?.timeoutMs, integrations.typesafe?.timeoutMs, integrations.registry?.timeoutMs]
      .filter((value) => Number.isInteger(value) && value > 0)))
  };
  const visibleRegistry = new Map([...registry].filter(([name, tool]) => policy.allowedTools.includes(name) && policy.allowedEffects.includes(tool.effect)));
  // Live progress listeners. Deliberately fire-and-forget: a turn's correctness never depends on
  // anyone watching, and a listener that throws is dropped rather than allowed to affect the run.
  const progressListeners = new Set();
  const harness = createChatHarness({
    registry, policy, sourceLock, workspaceRoot,
    onProgress: (update) => {
      for (const listener of progressListeners) {
        try { listener(update); } catch { progressListeners.delete(listener); }
      }
    },
    buildContext: ({ message, history, observations, proposedPlan }) => buildChatContext({ message, history, observations, proposedPlan, sourceLock: catalog, inventory, registry: visibleRegistry, policy, instructionRoot: path.join(root, 'instructions') }),
    persistRun: async record => {
      const id = record.id ?? digest(record).slice(0, 24);
      if (!/^[A-Za-z0-9._-]{1,128}$/.test(id)) throw new HarnessError('CHAT_STORE', 'Invalid run ID');
      const file = path.join(store, id + '.json');
      const content = canonical(record) + '\n';
      try { fs.writeFileSync(file, content, { flag: 'wx' }); }
      catch (error) {
        // The run id is content-derived: a repeated identical turn recomputes the same id
        // and the same bytes. That recurrence is an idempotent no-op, not lost evidence.
        if (error.code !== 'EEXIST' || fs.readFileSync(file, 'utf8') !== content) throw error;
      }
    }
  });
  // Past sessions. Every turn already appends a snapshot to session.jsonl, so the transcripts
  // exist on disk and nothing could read them back. Read-only by construction: a past session is
  // a recorded transcript, not a conversation to resume. Resuming would mean adopting another
  // session's approvals and proposed plan as if they were this one's, and an approval is bound to
  // the run that requested it.
  const SESSION_ID = /^chat-[0-9A-Za-z-]{1,64}$/;
  const sessionsRoot = path.dirname(store);
  const lastLine = (file) => {
    const text = fs.readFileSync(file, 'utf8');
    const lines = text.split('\n').filter((line) => line.trim());
    return lines.length ? parseJson(lines[lines.length - 1]) : null;
  };
  const listSessions = () => {
    let names = [];
    try { names = fs.readdirSync(sessionsRoot).filter((name) => SESSION_ID.test(name)); } catch { return []; }
    const rows = [];
    for (const id of names.sort().reverse().slice(0, 50)) {
      const file = path.join(sessionsRoot, id, 'session.jsonl');
      try {
        const snapshot = lastLine(file);
        if (!snapshot) continue;
        const first = (snapshot.history ?? []).find((entry) => entry.role === 'user');
        rows.push({
          id,
          current: path.resolve(sessionsRoot, id) === path.resolve(store),
          turns: (snapshot.history ?? []).length,
          runs: (snapshot.runs ?? []).length,
          opening: first ? String(first.content).slice(0, 160) : '',
        });
      } catch { /* a half-written or unreadable session is skipped, not fatal */ }
    }
    return rows;
  };

  const wrapped = {
    // Progress subscribers. A Set so a reconnecting window replaces its own listener rather than
    // accumulating them, and so a slow client cannot be delivered to twice.
    subscribe: (listener) => { progressListeners.add(listener); return () => progressListeners.delete(listener); },
    snapshot: () => harness.snapshot(),
    exchange: () => readMailbox(mailboxDir),
    sessions: () => listSessions(),
    // Returns a past transcript under its own key, never as `state`: the live state must not be
    // replaceable by a recording, or the interface would show a session that cannot be acted on
    // while looking exactly like one that can.
    openSession: ({ id }) => {
      if (!SESSION_ID.test(id)) throw new HarnessError('CHAT_SESSION', 'That is not a session id');
      const file = path.join(sessionsRoot, id, 'session.jsonl');
      let snapshot = null;
      try { snapshot = lastLine(file); } catch { snapshot = null; }
      if (!snapshot) throw new HarnessError('CHAT_SESSION', 'That session has no recorded transcript');
      return { id, transcript: { history: snapshot.history ?? [], runs: snapshot.runs ?? [], observations: snapshot.observations ?? null } };
    },
    // Cancel is not wrapped like the four below: it writes no session snapshot, because it does
    // not advance the conversation. The turn it aborts records its own failure on its own path.
    cancel: () => harness.cancel(),
    // Answering a filed question is Concord writing to its own outbox, the same class of
    // internal evidence as the run journal, so it goes through fileMessage directly. The
    // returned snapshot is unchanged state: the exchange is polled separately by the client.
    replyToPeer: ({ replyTo, message }) => {
      fileMessage(mailboxDir, { message, audience: 'client', subject: 'answered in Concord', replyTo });
      return harness.snapshot();
    },
  };
  for (const method of ['send', 'approve', 'executePlan', 'replay']) wrapped[method] = async (...args) => {
    // A prompt typed here goes three places: Concord's own model, Concord's pipeline, and the
    // provider connected over MCP. The third is a file rather than a call because no MCP client
    // measured so far declares sampling, so the provider collects rather than being pushed to.
    // Filed directly rather than through peer.post: this is Concord writing to its own outbox,
    // the same class of internal evidence as the run journal, not an effect on anything outside.
    if (method === 'send' && typeof args[0] === 'string' && args[0].trim()) {
      try { fileMessage(mailboxDir, { message: args[0], audience: 'agent', subject: 'asked in Concord' }); }
      catch { /* a full or unwritable outbox must never cost the operator their turn */ }
    }
    const result = await harness[method](...args);
    // Append-only chat snapshots are reviewable; no automatic effect resumption on restart.
    fs.appendFileSync(path.join(store, 'session.jsonl'), canonical(harness.snapshot()) + '\n');
    return result;
  };
  const status = {
    sourceCount: catalog.sources.length,
    files: inventory.repositories.reduce((n, r) => n + r.files, 0),
    capabilities: inventory.capabilities.length,
    skillFiles: inventory.capabilities.filter(c => c.kind === 'skill').length,
    tools: [...visibleRegistry.keys()].sort(),
  };
  const server = createServer({ harness: wrapped, status, host: '127.0.0.1', port });
  const url = await listenServer(server);
  const mode = registry.has('model.propose')
    ? 'live model configured; each network call requires its exact grant'
    : 'NO MODEL CONFIGURED - turns will refuse; pass --integrations naming a model.propose configuration';
  return {
    url, server, store, status, mode, policy, workspaceRoot,
    toolCount: visibleRegistry.size,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
