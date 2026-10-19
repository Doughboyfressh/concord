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
import { makeReverseTools } from './reverse.mjs';
import { makeReaderTools } from './readers.mjs';
import { makeForeignTools } from './foreign.mjs';
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
export const CHAT_FLAGS = ['workspace', 'policy', 'integrations', 'workers', 'browser', 'reverse', 'foreign', 'port', 'store'];

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
  const integrations = flags.integrations ? readJson(flags.integrations) : {};
  const workers = flags.workers ? readJson(flags.workers) : {};
  const browser = flags.browser ? readJson(flags.browser) : undefined;
  const reverseTable = readJson(path.join(root, 'reverse-tools.json'));
  const reverse = flags.reverse ? readJson(flags.reverse) : {};
  const foreignManifest = fs.existsSync(path.join(root, 'foreign-capabilities.json'))
    ? readJson(path.join(root, 'foreign-capabilities.json')) : { schemaVersion: 1, sources: [] };
  const descriptors = [
    ...makeBuiltinTools(), ...makeSourceTools(catalog), ...makeCapabilityTools(inventory), ...makeArtifactTools(),
    ...makeIntegrationTools(integrations), ...makeAgentTools(workers), ...makeBrowserTools(browser),
    ...makeReverseTools(reverseTable, reverse), ...makeReaderTools(),
    ...makeForeignTools(foreignManifest, flags.foreign ? readJson(flags.foreign) : {}),
  ];
  const registry = new Map(descriptors.map(d => [d.name, d]));
  if (registry.size !== descriptors.length) throw new HarnessError('CHAT_CONFIG', 'Duplicate tool name');
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
  const runtimeFiles = [...fs.readdirSync(path.join(root, 'src')).filter(f => f.endsWith('.mjs')).map(f => 'src/' + f), entry, 'app/index.html', 'app/style.css', 'app/client.mjs'].sort();
  const sourceLock = { catalog, inventoryHash: digest(inventory), runtime: { node: process.version, platform: process.platform, arch: process.arch, files: runtimeFiles.map(f => ({ path: f, sha256: createHash('sha256').update(fs.readFileSync(path.join(root, f))).digest('hex') })) } };
  const visibleRegistry = new Map([...registry].filter(([name, tool]) => policy.allowedTools.includes(name) && policy.allowedEffects.includes(tool.effect)));
  const harness = createChatHarness({
    registry, policy, sourceLock, workspaceRoot,
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
  const wrapped = { snapshot: () => harness.snapshot() };
  for (const method of ['send', 'approve', 'executePlan', 'replay']) wrapped[method] = async (...args) => {
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
    : 'offline deterministic demonstration';
  return {
    url, server, store, status, mode, policy, workspaceRoot,
    toolCount: visibleRegistry.size,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
