#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseJson, canonical, digest, HarnessError } from '../src/value.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';
import { makeSourceTools, loadSourceLock } from '../src/sources.mjs';
import { makeCapabilityTools } from '../src/capabilities.mjs';
import { makeIntegrationTools } from '../src/integrations.mjs';
import { makeAgentTools } from '../src/workers.mjs';
import { buildChatContext } from '../src/chat-context.mjs';
import { createChatHarness } from '../src/chat.mjs';
import { createServer, listenServer } from '../src/server.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
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

async function start() {
  const flags = {};
  const allowed = ['workspace','policy','integrations','workers','port','store'];
  for (let i = 2; i < process.argv.length; i += 2) {
    const key = process.argv[i]?.replace(/^--/, '');
    if (!process.argv[i]?.startsWith('--') || !allowed.includes(key) || !process.argv[i + 1] || flags[key]) throw new HarnessError('CHAT_USAGE', 'Usage: node scripts/chat.mjs [--workspace DIR] [--port 8787] [--policy FILE] [--integrations FILE] [--workers FILE] [--store DIR]');
    flags[key] = process.argv[i + 1];
  }
  const port = flags.port === undefined ? 8787 : Number(flags.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HarnessError('CHAT_CONFIG', 'Invalid local port');
  const workspaceRoot = fs.realpathSync(path.resolve(flags.workspace ?? root));
  const store = path.resolve(flags.store ?? path.join(root, 'runs', 'chat-' + new Date().toISOString().replaceAll(/[:.]/g, '-')));
  fs.mkdirSync(store, { recursive: true });
  const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
  const inventory = readJson(path.join(root, 'capabilities.lock.json'));
  const integrations = flags.integrations ? readJson(flags.integrations) : {};
  const workers = flags.workers ? readJson(flags.workers) : {};
  const descriptors = [...makeBuiltinTools(), ...makeSourceTools(catalog), ...makeCapabilityTools(inventory), ...makeIntegrationTools(integrations), ...makeAgentTools(workers)];
  const registry = new Map(descriptors.map(d => [d.name, d]));
  if (registry.size !== descriptors.length) throw new HarnessError('CHAT_CONFIG', 'Duplicate tool name');
  const policy = flags.policy ? readJson(flags.policy) : {
    version: 1, allowedTools: [...registry.keys()].sort(), allowedEffects: ['pure','read','write','network','process'],
    allowedOrigins: [...new Set([integrations.model?.origin, integrations.typesafe?.origin].filter(Boolean))].sort(),
    maxTasks: 32, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 60000
  };
  const runtimeFiles = [...fs.readdirSync(path.join(root, 'src')).filter(f => f.endsWith('.mjs')).map(f => 'src/' + f), 'scripts/chat.mjs', 'app/index.html', 'app/style.css', 'app/client.mjs'].sort();
  const sourceLock = { catalog, inventoryHash: digest(inventory), runtime: { node: process.version, platform: process.platform, arch: process.arch, files: runtimeFiles.map(f => ({ path: f, sha256: createHash('sha256').update(fs.readFileSync(path.join(root, f))).digest('hex') })) } };
  const visibleRegistry = new Map([...registry].filter(([name, tool]) => policy.allowedTools.includes(name) && policy.allowedEffects.includes(tool.effect)));
  const harness = createChatHarness({ registry, policy, sourceLock, workspaceRoot,
    buildContext: ({message,history}) => buildChatContext({ message, history, sourceLock: catalog, inventory, registry: visibleRegistry, corpusRoot: root, instructionRoot: path.join(root, 'instructions') }),
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
  for (const method of ['send','approve','executePlan','replay']) wrapped[method] = async (...args) => {
    const result = await harness[method](...args);
    // Append-only chat snapshots are reviewable; no automatic effect resumption on restart.
    fs.appendFileSync(path.join(store, 'session.jsonl'), canonical(harness.snapshot()) + '\n');
    return result;
  };
  const status = { sourceCount: catalog.sources.length, files: inventory.repositories.reduce((n, r) => n + r.files, 0), capabilities: inventory.capabilities.length, skillFiles: inventory.capabilities.filter(c => c.kind === 'skill').length, tools: [...visibleRegistry.keys()].sort() };
  const server = createServer({ harness: wrapped, status, host: '127.0.0.1', port });
  const url = await listenServer(server, { host: '127.0.0.1', port });
  console.log(`Concord chat: ${url}\nMode: ${registry.has('model.propose') ? 'live model configured; each network call requires its exact grant' : 'offline deterministic demonstration'}\nSources: ${status.sourceCount}; indexed references: ${status.capabilities}; skill files: ${status.skillFiles}\nLocal evidence: ${store}`);
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
start().catch(error => { console.error(error instanceof HarnessError ? `${error.code}: ${error.message}` : 'CHAT_START_FAILED: Check local configuration and paths.'); process.exitCode = 1; });
