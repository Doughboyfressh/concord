#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { canonical, digest, parseJson, HarnessError } from './value.mjs';
import { runPlan, replayPlan, registryManifest, inspectPlan } from './engine.mjs';
import { makeBuiltinTools } from './builtins.mjs';
import { loadSourceLock, makeSourceTools } from './sources.mjs';
import { makeIntegrationTools } from './integrations.mjs';
import { makeAgentTools } from './workers.mjs';
import { makeCapabilityTools } from './capabilities.mjs';
import { makeArtifactTools } from './artifacts.mjs';
import { makeBrowserTools } from './browser.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const usage = `Concord — evidence-bound AI harness

  node src/cli.mjs run PLAN --policy POLICY --out RUN [options]
  node src/cli.mjs replay RUN --plan PLAN --policy POLICY [options]
  node src/cli.mjs validate PLAN --policy POLICY [options]
  node src/cli.mjs inspect RUN
  node src/cli.mjs tools [--integrations CONFIG] [--workers CONFIG] [--browser CONFIG]
  node src/cli.mjs sources

Options:
  --workspace DIR     Explicit tool workspace (default: current directory)
  --integrations FILE Reviewed HTTP/process adapter configuration
  --workers FILE      Reviewed DeepSeek/Hermes worker configuration
  --browser FILE      Reviewed browser.snapshot configuration (executable, etc.)
  --approvals FILE    JSON array of exact request hashes (run only)
  --journal FILE      Exclusive, fsynced JSONL intent/receipt log (run only)
  --root SHA256       Independent terminal commitment (replay only)

Run exits: 0 completed, 2 invalid request, 3 approval needed, 4 failed.
Replay performs no tool calls. Existing output files are never overwritten.`;

function readJson(filename) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > 268435456) throw new HarnessError('INPUT_LIMIT', 'Input must be a regular file of at most 256 MiB');
    const chunks = [];
    let used = 0;
    for (;;) {
      const buffer = Buffer.alloc(65536);
      const n = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!n) break;
      used += n;
      if (used > 268435456) throw new HarnessError('INPUT_LIMIT', 'Input file grew past 256 MiB');
      chunks.push(buffer.subarray(0, n));
    }
    return parseJson(new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks, used)));
  } finally { fs.closeSync(fd); }
}

function parseArgs(argv) {
  const [command = 'help', ...rest] = argv;
  const positional = [], flags = {};
  const allowed = new Set(['policy', 'out', 'workspace', 'integrations', 'workers', 'browser', 'approvals', 'journal', 'plan', 'root']);
  for (let i = 0; i < rest.length; i++) {
    if (!rest[i].startsWith('--')) { positional.push(rest[i]); continue; }
    const name = rest[i].slice(2);
    if (!allowed.has(name) || Object.hasOwn(flags, name) || !rest[i + 1] || rest[i + 1].startsWith('--')) throw new HarnessError('CLI_USAGE', 'Unknown, duplicate, or incomplete flag');
    flags[name] = rest[++i];
  }
  return { command, positional, flags };
}

function runtimeLock(catalog) {
  const files = fs.readdirSync(path.join(root, 'src')).filter(n => n.endsWith('.mjs')).sort().map(name => ({ path: 'src/' + name, sha256: createHash('sha256').update(fs.readFileSync(path.join(root, 'src', name))).digest('hex') }));
  return { catalog, runtime: { node: process.version, platform: process.platform, arch: process.arch, files } };
}

function registryFor(catalog, flags) {
  const inventoryPath = path.join(root, 'capabilities.lock.json');
  const inventory = fs.existsSync(inventoryPath) ? readJson(inventoryPath) : undefined;
  const tools = [
    ...makeBuiltinTools(), ...makeSourceTools(catalog), ...makeCapabilityTools(inventory), ...makeArtifactTools(),
    ...makeIntegrationTools(flags.integrations ? readJson(flags.integrations) : {}),
    ...makeAgentTools(flags.workers ? readJson(flags.workers) : {}),
    ...makeBrowserTools(flags.browser ? readJson(flags.browser) : undefined),
  ];
  const registry = new Map();
  for (const tool of tools) {
    if (registry.has(tool.name)) throw new HarnessError('INVALID_REGISTRY', 'Duplicate tool name');
    registry.set(tool.name, tool);
  }
  return registry;
}

export async function main(argv = process.argv.slice(2)) {
  const { command, positional, flags } = parseArgs(argv);
  if (['help', '--help', '-h'].includes(command)) { console.log(usage); return 0; }
  if (command === 'inspect') {
    if (positional.length !== 1 || Object.keys(flags).length) throw new HarnessError('CLI_USAGE', 'inspect requires one run path');
    const run = readJson(positional[0]);
    console.log(JSON.stringify({ warning: 'Inspection is not verification; use replay with the original context and trusted root.', header: run.header, outcome: run.outcome, root: run.root, events: run.events?.map(e => ({ seq: e.seq, type: e.type, taskId: e.data?.taskId })) }, null, 2));
    return 0;
  }
  const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
  if (command === 'sources') {
    if (positional.length || Object.keys(flags).length) throw new HarnessError('CLI_USAGE', 'sources accepts no arguments');
    console.log(JSON.stringify(catalog, null, 2)); return 0;
  }
  const registry = registryFor(catalog, flags);
  if (command === 'tools') {
    if (positional.length || Object.keys(flags).some(k => !['integrations', 'workers', 'browser'].includes(k))) throw new HarnessError('CLI_USAGE', 'tools accepts adapter configuration flags only');
    console.log(JSON.stringify(registryManifest(registry), null, 2)); return 0;
  }
  if (!['run', 'replay', 'validate'].includes(command) || positional.length !== 1 || !flags.policy || (command === 'run' && !flags.out) || (command === 'replay' && !flags.plan)) throw new HarnessError('CLI_USAGE', usage);
  const commandFlags = { run: ['policy','out','workspace','integrations','workers','browser','approvals','journal'], replay: ['plan','policy','workspace','integrations','workers','browser','root'], validate: ['policy','workspace','integrations','workers','browser'] };
  if (Object.keys(flags).some(k => !commandFlags[command].includes(k))) throw new HarnessError('CLI_USAGE', 'Flag does not apply to this command');
  const workspaceRoot = fs.realpathSync(path.resolve(flags.workspace ?? process.cwd()));
  const options = { plan: readJson(command === 'replay' ? flags.plan : positional[0]), policy: readJson(flags.policy), registry, sourceLock: runtimeLock(catalog), workspaceRoot };
  if (command === 'validate') { console.log(JSON.stringify(inspectPlan(options), null, 2)); return 0; }
  let result;
  if (command === 'run') {
    // Reserve output before effects so a collision cannot hide a successful operation.
    fs.mkdirSync(path.dirname(path.resolve(flags.out)), { recursive: true });
    const out = fs.openSync(flags.out, 'wx');
    try {
      result = await runPlan({ ...options, approvals: flags.approvals ? readJson(flags.approvals) : [], journalPath: flags.journal });
      fs.writeFileSync(out, canonical(result) + '\n'); fs.fsyncSync(out);
    } finally { fs.closeSync(out); }
  } else result = replayPlan({ ...options, journal: readJson(positional[0]), expectedRoot: flags.root });
  console.log(JSON.stringify({ outcome: result.outcome, root: result.root, replayed: result.replayed ?? false }, null, 2));
  return result.outcome.status === 'completed' ? 0 : result.outcome.status === 'blocked' ? 3 : 4;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(code => { process.exitCode = code; }).catch(error => {
    // Adapter details and remote response bodies are deliberately excluded.
    console.error(error instanceof HarnessError ? `${error.code}: ${error.message}` : 'CONCORD_ERROR: Operation failed; inspect local configuration and journal.');
    process.exitCode = 2;
  });
}
