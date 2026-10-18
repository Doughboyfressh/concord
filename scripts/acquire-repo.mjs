import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonical, parseJson } from '../src/value.mjs';

/**
 * Turn a local clone into a foreign capability manifest.
 *
 * Out-of-band acquisition, the same role as acquire-upstreams.ps1 and acquire-hermes-local.py:
 * it reads a tree once and writes inert data that src/foreign.mjs can compile. Nothing here runs
 * the repository, installs anything, or reaches the network.
 *
 * The distinction this records is the whole point. A capability is either:
 *
 *   declared  the thing publishes a machine-readable contract — an MCP server entry, an OpenAPI
 *             operation, a SKILL.md with real frontmatter. The name, and often the input shape,
 *             come from the artifact itself.
 *   inferred  a filename or manifest convention says a capability probably exists — a
 *             package.json bin entry, a commands directory. There is no contract, so what is
 *             emitted is a candidate an operator must give a reviewed template before it can run.
 *
 * Conflating those two is how an importer ends up inventing tools. Every entry carries its
 * `evidence` and its `confidence`, so a reviewer can see which it is.
 *
 * Usage:  node scripts/acquire-repo.mjs <clone-dir> [--id <source-id>] [--out <file>]
 */

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', 'vendor', 'target']);
const MAX_FILES = 200000;
const MAX_DEPTH = 12;
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_LISTED = 2000;

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const readJsonFile = (file) => {
  const stat = fs.statSync(file);
  if (stat.size > MAX_JSON_BYTES) return null;
  try { return parseJson(fs.readFileSync(file, 'utf8')); }
  catch { return null; }
};

/** Every file in the tree, bounded, with the skip list applied. */
function walk(root) {
  const files = [];
  const visit = (dir, relative, depth) => {
    if (depth > MAX_DEPTH || files.length >= MAX_FILES) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (files.length >= MAX_FILES) return;
      const rel = relative ? relative + '/' + entry.name : entry.name;
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) visit(full, rel, depth + 1);
        continue;
      }
      if (entry.isFile()) files.push(rel);
    }
  };
  visit(root, '', 0);
  return files;
}

const frontmatter = (text) => {
  if (!text.startsWith('---')) return {};
  const end = text.indexOf('\n---', 3);
  if (end < 0) return {};
  const result = {};
  for (const line of text.slice(3, end).split('\n')) {
    const match = /^(name|description):\s*(.*)$/.exec(line);
    if (match) result[match[1]] = match[2].trim().replace(/^["']|["']$/g, '');
  }
  return result;
};

/** SKILL.md trees: a declared capability, since the file states its own name and description. */
function recogniseSkills(root, files) {
  const found = [];
  for (const file of files) {
    if (!/(^|\/)SKILL\.md$/.test(file)) continue;
    const bytes = fs.readFileSync(path.join(root, file));
    const meta = frontmatter(bytes.toString('utf8'));
    const complete = Boolean(meta.name && meta.description);
    found.push({
      kind: 'skill', name: meta.name ?? path.dirname(file).split('/').pop(),
      description: meta.description ?? null,
      evidence: file, confidence: complete ? 'declared' : 'inferred',
      reason: complete
        ? 'SKILL.md frontmatter declares a name and description'
        : 'A SKILL.md is present but its frontmatter does not declare both a name and a description',
      sha256: hash(bytes), bytes: bytes.length,
    });
  }
  return found;
}

/**
 * MCP server declarations. This is the high-fidelity path: a server entry names a command, and
 * the server itself can then be asked for its tool contracts by scripts/acquire-mcp.mjs.
 */
function recogniseMcp(root, files) {
  const found = [];
  const candidates = files.filter((file) => /(^|\/)(server\.json|\.mcp\.json|mcp\.json)$/.test(file));
  for (const file of candidates) {
    const document = readJsonFile(path.join(root, file));
    if (!document) continue;
    // Two shapes in the wild: an MCP server registry entry, and a client config with a map.
    if (typeof document.name === 'string' && Array.isArray(document.packages)) {
      for (const pkg of document.packages.slice(0, MAX_LISTED)) {
        found.push({
          kind: 'mcp-server', name: document.name,
          description: typeof document.description === 'string' ? document.description : null,
          evidence: file, confidence: 'declared',
          reason: 'An MCP server registry entry names the server and how to run it',
          transport: pkg?.transport?.type ?? null, registry: pkg?.registryType ?? null,
          identifier: pkg?.identifier ?? null, version: pkg?.version ?? document.version ?? null,
          runtimeHint: pkg?.runtimeHint ?? null,
          contractsPublishedLive: true,
        });
      }
      continue;
    }
    const servers = document.mcpServers ?? document.servers;
    if (servers && typeof servers === 'object' && !Array.isArray(servers)) {
      for (const [name, entry] of Object.entries(servers).slice(0, MAX_LISTED)) {
        if (!entry || typeof entry !== 'object') continue;
        found.push({
          kind: 'mcp-server', name, description: null, evidence: file, confidence: 'declared',
          reason: 'An MCP client configuration names the server and its command',
          command: typeof entry.command === 'string' ? entry.command : null,
          args: Array.isArray(entry.args) ? entry.args.filter((a) => typeof a === 'string') : [],
          transport: entry.type ?? 'stdio', contractsPublishedLive: true,
        });
      }
    }
  }
  return found;
}

/**
 * OpenAPI operations: declared, with a real input shape. A website or service that ships one of
 * these is describing tools, not just documentation.
 */
function recogniseOpenApi(root, files) {
  const found = [];
  const candidates = files.filter((file) => /(^|\/)(openapi|swagger)[^/]*\.json$/i.test(file));
  for (const file of candidates) {
    const document = readJsonFile(path.join(root, file));
    if (!document || !document.paths || typeof document.paths !== 'object') continue;
    const version = document.openapi ?? document.swagger ?? null;
    for (const [route, operations] of Object.entries(document.paths).slice(0, MAX_LISTED)) {
      if (!operations || typeof operations !== 'object') continue;
      for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
        const operation = operations[method];
        if (!operation || typeof operation !== 'object') continue;
        found.push({
          kind: 'endpoint', name: operation.operationId ?? (method + ' ' + route),
          description: typeof operation.summary === 'string' ? operation.summary : null,
          evidence: file, confidence: 'declared',
          reason: 'An OpenAPI operation declares its method, path and parameters',
          method: method.toUpperCase(), route,
          parameters: Array.isArray(operation.parameters)
            ? operation.parameters.filter((p) => p && typeof p.name === 'string').map((p) => ({ name: p.name, in: p.in ?? null, required: p.required === true }))
            : [],
          hasRequestBody: Boolean(operation.requestBody), openapiVersion: version,
        });
      }
    }
  }
  return found;
}

/**
 * Executable entrypoints a package declares. These are *candidates*: a bin entry names a command
 * but not its subcommands, flags or input shape, so nothing here can run until an operator writes
 * a reviewed argv template for it.
 */
function recogniseCli(root, files) {
  const found = [];
  for (const file of files.filter((f) => /(^|\/)package\.json$/.test(f))) {
    const document = readJsonFile(path.join(root, file));
    if (!document) continue;
    const bin = document.bin;
    const entries = typeof bin === 'string' ? { [document.name ?? 'default']: bin }
      : (bin && typeof bin === 'object' && !Array.isArray(bin)) ? bin : null;
    if (!entries) continue;
    for (const [command, target] of Object.entries(entries).slice(0, MAX_LISTED)) {
      if (typeof target !== 'string') continue;
      found.push({
        kind: 'cli', name: command, description: typeof document.description === 'string' ? document.description : null,
        evidence: file, confidence: 'inferred',
        reason: 'A package.json bin entry names an executable but declares no subcommands, flags or input shape, so a reviewed argv template is required before it can run',
        entrypoint: target, packageName: document.name ?? null, packageVersion: document.version ?? null,
      });
    }
  }
  return found;
}

/** Agent-facing instruction documents. Instructions, never tools. */
function recogniseInstructions(root, files) {
  const found = [];
  const wanted = (file) => /^(README|AGENTS|CONTRIBUTING|SECURITY)\.md$/i.test(file)
    || (/^(docs|\.agents|\.claude|\.factory)\//.test(file) && /\.mdx?$/i.test(file));
  for (const file of files.filter(wanted).slice(0, MAX_LISTED)) {
    const bytes = fs.readFileSync(path.join(root, file));
    if (bytes.length > MAX_JSON_BYTES) continue;
    const text = bytes.toString('utf8');
    const headings = [...text.matchAll(/^#{1,3}\s+(.+)$/gm)].map((m) => m[1].trim()).slice(0, 64);
    found.push({
      kind: 'instruction', name: file, description: headings[0] ?? null,
      evidence: file, confidence: 'declared',
      reason: 'A documentation file is instruction material; it declares no executable capability',
      headings, sha256: hash(bytes), bytes: bytes.length,
    });
  }
  return found;
}

/** Plugin manifests, which declare commands and agents a host is expected to load. */
function recognisePlugins(root, files) {
  const found = [];
  for (const file of files.filter((f) => /(^|\/)(\.claude-plugin\/)?plugin\.json$/.test(f))) {
    const document = readJsonFile(path.join(root, file));
    if (!document || typeof document.name !== 'string') continue;
    found.push({
      kind: 'plugin', name: document.name,
      description: typeof document.description === 'string' ? document.description : null,
      evidence: file, confidence: 'declared',
      reason: 'A plugin manifest declares its name and the surfaces a host should load',
      version: document.version ?? null,
      declares: ['commands', 'agents', 'skills', 'hooks', 'mcpServers'].filter((key) => Object.hasOwn(document, key)),
    });
  }
  return found;
}

function main() {
  const argv = process.argv.slice(2);
  if (!argv.length) {
    console.log('Usage: node scripts/acquire-repo.mjs <clone-dir> [--id <source-id>] [--out <file>]');
    return 2;
  }
  const root = path.resolve(argv[0]);
  const flag = (name) => { const at = argv.indexOf('--' + name); return at > 0 && argv[at + 1] ? argv[at + 1] : null; };
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    console.error('not a directory: ' + root);
    return 1;
  }
  const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const outPath = path.resolve(repoRoot, flag('out') ?? 'foreign-capabilities.json');
  const id = (flag('id') ?? path.basename(root)).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63) || 'source';

  const files = walk(root);
  const capabilities = [
    ...recogniseMcp(root, files),
    ...recogniseOpenApi(root, files),
    ...recogniseSkills(root, files),
    ...recognisePlugins(root, files),
    ...recogniseCli(root, files),
    ...recogniseInstructions(root, files),
  ];

  const source = {
    id, kind: 'repo', acquiredBy: 'scripts/acquire-repo.mjs',
    directory: path.relative(repoRoot, root).split(path.sep).join('/'),
    filesScanned: files.length, truncated: files.length >= MAX_FILES,
    // `tools` is what src/foreign.mjs can compile. A repo scan on its own publishes no tool
    // contracts: an MCP server has to be asked for them, and a CLI needs a reviewed template.
    tools: [],
    capabilities: capabilities.slice(0, MAX_LISTED * 4),
    counts: capabilities.reduce((totals, entry) => {
      totals[entry.kind] = (totals[entry.kind] ?? 0) + 1;
      return totals;
    }, {}),
    byConfidence: capabilities.reduce((totals, entry) => {
      totals[entry.confidence] = (totals[entry.confidence] ?? 0) + 1;
      return totals;
    }, {}),
  };

  let manifest = { schemaVersion: 1, sources: [] };
  if (fs.existsSync(outPath)) {
    const existing = readJsonFile(outPath);
    if (existing && existing.schemaVersion === 1 && Array.isArray(existing.sources)) manifest = existing;
  }
  manifest.sources = [...manifest.sources.filter((entry) => entry.id !== id), source]
    .sort((a, b) => (a.id < b.id ? -1 : 1));
  fs.writeFileSync(outPath, canonical(manifest) + '\n');

  console.log(JSON.stringify({
    id, directory: source.directory, filesScanned: files.length,
    counts: source.counts, byConfidence: source.byConfidence,
    compilableToolContracts: source.tools.length,
    note: source.counts['mcp-server']
      ? 'This repo declares an MCP server: run scripts/acquire-mcp.mjs against it to acquire real tool contracts.'
      : 'No MCP server declared, so no tool contracts were acquired; CLI entries are candidates needing reviewed argv templates.',
    out: path.relative(repoRoot, outPath).split(path.sep).join('/'),
  }, null, 2));
  return 0;
}

process.exitCode = main();
