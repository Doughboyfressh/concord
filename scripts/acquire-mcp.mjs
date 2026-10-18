import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonical, parseJson } from '../src/value.mjs';
import { callMcpServer, usableForeignSchema } from '../src/foreign.mjs';

/**
 * Ask a reviewed MCP server what it can do, and record the answer.
 *
 * This is the high-fidelity acquisition path. Every other recogniser infers a capability from a
 * filename or a manifest convention; an MCP server *publishes* its tool contracts, so the names,
 * descriptions and input schemas recorded here are the server's own words rather than anything
 * guessed from its source.
 *
 * Out of band by design, the same role as the sibling acquire scripts: this spawns the server, so
 * an operator runs it deliberately. Importing the result grants nothing — src/foreign.mjs
 * registers a tool only where the operator also configured the server and named the tool in its
 * allow list.
 *
 * Usage:
 *   node scripts/acquire-mcp.mjs --id <source-id> --executable <abs-path> [--cwd <dir>] -- <args...>
 */

const MAX_TOOLS = 512;

function main() {
  const argv = process.argv.slice(2);
  const separator = argv.indexOf('--');
  const options = separator < 0 ? argv : argv.slice(0, separator);
  const serverArgs = separator < 0 ? [] : argv.slice(separator + 1);
  const flag = (name) => { const at = options.indexOf('--' + name); return at >= 0 && options[at + 1] ? options[at + 1] : null; };

  const id = flag('id');
  const executable = flag('executable');
  if (!id || !executable) {
    console.log('Usage: node scripts/acquire-mcp.mjs --id <source-id> --executable <abs-path> [--cwd <dir>] [--out <file>] -- <args...>');
    return 2;
  }
  if (!/^[a-z][a-z0-9-]{1,63}$/.test(id)) { console.error('source id must be a portable lower-case identifier'); return 1; }
  if (!path.isAbsolute(executable)) { console.error('the executable must be an absolute path, so what was run is unambiguous'); return 1; }
  if (!fs.existsSync(executable)) { console.error('no such executable: ' + executable); return 1; }

  const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const outPath = path.resolve(repoRoot, flag('out') ?? 'foreign-capabilities.json');
  const cwd = path.resolve(repoRoot, flag('cwd') ?? '.');
  // The digest is recorded so a later compile can bind the approval to this exact binary.
  const executableSha256 = createHash('sha256').update(fs.readFileSync(executable)).digest('hex');

  return callMcpServer({
    executable, args: serverArgs, cwd, env: { PATH: process.env.PATH ?? '' },
    timeoutMs: 120_000, maxOutputBytes: 8 * 1024 * 1024,
    method: 'tools/list', params: {},
  }).then(({ initialize, result }) => {
    const published = Array.isArray(result?.tools) ? result.tools : [];
    if (published.length > MAX_TOOLS) {
      console.error('the server published more tools than the bound permits');
      return 1;
    }
    const tools = published.map((tool) => {
      const schema = usableForeignSchema(tool.inputSchema);
      return {
        name: tool.name,
        description: typeof tool.description === 'string' ? tool.description : null,
        inputSchema: tool.inputSchema ?? null,
        // Recorded at acquisition so a reviewer sees which contracts Concord can actually
        // enforce before deciding what to allow, rather than discovering it at call time.
        schemaUsable: schema !== null,
        confidence: 'declared',
        reason: 'The server published this tool through tools/list',
      };
    }).sort((a, b) => (a.name < b.name ? -1 : 1));

    const source = {
      id, kind: 'mcp', acquiredBy: 'scripts/acquire-mcp.mjs',
      server: {
        name: initialize?.serverInfo?.name ?? null,
        version: initialize?.serverInfo?.version ?? null,
        protocolVersion: initialize?.protocolVersion ?? null,
        capabilities: Object.keys(initialize?.capabilities ?? {}).sort(),
        instructions: typeof initialize?.instructions === 'string' ? initialize.instructions.slice(0, 4096) : null,
      },
      command: { executable, executableSha256, args: serverArgs, cwd: path.relative(repoRoot, cwd).split(path.sep).join('/') || '.' },
      tools,
      counts: { tools: tools.length, schemaUsable: tools.filter((tool) => tool.schemaUsable).length },
    };

    let manifest = { schemaVersion: 1, sources: [] };
    if (fs.existsSync(outPath)) {
      try {
        const existing = parseJson(fs.readFileSync(outPath, 'utf8'));
        if (existing && existing.schemaVersion === 1 && Array.isArray(existing.sources)) manifest = existing;
      } catch { /* a malformed manifest is replaced rather than merged into */ }
    }
    manifest.sources = [...manifest.sources.filter((entry) => entry.id !== id), source]
      .sort((a, b) => (a.id < b.id ? -1 : 1));
    fs.writeFileSync(outPath, canonical(manifest) + '\n');

    console.log(JSON.stringify({
      id, server: source.server.name, version: source.server.version,
      protocolVersion: source.server.protocolVersion,
      tools: source.counts.tools, schemaUsable: source.counts.schemaUsable,
      schemaUnusable: source.counts.tools - source.counts.schemaUsable,
      executableSha256,
      note: 'Nothing is registered yet. Add a servers entry naming this id, this executable digest and an allow list before any of these tools exist in Concord.',
      out: path.relative(repoRoot, outPath).split(path.sep).join('/'),
    }, null, 2));
    return 0;
  }).catch((error) => {
    console.error((error.code ?? 'ACQUIRE_FAILED') + ': ' + error.message);
    return 1;
  });
}

const code = main();
if (code instanceof Promise) code.then((value) => { process.exitCode = value; });
else process.exitCode = code;
