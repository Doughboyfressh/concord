import { spawn } from 'node:child_process';
import { HarnessError, canonical, clone, deepFreeze, digest, parseJson, validateSchema } from './value.mjs';
import { schemaWellFormed } from './engine.mjs';
import { limits, processEnv, resolveExecutable } from './integrations.mjs';

/**
 * Foreign capabilities: turning another program's published tool contracts into Concord tools.
 *
 * This is the general form of what `src/reverse.mjs` does for one named upstream. A *capability
 * manifest* records what some other thing says it can do, acquired out of band; this compiles the
 * entries an operator has reviewed into live tools. An MCP server is the highest-fidelity producer
 * of such a manifest, because it publishes its own names, descriptions and JSON Schemas rather
 * than needing them extracted from its source.
 *
 * Four properties make importing a foreign surface safe to do at all:
 *
 *   - **Nothing is granted by importing.** A manifest is inert data. A server's tools register
 *     only where the operator both configured that server and named the tool in its `allow` list,
 *     so acquiring a 40-tool manifest grants nothing by itself.
 *   - **Names are namespaced.** A foreign tool becomes `foreign.<sourceId>.<toolName>`, so it can
 *     never shadow a Concord tool or another server's tool of the same name.
 *   - **argv is entirely the operator's.** The plan supplies only the tool's arguments, which
 *     travel in the JSON-RPC body; nothing a plan says reaches the command line.
 *   - **A foreign schema is checked before it is trusted.** The server wrote it, so it is only
 *     used when Concord can actually enforce it; otherwise a bounded fallback is used and the
 *     substitution is reported rather than hidden.
 */

const MAX_FOREIGN_INPUT = 256 * 1024;
const MAX_TEXT_CHARS = 262144;
const MAX_TOOLS_PER_SERVER = 512;
const PROTOCOL_VERSION = '2025-06-18';

const fail = (code, message, details) => { throw new HarnessError(code, message, details); };
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function checkManifest(manifest) {
  if (!isObject(manifest) || manifest.schemaVersion !== 1 || !Array.isArray(manifest.sources)) {
    fail('FOREIGN_MANIFEST_INVALID', 'A foreign capability manifest requires schemaVersion 1 and a sources array');
  }
  const ids = new Set();
  for (const source of manifest.sources) {
    if (!isObject(source) || typeof source.id !== 'string' || !/^[a-z][a-z0-9-]{1,63}$/.test(source.id) || ids.has(source.id)) {
      fail('FOREIGN_MANIFEST_INVALID', 'Each manifest source needs a unique portable id');
    }
    ids.add(source.id);
    if (typeof source.kind !== 'string' || !/^[a-z][a-z0-9-]{1,31}$/.test(source.kind)) {
      fail('FOREIGN_MANIFEST_INVALID', 'Each manifest source must declare its kind', { source: source.id });
    }
    if (!Array.isArray(source.tools)) fail('FOREIGN_MANIFEST_INVALID', 'Each manifest source needs a tools array', { source: source.id });
    if (source.tools.length > MAX_TOOLS_PER_SERVER) fail('FOREIGN_MANIFEST_INVALID', 'A manifest source declares more tools than the bound permits', { source: source.id });
    const names = new Set();
    for (const tool of source.tools) {
      if (!isObject(tool) || typeof tool.name !== 'string' || !/^[A-Za-z0-9_.-]{1,96}$/.test(tool.name) || names.has(tool.name)) {
        fail('FOREIGN_MANIFEST_INVALID', 'Each manifest tool needs a unique portable name', { source: source.id });
      }
      names.add(tool.name);
    }
  }
  return deepFreeze(clone(manifest));
}

/** One reviewed foreign server: an exact executable, fixed argv, and the tools it may expose. */
function checkServer(value) {
  if (!isObject(value)) fail('FOREIGN_CONFIG', 'A foreign server entry must be an object');
  const allowed = ['id', 'executable', 'executableSha256', 'args', 'cwd', 'env', 'allowedEnv', 'allow', 'timeoutMs', 'maxOutputBytes'];
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail('FOREIGN_CONFIG', 'Unsupported foreign server field', { field: key });
  if (typeof value.id !== 'string' || !/^[a-z][a-z0-9-]{1,63}$/.test(value.id)) fail('FOREIGN_CONFIG', 'A foreign server needs a portable id');
  if (typeof value.executable !== 'string' || value.executable.length === 0) {
    fail('FOREIGN_CONFIG', 'A foreign server needs the path of the reviewed executable', { server: value.id });
  }
  // resolveExecutable verifies this digest against the file before spawning, so an absent or
  // malformed one could never have produced a working call. Checking its shape here turns that
  // into a registry-build failure rather than a failure on first use.
  if (typeof value.executableSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.executableSha256)) {
    fail('FOREIGN_CONFIG', 'A foreign server needs the SHA-256 digest of its reviewed executable, as 64 lower-case hex characters', { server: value.id });
  }
  if (!Array.isArray(value.args) || value.args.some((arg) => typeof arg !== 'string' || arg.includes('\0'))) {
    fail('FOREIGN_CONFIG', 'Foreign server args must be fixed strings', { server: value.id });
  }
  // An absent or empty allow list registers nothing. Importing a manifest is not a grant.
  if (!Array.isArray(value.allow) || value.allow.some((name) => typeof name !== 'string')) {
    fail('FOREIGN_CONFIG', 'A foreign server must declare an allow list naming the tools it may expose', { server: value.id });
  }
  return {
    id: value.id, executable: value.executable, executableSha256: value.executableSha256,
    args: [...value.args], cwd: value.cwd ?? '.', env: value.env ?? {}, allowedEnv: value.allowedEnv ?? [],
    allow: [...new Set(value.allow)],
    timeoutMs: value.timeoutMs ?? 60_000, maxOutputBytes: value.maxOutputBytes ?? 1_048_576,
  };
}

/**
 * Is this a schema Concord can enforce on a plan's input?
 *
 * A foreign server authored it, so it is accepted only if it is an object schema that validates.
 * Anything else is replaced by a bounded fallback, and the caller reports the substitution: an
 * unenforceable schema silently accepted would mean a tool whose input nothing checks.
 */
export function usableForeignSchema(schema) {
  if (!isObject(schema) || schema.type !== 'object') return null;
  try { schemaWellFormed(schema); }
  catch { return null; }
  try { validateSchema({}, schema); }
  catch (error) { if (error.code !== 'SCHEMA_MISMATCH') return null; }
  return schema;
}
const FALLBACK_SCHEMA = { type: 'object', additionalProperties: true };

/**
 * One bounded request/response exchange with an MCP server over stdio.
 *
 * The server is spawned per call and killed afterwards rather than kept alive between calls: a
 * session held across separately approved calls would make each call's receipt depend on state no
 * receipt records. Output is bounded while it streams, not after.
 */
export function callMcpServer({ executable, args, cwd, env, timeoutMs, maxOutputBytes, method, params, signal }) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let settled = false;
    let stdout = '';
    let stderr = '';
    let bytes = 0;
    let handshake = null;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      if (error) reject(error); else resolve(value);
    };
    const onAbort = () => finish(new HarnessError('FOREIGN_ABORTED', 'The foreign call was cancelled'));
    const timer = setTimeout(() => finish(new HarnessError('FOREIGN_TIMEOUT', 'The foreign server exceeded its deadline')), timeoutMs);
    if (signal) {
      if (signal.aborted) { finish(new HarnessError('FOREIGN_ABORTED', 'The foreign call was cancelled')); return; }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    const send = (message) => { try { child.stdin.write(JSON.stringify(message) + '\n'); } catch { /* the exit handler reports it */ } };
    child.on('error', (error) => finish(new HarnessError('FOREIGN_SPAWN_FAILED', 'The foreign server could not be started: ' + error.message)));
    child.stderr.on('data', (chunk) => { if (stderr.length < 8192) stderr += chunk.toString('utf8'); });
    child.on('exit', (code) => finish(new HarnessError('FOREIGN_EXITED',
      'The foreign server exited with code ' + code + ' before answering' + (stderr ? ': ' + stderr.slice(0, 512) : ''))));

    child.stdout.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > maxOutputBytes) { finish(new HarnessError('FOREIGN_OUTPUT_LIMIT', 'The foreign server produced more output than the budget permits')); return; }
      stdout += chunk.toString('utf8');
      let newline = stdout.indexOf('\n');
      while (newline >= 0) {
        const line = stdout.slice(0, newline).trim();
        stdout = stdout.slice(newline + 1);
        newline = stdout.indexOf('\n');
        if (!line) continue;
        let message;
        // A line that is not a JSON-RPC message is ignored rather than fatal: a server is
        // entitled to log, and only a reply to a request this client sent is of interest.
        try { message = parseJson(line); } catch { continue; }
        if (!isObject(message)) continue;
        if (message.id === 1 && message.result !== undefined) {
          handshake = message.result;
          send({ jsonrpc: '2.0', method: 'notifications/initialized' });
          send({ jsonrpc: '2.0', id: 2, method, params });
          continue;
        }
        if (message.id === 1 && message.error) { finish(new HarnessError('FOREIGN_HANDSHAKE_FAILED', 'The foreign server refused initialization: ' + (message.error.message ?? 'no reason given'))); return; }
        if (message.id === 2) {
          if (message.error) { finish(new HarnessError('FOREIGN_CALL_FAILED', 'The foreign server returned an error: ' + (message.error.message ?? 'no reason given'))); return; }
          finish(null, { initialize: handshake, result: message.result });
          return;
        }
      }
    });

    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: PROTOCOL_VERSION, capabilities: {},
      clientInfo: { name: 'concord-foreign-client', version: '1.0.0' },
    } });
  });
}

/** Concatenate an MCP content array into bounded text, reporting what was dropped. */
function textOf(content, limitations) {
  if (!Array.isArray(content)) return null;
  const parts = [];
  let nonText = 0;
  for (const block of content) {
    if (isObject(block) && block.type === 'text' && typeof block.text === 'string') parts.push(block.text);
    else nonText += 1;
  }
  if (nonText) limitations.push('The reply carried ' + nonText + ' non-text content block(s), which are reported as a count rather than copied');
  const joined = parts.join('\n');
  if (joined.length > MAX_TEXT_CHARS) {
    limitations.push('The reply text was truncated to the read bound');
    return joined.slice(0, MAX_TEXT_CHARS);
  }
  return joined;
}

/**
 * Compile a foreign capability manifest plus reviewed server configuration into Concord tools.
 *
 * Only what the operator both configured and allowed is registered. `foreign.catalog` reports the
 * whole manifest regardless, so an unprovisioned surface stays discoverable without pretending to
 * be executable.
 */
export function makeForeignTools(manifest, config = {}) {
  const checked = checkManifest(manifest);
  if (!isObject(config)) fail('FOREIGN_CONFIG', 'Foreign configuration must be an object');
  for (const key of Object.keys(config)) if (key !== 'servers') fail('FOREIGN_CONFIG', 'Unsupported foreign configuration field', { field: key });

  const servers = new Map();
  for (const value of config.servers ?? []) {
    const server = checkServer(value);
    if (servers.has(server.id)) fail('FOREIGN_CONFIG', 'Foreign server ids must be unique', { server: server.id });
    const source = checked.sources.find((entry) => entry.id === server.id);
    if (!source) fail('FOREIGN_CONFIG', 'No manifest source has this server id', { server: server.id });
    for (const name of server.allow) {
      if (!source.tools.some((tool) => tool.name === name)) {
        fail('FOREIGN_CONFIG', 'The allow list names a tool this source does not publish', { server: server.id, tool: name });
      }
    }
    servers.set(server.id, server);
  }

  const rows = [];
  for (const source of checked.sources) {
    const server = servers.get(source.id);
    for (const tool of source.tools) {
      const schema = usableForeignSchema(tool.inputSchema);
      rows.push({
        source: source.id, kind: source.kind, tool: tool.name,
        concordName: 'foreign.' + source.id + '.' + tool.name,
        allowed: server ? server.allow.includes(tool.name) : false,
        configured: Boolean(server),
        schemaUsable: schema !== null,
        available: Boolean(server) && server.allow.includes(tool.name),
      });
    }
  }
  const catalogData = deepFreeze({
    schemaVersion: 1, sources: checked.sources.map((source) => ({ id: source.id, kind: source.kind,
      server: source.server ?? null, tools: source.tools.length, configured: servers.has(source.id) })),
    total: rows.length, availableNow: rows.filter((row) => row.available).length, tools: rows,
  });
  const catalogSchema = { type: 'object', additionalProperties: false, properties: {
    source: { type: 'string', minLength: 1, maxLength: 64 },
    availableOnly: { type: 'boolean' },
  } };

  const tools = [{
    name: 'foreign.catalog', version: '1.0.0', effect: 'pure',
    outputKeys: ['schemaVersion', 'sources', 'total', 'availableNow', 'tools', 'matched', 'grantsCapabilities'],
    inputSchema: catalogSchema, config: { manifestDigest: digest(catalogData), total: rows.length },
    execute(input = {}) {
      validateSchema(input, catalogSchema);
      const selected = catalogData.tools.filter((row) => (!input.source || row.source === input.source)
        && (!input.availableOnly || row.available));
      // Inert data describing other programs. Listing a name never grants it.
      return { ...catalogData, tools: clone(selected), matched: selected.length, grantsCapabilities: false };
    },
  }];

  for (const source of checked.sources) {
    const server = servers.get(source.id);
    if (!server) continue;
    for (const tool of source.tools) {
      if (!server.allow.includes(tool.name)) continue;
      const published = usableForeignSchema(tool.inputSchema);
      const inputSchema = published ?? FALLBACK_SCHEMA;
      const processShape = {
        name: 'foreign.' + source.id + '.' + tool.name, version: '1.0.0',
        executable: server.executable, executableSha256: server.executableSha256,
        cwd: server.cwd, env: server.env, allowedEnv: server.allowedEnv,
        timeoutMs: server.timeoutMs, maxOutputBytes: server.maxOutputBytes,
      };
      tools.push({
        name: processShape.name, version: '1.0.0', effect: 'process',
        outputKeys: ['source', 'tool', 'isError', 'text', 'limitations', 'untrusted'],
        inputSchema,
        // The approval binds the server's identity and argv together with the published schema, so
        // a changed command or a changed contract invalidates an approval granted for the old one.
        config: { source: source.id, kind: source.kind, foreignTool: tool.name,
          argvDigest: digest(server.args), schemaDigest: digest(published ?? null),
          schemaUsable: published !== null },
        async execute(input, context) {
          validateSchema(input, inputSchema);
          const limitations = [];
          if (!published) limitations.push('The server published a schema Concord cannot enforce, so a bounded fallback was used and this input was not checked against the published contract');
          const encoded = Buffer.byteLength(canonical(input));
          if (encoded > MAX_FOREIGN_INPUT) fail('FOREIGN_INPUT_LIMIT', 'The foreign call input exceeds the byte limit');
          const bound = limits(processShape, context, processShape.name, 'process');
          const { executable, cwd } = await resolveExecutable(processShape, context.workspaceRoot);
          if (context?.signal?.aborted) fail('FOREIGN_ABORTED', 'The foreign call was cancelled');
          const { env } = processEnv(processShape);
          const { result } = await callMcpServer({
            executable, args: server.args, cwd, env,
            timeoutMs: bound.timeoutMs, maxOutputBytes: bound.maxOutputBytes, signal: context?.signal,
            method: 'tools/call', params: { name: tool.name, arguments: input },
          });
          const content = isObject(result) ? result.content : null;
          // A foreign reply is text from a program Concord does not control.
          return { source: source.id, tool: tool.name,
            isError: isObject(result) ? result.isError === true : false,
            text: textOf(content, limitations), limitations, untrusted: true };
        },
      });
    }
  }
  return tools;
}
