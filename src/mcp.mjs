#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonical, digest, parseJson, HarnessError } from './value.mjs';
import { runPlan } from './engine.mjs';
import { makeBuiltinTools } from './builtins.mjs';
import { loadSourceLock, makeSourceTools } from './sources.mjs';
import { makeCapabilityTools } from './capabilities.mjs';
import { makeArtifactTools } from './artifacts.mjs';
import { makeIntegrationTools } from './integrations.mjs';
import { makeAgentTools } from './workers.mjs';
import { makeBrowserTools } from './browser.mjs';
import { buildChatContext } from './chat-context.mjs';
import { createChatHarness } from './chat.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const PROTOCOL_VERSION = '2025-06-18';
const SERVER_NAME = 'concord';
const SERVER_VERSION = '0.2.0';
const MAX_LINE_BYTES = 8 * 1048576;
const GRANTED_EFFECTS = ['write', 'network', 'process'];
const RAW_PLAN_NAME = 'concord-mcp';
const RAW_TASK_ID = 'call';
const CHAT_TOOL_NAMES = ['concord_chat', 'concord_approve', 'concord_execute_plan', 'concord_replay', 'concord_chat_state'];

class McpProtocolError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/** Dotted Concord tool names aren't safe across every MCP client's function-name validator. */
export function mcpNameFor(toolName) {
  const mapped = toolName.replace(/\./g, '_');
  if (!/^[a-zA-Z0-9_-]+$/.test(mapped)) throw new HarnessError('MCP_CONFIG', 'Tool name does not map to a valid MCP tool name', { toolName });
  return mapped;
}

function isObjectSchema(schema) {
  return !!schema && typeof schema === 'object' && schema.type === 'object';
}

function readJsonFile(file, maxBytes = 33554432) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > maxBytes) throw new HarnessError('MCP_CONFIG', 'Expected a regular JSON file within the byte budget');
    const bytes = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < bytes.length) { const n = fs.readSync(fd, bytes, used, bytes.length - used, used); if (!n) break; used += n; }
    if (used !== stat.size) throw new HarnessError('MCP_CONFIG', 'JSON input changed during read');
    return parseJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, used)));
  } finally { fs.closeSync(fd); }
}

function parseArgs(argv) {
  const flags = {};
  const allowed = ['workspace', 'policy', 'integrations', 'workers', 'browser'];
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, '');
    if (!argv[i]?.startsWith('--') || !allowed.includes(key) || !argv[i + 1] || Object.hasOwn(flags, key)) {
      throw new HarnessError('MCP_USAGE', 'Usage: node src/mcp.mjs [--workspace DIR] [--policy FILE] [--integrations FILE] [--workers FILE] [--browser FILE]');
    }
    flags[key] = argv[i + 1];
  }
  return flags;
}

async function buildRegistry(flags) {
  const catalog = await loadSourceLock(path.join(root, 'sources.lock.json'));
  const inventory = readJsonFile(path.join(root, 'capabilities.lock.json'));
  const integrations = flags.integrations ? readJsonFile(flags.integrations) : {};
  const workers = flags.workers ? readJsonFile(flags.workers) : {};
  const browser = flags.browser ? readJsonFile(flags.browser) : undefined;
  const descriptors = [
    ...makeBuiltinTools(), ...makeSourceTools(catalog), ...makeCapabilityTools(inventory), ...makeArtifactTools(),
    ...makeIntegrationTools(integrations), ...makeAgentTools(workers), ...makeBrowserTools(browser),
  ];
  const registry = new Map();
  for (const tool of descriptors) {
    if (registry.has(tool.name)) throw new HarnessError('MCP_CONFIG', 'Duplicate tool name');
    registry.set(tool.name, tool);
  }
  return { registry, catalog, inventory, integrations };
}

function buildPolicy(flags, registry, integrations) {
  if (flags.policy) return readJsonFile(flags.policy);
  return {
    version: 1, allowedTools: [...registry.keys()].sort(), allowedEffects: ['pure', 'read', 'write', 'network', 'process'],
    allowedOrigins: [...new Set([integrations.model?.origin, integrations.typesafe?.origin, integrations.registry?.origin].filter(Boolean))].sort(),
    maxTasks: 32, maxOutputBytes: 1048576, maxJournalBytes: 16777216, timeoutMs: 60000,
  };
}

function blockedDetail(result) {
  const event = result.events.find(e => e.type === 'blocked');
  return event ? { effect: event.data.effect, tool: event.data.tool, input: event.data.input } : {};
}

function publicChatState(snapshot) {
  // Mirror server.mjs's publicState allowlist; never expose provider config or credentials.
  const result = {};
  for (const key of ['mode', 'history', 'selected', 'sourceCoverage', 'pending', 'proposedPlan', 'runs', 'lastError', 'observations', 'lessonCandidates', 'authority']) {
    if (snapshot && Object.hasOwn(snapshot, key)) result[key] = snapshot[key];
  }
  return result;
}

/**
 * Builds the MCP-facing surface over an already-assembled Concord registry/policy/harness:
 * raw tool access (one MCP tool per registered tool, gated effects round-tripping through
 * an exact request-hash `_confirm`), the 12 reviewed instruction modules as resources, and
 * the chat harness as five `concord_*` tools. Collisions in the dotted-to-underscored name
 * map are asserted here, at construction, rather than at first call.
 */
export function createMcpServer({ registry, policy, sourceLock, workspaceRoot, harness, instructionModules }) {
  const visibleRegistry = new Map([...registry].filter(([name, tool]) => policy.allowedTools.includes(name) && policy.allowedEffects.includes(tool.effect)));
  const nameMap = new Map();
  const wrapped = new Set();
  for (const [toolName, tool] of visibleRegistry) {
    const mcpName = mcpNameFor(toolName);
    if (nameMap.has(mcpName) || CHAT_TOOL_NAMES.includes(mcpName)) throw new HarnessError('MCP_CONFIG', 'MCP tool name collision', { mcpName });
    nameMap.set(mcpName, toolName);
    if (!isObjectSchema(tool.inputSchema)) wrapped.add(toolName);
  }
  const instructionsBySourceId = new Map(instructionModules.map(m => [m.sourceId, m]));

  function buildRawPlan(toolName, input) {
    return { version: 1, name: RAW_PLAN_NAME, tasks: [{ id: RAW_TASK_ID, tool: toolName, input }] };
  }

  async function callRawTool(toolName, tool, args) {
    let input = args;
    let confirmHash;
    if (GRANTED_EFFECTS.includes(tool.effect)) {
      if (!args || typeof args !== 'object' || Array.isArray(args)) {
        return { content: [{ type: 'text', text: canonical({ status: 'failed', code: 'INPUT_INVALID', message: 'Arguments must be an object for a gated effect.' }) }], isError: true };
      }
      const { _confirm, ...rest } = args;
      confirmHash = typeof _confirm === 'string' ? _confirm : undefined;
      input = rest;
    }
    const plan = buildRawPlan(toolName, input);
    const approvals = confirmHash ? [confirmHash] : [];
    let result;
    try {
      result = await runPlan({ plan, policy, registry, sourceLock, approvals, workspaceRoot });
    } catch (error) {
      const code = error instanceof HarnessError ? error.code : 'TOOL_CALL_FAILED';
      const message = error instanceof HarnessError ? error.message : 'The tool call could not be completed.';
      return { content: [{ type: 'text', text: canonical({ status: 'failed', code, message }) }], isError: true };
    }
    if (result.outcome.status === 'blocked') {
      const detail = blockedDetail(result);
      return {
        content: [{
          type: 'text', text: canonical({
            status: 'blocked', tool: toolName, effect: detail.effect, input: detail.input,
            requestHash: result.outcome.requestHash,
            hint: 'Call this tool again with "_confirm" set to this exact requestHash to execute it.',
          }),
        }],
      };
    }
    if (result.outcome.status === 'failed') {
      return { content: [{ type: 'text', text: canonical({ status: 'failed', code: result.outcome.code, taskId: result.outcome.taskId }) }], isError: true };
    }
    return { content: [{ type: 'text', text: canonical(result.results[RAW_TASK_ID]) }] };
  }

  let chatQueue = Promise.resolve();
  function serialize(fn) {
    const result = chatQueue.then(fn, fn);
    chatQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  async function callChatTool(name, args) {
    return serialize(async () => {
      try {
        let snapshot;
        let extra = {};
        if (name === 'concord_chat') {
          if (typeof args.message !== 'string' || !args.message.trim()) throw new McpProtocolError(-32602, 'Invalid params: "message" is required');
          snapshot = await harness.send(args.message);
        } else if (name === 'concord_approve') {
          if (typeof args.requestHash !== 'string') throw new McpProtocolError(-32602, 'Invalid params: "requestHash" is required');
          snapshot = await harness.approve(args.requestHash);
        } else if (name === 'concord_execute_plan') {
          snapshot = await harness.executePlan(args.plan);
        } else if (name === 'concord_replay') {
          if (typeof args.runId !== 'string') throw new McpProtocolError(-32602, 'Invalid params: "runId" is required');
          const replay = await harness.replay(args.runId);
          const summary = { runId: args.runId, verified: replay?.replayed === true };
          if (typeof replay?.root === 'string') summary.root = replay.root;
          if (Array.isArray(replay?.events)) summary.eventCount = replay.events.length;
          extra = { replay: summary };
          snapshot = harness.snapshot();
        } else {
          snapshot = harness.snapshot();
        }
        return { content: [{ type: 'text', text: canonical({ state: publicChatState(snapshot), ...extra }) }] };
      } catch (error) {
        if (error instanceof McpProtocolError) throw error;
        const code = error instanceof HarnessError ? error.code : 'CHAT_FAILED';
        const message = error instanceof HarnessError ? error.message : 'The chat action could not be completed.';
        return { content: [{ type: 'text', text: canonical({ status: 'failed', code, message }) }], isError: true };
      }
    });
  }

  function mcpSchemaFor(tool) {
    if (isObjectSchema(tool.inputSchema)) return tool.inputSchema;
    return { type: 'object', properties: { value: {} }, required: ['value'], additionalProperties: false };
  }

  function toolDefinitions() {
    const defs = [];
    for (const [toolName, tool] of visibleRegistry) {
      const gated = GRANTED_EFFECTS.includes(tool.effect);
      defs.push({
        name: mcpNameFor(toolName),
        description: `Concord tool "${toolName}" (${tool.effect} effect).` + (gated ? ' Requires a two-step propose/"_confirm" call before it executes.' : ''),
        inputSchema: mcpSchemaFor(tool),
      });
    }
    defs.push(
      { name: 'concord_chat', description: 'Send a message to Concord\'s deterministic chat harness, grounded in its reviewed source instructions, and get its reply.', inputSchema: { type: 'object', properties: { message: { type: 'string', minLength: 1, maxLength: 32768 } }, required: ['message'], additionalProperties: false } },
      { name: 'concord_approve', description: 'Approve a pending write/network/process effect in the chat harness by its exact request hash.', inputSchema: { type: 'object', properties: { requestHash: { type: 'string', minLength: 64, maxLength: 64 } }, required: ['requestHash'], additionalProperties: false } },
      { name: 'concord_execute_plan', description: 'Attempt the chat harness\'s currently proposed plan again (e.g. after approving a dependency), or adopt and attempt a new plan.', inputSchema: { type: 'object', properties: { plan: { type: 'object' } }, additionalProperties: false } },
      { name: 'concord_replay', description: 'Independently replay a prior chat run by id and verify it reproduces the same recorded outcome.', inputSchema: { type: 'object', properties: { runId: { type: 'string', minLength: 1, maxLength: 128 } }, required: ['runId'], additionalProperties: false } },
      { name: 'concord_chat_state', description: 'Read the chat harness\'s current state (history, pending approval, proposed plan, run list) without changing anything.', inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
    );
    return defs;
  }

  function resourceDefinitions() {
    return [...instructionsBySourceId.values()]
      .map(m => ({ uri: 'concord://instructions/' + m.sourceId, name: m.sourceId, title: m.sourceId, description: `Reviewed Concord source instruction module (${m.file})`, mimeType: 'text/markdown' }))
      .sort((a, b) => a.uri < b.uri ? -1 : a.uri > b.uri ? 1 : 0);
  }

  function readResource(uri) {
    const match = /^concord:\/\/instructions\/([a-z0-9-]+)$/.exec(typeof uri === 'string' ? uri : '');
    const module = match ? instructionsBySourceId.get(match[1]) : undefined;
    return module ? { uri, mimeType: 'text/markdown', text: module.text } : null;
  }

  async function handleToolsCall(params) {
    if (!params || typeof params !== 'object' || typeof params.name !== 'string') throw new McpProtocolError(-32602, 'Invalid params: "name" is required');
    const rawArgs = params.arguments;
    const args = rawArgs === undefined ? {} : rawArgs;
    if (typeof args !== 'object' || args === null || Array.isArray(args)) throw new McpProtocolError(-32602, 'Invalid params: "arguments" must be an object');
    if (CHAT_TOOL_NAMES.includes(params.name)) return callChatTool(params.name, args);
    const toolName = nameMap.get(params.name);
    if (!toolName) throw new McpProtocolError(-32602, 'Unknown tool: ' + params.name);
    const tool = registry.get(toolName);
    let input = args;
    if (wrapped.has(toolName)) {
      if (!Object.hasOwn(args, 'value')) throw new McpProtocolError(-32602, 'Invalid params: "value" is required');
      input = args.value;
    }
    return callRawTool(toolName, tool, input);
  }

  async function dispatch(method, params) {
    switch (method) {
      case 'initialize':
        return {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false }, resources: { listChanged: false, subscribe: false } },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
          instructions: 'Concord is a deterministic AI chat harness: every write, network, or process effect requires an exact content-derived approval hash before it runs. A raw tool call that needs a grant returns a "blocked" result with a requestHash; call the same tool again with "_confirm" set to that hash to execute it. The concord_* tools drive a stateful, instruction-grounded chat session over the same kernel; resources/* exposes the 12 reviewed source instruction modules.',
        };
      case 'ping':
        return {};
      case 'tools/list':
        return { tools: toolDefinitions() };
      case 'tools/call':
        return handleToolsCall(params);
      case 'resources/list':
        return { resources: resourceDefinitions() };
      case 'resources/read': {
        const resource = readResource(params?.uri);
        if (!resource) throw new McpProtocolError(-32002, 'Unknown resource: ' + params?.uri);
        return { contents: [resource] };
      }
      default:
        throw new McpProtocolError(-32601, 'Method not found: ' + method);
    }
  }

  async function handleLine(line) {
    let message;
    try { message = parseJson(line); }
    catch { return canonical({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      return canonical({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    }
    if (!Object.hasOwn(message, 'id')) return null; // A notification: never respond, even if further malformed.
    const id = message.id;
    if (message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
      return canonical({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } });
    }
    try {
      const result = await dispatch(message.method, message.params);
      return canonical({ jsonrpc: '2.0', id, result });
    } catch (error) {
      const code = error instanceof McpProtocolError ? error.code : -32603;
      const errorMessage = error instanceof McpProtocolError ? error.message : 'Internal error';
      return canonical({ jsonrpc: '2.0', id, error: { code, message: errorMessage } });
    }
  }

  return { handleLine };
}

export async function main(argv = process.argv.slice(2)) {
  const flags = parseArgs(argv);
  const { registry, catalog, inventory, integrations } = await buildRegistry(flags);
  const policy = buildPolicy(flags, registry, integrations);
  const workspaceRoot = fs.realpathSync(path.resolve(flags.workspace ?? root));
  const runtimeFiles = fs.readdirSync(path.join(root, 'src')).filter(f => f.endsWith('.mjs')).map(f => 'src/' + f).sort();
  const sourceLock = {
    catalog, inventoryHash: digest(inventory),
    runtime: { node: process.version, platform: process.platform, arch: process.arch, files: runtimeFiles.map(f => ({ path: f, sha256: createHash('sha256').update(fs.readFileSync(path.join(root, f))).digest('hex') })) },
  };
  const visibleRegistry = new Map([...registry].filter(([name, tool]) => policy.allowedTools.includes(name) && policy.allowedEffects.includes(tool.effect)));
  const instructionRoot = path.join(root, 'instructions');
  const buildContext = ({ message, history, observations, proposedPlan }) => buildChatContext({ message, history, observations, proposedPlan, sourceLock: catalog, inventory, registry: visibleRegistry, policy, instructionRoot });
  const resourceContext = buildContext({ message: 'Concord MCP server startup', history: [] });
  const harness = createChatHarness({ registry, policy, sourceLock, workspaceRoot, buildContext });

  const server = createMcpServer({ registry, policy, sourceLock, workspaceRoot, harness, instructionModules: resourceContext.instructions });

  let decoder = new TextDecoder('utf-8', { fatal: true });
  let buffered = '';
  const write = (text) => process.stdout.write(text + '\n');
  const writeError = (code, message) => write(canonical({ jsonrpc: '2.0', id: null, error: { code, message } }));

  process.stdin.on('data', (chunk) => {
    let text;
    try { text = decoder.decode(chunk, { stream: true }); }
    catch {
      writeError(-32700, 'Parse error: invalid UTF-8');
      buffered = '';
      decoder = new TextDecoder('utf-8', { fatal: true }); // A prior chunk may have left partial multi-byte state.
      return;
    }
    buffered += text;
    if (Buffer.byteLength(buffered) > MAX_LINE_BYTES) {
      writeError(-32600, 'Invalid Request: line exceeds the maximum size without a newline');
      buffered = '';
      return;
    }
    let boundary;
    while ((boundary = buffered.indexOf('\n')) >= 0) {
      const line = buffered.slice(0, boundary);
      buffered = buffered.slice(boundary + 1);
      if (!line.trim()) continue;
      server.handleLine(line)
        .then((response) => { if (response !== null) write(response); })
        .catch(() => writeError(-32603, 'Internal error'));
    }
  });
  process.stdin.on('end', () => process.exit(0));

  console.error(`Concord MCP server ready (stdio). Mode: ${registry.has('model.propose') ? 'live model configured; each network call requires its exact grant' : 'offline deterministic demonstration'}. Tools: ${visibleRegistry.size + CHAT_TOOL_NAMES.length}. Resources: ${resourceContext.instructions.length}.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof HarnessError ? `${error.code}: ${error.message}` : 'MCP_START_FAILED: Check local configuration and paths.');
    process.exitCode = 1;
  });
}
