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
import { createClientChannel, createHubResponder, makePeerTools, makeMailboxTools, readMailbox, fileMessage } from './peer.mjs';
import { joinHub } from './peer-hub.mjs';
import { makeSkillStoreTools } from './skillstore.mjs';
import { makeGovernanceTools } from './governance.mjs';
import { makeArtifactTools } from './artifacts.mjs';
import { makeIntegrationTools } from './integrations.mjs';
import { makeReverseTools } from './reverse.mjs';
import { makeReaderTools } from './readers.mjs';
import { makeForeignTools } from './foreign.mjs';
import { makeAgentTools } from './workers.mjs';
import { makeBrowserTools } from './browser.mjs';
import { makeDecompilerTools } from './decompiler.mjs';
import { makeWebTools } from './web.mjs';
import { makeBuildTools } from './build.mjs';
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
// The MCP Apps extension: a server may hand the host an HTML document and the host renders it as
// an interface. Claude Desktop declares this and declares neither sampling nor elicitation, so on
// that client this is the only direction in which Concord can present anything of its own.
const UI_EXTENSION = 'io.modelcontextprotocol/ui';
const UI_MIME_TYPE = 'text/html;profile=mcp-app';
const UI_RESOURCE_URI = 'ui://concord/chat';

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
  const allowed = ['workspace', 'policy', 'integrations', 'workers', 'browser', 'decompiler', 'web', 'build', 'reverse', 'foreign', 'mailbox'];
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, '');
    if (!argv[i]?.startsWith('--') || !allowed.includes(key) || !argv[i + 1] || Object.hasOwn(flags, key)) {
      throw new HarnessError('MCP_USAGE', 'Usage: node src/mcp.mjs [--workspace DIR] [--policy FILE] [--integrations FILE] [--workers FILE] [--browser FILE] [--decompiler FILE] [--web FILE] [--build FILE] [--reverse FILE] [--foreign FILE] [--mailbox DIR]');
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
  const decompiler = flags.decompiler ? readJsonFile(flags.decompiler) : undefined;
  const web = flags.web ? readJsonFile(flags.web) : undefined;
  const build = flags.build ? readJsonFile(flags.build) : undefined;
  const reverseTable = readJsonFile(path.join(root, 'reverse-tools.json'));
  const reverse = flags.reverse ? readJsonFile(flags.reverse) : {};
  const foreignPath = path.join(root, 'foreign-capabilities.json');
  const foreignManifest = fs.existsSync(foreignPath) ? readJsonFile(foreignPath) : { schemaVersion: 1, sources: [] };
  const foreign = flags.foreign ? readJsonFile(flags.foreign) : {};
  const descriptors = [
    ...makeBuiltinTools(), ...makeSourceTools(catalog), ...makeCapabilityTools(inventory), ...makeArtifactTools(),
    ...makeIntegrationTools(integrations), ...makeAgentTools(workers), ...makeBrowserTools(browser), ...makeDecompilerTools(decompiler),
    ...makeWebTools(web), ...makeBuildTools(build),
    ...makeReverseTools(reverseTable, reverse), ...makeReaderTools(),
    ...makeForeignTools(foreignManifest, foreign),
    ...makeSkillStoreTools(inventory),
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
    maxTasks: 32, maxOutputBytes: 1048576, maxJournalBytes: 16777216,
    // This transport registers peer.request, which waits on a person answering a prompt, and a
    // policy deadline is the ceiling every tool shares. Sixty seconds killed a real elicitation
    // while its dialog was still on screen. This is the kernel's own maximum from the policy
    // schema; a tool that returns quickly still returns quickly, since a ceiling is not a target.
    timeoutMs: 300000,
  };
}

function blockedDetail(result) {
  const event = result.events.find(e => e.type === 'blocked');
  return event ? { effect: event.data.effect, tool: event.data.tool, input: event.data.input } : {};
}

/**
 * The tool's own code for a failure, which the outcome does not carry but the journal does.
 *
 * Without this a caller sees only the kernel's wrapper — EFFECT_INDETERMINATE for anything that
 * threw out of a granted effect — and cannot tell a tool that refused before acting from one that
 * may have acted and then failed. The kernel is right not to decide that; it cannot know. The
 * tool said which it was, and this stops that answer being thrown away at the surface.
 */
function failureDetail(result) {
  const event = result.events.find(e => e.type === 'failed');
  if (!event) return {};
  return {
    ...(event.data.toolCode ? { toolCode: event.data.toolCode } : {}),
    ...(event.data.reason ? { reason: event.data.reason } : {}),
  };
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
export function createMcpServer({ registry, policy, sourceLock, workspaceRoot, harness, instructionModules, channel = null, uiApp = null, mailboxDir = null, onClientReady = null }) {
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
      return { content: [{ type: 'text', text: canonical({ status: 'failed', code: result.outcome.code, taskId: result.outcome.taskId, ...failureDetail(result) }) }], isError: true };
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

  /** Questions the operator asked through Concord that no one has answered yet. */
  function openQuestions() {
    if (!mailboxDir) return [];
    try { return readMailbox(mailboxDir).filter((entry) => entry.open && entry.for === 'agent'); }
    catch { return []; }
  }

  /**
   * The push.
   *
   * MCP has no way for a server to put text in front of a client's model unless that client
   * declares sampling, and neither Anthropic client does — measured, not assumed. But a tool's
   * description IS model-visible text, and a server may tell a client its tool list changed.
   * So Concord advertises the pending question in the description of the tool used to answer it,
   * and notifies. The client re-reads, and the question is in the agent's context without the
   * operator relaying anything.
   *
   * Honest about its own reach: this arrives when the client next reads its tools, not at an
   * instant of Concord's choosing, and a client that ignores listChanged will never look.
   */
  function answerToolDefinition() {
    const open = openQuestions();
    if (!open.length) {
      return { name: 'concord_answer', description: 'Answer a question the operator asked through Concord. Nothing is waiting right now.',
        inputSchema: { type: 'object', properties: { seq: { type: 'integer', minimum: 1 }, answer: { type: 'string', minLength: 1, maxLength: 65536 } }, required: ['seq', 'answer'], additionalProperties: false } };
    }
    // Newest first, and quoted. The oldest open item is usually the one nobody wanted; the one
    // that just arrived is the one being pushed. Quoting by sequence alone would notify that
    // something happened without ever saying what, which is not a message, only an alarm.
    const newest = open[open.length - 1];
    const quote = (entry) => {
      const text = entry.message.length > 300 ? entry.message.slice(0, 300) + '…' : entry.message;
      return `#${entry.seq}: "${text}"`;
    };
    const older = open.slice(0, -1).slice(-2).map(quote);
    return {
      name: 'concord_answer',
      description: `The operator asked Concord ${open.length} question${open.length === 1 ? '' : 's'} that ${open.length === 1 ? 'is' : 'are'} waiting for you. `
        + `Most recent ${quote(newest)}. `
        + (older.length ? `Also open ${older.join(' and ')}. ` : '')
        + `Answer by calling this tool with that seq and your answer; it appears in Concord's own interface. `
        + `All open sequences: ${open.map((entry) => entry.seq).join(', ')}.`,
      inputSchema: { type: 'object', properties: { seq: { type: 'integer', minimum: 1 }, answer: { type: 'string', minLength: 1, maxLength: 65536 } }, required: ['seq', 'answer'], additionalProperties: false },
    };
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
      { name: 'concord_chat', description: 'Send a message to Concord\'s deterministic chat harness, grounded in its reviewed source instructions, and get its reply.', inputSchema: { type: 'object', properties: { message: { type: 'string', minLength: 1, maxLength: 32768 } }, required: ['message'], additionalProperties: false },
        // Calling this opens Concord's own interface in hosts that render apps, so the
        // conversation continues in Concord's surface rather than in the host's chat box.
        ...(uiApp ? { _meta: { ui: { resourceUri: UI_RESOURCE_URI, visibility: ['model', 'app'] } } } : {}) },
      { name: 'concord_approve', description: 'Approve a pending write/network/process effect in the chat harness by its exact request hash.', inputSchema: { type: 'object', properties: { requestHash: { type: 'string', minLength: 64, maxLength: 64 } }, required: ['requestHash'], additionalProperties: false } },
      { name: 'concord_execute_plan', description: 'Attempt the chat harness\'s currently proposed plan again (e.g. after approving a dependency), or adopt and attempt a new plan.', inputSchema: { type: 'object', properties: { plan: { type: 'object' } }, additionalProperties: false } },
      { name: 'concord_replay', description: 'Independently replay a prior chat run by id and verify it reproduces the same recorded outcome.', inputSchema: { type: 'object', properties: { runId: { type: 'string', minLength: 1, maxLength: 128 } }, required: ['runId'], additionalProperties: false } },
      ...(mailboxDir ? [answerToolDefinition()] : []),
      { name: 'concord_chat_state', description: 'Read the chat harness\'s current state (history, pending approval, proposed plan, run list) without changing anything.', inputSchema: { type: 'object', properties: {}, additionalProperties: false },
        // The state tool is how a host asks "what is Concord right now", which makes it the other
        // natural way in. Attaching the surface only to concord_chat meant a host that opened with
        // a read saw text where it could have shown the interface.
        ...(uiApp ? { _meta: { ui: { resourceUri: UI_RESOURCE_URI, visibility: ['model', 'app'] } } } : {}) },
    );
    return defs;
  }

  function resourceDefinitions() {
    const ui = uiApp
      ? [{ uri: UI_RESOURCE_URI, name: 'concord_chat_app', title: 'Concord', description: "Concord's own chat interface, rendered by the host and driven by the concord_* tools.", mimeType: UI_MIME_TYPE }]
      : [];
    return ui.concat([...instructionsBySourceId.values()]
      .map(m => ({ uri: 'concord://instructions/' + m.sourceId, name: m.sourceId, title: m.sourceId, description: `Reviewed Concord source instruction module (${m.file})`, mimeType: 'text/markdown' }))
      .sort((a, b) => a.uri < b.uri ? -1 : a.uri > b.uri ? 1 : 0));
  }

  function readResource(uri) {
    if (uiApp && uri === UI_RESOURCE_URI) return { uri, mimeType: UI_MIME_TYPE, text: uiApp };
    const match = /^concord:\/\/instructions\/([a-z0-9-]+)$/.exec(typeof uri === 'string' ? uri : '');
    const module = match ? instructionsBySourceId.get(match[1]) : undefined;
    return module ? { uri, mimeType: 'text/markdown', text: module.text } : null;
  }

  async function handleToolsCall(params) {
    if (!params || typeof params !== 'object' || typeof params.name !== 'string') throw new McpProtocolError(-32602, 'Invalid params: "name" is required');
    const rawArgs = params.arguments;
    const args = rawArgs === undefined ? {} : rawArgs;
    if (typeof args !== 'object' || args === null || Array.isArray(args)) throw new McpProtocolError(-32602, 'Invalid params: "arguments" must be an object');
    if (mailboxDir && params.name === 'concord_answer') {
      if (!Number.isInteger(args.seq) || typeof args.answer !== 'string' || !args.answer.trim()) {
        throw new McpProtocolError(-32602, 'Invalid params: "seq" and "answer" are required');
      }
      try {
        const filed = fileMessage(mailboxDir, { message: args.answer, audience: 'operator', replyTo: args.seq, subject: 'answered by the connected provider' });
        return { content: [{ type: 'text', text: canonical({ answered: args.seq, seq: filed.seq, note: "Filed in Concord’s exchange; it appears in Concord’s own interface." }) }] };
      } catch (error) {
        const code = error instanceof HarnessError ? error.code : 'ANSWER_FAILED';
        return { content: [{ type: 'text', text: canonical({ status: 'failed', code, message: error.message }) }], isError: true };
      }
    }
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
        // What the client says it can do decides what Concord may ask it. Recorded here, and
        // reported by peer.capabilities, so an unanswerable question refuses instead of hanging.
        channel?.rememberClient(params);
        // The first moment this session knows who it is and what it can do, which is the earliest
        // it can usefully join the peer hub: a session registered before initialize would advertise
        // an identity of nulls and a capability list nobody declared. Deliberately not awaited —
        // joining is additive, and a hub that cannot be reached must delay nobody's initialize.
        try { onClientReady?.(channel?.describeClient() ?? null); } catch { /* a hub is a convenience, never a precondition */ }
        return {
          protocolVersion: PROTOCOL_VERSION,
          // `logging` is declared because peer.tell sends notifications/message. A server that
          // emits log notifications without declaring it is sending something the client never
          // agreed to receive.
          capabilities: {
            tools: { listChanged: Boolean(mailboxDir) }, resources: { listChanged: false, subscribe: false }, logging: {},
            // Declared only when a document was actually loaded. A capability a server cannot
            // honour is worse than one it never claimed.
            ...(uiApp ? { extensions: { [UI_EXTENSION]: { mimeTypes: [UI_MIME_TYPE] } } } : {}),
          },
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
    // A reply to something Concord asked carries an id and no method. It has to be claimed before
    // the request dispatcher sees it: that dispatcher would read a method-less message as a
    // malformed request and answer the client's perfectly good reply with a protocol error.
    if (channel?.deliver(message)) return null;
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

  return { handleLine, openQuestions };
}

export async function main(argv = process.argv.slice(2)) {
  const flags = parseArgs(argv);
  const { registry, catalog, inventory, integrations } = await buildRegistry(flags);
  // The other direction of this session. It exists only on this transport: a browser is not an
  // agent that can be asked anything, so the desktop and terminal launchers register none of it.
  const channel = createClientChannel({ send: (line) => process.stdout.write(line + '\n') });
  // The mailbox is registered on both transports because it is files, not protocol: Concord's
  // own agent posts from the desktop application and the connected agent collects here, and the
  // two are different processes that never meet.
  // Redirectable so a test, or a second operator, can hold an exchange of its own.
  const mailboxDir = path.resolve(flags.mailbox ?? path.join(root, 'runs', 'peer-mailbox'));
  /**
   * Membership of the peer hub, which is how this session reaches agents on other sessions.
   *
   * Held in a mutable binding and read through a function because the registry is built now and
   * the hub cannot be joined until a client has sent initialize. Every failure here is swallowed
   * on purpose: the hub makes an existing capability faster, and a Concord that refused to start
   * because a socket was busy would be a worse trade than the latency it saves. When it is absent
   * `peer.peers` reports `joined: false` and says the mailbox still reaches everyone.
   */
  let hubMembership = null;
  const respond = createHubResponder({ channel, mailboxDir });
  const joinPeerHub = (client) => {
    if (hubMembership || !client) return;
    joinHub({ root: workspaceRoot, identity: { name: client.name, version: client.version, capabilities: client.capabilities }, onServe: respond })
      .then((membership) => { hubMembership = membership; })
      .catch(() => { hubMembership = null; });
  };
  for (const tool of [...makePeerTools({ channel, hub: () => hubMembership }), ...makeMailboxTools({ directory: mailboxDir })]) {
    if (registry.has(tool.name)) throw new HarnessError('MCP_CONFIG', 'Peer tool name collision', { tool: tool.name });
    registry.set(tool.name, tool);
  }
  const workspaceRoot = fs.realpathSync(path.resolve(flags.workspace ?? root));
  const runtimeFiles = fs.readdirSync(path.join(root, 'src')).filter(f => f.endsWith('.mjs')).map(f => 'src/' + f).sort();
  const sourceLock = {
    catalog, inventoryHash: digest(inventory),
    runtime: { node: process.version, platform: process.platform, arch: process.arch, files: runtimeFiles.map(f => ({ path: f, sha256: createHash('sha256').update(fs.readFileSync(path.join(root, f))).digest('hex') })) },
  };
  // Delegation runs a sub-plan against this registry, so it is registered once the registry and
  // source lock exist and before the policy derives allowedTools from them.
  for (const tool of makeGovernanceTools({ registry, sourceLock })) registry.set(tool.name, tool);
  const policy = buildPolicy(flags, registry, integrations);
  const visibleRegistry = new Map([...registry].filter(([name, tool]) => policy.allowedTools.includes(name) && policy.allowedEffects.includes(tool.effect)));
  const instructionRoot = path.join(root, 'instructions');
  const buildContext = ({ message, history, observations, proposedPlan }) => buildChatContext({ message, history, observations, proposedPlan, sourceLock: catalog, inventory, registry: visibleRegistry, policy, instructionRoot });
  const resourceContext = buildContext({ message: 'Concord MCP server startup', history: [] });
  const harness = createChatHarness({ registry, policy, sourceLock, workspaceRoot, buildContext });

  // Read once at startup, like every other runtime file, so the served document and the digest in
  // the source lock describe the same bytes.
  const uiAppPath = path.join(root, 'app', 'mcp-app.html');
  const uiApp = fs.existsSync(uiAppPath) ? fs.readFileSync(uiAppPath, 'utf8') : null;
  const server = createMcpServer({ registry, policy, sourceLock, workspaceRoot, harness, instructionModules: resourceContext.instructions, channel, uiApp, mailboxDir, onClientReady: joinPeerHub });

  // Watch the exchange and tell the client when what it should know has changed. This is the
  // push: the question is already in the tool description by the time the client re-reads, so
  // notifying is all that is left to do. Signature-compared so an unrelated file touch does not
  // nag a client that has nothing new to learn.
  fs.mkdirSync(mailboxDir, { recursive: true });
  let advertised = canonical(server.openQuestions().map((entry) => entry.seq));
  let settle;
  const announce = () => {
    clearTimeout(settle);
    // A single answer rewrites one file and touches the directory more than once; let it finish.
    settle = setTimeout(() => {
      const next = canonical(server.openQuestions().map((entry) => entry.seq));
      if (next === advertised) return;
      advertised = next;
      try { channel.notify('notifications/tools/list_changed', {}); }
      catch { /* a client that has gone away is not an error worth stopping the server for */ }
    }, 150);
    settle.unref?.();
  };
  try { fs.watch(mailboxDir, announce).unref?.(); }
  catch { /* no watcher available: the description is still correct the next time tools are read */ }

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

  console.error(`Concord MCP server ready (stdio). Mode: ${registry.has('model.propose') ? 'live model configured; each network call requires its exact grant' : 'no model configured; turns refuse until one is'}. Tools: ${visibleRegistry.size + CHAT_TOOL_NAMES.length}. Resources: ${resourceContext.instructions.length}.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof HarnessError ? `${error.code}: ${error.message}` : 'MCP_START_FAILED: Check local configuration and paths.');
    process.exitCode = 1;
  });
}
