import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, HarnessError } from './value.mjs';

const MAX_INSTRUCTION_BYTES = 65536;
const MAX_MANIFEST_BYTES = 65536;
const decoder = new TextDecoder('utf-8', { fatal: true });

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function readBounded(file, limit) {
  const bytes = readFileSync(file);
  if (bytes.length > limit) throw new HarnessError('CHAT_CONTEXT', 'File exceeds the bounded read size', { file });
  return bytes;
}

function loadManifest(instructionRoot) {
  const bytes = readBounded(path.join(instructionRoot, 'manifest.json'), MAX_MANIFEST_BYTES);
  let manifest;
  try { manifest = JSON.parse(decoder.decode(bytes)); }
  catch { throw new HarnessError('CHAT_CONTEXT', 'Instruction manifest must be strict UTF-8 JSON'); }
  canonical(manifest);
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.modules)) {
    throw new HarnessError('CHAT_CONTEXT', 'Invalid instruction manifest');
  }
  return manifest;
}

/**
 * Assembles the deterministic chat turn context: every pinned source's reviewed
 * instruction module, plus a lexical preview of relevant catalogued capabilities.
 * Reads only the explicit instructionRoot; never network, clock, or ambient state.
 */
export function buildChatContext({ message, history, sourceLock, inventory, registry, instructionRoot }) {
  if (typeof message !== 'string' || !message.trim()) throw new HarnessError('CHAT_CONTEXT', 'A chat message is required');
  if (!Array.isArray(history)) throw new HarnessError('CHAT_CONTEXT', 'History must be an array of messages');
  if (!sourceLock || !Array.isArray(sourceLock.sources) || !sourceLock.sources.length) {
    throw new HarnessError('CHAT_CONTEXT', 'A loaded source lock is required');
  }

  const manifest = loadManifest(instructionRoot);
  const byId = new Map();
  for (const entry of manifest.modules) {
    if (!entry || typeof entry.sourceId !== 'string' || typeof entry.file !== 'string' || typeof entry.sha256 !== 'string') {
      throw new HarnessError('CHAT_CONTEXT', 'Invalid instruction manifest entry');
    }
    byId.set(entry.sourceId, entry);
  }
  const sourceIds = [...sourceLock.sources.map(s => s.id)].sort();
  if (byId.size !== sourceIds.length || sourceIds.some(id => !byId.has(id))) {
    throw new HarnessError('CHAT_CONTEXT', 'Instruction manifest does not cover exactly the pinned source set');
  }

  const instructions = sourceIds.map(id => {
    const entry = byId.get(id);
    if (entry.file !== `${id}.md`) throw new HarnessError('CHAT_CONTEXT', 'Instruction manifest entry has an unexpected filename', { sourceId: id });
    const bytes = readBounded(path.join(instructionRoot, entry.file), MAX_INSTRUCTION_BYTES);
    const digestHex = sha256(bytes);
    if (digestHex !== entry.sha256) throw new HarnessError('CHAT_CONTEXT', 'Instruction module does not match its recorded digest', { sourceId: id });
    return { sourceId: id, file: entry.file, sha256: digestHex, text: decoder.decode(bytes) };
  });

  // capabilities.search is a registered 'pure' tool: calling it directly to preview
  // relevant corpus references carries no side effects and grants no capability.
  let selected = [];
  const search = registry && typeof registry.get === 'function' ? registry.get('capabilities.search') : undefined;
  if (search && typeof search.execute === 'function') {
    try {
      const result = search.execute({ query: message, limit: 5 }, { policy: { maxOutputBytes: 1048576 } });
      if (result && Array.isArray(result.results)) {
        selected = result.results.map(r => ({ id: r.id, title: r.title, sourceId: r.sourceId, kind: r.kind, score: r.score }));
      }
    } catch { selected = []; }
  }

  const reply = `Offline deterministic demonstration: combined all ${instructions.length} reviewed source ` +
    `instruction modules (${sourceIds.join(', ')}) for this turn and proposed a pure-tool evidence plan ` +
    '(sources.catalog, capabilities.search, memory.candidate). No live model was called.';

  const systemPrompt = 'You are Concord, a deterministic chat harness supervisor. Ground every reply in the ' +
    `following ${instructions.length} reviewed source instruction modules. You may propose at most one tool ` +
    'plan as data; you cannot grant yourself a capability, effect, or approval the supervisor has not recorded.' +
    '\n\n' + instructions.map(m => `## ${m.sourceId}\n${m.text}`).join('\n\n');

  void inventory;
  return { sourceCoverage: sourceIds, instructions, selected, reply, systemPrompt };
}
