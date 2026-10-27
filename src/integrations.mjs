import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';
import { canonical, deepFreeze, parseJson as strictParseJson, validateSchema, HarnessError } from './value.mjs';

const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_OUTPUT = 1_048_576;
const MAX_INPUT = 32 * 1_048_576;
// A floor for the derived token ceiling, so a tightly attenuated policy cannot shrink a reply to
// the point where every answer is cut off mid-sentence. Low enough to stay a brake and not a budget.
const MIN_MODEL_TOKENS = 256;
/**
 * How much bigger a streamed body is than the text it carries.
 *
 * A streamed reply is not the reply: every token arrives inside its own `data: {...}` frame
 * carrying the model id, choice index and finish reason, so a few characters of content cost well
 * over a hundred bytes on the wire. Counting those framing bytes against maxOutputBytes made the
 * real output budget several times smaller than the number configured — and only on the streaming
 * path, so the chat UI, which always streams because it passes onProgress, silently had a far
 * tighter ceiling than the CLI or the tests running the identical adapter.
 *
 * Measured against a local qwen3 emitting a plan with a small file in it: the stream tripped a
 * 1 MiB bound after roughly 25 KB of actual text, and three turns failed INTEGRATION_OUTPUT_LIMIT
 * for replies that were never near the configured limit.
 *
 * So the two bounds are separated. maxOutputBytes keeps the meaning it has everywhere else — the
 * decoded text the model produced — and the raw stream gets its own ceiling whose only job is to
 * stop a peer streaming forever.
 *
 * Sixty-four is an allowance, not a measurement, and the first attempt at it was eight, which a
 * test immediately disproved. A frame's envelope — model id, object, created, choice index,
 * finish reason — runs to a couple of hundred bytes around a delta of one token, so the ratio is
 * tens to one and depends on how a server batches tokens into frames. The number is therefore set
 * above any plausible framing cost rather than tuned to an observed one, because being generous
 * here costs nothing: it is the text bound below that does the real work, and a peer that streams
 * past even this is misbehaving rather than verbose.
 */
const STREAM_FRAMING_ALLOWANCE = 64;
const objectSchema = { type: 'object' };
const envName = /^[A-Za-z_][A-Za-z0-9_]*$/;
const toolName = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const sensitiveName = /token|password|secret|api_?key/i;
// A credential-shaped value under a non-keyword name (e.g. config.env.CONFIG_FLAG set to an
// AWS access key) would otherwise bypass both the "no credentials in literal env" registration
// check and the runtime echo-rejection, since both were keyed only on the variable name.
const sensitiveValuePatterns = [
  /^AKIA[0-9A-Z]{16}$/, // AWS access key ID
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/, // PEM private key block
  /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/, // JWT
  /:\/\/[^\s:@/]+:[^\s:@/]+@/, // basic-auth-in-URL (user:pass@host)
];
function looksLikeSecret(key, value) {
  return sensitiveName.test(key) || (typeof value === 'string' && sensitiveValuePatterns.some((p) => p.test(value)));
}

function fail(code, message) { throw new HarnessError(code, message); }
function positive(value, fallback, label) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 2_147_483_647) {
    fail('INTEGRATION_CONFIG', `${label} must be a positive bounded integer`);
  }
  return result;
}
function text(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    fail('INTEGRATION_CONFIG', `${label} must be a nonempty string`);
  }
  return value;
}
function keys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) {
    fail('INTEGRATION_CONFIG', `Unsupported ${label} configuration field`);
  }
}
function origin(value) {
  let parsed;
  try { parsed = new URL(value); } catch { fail('INTEGRATION_CONFIG', 'Invalid integration origin'); }
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.origin !== value ||
      parsed.username || parsed.password) {
    fail('INTEGRATION_CONFIG', 'Origin must be an exact HTTP(S) origin without credentials or a path');
  }
  return parsed.origin;
}
function json(value) { return JSON.parse(canonical(value)); }
function parseJson(value, code = 'INTEGRATION_OUTPUT') {
  try { return strictParseJson(value); } catch { fail(code, 'Integration returned invalid JSON'); }
}
function decodeJson(chunks) {
  try { return parseJson(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { fail('INTEGRATION_OUTPUT', 'Integration returned invalid UTF-8 JSON'); }
}
function rejectSecrets(value, secrets) {
  if (typeof value === 'string' && secrets.some(secret => secret && value.includes(secret))) fail('INTEGRATION_SECRET', 'Integration output echoed a configured credential');
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) { rejectSecrets(key, secrets); rejectSecrets(child, secrets); }
  }
  return value;
}
export function limits(config, context, name, effect) {
  const policy = context?.policy ?? {};
  if (Array.isArray(policy.allowedTools) && !policy.allowedTools.includes(name)) {
    fail('INTEGRATION_POLICY', 'Integration tool is not allowlisted');
  }
  if (Array.isArray(policy.allowedEffects) && !policy.allowedEffects.includes(effect)) {
    fail('INTEGRATION_POLICY', 'Integration effect is not allowlisted');
  }
  if (context?.signal?.aborted) fail('INTEGRATION_ABORTED', 'Integration was cancelled');
  return {
    timeoutMs: Math.min(config.timeoutMs, positive(policy.timeoutMs, config.timeoutMs, 'policy timeoutMs')),
    maxOutputBytes: Math.min(config.maxOutputBytes, positive(policy.maxOutputBytes, config.maxOutputBytes, 'policy maxOutputBytes')),
  };
}
function credentials(config) {
  const token = process.env[config.apiKeyEnv];
  if (!token || !/^[\x21-\x7e]+$/.test(token)) fail('INTEGRATION_CREDENTIAL', 'Integration credential is unavailable or invalid');
  return token;
}
function settings(value, defaultName) {
  const result = json(value);
  result.name = result.name ?? defaultName;
  if (typeof result.name !== 'string' || !toolName.test(result.name)) fail('INTEGRATION_CONFIG', 'Invalid integration tool name');
  result.timeoutMs = positive(result.timeoutMs, DEFAULT_TIMEOUT, 'timeoutMs');
  result.maxOutputBytes = positive(result.maxOutputBytes, DEFAULT_OUTPUT, 'maxOutputBytes');
  return result;
}

/**
 * `onChunk` turns this into a streaming read without forking the transport. Every guarantee below
 * is unchanged and still applies, because they all sit outside the data path: the origin
 * allowlist, the input bound, the credential, the deadline, the abort relay, the status check and
 * the output byte bound. The only difference is that chunks are handed to the caller as they
 * arrive and the body resolves as text rather than decoded JSON, because a streamed body is a
 * sequence of events rather than one document.
 */
async function postJson(config, input, context, onChunk) {
  const bound = limits(config, context, config.name, 'network');
  if (!Array.isArray(context?.policy?.allowedOrigins) ||
      !context.policy.allowedOrigins.includes(config.origin)) {
    fail('INTEGRATION_ORIGIN', 'Integration origin is not allowlisted');
  }
  const encoded = Buffer.from(canonical(input));
  if (encoded.length > MAX_INPUT) fail('INTEGRATION_INPUT_LIMIT', 'Integration input exceeds the byte limit');
  const token = credentials(config);
  const url = new URL(config.path, `${config.origin}/`);
  return new Promise((resolveRequest, reject) => {
    let done = false;
    let timer;
    const finish = (error, result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      context?.signal?.removeEventListener('abort', cancelled);
      if (error) reject(error); else resolveRequest(result);
    };
    const error = (code, message) => new HarnessError(code, message);
    const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
      method: 'POST',
      agent: false, rejectUnauthorized: true, maxHeaderSize: 16_384,
      headers: { 'content-type': 'application/json', 'content-length': encoded.length, authorization: `Bearer ${token}` },
    }, response => {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.destroy();
        finish(error('INTEGRATION_HTTP_STATUS', `Integration HTTP status ${response.statusCode}`));
        return;
      }
      let bytes = 0;
      const chunks = [];
      // A streamed body carries framing the caller never sees, so it is allowed more wire bytes
      // than the text budget. The text itself is bounded by whoever decodes it; this ceiling
      // exists only so a peer cannot stream without end. A non-streamed body IS the text, so the
      // two coincide and nothing changes for it.
      const rawBound = onChunk ? bound.maxOutputBytes * STREAM_FRAMING_ALLOWANCE : bound.maxOutputBytes;
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > rawBound) {
          finish(error('INTEGRATION_OUTPUT_LIMIT', 'Integration output exceeds the byte limit'));
          response.destroy();
          request.destroy();
        } else {
          chunks.push(chunk);
          // After the bound, never before: a sink must not see bytes the budget has already
          // refused. A throwing sink is contained here for the same reason it is in the engine.
          if (onChunk) { try { onChunk(chunk); } catch { /* a display sink never breaks a call */ } }
        }
      });
      response.on('end', () => {
        if (done) return;
        try {
          if (onChunk) { finish(null, { text: Buffer.concat(chunks).toString('utf8') }); return; }
          finish(null, rejectSecrets(decodeJson(chunks), [token]));
        } catch (caught) { finish(caught); }
      });
      response.on('error', () => finish(error('INTEGRATION_HTTP', 'Integration response failed')));
      response.on('aborted', () => finish(error('INTEGRATION_HTTP', 'Integration response was interrupted')));
    });
    const cancelled = () => {
      finish(error('INTEGRATION_ABORTED', 'Integration was cancelled'));
      request.destroy();
    };
    request.on('error', () => finish(error('INTEGRATION_HTTP', 'Integration request failed')));
    timer = setTimeout(() => {
      finish(error('INTEGRATION_TIMEOUT', 'Integration request timed out'));
      request.destroy();
    }, bound.timeoutMs);
    context?.signal?.addEventListener('abort', cancelled, { once: true });
    if (context?.signal?.aborted) { cancelled(); return; }
    request.end(encoded);
  });
}

function baseNetworkSettings(value, allowedFields, defaultName, defaultPath) {
  keys(value, allowedFields, 'network');
  const config = settings(value, defaultName);
  config.origin = origin(config.origin);
  config.apiKeyEnv = text(config.apiKeyEnv, 'apiKeyEnv');
  if (!envName.test(config.apiKeyEnv)) fail('INTEGRATION_CONFIG', 'Invalid credential environment variable name');
  config.path = config.path ?? defaultPath;
  if (typeof config.path !== 'string' || !/^\/(?!\/)/.test(config.path) ||
      config.path.includes('\\') || config.path.includes('#') || config.path.includes('?') ||
      new URL(config.path, `${config.origin}/`).origin !== config.origin) {
    fail('INTEGRATION_CONFIG', 'Integration endpoint must be an absolute path on the configured origin');
  }
  return config;
}
function networkSettings(value, defaultName, defaultPath) {
  const config = baseNetworkSettings(value, ['name', 'origin', 'model', 'apiKeyEnv', 'path', 'timeoutMs', 'maxOutputBytes'], defaultName, defaultPath);
  config.model = text(config.model, 'model');
  return config;
}

function typeSafe(value) {
  const config = networkSettings(value, 'typesafe.evaluate', '/v1/systemone');
  if (!/^jev-\d+\.\d+\.\d+$/.test(config.model)) {
    fail('INTEGRATION_CONFIG', 'TypeSafe requires a versioned Jev model ID');
  }
  const inputSchema = {
    type: 'object', required: ['state', 'questions'], additionalProperties: false,
    properties: { state: { anyOf: [{ type: 'string' }, { type: 'object' }, { type: 'array' }] }, questions: { type: 'object' } },
  };
  return {
    name: config.name, version: '1', effect: 'network', inputSchema, config,
    async execute(input, context) {
      validateSchema(input, inputSchema);
      input = json(input);
      if (!Object.keys(input.questions).length) fail('INTEGRATION_INPUT', 'TypeSafe requires at least one question');
      for (const question of Object.values(input.questions)) {
        if (!question || typeof question !== 'object' || Array.isArray(question) ||
            !['choice', 'score', 'noul'].includes(question.type) || question.instructions === undefined) {
          fail('INTEGRATION_INPUT', 'Unsupported TypeSafe question');
        }
        if (question.type === 'choice' && (!question.criteria || Array.isArray(question.criteria) ||
            typeof question.criteria !== 'object' || Object.keys(question.criteria).length < 2 || Object.keys(question.criteria).length > 255)) {
          fail('INTEGRATION_INPUT', 'TypeSafe Choice requires 2 to 255 options');
        }
        if (question.type === 'score' && (!Array.isArray(question.criteria) || question.criteria.length < 2 || question.criteria.length > 10)) {
          fail('INTEGRATION_INPUT', 'TypeSafe Score requires 2 to 10 levels');
        }
      }
      const result = await postJson(config, { model: config.model, state: input.state, questions: input.questions }, context);
      if (!result || result.model !== config.model || !result.answers || typeof result.answers !== 'object' ||
          Array.isArray(result.answers) || Object.keys(result.answers).length !== Object.keys(input.questions).length) {
        fail('INTEGRATION_OUTPUT', 'TypeSafe response does not match the pinned request');
      }
      for (const [id, question] of Object.entries(input.questions)) {
        const answer = result.answers[id];
        if (!answer || answer.type !== question.type) fail('INTEGRATION_OUTPUT', 'TypeSafe answer type does not match its question');
        if (question.type === 'noul' && (typeof answer.noul !== 'number' || answer.noul < 0 || answer.noul > 1)) {
          fail('INTEGRATION_OUTPUT', 'Invalid TypeSafe Noul answer');
        }
        if (question.type === 'choice' && !Object.hasOwn(question.criteria, answer.choice)) {
          fail('INTEGRATION_OUTPUT', 'TypeSafe selected an unknown option');
        }
        if (question.type !== 'noul' && (typeof answer.confidence !== 'number' || answer.confidence < 0 || answer.confidence > 1 ||
            !answer.probabilities || typeof answer.probabilities !== 'object' || Array.isArray(answer.probabilities))) {
          fail('INTEGRATION_OUTPUT', 'Invalid TypeSafe distribution or confidence');
        }
        if (question.type !== 'noul') {
          const expected = question.type === 'choice' ? Object.keys(question.criteria).sort() : question.criteria.map((_, index) => String(index)).sort();
          const probabilities = Object.values(answer.probabilities);
          if (canonical(Object.keys(answer.probabilities).sort()) !== canonical(expected) ||
              probabilities.some(value => typeof value !== 'number' || value < 0 || value > 1) ||
              Math.abs(probabilities.reduce((sum, value) => sum + value, 0) - 1) > 0.001) {
            fail('INTEGRATION_OUTPUT', 'Invalid TypeSafe probability distribution');
          }
        }
        if (question.type === 'score' && (typeof answer.score !== 'number' || answer.score < 0 || answer.score > question.criteria.length - 1)) fail('INTEGRATION_OUTPUT', 'Invalid TypeSafe score');
      }
      return result;
    },
  };
}

/**
 * One streamed proposal, reported as progress and returned as a single value.
 *
 * Measured against the configured model before this was written: of a ten-second call, the first
 * 9.6 seconds produced `reasoning_content` and the last 0.4 seconds produced the actual
 * `content` in one burst. So the useful live signal here is how far the model has got, not the
 * text -- and the two channels must never be conflated. `reasoning_content` is the model's
 * private working: it is counted and never forwarded, because displaying it would put text that
 * is neither the answer nor evidence in front of an operator as though it were one of them.
 * Only `content` is previewed, and even that is explicitly a preview: nothing here is recorded.
 * What becomes evidence is the single value this returns, exactly as in the non-streaming path.
 */
/**
 * A model that stopped because it ran out of room, rather than because it had finished.
 *
 * Measured by replaying a failed turn against the local model: finish_reason "length",
 * completion_tokens exactly equal to max_tokens, 116,017 characters of reasoning, and content of
 * length zero. It thought until the budget was gone and never began the answer.
 *
 * That arrived as INTEGRATION_OUTPUT, "no message content", which is true and useless — it reads
 * as a broken provider when the provider did exactly as told. The cause was this harness's own
 * token brake, added the same day to stop runaway generation: the brake bounds reasoning and
 * answer together, so a prompt hard enough to reason about at length leaves nothing to answer
 * with. Naming the case is what makes it actionable, because the response is specific and is not
 * "retry": ask for something smaller, or give the model more room.
 */
function truncated(finishReason, content, reasoningChars) {
  if (finishReason !== 'length') return;
  if (typeof content === 'string' && content) return; // Truncated after answering: the caller can judge the answer.
  fail('INTEGRATION_TRUNCATED',
    `The model reached its token limit having produced ${reasoningChars} characters of reasoning and no answer; `
    + 'ask for a smaller step, or raise the model maxOutputBytes so the budget covers thinking and answering');
}

async function streamProposal(config, body, context) {
  let pending = '';
  let content = '';
  let identity;
  let finishReason = null;
  let reasoningChars = 0;
  const report = (update) => context.onProgress({ phase: update.phase, ...update });
  // The text bound, enforced here because here is where the text exists. postJson sees frames.
  // Reasoning counts: it is generation the model spent and the budget is about what it produced,
  // not about which half of it survives into the reply. Checked after the stream rather than
  // thrown from the sink, because postJson contains a throwing sink by design -- a display sink
  // must never break a call -- so an exception raised in there would be swallowed.
  const textBound = limits(config, context, config.name, 'network').maxOutputBytes;
  let overflowed = false;

  const consume = (chunk) => {
    pending += chunk.toString('utf8');
    const lines = pending.split('\n');
    pending = lines.pop() ?? '';
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const payload = trimmed.slice(5).trim();
      if (!payload || payload === '[DONE]') continue;
      let frame;
      try { frame = JSON.parse(payload); } catch { continue; }
      if (typeof frame?.model === 'string' && frame.model) identity = frame.model;
      // Why generation stopped, which the last frame carries. Without it a model that spent its
      // whole budget thinking and never answered is indistinguishable from one that answered with
      // nothing, and those need different responses from whoever reads the failure.
      if (typeof frame?.choices?.[0]?.finish_reason === 'string') finishReason = frame.choices[0].finish_reason;
      const delta = frame?.choices?.[0]?.delta ?? {};
      if (typeof delta.reasoning_content === 'string' && delta.reasoning_content) {
        reasoningChars += delta.reasoning_content.length;
        report({ phase: 'reasoning', reasoningChars });
      }
      if (typeof delta.content === 'string' && delta.content) {
        content += delta.content;
        report({ phase: 'drafting', reasoningChars, preview: previewOfReply(content) });
      }
      if (!overflowed && Buffer.byteLength(content) + reasoningChars > textBound) overflowed = true;
    }
  };

  await postJson(config, { ...body, stream: true }, context, consume);
  if (overflowed) fail('INTEGRATION_OUTPUT_LIMIT', 'Integration output exceeds the byte limit');
  return { content, model: identity, finishReason, reasoningChars };
}

/**
 * The reply as it is being written, pulled out of a JSON object that is still arriving.
 *
 * The model is constrained to `response_format: json_object`, so what streams is the characters
 * of `{"reply": "...` and not prose. Showing those raw would be worse than showing nothing. This
 * reads the `reply` string out of the partial document, honouring escapes so a half-arrived `\u`
 * or `\"` never renders as garbage, and returns nothing at all until the field has started.
 */
function previewOfReply(partial) {
  const start = partial.search(/"reply"\s*:\s*"/);
  if (start < 0) return '';
  let index = partial.indexOf('"', partial.indexOf(':', start) + 1) + 1;
  let out = '';
  while (index < partial.length) {
    const character = partial[index];
    if (character === '\\') {
      const next = partial[index + 1];
      if (next === undefined) break; // escape still arriving; stop rather than guess
      if (next === 'u') {
        const hex = partial.slice(index + 2, index + 6);
        if (hex.length < 4) break;
        out += String.fromCharCode(parseInt(hex, 16));
        index += 6;
        continue;
      }
      out += { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f' }[next] ?? next;
      index += 2;
      continue;
    }
    if (character === '"') break; // the field is complete
    out += character;
    index += 1;
  }
  return out;
}

function model(value) {
  const config = networkSettings(value, 'model.propose', '/v1/chat/completions');
  const inputSchema = {
    type: 'object', required: ['prompt'], additionalProperties: false,
    properties: { prompt: { type: 'string', minLength: 1 }, system: { type: 'string' } },
  };
  return {
    name: config.name, version: '1', effect: 'network', inputSchema, config,
    async execute(input, context) {
      validateSchema(input, inputSchema);
      const messages = [];
      if (input.system !== undefined) messages.push({ role: 'system', content: input.system });
      messages.push({ role: 'user', content: input.prompt });
      /**
       * Tell the provider where to stop, instead of only judging it after it has stopped.
       *
       * maxOutputBytes was already the bound, and postJson still enforces it on the response, but
       * it was enforced only on the way back: nothing told the model about it. On an open-ended
       * prompt that is the difference between a bounded answer and a runaway that spends the whole
       * budget and then fails the turn for exceeding it. Measured, not theorised — asked to list
       * everything it cannot do, Concord produced a correct first page, ran out of real limits,
       * kept generating, and collapsed into cycling synonyms. Greedy decoding aggravates this,
       * because temperature 0 is the setting most prone to repetition loops, and temperature stays
       * at 0 because a proposal that varied between identical runs would cost more than it buys.
       *
       * Four bytes per token is an approximation for English and is deliberately low. It is a
       * brake, never the thing that decides correctness: a reply that would still exceed the byte
       * bound is rejected by the check in postJson exactly as before.
       */
      const bound = limits(config, context, config.name, 'network');
      const maxTokens = Math.max(MIN_MODEL_TOKENS, Math.floor(bound.maxOutputBytes / 4));
      const body = { model: config.model, messages, response_format: { type: 'json_object' }, temperature: 0, max_tokens: maxTokens };
      let response;
      let content;
      let identity;
      if (typeof context?.onProgress === 'function') {
        const streamed = await streamProposal(config, body, context);
        content = streamed.content;
        identity = streamed.model;
        truncated(streamed.finishReason, content, streamed.reasoningChars);
        if (typeof content !== 'string' || !content) fail('INTEGRATION_OUTPUT', 'Model stream produced no message content');
      } else {
        response = await postJson(config, body, context);
        if (response?.model !== undefined && (typeof response.model !== 'string' || !response.model)) fail('INTEGRATION_OUTPUT', 'Model response has an invalid model identity');
        content = response?.choices?.[0]?.message?.content;
        identity = response.model;
        truncated(response?.choices?.[0]?.finish_reason, content,
          (response?.choices?.[0]?.message?.reasoning_content ?? '').length);
        if (typeof content !== 'string') fail('INTEGRATION_OUTPUT', 'Model response is missing JSON message content');
      }
      const proposal = parseJson(content);
      if (!proposal || typeof proposal !== 'object' || Array.isArray(proposal)) fail('INTEGRATION_OUTPUT', 'Model proposal must be a JSON object');
      return { proposal, model: identity ?? config.model, usage: response?.usage ?? null };
    },
  };
}

/**
 * A UI component registry client (21st-style). This is Concord's own defined
 * request/response contract, fixture-tested only; real 21st.dev wire compatibility
 * is unverified. Never a bare passthrough — every returned component entry is
 * schema-checked before this returns.
 */
function registryClient(value) {
  const config = baseNetworkSettings(value, ['name', 'origin', 'apiKeyEnv', 'path', 'timeoutMs', 'maxOutputBytes'], 'ui.components.search', '/v1/components/search');
  const inputSchema = {
    type: 'object', required: ['query'], additionalProperties: false,
    properties: { query: { type: 'string', minLength: 1, maxLength: 4096 }, limit: { type: 'integer', minimum: 1, maximum: 50 } },
  };
  return {
    name: config.name, version: '1', effect: 'network', inputSchema, config,
    async execute(input, context) {
      validateSchema(input, inputSchema);
      const limit = input.limit ?? 10;
      const result = await postJson(config, { query: input.query, limit }, context);
      if (!result || !Array.isArray(result.components) || result.components.length > limit) {
        fail('INTEGRATION_OUTPUT', 'Component registry response does not match the pinned request');
      }
      for (const component of result.components) {
        if (!component || typeof component !== 'object' || Array.isArray(component) ||
            typeof component.name !== 'string' || !component.name ||
            typeof component.registryPath !== 'string' || !component.registryPath ||
            (component.dependencies !== undefined && (!Array.isArray(component.dependencies) ||
              component.dependencies.length > 100 || component.dependencies.some((d) => typeof d !== 'string')))) {
          fail('INTEGRATION_OUTPUT', 'Component registry returned a malformed component entry');
        }
      }
      return result;
    },
  };
}

function contained(root, target) {
  const path = relative(root, target);
  return path === '' || (path !== '..' && !path.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(path));
}

function worker(value) {
  keys(value, ['name', 'version', 'executable', 'args', 'cwd', 'env', 'allowedEnv', 'executableSha256', 'timeoutMs', 'maxOutputBytes'], 'worker');
  const config = settings(value, undefined);
  config.version = text(config.version, 'worker version');
  config.executable = text(config.executable, 'worker executable');
  if (!isAbsolute(config.executable)) fail('INTEGRATION_CONFIG', 'Worker executable must be an absolute path');
  config.args = config.args ?? [];
  if (!Array.isArray(config.args) || config.args.some(arg => typeof arg !== 'string' || arg.includes('\0'))) fail('INTEGRATION_CONFIG', 'Worker args must be fixed strings');
  config.cwd = text(config.cwd ?? '.', 'worker cwd');
  if (isAbsolute(config.cwd)) fail('INTEGRATION_CONFIG', 'Worker cwd must be relative to the workspace');
  config.env = config.env ?? {};
  config.allowedEnv = config.allowedEnv ?? [];
  if (!config.env || Array.isArray(config.env) || typeof config.env !== 'object' ||
      Object.entries(config.env).some(([key, value]) => !envName.test(key) || typeof value !== 'string' || value.includes('\0') || looksLikeSecret(key, value))) {
    fail('INTEGRATION_CONFIG', 'Worker literal env must contain noncredential string values');
  }
  if (!Array.isArray(config.allowedEnv) || config.allowedEnv.some(key => !envName.test(key))) fail('INTEGRATION_CONFIG', 'Worker allowedEnv must list environment names');
  if (config.executableSha256 !== undefined && !/^[a-f0-9]{64}$/.test(config.executableSha256)) fail('INTEGRATION_CONFIG', 'Invalid worker executable digest');
  return {
    name: config.name, version: config.version, effect: 'process', inputSchema: objectSchema, config,
    async execute(input, context) {
      validateSchema(input, objectSchema);
      const bound = limits(config, context, config.name, 'process');
      const bytes = Buffer.from(`${canonical(input)}\n`);
      if (bytes.length > MAX_INPUT) fail('INTEGRATION_INPUT_LIMIT', 'Worker input exceeds the byte limit');
      let executable, cwd;
      try {
        executable = await realpath(config.executable);
        if (resolve(executable) !== resolve(config.executable) || !(await stat(executable)).isFile()) fail('INTEGRATION_EXECUTABLE', 'Worker executable must be an existing regular file without path aliases');
        const root = await realpath(context.workspaceRoot);
        cwd = await realpath(resolve(root, config.cwd));
        if (!contained(root, cwd) || !(await stat(cwd)).isDirectory()) fail('INTEGRATION_CWD', 'Worker cwd must remain inside the workspace');
        if (config.executableSha256 && createHash('sha256').update(await readFile(executable)).digest('hex') !== config.executableSha256) fail('INTEGRATION_EXECUTABLE', 'Worker executable digest does not match');
      } catch (error) {
        if (error instanceof HarnessError) throw error;
        fail('INTEGRATION_PATH', 'Worker executable or working directory is unavailable');
      }
      if (context?.signal?.aborted) fail('INTEGRATION_ABORTED', 'Worker was cancelled');
      const env = { ...config.env };
      for (const key of config.allowedEnv) if (process.env[key] !== undefined) env[key] = process.env[key];
      const secrets = Object.entries(env).filter(([key, value]) => looksLikeSecret(key, value)).map(([, value]) => value);
      return new Promise((resolveWorker, reject) => {
        const child = spawn(executable, config.args, { cwd, env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
        let outcome;
        let total = 0;
        const chunks = [];
        let timer;
        const cancelled = () => stop('INTEGRATION_ABORTED', 'Worker was cancelled');
        const stop = (code, message) => {
          outcome ??= new HarnessError(code, message);
          child.kill('SIGKILL');
          child.stdin.destroy();
          child.stdout.destroy();
          child.stderr.destroy();
        };
        const collect = (chunk, stdout) => {
          total += chunk.length;
          if (total > bound.maxOutputBytes) stop('INTEGRATION_OUTPUT_LIMIT', 'Worker output exceeds the combined stdout/stderr byte limit');
          else if (stdout) chunks.push(chunk);
        };
        child.stdout.on('data', chunk => collect(chunk, true));
        child.stderr.on('data', chunk => collect(chunk, false));
        child.stdout.on('error', () => stop('INTEGRATION_IO', 'Worker output failed'));
        child.stderr.on('error', () => stop('INTEGRATION_IO', 'Worker diagnostics failed'));
        child.stdin.on('error', () => stop('INTEGRATION_IO', 'Worker input failed'));
        child.on('error', () => { outcome ??= new HarnessError('INTEGRATION_PROCESS', 'Worker could not start'); });
        child.on('close', code => {
          clearTimeout(timer);
          context?.signal?.removeEventListener('abort', cancelled);
          if (outcome) { reject(outcome); return; }
          if (code !== 0) { reject(new HarnessError('INTEGRATION_EXIT', 'Worker exited unsuccessfully')); return; }
          try { resolveWorker(rejectSecrets(decodeJson(chunks), secrets)); }
          catch (error) { reject(error); }
        });
        timer = setTimeout(() => stop('INTEGRATION_TIMEOUT', 'Worker timed out'), bound.timeoutMs);
        context?.signal?.addEventListener('abort', cancelled, { once: true });
        if (context?.signal?.aborted) cancelled();
        else child.stdin.end(bytes);
      });
    },
  };
}

/**
 * Validates and normalizes one reviewed process-command entry: fixed absolute executable,
 * fixed args, contained cwd, noncredential literal env plus explicit allowedEnv passthrough,
 * and a mandatory executable digest (unlike worker(), which accepts arbitrary reviewed
 * commands rather than one pinned protocol binary). Shared by process.run and
 * process.runMany so both validate identically rather than duplicating this.
 */
function processConfig(value) {
  keys(value, ['name', 'version', 'executable', 'args', 'cwd', 'env', 'allowedEnv', 'executableSha256', 'timeoutMs', 'maxOutputBytes'], 'process');
  const config = settings(value, undefined);
  config.version = text(config.version, 'process version');
  config.executable = text(config.executable, 'process executable');
  if (!isAbsolute(config.executable)) fail('INTEGRATION_CONFIG', 'Process executable must be an absolute path');
  config.args = config.args ?? [];
  if (!Array.isArray(config.args) || config.args.some(arg => typeof arg !== 'string' || arg.includes('\0'))) fail('INTEGRATION_CONFIG', 'Process args must be fixed strings');
  config.cwd = text(config.cwd ?? '.', 'process cwd');
  if (isAbsolute(config.cwd)) fail('INTEGRATION_CONFIG', 'Process cwd must be relative to the workspace');
  config.env = config.env ?? {};
  config.allowedEnv = config.allowedEnv ?? [];
  if (!config.env || Array.isArray(config.env) || typeof config.env !== 'object' ||
      Object.entries(config.env).some(([key, value]) => !envName.test(key) || typeof value !== 'string' || value.includes('\0') || looksLikeSecret(key, value))) {
    fail('INTEGRATION_CONFIG', 'Process literal env must contain noncredential string values');
  }
  if (!Array.isArray(config.allowedEnv) || config.allowedEnv.some(key => !envName.test(key))) fail('INTEGRATION_CONFIG', 'Process allowedEnv must list environment names');
  if (!/^[a-f0-9]{64}$/.test(config.executableSha256 ?? '')) fail('INTEGRATION_CONFIG', 'A reviewed process entry requires an exact executable digest');
  return config;
}

/** Resolves and digest-verifies one process entry's executable and workspace-contained cwd. */
export async function resolveExecutable(config, workspaceRoot) {
  let executable, cwd;
  try {
    executable = await realpath(config.executable);
    if (resolve(executable) !== resolve(config.executable) || !(await stat(executable)).isFile()) fail('INTEGRATION_EXECUTABLE', 'Process executable must be an existing regular file without path aliases');
    const root = await realpath(workspaceRoot);
    cwd = await realpath(resolve(root, config.cwd));
    if (!contained(root, cwd) || !(await stat(cwd)).isDirectory()) fail('INTEGRATION_CWD', 'Process cwd must remain inside the workspace');
    if (createHash('sha256').update(await readFile(executable)).digest('hex') !== config.executableSha256) fail('INTEGRATION_EXECUTABLE', 'Process executable digest does not match');
  } catch (error) {
    if (error instanceof HarnessError) throw error;
    fail('INTEGRATION_PATH', 'Process executable or working directory is unavailable');
  }
  return { executable, cwd };
}

export function processEnv(config) {
  const env = { ...config.env };
  for (const key of config.allowedEnv) if (process.env[key] !== undefined) env[key] = process.env[key];
  const secrets = Object.entries(env).filter(([key, value]) => looksLikeSecret(key, value)).map(([, value]) => value);
  return { env, secrets };
}

/** One bounded child process: spawn, collect stdout/stderr under a shared byte budget, enforce a deadline. */
export function spawnBounded({ executable, args, cwd, env, secrets, timeoutMs, maxOutputBytes, signal }) {
  return new Promise((resolveSpawn, reject) => {
    const child = spawn(executable, args, { cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let outcome;
    let total = 0;
    const stdoutChunks = [];
    const stderrChunks = [];
    let timer;
    const cancelled = () => stop('INTEGRATION_ABORTED', 'Process was cancelled');
    const stop = (code, message) => {
      outcome ??= new HarnessError(code, message);
      child.kill('SIGKILL');
      child.stdout.destroy();
      child.stderr.destroy();
    };
    const collect = (chunk, chunks) => {
      total += chunk.length;
      if (total > maxOutputBytes) stop('INTEGRATION_OUTPUT_LIMIT', 'Process output exceeds the combined stdout/stderr byte limit');
      else chunks.push(chunk);
    };
    child.stdout.on('data', chunk => collect(chunk, stdoutChunks));
    child.stderr.on('data', chunk => collect(chunk, stderrChunks));
    child.stdout.on('error', () => stop('INTEGRATION_IO', 'Process output failed'));
    child.stderr.on('error', () => stop('INTEGRATION_IO', 'Process diagnostics failed'));
    child.on('error', () => { outcome ??= new HarnessError('INTEGRATION_PROCESS', 'Process could not start'); });
    child.on('close', (code, sig) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', cancelled);
      if (outcome) { reject(outcome); return; }
      if (code !== 0) { reject(new HarnessError('INTEGRATION_EXIT', 'Process exited unsuccessfully')); return; }
      let stdout, stderr;
      try {
        stdout = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(stdoutChunks));
        stderr = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(stderrChunks));
      } catch { reject(new HarnessError('INTEGRATION_OUTPUT', 'Process output must be valid UTF-8')); return; }
      try { resolveSpawn(rejectSecrets({ exitCode: code, signal: sig ?? null, stdout, stderr }, secrets)); }
      catch (error) { reject(error); }
    });
    timer = setTimeout(() => stop('INTEGRATION_TIMEOUT', 'Process timed out'), timeoutMs);
    signal?.addEventListener('abort', cancelled, { once: true });
    if (signal?.aborted) cancelled();
  });
}

/**
 * A generic bounded local-command runner (Orca-style), sibling to worker() but for
 * raw stdout/stderr/exit-code capture instead of a single-JSON-document protocol.
 * Task input is never read — argv comes only from this reviewed configuration, never
 * from a plan. executableSha256 is mandatory here (optional on worker()) because this
 * accepts arbitrary reviewed commands, not one pinned protocol binary.
 */
function processRun(value) {
  const config = processConfig(value);
  return {
    name: config.name, version: config.version, effect: 'process', inputSchema: objectSchema, config,
    async execute(input, context) {
      validateSchema(input, objectSchema);
      const bound = limits(config, context, config.name, 'process');
      const { executable, cwd } = await resolveExecutable(config, context.workspaceRoot);
      if (context?.signal?.aborted) fail('INTEGRATION_ABORTED', 'Process was cancelled');
      const { env, secrets } = processEnv(config);
      return spawnBounded({ executable, args: config.args, cwd, env, secrets, timeoutMs: bound.timeoutMs, maxOutputBytes: bound.maxOutputBytes, signal: context?.signal });
    },
  };
}

/**
 * Concurrent execution of several already-reviewed `processesBatch` entries, by name, inside
 * one bounded process-effect call (Orca's parallel-workstream role). This is not an
 * engine.mjs change: runPlan's own cross-task execution stays strictly sequential; the
 * concurrency happens entirely inside this one tool's execute(), so the whole batch remains
 * a pure function of its declared input/output and stays replay-safe. Every child outcome is
 * returned as data, never thrown — a deliberate departure from process.run's
 * throw-on-any-failure contract, so one failing or slow child never discards the others'
 * evidence. Task input selects only which reviewed, named entries to run, never new argv.
 * Each child's own output budget is the aggregate budget divided by the selected count
 * (mirroring files.read/memory.recall's existing per-call division), and its own timeout is
 * clamped to the tool's policy-bound timeout — so one slow child cannot starve the others,
 * and the worst-case aggregate output can never trip the kernel's own output-limit check.
 */
function processRunMany(entries) {
  if (!Array.isArray(entries) || !entries.length) fail('INTEGRATION_CONFIG', 'processesBatch requires at least one entry');
  const byName = new Map();
  for (const value of entries) {
    const config = processConfig(value);
    if (byName.has(config.name)) fail('INTEGRATION_CONFIG', 'processesBatch entry names must be unique');
    byName.set(config.name, config);
  }
  const names = [...byName.keys()].sort();
  const inputSchema = {
    type: 'object', required: ['names'], additionalProperties: false,
    properties: { names: { type: 'array', minItems: 1, maxItems: names.length, items: { enum: names } } },
  };
  const toolConfig = { name: 'process.runMany', timeoutMs: DEFAULT_TIMEOUT, maxOutputBytes: DEFAULT_OUTPUT, entries: names };
  return {
    name: 'process.runMany', version: '1.0.0', effect: 'process', inputSchema, config: toolConfig,
    async execute(input, context) {
      validateSchema(input, inputSchema);
      const selected = [...new Set(input.names)];
      const bound = limits(toolConfig, context, 'process.runMany', 'process');
      const perChildBytes = Math.max(1, Math.floor(bound.maxOutputBytes / selected.length));
      const outcomes = await Promise.allSettled(selected.map(async (name) => {
        const config = byName.get(name);
        const { executable, cwd } = await resolveExecutable(config, context.workspaceRoot);
        if (context?.signal?.aborted) fail('INTEGRATION_ABORTED', 'Process was cancelled');
        const { env, secrets } = processEnv(config);
        const result = await spawnBounded({
          executable, args: config.args, cwd, env, secrets, signal: context?.signal,
          timeoutMs: Math.min(config.timeoutMs, bound.timeoutMs), maxOutputBytes: Math.min(config.maxOutputBytes, perChildBytes),
        });
        return { name, ...result };
      }));
      return {
        results: outcomes.map((outcome, index) => outcome.status === 'fulfilled'
          ? outcome.value
          : { name: selected[index], failed: true, code: outcome.reason instanceof HarnessError ? outcome.reason.code : 'INTEGRATION_PROCESS' }),
      };
    },
  };
}

/** Registration is data-only. Credentials and all effects are deferred until execute. */
export function makeIntegrationTools(config = {}) {
  keys(config, ['typesafe', 'model', 'registry', 'workers', 'processes', 'processesBatch'], 'integration');
  config = json(config);
  const tools = [];
  if (config.typesafe) tools.push(typeSafe(config.typesafe));
  if (config.model) tools.push(model(config.model));
  if (config.registry) tools.push(registryClient(config.registry));
  if (config.workers !== undefined && !Array.isArray(config.workers)) fail('INTEGRATION_CONFIG', 'workers must be an array');
  for (const value of config.workers ?? []) tools.push(worker(value));
  if (config.processes !== undefined && !Array.isArray(config.processes)) fail('INTEGRATION_CONFIG', 'processes must be an array');
  for (const value of config.processes ?? []) tools.push(processRun(value));
  if (config.processesBatch !== undefined) tools.push(processRunMany(config.processesBatch));
  const names = tools.map(tool => tool.name);
  if (new Set(names).size !== names.length) fail('INTEGRATION_CONFIG', 'Integration tool names must be unique');
  for (const tool of tools) {
    // Commit the complete explicit configuration, without resolving environment values.
    deepFreeze(tool.config);
    deepFreeze(tool.inputSchema);
    Object.freeze(tool);
  }
  return tools;
}
