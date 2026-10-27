// Concord chat client. Same-origin only (CSP: connect-src 'self').
//
// SECURITY INVARIANT, unchanged from the first version of this file and load-bearing: nothing
// server-, model- or file-derived is ever written through innerHTML. Every untrusted string goes
// through textContent, via the `text` property of the `h` helper below, which is the only place
// in this file that assigns text at all. A malicious plan, reply, capability title, peer message
// or lesson cannot inject markup.
//
// What changed is what gets rendered. The harness hands this page a complete execution record
// every turn -- per-task output hashes, failure codes and diagnostics in `observations`, the run
// attribution already settled onto each reply's `execution`, verified citations, the
// self-distilled `lessonCandidates`, and the `authority` actually in force. The previous client
// fetched all of it and displayed none of it. Here provenance is inline with the message that
// claims it, because an answer you can re-verify is the one thing this harness has that a chat
// app does not.
const SVG = 'http://www.w3.org/2000/svg';

let token = null;
let state = emptyState();
let status = { sourceCount: 0, files: 0, capabilities: 0, skillFiles: 0, tools: [] };
let exchange = [];
let busy = false;
// Receipt strips are rebuilt on every render, so which ones the operator opened has to survive
// the rebuild or reading a receipt would collapse it the moment anything else changed.
const expanded = new Set();
const dismissedLessons = new Set();
const replayNotes = new Map();
// The run root reported by the first replay of each run. A later replay returning the same root
// proves the plan, policy, tool registry, source lock and workspace root are still the ones that
// run executed under; a different root is a REPLAY_CONTEXT condition and is worth saying out loud.
const replayRoots = new Map();
// Set when the operator explicitly chooses to write something else while an effect is gated.
// Abandoning the gate then happens because they said so, not because the composer was available.
let gateDismissed = false;
// Filters the transcript. Kept in memory, not the URL: the window has no address bar.
let search = '';
// The last message a turn failed on, offered back for a retry instead of being lost.
let retryable = null;
// Past sessions, and the one being read if any. A past session is a recording: it is rendered in
// place of the live transcript and the composer is withdrawn, because there is nothing to send to.
let sessions = [];
let viewing = null;

function emptyState() {
  return { mode: null, history: [], sourceCoverage: [], selected: [], pending: null,
    proposedPlan: null, plannedGrants: null, runs: [], observations: [], lessonCandidates: [], authority: null, lastError: null };
}

const el = (id) => document.getElementById(id);
const thread = el('thread');
const emptySection = el('empty');
const composer = el('composer');
const messageInput = el('message');
const sendButton = el('send');
const errorBox = el('error');
const activity = el('activity');
const progress = el('progress');
const toast = el('toast');
const shell = el('shell');

/* ---- dom helpers --------------------------------------------------------------------------- */
function h(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value; // the only text assignment in this file
    else if (key === 'onClick') node.addEventListener('click', value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat(2)) if (child !== null && child !== undefined && child !== false) node.append(child);
  return node;
}

function icon(id, cls = 'icon') {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('class', cls);
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG, 'use');
  use.setAttribute('href', '#' + id);
  svg.append(use);
  return svg;
}

const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };

/* ---- markdown ------------------------------------------------------------------------------ */
// A model's reply is markdown, and rendering it as literal characters is the most visible way an
// interface says "prototype". This builds DOM NODES from the token stream -- it never assembles a
// string of HTML and never touches innerHTML, so the invariant at the top of this file still
// holds for text the model wrote. Deliberately small: fenced code, headings, lists, quotes, rules,
// and inline code/bold/italic/links. Anything it does not recognise stays literal text, which is
// the safe direction to fail in.
const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\*[^*\n]+\*)|(\[[^\]\n]+\]\((https?:\/\/[^\s)]+)\))/;

function inlineInto(parent, text) {
  let rest = String(text);
  for (;;) {
    const match = INLINE.exec(rest);
    if (!match) { if (rest) parent.append(document.createTextNode(rest)); return; }
    if (match.index > 0) parent.append(document.createTextNode(rest.slice(0, match.index)));
    const token = match[0];
    if (token.startsWith('`')) parent.append(h('code', { text: token.slice(1, -1) }));
    else if (token.startsWith('**')) parent.append(h('strong', { text: token.slice(2, -2) }));
    else if (token.startsWith('*')) parent.append(h('em', { text: token.slice(1, -1) }));
    else {
      // Only http(s), and opened away from the app window: this window has no address bar to get
      // back from. The label is the model's text and goes through textContent like everything else.
      parent.append(h('a', {
        href: match[5], target: '_blank', rel: 'noopener noreferrer',
        text: token.slice(1, token.indexOf(']')),
      }));
    }
    rest = rest.slice(match.index + token.length);
  }
}

function renderMarkdown(text) {
  const frag = document.createDocumentFragment();
  const lines = String(text ?? '').split('\n');
  let paragraph = [];
  const flush = () => {
    if (!paragraph.length) return;
    const node = h('p');
    inlineInto(node, paragraph.join(' '));
    frag.append(node);
    paragraph = [];
  };
  const listOf = (tag, test) => {
    const list = h(tag, { class: 'md-list' });
    while (index < lines.length) {
      const item = test(lines[index]);
      if (!item) break;
      const li = h('li');
      inlineInto(li, item[1]);
      list.append(li);
      index += 1;
    }
    return list;
  };

  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    const fence = /^\s*```(\w*)\s*$/.exec(line);
    if (fence) {
      flush();
      index += 1;
      const body = [];
      while (index < lines.length && !/^\s*```\s*$/.test(lines[index])) { body.push(lines[index]); index += 1; }
      index += 1;
      const source = body.join('\n');
      const pre = h('pre', { class: 'md-code' }, h('code', { text: source }));
      if (fence[1]) pre.setAttribute('data-lang', fence[1]);
      frag.append(h('div', { class: 'md-code-wrap' }, pre,
        h('button', { type: 'button', class: 'copy-code', title: 'Copy this block',
          onClick: () => copyText(source, 'Code copied.'), text: 'copy' })));
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flush();
      // Offset by two: the page already owns h1/h2, and a reply must not outrank them.
      const node = h('h' + Math.min(6, heading[1].length + 2));
      inlineInto(node, heading[2]);
      frag.append(node);
      index += 1;
      continue;
    }
    if (/^\s*([-*_])\s*\1\s*\1[\s\1]*$/.test(line)) { flush(); frag.append(h('hr')); index += 1; continue; }
    if (/^\s*[-*+]\s+/.test(line)) { flush(); frag.append(listOf('ul', (l) => /^\s*[-*+]\s+(.*)$/.exec(l))); continue; }
    if (/^\s*\d+[.)]\s+/.test(line)) { flush(); frag.append(listOf('ol', (l) => /^\s*\d+[.)]\s+(.*)$/.exec(l))); continue; }
    if (/^\s*>\s?/.test(line)) {
      flush();
      const quote = h('blockquote');
      while (index < lines.length && /^\s*>\s?/.test(lines[index])) {
        inlineInto(quote, lines[index].replace(/^\s*>\s?/, ''));
        quote.append(document.createElement('br'));
        index += 1;
      }
      if (quote.lastChild) quote.removeChild(quote.lastChild);
      frag.append(quote);
      continue;
    }
    if (!line.trim()) { flush(); index += 1; continue; }
    paragraph.push(line);
    index += 1;
  }
  flush();
  return frag;
}
const short = (value, n = 12) => (typeof value === 'string' ? value.slice(0, n) : '');
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const bytes = (n) => {
  if (!Number.isFinite(n)) return '—';
  if (n >= 1048576) return `${Math.round(n / 1048576)} MiB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KiB`;
  return `${n} B`;
};

/* ---- transport ----------------------------------------------------------------------------- */
async function call(path, body) {
  const headers = { 'Content-Type': 'application/json; charset=utf-8' };
  if (token) headers['X-Concord-Token'] = token;
  const response = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body ?? {}) });
  let payload;
  try { payload = await response.json(); } catch { throw new Error('The server returned an invalid response.'); }
  if (!response.ok) throw new Error(payload?.error?.message || 'The action could not be completed.');
  return payload;
}

async function fetchState() {
  const response = await fetch('/api/state');
  const payload = await response.json();
  if (!response.ok) throw new Error('Unable to load the chat state.');
  token = payload.token;
  status = payload.status ?? status;
  applyState(payload.state ?? state);
  fetchExchange();
  fetchSessions();
}

function applyState(next) {
  const before = state.history.length;
  state = { ...emptyState(), ...next };
  render();

  const latest = state.history[state.history.length - 1];
  if (state.history.length > before && latest && latest.role === 'assistant') {
    announce('Concord replied. ' + String(latest.content ?? '').slice(0, 300));
  }

  if (state.lastError) {
    const cause = state.lastError.reasonCode ? ` (${state.lastError.reasonCode})` : '';
    // lastError.reason is the supervisor's own diagnostic -- which rule was broken, not just that
    // one was. Dropping it was the difference between a code and an explanation.
    const detail = state.lastError.reason ? ` ${state.lastError.reason}` : ' The recorded receipt below says why.';
    // The tool's own code lives on the failing task in the observation, not on lastError, and it
    // is the one that distinguishes "no credential" from "endpoint unreachable".
    const failing = observationIndex().get(state.lastError.runId);
    const task = (failing?.tasks ?? []).find((entry) => entry.code);
    showError(`Supervisor refused: ${state.lastError.code}${cause}.${detail}`,
      { retry: true, hint: diagnose(state.lastError.code, task?.toolCode) });
    announce(`The turn was refused: ${state.lastError.code}.`);
  }
}

// Pull-based, because no measured MCP client declares sampling: Concord files what you typed and
// the connected provider collects it on its own schedule. Supplementary by design -- a failed
// poll must never disturb the conversation.
/* ---- live progress -------------------------------------------------------------------------- */
// Measured against the configured model: ~95% of a turn is the model reasoning, with the answer
// arriving in one short burst at the end. So what is shown while waiting is how far it has got,
// not a stream of text -- and the reasoning itself is never displayed, only counted. The preview
// that does appear is labelled, because nothing here has been recorded yet and a preview that
// looked like an answer would be the exact lie the receipt exists to prevent.
let progressUpdate = null;

function subscribeProgress() {
  let source;
  try { source = new EventSource('/api/stream'); } catch { return; }
  source.addEventListener('message', (event) => {
    let update;
    try { update = JSON.parse(event.data); } catch { return; }
    progressUpdate = update;
    renderProgress();
  });
  // The stream is supplementary. If it drops, the turn is unaffected and the dock still has the
  // elapsed counter, so this reconnects quietly rather than reporting anything.
  source.addEventListener('error', () => { progressUpdate = null; renderProgress(); });
}

function renderProgress() {
  const node = el('progress-note');
  if (!node) return;
  clear(node);
  if (!busy || !progressUpdate) { node.hidden = true; return; }
  node.hidden = false;
  if (progressUpdate.phase === 'reasoning') {
    node.append(h('span', { class: 'progress-phase', text: 'thinking' }),
      h('span', { text: `${progressUpdate.reasoningChars ?? 0} characters of private reasoning, not shown and not recorded` }));
    return;
  }
  if (progressUpdate.phase === 'drafting') {
    node.append(h('span', { class: 'progress-phase', text: 'drafting' }),
      h('span', { class: 'progress-preview', text: String(progressUpdate.preview ?? '').slice(-600) }),
      h('span', { class: 'progress-caveat', text: 'preview — not yet recorded' }));
  }
}

async function fetchSessions() {
  try {
    const response = await fetch('/api/sessions');
    if (!response.ok) return;
    const payload = await response.json();
    sessions = Array.isArray(payload.sessions) ? payload.sessions : [];
    renderSessions();
  } catch { /* the list is supplementary; a failed read must not disturb the conversation */ }
}

async function openSession(id) {
  try {
    const payload = await call('/api/session', { id });
    viewing = payload.session ?? null;
    render();
    thread.scrollTop = 0;
  } catch (error) {
    showError(error.message);
  }
}

function closeSession() {
  viewing = null;
  render();
}

function renderSessions() {
  const list = el('session-list');
  if (!list) return;
  el('session-count').textContent = String(sessions.length);
  clear(list);
  if (!sessions.length) { list.append(h('li', null, h('span', { class: 'turn-text', text: 'No recorded sessions.' }))); return; }
  for (const session of sessions) {
    const label = session.opening || '(no message yet)';
    const active = viewing ? viewing.id === session.id : session.current;
    list.append(h('li', null, h('button', {
      type: 'button',
      title: `${session.id} · ${plural(session.turns, 'turn')} · ${plural(session.runs, 'run')}`,
      'aria-current': active ? 'true' : null,
      onClick: () => (session.current ? closeSession() : openSession(session.id)),
    },
      h('span', { class: 'turn-dot', 'data-kind': session.current ? 'user' : 'reply-only' }),
      h('span', { class: 'turn-text', text: label }),
      session.current ? h('span', { class: 'pill', text: 'live' }) : null)));
  }
}

async function fetchExchange() {
  try {
    const response = await fetch('/api/exchange');
    if (!response.ok) return;
    const payload = await response.json();
    exchange = Array.isArray(payload.messages) ? payload.messages : [];
    renderExchange();
  } catch { /* ignored on purpose */ }
}
setInterval(fetchExchange, 5000);

/* ---- chrome -------------------------------------------------------------------------------- */
function showError(text, options = {}) {
  clear(errorBox);
  if (!text) { errorBox.hidden = true; return; }
  errorBox.append(h('span', { text }));
  // A failed turn whose message is recoverable offers the recovery, rather than leaving the
  // operator to retype what they already typed.
  if (options.retry && retryable) {
    errorBox.append(h('button', { type: 'button', class: 'ghost', text: 'Retry',
      onClick: () => { const again = retryable; retryable = null; showError(null); sendMessage(again); } }));
  }
  if (options.hint) errorBox.append(h('span', { class: 'error-hint', text: options.hint }));
  errorBox.hidden = false;
}

function announce(text) {
  const node = el('announce');
  if (node) node.textContent = text;
}

// A failure that is really "the model endpoint is not answering" should say so, rather than
// handing over a code and leaving the operator to work out that Ollama is not running.
function diagnose(code, toolCode) {
  if (toolCode === 'INTEGRATION_CREDENTIAL') return 'The model adapter has no credential. For a loopback server one is supplied automatically; for a remote one set the configured apiKeyEnv variable.';
  if (code === 'WEB_TIMEOUT' || toolCode === 'WEB_TIMEOUT' || toolCode === 'INTEGRATION_TIMEOUT') return 'The model did not answer within its deadline. Check that the configured model server is running and reachable.';
  if (toolCode === 'INTEGRATION_PROCESS' || toolCode === 'WEB_HTTP') return 'The model server refused or could not be reached. Check that it is running at the configured origin.';
  return '';
}

function showToast(text) {
  toast.textContent = text;
  toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.hidden = true; }, 5000);
}

function setActivity(label, kind) {
  activity.textContent = label;
  activity.dataset.state = kind;
}

// A turn can run for the whole policy deadline -- 300 seconds on this machine -- so "Working"
// with no elapsed time and no way out is not an acceptable thing to show someone. The label
// counts, and the stop button is live for exactly as long as there is something to stop.
let busyTimer = null;
let busyLabel = '';

function setBusy(next, label) {
  busy = next;
  sendButton.disabled = next;
  messageInput.readOnly = next;
  progress.hidden = !next;
  el('cancel').hidden = !next;
  thread.setAttribute('aria-busy', next ? 'true' : 'false');
  clearInterval(busyTimer);
  busyTimer = null;
  renderDock();
  if (!next) { progressUpdate = null; renderProgress(); setActivity(label ?? 'Ready', 'ready'); return; }
  renderProgress();
  busyLabel = label ?? 'Working';
  const started = Date.now();
  const tick = () => setActivity(`${busyLabel} · ${Math.round((Date.now() - started) / 1000)}s`, 'busy');
  tick();
  busyTimer = setInterval(tick, 1000);
}

/* ---- rail ---------------------------------------------------------------------------------- */
function renderTurnIndex() {
  const list = el('turn-index');
  clear(list);
  el('turn-count').textContent = String(state.history.length);
  if (!state.history.length) {
    list.append(h('li', null, h('span', { class: 'turn-text', text: 'No turns yet.' })));
    return;
  }
  state.history.forEach((message, index) => {
    const kind = message.role === 'user' ? 'user' : (message.execution?.kind ?? 'reply-only');
    const label = (message.content ?? '').replace(/\s+/g, ' ').trim() || '(empty)';
    list.append(h('li', null, h('button', {
      type: 'button',
      title: label,
      onClick: () => {
        const target = document.getElementById(`msg-${index}`);
        if (target) target.scrollIntoView({ block: 'start' });
      },
    }, h('span', { class: 'turn-dot', 'data-kind': kind }), h('span', { class: 'turn-text', text: label }))));
  });
}

function renderAuthority() {
  const facts = el('authority');
  clear(facts);
  const authority = state.authority;
  const chip = el('authority-chip');
  if (!authority) {
    facts.append(h('dt', { text: 'In force' }), h('dd', { text: 'after the first turn' }));
    chip.textContent = 'authority pending';
    chip.title = 'The authority in force is reported once a turn has run.';
  } else {
    const effects = Array.isArray(authority.allowedEffects) ? authority.allowedEffects : [];
    const tools = Array.isArray(authority.allowedTools) ? authority.allowedTools.length : 0;
    const gated = effects.filter((effect) => effect === 'write' || effect === 'network' || effect === 'process');
    const origins = Array.isArray(authority.allowedOrigins) ? authority.allowedOrigins : [];
    const rows = [
      ['Effects', effects.join(' · ') || 'none'],
      ['Gated', gated.join(' · ') || 'none'],
      ['Tools allowed', String(tools)],
      ['Max tasks', String(authority.maxTasks ?? '—')],
      ['Deadline', authority.timeoutMs ? `${authority.timeoutMs} ms` : '—'],
      ['Output cap', bytes(authority.maxOutputBytes)],
      ['Journal cap', bytes(authority.maxJournalBytes)],
      // The network allowlist. It decides where a network effect may go at all, which makes it
      // the most consequential field in the policy and the one most worth being able to read.
      ['Network origins', origins.length ? origins.join(' · ') : 'none permitted'],
    ];
    for (const [key, value] of rows) facts.append(h('dt', { text: key }), h('dd', { text: value }));
    chip.textContent = gated.length ? plural(gated.length, 'gated effect') : 'no gated effects';
    chip.title = gated.length
      ? `These effects cannot run without your exact approval: ${gated.join(', ')}`
      : 'This authority permits no write, network or process effect at all.';
  }

  const tools = Array.isArray(status.tools) ? status.tools : [];
  el('tool-count').textContent = String(tools.length);
  const toolList = el('tool-list');
  clear(toolList);
  for (const name of tools) toolList.append(h('li', { text: name }));
}

function renderInventory() {
  const facts = el('inventory');
  clear(facts);
  const rows = [
    ['Sources', status.sourceCount ?? 0],
    ['Files', status.files ?? 0],
    ['Capabilities', status.capabilities ?? 0],
    ['Skill files', status.skillFiles ?? 0],
    ['Runs', (state.runs ?? []).length],
  ];
  for (const [key, value] of rows) facts.append(h('dt', { text: key }), h('dd', { text: String(value) }));

  el('source-count').textContent = String(state.sourceCoverage.length);
  const list = el('source-list');
  clear(list);
  if (!state.sourceCoverage.length) {
    list.append(h('li', null, h('span', { text: 'Selected with the first turn.' })));
    return;
  }
  for (const sourceId of state.sourceCoverage) {
    const matches = state.selected.filter((item) => item.sourceId === sourceId);
    // The score is why a capability was selected for this turn. Without it the count says a
    // source matched but not how well, which is the part worth knowing.
    const best = matches.reduce((top, item) => (typeof item.score === 'number' && item.score > top ? item.score : top), 0);
    list.append(h('li', { title: matches.map((item) => item.title).filter(Boolean).join(', ') },
      h('span', { text: sourceId }),
      h('span', { class: 'mono', text: matches.length ? `${matches.length}${best ? ' · ' + best.toFixed(2) : ''}` : '' })));
  }
}

function renderExchange() {
  const list = el('exchange-list');
  if (!list) return;
  const answers = new Map();
  for (const entry of exchange) if (Number.isInteger(entry.replyTo)) answers.set(entry.replyTo, entry);
  const asked = exchange.filter((entry) => !Number.isInteger(entry.replyTo));
  el('exchange-count').textContent = String(asked.filter((entry) => entry.open).length);
  clear(list);
  if (!asked.length) {
    list.append(h('p', { text: 'Prompts you send are also filed for the provider connected over MCP.' }));
    return;
  }
  for (const entry of asked.slice(-5)) {
    const answer = answers.get(entry.seq);
    const row = h('div', { class: 'exchange-row', 'data-open': entry.open ? 'true' : 'false' },
      h('span', { class: 'exchange-state', text: entry.open ? 'waiting' : 'answered' }),
      h('p', { text: entry.message }),
      answer ? h('p', { class: 'answer', text: answer.message }) : null);
    // A waiting question was a dead end: readable, unanswerable. It is Concord's own outbox, so
    // answering is an internal write, not an effect on anything outside this machine.
    if (entry.open && !answer) {
      const field = h('input', { type: 'text', class: 'exchange-reply', 'aria-label': 'Answer this question', placeholder: 'Answer…' });
      field.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter') return;
        event.preventDefault();
        const text = field.value;
        field.value = '';
        replyToPeer(entry.seq, text);
      });
      row.append(field);
    }
    list.append(row);
  }
}

/* ---- the receipt --------------------------------------------------------------------------- */
// `observations` arrives as a bounded-records envelope, not a bare array: the harness keeps the
// newest 8 within a byte budget and reports how many it dropped. Reading `.records` is required,
// and `omittedCount` is worth keeping rather than discarding -- it is the difference between
// "this run has no receipt" and "this run's receipt aged out of the window", which a reader
// otherwise cannot tell apart.
function observationRecords() {
  const source = state.observations;
  if (Array.isArray(source)) return { records: source, omittedCount: 0, totalCount: source.length, fullDigest: null };
  if (source && Array.isArray(source.records)) {
    return {
      records: source.records,
      omittedCount: source.omittedCount ?? 0,
      totalCount: source.totalCount ?? source.records.length,
      fullDigest: typeof source.fullDigest === 'string' ? source.fullDigest : null,
    };
  }
  return { records: [], omittedCount: 0, totalCount: 0, fullDigest: null };
}

// One observation per run, keyed so a reply's settled attempts can be joined to the real
// per-task record rather than guessed at by position.
function observationIndex() {
  const index = new Map();
  for (const observation of observationRecords().records) {
    if (observation && typeof observation.runId === 'string') index.set(observation.runId, observation);
  }
  return index;
}

function taskRow(task) {
  const outcome = task.code ? 'failed' : (task.requestHash ? 'blocked' : 'completed');
  const right = task.code
    ? (task.toolCode && task.toolCode !== task.code ? `${task.code} / ${task.toolCode}` : task.code)
    : (task.requestHash ? `awaiting ${short(task.requestHash, 8)}` : `out ${short(task.outputHash, 10)}`);
  return h('li', { 'data-outcome': outcome },
    h('span', null,
      h('span', { class: 'task-id', text: task.taskId ?? '—' }),
      task.tool ? h('span', { class: 'task-tool', text: task.tool }) : null),
    h('span', { class: 'task-out', text: right }),
    task.reason ? h('p', { class: 'task-reason', text: task.reason }) : null);
}

function runBlock(runId, runStatus, observation) {
  const note = replayNotes.get(runId);
  const tasks = Array.isArray(observation?.tasks) ? observation.tasks : [];
  return h('div', { class: 'receipt-run' },
    h('div', { class: 'receipt-run-head' },
      h('span', { class: 'runid', text: runId }),
      h('span', { text: runStatus ?? observation?.status ?? 'unknown' }),
      observation?.root ? h('span', { class: 'runid', text: `root ${short(observation.root, 12)}` }) : null),
    tasks.length
      ? h('ol', { class: 'tasks' }, tasks.map(taskRow))
      // The supervisor records a rejected proposal as an observation with no task list, because
      // nothing ran. Saying so beats rendering an empty table that looks like a clean run.
      : h('p', { class: 'replay-note', text: observation
          ? (observation.reason ?? 'No task record: nothing executed under this run.')
          : `This run's receipt has aged out of the bounded observation window (${observationRecords().omittedCount} of ${observationRecords().totalCount} dropped), so its task record is not available here. Replay still verifies it from its journal.` }),
    h('div', { class: 'receipt-actions' },
      h('button', { type: 'button', onClick: () => replayRun(runId) }, icon('i-replay'), h('span', { text: 'Replay' })),
      note ? h('span', { class: 'replay-note', 'data-verified': String(note.verified), text: note.text }) : null));
}

function receiptFor(message, index, observations) {
  const execution = message.execution;
  // Stated, not omitted. An absent strip is indistinguishable from a strip that failed to render,
  // and in a harness whose whole claim is "every effect is recorded" the reader has to be able to
  // tell "nothing ran" from "we lost the record of what ran".
  if (execution && execution.kind === 'reply-only') {
    return [h('div', { class: 'receipt-strip receipt-none' },
      icon('i-receipt'),
      h('span', { class: 'verdict', text: 'no effect' }),
      h('span', { text: 'nothing ran, so there is nothing to verify' }))];
  }
  if (!execution || execution.kind !== 'plan-proposed') return [];
  const attempts = Array.isArray(execution.attempts) ? execution.attempts : [];
  const key = `receipt-${index}`;
  const open = expanded.has(key);
  const last = attempts[attempts.length - 1];
  const runStatus = execution.ran ? 'completed' : (last?.status ?? 'not run');
  const tools = Array.isArray(execution.toolsCompleted) ? execution.toolsCompleted : [];
  const observation = last ? observations.get(last.runId) : null;

  const strip = h('button', {
    type: 'button',
    class: 'receipt-strip',
    'aria-expanded': open ? 'true' : 'false',
    'data-status': runStatus,
    onClick: () => { if (open) expanded.delete(key); else expanded.add(key); render(); },
  },
    icon('i-receipt'),
    h('span', { class: 'verdict', text: execution.ran ? 'executed' : runStatus }),
    h('span', { text: attempts.length ? plural(execution.attemptCount ?? attempts.length, 'attempt') : 'no attempt' }),
    tools.length ? h('span', { text: tools.join(', ') }) : null,
    observation?.root ? h('span', { class: 'hash', text: short(observation.root, 10) }) : null,
    icon('i-chevron', 'icon chev'));

  if (!open) return [strip];
  return [strip, h('div', { class: 'receipt' },
    attempts.length
      ? attempts.map((attempt) => runBlock(attempt.runId, attempt.status, observations.get(attempt.runId)))
      : h('p', { class: 'replay-note', text: 'This reply proposed a plan that has not been run.' }),
    execution.planHash ? h('div', { class: 'receipt-run-head' },
      h('span', { class: 'hash-label', text: 'plan' }),
      h('span', { class: 'runid', text: execution.planHash }),
      // Position in the run ledger when this reply was committed: what makes attribution pick
      // the turn that actually proposed the plan rather than any turn proposing identical bytes.
      Number.isInteger(execution.runsAtCommit)
        ? h('span', { text: `committed at run ${execution.runsAtCommit}` }) : null,
      // A digest of the whole observation set, including the entries the window dropped.
      observationRecords().fullDigest
        ? h('span', { text: `observations ${short(observationRecords().fullDigest, 10)}` }) : null) : null)];
}

// A citation exists only because the kernel checked it: a quote that does not appear verbatim in
// the recorded output of the cited task is refused at the source, so this marker is a verified
// fact rather than the model's claim about itself. Worth its own visual treatment for that reason.
function citationsFor(message) {
  const citations = Array.isArray(message.citations) ? message.citations : [];
  if (!citations.length) return null;
  return h('ul', { class: 'citations' }, citations.map((citation) => h('li', { class: 'citation' },
    icon('i-quote'),
    citation.quote
      ? h('blockquote', { text: citation.quote })
      : h('blockquote', { text: `recorded output of ${citation.taskId}` }),
    h('p', { class: 'provenance', text: [
      citation.tool ? citation.tool : null,
      citation.taskId ? `task ${citation.taskId}` : null,
      citation.runId ? `run ${citation.runId}` : null,
      citation.outputHash ? `out ${short(citation.outputHash, 10)}` : null,
      'verified against the recorded output',
    ].filter(Boolean).join(' · ') }))));
}

/* ---- thread -------------------------------------------------------------------------------- */
function renderThread() {
  // Scrolling to the bottom on every repaint yanked the view away from anyone reading an expanded
  // receipt further up -- and expanding a receipt is itself a repaint. Follow the conversation
  // only for a reader who was already at the bottom.
  const previousTop = thread.scrollTop;
  const wasAtBottom = thread.scrollHeight - thread.scrollTop - thread.clientHeight < 80;
  clear(thread);
  // Checked before the empty state, not after: a fresh live session has no turns, so an
  // empty-first ordering made a recording impossible to open in exactly the case where you would
  // most want to -- having just started, with nothing of your own on screen yet.
  // A past session replaces the transcript wholesale and says so. Its receipts still render, but
  // nothing in it can be acted on: the plan it proposed and the approvals it held belonged to a
  // harness that is no longer running.
  if (viewing) {
    thread.append(h('section', { class: 'card card-reading' },
      h('div', { class: 'card-head' }, icon('i-receipt'),
        h('h2', { text: 'Reading a past session' }),
        h('span', { class: 'spacer' }),
        h('button', { type: 'button', class: 'btn-primary', onClick: () => closeSession(), text: 'Back to the live session' })),
      h('div', { class: 'card-body' },
        h('p', { text: `${viewing.id} · ${plural((viewing.transcript?.history ?? []).length, 'turn')} · ${plural((viewing.transcript?.runs ?? []).length, 'run')}. This is a recording: it cannot be continued, approved or replayed from here.` }))));
    for (const [index, message] of (viewing.transcript?.history ?? []).entries()) {
      const assistant = message.role !== 'user';
      const body = h('div', { class: 'msg-body' });
      if (assistant) body.append(renderMarkdown(message.content ?? '')); else body.textContent = message.content ?? '';
      thread.append(h('article', { class: 'msg', id: `msg-${index}`, 'data-role': assistant ? 'assistant' : 'user' },
        h('div', { class: 'msg-who' }, h('span', { text: assistant ? 'Concord' : 'You' })),
        body));
    }
    thread.scrollTop = wasAtBottom ? thread.scrollHeight : previousTop;
    renderDock();
    return;
  }

  if (!state.history.length && !state.pending && !state.proposedPlan) {
    if (emptySection) thread.append(emptySection);
    wireSuggestions();
    renderDock();
    return;
  }

  const observations = observationIndex();
  const needle = search.trim().toLowerCase();
  let shown = 0;
  state.history.forEach((message, index) => {
    const assistant = message.role !== 'user';
    const content = message.content ?? '';
    if (needle && !content.toLowerCase().includes(needle)) return;
    shown += 1;
    // The model writes markdown; a person writes what they typed. Only the model's side is
    // parsed, so nothing a person types is ever reinterpreted as formatting.
    const body = h('div', { class: 'msg-body' });
    if (assistant) body.append(renderMarkdown(content)); else body.textContent = content;
    thread.append(h('article', {
      class: 'msg',
      id: `msg-${index}`,
      'data-role': assistant ? 'assistant' : 'user',
      'data-kind': assistant ? (message.execution?.kind ?? 'reply-only') : 'user',
    },
      h('div', { class: 'msg-who' },
        h('span', { text: assistant ? 'Concord' : 'You' }),
        h('span', { class: 'msg-tools' },
          h('button', { type: 'button', class: 'ghost', title: 'Copy this message',
            onClick: () => copyText(content, 'Message copied.'), text: 'copy' }),
          assistant ? null : h('button', { type: 'button', class: 'ghost', title: 'Put this back in the composer to edit and send again',
            onClick: () => { messageInput.value = content; autoGrow(); messageInput.focus(); }, text: 'edit' }))),
      body,
      assistant ? citationsFor(message) : null,
      assistant ? receiptFor(message, index, observations) : null));
  });
  if (needle && shown === 0) {
    thread.append(h('p', { class: 'replay-note', text: `No message in this session contains "${search.trim()}".` }));
  }

  const plan = state.proposedPlan;
  if (plan && Array.isArray(plan.tasks) && plan.tasks.length) thread.append(planCard(plan));
  // Before the run, not after a block: these are every effect the plan will ask for, each bound
  // by its own exact request. Hidden once a gate is actually pending, because then the plan is
  // mid-flight and the gate card below is the thing to act on.
  if (!state.pending && ungrantedPlanned().length) thread.append(plannedGrantsCard(state.plannedGrants));
  (state.lessonCandidates ?? []).forEach((candidate, index) => {
    if (!dismissedLessons.has(candidate.key ?? String(index))) thread.append(lessonCard(candidate, index));
  });
  if (state.pending) thread.append(gateCard(state.pending));

  thread.scrollTop = wasAtBottom ? thread.scrollHeight : previousTop;
  renderDock();
}

// The dock is one of two views, never both: the composer, or the gate. `send()` in the harness has
// no guard against a pending approval -- it adopts a fresh plan and applyOutcome overwrites
// `pending` -- so a composer left live beside a gate turns "ask a follow-up question" into
// "silently discard the effect you were deciding about".
function renderDock() {
  const bar = el('gate-bar');
  // Reading a recording: there is nothing to send to, so the composer is withdrawn rather than
  // left live to type into a session that ended.
  if (viewing) {
    composer.hidden = true;
    bar.hidden = false;
    clear(bar);
    bar.append(
      h('span', { class: 'gate-bar-text', text: 'You are reading a past session.' }),
      h('button', { type: 'button', class: 'btn-primary', onClick: () => closeSession(), text: 'Back to the live session' }));
    return;
  }
  // Not blocking while the approved effect is actually running: `pending` stays set until the
  // response returns, so without this the dock went on asking for an approval that had already
  // been given and was at that moment executing.
  const blocking = Boolean(state.pending) && !gateDismissed && !busy;
  composer.hidden = blocking;
  bar.hidden = !blocking;
  clear(bar);
  if (!blocking) return;
  bar.append(
    h('span', { class: 'gate-bar-text', text: `${state.pending.tool ?? 'An effect'} is waiting on your approval.` }),
    h('button', { type: 'button', class: 'btn-gate', onClick: () => approvePending(), text: 'Approve this exact request' }),
    h('button', {
      type: 'button',
      title: 'The harness replaces the pending approval with your next proposal, so this effect will not run.',
      onClick: () => { gateDismissed = true; renderDock(); messageInput.focus(); },
      text: 'Write something else instead',
    }));
}

/** Effects this plan will ask for that the session does not already hold a grant for. */
function ungrantedPlanned() {
  return (state.plannedGrants?.grants ?? []).filter((grant) => !grant.granted);
}

/**
 * Every effect a plan will perform, shown before any of it runs.
 *
 * The harness used to refuse a plan with more than one gated effect, so this view could not exist:
 * an operator met effects one at a time, each after the previous had already happened. Each of
 * these carries its own exact request hash, computed from the plan rather than discovered by
 * running into it, so the whole set can be granted and then executed in a single pass.
 */
function plannedGrantsCard(planned) {
  const ungranted = ungrantedPlanned();
  const total = planned.grants.length;
  const held = total - ungranted.length;
  return h('section', { class: 'card card-gate' },
    h('div', { class: 'card-head' }, icon('i-gate'),
      h('h2', { text: total === 1 ? 'This plan performs 1 effect' : `This plan performs ${total} effects` }),
      h('span', { class: 'spacer' }),
      h('span', { class: 'pill', text: held ? `${held}/${total} granted` : String(total) })),
    h('div', { class: 'card-body' },
      h('p', { class: 'note', text: 'Each is bound to its own exact request, computed before the plan runs. Granting them all lets it complete in one pass, so no effect is ever repeated. Granting none is a valid outcome; nothing has run.' }),
      h('ul', { class: 'grant-list' }, planned.grants.map((grant) => h('li', { class: grant.granted ? 'granted' : '' },
        h('span', { class: 'effect-tag', text: grant.effect }),
        h('span', { class: 'tool', text: grant.tool }),
        h('span', { class: 'task', text: `task ${grant.taskId}` }),
        grant.granted ? h('span', { class: 'gated', text: 'granted' }) : null,
        h('details', { class: 'disclose' },
          h('summary', { text: 'Exact request' }),
          h('code', { text: grant.requestHash }),
          h('pre', { class: 'payload', text: JSON.stringify(grant.input?.value ?? grant.input ?? null, null, 2) }))))),
      (planned.deferred ?? []).length
        ? h('p', { class: 'note', text: `${plural(planned.deferred.length, 'effect')} cannot be granted yet because its input comes from an earlier task's result: ${planned.deferred.map((d) => d.taskId).join(', ')}.` })
        : null,
      h('div', { class: 'actions' },
        h('button', {
          type: 'button', class: 'btn-gate',
          onClick: () => approveAllPlanned(),
          text: ungranted.length === 1 ? 'Approve this exact request' : `Approve all ${ungranted.length} exact requests`,
        }),
        h('span', { class: 'note', text: 'Approving runs nothing on its own — press Run this plan afterwards.' }))));
}

function planCard(plan) {
  const pendingTask = state.pending?.taskId;
  return h('section', { class: 'card' },
    h('div', { class: 'card-head' }, icon('i-plan'),
      h('h2', { text: plan.name ? `Proposed plan · ${plan.name}` : 'Proposed plan' }),
      h('span', { class: 'spacer' }),
      h('span', { class: 'pill', text: String(plan.tasks.length) })),
    h('div', { class: 'card-body' },
      h('ol', { class: 'plan-tasks' }, plan.tasks.map((task, index) => h('li', null,
        h('span', { class: 'n', text: String(index + 1) }),
        h('span', { class: 'id', text: task.id ?? '—' }),
        h('span', { class: 'tool', text: task.tool ?? '—' }),
        task.id && task.id === pendingTask ? h('span', { class: 'gated', text: 'awaiting approval' }) : null,
        Array.isArray(task.dependsOn) && task.dependsOn.length
          ? h('span', { class: 'needs', text: `needs ${task.dependsOn.join(', ')}` })
          : null))),
      h('details', { class: 'disclose' },
        h('summary', { text: 'Exact plan' }),
        h('pre', { class: 'payload', text: JSON.stringify(plan, null, 2) })),
      state.pending ? null : planActions()));
}

/**
 * What the plan card offers depends on whether the plan has already run.
 *
 * It used to offer "Run this plan" unconditionally. The button worked -- it ran the plan and the
 * receipt strip above updated -- but the card itself rendered identically before and after, so
 * the only large element on screen said nothing had happened. Worse, a second press really is a
 * no-op: the harness returns the snapshot unchanged for a plan it has already attempted, so the
 * card was inviting a click that could not do anything and then not saying so.
 *
 * The proposer is the latest assistant turn that proposed a plan, which is the turn whose
 * proposal became `proposedPlan`. The window never calls execute with an explicit plan, so the
 * two cannot drift apart here.
 */
function planActions() {
  const proposer = [...state.history].reverse()
    .find((message) => message.role !== 'user' && message.execution?.kind === 'plan-proposed');
  const attempts = proposer?.execution?.attempts ?? [];
  const tools = proposer?.execution?.toolsCompleted ?? [];
  if (!attempts.length) {
    const ungranted = ungrantedPlanned();
    return h('div', { class: 'actions' },
      h('button', { type: 'button', class: 'btn-primary', onClick: () => executePlan(), text: 'Run this plan' }),
      // Says what will actually happen on press. Running with effects still ungranted is allowed
      // and stops at the first one; saying so beats letting the button imply it will complete.
      h('span', { class: 'note', text: ungranted.length
        ? `${plural(ungranted.length, 'effect')} still ungranted, so this stops at the first one. Grant them above to run straight through.`
        : 'Pure and read effects run without a gate; anything else stops here.' }));
  }
  const last = attempts[attempts.length - 1];
  return h('div', { class: 'actions' },
    h('span', { class: 'ran-badge', 'data-status': last.status, text: proposer.execution.ran ? 'already ran' : last.status }),
    // Offered once a plan has run, which is when "what next" is the real question. It grants
    // reasoning calls only: anything that touches the world still stops and asks.
    h('button', { type: 'button', onClick: () => advance(4), title: 'Let Concord take up to four more steps on its own. It stops at any effect needing approval.', text: 'Continue without me' }),
    h('span', { class: 'note', text: tools.length
      ? `${plural(attempts.length, 'attempt')} · ${tools.join(', ')} · receipt on the reply above`
      : `${plural(attempts.length, 'attempt')} · receipt on the reply above` }),
    h('button', {
      type: 'button',
      title: 'Open the receipt for this run',
      onClick: () => {
        const index = state.history.indexOf(proposer);
        if (index >= 0) expanded.add(`receipt-${index}`);
        render();
        document.getElementById(`msg-${index}`)?.scrollIntoView({ block: 'start' });
      },
      text: 'Show the receipt',
    }),
    h('span', { class: 'note', text: 'Running it again does nothing: the harness returns the same snapshot for a plan it has already attempted. Ask again to propose a new one.' }));
}

function gateCard(pending) {
  const provenance = pending.evidenceProvenance;
  return h('section', { class: 'card card-gate' },
    h('div', { class: 'card-head' }, icon('i-gate'), h('h2', { text: 'This effect needs your approval' })),
    h('div', { class: 'card-body' },
      h('div', { class: 'effect-row' },
        h('span', { class: 'effect-tag', text: pending.effect ?? 'effect' }),
        h('span', { class: 'tool', text: pending.tool ?? 'unknown tool' }),
        pending.taskId ? h('span', { class: 'task', text: `task ${pending.taskId}` }) : null),
      h('p', { text: 'Approval binds this exact request. A changed input, a different plan, or another policy produces a different hash and will stop again.' }),
      // Where a network effect is permitted to go is decision-relevant at exactly this moment,
      // and it was the one policy field the gate never showed.
      pending.effect === 'network' ? h('div', { class: 'facts facts-inline' },
        h('dt', { text: 'May reach' }),
        h('dd', { text: (Array.isArray(state.authority?.allowedOrigins) && state.authority.allowedOrigins.length)
          ? state.authority.allowedOrigins.join(' · ')
          : 'no origin is allowlisted, so this call will refuse' })) : null,
      h('div', { class: 'hash-row' },
        h('span', { class: 'hash-label', text: 'request' }),
        h('code', { text: pending.requestHash ?? '' }),
        h('button', {
          type: 'button', class: 'icon-btn', 'aria-label': 'Copy the request hash',
          onClick: () => copyText(pending.requestHash),
        }, icon('i-copy'))),
      h('details', { class: 'disclose', open: true },
        h('summary', { text: 'Exact input' }),
        h('pre', { class: 'payload', text: JSON.stringify(pending.input ?? null, null, 2) })),
      provenance ? h('div', null,
        h('p', { text: 'This effect would persist a lesson. Its evidence:' }),
        h('div', { class: 'provenance-grid' },
          h('div', { class: 'provenance-cell', 'data-tone': 'ok' },
            h('b', { text: String(provenance.groundedCount ?? 0) }),
            h('span', { text: 'grounded in a recorded run' })),
          h('div', { class: 'provenance-cell', 'data-tone': 'warn' },
            h('b', { text: String(provenance.unverifiedHereCount ?? 0) }),
            h('span', { text: 'not verifiable in this session' })))) : null,
      h('div', { class: 'actions' },
        h('button', { type: 'button', class: 'btn-gate', onClick: () => approvePending(), text: 'Approve this exact request' }),
        h('span', { class: 'note', text: 'Ctrl + Enter · leaving it blocked is a valid outcome; nothing has run.' }))));
}

function lessonCard(candidate, index) {
  const key = candidate.key ?? String(index);
  const grounded = candidate.evidenceGrounded === true;
  return h('section', { class: 'card card-lesson' },
    h('div', { class: 'card-head' }, icon('i-lesson'),
      h('h2', { text: candidate.kind === 'success'
        ? 'Concord noticed a working composition'
        : 'Concord distilled a lesson from a failure' }),
      h('span', { class: 'spacer' }),
      h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Dismiss this suggestion',
        onClick: () => { dismissedLessons.add(key); render(); }, text: '×' })),
    h('div', { class: 'card-body' },
      h('p', { class: 'lesson-text', text: candidate.lesson ?? '' }),
      h('div', { class: 'lesson-meta' },
        candidate.occurrence > 1 ? h('span', { text: `occurrence ${candidate.occurrence}` }) : null,
        candidate.runId ? h('span', { text: `run ${candidate.runId}` }) : null,
        // The evidence it would be promoted against, not just whether that evidence is grounded.
        Array.isArray(candidate.suggestedEvidence) && candidate.suggestedEvidence.length
          ? h('span', { class: 'mono', text: `evidence ${candidate.suggestedEvidence.map((e) => short(e, 10)).join(', ')}` })
          : null,
        h('span', { class: grounded ? 'grounded' : 'ungrounded',
          text: grounded ? 'evidence grounded in a recorded run' : 'evidence not verifiable here' })),
      h('p', { text: 'A suggestion, never authority. Nothing is stored unless you ask Concord to promote it, and that is itself a gated effect.' })));
}

/* ---- mode ---------------------------------------------------------------------------------- */
function renderMode() {
  const chip = el('mode-chip');
  if (state.mode === 'live') {
    chip.dataset.mode = 'live';
    chip.textContent = 'Live model';
    chip.title = 'A configured model proposes replies and plans. Protected effects still need your approval.';
  } else {
    // Before the first turn the harness reports no mode. What is configured is already knowable
    // from the tool inventory, so report that instead of "Connecting" forever. There is no
    // demonstration mode: without model.propose a turn refuses, and saying so up front beats
    // letting someone type a message to find out.
    const live = Array.isArray(status.tools) && status.tools.includes('model.propose');
    chip.dataset.mode = live ? 'live' : 'no-model';
    chip.textContent = live ? 'Live model' : 'No model configured';
    chip.title = live
      ? 'A model is configured. Protected effects still need your approval.'
      : 'No model adapter is registered, so a turn cannot be proposed. Start with --integrations naming a model.propose configuration.';
  }
}

// A throw anywhere in here used to escape into the caller and leave the thread cleared but never
// refilled -- a blank conversation with no error and no clue, which is the worst failure an
// interface can have. A render fault is now reported where the operator is already looking, and
// left in the console for diagnosis, instead of being indistinguishable from "nothing happened".
function render() {
  try {
    renderMode();
    renderSessions();
    renderTurnIndex();
    renderAuthority();
    renderInventory();
    renderExchange();
    renderThread();
  } catch (error) {
    console.error('render failed', error);
    showError(`The interface could not render this state: ${error.message}`);
  }
}

/* ---- actions ------------------------------------------------------------------------------- */
async function sendMessage(message) {
  if (busy || !message.trim()) return;
  showError(null);
  // Abandoning a gate is reported after the fact as well as warned about before it: the harness
  // replaces `pending` with this turn's proposal, and an effect quietly ceasing to exist is
  // exactly the kind of thing this interface is supposed to refuse to do silently.
  const abandoned = state.pending ? (state.pending.tool ?? 'an effect') : null;
  const previousHistory = state.history;
  // One round trip, no streaming channel, so the typed message is echoed immediately. Without it
  // the composer empties and nothing appears until the whole turn returns, which reads as a
  // dropped message.
  state = { ...state, history: [...state.history, { role: 'user', content: message }] };
  render();
  setBusy(true, 'Running the turn');
  try {
    const payload = await call('/api/chat', { message });
    gateDismissed = false;
    applyState(payload.state);
    if (abandoned) showToast(`The pending ${abandoned} approval was abandoned; this turn proposed something new.`);
  } catch (error) {
    // Give the text back. A failed turn that also destroys what you typed makes the failure
    // twice as expensive, and the optimistic echo has to be rolled back with it.
    state = { ...state, history: previousHistory };
    retryable = message;
    render();
    if (!messageInput.value) { messageInput.value = message; autoGrow(); }
    showError(error.message, { retry: true });
    announce('The turn failed: ' + error.message);
    setActivity('Failed', 'error');
  } finally {
    setBusy(false);
  }
}

/**
 * Grant every effect this plan will perform, as a set.
 *
 * Sequential rather than concurrent, and it stops at the first refusal: each grant is a separate
 * authorization, so a failure halfway must leave the remaining effects ungranted rather than
 * racing them through. Nothing executes here — the harness adds these to the session and waits.
 */
async function approveAllPlanned() {
  const ungranted = ungrantedPlanned();
  if (busy || !ungranted.length) return;
  showError(null);
  setBusy(true, `Granting ${plural(ungranted.length, 'effect')}`);
  try {
    for (const grant of ungranted) {
      const payload = await call('/api/approve', { requestHash: grant.requestHash });
      applyState(payload.state);
    }
    setActivity('Granted', 'ok');
  } catch (error) {
    showError(error.message);
    setActivity('Failed', 'error');
  } finally {
    setBusy(false);
  }
}

async function approvePending() {
  if (busy || !state.pending) return;
  showError(null);
  setBusy(true, 'Running the approved effect');
  try {
    const payload = await call('/api/approve', { requestHash: state.pending.requestHash });
    applyState(payload.state);
  } catch (error) {
    showError(error.message);
    setActivity('Failed', 'error');
  } finally {
    setBusy(false);
  }
}

/**
 * Let the harness keep going without another message.
 *
 * The budget is in the button rather than in a setting, because it is the authorisation: pressing
 * this grants that many reasoning calls and nothing else. The copy says where it will stop, since
 * an operator handing over control should know in advance what brings it back.
 */
async function advance(maxSteps) {
  if (busy) return;
  showError(null);
  setBusy(true, `Continuing up to ${plural(maxSteps, 'step')}`);
  try {
    const payload = await call('/api/advance', { maxSteps });
    applyState(payload.state);
    const reason = payload.state?.advanced?.reason ?? null;
    const steps = payload.state?.advanced?.steps ?? 0;
    showToast({
      AWAITING_APPROVAL: 'Stopped: the next plan performs an effect and needs your approval.',
      BUDGET_SPENT: `Ran ${plural(steps, 'step')} and stopped at the budget you set.`,
      NOTHING_PROPOSED: `Stopped after ${plural(steps, 'step')}: Concord proposed no further plan.`,
      PLAN_FAILED: `Stopped after ${plural(steps, 'step')}: a plan failed. The receipt says why.`,
      REASONING_FAILED: `Stopped after ${plural(steps, 'step')}: the model call failed.`,
      UNEXPECTED_GATE: 'Stopped: an unexpected effect asked for approval.',
    }[reason] ?? `Stopped after ${plural(steps, 'step')}.`);
    setActivity('Ready', 'ok');
  } catch (error) {
    showError(error.message);
    setActivity('Failed', 'error');
  } finally {
    setBusy(false);
  }
}

async function executePlan() {
  if (busy) return;
  showError(null);
  setBusy(true, 'Running the plan');
  // Counted before and after, because the harness answers an already-attempted plan with the
  // snapshot unchanged and a 200. Without this the interface could not tell "ran" from "declined
  // to run again", and reported neither -- which is what made a working button look broken.
  const before = state.runs.length;
  try {
    const payload = await call('/api/execute', {});
    applyState(payload.state);
    if (state.runs.length > before) {
      const latest = observationIndex().get(state.runs[state.runs.length - 1].id);
      const tasks = Array.isArray(latest?.tasks) ? latest.tasks.length : 0;
      showToast(latest?.status === 'completed'
        ? `Plan ran: ${plural(tasks, 'task')} completed. The receipt is on the reply above.`
        : `Plan ran and ${latest?.status ?? 'did not complete'}. The receipt says why.`);
    } else if (state.pending) {
      showToast('The plan stopped at an effect that needs your approval.');
    } else {
      showToast('Nothing ran: this plan was already attempted. Ask again to propose a new one.');
    }
  } catch (error) {
    showError(error.message);
    setActivity('Failed', 'error');
  } finally {
    setBusy(false);
  }
}

async function replayRun(runId) {
  if (busy) return;
  showError(null);
  setBusy(true, 'Replaying');
  try {
    const payload = await call('/api/replay', { runId });
    const verified = payload.replay?.verified === true;
    const events = payload.replay?.eventCount;
    const root = typeof payload.replay?.root === 'string' ? payload.replay.root : null;
    // Root stability across two replays. The server already returns the root and this client used
    // to drop it. An identical root on a later replay means the plan, policy, registry, source
    // lock and workspace root are still the ones that run executed under; a different root is a
    // REPLAY_CONTEXT condition, and saying "verified" without saying that would hide it.
    const seen = replayRoots.get(runId);
    let stability = '';
    if (root) {
      if (seen === undefined) replayRoots.set(runId, root);
      else stability = seen === root ? ' · same root as the last replay' : ' · ROOT DIFFERS from the last replay';
    }
    replayNotes.set(runId, {
      verified: verified && stability !== ' · ROOT DIFFERS from the last replay',
      text: verified
        ? (events === undefined ? `replayed · verified${stability}` : `replayed · ${plural(events, 'event')} verified${stability}`)
        : 'replay did not verify',
    });
    if (payload.state) applyState(payload.state); else render();
    showToast(verified
      ? `Run ${runId} replayed from its journal and verified.`
      : `Run ${runId} did not verify on replay.`);
  } catch (error) {
    showError(error.message);
    setActivity('Failed', 'error');
  } finally {
    setBusy(false);
  }
}

// Stops whatever is executing. The cancelled turn settles on its own request with a recorded
// failure, so this does not apply state itself -- doing so would race the response that is about
// to arrive and could show a stale snapshot as the final word.
async function cancelTurn() {
  if (!busy) return;
  setActivity('Stopping', 'busy');
  try {
    await call('/api/cancel', {});
    showToast('Stopped. The run is recorded as failed, with the reason on its receipt.');
  } catch (error) {
    showError(error.message);
  }
}

async function replyToPeer(replyTo, message) {
  if (!message.trim()) return;
  try {
    await call('/api/exchange/reply', { replyTo, message });
    showToast('Answer filed for the connected provider.');
    await fetchExchange();
  } catch (error) {
    showError(error.message);
  }
}

async function copyText(value, note = 'Request hash copied.') {
  if (typeof value !== 'string' || !value) return;
  try {
    await navigator.clipboard.writeText(value);
    showToast(note);
  } catch {
    // Clipboard access can be refused. Selecting the hash always works (it is user-select: all),
    // so say that rather than failing silently.
    showToast('Copying was refused. Click the hash to select it.');
  }
}

/* ---- wiring -------------------------------------------------------------------------------- */
function wireSuggestions() {
  for (const button of document.querySelectorAll('.suggestions button[data-prompt]')) {
    if (button.dataset.wired === 'true') continue;
    button.dataset.wired = 'true';
    button.addEventListener('click', () => sendMessage(button.dataset.prompt));
  }
}

function autoGrow() {
  messageInput.style.height = 'auto';
  messageInput.style.height = `${Math.min(messageInput.scrollHeight, window.innerHeight * 0.4)}px`;
}

composer.addEventListener('submit', (event) => {
  event.preventDefault();
  const message = messageInput.value;
  messageInput.value = '';
  autoGrow();
  sendMessage(message);
});

const searchInput = el('thread-search');
searchInput.addEventListener('input', () => { search = searchInput.value; renderThread(); });
searchInput.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') { searchInput.value = ''; search = ''; renderThread(); }
});

messageInput.addEventListener('input', autoGrow);
messageInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey && !event.ctrlKey && !event.metaKey) {
    event.preventDefault();
    composer.requestSubmit();
  }
});

const RAIL_KEY = 'concord.rail';
const THEME_KEY = 'concord.theme';

function setRail(open) {
  shell.dataset.rail = open ? 'open' : 'closed';
  el('rail-toggle').setAttribute('aria-expanded', open ? 'true' : 'false');
  try { localStorage.setItem(RAIL_KEY, open ? 'open' : 'closed'); } catch { /* storage may be blocked */ }
}

function setTheme(theme) {
  if (theme === null) {
    document.documentElement.removeAttribute('data-theme');
    try { localStorage.removeItem(THEME_KEY); } catch { /* storage may be blocked */ }
    return;
  }
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* storage may be blocked */ }
}

el('cancel').addEventListener('click', () => cancelTurn());
el('rail-toggle').addEventListener('click', () => setRail(shell.dataset.rail !== 'open'));
el('theme-toggle').addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  // Three states collapsed into a toggle an operator can predict: the first press opposes
  // whatever is on screen, and pressing back towards the system preference clears the override.
  if (current === null) setTheme(dark ? 'light' : 'dark');
  else if ((current === 'dark') === dark) setTheme(current === 'dark' ? 'light' : 'dark');
  else setTheme(null);
});

document.addEventListener('keydown', (event) => {
  const meta = event.ctrlKey || event.metaKey;
  if (meta && event.key.toLowerCase() === 'k') { event.preventDefault(); messageInput.focus(); return; }
  if (meta && event.key.toLowerCase() === 'b') { event.preventDefault(); setRail(shell.dataset.rail !== 'open'); return; }
  if (meta && event.key === 'Enter' && state.pending && !busy) { event.preventDefault(); approvePending(); return; }
  if (event.key === 'Escape' && !errorBox.hidden) showError(null);
});

try {
  const storedTheme = localStorage.getItem(THEME_KEY);
  if (storedTheme === 'dark' || storedTheme === 'light') document.documentElement.setAttribute('data-theme', storedTheme);
  setRail(localStorage.getItem(RAIL_KEY) !== 'closed');
} catch {
  setRail(true);
}

wireSuggestions();
subscribeProgress();
setActivity('Connecting', 'busy');
fetchState()
  .then(() => setActivity('Ready', 'ready'))
  .catch((error) => { showError(error.message); setActivity('Disconnected', 'error'); });
