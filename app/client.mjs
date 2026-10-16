// Concord chat client. Same-origin only (CSP: connect-src 'self'). Never uses
// innerHTML with server- or model-derived text; everything untrusted goes through
// textContent so a malicious plan, reply, or capability title cannot inject markup.
let token = null;
let state = { mode: null, history: [], sourceCoverage: [], selected: [], pending: null, proposedPlan: null, runs: [] };
let status = { sourceCount: 0, files: 0, capabilities: 0, skillFiles: 0, tools: [] };
let busy = false;

const el = (id) => document.getElementById(id);
const conversation = el('conversation');
const emptyState = el('empty-state');
const composer = el('composer');
const messageInput = el('message');
const sendButton = el('send-button');
const requestError = el('request-error');
const activity = el('activity');
const toast = el('toast');

function setActivity(label, isBusy) {
  activity.classList.toggle('busy', Boolean(isBusy));
  activity.lastChild.textContent = label;
}

function showToast(text) {
  toast.textContent = text;
  toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.hidden = true; }, 4000);
}

function showError(text) {
  if (!text) { requestError.hidden = true; requestError.textContent = ''; return; }
  requestError.textContent = text;
  requestError.hidden = false;
}

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
}

function applyState(next) {
  state = { mode: null, history: [], sourceCoverage: [], selected: [], pending: null, proposedPlan: null, runs: [], ...next };
  render();
}

function clearChildren(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function renderModeBadge() {
  const badge = el('mode-badge');
  const description = el('mode-description');
  const composerMode = el('composer-mode');
  badge.classList.remove('offline', 'live');
  if (state.mode === 'live') {
    badge.textContent = 'Live model';
    badge.classList.add('live');
    description.textContent = 'A configured model proposes replies and plans; protected effects still need your approval.';
    composerMode.textContent = 'Live model';
  } else if (state.mode === 'offline-demo') {
    badge.textContent = 'Offline demo';
    badge.classList.add('offline');
    description.textContent = 'Offline deterministic demonstration: pure-tool plans execute automatically; nothing leaves this process.';
    composerMode.textContent = 'Offline demonstration';
  } else {
    badge.textContent = 'Connecting';
    description.textContent = 'Connecting to your local harness…';
  }
}

function renderSources() {
  const list = el('source-list');
  el('source-count').textContent = String(state.sourceCoverage.length);
  el('message-count').textContent = String(state.history.length);
  el('run-count').textContent = String(state.runs.length);
  clearChildren(list);
  if (!state.sourceCoverage.length) {
    const p = document.createElement('p');
    p.className = 'muted small';
    p.textContent = 'Loading source coverage…';
    list.append(p);
    return;
  }
  for (const sourceId of state.sourceCoverage) {
    const row = document.createElement('div');
    row.className = 'source-row';
    const line = document.createElement('div');
    line.className = 'source-line';
    const symbol = document.createElement('span');
    symbol.className = 'source-symbol';
    symbol.textContent = sourceId.slice(0, 1).toUpperCase();
    const name = document.createElement('span');
    name.className = 'source-name';
    name.textContent = sourceId;
    const dot = document.createElement('span');
    dot.className = 'source-status connected';
    line.append(symbol, name, dot);
    row.append(line);
    const matches = state.selected.filter((item) => item.sourceId === sourceId);
    if (matches.length) {
      const role = document.createElement('div');
      role.className = 'source-role';
      role.textContent = `${matches.length} matching capability reference${matches.length === 1 ? '' : 's'}`;
      row.append(role);
    }
    list.append(row);
  }
}

function roleLabel(role) {
  return role === 'user' ? 'You' : 'Concord';
}

function renderConversation() {
  clearChildren(conversation);
  if (!state.history.length) {
    conversation.append(emptyState);
    return;
  }
  for (const message of state.history) {
    const wrap = document.createElement('div');
    wrap.className = `message ${message.role === 'user' ? 'user' : 'assistant'}`;
    const header = document.createElement('div');
    header.className = 'message-header';
    const avatar = document.createElement('span');
    avatar.className = 'avatar';
    avatar.textContent = message.role === 'user' ? 'Y' : 'C';
    const role = document.createElement('span');
    role.className = 'message-role';
    role.textContent = roleLabel(message.role);
    header.append(avatar, role);
    const body = document.createElement('div');
    body.className = 'message-body';
    body.textContent = message.content;
    wrap.append(header, body);
    conversation.append(wrap);
  }
  conversation.scrollTop = conversation.scrollHeight;
}

function renderApproval() {
  const panel = el('approval-panel');
  const content = el('approval-content');
  clearChildren(content);
  panel.classList.toggle('has-pending', Boolean(state.pending));
  if (!state.pending) {
    const p = document.createElement('p');
    p.className = 'muted small';
    p.textContent = 'No effect awaiting approval.';
    content.append(p);
    return;
  }
  const tag = document.createElement('span');
  tag.className = 'effect-tag';
  tag.textContent = state.pending.effect ?? 'effect';
  const tool = document.createElement('p');
  tool.className = 'pending-tool';
  tool.textContent = `Tool: ${state.pending.tool ?? 'unknown'}`;
  const hash = document.createElement('div');
  hash.className = 'hash';
  hash.textContent = state.pending.requestHash;
  const details = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'Exact input';
  const pre = document.createElement('pre');
  pre.textContent = JSON.stringify(state.pending.input ?? null, null, 2);
  details.append(summary, pre);
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'action-button approve';
  button.textContent = 'Approve this exact effect';
  button.addEventListener('click', () => approvePending());
  content.append(tag, tool, hash, details, button);
}

function renderPlan() {
  const content = el('plan-content');
  const plan = state.proposedPlan;
  el('plan-count').textContent = String(plan?.tasks?.length ?? 0);
  clearChildren(content);
  if (!plan || !Array.isArray(plan.tasks) || !plan.tasks.length) {
    const p = document.createElement('p');
    p.className = 'muted small';
    p.textContent = 'Your next plan will appear here.';
    content.append(p);
    return;
  }
  const details = document.createElement('details');
  details.open = true;
  const summary = document.createElement('summary');
  summary.textContent = `${plan.tasks.length} task${plan.tasks.length === 1 ? '' : 's'}: ${plan.tasks.map((t) => t.tool).join(', ')}`;
  const pre = document.createElement('pre');
  pre.textContent = JSON.stringify(plan, null, 2);
  details.append(summary, pre);
  content.append(details);
  if (!state.pending) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'action-button primary';
    button.textContent = 'Run this plan';
    button.addEventListener('click', () => executePlan());
    content.append(button);
  }
}

function renderContext() {
  const content = el('context-content');
  el('context-count').textContent = String(state.selected.length);
  clearChildren(content);
  if (!state.selected.length) {
    const p = document.createElement('p');
    p.className = 'muted small';
    p.textContent = 'Source instructions are selected with each turn.';
    content.append(p);
    return;
  }
  for (const item of state.selected) {
    const row = document.createElement('div');
    row.className = 'context-item';
    row.textContent = item.title || item.id;
    const span = document.createElement('span');
    span.textContent = `${item.sourceId ?? ''} · ${item.kind ?? ''}`;
    row.append(span);
    content.append(row);
  }
}

function renderRuns() {
  const list = el('run-list');
  clearChildren(list);
  if (!state.runs.length) {
    const p = document.createElement('p');
    p.className = 'muted small';
    p.textContent = 'Completed and blocked runs appear here.';
    list.append(p);
    return;
  }
  for (const run of [...state.runs].reverse()) {
    const row = document.createElement('div');
    row.className = 'run-item';
    const top = document.createElement('div');
    top.className = 'run-top';
    const id = document.createElement('span');
    id.className = 'run-id';
    id.textContent = run.id;
    const statusTag = document.createElement('span');
    statusTag.className = `run-status ${run.status}`;
    statusTag.textContent = run.status;
    top.append(id, statusTag);
    const kind = document.createElement('div');
    kind.className = 'run-kind';
    kind.textContent = 'Concord evidence run';
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'replay-button';
    button.textContent = 'Replay';
    button.addEventListener('click', () => replayRun(run.id));
    row.append(top, kind, button);
    list.append(row);
  }
}

function renderInventory() {
  const inventory = el('inventory');
  clearChildren(inventory);
  const entries = [
    ['Sources', status.sourceCount],
    ['Files', status.files],
    ['Capabilities', status.capabilities],
    ['Skill files', status.skillFiles],
  ];
  for (const [label, value] of entries) {
    const span = document.createElement('span');
    span.textContent = `${label}: ${value}`;
    inventory.append(span);
  }
  el('tool-list').textContent = (status.tools ?? []).join('\n');
}

function render() {
  renderModeBadge();
  renderSources();
  renderConversation();
  renderApproval();
  renderPlan();
  renderContext();
  renderRuns();
  renderInventory();
}

function setBusy(next, label) {
  busy = next;
  sendButton.disabled = busy;
  setActivity(label ?? (busy ? 'Working' : 'Ready'), busy);
}

async function sendMessage(message) {
  if (busy || !message.trim()) return;
  showError(null);
  setBusy(true, 'Sending');
  try {
    const payload = await call('/api/chat', { message });
    applyState(payload.state);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
}

async function approvePending() {
  if (busy || !state.pending) return;
  showError(null);
  setBusy(true, 'Approving');
  try {
    const payload = await call('/api/approve', { requestHash: state.pending.requestHash });
    applyState(payload.state);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
}

async function executePlan() {
  if (busy) return;
  showError(null);
  setBusy(true, 'Running plan');
  try {
    const payload = await call('/api/execute', {});
    applyState(payload.state);
  } catch (error) {
    showError(error.message);
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
    applyState(payload.state);
    showToast(payload.replay?.verified ? `Replay verified ${payload.replay.eventCount ?? ''} event(s).` : 'Replay did not verify.');
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
}

composer.addEventListener('submit', (event) => {
  event.preventDefault();
  const message = messageInput.value;
  messageInput.value = '';
  sendMessage(message);
});

messageInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    composer.requestSubmit();
  }
});

for (const button of document.querySelectorAll('.suggestions button[data-prompt]')) {
  button.addEventListener('click', () => sendMessage(button.dataset.prompt));
}

el('sources-toggle').addEventListener('click', () => {
  el('source-sidebar').classList.add('sources-open');
  el('sources-backdrop').hidden = false;
});
function closeSources() {
  el('source-sidebar').classList.remove('sources-open');
  el('sources-backdrop').hidden = true;
}
el('sources-close').addEventListener('click', closeSources);
el('sources-backdrop').addEventListener('click', closeSources);

setActivity('Connecting', true);
fetchState()
  .then(() => setActivity('Ready', false))
  .catch((error) => { showError(error.message); setActivity('Disconnected', false); });
