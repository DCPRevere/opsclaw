// Chat sidebar: pinned rooms ("*" = Operations, then one per environment),
// then one thread per incident, grouped by environment. Resolved threads
// fold into a "Resolved" group. The list comes from GET
// /api/chat/conversations, already filtered to what this person may see.
import { api, escapeHtml } from './api.js';
import { state } from './state.js';
import { refreshIncidentCards } from './chat.js';

let data = { conversations: [], threads: [] };
let onSelect = () => {};

export function initThreads(selectCallback) {
  onSelect = selectCallback;
}

export function current() {
  return data.conversations.find((c) => c.id === state.chatConversation)
    || data.threads.find((t) => t.id === state.chatConversation)
    || null;
}

export async function loadSidebar() {
  const r = await api('/api/chat/conversations');
  if (!r.ok) return;
  data = { conversations: r.data.conversations || [], threads: r.data.threads || [] };
  const known = data.conversations.some((c) => c.id === state.chatConversation)
    || data.threads.some((t) => t.id === state.chatConversation);
  if (!known) state.chatConversation = 'operations';
  render();
}

function age(at) {
  const ms = Date.now() - new Date(at).getTime();
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

function item(id, html, cls) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'side-item' + (cls ? ' ' + cls : '') + (id === state.chatConversation ? ' active' : '');
  b.dataset.id = id;
  b.innerHTML = html;
  b.addEventListener('click', () => {
    if (state.chatConversation === id) return;
    state.chatConversation = id;
    render();
    onSelect(id);
  });
  return b;
}

function heading(text) {
  const h = document.createElement('div');
  h.className = 'side-heading';
  h.textContent = text;
  return h;
}

function threadItem(t) {
  const sev = String(t.severity || '').toLowerCase();
  const state_ = String(t.state || '').toLowerCase();
  const tag = t.accepted ? '' : ({ acknowledged: 'ack · ', expired: 'expired · ' }[state_] || '');
  return item(
    t.id,
    `<span class="sev-dot sev-${escapeHtml(sev)}"></span>`
      + `<span class="side-label">${escapeHtml(t.label)}</span>`
      + `<span class="side-meta">${tag}${age(t.opened_at)}</span>`,
    'thread',
  );
}

function render() {
  const side = document.getElementById('chat-sidebar');
  if (!side) return;
  side.innerHTML = '';
  side.appendChild(heading('Pinned'));
  for (const c of data.conversations) {
    const label = c.kind === 'operations' ? '* Everything' : c.label;
    side.appendChild(item(c.id, `<span class="side-pin">#</span><span class="side-label">${escapeHtml(label)}</span>`, 'room'));
  }
  const open = data.threads.filter((t) => !t.closed && !t.accepted);
  const known = data.threads.filter((t) => !t.closed && t.accepted);
  const closed = data.threads.filter((t) => t.closed);
  const envs = [...new Set(data.threads.map((t) => `${t.project}::${t.environment}`))].sort();
  const rank = { critical: 0, warning: 1, info: 2 };
  for (const env of envs) {
    const here = open
      .filter((t) => `${t.project}::${t.environment}` === env)
      .sort((a, b) => (rank[String(a.severity).toLowerCase()] ?? 9) - (rank[String(b.severity).toLowerCase()] ?? 9)
        || new Date(b.opened_at) - new Date(a.opened_at));
    if (!here.length) continue;
    side.appendChild(heading(`Issues · ${env.replace('::', ' / ')} (${here.length})`));
    for (const t of here) side.appendChild(threadItem(t));
  }
  if (!open.length) {
    const none = document.createElement('div');
    none.className = 'side-empty muted';
    none.textContent = 'No open issues.';
    side.appendChild(none);
  }
  fold(side, `Known, left alone (${known.length})`, known);
  fold(side, `Closed this week (${closed.length})`, closed);
}

function fold(side, title, threads) {
  if (!threads.length) return;
  const d = document.createElement('details');
  d.className = 'side-closed';
  if (threads.some((t) => t.id === state.chatConversation)) d.open = true;
  const s = document.createElement('summary');
  s.textContent = title;
  d.appendChild(s);
  for (const t of threads) d.appendChild(threadItem(t));
  side.appendChild(d);
}

// The header above the log: for an incident thread, the incident itself
// (as this person may see it) with Acknowledge / Resolve.
export async function renderHeader() {
  const box = document.getElementById('thread-header');
  const c = current();
  if (!c || c.kind !== 'incident') {
    box.style.display = 'none';
    box.innerHTML = '';
    const env = c && c.kind === 'environment';
    document.getElementById('chat-scope-note').textContent = env
      ? `${c.label}: tools reach only this environment.`
      : 'Everything: team coordination across environments. Pick an environment or an issue to work on targets.';
    return;
  }
  document.getElementById('chat-scope-note').textContent =
    `Issue thread in ${c.project} / ${c.environment}: questions here stay on this incident.`;
  const r = await api(`/api/incidents/${c.incident}`);
  if (state.chatConversation !== c.id) return;
  box.style.display = 'block';
  if (!r.ok) {
    box.innerHTML = '<div class="muted">This incident is no longer available.</div>';
    return;
  }
  const i = r.data;
  const sev = String(i.severity || '').toLowerCase();
  const st = String(i.state || '').toLowerCase();
  const when = (t) => (t ? new Date(t).toLocaleString() : null);
  const timeline = [
    `opened ${when(i.opened_at)}`,
    i.acked_at && `acknowledged ${when(i.acked_at)}`,
    i.reopened_at && `re-opened ${when(i.reopened_at)}`,
    i.accepted_at && `accepted as known ${when(i.accepted_at)}`,
    i.resolved_at && `resolved ${when(i.resolved_at)}`,
    i.notify_count ? `${i.notify_count} notification(s)` : null,
  ].filter(Boolean).join(' · ');
  const block = (label, text) => (text
    ? `<div class="th-block"><div class="th-label">${label}</div><div>${escapeHtml(text)}</div></div>`
    : '');
  box.innerHTML = `
    <div class="th-top">
      <span class="badge severity-${escapeHtml(sev)}">${escapeHtml(i.severity)}</span>
      <span class="badge state-${escapeHtml(st)}">${escapeHtml(i.state)}</span>
      ${i.accepted_at ? '<span class="badge state-accepted">known, left alone</span>' : ''}
      <strong>${escapeHtml(i.target)}</strong>
      <span class="muted">${escapeHtml(timeline)}</span>
    </div>
    ${block('Hypothesis', i.hypothesis)}
    ${block('Evidence', i.signals)}
    ${block('Recommended', i.recommended_action)}
    ${i.access && i.access.note ? `<div class="muted">${escapeHtml(i.access.note)}</div>` : ''}
    <div class="th-actions"></div>
    <div class="th-note muted"></div>`;
  const actions = box.querySelector('.th-actions');
  const note = box.querySelector('.th-note');
  const act = (label, verb, cls) => {
    const b = document.createElement('button');
    b.className = cls;
    b.textContent = label;
    b.addEventListener('click', async () => {
      b.disabled = true;
      const res = await api(`/api/incidents/${i.id}/${verb}`, 'POST');
      if (!res.ok) {
        note.textContent = (res.data && res.data.error) || 'Could not update the incident.';
        b.disabled = false;
        return;
      }
      await loadSidebar();
      await renderHeader();
      refreshIncidentCards();
    });
    actions.appendChild(b);
  };
  if (st === 'resolved') return;
  if (st === 'active' || st === 'expired') act('Acknowledge', 'ack', 'primary');
  if (i.accepted_at) act('Watch again', 'unaccept', 'ghost');
  else act('Known, leave it', 'accept', 'ghost');
  act('Resolve', 'resolve', 'ghost');
}

// The thread id for an incident event (`target` is `project::env::name…`).
export function threadIdFor(target, incidentId) {
  const parts = String(target || '').split('::');
  return parts.length >= 2 ? `${parts[0]}::${parts[1]}#${incidentId}` : null;
}
