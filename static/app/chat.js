// Chat surface + SSE proactive push — ported from gianna's static/app/
// chat.js: fetch a short-lived stream ticket (never the long-lived session
// token — it would land in access logs via the query string, see
// http::sse's module doc), then connect EventSource with it. Native
// EventSource auto-reconnect is avoided deliberately: a reconnect would
// replay the now-expired/used ticket, so reconnection is manual with
// capped exponential backoff, fetching a FRESH ticket each time.
//
// Render-source design call: chat messages render from the SSE `chat`
// event ONLY, never a second time from the POST response body — the
// gateway broadcasts the operator's message, the agent's LIVE TOOL CALLS
// (role "tool", published mid-turn by ChatTurn), and the reply to every
// connected tab including the sender's own. A pending "…thinking" row
// gives the sender immediate feedback without a second render path.
//
// Message affordances (gianna's copy button + selection-with-attribution,
// plus opsclaw's own reply-quote): each bubble gets hover-revealed Copy and
// Reply buttons; selecting across multiple bubbles copies a speaker-
// labelled transcript. Assistant text renders through format.js's
// escape-first markdown (never raw model HTML); user text stays plain.
import { api, escapeHtml } from './api.js';
import { state } from './state.js';
import { renderMarkdown, asDate, fmtTime, dayKey, dayLabel } from './format.js';
import { initThreads, loadSidebar, renderHeader, threadIdFor } from './threads.js';

let evtSource = null;
let streamConnecting = false;
let streamBackoff = 2000;
let streamRetryTimer = null;
let pendingRow = null;
let pendingTurnId = null;
// A transport failure does not tell us whether the daemon accepted the POST.
// Preserve that exact request key for an explicit retry; changing it could
// execute a second turn after the first already acted.
let uncertainSend = null;
// Day-separator tracking (gianna's WhatsApp-style pills): the local
// calendar day of the last rendered row; reset whenever the log reloads.
let lastMsgDay = null;
// The `seq` of the oldest history row on screen — the anchor "Show
// earlier" pages backward from (null until history loads, or when empty).
let oldestSeq = null;

function scheduleReconnect() {
  if (streamRetryTimer) return;
  streamRetryTimer = setTimeout(() => { streamRetryTimer = null; openStream(); }, streamBackoff);
  streamBackoff = Math.min(streamBackoff * 2, 30000);
}

export async function openStream() {
  if (evtSource || streamConnecting || !state.signedIn) return;
  streamConnecting = true;
  let t;
  try { t = await api('/api/stream-ticket'); } catch (_) { t = null; }
  streamConnecting = false;
  if (!t || !t.ok) { scheduleReconnect(); return; }
  if (evtSource) return; // another call won the race while we awaited
  streamBackoff = 2000;
  evtSource = new EventSource('/api/stream?token=' + encodeURIComponent(t.data.ticket));
  evtSource.addEventListener('message', (e) => {
    let ev = {};
    try { ev = JSON.parse(e.data); } catch (_) { return; }
    if (state.chatConversation === 'operations') {
      addMsg({ role: 'assistant', content: ev.body && ev.body.text ? ev.body.text : JSON.stringify(ev.body) });
    }
  });
  // Chat-kind events (`channels::web::WebEvent::chat`): every operator's
  // message, every mid-turn tool call, and every reply arrives here,
  // including this tab's own. Only an ASSISTANT reply clears this tab's own
  // pending row — a `user` event can be another operator's concurrent
  // message and a `tool` event means the turn is still running (the
  // pending row stays below the streaming tool rows).
  evtSource.addEventListener('chat', (e) => {
    let ev = {};
    try { ev = JSON.parse(e.data); } catch (_) { return; }
    const body = ev.body || {};
    if (body.conversation !== state.chatConversation) return;
    // A tool's result landing annotates the ⚙ row already on screen — it
    // is not a new row of its own.
    if (body.role === 'tool_status') { annotateToolStatus(body.speaker, body.text === 'ok'); return; }
    if (body.role === 'assistant' && body.turn_id === pendingTurnId) clearPending();
    addMsg({ role: body.role || 'assistant', speaker: body.speaker, content: body.text || '' });
    if (body.role !== 'assistant' && pendingRow) {
      // Keep the thinking row anchored at the bottom while tool rows stream in.
      pendingRow.parentNode.appendChild(pendingRow);
      pendingRow.parentNode.scrollTop = pendingRow.parentNode.scrollHeight;
    }
  });
  // Structured announcements (channels::web maps OutboundMessage.meta):
  // an approval or an incident page renders as an ACTIONABLE card in the
  // chat log — the buttons drive the same endpoints as the dedicated tabs,
  // so acting from chat and acting from the tab are the same operation.
  evtSource.addEventListener('approval', (e) => {
    let ev = {};
    try { ev = JSON.parse(e.data); } catch (_) { return; }
    const body = ev.body || {};
    if ((body.conversation || 'operations') === state.chatConversation) addApprovalCard(body);
  });
  evtSource.addEventListener('incident', (e) => {
    let ev = {};
    try { ev = JSON.parse(e.data); } catch (_) { return; }
    const body = ev.body || {};
    // A new or re-sent page: its thread may be new, so refresh the sidebar.
    loadSidebar();
    if ((body.conversation || 'operations') === state.chatConversation) addIncidentCard(body);
  });
  evtSource.onerror = () => {
    evtSource.close();
    evtSource = null;
    scheduleReconnect();
  };
}

// A chat reply is rendered from SSE, not the POST body. Do not submit until
// EventSource is actually open: immediately sending after login could publish
// both the user row and reply before this tab had joined the hub, leaving its
// local "thinking" row stuck forever.
async function ensureStreamOpen() {
  await openStream();
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (evtSource && evtSource.readyState === EventSource.OPEN) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return false;
}

// Shared card scaffolding for actionable announcements. `decide` runs the
// clicked action with every button disabled; failure re-enables them and
// surfaces the server's error text (a 409 here usually means someone else
// decided first — the note says so rather than pretending success).
function actionCard(className, headHtml, bodyLines) {
  const log = document.getElementById('chat-log');
  const card = document.createElement('div');
  card.className = 'actioncard ' + className;
  const head = document.createElement('div');
  head.className = 'ac-head';
  head.innerHTML = headHtml;
  card.appendChild(head);
  for (const el of bodyLines) card.appendChild(el);
  const actions = document.createElement('div');
  actions.className = 'ac-actions';
  const note = document.createElement('div');
  note.className = 'ac-note muted';
  card.appendChild(actions);
  card.appendChild(note);
  log.appendChild(card);
  log.scrollTop = log.scrollHeight;
  return { card, actions, note };
}

function line(cls, text) {
  const d = document.createElement('div');
  d.className = cls;
  d.textContent = text;
  return d;
}

// A target arrives as `project::env::target` (older events carried the
// structured form; render that too rather than "[object Object]").
function targetText(t) {
  if (!t) return '';
  if (typeof t === 'string') return t;
  const base = [t.project, t.env, t.target].filter(Boolean).join('::');
  return t.resource ? `${base}::${[].concat(t.resource).join('::')}` : base;
}

function addApprovalCard(a) {
  const cmd = document.createElement('code');
  cmd.className = 'ac-cmd';
  cmd.textContent = a.command || '';
  const rows = [cmd, line('ac-line', `${a.tool || ''} on ${targetText(a.target)}`)];
  if (a.hypothesis) rows.push(line('ac-line muted', a.hypothesis));
  const { card, actions, note } = actionCard(
    'approval',
    `Approval needed <span class="badge">${escapeHtml(a.risk || '')}</span>`,
    rows,
  );
  const decide = async (verb) => {
    actions.querySelectorAll('button').forEach((b) => { b.disabled = true; });
    const r = await api(`/api/approvals/${a.id}/${verb}`, 'POST');
    if (r.ok) {
      note.textContent = verb === 'approve' ? 'Approved — the command will now execute.' : 'Denied.';
      card.classList.add('decided');
    } else {
      note.textContent = (r.data && r.data.error) || 'Could not record the decision — see the Approvals tab.';
      actions.querySelectorAll('button').forEach((b) => { b.disabled = false; });
    }
  };
  const ap = document.createElement('button');
  ap.className = 'primary';
  ap.textContent = 'Approve';
  ap.addEventListener('click', () => decide('approve'));
  const dn = document.createElement('button');
  dn.className = 'danger';
  dn.textContent = 'Deny';
  dn.addEventListener('click', () => decide('deny'));
  actions.append(ap, dn);
}

function addIncidentCard(i) {
  const rows = [line('ac-line', targetText(i.target))];
  if (i.hypothesis) rows.push(line('ac-line muted', i.hypothesis));
  const { card, actions, note } = actionCard(
    'incident',
    `Incident <span class="badge">${escapeHtml(i.severity || '')}</span>`,
    rows,
  );
  const thread = threadIdFor(targetText(i.target), i.id);
  if (thread) {
    const open = document.createElement('button');
    open.className = 'ghost';
    open.textContent = 'Open thread';
    open.addEventListener('click', () => {
      state.chatConversation = thread;
      uncertainSend = null;
      clearPending();
      loadHistory();
    });
    actions.appendChild(open);
  }
  const ack = document.createElement('button');
  ack.className = 'primary';
  ack.textContent = 'Acknowledge';
  ack.addEventListener('click', async () => {
    ack.disabled = true;
    const r = await api(`/api/incidents/${i.id}/ack`, 'POST');
    if (r.ok) {
      note.textContent = 'Acknowledged — paging stops; details in the Incidents tab.';
      card.classList.add('decided');
    } else {
      note.textContent = (r.data && r.data.error) || 'Could not acknowledge — see the Incidents tab.';
      ack.disabled = false;
    }
  });
  actions.append(ack);
}

export function closeStream() {
  if (evtSource) { evtSource.close(); evtSource = null; }
  if (streamRetryTimer) { clearTimeout(streamRetryTimer); streamRetryTimer = null; }
}

// Write `text` to the clipboard: async API in secure contexts, hidden-
// textarea fallback otherwise (gianna's copyText).
function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text).catch(() => {});
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (_) {}
  ta.remove();
  return Promise.resolve();
}

function metaButton(label, title, onClick) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'msgbtn';
  b.textContent = label;
  b.title = title;
  b.setAttribute('aria-label', title);
  b.addEventListener('click', onClick);
  return b;
}

// Insert a centered date pill into `host` when `d` falls on a new local
// calendar day relative to the last rendered row (gianna's maybeDaySep).
function maybeDaySep(d, host) {
  const key = dayKey(d);
  if (key === lastMsgDay) return;
  lastMsgDay = key;
  const sep = document.createElement('div');
  sep.className = 'daysep';
  sep.textContent = dayLabel(d);
  sep.setAttribute('role', 'separator');
  host.appendChild(sep);
}

// Append a ✓/✗ outcome glyph to a ⚙ row's summary line, at most once.
function markToolRow(row, ok) {
  row.dataset.status = ok ? 'ok' : 'error';
  const glyph = document.createElement('span');
  glyph.className = 'toolstatus ' + row.dataset.status;
  glyph.textContent = ok ? ' ✓' : ' ✗';
  row.querySelector('summary').appendChild(glyph);
}

// A live `tool_status` event: annotate the LAST un-annotated ⚙ row for
// this tool name (calls run sequentially inside a turn, so that row is the
// one whose result just landed).
function annotateToolStatus(name, ok) {
  const rows = document.querySelectorAll('#chat-log .toolrow');
  for (let i = rows.length - 1; i >= 0; i--) {
    if (rows[i].dataset.tool === name && !rows[i].dataset.status) {
      markToolRow(rows[i], ok);
      return;
    }
  }
}

// One message row. `m`: { role: 'user'|'assistant'|'tool', speaker, content, at }.
// Tool rows render as a single collapsed activity line (name + args,
// expandable); user/assistant get bubbles with meta (speaker, time, Copy,
// Reply). Assistant content goes through renderMarkdown (escape-first —
// never raw model HTML); user content is escaped plain text. `into` lets
// the older-page loader build into a DocumentFragment — that path owns its
// own scroll handling, so appends there never touch scrollTop.
function addMsg(m, into) {
  const log = into || document.getElementById('chat-log');
  maybeDaySep(asDate(m.at), log);
  if (m.role === 'tool') {
    const row = document.createElement('details');
    row.className = 'toolrow';
    row.dataset.tool = m.speaker || 'tool';
    // Persisted rows carry their outcome as a content suffix (ChatTurn
    // folds it in after the turn); a live row arrives un-suffixed and gets
    // its glyph from the later tool_status event instead.
    let args = m.content;
    let done = null;
    if (args.endsWith(' → ok')) { done = true; args = args.slice(0, -' → ok'.length); }
    else if (args.endsWith(' → error')) { done = false; args = args.slice(0, -' → error'.length); }
    const sum = document.createElement('summary');
    sum.innerHTML = `<span class="toolglyph">⚙</span> <code>${escapeHtml(m.speaker || 'tool')}</code>`;
    const pre = document.createElement('pre');
    pre.textContent = args;
    row.appendChild(sum);
    row.appendChild(pre);
    if (done !== null) markToolRow(row, done);
    log.appendChild(row);
    if (!into) log.scrollTop = log.scrollHeight;
    return;
  }

  const wrap = document.createElement('div');
  const mine = m.role !== 'assistant';
  wrap.className = 'msgwrap' + (mine ? ' out' : '');

  const bubble = document.createElement('div');
  bubble.className = 'msg' + (mine ? ' out' : '');
  bubble.dataset.speaker = m.speaker || (mine ? 'operator' : 'opsclaw');
  bubble.innerHTML = mine ? escapeHtml(m.content) : renderMarkdown(m.content);

  const meta = document.createElement('div');
  meta.className = 'msgmeta';
  const time = document.createElement('span');
  time.className = 'msgtime';
  const d = asDate(m.at);
  time.textContent = (m.speaker && mine ? m.speaker + ' · ' : '') + fmtTime(d);
  time.title = d.toISOString();
  meta.appendChild(time);
  meta.appendChild(metaButton('⧉', 'Copy message', (e) => {
    copyText(bubble.innerText.trim()).then(() => {
      e.target.textContent = '✓';
      setTimeout(() => { e.target.textContent = '⧉'; }, 1400);
    });
  }));
  meta.appendChild(metaButton('↩', 'Reply (quote into input)', () => {
    const input = document.getElementById('chat-input');
    const quoted = bubble.innerText.trim().split('\n').map((l) => '> ' + l).join('\n');
    input.value = quoted + '\n\n' + input.value;
    input.focus();
  }));

  wrap.appendChild(bubble);
  wrap.appendChild(meta);
  log.appendChild(wrap);
  if (!into) log.scrollTop = log.scrollHeight;
}

function showPending() {
  clearPending();
  const log = document.getElementById('chat-log');
  const div = document.createElement('div');
  div.className = 'msg pending muted';
  div.textContent = 'thinking…';
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  pendingRow = div;
}

function clearPending() {
  if (pendingRow) { pendingRow.remove(); pendingRow = null; }
  pendingTurnId = null;
}

function showError(text) {
  const log = document.getElementById('chat-log');
  const div = document.createElement('div');
  div.className = 'msg err';
  div.textContent = text;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

// Render the durable shared transcript (GET /api/chat/history — migration
// 0007, survives restarts and includes tool rows). Called from main.js on
// every 'opsclaw:view' -> 'chat' transition. Best-effort: a failed/empty
// history just leaves the log as-is.
export async function loadHistory() {
  await loadSidebar();
  updateScopeNote();
  renderHeader();
  const conversation = state.chatConversation;
  const r = await api('/api/chat/history?conversation=' + encodeURIComponent(conversation));
  if (!r.ok) return;
  if (conversation !== state.chatConversation) return;
  const log = document.getElementById('chat-log');
  log.innerHTML = '';
  lastMsgDay = null;
  const rows = r.data.history || [];
  oldestSeq = rows.length ? rows[0].seq : null;
  earlierButton(!!r.data.has_more);
  for (const m of rows) addMsg(m);
}

// Paged history (gianna's "show earlier"): a button above the log that
// prepends the previous page — the whole archive is reachable, page by page.
function earlierButton(show) {
  const old = document.getElementById('chat-earlier');
  if (old) old.remove();
  if (!show) return;
  const b = document.createElement('button');
  b.type = 'button';
  b.id = 'chat-earlier';
  b.className = 'ghost';
  b.textContent = 'Show earlier';
  b.addEventListener('click', loadEarlier);
  document.getElementById('chat-log').prepend(b);
}

async function loadEarlier() {
  if (oldestSeq == null) return;
  const conversation = state.chatConversation;
  const r = await api('/api/chat/history?conversation=' + encodeURIComponent(conversation)
    + '&before=' + encodeURIComponent(oldestSeq));
  if (!r.ok || !Array.isArray(r.data.history)) return;
  if (conversation !== state.chatConversation) return;
  const ms = r.data.history;
  if (ms.length) oldestSeq = ms[0].seq;
  const log = document.getElementById('chat-log');
  const anchor = log.children[1]; // first real row (after the button)
  earlierButton(!!r.data.has_more);
  // The older page is EARLIER than what's on screen, so it gets its own
  // day tracking (oldest→newest within the page); save/restore the live
  // tracker so the prepend doesn't disturb separators already rendered.
  const frag = document.createDocumentFragment();
  const liveDay = lastMsgDay;
  lastMsgDay = null;
  for (const m of ms) addMsg(m, frag);
  lastMsgDay = liveDay;
  const btn = document.getElementById('chat-earlier');
  if (btn) btn.after(frag); else log.prepend(frag);
  // Restore the viewport to the row that was at the top before the prepend.
  if (anchor) anchor.scrollIntoView({ block: 'start' });
}

export function initChat() {
  const input = document.getElementById('chat-input');
  const form = document.getElementById('chat-form');
  const submitBtn = form.querySelector('button[type=submit]');
  initThreads(() => {
    uncertainSend = null;
    clearPending();
    loadHistory();
  });

  // Selection copy with attribution (gianna): selecting across two or more
  // bubbles copies "Speaker:\ntext" blocks instead of the raw concatenation.
  document.addEventListener('copy', (e) => {
    const sel = document.getSelection();
    if (!sel || sel.isCollapsed || sel.rangeCount === 0) return;
    const range = sel.getRangeAt(0);
    const bubbles = [...document.querySelectorAll('#chat-log .msg')]
      .filter((b) => range.intersectsNode(b));
    if (bubbles.length < 2) return; // single bubble: browser default is right
    e.preventDefault();
    const parts = bubbles.map((b) => `${b.dataset.speaker || ''}:\n${b.innerText.trim()}`);
    e.clipboardData.setData('text/plain', parts.join('\n\n'));
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const message = input.value.trim();
    if (!message) return;
    input.disabled = true;
    submitBtn.disabled = true;
    try {
      if (!(await ensureStreamOpen())) {
        showError('The live chat connection is not ready — try again.');
        return;
      }
      input.value = '';
      showPending();
      const idempotencyKey = uncertainSend && uncertainSend.message === message
        && uncertainSend.conversation === state.chatConversation
        ? uncertainSend.key
        : ((globalThis.crypto && crypto.randomUUID)
          ? crypto.randomUUID()
          : `${Date.now()}-${Math.random().toString(36).slice(2)}`);
      pendingTurnId = idempotencyKey;
      const r = await api('/api/chat', 'POST', {
        message,
        conversation: state.chatConversation,
        idempotency_key: idempotencyKey,
      });
      if (!r.ok) {
        clearPending();
        const stillRunning = r.status === 409 && String(r.data.error || '').includes('already in progress');
        if (r.status === 0 || stillRunning) {
          uncertainSend = { message, key: idempotencyKey, conversation: state.chatConversation };
          input.value = message;
          showError(stillRunning
            ? 'That request is still running — wait, then retry to retrieve its reply.'
            : 'Delivery is uncertain — retrying this message will safely reuse its request key.');
        } else {
          uncertainSend = null;
          showError(r.data.error || 'The chat turn failed — please try again.');
        }
      } else {
        uncertainSend = null;
        // A completed replay is not broadcast again over SSE. Render the
        // stored response returned by the idempotency record in this tab.
        if (r.data.duplicate && r.data.reply) {
          clearPending();
          addMsg({ role: 'assistant', speaker: 'assistant', content: r.data.reply });
        }
      }
      // On success the reply (and the echo of this message, and the tool
      // rows) arrive via the SSE `chat` event — see the module doc.
    } finally {
      input.disabled = false;
      submitBtn.disabled = false;
      input.focus();
    }
  });
}

function updateScopeNote() {
  const id = state.chatConversation;
  const input = document.getElementById('chat-input');
  if (id === 'operations') input.placeholder = 'Ask the agent…';
  else if (id.includes('#')) input.placeholder = 'Ask about this issue…';
  else input.placeholder = `Ask about ${id.replace('::', ' / ')}…`;
}
