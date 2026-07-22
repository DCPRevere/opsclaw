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
import { renderMarkdown, asDate, fmtTime } from './format.js';

let evtSource = null;
let streamConnecting = false;
let streamBackoff = 2000;
let streamRetryTimer = null;
let pendingRow = null;

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
    addMsg({ role: 'assistant', content: ev.body && ev.body.text ? ev.body.text : JSON.stringify(ev.body) });
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
    if (body.role === 'assistant') clearPending();
    addMsg({ role: body.role || 'assistant', speaker: body.speaker, content: body.text || '' });
    if (body.role !== 'assistant' && pendingRow) {
      // Keep the thinking row anchored at the bottom while tool rows stream in.
      pendingRow.parentNode.appendChild(pendingRow);
      pendingRow.parentNode.scrollTop = pendingRow.parentNode.scrollHeight;
    }
  });
  evtSource.onerror = () => {
    evtSource.close();
    evtSource = null;
    scheduleReconnect();
  };
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

// One message row. `m`: { role: 'user'|'assistant'|'tool', speaker, content, at }.
// Tool rows render as a single collapsed activity line (name + args,
// expandable); user/assistant get bubbles with meta (speaker, time, Copy,
// Reply). Assistant content goes through renderMarkdown (escape-first —
// never raw model HTML); user content is escaped plain text.
function addMsg(m) {
  const log = document.getElementById('chat-log');
  if (m.role === 'tool') {
    const row = document.createElement('details');
    row.className = 'toolrow';
    const sum = document.createElement('summary');
    sum.innerHTML = `<span class="toolglyph">⚙</span> <code>${escapeHtml(m.speaker || 'tool')}</code>`;
    const args = document.createElement('pre');
    args.textContent = m.content;
    row.appendChild(sum);
    row.appendChild(args);
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
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
  log.scrollTop = log.scrollHeight;
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
  const r = await api('/api/chat/history');
  if (!r.ok) return;
  const log = document.getElementById('chat-log');
  log.innerHTML = '';
  for (const m of r.data.history || []) addMsg(m);
}

export function initChat() {
  const input = document.getElementById('chat-input');
  const form = document.getElementById('chat-form');
  const submitBtn = form.querySelector('button[type=submit]');

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
    input.value = '';
    input.disabled = true;
    submitBtn.disabled = true;
    showPending();
    try {
      const r = await api('/api/chat', 'POST', { message });
      if (!r.ok) {
        clearPending();
        showError(r.data.error || 'The chat turn failed — please try again.');
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
