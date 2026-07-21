// Chat surface + SSE proactive push — ported from gianna's static/app/
// chat.js: fetch a short-lived stream ticket (never the long-lived session
// token — it would land in access logs via the query string, see
// http::sse's module doc), then connect EventSource with it. Native
// EventSource auto-reconnect is avoided deliberately: a reconnect would
// replay the now-expired/used ticket, so reconnection is manual with
// capped exponential backoff, fetching a FRESH ticket each time.
//
// POST /api/chat + GET /api/chat/history land the real chat turn (the
// input used to be disabled with an honest "not wired yet" placeholder —
// see git history — now that `state.chat` is wired to the real agent
// loop end to end).
//
// Render-source design call: chat messages render from the SSE `chat`
// event ONLY, never a second time from the POST response body — the
// gateway broadcasts BOTH the operator's own message and the reply to
// every connected tab (`http::routes::chat`'s module doc: "web chat is a
// team surface, one shared conversation"), including the sender's own tab.
// Rendering from the POST response too would double the sender's own
// message in their own log; a pending "…thinking" row is used instead so
// the sender gets immediate feedback without a second render path to keep
// in sync with the SSE one.
import { api, escapeHtml } from './api.js';
import { state } from './state.js';

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
    addMsg(ev.body && ev.body.text ? ev.body.text : JSON.stringify(ev.body), 'in');
  });
  // Chat-kind events (`channels::web::WebEvent::chat`): every operator's
  // message and every reply arrives here, including this tab's own —
  // see the module doc above for why that's the ONLY render path. Only an
  // ASSISTANT reply clears this tab's own pending row — a `user` event can
  // be another operator's concurrent message (DESIGN: shared team chat),
  // which must not swallow this tab's own in-flight "thinking…" indicator.
  evtSource.addEventListener('chat', (e) => {
    let ev = {};
    try { ev = JSON.parse(e.data); } catch (_) { return; }
    const body = ev.body || {};
    if (body.role === 'assistant') clearPending();
    addMsg(body.text || '', body.role === 'assistant' ? 'in' : 'out', body.speaker);
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

function addMsg(text, dir, speaker) {
  const log = document.getElementById('chat-log');
  const div = document.createElement('div');
  div.className = 'msg' + (dir === 'out' ? ' out' : '');
  div.innerHTML = speaker && dir === 'out'
    ? `<strong>${escapeHtml(speaker)}:</strong> ${escapeHtml(text)}`
    : escapeHtml(text);
  log.appendChild(div);
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

// Render the shared transcript (GET /api/chat/history) — a signed-in
// operator opening the chat view sees the team's prior conversation, not a
// blank log (the transcript is in-memory server-side and shared across
// every surface, agent::dispatch::ChatTurn's own doc). Called from
// main.js on every 'opsclaw:view' -> 'chat' transition (covers first
// sign-in, since enterApp() lands on the chat view, and every later
// switch back to it) rather than once at boot, since boot happens before
// the session check resolves. Best-effort: a failed/empty history just
// leaves the log as-is.
export async function loadHistory() {
  const r = await api('/api/chat/history');
  if (!r.ok) return;
  const log = document.getElementById('chat-log');
  log.innerHTML = '';
  for (const turn of r.data.history || []) {
    addMsg(turn.content, turn.role === 'assistant' ? 'in' : 'out');
  }
}

export function initChat() {
  const input = document.getElementById('chat-input');
  const form = document.getElementById('chat-form');
  const submitBtn = form.querySelector('button[type=submit]');

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
      // On success the reply (and the echo of this message) arrive via the
      // SSE `chat` event, which also clears the pending row — see the
      // module doc for why nothing renders here directly.
    } finally {
      input.disabled = false;
      submitBtn.disabled = false;
      input.focus();
    }
  });
}
