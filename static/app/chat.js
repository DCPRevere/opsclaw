// Chat surface + SSE proactive push — ported from gianna's static/app/
// chat.js: fetch a short-lived stream ticket (never the long-lived session
// token — it would land in access logs via the query string, see
// http::sse's module doc), then connect EventSource with it. Native
// EventSource auto-reconnect is avoided deliberately: a reconnect would
// replay the now-expired/used ticket, so reconnection is manual with
// capped exponential backoff, fetching a FRESH ticket each time.
import { api, escapeHtml } from './api.js';
import { state } from './state.js';

let evtSource = null;
let streamConnecting = false;
let streamBackoff = 2000;
let streamRetryTimer = null;

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

function addMsg(text, dir) {
  const log = document.getElementById('chat-log');
  const div = document.createElement('div');
  div.className = 'msg' + (dir === 'out' ? ' out' : '');
  div.innerHTML = escapeHtml(text);
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

export function initChat() {
  // There is no POST /api/chat yet — a chat TURN is agent-loop-backed
  // (a later task, see http/mod.rs's module doc), where this SSE stream
  // (proactive push from scan jobs/incidents/approvals) already works
  // end-to-end today. The input is disabled with an honest placeholder
  // rather than silently swallowing a submitted message.
  const input = document.getElementById('chat-input');
  const form = document.getElementById('chat-form');
  const submitBtn = form.querySelector('button[type=submit]');
  input.disabled = true;
  submitBtn.disabled = true;
  input.placeholder = 'Chat turns land in a later task — this stream already shows proactive alerts.';
  form.addEventListener('submit', (e) => e.preventDefault());
}
