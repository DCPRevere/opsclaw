// Invites, CLI sessions, web push, and config.toml read/write.
import { api, escapeHtml } from './api.js';

async function loadInvites() {
  const r = await api('/api/invites');
  const box = document.getElementById('invites-list');
  if (!r.ok) { box.innerHTML = ''; return; }
  const invites = r.data.invites || [];
  box.innerHTML = invites.length === 0 ? '<p class="muted">No open invites.</p>' : invites.map((i) => `
    <div class="list-item" data-code="${escapeHtml(i.code)}">
      <div class="title"><strong>${escapeHtml(i.code)}</strong><span>expires ${escapeHtml(i.expires_at)}</span></div>
      <button class="ghost" data-action="revoke">Revoke</button>
    </div>
  `).join('');
  for (const el of box.querySelectorAll('[data-code]')) {
    el.querySelector('[data-action=revoke]').addEventListener('click', async () => {
      await api(`/api/invites/${encodeURIComponent(el.dataset.code)}`, 'DELETE');
      await loadInvites();
    });
  }
}

async function loadCliTokens() {
  const r = await api('/api/cli-tokens');
  const box = document.getElementById('cli-tokens-list');
  if (!r.ok) { box.innerHTML = ''; return; }
  const tokens = r.data.tokens || [];
  box.innerHTML = tokens.length === 0 ? '<p class="muted">No CLI sessions.</p>' : tokens.map((t) => `
    <div class="list-item" data-id="${t.id}">
      <div class="title"><strong>${escapeHtml(t.name)}</strong><span>created ${escapeHtml(t.created_at)}${t.last_used_at ? ' · last used ' + escapeHtml(t.last_used_at) : ''}</span></div>
      <button class="ghost" data-action="revoke">Revoke</button>
    </div>
  `).join('');
  for (const el of box.querySelectorAll('[data-id]')) {
    el.querySelector('[data-action=revoke]').addEventListener('click', async () => {
      await api(`/api/cli-tokens/${el.dataset.id}`, 'DELETE');
      await loadCliTokens();
    });
  }
}

async function loadConfig() {
  const r = await api('/api/config');
  const box = document.getElementById('config-toml');
  const err = document.getElementById('config-err');
  err.textContent = '';
  if (!r.ok) { err.textContent = r.data.error || 'Could not load config.'; return; }
  box.value = r.data.toml;
}

async function saveConfig() {
  const err = document.getElementById('config-err');
  err.textContent = '';
  const toml = document.getElementById('config-toml').value;
  const r = await api('/api/config', 'POST', { toml });
  if (!r.ok) { err.textContent = r.data.error || 'Could not save config.'; return; }
  err.textContent = r.data.note || 'Saved.';
  err.classList.remove('err');
  err.classList.add('muted');
}

// ---- Web push subscribe/unsubscribe ----
//
// DESIGN §4 HTTP gateway (PWA/push paragraphs): request Notification
// permission, subscribe the service worker's pushManager with the
// daemon's VAPID public key, and hand the resulting PushSubscription to
// POST /api/push/subscribe. Feature-detects: a browser with no
// serviceWorker/PushManager (or a daemon with no VAPID key configured —
// GET /api/push/vapid-public-key 404s) simply never shows the card, rather
// than presenting a button that can't work.

function base64UrlToUint8Array(base64Url) {
  const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function pushSupported() {
  return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

async function currentPushSubscription() {
  const reg = await navigator.serviceWorker.ready;
  return reg.pushManager.getSubscription();
}

async function refreshPushUi() {
  const card = document.getElementById('push-card');
  const enableBtn = document.getElementById('push-enable-btn');
  const disableBtn = document.getElementById('push-disable-btn');
  const status = document.getElementById('push-status');
  if (!pushSupported()) { card.style.display = 'none'; return; }

  const vapid = await api('/api/push/vapid-public-key');
  if (!vapid.ok) { card.style.display = 'none'; return; } // not configured on this daemon

  card.style.display = '';
  const sub = await currentPushSubscription();
  const subscribed = !!sub;
  enableBtn.style.display = subscribed ? 'none' : '';
  disableBtn.style.display = subscribed ? '' : 'none';
  status.textContent = subscribed ? 'Notifications are enabled on this device.' : '';
}

async function enablePush() {
  const status = document.getElementById('push-status');
  status.textContent = '';
  if (Notification.permission === 'denied') {
    status.textContent = 'Notifications are blocked for this site in your browser settings.';
    return;
  }
  const permission = await Notification.requestPermission();
  if (permission !== 'granted') {
    status.textContent = 'Permission was not granted.';
    return;
  }
  const vapid = await api('/api/push/vapid-public-key');
  if (!vapid.ok) { status.textContent = 'Push is not configured on this daemon.'; return; }

  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: base64UrlToUint8Array(vapid.data.vapid_public_key),
  });
  const json = sub.toJSON();
  const r = await api('/api/push/subscribe', 'POST', { endpoint: json.endpoint, keys: json.keys });
  if (!r.ok) { status.textContent = r.data.error || 'Could not save subscription.'; return; }
  await refreshPushUi();
}

async function disablePush() {
  const status = document.getElementById('push-status');
  status.textContent = '';
  const sub = await currentPushSubscription();
  if (sub) {
    await api('/api/push/unsubscribe', 'POST', { endpoint: sub.endpoint });
    await sub.unsubscribe();
  }
  await refreshPushUi();
}

export function initSettings() {
  document.getElementById('create-invite-btn').addEventListener('click', async () => {
    const r = await api('/api/invites', 'POST');
    const box = document.getElementById('new-invite-code');
    if (!r.ok) { box.textContent = r.data.error || 'Could not create invite.'; return; }
    box.textContent = `Share this code: ${r.data.code} (expires ${r.data.expires_at})`;
    await loadInvites();
  });
  document.getElementById('config-save-btn').addEventListener('click', saveConfig);
  document.getElementById('config-reload-btn').addEventListener('click', loadConfig);
  document.getElementById('push-enable-btn').addEventListener('click', enablePush);
  document.getElementById('push-disable-btn').addEventListener('click', disablePush);
  document.addEventListener('opsclaw:view', (e) => {
    if (e.detail.name === 'settings') { loadInvites(); loadCliTokens(); loadConfig(); refreshPushUi(); }
  });
}
