// Invites, CLI sessions, and config.toml read/write.
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
  document.addEventListener('opsclaw:view', (e) => {
    if (e.detail.name === 'settings') { loadInvites(); loadCliTokens(); loadConfig(); }
  });
}
