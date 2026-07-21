// Incident list/detail with ack/resolve.
import { api, escapeHtml } from './api.js';

function severityBadge(sev) {
  return `<span class="badge severity-${sev}">${escapeHtml(sev)}</span>`;
}
function stateBadge(st) {
  return `<span class="badge state-${st}">${escapeHtml(st)}</span>`;
}

async function loadList() {
  const includeClosed = document.getElementById('incidents-include-closed').checked;
  const r = await api(`/api/incidents?include_closed=${includeClosed}&limit=50`);
  const list = document.getElementById('incidents-list');
  if (!r.ok) { list.innerHTML = `<p class="err">${escapeHtml(r.data.error || 'failed to load')}</p>`; return; }
  const incidents = r.data.incidents || [];
  if (incidents.length === 0) { list.innerHTML = '<p class="muted">No incidents.</p>'; return; }
  list.innerHTML = incidents.map((i) => `
    <div class="list-item" data-id="${i.id}">
      <div class="title">
        <strong>${escapeHtml(i.target)}</strong>
        <span>${escapeHtml(i.hypothesis)}</span>
      </div>
      ${severityBadge(i.severity)} ${stateBadge(i.state)}
    </div>
  `).join('');
  for (const el of list.querySelectorAll('.list-item')) {
    el.addEventListener('click', () => showDetail(el.dataset.id));
  }
}

async function showDetail(id) {
  const r = await api(`/api/incidents/${id}`);
  const box = document.getElementById('incident-detail');
  if (!r.ok) { box.style.display = 'none'; return; }
  const i = r.data;
  box.style.display = 'block';
  box.innerHTML = `
    <h3>${escapeHtml(i.target)} ${severityBadge(i.severity)} ${stateBadge(i.state)}</h3>
    <p>${escapeHtml(i.hypothesis)}</p>
    <p class="muted">${escapeHtml(i.signals || '')}</p>
    ${i.recommended_action ? `<p><strong>Recommended:</strong> ${escapeHtml(i.recommended_action)}</p>` : ''}
    <p class="muted">opened ${escapeHtml(i.opened_at)} · notified ${i.notify_count} time(s)</p>
    <div class="incident-actions">
      <button class="primary" id="incident-ack" ${i.state !== 'active' ? 'disabled' : ''}>Acknowledge</button>
      <button class="danger" id="incident-resolve" ${i.state === 'resolved' ? 'disabled' : ''}>Resolve</button>
    </div>
  `;
  box.querySelector('#incident-ack').addEventListener('click', async () => {
    await api(`/api/incidents/${id}/ack`, 'POST');
    await loadList();
    await showDetail(id);
  });
  box.querySelector('#incident-resolve').addEventListener('click', async () => {
    await api(`/api/incidents/${id}/resolve`, 'POST');
    await loadList();
    await showDetail(id);
  });
}

export function initIncidents() {
  document.getElementById('incidents-include-closed').addEventListener('change', loadList);
  document.addEventListener('opsclaw:view', (e) => { if (e.detail.name === 'incidents') loadList(); });
}
