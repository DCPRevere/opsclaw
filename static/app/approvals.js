// Approval queue with approve/deny — the mobile-first surface (DESIGN §5:
// "decidable from a phone"). Every field a human needs to decide is on the
// row already: exact command, target, risk, hypothesis.
import { api, escapeHtml } from './api.js';

async function loadList() {
  const r = await api('/api/approvals');
  const list = document.getElementById('approvals-list');
  if (!r.ok) { list.innerHTML = `<p class="err">${escapeHtml(r.data.error || 'failed to load')}</p>`; return; }
  const approvals = r.data.approvals || [];
  if (approvals.length === 0) { list.innerHTML = '<p class="muted">No pending approvals.</p>'; return; }
  list.innerHTML = approvals.map((a) => `
    <div class="card" data-id="${a.id}">
      <div><span class="badge severity-${riskClass(a.risk)}">${escapeHtml(a.risk)}</span> ${escapeHtml(a.target)} · ${escapeHtml(a.tool)}</div>
      <code class="cmd">${escapeHtml(a.command)}</code>
      <p class="muted">${escapeHtml(a.hypothesis)}</p>
      <p class="muted">expires ${escapeHtml(a.expires_at)}</p>
      <div class="approval-actions">
        <button class="primary" data-action="approve">Approve</button>
        <button class="danger" data-action="deny">Deny</button>
      </div>
    </div>
  `).join('');
  for (const card of list.querySelectorAll('[data-id]')) {
    const id = card.dataset.id;
    card.querySelector('[data-action=approve]').addEventListener('click', () => decide(id, 'approve'));
    card.querySelector('[data-action=deny]').addEventListener('click', () => decide(id, 'deny'));
  }
}

function riskClass(risk) {
  if (risk === 'destructive' || risk === 'high') return 'critical';
  if (risk === 'medium') return 'warning';
  return 'info';
}

async function decide(id, action) {
  const r = await api(`/api/approvals/${id}/${action}`, 'POST');
  if (!r.ok) { alert(r.data.error || 'Could not record the decision.'); return; }
  await loadList();
}

export function initApprovals() {
  document.addEventListener('opsclaw:view', (e) => { if (e.detail.name === 'approvals') loadList(); });
}
