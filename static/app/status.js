// Status surface (heartbeat liveness, tick interval, e-stop) + the
// persistent e-stop banner (visible from every view, not just the status
// tab, since "nothing is executing" is the single most important thing an
// operator can know at a glance).
import { api, escapeHtml } from './api.js';

let pollTimer = null;

async function refresh() {
  const r = await api('/api/status');
  if (!r.ok) return;
  applyEstopBanner(r.data.estop_engaged);
  const box = document.getElementById('status-card');
  if (box) {
    box.innerHTML = `
      <h2>Daemon status</h2>
      <table>
        <tr><td>Version</td><td>${escapeHtml(r.data.version)}</td></tr>
        <tr><td>Mode</td><td>${r.data.fakes_mode ? 'fakes (no live credentials)' : 'live'}</td></tr>
        <tr><td>Heartbeat</td><td><span class="badge ${r.data.heartbeat === 'healthy' ? 'ok' : 'severity-critical'}">${escapeHtml(r.data.heartbeat)}</span></td></tr>
        <tr><td>Tick interval</td><td>${r.data.tick_interval_ms} ms</td></tr>
        <tr><td>Tick lag</td><td>${r.data.lag_ms === null ? '—' : r.data.lag_ms + ' ms'}</td></tr>
        <tr><td>E-stop</td><td>${r.data.estop_engaged ? 'ENGAGED' : 'clear'}</td></tr>
      </table>
      <div class="approval-actions">
        <button class="danger" id="estop-engage-btn" ${r.data.estop_engaged ? 'disabled' : ''}>Engage e-stop</button>
        <button class="primary" id="estop-resume-btn" ${!r.data.estop_engaged ? 'disabled' : ''}>Resume</button>
      </div>
    `;
    box.querySelector('#estop-engage-btn').addEventListener('click', engage);
    box.querySelector('#estop-resume-btn').addEventListener('click', resume);
  }
}

function applyEstopBanner(engaged) {
  document.getElementById('estop-banner').classList.toggle('show', !!engaged);
}

async function engage() {
  const reason = prompt('Reason for engaging the e-stop:') || '';
  const r = await api('/api/estop/engage', 'POST', { reason });
  if (!r.ok) { alert(r.data.error || 'Could not engage e-stop.'); return; }
  await refresh();
}

async function resume() {
  const r = await api('/api/estop/resume', 'POST');
  if (!r.ok) { alert(r.data.error || 'Could not resume.'); return; }
  await refresh();
}

export function initStatus() {
  document.getElementById('estop-resume-inline').addEventListener('click', resume);
  document.addEventListener('opsclaw:view', (e) => { if (e.detail.name === 'status') refresh(); });
  // Poll status every 15s regardless of the active view so the e-stop
  // banner stays live even while looking at chat/incidents/approvals.
  refresh();
  pollTimer = setInterval(refresh, 15000);
}

export function stopStatusPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}
