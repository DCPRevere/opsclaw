// Entry module (loaded via <script type="module" src="/app/main.js">).
// Wires every surface's init function, boots the session check, and
// registers the service worker with an update-available banner — ported
// in shape from gianna's static/app/main.js.
import { checkSession, initAuth } from './auth.js';
import { switchView } from './state.js';
import { initChat, openStream, closeStream } from './chat.js';
import { initIncidents } from './incidents.js';
import { initApprovals } from './approvals.js';
import { initStatus } from './status.js';
import { initSettings } from './settings.js';

function initNav() {
  for (const btn of document.querySelectorAll('#nav button')) {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  }
}

document.addEventListener('opsclaw:view', (e) => {
  if (e.detail.name === 'chat') { openStream(); } else { /* stream stays open across views */ }
});

async function boot() {
  initNav();
  initAuth();
  initChat();
  initIncidents();
  initApprovals();
  initStatus();
  initSettings();
  await checkSession();
}

window.addEventListener('beforeunload', closeStream);

boot();

// ---- service worker registration + update banner ----

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').then((reg) => {
    reg.addEventListener('updatefound', () => {
      const installing = reg.installing;
      if (!installing) return;
      installing.addEventListener('statechange', () => {
        if (installing.state === 'installed' && navigator.serviceWorker.controller) {
          document.getElementById('reload-banner').classList.add('show');
        }
      });
    });
  }).catch(() => { /* PWA install/offline support is best-effort, never fatal */ });

  document.getElementById('reload-btn').addEventListener('click', () => {
    navigator.serviceWorker.getRegistration().then((reg) => {
      if (reg && reg.waiting) reg.waiting.postMessage('skipWaiting');
      location.reload();
    });
  });
}
