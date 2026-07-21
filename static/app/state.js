// Tiny shared UI state + view-switching — no framework, direct DOM
// manipulation (gianna's static/app/state.js pattern).
export const state = { signedIn: false };

export function showAuth() {
  state.signedIn = false;
  document.getElementById('nav').style.display = 'none';
  document.getElementById('logout-btn').style.display = 'none';
  switchView('auth');
}

export function enterApp() {
  state.signedIn = true;
  document.getElementById('nav').style.display = 'flex';
  document.getElementById('logout-btn').style.display = 'inline-block';
  switchView('chat');
}

export function switchView(name) {
  for (const el of document.querySelectorAll('.view')) {
    el.classList.toggle('active', el.id === `${name}-view`);
  }
  for (const btn of document.querySelectorAll('#nav button')) {
    btn.classList.toggle('active', btn.dataset.view === name);
  }
  document.dispatchEvent(new CustomEvent('opsclaw:view', { detail: { name } }));
}
