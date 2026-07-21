// Login, join-by-invite, logout — ported in shape from gianna's
// static/app/auth.js's fetch pattern, adapted to opsclaw's separate
// /api/login and /api/join endpoints (gianna branches one form on whether
// an invite code was entered; opsclaw's shell keeps them as two forms
// toggled by a link, since "sign in" and "redeem an invite" are more
// clearly distinct actions here).
import { api, withBusy } from './api.js';
import { state, showAuth, enterApp } from './state.js';

export function initAuth() {
  const loginForm = document.getElementById('login-form');
  const joinForm = document.getElementById('join-form');
  const showJoin = document.getElementById('show-join');
  const showLogin = document.getElementById('show-login');
  const joinCard = document.getElementById('join-card');

  showJoin.addEventListener('click', (e) => {
    e.preventDefault();
    loginForm.closest('.card').style.display = 'none';
    joinCard.style.display = 'block';
  });
  showLogin.addEventListener('click', (e) => {
    e.preventDefault();
    joinCard.style.display = 'none';
    loginForm.closest('.card').style.display = 'block';
  });

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = loginForm.querySelector('button[type=submit]');
    const err = document.getElementById('login-err');
    await withBusy(btn, async () => {
      err.textContent = '';
      const email = document.getElementById('login-email').value;
      const password = document.getElementById('login-password').value;
      const r = await api('/api/login', 'POST', { email, password });
      if (!r.ok) { err.textContent = r.data.error || 'Sign-in failed.'; return; }
      enterApp();
    });
  });

  joinForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = joinForm.querySelector('button[type=submit]');
    const err = document.getElementById('join-err');
    await withBusy(btn, async () => {
      err.textContent = '';
      const code = document.getElementById('join-code').value.trim();
      const display_name = document.getElementById('join-name').value;
      const email = document.getElementById('join-email').value;
      const password = document.getElementById('join-password').value;
      const r = await api('/api/join', 'POST', { code, display_name, email, password });
      if (!r.ok) { err.textContent = r.data.error || 'Could not join.'; return; }
      enterApp();
    });
  });

  document.getElementById('logout-btn').addEventListener('click', async () => {
    await api('/api/logout', 'POST');
    showAuth();
  });
}

// GET /api/me on load: if the session cookie is already valid, skip
// straight past the login form (mirrors gianna's app-boot session check).
export async function checkSession() {
  const r = await api('/api/me');
  if (r.ok) { enterApp(); } else { showAuth(); }
}

export { state };
