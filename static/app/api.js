// Vanilla fetch wrapper — ported from gianna's static/app/api.js. Every
// call returns a normalised {ok, status, data} shape and rides the
// HttpOnly session cookie (`credentials: 'same-origin'`); a 401 while the
// app believed it was signed in means the session was revoked or expired
// elsewhere, so it drops back to the login view.
import { state, showAuth } from './state.js';

export async function api(path, method = 'GET', body) {
  const headers = { 'Content-Type': 'application/json' };
  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (_) {
    return { ok: false, status: 0, data: { error: 'Could not reach the daemon — check your connection.' } };
  }
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body is fine */ }
  if (res.status === 401 && state.signedIn) {
    state.signedIn = false;
    showAuth();
  }
  return { ok: res.ok, status: res.status, data };
}

// Disable a button for the duration of an async action so a slow request
// can't be double-submitted by an impatient click.
export async function withBusy(btn, fn) {
  if (!btn || btn.disabled) return;
  btn.disabled = true;
  try {
    return await fn();
  } finally {
    btn.disabled = false;
  }
}

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}
