// Login, join-by-invite, logout — ported in shape from gianna's
// static/app/auth.js's fetch pattern, adapted to opsclaw's separate
// /api/login and /api/join endpoints (gianna branches one form on whether
// an invite code was entered; opsclaw's shell keeps them as two forms
// toggled by a link, since "sign in" and "redeem an invite" are more
// clearly distinct actions here).
//
// The shell ships with every auth card hidden and reveals one only after
// GET /api/auth/config says which provider is configured. That discovery
// must happen before the operator can act — otherwise a hanko deployment
// flashes a password form that would always be refused.
import { api, withBusy } from './api.js';
import { state, showAuth, enterApp } from './state.js';

// The provider this daemon uses, as reported by the server. Also holds the
// Hanko session token between authenticating and redeeming an invite, for
// an operator whose identity has no account linked yet.
const provider = { name: 'local', apiUrl: null, sessionToken: null };

function show(el, on) {
  el.style.display = on ? 'block' : 'none';
}

export function initAuth() {
  const loginForm = document.getElementById('login-form');
  const joinForm = document.getElementById('join-form');
  const showLogin = document.getElementById('show-login');
  const loginCard = document.getElementById('login-card');
  const joinCard = document.getElementById('join-card');
  const hankoCard = document.getElementById('hanko-card');
  const joinPasswordRow = document.getElementById('join-password-row');

  // One link per sign-in card, so `.show-join` is a class rather than an id.
  for (const link of document.querySelectorAll('.show-join')) {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      show(loginCard, false);
      show(hankoCard, false);
      show(joinCard, true);
    });
  }
  showLogin.addEventListener('click', (e) => {
    e.preventDefault();
    show(joinCard, false);
    show(provider.name === 'hanko' ? hankoCard : loginCard, true);
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
      const body = { code, display_name, email };
      if (provider.name === 'hanko') {
        if (!provider.sessionToken) {
          err.textContent = 'Sign in with your passkey first, then redeem the code.';
          return;
        }
        body.session_token = provider.sessionToken;
      } else {
        body.password = document.getElementById('join-password').value;
      }
      const r = await api('/api/join', 'POST', body);
      if (!r.ok) { err.textContent = r.data.error || 'Could not join.'; return; }
      enterApp();
    });
  });

  document.getElementById('logout-btn').addEventListener('click', async () => {
    await api('/api/logout', 'POST');
    if (provider.name === 'hanko') {
      const mod = await import('./hanko.js');
      await mod.signOut();
    }
    provider.sessionToken = null;
    showAuth();
  });

  // Reveal the right surface whenever the auth view is shown — first load,
  // sign-out, and the mid-session 401 that api.js turns into showAuth().
  // Driving it off the view event rather than calling it once here is what
  // makes those last two work: state.js cannot import this module (it would
  // be circular), so the event is the only seam that catches every path.
  cards = { loginCard, joinCard, hankoCard, joinPasswordRow };
  document.addEventListener('opsclaw:view', (e) => {
    if (e.detail.name === 'auth') revealAuth();
  });
}

// Set by initAuth; the reveal runs on a view event, which can fire before or
// after discovery resolves.
let cards = null;
// Discovery runs at most once per page load, and the reveal is idempotent —
// a sign-out after a sign-in must not refetch the config or re-register the
// custom elements.
let discovery = null;

function revealAuth() {
  if (!cards) return;
  discovery = discovery || discoverProvider(cards);
  return discovery;
}

async function discoverProvider(els) {
  const r = await api('/api/auth/config');
  // A discovery failure must not leave a blank screen with no way in: fall
  // back to the password form, which is what every pre-hanko deployment is.
  provider.name = (r.ok && r.data.provider) || 'local';
  provider.apiUrl = (r.ok && r.data.api_url) || null;

  if (provider.name !== 'hanko' || !provider.apiUrl) {
    show(els.loginCard, true);
    return;
  }

  show(els.hankoCard, true);
  // No local password is ever set under this provider. The `required`
  // attribute has to go too, or the hidden field blocks form submission.
  show(els.joinPasswordRow, false);
  document.getElementById('join-password').removeAttribute('required');

  const err = document.getElementById('hanko-err');
  // The card is already visible, so a failure to load the widget must put a
  // message in it — otherwise the operator faces an empty box with no
  // explanation and nothing to retry. The bundle is not precached by the
  // service worker, so an offline PWA lands here.
  try {
    const mod = await import('./hanko.js');
    await mod.mountLogin(
      provider.apiUrl,
      document.getElementById('hanko-mount'),
      async (token) => {
        err.textContent = '';
        provider.sessionToken = token;
        const r = await api('/api/auth/hanko/exchange', 'POST', { session_token: token });
        if (r.ok) { enterApp(); return; }
        // Two very different things are 401 here: the token did not verify,
        // and the token verified but no account is linked to it. Only the
        // second is an invite situation. Branch on the server's explicit
        // discriminator, never on the bare status — sending an operator
        // whose token was rejected to a "redeem an invite" form tells them
        // to do something that cannot work.
        if (r.data.code === 'no_linked_account') {
          show(els.hankoCard, false);
          show(els.joinCard, true);
          document.getElementById('join-err').textContent = r.data.error || '';
          return;
        }
        err.textContent = r.data.error || 'Sign-in failed.';
      },
      (message) => { err.textContent = message; },
    );
  } catch (_) {
    err.textContent = 'Could not load the sign-in widget. Reload to try again.';
  }
}

// GET /api/me on load: if the session cookie is already valid, skip
// straight past the login form (mirrors gianna's app-boot session check).
export async function checkSession() {
  const r = await api('/api/me');
  if (r.ok) { enterApp(); } else { showAuth(); }
}

export { state };
