// Hanko sign-in, loaded lazily by auth.js only when GET /api/auth/config
// reports `provider: "hanko"` — a local-provider deployment never fetches
// the ~170KB widget bundle.
//
// The bundle is vendored (`/app/hanko-elements.js`, see static/vendor/), so
// the page's `script-src 'self'` is unchanged; only `connect-src` names the
// Hanko origin, and only under this provider.
//
// TOKEN DELIVERY. The widget's own `hanko.getSessionToken()` reads the
// `hanko` COOKIE, which is HttpOnly by default at the Hanko backend and in
// any case belongs to Hanko's origin, not this daemon's — so it is not
// usable here. Instead we register with `sessionTokenLocation:
// 'sessionStorage'` and read the token back out of the SDK's own storage.
// That requires `session.enable_auth_token_header: true` on the Hanko side;
// without it Hanko never returns the `X-Auth-Token` header the SDK stores,
// and sign-in stalls with no token to exchange.
import { register } from './hanko-elements.js';

// Resolved once per page load: repeated register() calls would re-define the
// custom elements.
let ready = null;

function setup(apiUrl) {
  if (!ready) {
    ready = register(apiUrl, { sessionTokenLocation: 'sessionStorage' });
  }
  return ready;
}

// Render <hanko-login> into `mount` and call `onToken(token)` once the
// operator has authenticated. `<hanko-login>` rather than `<hanko-auth>`:
// the latter also offers self-registration, and an operator account here is
// granted deliberately, never self-served.
export async function mountLogin(apiUrl, mount, onToken, onError) {
  let hanko;
  try {
    ({ hanko } = await setup(apiUrl));
  } catch (e) {
    onError('Could not load the sign-in widget.');
    return null;
  }

  mount.innerHTML = '<hanko-login></hanko-login>';
  const el = mount.querySelector('hanko-login');
  el.setAttribute('api', apiUrl);

  // The event carries claims but never the raw token, so it is a trigger
  // only — the token comes from the SDK's storage.
  el.addEventListener('onSessionCreated', () => {
    const token = hanko.client.sessionTokenStorage.getSessionToken();
    if (!token) {
      onError(
        'Signed in, but no session token was returned. The Hanko project needs ' +
        'session.enable_auth_token_header = true.'
      );
      return;
    }
    onToken(token);
  });
  return hanko;
}

// End the Hanko session too, not just this daemon's. Without it the next
// sign-in on a shared on-call machine silently resumes the previous
// operator's identity.
export async function signOut() {
  if (!ready) return;
  try {
    const { hanko } = await ready;
    await hanko.logout();
  } catch (_) {
    // Best-effort: the local session cookie is already cleared, and a
    // failure here must not strand the operator on a signed-in-looking UI.
  }
}
