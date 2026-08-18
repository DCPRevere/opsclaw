//! Typed auth extractor + login/logout handlers. Ported from gianna's
//! `src/http/handlers/auth_gates.rs` — simplified to ONE gate (`Authed`)
//! rather than gianna's `Authed`/`AuthedRead`/`AuthedWrite` trio: gianna's
//! extra two encode a subscription-tier gate opsclaw has no analog for
//! (DESIGN.md doesn't define operator roles or tiers — every signed-in
//! operator has the same standing, and per-action authorization is the
//! POLICY layer's job, not auth's). The rationale DESIGN §3 calls out
//! survives unchanged: "typed auth extractors that encode the permission in
//! the handler signature... hand-rolled gate calls let a missing check ship
//! silently" — `Authed` is that same `FromRequestParts` pattern, just with
//! one tier instead of three.
//!
//! `Authed` accepts EITHER credential a signed-in operator might be holding:
//! the web session cookie, or an `ops_` remote-CLI bearer token (see
//! `authenticate`'s doc). This is the opposite direction from `/cli/v1/*`
//! (`routes::cli`), which accepts ONLY the bearer and never the cookie —
//! that route family is reached programmatically and must stay usable even
//! when no browser session exists; `Authed`-gated routes (estop, incidents,
//! approvals, ...) are reached by BOTH the web UI and the remote CLI
//! (DESIGN §7 decision 14's small operator-action set), so accepting either
//! credential here is what lets the CLI reach them without a second,
//! duplicate set of routes.

use axum::extract::{FromRequestParts, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;
use uuid::Uuid;

use super::auth;
use super::state::AppState;
use crate::{Error, Result};

/// A pragmatic email shape check (full RFC 5322 validation is a fool's
/// errand); ported verbatim from gianna's `handlers/auth_gates.rs::
/// plausible_email`.
pub(crate) fn plausible_email(email: &str) -> bool {
    if email.len() > 254 || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else { return false };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
}

pub(crate) fn bearer(headers: &HeaderMap) -> Result<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| Error::unauthorized("missing bearer token"))
}

pub(crate) struct Ctx {
    pub(crate) account_id: Uuid,
}

/// Socket peer when the router is served with Axum `ConnectInfo`; absent for
/// in-process router tests. Unlike `ConnectInfo` itself this extractor is
/// deliberately optional without turning a missing extension into a 500.
pub(crate) struct ClientAddr(pub(crate) Option<SocketAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        let peer =
            parts.extensions.get::<axum::extract::ConnectInfo<SocketAddr>>().map(|info| info.0);
        Ok(ClientAddr(peer))
    }
}

pub(crate) async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Ctx> {
    // Two independently-revocable session kinds share this one gate
    // (DESIGN §7 decision 14: the remote CLI's small operator-action set —
    // approve/deny, estop, incidents — needs the SAME standing a signed-in
    // web operator has, not a narrower one). The web UI authenticates by the
    // HttpOnly session cookie ONLY — the token is never exposed to
    // JavaScript, so an XSS can't steal it. A request carrying an `ops_`
    // bearer instead is the remote CLI: resolved the same way
    // `routes::cli::authenticate_cli` does (bearer -> sha256 -> `CliTokenRepo`
    // lookup), so a CLI token revocation (`logout`) takes effect here too.
    // Precedence: cookie first (the common case, and it's what a browser tab
    // will present even if some proxy also forwards an Authorization
    // header), bearer only when there is no session cookie at all — a
    // request never gets to choose the weaker of two credentials it holds.
    if let Some(token) = auth::session_cookie_value(headers) {
        let claims = auth::verify_token(&state.jwt_secret, &token)?;
        let account_id: Uuid = claims.sub.parse().map_err(|_| Error::unauthorized("bad token"))?;
        // Revocation check: the token must carry the account's CURRENT
        // token_version — a password reset (or explicit sign-out-everywhere)
        // bumps it, killing every older session. A genuinely-missing account
        // is a 401; any other repo failure propagates as-is (a 500), never
        // collapsed into "please sign in again" — that would hide an outage
        // behind a message that doesn't help and masks the real problem.
        let account = state
            .repos
            .by_id(account_id)
            .await?
            .ok_or_else(|| Error::unauthorized("unknown account"))?;
        if claims.ver != account.token_version {
            return Err(Error::unauthorized("session revoked — please sign in again"));
        }
        let span = tracing::Span::current();
        span.record("account", tracing::field::display(&account_id));
        span.record("session", claims.ver);
        return Ok(Ctx { account_id });
    }

    if let Ok(token) = bearer(headers)
        && token.starts_with(super::cli_auth::TOKEN_PREFIX)
    {
        // `find_cli_token` returns `(token_id, account_id)` in that order
        // (see `CliTokenRepo::find_cli_token`) — binding it the other way
        // round hands every `Authed` route the TOKEN row's uuid as the
        // operator identity, which `by_id` then fails to resolve.
        let (_token_id, account_id) = state
            .repos
            .find_cli_token(&super::cli_auth::token_hash(token))
            .await?
            .ok_or_else(|| Error::unauthorized("token revoked — run `opsclaw-cli login`"))?;
        let span = tracing::Span::current();
        span.record("account", tracing::field::display(&account_id));
        return Ok(Ctx { account_id });
    }

    Err(Error::unauthorized("not signed in"))
}

/// `authenticate` — the signed-in `Ctx`. Every operator has the same
/// standing (no roles/tiers in DESIGN.md); a route that additionally needs
/// operator-specific scoping (e.g. "only this account's own CLI tokens")
/// checks `ctx.account_id` against the resource in the handler body, same
/// as gianna's account-scoped CLI-token routes do under `Authed`.
pub struct Authed(pub(crate) Ctx);

impl FromRequestParts<AppState> for Authed {
    type Rejection = Error;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self> {
        Ok(Authed(authenticate(state, &parts.headers).await?))
    }
}

// ---- login/logout ----

#[derive(Deserialize)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

/// Rate-limit identity from the TCP peer, never an attacker-controlled
/// forwarding header. OpsClaw has no trusted-proxy configuration, so
/// accepting X-Forwarded-For would let a direct client mint a new bucket per
/// guess. Router-only tests have no ConnectInfo and share the conservative
/// `unknown` bucket.
fn client_ip(peer: Option<SocketAddr>) -> String {
    peer.map(|addr| addr.ip().to_string()).unwrap_or_else(|| "unknown".into())
}

pub(crate) fn check_auth_rate(state: &AppState, peer: Option<SocketAddr>) -> Result<()> {
    if state.auth_limiter.allow_at(&client_ip(peer), Utc::now().timestamp()) {
        Ok(())
    } else {
        Err(Error::rate_limited("too many attempts — please wait a minute", 60))
    }
}

/// POST /api/login — email + password, returning a fresh session cookie. A
/// uniform error for both unknown-email and wrong-password avoids leaking
/// which emails are registered operators.
///
/// Refused outright when an external provider is configured. The gate is
/// HERE, on the handler, not merely in the UI: leaving the route live would
/// mean every account created before the switch kept a working parallel
/// password, making the provider setting advisory rather than authoritative.
/// The break-glass for a provider outage is an `ops_` CLI token minted
/// beforehand, which reaches every `Authed` route including e-stop.
pub(crate) async fn login(
    State(state): State<AppState>,
    ClientAddr(peer): ClientAddr,
    axum::Json(req): axum::Json<LoginReq>,
) -> Result<Response> {
    if state.config.auth.provider != crate::config::AuthProvider::Local {
        return Err(Error::validation("password sign-in is disabled — this daemon uses hanko"));
    }
    check_auth_rate(&state, peer)?;
    let invalid = || Error::unauthorized("invalid email or password");
    let account = state.repos.by_email(&req.email).await?.ok_or_else(invalid)?;
    if !auth::verify_password(&req.password, &account.password_hash)? {
        return Err(invalid());
    }
    session_response(&state, account.id, account.token_version)
}

/// Build the auth response: set the HttpOnly session cookie and return the
/// (token-free) JSON body. The token lives only in the cookie, never in the
/// body or JavaScript.
pub(crate) fn session_response(
    state: &AppState,
    account_id: Uuid,
    token_version: i64,
) -> Result<Response> {
    let token = auth::issue_token(&state.jwt_secret, account_id, token_version)?;
    let cookie = auth::session_cookie(&token, state.config.http.cookies_secure);
    Ok((
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(json!({ "account_id": account_id })),
    )
        .into_response())
}

/// POST /api/logout — clear the session cookie. Stateless JWT, so this just
/// drops the cookie; full revocation across devices is the `token_version`
/// bump (a later "sign out everywhere" action, not built here). Always 200
/// so the client can clear UI state regardless.
pub async fn logout(State(state): State<AppState>) -> Response {
    let cookie = auth::clear_session_cookie(state.config.http.cookies_secure);
    ([(axum::http::header::SET_COOKIE, cookie)], axum::Json(json!({ "ok": true }))).into_response()
}

/// GET /api/me — whose session this is (for the SPA to confirm sign-in
/// state on load).
pub async fn me(State(state): State<AppState>, Authed(ctx): Authed) -> Result<axum::Json<Value>> {
    let account = state
        .repos
        .by_id(ctx.account_id)
        .await?
        .ok_or_else(|| Error::unauthorized("unknown account"))?;
    Ok(axum::Json(json!({
        "account_id": account.id,
        "email": account.email,
        "display_name": account.display_name,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_rate_limit_is_keyed_by_socket_peer() {
        let state = AppState::fake();
        let first: SocketAddr = "192.0.2.10:1234".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:5678".parse().unwrap();
        for _ in 0..10 {
            check_auth_rate(&state, Some(first)).unwrap();
        }
        assert!(check_auth_rate(&state, Some(first)).is_err());
        assert!(check_auth_rate(&state, Some(second)).is_ok());
    }
}
