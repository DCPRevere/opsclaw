//! Provider discovery and the Hanko sign-in exchange (DESIGN §7 decision
//! 16).
//!
//! Both routes are deliberately UNAUTHENTICATED — they are the front door,
//! reached before any session exists — following the written precedent of
//! `routes::push::vapid_public_key`. Neither exposes a secret: the provider
//! name and the Hanko API URL are values the browser must know to render a
//! login screen at all, and the browser learns the API URL anyway the moment
//! the widget talks to it.
//!
//! `GET /api/config` is a different thing entirely and stays `Authed`: it
//! serialises the WHOLE config.
//!
//! The exchange is the entire integration seam. It verifies the Hanko token,
//! resolves the operator's own `accounts` row, and then calls the same
//! `session_response` the password path calls — so from the cookie onward,
//! the two providers are indistinguishable and every downstream gate
//! (`Authed`, the `ops_` bearer, SSE tickets, `token_version`) is untouched.

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::AuthProvider;
use crate::http::handlers::{ClientAddr, check_auth_rate, session_response};
use crate::http::state::AppState;
use crate::{Error, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/config", get(auth_config))
        .route("/api/auth/hanko/exchange", post(hanko_exchange))
}

/// GET /api/auth/config — which provider this daemon uses.
///
/// The login screen must know this BEFORE anyone is signed in, otherwise it
/// cannot decide whether to render a password form or the Hanko widget.
async fn auth_config(State(state): State<AppState>) -> Result<axum::Json<Value>> {
    Ok(axum::Json(match state.config.auth.provider {
        AuthProvider::Local => json!({ "provider": "local" }),
        AuthProvider::Hanko => json!({
            "provider": "hanko",
            "api_url": state.config.auth.api_base(),
        }),
        AuthProvider::Oidc => json!({
            "provider": "oidc",
            "login_url": "/api/auth/oidc/start",
        }),
    }))
}

#[derive(Deserialize)]
pub struct ExchangeReq {
    /// The Hanko session token, sent explicitly in the BODY.
    ///
    /// Never read from an ambient cookie: the Hanko cookie belongs to
    /// Hanko's origin and does not reach this daemon in the normal
    /// cross-origin deployment, and honouring an ambient credential on a
    /// login endpoint is how login-CSRF works.
    pub session_token: String,
}

/// POST /api/auth/hanko/exchange — trade a verified Hanko session for this
/// daemon's own session cookie.
///
/// There is NO auto-provisioning. An identity Hanko authenticates but which
/// no `accounts` row claims gets a 401: a Hanko project can be open to
/// self-registration, and this daemon holds cluster credentials. Operators
/// arrive through `opsclaw-cli account create --hanko-subject` or by
/// redeeming an invite.
async fn hanko_exchange(
    State(state): State<AppState>,
    ClientAddr(peer): ClientAddr,
    axum::Json(req): axum::Json<ExchangeReq>,
) -> Result<axum::response::Response> {
    // First, before any outbound call: an unlimited endpoint here is a free
    // request amplifier pointed at the identity provider.
    check_auth_rate(&state, peer)?;
    let hanko = state
        .hanko
        .as_ref()
        .ok_or_else(|| Error::validation("this daemon does not use hanko sign-in"))?;

    let identity = hanko.verify(&req.session_token).await?;
    let account =
        state.repos.by_external_subject(crate::db::AUTH_PROVIDER_HANKO, &identity.subject).await?;

    let Some(account) = account else {
        tracing::info!(
            subject = %identity.subject,
            "hanko sign-in for an identity no operator account is linked to"
        );
        // Carries an explicit `code` because this 401 means something
        // different from the verification-failed 401 the same endpoint also
        // returns: here the operator DID authenticate, they just have no
        // account yet, which is what an invite is for. The app branches on
        // the code to decide whether to offer the join form — branching on
        // the status alone would send an operator whose token was rejected
        // to a form that cannot help them.
        return Ok((
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "error": "no operator account is linked to this identity — \
                          ask an operator for an invite",
                "code": NO_LINKED_ACCOUNT,
            })),
        )
            .into_response());
    };

    tracing::info!(account = %account.id, "hanko sign-in");
    session_response(&state, account.id, account.token_version)
}

/// The `code` on the "authenticated, but unlinked" 401. Shared with
/// `static/app/auth.js`, which keys the invite prompt off it.
pub const NO_LINKED_ACCOUNT: &str = "no_linked_account";
