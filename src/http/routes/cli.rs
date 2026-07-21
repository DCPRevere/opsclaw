//! The remote-CLI surface (DESIGN §1/§7: token-auth against the daemon's
//! gateway). Ported from gianna's `src/http/cli_api.rs` — the PKCE hand-off
//! (`authorize`/`exchange`) is near-verbatim; the `/cli/v1/*` product
//! routes are opsclaw's own set (`me`, `status`, `incidents`, `approvals`)
//! rather than gianna's (`tasks`/`routines`/`reminders`/`memory`).
//!
//! Auth is an `ops_` bearer token (see `http::cli_auth`); the web session
//! cookie is deliberately NOT accepted here, so the two session kinds stay
//! independently revocable (gianna's stance, ported unchanged).

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::db::CliToken;
use crate::http::cli_auth;
use crate::http::handlers::{self, Authed};
use crate::http::state::AppState;
use crate::{Error, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        // Browser hand-off (web-session authed — the operator approving a
        // CLI login from their already-open tab).
        .route("/api/cli/authorize", post(authorize))
        // The remote-CLI's own bearer-authed surface.
        .route("/cli/v1/auth/token", post(exchange))
        .route("/cli/v1/me", get(me))
        .route("/cli/v1/status", get(status))
        .route("/cli/v1/token", delete(revoke))
        // In-app "manage my CLI sessions" (web-session authed).
        .route("/api/cli-tokens", get(list_tokens))
        .route("/api/cli-tokens/{id}", delete(revoke_token))
}

#[derive(Deserialize)]
pub struct AuthorizeReq {
    /// sha256 hex of the CLI's verifier (PKCE-style).
    pub challenge: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// POST /api/cli/authorize — the signed-in web operator approves a CLI
/// login, minting a one-time code bound to the CLI's challenge.
async fn authorize(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Json(req): Json<AuthorizeReq>,
) -> Result<Json<Value>> {
    if req.challenge.len() != 64 || !req.challenge.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::validation("challenge must be a sha256 hex digest"));
    }
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("opsclaw-cli")
        .chars()
        .take(80)
        .collect::<String>();

    let code = cli_auth::generate_code();
    {
        let mut codes = state.cli_auth_codes.lock().unwrap();
        let now = Utc::now();
        // Sweep expired entries on insert (same stance as invites).
        codes.retain(|_, p| (now - p.issued_at).num_seconds() < cli_auth::CODE_TTL_SECS);
        codes.insert(
            code.clone(),
            cli_auth::PendingCliAuth {
                account_id: ctx.account_id,
                challenge: req.challenge,
                name,
                issued_at: now,
            },
        );
    }
    Ok(Json(json!({ "code": code })))
}

#[derive(Deserialize)]
pub struct ExchangeReq {
    pub code: String,
    pub verifier: String,
}

/// POST /cli/v1/auth/token — exchange a one-time code + verifier for a
/// long-lived CLI token. Unauthenticated by nature; shares the per-IP auth
/// rate limit with login.
async fn exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExchangeReq>,
) -> Result<Json<Value>> {
    handlers::check_auth_rate(&state, &headers)?;
    let denied = || Error::unauthorized("invalid or expired authorization code");

    // One-time: the code leaves the map on FIRST presentation, valid or
    // not — a failed guess must not leave it alive for a second try.
    let pending = state.cli_auth_codes.lock().unwrap().remove(&req.code).ok_or_else(denied)?;
    if (Utc::now() - pending.issued_at).num_seconds() >= cli_auth::CODE_TTL_SECS {
        return Err(denied());
    }
    if cli_auth::challenge_for(&req.verifier) != pending.challenge {
        return Err(denied());
    }

    let account = state
        .repos
        .by_id(pending.account_id)
        .await?
        .ok_or_else(|| Error::unauthorized("unknown account"))?;
    let token = cli_auth::generate_token();
    state
        .repos
        .create_cli_token(
            CliToken {
                id: Uuid::new_v4(),
                account: account.id,
                name: pending.name,
                created_at: Utc::now(),
                last_used_at: None,
            },
            &cli_auth::token_hash(&token),
        )
        .await?;
    Ok(Json(json!({ "token": token, "email": account.email })))
}

/// Authenticate a `/cli/v1` request: resolve the `ops_` bearer to its
/// account. Returns the token row id too, so `revoke` can revoke exactly
/// itself (not every session on the account).
async fn authenticate_cli(state: &AppState, headers: &HeaderMap) -> Result<(Uuid, Uuid)> {
    let token = handlers::bearer(headers)?;
    if !token.starts_with(cli_auth::TOKEN_PREFIX) {
        return Err(Error::unauthorized("a CLI token is required (run `opsclaw-cli login`)"));
    }
    let (token_id, account_id) = state
        .repos
        .find_cli_token(&cli_auth::token_hash(token))
        .await?
        .ok_or_else(|| Error::unauthorized("token revoked — run `opsclaw-cli login`"))?;
    Ok((account_id, token_id))
}

/// GET /cli/v1/me — whose session this is.
async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>> {
    let (account_id, _token_id) = authenticate_cli(&state, &headers).await?;
    let account = state
        .repos
        .by_id(account_id)
        .await?
        .ok_or_else(|| Error::unauthorized("unknown account"))?;
    Ok(Json(json!({ "account_id": account.id, "email": account.email })))
}

/// GET /cli/v1/status — the remote CLI's status view (DESIGN §7 decision
/// 14: "Remote CLI v1: small set — chat, incidents, approve/deny, estop,
/// status"). Bearer-authed twin of `/api/status`.
async fn status(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>> {
    authenticate_cli(&state, &headers).await?;
    let now_ms = Utc::now().timestamp_millis();
    let heartbeat = state.scheduler.heartbeat_status(now_ms);
    let estop_engaged = state.estop.engaged().await?;
    Ok(Json(json!({
        "heartbeat": heartbeat.as_str(),
        "estop_engaged": estop_engaged,
    })))
}

/// DELETE /cli/v1/token — revoke the presented token (logout).
async fn revoke(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>> {
    let (account_id, token_id) = authenticate_cli(&state, &headers).await?;
    state.repos.revoke_cli_token(account_id, token_id).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---- in-app CLI-session management (web session, not the ops_ bearer) ----

/// GET /api/cli-tokens — the signed-in account's CLI sessions (metadata
/// only; the token secret is never stored, let alone returned).
async fn list_tokens(State(state): State<AppState>, Authed(ctx): Authed) -> Result<Json<Value>> {
    let tokens = state.repos.list_cli_tokens(ctx.account_id).await?;
    Ok(Json(json!({
        "tokens": tokens.iter().map(|t| json!({
            "id": t.id,
            "name": t.name,
            "created_at": t.created_at,
            "last_used_at": t.last_used_at,
        })).collect::<Vec<_>>()
    })))
}

/// DELETE /api/cli-tokens/{id} — revoke one CLI session. 404 if it isn't
/// this account's (never leaks another account's token existence).
async fn revoke_token(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    if !state.repos.revoke_cli_token(ctx.account_id, id).await? {
        return Err(Error::NotFound("no such CLI session".into()));
    }
    Ok(Json(json!({ "revoked": id })))
}
