//! Teammate invites (DESIGN §3: "invite flow for teammates"). Ported in
//! spirit from gianna's `roster_api::{create_invite, join}` — simplified
//! for single-tenant opsclaw: no household id on the invite, and `join`
//! creates a brand-new operator account rather than adding a member to an
//! existing household.
//!
//! First-boot bootstrap has NO gianna analog (gianna is self-service
//! signup — every household creates itself; opsclaw is an operator-invite-
//! only system with no public signup). The chosen design (flagged in the
//! port report, not silently assumed): the FIRST account is created by the
//! local CLI directly via `AccountRepo::insert` during `opsclaw onboard`
//! (bypassing HTTP entirely — the CLI links the library directly, DESIGN
//! §1), never through this HTTP invite flow. Every account after the first
//! goes through `create_invite` + `join` here, gated by `Authed` (an
//! existing operator issues the invite).

use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::Error;
use crate::Result;
use crate::db::{Account, AccountRepo, Invite};
use crate::http::handlers::{Authed, check_auth_rate, session_response};
use crate::http::state::AppState;
use crate::http::{auth, cli_auth};

/// How long an issued invite code stays open before it must be reissued.
/// Generous (a teammate may not act on a Slack DM immediately) but bounded
/// — an invite is a standing credential to create an operator account, so
/// it must not live forever.
const INVITE_TTL: Duration = Duration::days(7);

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/invites", get(list_invites).post(create_invite))
        .route("/api/invites/{code}", delete(revoke_invite))
        .route("/api/join", post(join))
}

/// POST /api/invites — an existing operator mints a one-time code for a
/// new teammate. `Authed`-gated: only a signed-in operator can invite.
async fn create_invite(State(state): State<AppState>, Authed(ctx): Authed) -> Result<Json<Value>> {
    let code = cli_auth::challenge_for(&Uuid::new_v4().to_string())[..16].to_string();
    let now = Utc::now();
    let invite = Invite {
        code: code.clone(),
        issued_by: ctx.account_id,
        created_at: now,
        expires_at: now + INVITE_TTL,
    };
    state.repos.create_invite(&invite).await?;
    Ok(Json(json!({ "code": code, "expires_at": invite.expires_at })))
}

/// GET /api/invites — every currently-open invite, so an operator can see
/// (and revoke) outstanding invites. `Authed`-gated; not scoped to "invites
/// I personally issued" — single-tenant, every operator manages the same
/// team's invites (DESIGN §1: shared team state).
async fn list_invites(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let open = state.repos.list_open_invites(Utc::now()).await?;
    Ok(Json(json!({
        "invites": open.iter().map(|i| json!({
            "code": i.code,
            "issued_by": i.issued_by,
            "created_at": i.created_at,
            "expires_at": i.expires_at,
        })).collect::<Vec<_>>()
    })))
}

/// DELETE /api/invites/{code} — revoke one open invite.
async fn revoke_invite(
    State(state): State<AppState>,
    Authed(_ctx): Authed,
    Path(code): Path<String>,
) -> Result<Json<Value>> {
    if !state.repos.revoke_invite(&code).await? {
        return Err(Error::NotFound("no such open invite".into()));
    }
    Ok(Json(json!({ "revoked": code })))
}

#[derive(Deserialize)]
pub struct JoinReq {
    pub code: String,
    pub email: String,
    pub password: String,
    pub display_name: String,
}

/// POST /api/join — consume an invite code and create a new operator
/// account. Unauthenticated by nature (the invite code IS the proof), so
/// it shares the per-IP auth rate limit with login.
async fn join(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<JoinReq>,
) -> Result<axum::response::Response> {
    check_auth_rate(&state, &headers)?;
    if !crate::http::handlers::plausible_email(&req.email) {
        return Err(Error::validation("that doesn't look like a valid email address"));
    }
    if req.password.len() < 8 {
        return Err(Error::validation("password must be at least 8 characters"));
    }
    let display_name = req.display_name.trim();
    if display_name.is_empty() {
        return Err(Error::validation("display name must not be empty"));
    }

    // Atomic consume: the double-join TOCTOU race is closed at the repo
    // layer (`InviteRepo::take_invite`'s UPDATE...RETURNING), so only the
    // FIRST concurrent join on a given code ever gets here.
    let denied = || Error::unauthorized("invalid or expired invite code");
    state.repos.take_invite(&req.code, Utc::now()).await?.ok_or_else(denied)?;

    if state.repos.by_email(&req.email).await?.is_some() {
        return Err(Error::validation("an account with that email already exists"));
    }

    let account = Account {
        id: Uuid::new_v4(),
        email: req.email,
        display_name: display_name.to_string(),
        password_hash: auth::hash_password(&req.password)?,
        token_version: 0,
        created_at: Utc::now(),
    };
    AccountRepo::insert(&*state.repos, &account).await?;
    session_response(&state, account.id, account.token_version)
}
