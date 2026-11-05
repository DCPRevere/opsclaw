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
use crate::http::handlers::{Authed, ClientAddr, check_auth_rate, session_response};
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

#[cfg(test)]
mod join_order_tests {
    use super::*;
    use crate::db::{AccountRepo, Invite};
    use crate::http::AppState;

    async fn seeded() -> (AppState, String) {
        let state = AppState::fake();
        let code = "invite-code-1".to_string();
        state
            .repos
            .create_invite(&Invite {
                code: code.clone(),
                issued_by: Uuid::new_v4(),
                created_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::days(7),
            })
            .await
            .unwrap();
        (state, code)
    }

    fn req(code: &str, email: &str, password: Option<&str>) -> JoinReq {
        JoinReq {
            code: code.into(),
            email: email.into(),
            display_name: "Op".into(),
            password: password.map(str::to_string),
            session_token: None,
        }
    }

    /// A bad invite code must produce the SAME answer whether or not the
    /// email belongs to an operator. Otherwise `/api/join` — which is
    /// unauthenticated — enumerates the operator roster.
    #[tokio::test]
    async fn a_bad_code_answers_identically_for_known_and_unknown_emails() {
        let (state, _code) = seeded().await;
        let existing = Account {
            id: Uuid::new_v4(),
            email: "known@example.com".into(),
            display_name: "Known".into(),
            password_hash: "x".into(),
            token_version: 0,
            created_at: Utc::now(),
            auth_provider: crate::db::AUTH_PROVIDER_LOCAL.into(),
            external_subject: None,
        };
        AccountRepo::insert(&*state.repos, &existing).await.unwrap();

        let known = join(
            axum::extract::State(state.clone()),
            ClientAddr(None),
            axum::Json(req("bogus", "known@example.com", Some("longenough"))),
        )
        .await
        .unwrap_err();
        let unknown = join(
            axum::extract::State(state.clone()),
            ClientAddr(None),
            axum::Json(req("bogus", "nobody@example.com", Some("longenough"))),
        )
        .await
        .unwrap_err();
        assert_eq!(known.to_string(), unknown.to_string(), "the two must be indistinguishable");
        assert!(known.to_string().contains("invite"), "{known}");
    }

    /// The invite must survive a failure that happens after the code is
    /// checked but before it is consumed.
    #[tokio::test]
    async fn a_failed_join_leaves_the_code_usable() {
        let (state, code) = seeded().await;
        // Too-short password: fails during credential resolution.
        assert!(
            join(
                axum::extract::State(state.clone()),
                ClientAddr(None),
                axum::Json(req(&code, "op@example.com", Some("short"))),
            )
            .await
            .is_err()
        );
        assert!(
            state.repos.get_invite(&code, Utc::now()).await.unwrap().is_some(),
            "the code must not have been consumed"
        );
        join(
            axum::extract::State(state.clone()),
            ClientAddr(None),
            axum::Json(req(&code, "op@example.com", Some("long-enough-password"))),
        )
        .await
        .unwrap();
        assert!(state.repos.get_invite(&code, Utc::now()).await.unwrap().is_none(), "now consumed");
    }
}

#[derive(Deserialize)]
pub struct JoinReq {
    pub code: String,
    pub email: String,
    pub display_name: String,
    /// Required under `auth.provider = "local"`, refused otherwise. Optional
    /// at the serde layer so a hanko join does not fail deserialization with
    /// a generic 4xx that reads like a bad invite code.
    #[serde(default)]
    pub password: Option<String>,
    /// Required under `auth.provider = "hanko"`, refused otherwise: the
    /// Hanko session token proving who is redeeming the invite.
    #[serde(default)]
    pub session_token: Option<String>,
}

/// POST /api/join — consume an invite code and create a new operator
/// account. Unauthenticated by nature (the invite code IS the proof), so
/// it shares the per-IP auth rate limit with login.
async fn join(
    State(state): State<AppState>,
    ClientAddr(peer): ClientAddr,
    Json(req): Json<JoinReq>,
) -> Result<axum::response::Response> {
    check_auth_rate(&state, peer)?;
    if !crate::http::handlers::plausible_email(&req.email) {
        return Err(Error::validation("that doesn't look like a valid email address"));
    }
    let display_name = req.display_name.trim();
    if display_name.is_empty() {
        return Err(Error::validation("display name must not be empty"));
    }

    // Three-step ordering, and each step is where it is for a reason.
    //
    // 1. CHECK the invite without consuming it. This route is
    //    unauthenticated, so the code is the only thing that distinguishes a
    //    teammate from an anonymous caller — nothing observable and nothing
    //    expensive may happen before it is known good. Skipping this check
    //    would make the email-exists branch below an operator-enumeration
    //    oracle (the same leak the uniform `/api/login` error exists to
    //    prevent), and would let anyone spend an argon2 hash — or, under
    //    hanko, an outbound call to the identity provider — per request.
    let denied = || Error::unauthorized("invalid or expired invite code");
    state.repos.get_invite(&req.code, Utc::now()).await?.ok_or_else(denied)?;

    // 2. Resolve the credential, still without consuming.
    //
    //    `take_invite` is a one-time, 7-day consume, so any failure after it
    //    burns the code and leaves the teammate locked out with nothing to
    //    retry. The hanko path adds several ways to fail late (provider
    //    timeout, audience mismatch, an already-linked subject), which is
    //    what makes consuming first untenable rather than merely unlucky.
    let (password_hash, auth_provider, external_subject) = match state.config.auth.provider {
        crate::config::AuthProvider::Oidc => {
            return Err(Error::validation(
                "this daemon uses SSO — sign in with your company account instead of an invite",
            ));
        }
        crate::config::AuthProvider::Local => {
            if req.session_token.is_some() {
                return Err(Error::validation(
                    "this daemon uses password sign-in — send a password, not a session token",
                ));
            }
            let password = req.password.as_deref().unwrap_or_default();
            if password.len() < 8 {
                return Err(Error::validation("password must be at least 8 characters"));
            }
            (auth::hash_password(password)?, crate::db::AUTH_PROVIDER_LOCAL, None)
        }
        crate::config::AuthProvider::Hanko => {
            if req.password.is_some() {
                return Err(Error::validation(
                    "this daemon uses hanko sign-in — sign in with your passkey, not a password",
                ));
            }
            let token = req.session_token.as_deref().ok_or_else(|| {
                Error::validation("sign in with hanko first, then redeem the invite")
            })?;
            let hanko = state
                .hanko
                .as_ref()
                .ok_or_else(|| Error::unavailable("hanko sign-in is not wired on this daemon"))?;
            let identity = hanko.verify(token).await?;
            if state
                .repos
                .by_external_subject(crate::db::AUTH_PROVIDER_HANKO, &identity.subject)
                .await?
                .is_some()
            {
                return Err(Error::validation(
                    "that identity already has an operator account — sign in instead",
                ));
            }
            (auth::NO_PASSWORD.to_string(), crate::db::AUTH_PROVIDER_HANKO, Some(identity.subject))
        }
    };

    if state.repos.by_email(&req.email).await?.is_some() {
        return Err(Error::validation("an account with that email already exists"));
    }

    // 3. Consume. The double-join TOCTOU race is closed at the repo layer
    //    (`InviteRepo::take_invite`'s UPDATE...RETURNING), so only the FIRST
    //    concurrent join on a given code ever gets past here — step 1's
    //    read is a gate, not a substitute for this.
    state.repos.take_invite(&req.code, Utc::now()).await?.ok_or_else(denied)?;

    let account = Account {
        id: Uuid::new_v4(),
        email: req.email,
        display_name: display_name.to_string(),
        password_hash,
        token_version: 0,
        created_at: Utc::now(),
        auth_provider: auth_provider.to_string(),
        external_subject,
    };
    AccountRepo::insert(&*state.repos, &account).await?;
    session_response(&state, account.id, account.token_version)
}
