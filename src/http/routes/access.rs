//! `/api/access`: what the signed-in person may see, and time-boxed raw
//! access (elevations) to logs and messages (docs/plans/ACCESS.md §4).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::Error;
use crate::Result;
use crate::access::{Elevation, ElevationMode, ElevationState};
use crate::audit::AuditOutcome;
use crate::domain::{Principal, RiskClass};
use crate::http::handlers::{Authed, Ctx};
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/access/me", get(me))
        .route("/api/access/elevations", get(list).post(request))
        .route("/api/access/elevations/{id}/approve", post(approve))
        .route("/api/access/elevations/{id}/deny", post(deny))
        .route("/api/access/elevations/{id}/revoke", post(revoke))
}

async fn audit(state: &AppState, who: &Principal, scope: &str, line: &str, outcome: AuditOutcome) {
    match &state.audit {
        Some(a) => {
            if let Err(e) =
                a.append(who, scope, "access", line, RiskClass::Read, outcome, None).await
            {
                tracing::error!("access decision not audited: {e}");
            }
        }
        None => tracing::info!(%who, scope, line, ?outcome, "access decision"),
    }
}

fn elevation_json(e: &Elevation) -> Value {
    json!({
        "id": e.id,
        "account": e.account,
        "scope": e.scope,
        "class": e.class,
        "reason": e.reason,
        "requested_at": e.requested_at,
        "expires_at": e.expires_at,
        "state": e.state,
        "live": e.live(Utc::now()),
        "approved": e.approved(),
        "decided_by": e.decided_by,
    })
}

/// GET /api/access/me: roles, groups, preset and live elevations.
async fn me(State(state): State<AppState>, Authed(ctx): Authed) -> Result<Json<Value>> {
    let account = state
        .repos
        .by_id(ctx.account_id)
        .await?
        .ok_or_else(|| Error::unauthorized("unknown account"))?;
    let groups = state.repos.groups(ctx.account_id).await?;
    let subject = crate::access::Subject { account: ctx.account_id, email: account.email, groups };
    let roles = state.access.roles_of(&subject);
    let elevations: Vec<Value> = state
        .repos
        .elevations_for(ctx.account_id)
        .await?
        .iter()
        .filter(|e| e.live(Utc::now()) || e.state == ElevationState::Pending)
        .map(elevation_json)
        .collect();
    Ok(Json(json!({
        "preset": state.access.config().preset,
        "roles": roles,
        "groups": subject.groups,
        "elevations": elevations,
    })))
}

/// GET /api/access/elevations: your own, plus everyone's that you may
/// decide.
async fn list(State(state): State<AppState>, Authed(ctx): Authed) -> Result<Json<Value>> {
    let me = ctx.principal();
    let mut out = Vec::new();
    for e in state.repos.list_elevations().await? {
        let theirs = Principal::Operator { account: e.account };
        let mine = e.account == ctx.account_id;
        if mine || state.access.approve(&me, ctx.via, &e.scope, &theirs).await.is_ok() {
            out.push(elevation_json(&e));
        }
    }
    Ok(Json(json!({ "elevations": out })))
}

#[derive(Deserialize)]
pub struct ElevationReq {
    pub scope: String,
    pub class: String,
    pub reason: String,
    #[serde(default)]
    pub hours: Option<u32>,
}

/// POST /api/access/elevations: open (self-service) or request (approval)
/// raw access to one class in one scope, with a reason.
async fn request(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Json(req): Json<ElevationReq>,
) -> Result<Json<Value>> {
    let reason = req.reason.trim();
    if reason.len() < 3 {
        return Err(Error::validation("an elevation needs a reason (an incident or ticket id)"));
    }
    let me = ctx.principal();
    let mode = match state.access.may_elevate(&me, &req.scope, &req.class).await {
        Ok(mode) => mode,
        Err(denied) => {
            audit(
                &state,
                &me,
                &req.scope,
                &format!("elevate {} refused: {denied}", req.class),
                AuditOutcome::Denied,
            )
            .await;
            return Err(Error::validation(denied.to_string()));
        }
    };
    let max = state.access.max_elevation();
    let wanted = chrono::Duration::hours(req.hours.unwrap_or(1).max(1) as i64);
    let length = wanted.min(max);
    let now = Utc::now();
    let e = Elevation {
        id: Uuid::new_v4(),
        account: ctx.account_id,
        scope: req.scope.clone(),
        class: req.class.clone(),
        reason: reason.to_string(),
        requested_at: now,
        expires_at: now + length,
        state: if mode == ElevationMode::SelfService {
            ElevationState::Active
        } else {
            ElevationState::Pending
        },
        decided_by: None,
    };
    state.repos.insert_elevation(&e).await?;
    let outcome = if e.state == ElevationState::Active {
        AuditOutcome::Executed
    } else {
        AuditOutcome::ApprovalQueued
    };
    audit(
        &state,
        &me,
        &e.scope,
        &format!("elevate raw {} for {}m: {}", e.class, length.num_minutes(), e.reason),
        outcome,
    )
    .await;
    Ok(Json(elevation_json(&e)))
}

async fn load(state: &AppState, id: Uuid) -> Result<Elevation> {
    state.repos.elevation(id).await?.ok_or_else(|| Error::NotFound("elevation".into()))
}

async fn decide(state: &AppState, ctx: &Ctx, id: Uuid, to: ElevationState) -> Result<Json<Value>> {
    let e = load(state, id).await?;
    let me = ctx.principal();
    let theirs = Principal::Operator { account: e.account };
    if e.state != ElevationState::Pending {
        return Err(Error::Conflict(format!("elevation is {}, not pending", e.state.as_str())));
    }
    if let Err(denied) = state.access.approve(&me, ctx.via, &e.scope, &theirs).await {
        audit(
            state,
            &me,
            &e.scope,
            &format!("decide elevation {id} refused: {denied}"),
            AuditOutcome::Denied,
        )
        .await;
        return Err(Error::validation(denied.to_string()));
    }
    // The window starts when it is approved, not when it was asked for.
    let expires =
        (to == ElevationState::Active).then(|| Utc::now() + (e.expires_at - e.requested_at));
    state.repos.decide_elevation(id, to, Some(ctx.account_id), expires).await?;
    audit(
        state,
        &me,
        &e.scope,
        &format!("{} elevation {id} (raw {} for {})", to.as_str(), e.class, e.account),
        if to == ElevationState::Active { AuditOutcome::Executed } else { AuditOutcome::Blocked },
    )
    .await;
    Ok(Json(elevation_json(&load(state, id).await?)))
}

async fn approve(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    decide(&state, &ctx, id, ElevationState::Active).await
}

async fn deny(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    decide(&state, &ctx, id, ElevationState::Denied).await
}

/// POST /api/access/elevations/{id}/revoke: end it now. The holder, or
/// anyone who may decide it.
async fn revoke(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    let e = load(&state, id).await?;
    let me = ctx.principal();
    let theirs = Principal::Operator { account: e.account };
    let allowed = e.account == ctx.account_id
        || state.access.approve(&me, ctx.via, &e.scope, &theirs).await.is_ok();
    if !allowed {
        return Err(Error::NotFound("elevation".into()));
    }
    state
        .repos
        .decide_elevation(id, ElevationState::Revoked, Some(ctx.account_id), Some(Utc::now()))
        .await?;
    audit(&state, &me, &e.scope, &format!("revoke elevation {id}"), AuditOutcome::Executed).await;
    Ok(Json(elevation_json(&load(&state, id).await?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{Exposure, Via};
    use crate::http::routes::access_fixture::Fixture;

    const ES: &str = "acme::prod::aks";

    fn req(class: &str) -> Json<ElevationReq> {
        Json(ElevationReq {
            scope: "acme::prod".into(),
            class: class.into(),
            reason: "INC-42".into(),
            hours: Some(2),
        })
    }

    #[tokio::test]
    async fn an_approved_elevation_gives_raw_access_for_its_window() {
        let f = Fixture::new();
        let ivy = f.person("ivy@acme.com", &[]).await;
        let ivy_p = ivy.principal();
        let ivy_id = ivy.account_id;
        assert_eq!(f.state.access.read(&ivy_p, Via::Web, ES, "logs").await, Ok(Exposure::Redacted));

        let Json(e) = request(State(f.state.clone()), Authed(ivy), req("logs")).await.unwrap();
        assert_eq!(e["state"], "pending");
        let id: Uuid = serde_json::from_value(e["id"].clone()).unwrap();
        // Still redacted while pending.
        assert_eq!(f.state.access.read(&ivy_p, Via::Web, ES, "logs").await, Ok(Exposure::Redacted));

        // Ivy can't approve her own; a reader can't approve at all.
        let ivy_again = Ctx { account_id: ivy_id, via: Via::Web };
        assert!(approve(State(f.state.clone()), Authed(ivy_again), Path(id)).await.is_err());
        let reader = f.person("reader@acme.com", &[]).await;
        assert!(approve(State(f.state.clone()), Authed(reader), Path(id)).await.is_err());

        let lead = f.person("lead@acme.com", &[]).await;
        let Json(e) = approve(State(f.state.clone()), Authed(lead), Path(id)).await.unwrap();
        assert_eq!(e["state"], "active");
        assert_eq!(e["approved"], true);
        assert_eq!(f.state.access.read(&ivy_p, Via::Web, ES, "logs").await, Ok(Exposure::Raw));
        assert_eq!(f.state.access.read(&ivy_p, Via::Mcp, ES, "logs").await, Ok(Exposure::Raw));

        // Revoked: back to redacted.
        let ivy_again = Ctx { account_id: ivy_id, via: Via::Web };
        let _ = revoke(State(f.state.clone()), Authed(ivy_again), Path(id)).await.unwrap();
        assert_eq!(f.state.access.read(&ivy_p, Via::Web, ES, "logs").await, Ok(Exposure::Redacted));
    }

    #[tokio::test]
    async fn elevations_need_a_role_and_a_reason() {
        let f = Fixture::new();
        let bob = f.person("bob@acme.com", &["oncall"]).await;
        assert!(request(State(f.state.clone()), Authed(bob), req("logs")).await.is_err());
        let ivy = f.person("ivy@acme.com", &[]).await;
        let mut r = req("logs");
        r.reason = " ".into();
        assert!(request(State(f.state.clone()), Authed(ivy), r).await.is_err());
    }

    #[tokio::test]
    async fn me_reports_roles_from_groups_and_membership() {
        let f = Fixture::new();
        let bob = f.person("bob@acme.com", &["oncall"]).await;
        let Json(v) = me(State(f.state.clone()), Authed(bob)).await.unwrap();
        assert_eq!(v["roles"], serde_json::json!(["oncall"]));
        assert_eq!(v["preset"], "team");
    }
}
