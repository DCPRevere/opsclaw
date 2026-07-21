//! Incident list/detail + ack/resolve (DESIGN §3: "incident list/detail
//! with ack/resolve"). Composes over `db::IncidentRepo` +
//! `incidents::lifecycle::validate_transition` — no gianna analog by name
//! (gianna has no incident concept), but the shape (typed extractor gate,
//! JSON list/detail, a state-mutating action gated the same way) matches
//! every other route in this module.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::Error;
use crate::Result;
use crate::db::{AuditRepo, IncidentRepo};
use crate::domain::IncidentState;
use crate::http::handlers::Authed;
use crate::http::state::AppState;
use crate::incidents::lifecycle;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/incidents", get(list))
        .route("/api/incidents/{id}", get(get_one))
        .route("/api/incidents/{id}/ack", post(ack))
        .route("/api/incidents/{id}/resolve", post(resolve))
        .route("/api/incidents/{id}/postmortem", get(postmortem))
}

fn incident_json(i: &crate::domain::Incident) -> Value {
    json!({
        "id": i.id,
        "fingerprint": i.fingerprint,
        "target": i.target.to_string(),
        "severity": i.severity,
        "state": i.state,
        "signals": i.signals,
        "hypothesis": i.hypothesis,
        "recommended_action": i.recommended_action,
        "opened_at": i.opened_at,
        "acked_at": i.acked_at,
        "acked_by": i.acked_by,
        "resolved_at": i.resolved_at,
        "last_notified_at": i.last_notified_at,
        "notify_count": i.notify_count,
        "escalation_step": i.escalation_step,
    })
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    include_closed: bool,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

/// GET /api/incidents?include_closed=&limit= — newest first (repo's own
/// ordering contract).
async fn list(State(state): State<AppState>, Authed(_ctx): Authed, Query(q): Query<ListQuery>) -> Result<Json<Value>> {
    let incidents = IncidentRepo::list(&*state.repos, q.include_closed, q.limit).await?;
    Ok(Json(json!({ "incidents": incidents.iter().map(incident_json).collect::<Vec<_>>() })))
}

/// GET /api/incidents/{id}
async fn get_one(State(state): State<AppState>, Authed(_ctx): Authed, Path(id): Path<Uuid>) -> Result<Json<Value>> {
    let incident = IncidentRepo::get(&*state.repos, id).await?.ok_or_else(|| Error::NotFound("incident".into()))?;
    Ok(Json(incident_json(&incident)))
}

/// Shared ack/resolve body: validate the transition against the CURRENT
/// stored state before writing (never trust the client's idea of the
/// current state — a stale UI retrying a click must not silently coerce an
/// already-resolved incident back through a transition).
async fn transition(state: &AppState, id: Uuid, to: IncidentState, by: Option<Uuid>) -> Result<crate::domain::Incident> {
    let current = IncidentRepo::get(&*state.repos, id).await?.ok_or_else(|| Error::NotFound("incident".into()))?;
    lifecycle::validate_transition(current.state, to)?;
    state.repos.set_state(id, to, by).await?;
    IncidentRepo::get(&*state.repos, id).await?.ok_or_else(|| Error::NotFound("incident".into()))
}

/// POST /api/incidents/{id}/ack — acknowledge (Active -> Acknowledged).
/// `acked_by` is the signed-in operator, never trusted from the body.
async fn ack(State(state): State<AppState>, Authed(ctx): Authed, Path(id): Path<Uuid>) -> Result<Json<Value>> {
    let updated = transition(&state, id, IncidentState::Acknowledged, Some(ctx.account_id)).await?;
    Ok(Json(incident_json(&updated)))
}

/// POST /api/incidents/{id}/resolve — force-resolve (valid from both
/// Active and Acknowledged per `lifecycle::validate_transition`).
async fn resolve(State(state): State<AppState>, Authed(ctx): Authed, Path(id): Path<Uuid>) -> Result<Json<Value>> {
    let updated = transition(&state, id, IncidentState::Resolved, Some(ctx.account_id)).await?;
    Ok(Json(incident_json(&updated)))
}

/// GET /api/incidents/{id}/postmortem — rendered markdown over the
/// incident's own audit trail. Scoped to records whose `fq_target` matches
/// the incident's target (the closest available linkage — there is no
/// direct incident->audit-record foreign key by design, since not every
/// audited command that touches a target is incident-caused).
async fn postmortem(State(state): State<AppState>, Authed(_ctx): Authed, Path(id): Path<Uuid>) -> Result<Json<Value>> {
    let incident = IncidentRepo::get(&*state.repos, id).await?.ok_or_else(|| Error::NotFound("incident".into()))?;
    let fq = incident.target.to_string();
    let mut records = Vec::new();
    let mut from_seq = 1i64;
    // Page through the whole chain looking for this target's records — the
    // audit log has no target index (it's a hash chain, sequential by
    // design), so a postmortem walks it once. Capped generously; a truly
    // enormous chain is a later pagination concern, not this route's.
    loop {
        let page = AuditRepo::range(&*state.repos, from_seq, 500).await?;
        if page.is_empty() {
            break;
        }
        from_seq = page.last().map(|r| r.seq + 1).unwrap_or(from_seq);
        records.extend(page.into_iter().filter(|r| r.fq_target == fq));
        if from_seq > 50_000 {
            break; // generous cap; see comment above
        }
    }
    let rendered = crate::incidents::render_postmortem(&incident, &records);
    Ok(Json(json!({ "postmortem": rendered })))
}
