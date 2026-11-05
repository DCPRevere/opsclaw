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

/// The incident as this reader may see it, or `None` when they may not
/// know it exists (`crate::access::findings`).
async fn visible(
    state: &AppState,
    ctx: &crate::http::handlers::Ctx,
    i: &crate::domain::Incident,
) -> Option<Value> {
    let view = crate::access::findings::incident_view(
        &state.access,
        &*state.repos,
        &ctx.principal(),
        ctx.via,
        i,
    )
    .await?;
    let mut v = incident_json(i);
    v["signals"] = json!(view.signals);
    v["hypothesis"] = json!(view.hypothesis);
    v["recommended_action"] = json!(view.recommended_action);
    v["access"] = json!({ "level": view.level, "note": view.note });
    Some(v)
}

/// 404 rather than 403: a reader without access doesn't learn it exists.
async fn get_visible(
    state: &AppState,
    ctx: &crate::http::handlers::Ctx,
    id: Uuid,
) -> Result<(crate::domain::Incident, Value)> {
    let incident = IncidentRepo::get(&*state.repos, id)
        .await?
        .ok_or_else(|| Error::NotFound("incident".into()))?;
    let v =
        visible(state, ctx, &incident).await.ok_or_else(|| Error::NotFound("incident".into()))?;
    Ok((incident, v))
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
async fn list(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>> {
    let incidents = IncidentRepo::list(&*state.repos, q.include_closed, q.limit).await?;
    let mut shown = Vec::new();
    for i in &incidents {
        if let Some(v) = visible(&state, &ctx, i).await {
            shown.push(v);
        }
    }
    Ok(Json(json!({ "incidents": shown })))
}

/// GET /api/incidents/{id}
async fn get_one(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    Ok(Json(get_visible(&state, &ctx, id).await?.1))
}

/// Shared ack/resolve body: validate the transition against the CURRENT
/// stored state before writing (never trust the client's idea of the
/// current state — a stale UI retrying a click must not silently coerce an
/// already-resolved incident back through a transition).
async fn transition(
    state: &AppState,
    id: Uuid,
    to: IncidentState,
    by: Option<Uuid>,
) -> Result<crate::domain::Incident> {
    let current = IncidentRepo::get(&*state.repos, id)
        .await?
        .ok_or_else(|| Error::NotFound("incident".into()))?;
    lifecycle::validate_transition(current.state, to)?;
    state.repos.set_state(id, to, by).await?;
    IncidentRepo::get(&*state.repos, id).await?.ok_or_else(|| Error::NotFound("incident".into()))
}

/// POST /api/incidents/{id}/ack — acknowledge (Active -> Acknowledged).
/// `acked_by` is the signed-in operator, never trusted from the body.
async fn ack(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    get_visible(&state, &ctx, id).await?;
    let updated = transition(&state, id, IncidentState::Acknowledged, Some(ctx.account_id)).await?;
    Ok(Json(visible(&state, &ctx, &updated).await.unwrap_or_else(|| incident_json(&updated))))
}

/// POST /api/incidents/{id}/resolve — force-resolve (valid from both
/// Active and Acknowledged per `lifecycle::validate_transition`).
async fn resolve(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    get_visible(&state, &ctx, id).await?;
    let updated = transition(&state, id, IncidentState::Resolved, Some(ctx.account_id)).await?;
    Ok(Json(visible(&state, &ctx, &updated).await.unwrap_or_else(|| incident_json(&updated))))
}

/// GET /api/incidents/{id}/postmortem — rendered markdown over the
/// incident's own audit trail. Scoped to records whose `fq_target` matches
/// the incident's target (the closest available linkage — there is no
/// direct incident->audit-record foreign key by design, since not every
/// audited command that touches a target is incident-caused).
async fn postmortem(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    let (incident, v) = get_visible(&state, &ctx, id).await?;
    // The postmortem quotes the evidence and every command run: full,
    // unwithheld access only.
    if v["signals"].is_null() || !v["access"]["note"].is_null() {
        return Err(Error::Validation(
            "the postmortem needs full, unredacted access to this incident's evidence".into(),
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::routes::access_fixture::Fixture;

    const LOG: &str = "acme::prod::aks";

    async fn listed(f: &Fixture, ctx: Ctx) -> Vec<Value> {
        let q = ListQuery { include_closed: true, limit: 50 };
        let Json(v) = list(State(f.state.clone()), Authed(ctx), Query(q)).await.unwrap();
        v["incidents"].as_array().unwrap().clone()
    }

    use crate::http::handlers::Ctx;

    #[tokio::test]
    async fn each_reader_sees_an_incident_at_their_level() {
        let f = Fixture::new();
        let id = f.incident("login failed for jane@acme.com", &[(LOG, "logs")]).await;

        // No role: the incident doesn't exist for them.
        let eve = f.person("eve@acme.com", &[]).await;
        assert!(listed(&f, eve).await.is_empty());
        let eve = f.person("eve2@acme.com", &[]).await;
        assert!(get_one(State(f.state.clone()), Authed(eve), Path(id)).await.is_err());

        // Summary: no evidence.
        let reader = f.person("reader@acme.com", &[]).await;
        let rows = listed(&f, reader).await;
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["signals"].is_null());
        assert_eq!(rows[0]["access"]["level"], "summary");

        // Full with redacted logs: evidence redacted.
        let bob = f.person("bob@acme.com", &["oncall"]).await;
        let rows = listed(&f, bob).await;
        assert_eq!(rows[0]["signals"], "login failed for <redacted:email>");
        assert!(rows[0]["access"]["note"].as_str().unwrap().contains("redacted"));
        let bob = f.person("bob2@acme.com", &["oncall"]).await;
        assert!(
            postmortem(State(f.state.clone()), Authed(bob), Path(id)).await.is_err(),
            "the postmortem needs unredacted access"
        );
    }

    #[tokio::test]
    async fn evidence_from_a_class_the_reader_lacks_is_withheld() {
        let f = Fixture::new();
        f.incident("queue payload {name: Jane}", &[(LOG, "messages")]).await;
        let bob = f.person("bob@acme.com", &["oncall"]).await;
        let rows = listed(&f, bob).await;
        assert!(rows[0]["signals"].is_null());
        assert!(rows[0]["access"]["note"].as_str().unwrap().contains("messages"));
    }

    #[tokio::test]
    async fn a_restricted_incident_is_only_for_the_named() {
        let f = Fixture::new();
        let id = f.incident("security thing", &[]).await;
        f.state
            .repos
            .set_restricted("incident", &id.to_string(), Some(&["sec-team".into()]))
            .await
            .unwrap();
        let bob = f.person("bob@acme.com", &["oncall"]).await;
        assert!(listed(&f, bob).await.is_empty());
        let sam = f.person("sam@acme.com", &["oncall", "sec-team"]).await;
        assert_eq!(listed(&f, sam).await.len(), 1);
    }
}
