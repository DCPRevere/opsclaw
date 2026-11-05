//! Daemon status (DESIGN §3: "status (heartbeat liveness, per-target scan
//! state, e-stop)") — all three legs of that triple: heartbeat (last tick +
//! current adaptive interval), e-stop engagement, and the per-target scan
//! state (every scheduled job with its cadence position). Read-only,
//! `Authed`-gated. No gianna analog by name (gianna's admin
//! scheduler-health view is the closest relative — same idea, ported as a
//! first-party operator surface here rather than an admin-token-gated one,
//! since opsclaw has no separate admin tier).

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde_json::{Value, json};

use crate::Result;
use crate::db::JobRepo;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/status", get(status))
}

/// GET /api/status — heartbeat health (reads the SAME cells the watchdog's
/// own alerts do, so this view can never disagree with a page: status +
/// last tick + current adaptive interval), e-stop engagement, and the
/// per-target scan state.
async fn status(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let now_ms = Utc::now().timestamp_millis();
    let heartbeat = state.scheduler.heartbeat_status(now_ms);
    let estop_engaged = state.estop.engaged().await?;
    let turns = state.turn_gate.snapshot(now_ms);
    // Per-target scan state (DESIGN §3): every scheduled job — the seeded
    // per-target scan jobs plus operator-authored ones — with its cadence
    // position. `kind_label` only, never the payload BODY (a prompt can be
    // long and sensitive — see `Payload::kind_label`'s own doc). Sorted by
    // name so the rendered listing is stable across polls.
    let mut jobs = JobRepo::list(&*state.repos).await?;
    jobs.sort_by(|a, b| a.name.cmp(&b.name));
    // Failure visibility per job: `last_run_at` advances even when every
    // fire fails (the schedule moves on regardless), so without the streak
    // and last error this surface showed a 20-hour scan outage as a
    // healthy, on-cadence job — the journal was the only witness.
    let mut rows: Vec<Value> = Vec::with_capacity(jobs.len());
    for j in &jobs {
        let streak = JobRepo::count_job_failures(&*state.repos, j.id).await.unwrap_or(0);
        let last_error = if streak > 0 {
            JobRepo::latest_job_failure(&*state.repos, j.id)
                .await
                .ok()
                .flatten()
                .map(|f| crate::policy::Scrubber::global().scrub(&f.last_error))
        } else {
            None
        };
        rows.push(json!({
            "name": j.name,
            "kind": j.payload.kind_label(),
            "enabled": j.enabled,
            "system": j.system,
            "next_run_at": j.next_run_at,
            "last_run_at": j.last_run_at,
            "consecutive_failures": streak,
            "last_error": last_error,
        }));
    }
    let jobs = rows;
    let spend = match state.cost_guard.spend_snapshot().await {
        Ok(snapshot) => serde_json::to_value(snapshot).unwrap_or(Value::Null),
        Err(error) => json!({
            "cap_cents": state.cost_guard.cap_cents(),
            "complete": false,
            "error": error.to_string(),
        }),
    };
    Ok(Json(json!({
        "version": crate::version(),
        "fakes_mode": state.config.fully_faked(),
        "heartbeat": heartbeat.as_str(),
        "tick_interval_ms": state.scheduler.interval_ms(),
        "last_tick_ms": state.scheduler.last_tick_at_ms(),
        "lag_ms": state.scheduler.lag(),
        "estop_engaged": estop_engaged,
        "spend": spend,
        "turns": turns,
        "jobs": jobs,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn status_exposes_live_turn_kind_domain_and_age() {
        let state = AppState::fake();
        let guard = state.turn_gate.acquire_interactive("chat").await;
        let account_id = uuid::Uuid::new_v4();
        let Json(body) = status(
            State(state),
            Authed(crate::http::handlers::Ctx { account_id, via: crate::access::Via::Web }),
        )
        .await
        .unwrap();
        assert_eq!(body["turns"][0]["kind"], "chat");
        assert_eq!(body["turns"][0]["conflict_domain"], "all targets");
        assert_eq!(body["turns"][0]["state"], "active");
        assert!(body["turns"][0]["age_ms"].as_i64().unwrap() >= 0);
        drop(guard);
    }
}
