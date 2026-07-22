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
    // Per-target scan state (DESIGN §3): every scheduled job — the seeded
    // per-target scan jobs plus operator-authored ones — with its cadence
    // position. `kind_label` only, never the payload BODY (a prompt can be
    // long and sensitive — see `Payload::kind_label`'s own doc). Sorted by
    // name so the rendered listing is stable across polls.
    let mut jobs = JobRepo::list(&*state.repos).await?;
    jobs.sort_by(|a, b| a.name.cmp(&b.name));
    let jobs: Vec<Value> = jobs
        .iter()
        .map(|j| {
            json!({
                "name": j.name,
                "kind": j.payload.kind_label(),
                "enabled": j.enabled,
                "system": j.system,
                "next_run_at": j.next_run_at,
                "last_run_at": j.last_run_at,
            })
        })
        .collect();
    Ok(Json(json!({
        "version": crate::version(),
        "fakes_mode": state.config.fully_faked(),
        "heartbeat": heartbeat.as_str(),
        "tick_interval_ms": state.scheduler.interval_ms(),
        "last_tick_ms": state.scheduler.last_tick_at_ms(),
        "lag_ms": state.scheduler.lag(),
        "estop_engaged": estop_engaged,
        "jobs": jobs,
    })))
}
