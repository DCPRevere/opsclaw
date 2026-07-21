//! Daemon status (DESIGN §3: "status (heartbeat liveness, per-target scan
//! state, e-stop)"). Read-only, `Authed`-gated. No gianna analog by name
//! (gianna's admin scheduler-health view is the closest relative — same
//! idea, ported as a first-party operator surface here rather than an
//! admin-token-gated one, since opsclaw has no separate admin tier).

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde_json::{Value, json};

use crate::Result;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/status", get(status))
}

/// GET /api/status — heartbeat health (reads the SAME cell the watchdog's
/// own alert does, so this view can never disagree with a page), the
/// current adaptive tick interval, and e-stop engagement.
async fn status(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let now_ms = Utc::now().timestamp_millis();
    let heartbeat = state.scheduler.heartbeat_status(now_ms);
    let estop_engaged = state.estop.engaged().await?;
    Ok(Json(json!({
        "version": crate::version(),
        "fakes_mode": state.config.fully_faked(),
        "heartbeat": heartbeat.as_str(),
        "tick_interval_ms": state.scheduler.interval_ms(),
        "lag_ms": state.scheduler.lag(),
        "estop_engaged": estop_engaged,
    })))
}
