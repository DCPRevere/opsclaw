//! Remote e-stop (DESIGN §4: "Remote `estop` (PWA / remote CLI / chat) is a
//! gateway endpoint"). Engages/resumes via `policy::EStop`, which writes
//! BOTH mechanisms (sentinel file + DB flag) — see that module's doc
//! comment for why two. `Authed`-gated: any signed-in operator may pull
//! this lever (an e-stop is a "stop everything now" action; requiring it
//! to clear a narrower gate than login itself would work against the
//! reason it exists).

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Result;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/estop/engage", post(engage)).route("/api/estop/resume", post(resume))
}

#[derive(Deserialize)]
pub struct EngageReq {
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /api/estop/engage — nothing executes anywhere after this returns
/// (`policy::Policy::execute` re-reads the e-stop before every command).
async fn engage(State(state): State<AppState>, Authed(ctx): Authed, Json(req): Json<EngageReq>) -> Result<Json<Value>> {
    let reason = req.reason.filter(|r| !r.trim().is_empty()).unwrap_or_else(|| format!("engaged by operator {}", ctx.account_id));
    state.estop.engage(&reason).await?;
    tracing::warn!(operator = %ctx.account_id, reason = %reason, "e-stop engaged via HTTP");
    Ok(Json(json!({ "estop_engaged": true })))
}

/// POST /api/estop/resume — clears both mechanisms.
async fn resume(State(state): State<AppState>, Authed(ctx): Authed) -> Result<Json<Value>> {
    state.estop.resume().await?;
    tracing::warn!(operator = %ctx.account_id, "e-stop resumed via HTTP");
    Ok(Json(json!({ "estop_engaged": false })))
}
