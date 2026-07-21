//! The approval queue + approve/deny (DESIGN §3: "the approval queue with
//! approve/deny"). A thin JSON wrapper over `incidents::approvals::{approve,
//! deny}` — all the real logic (verbatim-command execution, the double-tap
//! guard, `DecisionOutcome`) already lives there; this module only
//! translates HTTP <-> that API and attributes the decision to the signed-in
//! operator (`ctx.account_id`), never a client-supplied id.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::Result;
use crate::http::handlers::Authed;
use crate::http::state::AppState;
use crate::incidents::approvals::{self, DecisionOutcome};
use crate::policy::PolicyOutcome;
use crate::targets::ExecOutput;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/approvals", get(list_pending))
        .route("/api/approvals/{id}/approve", post(approve))
        .route("/api/approvals/{id}/deny", post(deny))
}

fn approval_json(a: &crate::domain::ApprovalRequest) -> Value {
    json!({
        "id": a.id,
        "incident": a.incident,
        "requested_by": a.requested_by,
        "target": a.target.to_string(),
        "tool": a.tool,
        "command": a.command,
        "risk": a.risk,
        "hypothesis": a.hypothesis,
        "state": a.state,
        "requested_at": a.requested_at,
        "expires_at": a.expires_at,
        "decided_at": a.decided_at,
        "decided_by": a.decided_by,
    })
}

fn exec_output_json(o: &ExecOutput) -> Value {
    json!({
        "exit_code": o.exit_code,
        "stdout": o.stdout,
        "stderr": o.stderr,
        "duration_ms": o.duration_ms,
    })
}

fn outcome_json(outcome: &DecisionOutcome) -> Value {
    match outcome {
        DecisionOutcome::Denied => json!({ "decision": "denied" }),
        DecisionOutcome::ApprovedAndExecuted(policy_outcome) => {
            let (status, detail) = match policy_outcome {
                PolicyOutcome::Executed(out) => ("executed", exec_output_json(out)),
                PolicyOutcome::NeedsApproval(id) => ("needs_approval", json!({ "approval": id })),
                PolicyOutcome::Blocked { reason, dry_run_logged } => {
                    ("blocked", json!({ "reason": reason, "dry_run_logged": dry_run_logged }))
                }
                PolicyOutcome::EStopped => ("estopped", json!({})),
            };
            json!({ "decision": "approved", "status": status, "detail": detail })
        }
    }
}

/// GET /api/approvals — the pending queue (brief §5: decidable from a
/// phone — every field a human needs to decide is already on the row).
async fn list_pending(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let pending = state.repos.list_pending().await?;
    Ok(Json(json!({ "approvals": pending.iter().map(approval_json).collect::<Vec<_>>() })))
}

/// POST /api/approvals/{id}/approve — approve and execute the stored
/// command verbatim. `state.approved` is `Arc<dyn ExecuteApproved>` — the
/// narrower trait `approvals::approve` requires (never a `PolicyExecute`,
/// which would re-enter the autonomy gate and queue a second approval —
/// see that trait's doc comment).
async fn approve(State(state): State<AppState>, Authed(ctx): Authed, Path(id): Path<Uuid>) -> Result<Json<Value>> {
    let outcome = approvals::approve(&*state.repos, &state.approved, id, ctx.account_id).await?;
    Ok(Json(outcome_json(&outcome)))
}

/// POST /api/approvals/{id}/deny
async fn deny(State(state): State<AppState>, Authed(ctx): Authed, Path(id): Path<Uuid>) -> Result<Json<Value>> {
    let outcome = approvals::deny(&*state.repos, id, ctx.account_id).await?;
    Ok(Json(outcome_json(&outcome)))
}
