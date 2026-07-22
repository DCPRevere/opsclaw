//! `list_incidents` — read-only incident queries (DESIGN.md §4 item 3:
//! "incident + runbook queries"). Lets the agent (or an operator via chat)
//! ask "what's currently open?" / "what happened last week?" without a
//! separate HTTP/CLI round-trip.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct ListIncidentsTool;

#[async_trait]
impl Tool for ListIncidentsTool {
    fn name(&self) -> &'static str {
        "list_incidents"
    }

    fn description(&self) -> &str {
        "List incidents. By default returns only OPEN ones (active or acknowledged); set \
         `include_closed` to true to include resolved/expired incidents too. Use before \
         opening a new incident with opsclaw_notify if you're unsure whether one already \
         exists — though opsclaw_notify itself dedups automatically."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "include_closed": {"type": "boolean", "description": "include resolved/expired incidents (default false)"},
                "limit": {"type": "integer", "description": "max rows to return (default 20)"}
            }
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        false
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let repo = ctx.incidents.as_ref().ok_or_else(|| {
            ToolError::Internal("list_incidents called with no incident store wired".to_string())
        })?;
        let include_closed = args["include_closed"].as_bool().unwrap_or(false);
        let limit = args["limit"].as_i64().unwrap_or(20);

        let incidents = repo
            .list(include_closed, limit)
            .await
            .map_err(|e| ToolError::Internal(format!("incident list failed: {e}")))?;

        if incidents.is_empty() {
            return Ok(ToolResult {
                output: if include_closed {
                    "no incidents recorded.".to_string()
                } else {
                    "no open incidents.".to_string()
                },
            });
        }

        let out = incidents
            .iter()
            .map(|i| {
                format!(
                    "- {} [{:?}/{:?}] {} — {} (opened {})",
                    i.id,
                    i.severity,
                    i.state,
                    i.target,
                    i.hypothesis,
                    i.opened_at.to_rfc3339()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok(ToolResult { output: out })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::IncidentRepo;
    use crate::db::memory::InMemoryDb;
    use crate::domain::{FqTarget, Incident, IncidentState, Principal, Severity};
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    struct NoopPolicy;
    #[async_trait]
    impl PolicyExecute for NoopPolicy {
        async fn execute(&self, _req: CommandRequest) -> crate::Result<PolicyOutcome> {
            Ok(PolicyOutcome::EStopped)
        }
    }

    fn incident(state: IncidentState) -> Incident {
        Incident {
            id: Uuid::new_v4(),
            fingerprint: "fp".into(),
            fault_class: String::new(),
            target: FqTarget::new("remundo", "prod", "web-1"),
            severity: Severity::Warning,
            state,
            signals: "cpu high".into(),
            hypothesis: "runaway process".into(),
            recommended_action: None,
            opened_at: Utc::now(),
            reopened_at: None,
            acked_at: None,
            acked_by: None,
            resolved_at: None,
            last_notified_at: None,
            notify_count: 0,
            escalation_step: 0,
            step_started_at: None,
        }
    }

    fn ctx_with(incidents: Arc<dyn IncidentRepo>) -> ToolCtx {
        ToolCtx {
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![],
            incidents: Some(incidents),
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        }
    }

    #[tokio::test]
    async fn defaults_to_open_only() {
        let db = InMemoryDb::new();
        IncidentRepo::insert(&db, &incident(IncidentState::Active)).await.unwrap();
        IncidentRepo::insert(&db, &incident(IncidentState::Resolved)).await.unwrap();
        let db: Arc<dyn IncidentRepo> = Arc::new(db);
        let ctx = ctx_with(db);
        let r = ListIncidentsTool.call(&ctx, json!({})).await.unwrap();
        assert_eq!(r.output.lines().count(), 1, "{}", r.output);
    }

    #[tokio::test]
    async fn include_closed_shows_everything() {
        let db = InMemoryDb::new();
        IncidentRepo::insert(&db, &incident(IncidentState::Active)).await.unwrap();
        IncidentRepo::insert(&db, &incident(IncidentState::Resolved)).await.unwrap();
        let db: Arc<dyn IncidentRepo> = Arc::new(db);
        let ctx = ctx_with(db);
        let r = ListIncidentsTool.call(&ctx, json!({"include_closed": true})).await.unwrap();
        assert_eq!(r.output.lines().count(), 2, "{}", r.output);
    }

    #[tokio::test]
    async fn empty_says_no_open_incidents() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db);
        let r = ListIncidentsTool.call(&ctx, json!({})).await.unwrap();
        assert_eq!(r.output, "no open incidents.");
    }

    #[tokio::test]
    async fn missing_repo_is_internal_fault() {
        let ctx = ToolCtx {
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        };
        let err = ListIncidentsTool.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }
}
