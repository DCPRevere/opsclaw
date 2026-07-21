//! `opsclaw_notify` — the ONE structured escalation tool (brief §6, DESIGN.md
//! §4 "Tool surface" item 3: "exactly one — the `escalate_to_human` /
//! `opsclaw_notify` split was a fork scar"). The payload is the product's
//! most visible artifact: severity, fully-qualified target, the observed
//! signals with actual numbers, the hypothesis, and a recommended action.
//!
//! Dedup lives here, not in the caller: this tool IS the anti-spam choke
//! point for escalation. It computes the fingerprint
//! (`incidents::fingerprint_for`) and looks for an already-open incident
//! (`IncidentRepo::find_open_by_fingerprint`) — a matching open incident
//! means this is a new OCCURRENCE of the same problem, so the tool reports
//! that plainly rather than opening a duplicate. Only a genuinely new
//! fingerprint opens a new `Incident` row. Escalation-chain delivery (who
//! gets notified, ack_timeout, repeat_interval) is the scheduler's job
//! (`incidents::escalation`) once the incident exists — this tool's
//! responsibility ends at "the incident now exists (or already did)".

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::{Incident, IncidentState, RiskClass, Severity};
use crate::incidents::fingerprint_for;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct NotifyTool;

fn parse_severity(s: &str) -> Result<Severity, ToolError> {
    match s {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "critical" => Ok(Severity::Critical),
        other => Err(ToolError::UserFacing(format!(
            "unknown severity {other:?}. Valid severities: info, warning, critical."
        ))),
    }
}

#[async_trait]
impl Tool for NotifyTool {
    fn name(&self) -> &'static str {
        "opsclaw_notify"
    }

    fn description(&self) -> &str {
        "Escalate a confirmed problem to a human. This is the ONLY way to raise an incident \
         — call it once you've confirmed a signal with a diagnostic tool and formed a \
         hypothesis, not on a single unconfirmed reading. Provide: severity, the \
         fully-qualified target, `fault_class` (a short stable label for the kind of \
         problem, e.g. cpu_saturation, dlq_backlog, target_unreachable — used to detect a \
         repeat of the SAME problem so it doesn't page twice), `resource` (the specific \
         thing affected within the target, or empty string if the fault has no finer \
         resource than the target itself), `evidence` (the observed signals WITH ACTUAL \
         NUMBERS), `hypothesis`, and an optional `recommended_action`. Calling this again \
         for the same target+fault_class+resource while it's still open attaches as a new \
         occurrence — it does not create a duplicate incident or double-page."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["info", "warning", "critical"]},
                "target": {"type": "string", "description": "fully-qualified target"},
                "fault_class": {"type": "string", "description": "stable short label for the fault kind, e.g. cpu_saturation"},
                "resource": {"type": "string", "description": "the specific resource affected, or \"\" if none finer than the target"},
                "evidence": {"type": "string", "description": "observed signals with actual numbers"},
                "hypothesis": {"type": "string"},
                "recommended_action": {"type": "string"}
            },
            "required": ["severity", "target", "fault_class", "resource", "evidence", "hypothesis"]
        })
    }

    fn risk(&self) -> RiskClass {
        // Opening an incident has no remote side effect (nothing runs
        // against a target), so this is never gated by autonomy — it's a
        // daemon-local write, not a command dispatched through policy.
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        // Still an ACTION for the duplicate-call-guard's purposes (it
        // writes a row) even though it carries no policy risk.
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let repo = ctx.incidents.as_ref().ok_or_else(|| {
            ToolError::Internal("opsclaw_notify called with no incident store wired".to_string())
        })?;

        let severity = args["severity"]
            .as_str()
            .ok_or_else(|| ToolError::UserFacing("opsclaw_notify requires \"severity\"".to_string()))
            .and_then(parse_severity)?;
        let target_str = args["target"]
            .as_str()
            .ok_or_else(|| ToolError::UserFacing("opsclaw_notify requires \"target\"".to_string()))?;
        let fault_class = args["fault_class"].as_str().ok_or_else(|| {
            ToolError::UserFacing("opsclaw_notify requires \"fault_class\"".to_string())
        })?;
        let resource = args["resource"].as_str().unwrap_or("");
        let evidence = args["evidence"]
            .as_str()
            .ok_or_else(|| ToolError::UserFacing("opsclaw_notify requires \"evidence\"".to_string()))?;
        let hypothesis = args["hypothesis"].as_str().ok_or_else(|| {
            ToolError::UserFacing("opsclaw_notify requires \"hypothesis\"".to_string())
        })?;
        let recommended_action = args["recommended_action"].as_str().map(str::to_string);

        let target = ctx.resolve_target(target_str)?;
        let fingerprint = fingerprint_for(&target, fault_class, resource);

        let existing = repo
            .find_open_by_fingerprint(&fingerprint)
            .await
            .map_err(|e| ToolError::Internal(format!("incident lookup failed: {e}")))?;

        if let Some(incident) = existing {
            return Ok(ToolResult {
                output: format!(
                    "already tracking this as incident {} (opened {}, {} notifications sent \
                     so far) — attached as a new occurrence, not a new incident.",
                    incident.id,
                    incident.opened_at.to_rfc3339(),
                    incident.notify_count
                ),
            });
        }

        let now = Utc::now();
        let incident = Incident {
            id: Uuid::new_v4(),
            fingerprint,
            target,
            severity,
            state: IncidentState::Active,
            signals: evidence.to_string(),
            hypothesis: hypothesis.to_string(),
            recommended_action,
            opened_at: now,
            acked_at: None,
            acked_by: None,
            resolved_at: None,
            last_notified_at: None,
            notify_count: 0,
            escalation_step: 0,
            step_started_at: None,
        };
        repo.insert(&incident)
            .await
            .map_err(|e| ToolError::Internal(format!("incident insert failed: {e}")))?;

        Ok(ToolResult {
            output: format!(
                "opened incident {} (severity {:?}) — the escalation chain will notify per its \
                 configured priority; this call does not itself send anything.",
                incident.id, severity
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory::InMemoryDb;
    use crate::db::IncidentRepo;
    use crate::domain::{FqTarget, Principal};
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use std::sync::Arc;

    struct NoopPolicy;
    #[async_trait]
    impl PolicyExecute for NoopPolicy {
        async fn execute(&self, _req: CommandRequest) -> crate::Result<PolicyOutcome> {
            Ok(PolicyOutcome::EStopped)
        }
    }

    fn target() -> FqTarget {
        FqTarget::new("remundo", "prod", "web-1")
    }

    fn ctx_with(incidents: Arc<dyn IncidentRepo>) -> ToolCtx {
        ToolCtx {
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![target()],
            incidents: Some(incidents),
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
        }
    }

    fn base_args() -> Value {
        json!({
            "severity": "critical",
            "target": "remundo::prod::web-1",
            "fault_class": "cpu_saturation",
            "resource": "",
            "evidence": "cpu at 97% for 8 minutes",
            "hypothesis": "runaway worker process"
        })
    }

    #[tokio::test]
    async fn opens_a_new_incident_on_first_call() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        let r = NotifyTool.call(&ctx, base_args()).await.unwrap();
        assert!(r.output.contains("opened incident"));

        let open = db.find_open_by_fingerprint(&fingerprint_for(&target(), "cpu_saturation", "")).await.unwrap();
        assert!(open.is_some());
        let incident = open.unwrap();
        assert_eq!(incident.severity, Severity::Critical);
        assert_eq!(incident.signals, "cpu at 97% for 8 minutes");
        assert_eq!(incident.hypothesis, "runaway worker process");
        assert_eq!(incident.state, IncidentState::Active);
    }

    #[tokio::test]
    async fn second_call_with_same_fingerprint_attaches_not_duplicates() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        NotifyTool.call(&ctx, base_args()).await.unwrap();
        let r2 = NotifyTool.call(&ctx, base_args()).await.unwrap();
        assert!(r2.output.contains("already tracking"), "{}", r2.output);

        let all = db.list(true, 100).await.unwrap();
        assert_eq!(all.len(), 1, "must not create a second incident row");
    }

    #[tokio::test]
    async fn different_fault_class_opens_a_distinct_incident() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        NotifyTool.call(&ctx, base_args()).await.unwrap();

        let mut second = base_args();
        second["fault_class"] = json!("disk_full");
        NotifyTool.call(&ctx, second).await.unwrap();

        let all = db.list(true, 100).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn recommended_action_is_optional() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        NotifyTool.call(&ctx, base_args()).await.unwrap();
        let incident = db
            .find_open_by_fingerprint(&fingerprint_for(&target(), "cpu_saturation", ""))
            .await
            .unwrap()
            .unwrap();
        assert!(incident.recommended_action.is_none());
    }

    #[tokio::test]
    async fn unknown_severity_is_user_facing() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db);
        let mut args = base_args();
        args["severity"] = json!("urgent");
        let err = NotifyTool.call(&ctx, args).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[tokio::test]
    async fn missing_incident_store_is_an_internal_fault() {
        let ctx = ToolCtx {
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![target()],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
        };
        let err = NotifyTool.call(&ctx, base_args()).await.unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }
}
