//! `systemd` — service management vocabulary (DESIGN.md §4 item 1, brief
//! §10). Composes `systemctl <action> <unit>` for a small, known verb set —
//! never free-text shell — so the classifier sees a predictable command
//! shape and the model can't smuggle an arbitrary command through a
//! "systemd" label.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct SystemdTool;

/// Validate the unit name loosely (systemd unit names are alnum plus
/// `-_.@:\`), so a service name can't be used to inject shell metacharacters
/// into the composed `systemctl` line even though the fixed verb set alone
/// already bounds most of the risk.
fn valid_unit_name(unit: &str) -> bool {
    !unit.is_empty() && unit.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@:\\".contains(c))
}

fn compose(action: &str, unit: &str) -> Result<String, ToolError> {
    if !valid_unit_name(unit) {
        return Err(ToolError::UserFacing(format!(
            "invalid systemd unit name {unit:?} — expected a plain unit name (letters, \
             digits, -_.@: only)"
        )));
    }
    match action {
        "status" | "restart" | "stop" | "start" => Ok(format!("systemctl {action} {unit}")),
        other => Err(ToolError::UserFacing(format!(
            "unknown systemd action {other:?}. Valid actions: status, restart, stop, start."
        ))),
    }
}

fn risk_for(action: &str) -> RiskClass {
    match action {
        "status" => RiskClass::Read,
        _ => RiskClass::Medium,
    }
}

#[async_trait]
impl Tool for SystemdTool {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn description(&self) -> &str {
        "Check or manage a systemd service: status (read-only), restart, stop, start. \
         Confirm a service is actually unhealthy (status, logs) before restarting it — a \
         restart is a mutation and gets classified/gated accordingly."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "fully-qualified target"},
                "action": {"type": "string", "enum": ["status", "restart", "stop", "start"]},
                "unit": {"type": "string", "description": "the systemd unit name, e.g. nginx.service"},
                "hypothesis": {"type": "string", "description": "why you're taking this action (required for mutations)"}
            },
            "required": ["target", "action", "unit"]
        })
    }

    fn risk(&self) -> RiskClass {
        // Coarse self-declared class before the concrete action is known —
        // Medium (never silently Read) so gating never under-classifies a
        // mutation before the classifier sees the real command.
        RiskClass::Medium
    }

    fn is_action(&self) -> bool {
        true
    }

    fn reads_only(&self, args: &Value) -> bool {
        risk_for(args["action"].as_str().unwrap_or_default()) == RiskClass::Read
    }

    fn allowed_in_heartbeat(&self) -> bool {
        // status is fine unattended; restart/stop/start still route through
        // the SAME autonomy gate as any other mutation — this only controls
        // whether the tool is offered at all during a heartbeat run, and a
        // scan legitimately wants to check status.
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let target_str = args["target"].as_str().ok_or_else(|| {
            ToolError::UserFacing("systemd requires a \"target\" argument".to_string())
        })?;
        let action = args["action"].as_str().ok_or_else(|| {
            ToolError::UserFacing("systemd requires an \"action\" argument".to_string())
        })?;
        let unit = args["unit"].as_str().ok_or_else(|| {
            ToolError::UserFacing("systemd requires a \"unit\" argument".to_string())
        })?;
        let hypothesis = args["hypothesis"].as_str().map(str::to_string);
        let command = compose(action, unit)?;
        let target = ctx.resolve_target_for(
            target_str,
            self.name(),
            &[crate::config::TargetKindName::Ssh, crate::config::TargetKindName::Local],
        )?;
        run_command(ctx, self.name(), target, command, risk_for(action), hypothesis).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FqTarget, Principal};
    use crate::policy::PolicyExecute;
    use crate::tools::executor::tests::RecordingPolicy;
    use std::sync::Arc;

    fn target() -> FqTarget {
        FqTarget::new("example", "prod", "web-1")
    }

    fn ctx_with(policy: Arc<dyn PolicyExecute>) -> ToolCtx {
        ToolCtx {
            call: Default::default(),
            principal: Principal::Agent { job: None },
            policy,
            known_targets: vec![target()],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        }
    }

    #[tokio::test]
    async fn restart_composes_systemctl_restart() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        SystemdTool
            .call(&ctx, json!({"target": "example::prod::web-1", "action": "restart", "unit": "nginx.service"}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].command, "systemctl restart nginx.service");
        assert_eq!(seen[0].declared_risk, RiskClass::Medium);
    }

    #[tokio::test]
    async fn status_is_read_risk() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        SystemdTool
            .call(
                &ctx,
                json!({"target": "example::prod::web-1", "action": "status", "unit": "nginx"}),
            )
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].declared_risk, RiskClass::Read);
    }

    #[tokio::test]
    async fn unit_name_with_shell_metacharacters_is_rejected() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = SystemdTool
            .call(&ctx, json!({"target": "example::prod::web-1", "action": "restart", "unit": "nginx; rm -rf /"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty(), "must never reach policy");
    }

    #[tokio::test]
    async fn unknown_action_is_user_facing() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy);
        let err = SystemdTool
            .call(
                &ctx,
                json!({"target": "example::prod::web-1", "action": "reload", "unit": "nginx"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }
}
