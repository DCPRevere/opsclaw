//! `docker` — container inspection/management vocabulary (DESIGN.md §4
//! item 1, brief §10). Same discipline as [`crate::tools::systemd`]: a
//! small fixed verb set composed into a `docker` command line, never
//! free-text shell.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct DockerTool;

/// Loose container name/id validation — alnum, `-_.` only — to keep
/// argument injection out of the composed line, same rationale as
/// `systemd::valid_unit_name`.
fn valid_container_ref(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

fn compose(action: &str, container: Option<&str>) -> Result<String, ToolError> {
    match action {
        "ps" => Ok("docker ps -a".to_string()),
        "logs" | "restart" | "stop" | "start" => {
            let container = container.ok_or_else(|| {
                ToolError::UserFacing(format!("docker {action} requires a \"container\" argument"))
            })?;
            if !valid_container_ref(container) {
                return Err(ToolError::UserFacing(format!(
                    "invalid container reference {container:?} — expected a plain name/id \
                     (letters, digits, -_. only)"
                )));
            }
            match action {
                "logs" => Ok(format!("docker logs --tail 200 {container}")),
                _ => Ok(format!("docker {action} {container}")),
            }
        }
        other => Err(ToolError::UserFacing(format!(
            "unknown docker action {other:?}. Valid actions: ps, logs, restart, stop, start."
        ))),
    }
}

fn risk_for(action: &str) -> RiskClass {
    match action {
        "ps" | "logs" => RiskClass::Read,
        _ => RiskClass::Medium,
    }
}

#[async_trait]
impl Tool for DockerTool {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn description(&self) -> &str {
        "Inspect or manage docker containers on a target: ps (list, read-only), logs \
         (read-only, last 200 lines), restart, stop, start. Check logs/ps before restarting \
         a container to confirm it's actually the problem."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "fully-qualified target"},
                "action": {"type": "string", "enum": ["ps", "logs", "restart", "stop", "start"]},
                "container": {"type": "string", "description": "container name or id (required for logs/restart/stop/start)"},
                "hypothesis": {"type": "string", "description": "why you're taking this action (required for mutations)"}
            },
            "required": ["target", "action"]
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Medium
    }

    fn is_action(&self) -> bool {
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let target_str = args["target"].as_str().ok_or_else(|| {
            ToolError::UserFacing("docker requires a \"target\" argument".to_string())
        })?;
        let action = args["action"].as_str().ok_or_else(|| {
            ToolError::UserFacing("docker requires an \"action\" argument".to_string())
        })?;
        let container = args["container"].as_str();
        let hypothesis = args["hypothesis"].as_str().map(str::to_string);
        let command = compose(action, container)?;
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
    async fn ps_needs_no_container_and_is_read_risk() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        DockerTool
            .call(&ctx, json!({"target": "example::prod::web-1", "action": "ps"}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].command, "docker ps -a");
        assert_eq!(seen[0].declared_risk, RiskClass::Read);
    }

    #[tokio::test]
    async fn logs_composes_tail_200() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        DockerTool
            .call(
                &ctx,
                json!({"target": "example::prod::web-1", "action": "logs", "container": "api"}),
            )
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].command, "docker logs --tail 200 api");
    }

    #[tokio::test]
    async fn restart_requires_container() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy);
        let err = DockerTool
            .call(&ctx, json!({"target": "example::prod::web-1", "action": "restart"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[tokio::test]
    async fn container_ref_with_metacharacters_is_rejected() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = DockerTool
            .call(&ctx, json!({"target": "example::prod::web-1", "action": "restart", "container": "api; rm -rf /"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty());
    }
}
