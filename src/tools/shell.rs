//! `shell` — the daemon host as the `local` target (DESIGN.md §4 item 1).
//! Same shape as [`crate::tools::ssh`] but addresses a `local`-kind target:
//! a daemon placed adjacent to a fleet (a bastion) still needs to run local
//! diagnostics (disk on the bastion itself, checking its own resolv.conf,
//! etc.) without an ssh hop to itself.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct ShellTool;

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &'static str {
        "shell"
    }

    fn description(&self) -> &str {
        "Run a shell command on the daemon's OWN host (a configured `local`-kind target) — \
         use this for diagnostics/remediation on the machine the daemon itself runs on \
         (e.g. a bastion host), never as a substitute for `ssh` against a remote target. \
         The exact command you give is what runs, verbatim — classified and gated by policy \
         before execution."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "fully-qualified local target, e.g. remundo::prod::bastion"},
                "command": {"type": "string", "description": "the exact shell command to run"},
                "hypothesis": {"type": "string", "description": "why you're running this command"}
            },
            "required": ["target", "command"]
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
            ToolError::UserFacing("shell requires a \"target\" argument".to_string())
        })?;
        let command = args["command"].as_str().ok_or_else(|| {
            ToolError::UserFacing("shell requires a \"command\" argument".to_string())
        })?;
        let hypothesis = args["hypothesis"].as_str().map(str::to_string);
        let target = ctx.resolve_target(target_str)?;
        run_command(ctx, self.name(), target, command.to_string(), self.risk(), hypothesis).await
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
        FqTarget::new("remundo", "prod", "bastion")
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
        }
    }

    #[tokio::test]
    async fn composes_the_exact_command_line() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, "ok"));
        let ctx = ctx_with(policy.clone());
        ShellTool
            .call(&ctx, json!({"target": "remundo::prod::bastion", "command": "df -h"}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].tool, "shell");
        assert_eq!(seen[0].command, "df -h");
    }

    #[test]
    fn declares_action_and_medium_risk() {
        assert!(ShellTool.is_action());
        assert_eq!(ShellTool.risk(), RiskClass::Medium);
    }
}
