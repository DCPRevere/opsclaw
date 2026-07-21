//! `ssh` — the raw command runner against a target (DESIGN.md §4 item 1).
//! Composes exactly the command line the model gives it; risk classification
//! of the concrete string happens in `policy::classify`, not here — this
//! tool only supplies its coarse self-declared class and lets the choke
//! point raise it per command.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct SshTool;

#[async_trait]
impl Tool for SshTool {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn description(&self) -> &str {
        "Run a shell command on a target over SSH. Use for diagnostics (uptime, df, ps, \
         journalctl, ...) and remediation (restart a process, clear a lock file). The exact \
         command you give is what runs, verbatim — classified and gated by policy before \
         execution. `target` must be one of the targets you've been told about; state a \
         `hypothesis` for WHY you're running this so a human reviewing an approval request \
         understands the reasoning."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "fully-qualified target, e.g. remundo::prod::web-1"},
                "command": {"type": "string", "description": "the exact shell command to run"},
                "hypothesis": {"type": "string", "description": "why you're running this command"}
            },
            "required": ["target", "command"]
        })
    }

    fn risk(&self) -> RiskClass {
        // ssh can run anything — the classifier does the real work per
        // command; the coarse declared class starts at Medium (never
        // silently Read) so an unclassified/unknown command pattern doesn't
        // default to auto-executing.
        RiskClass::Medium
    }

    fn is_action(&self) -> bool {
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        // Diagnostics during a scan are exactly what ssh is for; the
        // classifier/gate still blocks mutations at observe/suggest as
        // normal — this only controls whether the tool APPEARS at all.
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let target_str = args["target"].as_str().ok_or_else(|| {
            ToolError::UserFacing("ssh requires a \"target\" argument".to_string())
        })?;
        let command = args["command"].as_str().ok_or_else(|| {
            ToolError::UserFacing("ssh requires a \"command\" argument".to_string())
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
        FqTarget::new("remundo", "prod", "web-1")
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
    async fn composes_the_exact_command_line() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, "up 5 days"));
        let ctx = ctx_with(policy.clone());
        SshTool
            .call(&ctx, json!({"target": "remundo::prod::web-1", "command": "uptime", "hypothesis": "check load"}))
            .await
            .unwrap();

        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].tool, "ssh");
        assert_eq!(seen[0].command, "uptime");
        assert_eq!(seen[0].target, target());
        assert_eq!(seen[0].hypothesis.as_deref(), Some("check load"));
    }

    #[tokio::test]
    async fn unknown_target_is_a_user_facing_error_naming_the_valid_ones() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy);
        let err = SshTool
            .call(&ctx, json!({"target": "unknown::env::x", "command": "uptime"}))
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => {
                assert!(msg.contains("unknown target"));
                assert!(msg.contains("remundo::prod::web-1"));
            }
            _ => panic!("expected UserFacing"),
        }
    }

    #[tokio::test]
    async fn missing_command_argument_is_user_facing() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy);
        let err = SshTool.call(&ctx, json!({"target": "remundo::prod::web-1"})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[test]
    fn declares_action_and_medium_risk() {
        assert!(SshTool.is_action());
        assert_eq!(SshTool.risk(), RiskClass::Medium);
        assert!(SshTool.allowed_in_heartbeat());
    }
}
