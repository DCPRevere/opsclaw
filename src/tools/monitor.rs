//! `monitor` — cpu/mem/disk/proc overview vocabulary (DESIGN.md §4 item 1,
//! brief §10). A read-only diagnostic tool: it composes the well-known
//! command for the requested view rather than letting the model free-write
//! arbitrary shell, so a scan step is always the SAME evidence-gathering
//! command regardless of model phrasing — DESIGN.md's environment-
//! scepticism guidance (evaluate writable mounts, not every mount; `df`
//! lies under gVisor's host-bind mounts) starts with consistent, known
//! commands to reason about.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct MonitorTool;

/// The composed command for each view. `df -P` (POSIX output format, one
/// line per mount, no wrapping) makes the evidence easy for the MODEL to
/// parse reliably rather than a plain `df -h`'s multi-line-wrap behaviour
/// on narrow terminals.
fn command_for(view: &str) -> Result<&'static str, ToolError> {
    match view {
        "cpu" => Ok("top -bn1 | head -n 12"),
        "mem" => Ok("free -m"),
        "disk" => Ok("df -P"),
        "proc" => Ok("ps aux --sort=-%cpu | head -n 20"),
        other => Err(ToolError::UserFacing(format!(
            "unknown monitor view {other:?}. Valid views: cpu, mem, disk, proc."
        ))),
    }
}

#[async_trait]
impl Tool for MonitorTool {
    fn name(&self) -> &'static str {
        "monitor"
    }

    fn description(&self) -> &str {
        "Get a cpu/mem/disk/proc snapshot from a target — a quick, consistent overview \
         (top, free, df, ps) rather than composing your own command; use `ssh` for anything \
         more specific. Remember environment scepticism: a single reading proves little on \
         its own (df can lie under a sandboxed/bind-mounted filesystem) — corroborate with a \
         second view or a second reading over time before concluding."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "fully-qualified target"},
                "view": {"type": "string", "enum": ["cpu", "mem", "disk", "proc"]}
            },
            "required": ["target", "view"]
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
        let target_str = args["target"].as_str().ok_or_else(|| {
            ToolError::UserFacing("monitor requires a \"target\" argument".to_string())
        })?;
        let view = args["view"].as_str().ok_or_else(|| {
            ToolError::UserFacing("monitor requires a \"view\" argument".to_string())
        })?;
        let command = command_for(view)?;
        let target = ctx.resolve_target_for(
            target_str,
            self.name(),
            &[crate::config::TargetKindName::Ssh, crate::config::TargetKindName::Local],
        )?;
        run_command(ctx, self.name(), target, command.to_string(), self.risk(), None).await
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
    async fn disk_view_composes_df() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        MonitorTool
            .call(&ctx, json!({"target": "example::prod::web-1", "view": "disk"}))
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].command, "df -P");
    }

    #[tokio::test]
    async fn mem_view_composes_free() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        MonitorTool
            .call(&ctx, json!({"target": "example::prod::web-1", "view": "mem"}))
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].command, "free -m");
    }

    #[tokio::test]
    async fn cpu_and_proc_views_compose_expected_commands() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        MonitorTool
            .call(&ctx, json!({"target": "example::prod::web-1", "view": "cpu"}))
            .await
            .unwrap();
        assert!(policy.seen.lock().unwrap()[0].command.starts_with("top"));
        MonitorTool
            .call(&ctx, json!({"target": "example::prod::web-1", "view": "proc"}))
            .await
            .unwrap();
        assert!(policy.seen.lock().unwrap()[1].command.starts_with("ps"));
    }

    #[tokio::test]
    async fn unknown_view_is_user_facing_and_never_reaches_policy() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = MonitorTool
            .call(&ctx, json!({"target": "example::prod::web-1", "view": "network"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty(), "must not submit anything to policy");
    }

    #[test]
    fn is_read_only() {
        assert!(!MonitorTool.is_action());
        assert_eq!(MonitorTool.risk(), RiskClass::Read);
    }
}
