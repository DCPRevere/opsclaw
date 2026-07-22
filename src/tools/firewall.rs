//! `firewall` — firewall state vocabulary (DESIGN.md §4 item 1, brief §10
//! "Diagnostic"). v1 is deliberately READ-ONLY: a single `status` action
//! composing `iptables -L -n -v` (rules, packet/byte counters, numeric —
//! no reverse-DNS stalls). Mutating verbs (open/close a port, flush a
//! chain) are future vocabulary once approval flows have soak time; the
//! `action` argument exists NOW, rather than the tool taking no args, so
//! adding them later is additive for the model, not a schema break. The
//! tool self-declares `Read`, but the composed line still goes through the
//! policy classifier as it will actually run (the `ab058ec` discipline) —
//! declared risk can be RAISED there, never lowered, so a future
//! mis-declared verb can't sneak under the gate. Target is REQUIRED:
//! firewall state is per-host, and there is no meaningful "the daemon's
//! vantage" fallback like `dns`/`cert` have — guessing a host for a
//! security-posture read would be worse than asking.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct FirewallTool;

fn compose(action: &str) -> Result<&'static str, ToolError> {
    match action {
        "status" => Ok("iptables -L -n -v"),
        other => Err(ToolError::UserFacing(format!(
            "unknown firewall action {other:?}. Valid actions: status. (Firewall mutations \
             are not part of this tool's vocabulary yet.)"
        ))),
    }
}

#[async_trait]
impl Tool for FirewallTool {
    fn name(&self) -> &'static str {
        "firewall"
    }

    fn description(&self) -> &str {
        "Read a target's firewall state (iptables -L -n -v): chains, rules, and \
         packet/byte counters. Use it to check whether traffic you expected is being \
         dropped or a port you need is filtered. Read-only — this tool cannot change \
         firewall rules; propose rule changes to a human via the notify tool instead."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "fully-qualified target whose firewall to inspect"},
                "action": {"type": "string", "enum": ["status"], "description": "only \"status\" exists today"}
            },
            "required": ["target", "action"]
        })
    }

    fn risk(&self) -> RiskClass {
        // v1's whole vocabulary is one read; when mutating verbs land this
        // becomes Medium like `systemd` (coarse class must never silently
        // under-declare a mutation).
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
            ToolError::UserFacing("firewall requires a \"target\" argument".to_string())
        })?;
        let action = args["action"].as_str().ok_or_else(|| {
            ToolError::UserFacing("firewall requires an \"action\" argument".to_string())
        })?;
        let command = compose(action)?;
        let target = ctx.resolve_target(target_str)?;
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
        FqTarget::new("remundo", "prod", "web-1")
    }

    fn ctx_with(policy: Arc<dyn PolicyExecute>) -> ToolCtx {
        let mut ctx = ToolCtx::for_tests(Principal::Agent { job: None }, policy);
        ctx.known_targets = vec![target()];
        ctx
    }

    #[tokio::test]
    async fn status_composes_the_iptables_read() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, "Chain INPUT"));
        let ctx = ctx_with(policy.clone());
        FirewallTool
            .call(&ctx, json!({"target": "remundo::prod::web-1", "action": "status"}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].command, "iptables -L -n -v");
        assert_eq!(seen[0].declared_risk, RiskClass::Read);
        assert_eq!(seen[0].target, target());
    }

    #[tokio::test]
    async fn unknown_action_is_rejected_and_never_reaches_policy() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = FirewallTool
            .call(&ctx, json!({"target": "remundo::prod::web-1", "action": "flush"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty(), "must never reach policy");
    }

    #[tokio::test]
    async fn missing_target_is_user_facing() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = FirewallTool.call(&ctx, json!({"action": "status"})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn is_read_only() {
        assert!(!FirewallTool.is_action());
        assert_eq!(FirewallTool.risk(), RiskClass::Read);
        assert!(FirewallTool.allowed_in_heartbeat());
    }
}
