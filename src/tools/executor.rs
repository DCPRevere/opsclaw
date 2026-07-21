//! Shared plumbing for executor-backed tools (DESIGN.md §4 "Tool surface",
//! item 1): every tool that composes a concrete command line against a
//! target funnels through [`run_command`], which does exactly two things —
//! build the `policy::CommandRequest` from trusted context plus the
//! composed command, and turn the resulting `PolicyOutcome` into the
//! `ToolResult`/`ToolError` the agent loop expects. Tools own vocabulary
//! (what command to compose for "check disk usage"); this module owns the
//! ONE path from a composed command line to `ctx.policy.execute` — no tool
//! calls `PolicyExecute::execute` directly, so every executor-backed tool
//! reports its outcome identically.

use crate::domain::{FqTarget, RiskClass};
use crate::policy::{CommandRequest, PolicyOutcome};
use crate::tools::{ToolCtx, ToolError, ToolResult};

/// Compose and submit one command. `hypothesis` is the model's stated
/// working theory for why this command is worth running — threaded into
/// `CommandRequest` so an approval request (if this command needs one)
/// carries it, per DESIGN.md §4 "Approvals": "the request must carry enough
/// context ... for a human to decide from their phone."
pub async fn run_command(
    ctx: &ToolCtx,
    tool: &'static str,
    target: FqTarget,
    command: String,
    declared_risk: RiskClass,
    hypothesis: Option<String>,
) -> Result<ToolResult, ToolError> {
    let req = CommandRequest {
        principal: ctx.principal.clone(),
        tool: tool.to_string(),
        target,
        command,
        declared_risk,
        hypothesis,
        runbook: None,
    };
    let outcome = ctx
        .policy
        .execute(req)
        .await
        .map_err(|e| ToolError::Internal(format!("policy engine: {e}")))?;
    Ok(ToolResult { output: describe_outcome(outcome) })
}

/// Render a `PolicyOutcome` as the text handed back to the model. Every
/// branch states plainly what actually happened — DESIGN.md's "actions
/// require evidence" discipline (ported from gianna's persona rule) starts
/// here: the model is never told a command "ran" when it was blocked,
/// queued, or e-stopped.
fn describe_outcome(outcome: PolicyOutcome) -> String {
    match outcome {
        PolicyOutcome::Executed(out) => {
            let status = format!("exit {}", out.exit_code);
            let mut s = format!("ran ({status}, {}ms)", out.duration_ms);
            if !out.stdout.is_empty() {
                s.push_str(&format!("\nstdout:\n{}", out.stdout));
            }
            if !out.stderr.is_empty() {
                s.push_str(&format!("\nstderr:\n{}", out.stderr));
            }
            s
        }
        PolicyOutcome::NeedsApproval(id) => format!(
            "queued for human approval (request {id}) — this command has NOT run yet. \
             Tell the user it's awaiting approval; do not claim it happened."
        ),
        PolicyOutcome::Blocked { reason, dry_run_logged } => {
            let logged = if dry_run_logged { " (logged to the dry-run log)" } else { "" };
            format!("blocked by policy: {reason}{logged}. This command did NOT run.")
        }
        PolicyOutcome::EStopped => {
            "blocked: the emergency stop is engaged — nothing executes anywhere right now."
                .to_string()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domain::Principal;
    use crate::policy::{CommandRequest as CR, PolicyExecute};
    use crate::targets::ExecOutput;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Records every `CommandRequest` it's handed and returns a scripted
    /// outcome — the "fake Policy that records CommandRequests" pattern
    /// used across this codebase's policy-adjacent tests.
    pub(crate) struct RecordingPolicy {
        pub(crate) seen: Mutex<Vec<CR>>,
        pub(crate) outcome: Box<dyn Fn() -> PolicyOutcome + Send + Sync>,
    }

    impl RecordingPolicy {
        pub(crate) fn always_executes(exit_code: i32, stdout: &str) -> Self {
            let stdout = stdout.to_string();
            RecordingPolicy {
                seen: Mutex::new(Vec::new()),
                outcome: Box::new(move || {
                    PolicyOutcome::Executed(ExecOutput {
                        exit_code,
                        stdout: stdout.clone(),
                        stderr: String::new(),
                        duration_ms: 5,
                    })
                }),
            }
        }
    }

    #[async_trait]
    impl PolicyExecute for RecordingPolicy {
        async fn execute(&self, req: CR) -> crate::Result<PolicyOutcome> {
            self.seen.lock().unwrap().push(req);
            Ok((self.outcome)())
        }
    }

    fn target() -> FqTarget {
        FqTarget::new("remundo", "prod", "web-1")
    }

    fn ctx_with(policy: std::sync::Arc<dyn PolicyExecute>) -> ToolCtx {
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
    async fn run_command_builds_the_exact_command_request() {
        let policy = std::sync::Arc::new(RecordingPolicy::always_executes(0, "ok"));
        let ctx = ctx_with(policy.clone());
        run_command(
            &ctx,
            "ssh",
            target(),
            "uptime".into(),
            RiskClass::Read,
            Some("checking load".into()),
        )
        .await
        .unwrap();

        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].tool, "ssh");
        assert_eq!(seen[0].command, "uptime");
        assert_eq!(seen[0].declared_risk, RiskClass::Read);
        assert_eq!(seen[0].hypothesis.as_deref(), Some("checking load"));
        assert_eq!(seen[0].target, target());
        assert!(seen[0].runbook.is_none());
    }

    #[tokio::test]
    async fn executed_outcome_reports_exit_code_and_output() {
        let policy = std::sync::Arc::new(RecordingPolicy::always_executes(0, "5 days uptime"));
        let ctx = ctx_with(policy);
        let r = run_command(&ctx, "ssh", target(), "uptime".into(), RiskClass::Read, None)
            .await
            .unwrap();
        assert!(r.output.contains("exit 0"));
        assert!(r.output.contains("5 days uptime"));
    }

    #[tokio::test]
    async fn nonzero_exit_is_reported_honestly() {
        let policy = std::sync::Arc::new(RecordingPolicy::always_executes(1, ""));
        let ctx = ctx_with(policy);
        let r = run_command(&ctx, "ssh", target(), "false".into(), RiskClass::Read, None)
            .await
            .unwrap();
        assert!(r.output.contains("exit 1"));
    }

    #[tokio::test]
    async fn needs_approval_outcome_says_it_has_not_run() {
        struct Approval;
        #[async_trait]
        impl PolicyExecute for Approval {
            async fn execute(&self, _req: CR) -> crate::Result<PolicyOutcome> {
                Ok(PolicyOutcome::NeedsApproval(uuid::Uuid::nil()))
            }
        }
        let ctx = ctx_with(std::sync::Arc::new(Approval));
        let r = run_command(&ctx, "systemd", target(), "restart nginx".into(), RiskClass::Medium, None)
            .await
            .unwrap();
        assert!(r.output.contains("NOT run yet"));
        assert!(r.output.contains("awaiting approval") || r.output.contains("queued"));
    }

    #[tokio::test]
    async fn blocked_outcome_says_it_did_not_run() {
        struct Blocked;
        #[async_trait]
        impl PolicyExecute for Blocked {
            async fn execute(&self, _req: CR) -> crate::Result<PolicyOutcome> {
                Ok(PolicyOutcome::Blocked { reason: "observe autonomy".into(), dry_run_logged: true })
            }
        }
        let ctx = ctx_with(std::sync::Arc::new(Blocked));
        let r = run_command(&ctx, "docker", target(), "docker restart x".into(), RiskClass::Medium, None)
            .await
            .unwrap();
        assert!(r.output.contains("did NOT run"));
        assert!(r.output.contains("observe autonomy"));
    }

    #[tokio::test]
    async fn estopped_outcome_is_reported() {
        struct EStopped;
        #[async_trait]
        impl PolicyExecute for EStopped {
            async fn execute(&self, _req: CR) -> crate::Result<PolicyOutcome> {
                Ok(PolicyOutcome::EStopped)
            }
        }
        let ctx = ctx_with(std::sync::Arc::new(EStopped));
        let r = run_command(&ctx, "ssh", target(), "uptime".into(), RiskClass::Read, None)
            .await
            .unwrap();
        assert!(r.output.contains("emergency stop"));
    }

    #[tokio::test]
    async fn policy_error_is_an_internal_fault() {
        struct Faulty;
        #[async_trait]
        impl PolicyExecute for Faulty {
            async fn execute(&self, _req: CR) -> crate::Result<PolicyOutcome> {
                Err(crate::Error::other("db unreachable"))
            }
        }
        let ctx = ctx_with(std::sync::Arc::new(Faulty));
        let err = run_command(&ctx, "ssh", target(), "uptime".into(), RiskClass::Read, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }
}
