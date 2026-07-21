//! `runbook_history` — runbook RUN HISTORY queries (DESIGN.md §4 item 3:
//! "incident + runbook queries").
//!
//! **Known gap, reported rather than papered over**: there is no
//! runbook-DEFINITION store yet (no directory scan / `RunbookRepo` — only
//! `db::RunbookRunRepo`, which records EXECUTION history keyed by a
//! `runbook_name` the caller already knows, and `runbooks::` itself, which
//! only parses/matches/renders a `Runbook` handed to it, with no listing of
//! what runbook files exist on disk). So this tool can only answer "what has
//! `{name}` done historically and how often did it succeed" for a name the
//! model or operator already knows — it CANNOT answer "what runbooks do you
//! have?". A `runbook_list`/`RunbookRepo` tool is a follow-up once that
//! store exists.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct RunbookHistoryTool;

#[async_trait]
impl Tool for RunbookHistoryTool {
    fn name(&self) -> &'static str {
        "runbook_history"
    }

    fn description(&self) -> &str {
        "Get the execution history and success rate for a NAMED runbook (by its title). \
         There is currently no way to list what runbooks exist — you must already know the \
         name (e.g. from a runbook match, an operator mentioning one, or prior context). \
         Useful to check whether a runbook has been reliable before trusting it, or to see \
         what it did last time it ran."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "runbook_name": {"type": "string", "description": "the runbook's title, exactly as named"},
                "limit": {"type": "integer", "description": "max runs to return (default 5)"}
            },
            "required": ["runbook_name"]
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
        let repo = ctx.runbook_runs.as_ref().ok_or_else(|| {
            ToolError::Internal("runbook_history called with no runbook-run store wired".to_string())
        })?;
        let runbook_name = args["runbook_name"].as_str().ok_or_else(|| {
            ToolError::UserFacing("runbook_history requires a \"runbook_name\" argument".to_string())
        })?;
        let limit = args["limit"].as_i64().unwrap_or(5);

        let rate = repo
            .success_rate(runbook_name)
            .await
            .map_err(|e| ToolError::Internal(format!("runbook success-rate lookup failed: {e}")))?;
        let runs = repo
            .list_for_runbook(runbook_name, limit)
            .await
            .map_err(|e| ToolError::Internal(format!("runbook history lookup failed: {e}")))?;

        if rate.total_runs == 0 {
            return Ok(ToolResult {
                output: format!(
                    "no recorded runs for {runbook_name:?} — either it has never run, or the \
                     name doesn't match exactly."
                ),
            });
        }

        let mut out = format!(
            "{runbook_name:?}: {}/{} runs succeeded ({:.0}%)\n",
            rate.successful_runs,
            rate.total_runs,
            rate.rate * 100.0
        );
        for r in &runs {
            let outcome = if r.succeeded() { "ok" } else { "failed" };
            out.push_str(&format!(
                "- {} against {} [{outcome}] ({} steps)\n",
                r.started_at.to_rfc3339(),
                r.target,
                r.steps.len()
            ));
        }
        Ok(ToolResult { output: out })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory::InMemoryDb;
    use crate::db::RunbookRunRepo;
    use crate::domain::{FqTarget, Principal};
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use crate::runbooks::history::{RunbookRun, StepOutcome, StepStatus};
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

    fn run(name: &str, ok: bool) -> RunbookRun {
        RunbookRun {
            id: Uuid::new_v4(),
            runbook: name.into(),
            target: FqTarget::new("remundo", "prod", "web-1"),
            principal: None,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            steps: vec![StepOutcome {
                step_index: 0,
                status: if ok { StepStatus::Ok } else { StepStatus::Failed },
                output: String::new(),
            }],
        }
    }

    fn ctx_with(runs: Arc<dyn RunbookRunRepo>) -> ToolCtx {
        ToolCtx {
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![],
            incidents: None,
            approvals: None,
            runbook_runs: Some(runs),
            memory: None,
            config: None,
            endpoints: None,
        }
    }

    #[tokio::test]
    async fn reports_success_rate_and_recent_runs() {
        let db = InMemoryDb::new();
        RunbookRunRepo::record_run(&db, &run("DLQ backlog triage", true)).await.unwrap();
        RunbookRunRepo::record_run(&db, &run("DLQ backlog triage", false)).await.unwrap();
        let db: Arc<dyn RunbookRunRepo> = Arc::new(db);
        let ctx = ctx_with(db);
        let r = RunbookHistoryTool
            .call(&ctx, json!({"runbook_name": "DLQ backlog triage"}))
            .await
            .unwrap();
        assert!(r.output.contains("1/2 runs succeeded"), "{}", r.output);
        assert!(r.output.contains("[ok]"));
        assert!(r.output.contains("[failed]"));
    }

    #[tokio::test]
    async fn unknown_runbook_name_says_no_recorded_runs() {
        let db: Arc<dyn RunbookRunRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db);
        let r = RunbookHistoryTool
            .call(&ctx, json!({"runbook_name": "nonexistent"}))
            .await
            .unwrap();
        assert!(r.output.contains("no recorded runs"));
    }

    #[tokio::test]
    async fn missing_name_argument_is_user_facing() {
        let db: Arc<dyn RunbookRunRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db);
        let err = RunbookHistoryTool.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
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
        };
        let err = RunbookHistoryTool
            .call(&ctx, json!({"runbook_name": "x"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }
}
