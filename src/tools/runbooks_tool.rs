//! Runbook queries (DESIGN.md §4 item 3: "incident + runbook queries") —
//! two tools over two DIFFERENT stores that answer two different questions:
//!
//! - [`RunbookListTool`] (`runbook_list`) — "what runbooks do you have?"
//!   over `crate::runbooks::RunbookStore`, the DEFINITION store (title,
//!   trigger summary, step count) loaded from
//!   `config.daemon.runbooks_dir`. Also joins in each runbook's success
//!   rate from `db::RunbookRunRepo` when that's wired, so a listing
//!   surfaces reliability at a glance.
//! - [`RunbookHistoryTool`] (`runbook_history`) — "what has `{name}` done
//!   historically?" over `db::RunbookRunRepo`, EXECUTION history. When
//!   `ctx.runbooks` is also wired, an unrecognized name is now resolved
//!   against the definition store first and reported as "no such runbook,
//!   did you mean one of these?" rather than the ambiguous "no recorded
//!   runs" (which used to conflate "never ran" with "doesn't exist") —
//!   this is the discover-then-inspect flow: `runbook_list` first to learn
//!   real names, `runbook_history` second to inspect one.
//!
//! Previously (before `RunbookStore` existed) this file only had
//! `runbook_history`, with a documented gap that there was no way to
//! discover runbook names at all — that gap is now closed by
//! `RunbookListTool`.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct RunbookListTool;

#[async_trait]
impl Tool for RunbookListTool {
    fn name(&self) -> &'static str {
        "runbook_list"
    }

    fn description(&self) -> &str {
        "List every runbook this daemon knows about: title, what triggers it (alert \
         categories/keywords/target glob), step count, and its success rate if it has run \
         history. Call this before runbook_history if you don't already know a runbook's \
         exact name."
    }

    fn schema(&self) -> Value {
        json!({"type": "object", "properties": {}})
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

    async fn call(&self, ctx: &ToolCtx, _args: Value) -> Result<ToolResult, ToolError> {
        let store = ctx.runbooks.as_ref().ok_or_else(|| {
            ToolError::Internal("runbook_list called with no runbook store wired".to_string())
        })?;

        let loaded = store.list();
        let errors = store.errors();

        if loaded.is_empty() && errors.is_empty() {
            return Ok(ToolResult {
                output: format!("no runbooks found in {}.", store.dir().display()),
            });
        }

        let mut out = String::new();
        for lr in &loaded {
            let fm = &lr.runbook.front_matter;
            let mut trigger_bits = Vec::new();
            if !fm.trigger.alert_categories.is_empty() {
                trigger_bits
                    .push(format!("categories: {}", fm.trigger.alert_categories.join(", ")));
            }
            if !fm.trigger.keywords.is_empty() {
                trigger_bits.push(format!("keywords: {}", fm.trigger.keywords.join(", ")));
            }
            if let Some(glob) = &fm.trigger.target_glob {
                trigger_bits.push(format!("target: {glob}"));
            }
            let trigger_summary = if trigger_bits.is_empty() {
                "no trigger configured".to_string()
            } else {
                trigger_bits.join("; ")
            };

            // Success rate is a best-effort JOIN: run history may not be
            // wired at all, or this runbook may simply have never run
            // (RunbookRunRepo::success_rate returns 0/0 for that — see its
            // own doc — which reads as "no data" below, not "0% reliable").
            let rate_note = if let Some(repo) = &ctx.runbook_runs {
                match repo.success_rate(&fm.title).await {
                    Ok(rate) if rate.total_runs > 0 => format!(
                        " — {}/{} runs succeeded ({:.0}%)",
                        rate.successful_runs,
                        rate.total_runs,
                        rate.rate * 100.0
                    ),
                    Ok(_) => " — no run history yet".to_string(),
                    Err(_) => String::new(), // best-effort join; a lookup failure just omits the note
                }
            } else {
                String::new()
            };

            out.push_str(&format!(
                "- {} ({} steps; {}){}\n",
                fm.title,
                lr.runbook.steps.len(),
                trigger_summary,
                rate_note
            ));
        }
        for e in &errors {
            out.push_str(&format!("- [FAILED TO LOAD] {}: {}\n", e.file, e.message));
        }
        Ok(ToolResult { output: out })
    }
}

pub struct RunbookHistoryTool;

#[async_trait]
impl Tool for RunbookHistoryTool {
    fn name(&self) -> &'static str {
        "runbook_history"
    }

    fn description(&self) -> &str {
        "Get the execution history and success rate for a NAMED runbook (its exact title — \
         call runbook_list first if you don't already know it). Useful to check whether a \
         runbook has been reliable before trusting it, or to see what it did last time it ran."
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
            ToolError::Internal(
                "runbook_history called with no runbook-run store wired".to_string(),
            )
        })?;
        let runbook_name = args["runbook_name"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "runbook_history requires a \"runbook_name\" argument".to_string(),
            )
        })?;
        let limit = args["limit"].as_i64().unwrap_or(5);

        // Discover-then-inspect: when the definition store is ALSO wired,
        // resolve the name against it first so an unrecognized name gets a
        // helpful "did you mean" instead of the ambiguous "no recorded
        // runs" (which used to conflate "never ran" with "doesn't exist").
        // Skipped gracefully when `ctx.runbooks` is absent — history
        // queries must still work standalone (a caller with only
        // `runbook_runs` wired, e.g. a narrower test context).
        if let Some(store) = &ctx.runbooks
            && store.get(runbook_name).is_none()
        {
            let known: Vec<String> =
                store.list().into_iter().map(|lr| lr.runbook.title().to_string()).collect();
            return Err(ToolError::UserFacing(format!(
                "no runbook named {runbook_name:?}. Known runbooks: {}.",
                if known.is_empty() { "(none loaded)".to_string() } else { known.join(", ") }
            )));
        }

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
                output: format!("no recorded runs for {runbook_name:?} — it has never run."),
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
    use crate::db::RunbookRunRepo;
    use crate::db::memory::InMemoryDb;
    use crate::domain::{FqTarget, Principal};
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use crate::runbooks::history::{RunbookRun, StepOutcome, StepStatus};
    use crate::runbooks::{Runbook, RunbookStore};
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

    fn runbook_src(title: &str, keywords: &[&str]) -> String {
        format!(
            "+++\ntitle = \"{title}\"\n\n[trigger]\nkeywords = {:?}\n+++\n- step one\n- step two\n",
            keywords
        )
    }

    fn base_ctx() -> ToolCtx {
        ToolCtx::for_tests(Principal::Agent { job: None }, Arc::new(NoopPolicy))
    }

    #[tokio::test]
    async fn list_reports_title_steps_and_trigger_summary() {
        let rb = Runbook::parse(&runbook_src("DLQ backlog triage", &["dlq"])).unwrap();
        let store = RunbookStore::from_parsed("/nonexistent", vec![("dlq.md".into(), rb)]);
        let mut ctx = base_ctx();
        ctx.runbooks = Some(Arc::new(store));

        let r = RunbookListTool.call(&ctx, json!({})).await.unwrap();
        assert!(r.output.contains("DLQ backlog triage"));
        assert!(r.output.contains("2 steps"));
        assert!(r.output.contains("keywords: dlq"));
    }

    #[tokio::test]
    async fn list_joins_success_rate_when_run_repo_wired() {
        let rb = Runbook::parse(&runbook_src("DLQ backlog triage", &["dlq"])).unwrap();
        let store = RunbookStore::from_parsed("/nonexistent", vec![("dlq.md".into(), rb)]);
        let db = InMemoryDb::new();
        RunbookRunRepo::record_run(&db, &run("DLQ backlog triage", true)).await.unwrap();
        RunbookRunRepo::record_run(&db, &run("DLQ backlog triage", false)).await.unwrap();

        let mut ctx = base_ctx();
        ctx.runbooks = Some(Arc::new(store));
        ctx.runbook_runs = Some(Arc::new(db));

        let r = RunbookListTool.call(&ctx, json!({})).await.unwrap();
        assert!(r.output.contains("1/2 runs succeeded"), "{}", r.output);
    }

    #[tokio::test]
    async fn list_notes_no_history_when_run_repo_wired_but_never_ran() {
        let rb = Runbook::parse(&runbook_src("Never run yet", &["x"])).unwrap();
        let store = RunbookStore::from_parsed("/nonexistent", vec![("nr.md".into(), rb)]);
        let mut ctx = base_ctx();
        ctx.runbooks = Some(Arc::new(store));
        ctx.runbook_runs = Some(Arc::new(InMemoryDb::new()));

        let r = RunbookListTool.call(&ctx, json!({})).await.unwrap();
        assert!(r.output.contains("no run history yet"));
    }

    #[tokio::test]
    async fn list_reports_load_errors_alongside_good_runbooks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("good.md"), runbook_src("Good runbook", &["x"])).unwrap();
        std::fs::write(dir.path().join("bad.md"), "not even front matter").unwrap();
        let store = crate::runbooks::RunbookStore::load(dir.path()).unwrap();

        let mut ctx = base_ctx();
        ctx.runbooks = Some(Arc::new(store));
        let r = RunbookListTool.call(&ctx, json!({})).await.unwrap();
        assert!(r.output.contains("Good runbook"));
        assert!(r.output.contains("FAILED TO LOAD"));
        assert!(r.output.contains("bad.md"));
    }

    #[tokio::test]
    async fn list_empty_store_says_so() {
        let store = RunbookStore::from_parsed("/nonexistent", vec![]);
        let mut ctx = base_ctx();
        ctx.runbooks = Some(Arc::new(store));
        let r = RunbookListTool.call(&ctx, json!({})).await.unwrap();
        assert!(r.output.contains("no runbooks found"));
    }

    #[tokio::test]
    async fn list_missing_store_is_internal_fault() {
        let ctx = base_ctx();
        let err = RunbookListTool.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }

    #[tokio::test]
    async fn history_reports_success_rate_and_recent_runs() {
        let db = InMemoryDb::new();
        RunbookRunRepo::record_run(&db, &run("DLQ backlog triage", true)).await.unwrap();
        RunbookRunRepo::record_run(&db, &run("DLQ backlog triage", false)).await.unwrap();
        let mut ctx = base_ctx();
        ctx.runbook_runs = Some(Arc::new(db));

        let r = RunbookHistoryTool
            .call(&ctx, json!({"runbook_name": "DLQ backlog triage"}))
            .await
            .unwrap();
        assert!(r.output.contains("1/2 runs succeeded"), "{}", r.output);
        assert!(r.output.contains("[ok]"));
        assert!(r.output.contains("[failed]"));
    }

    #[tokio::test]
    async fn history_unknown_name_says_no_recorded_runs_when_no_store_wired() {
        let mut ctx = base_ctx();
        ctx.runbook_runs = Some(Arc::new(InMemoryDb::new()));
        let r =
            RunbookHistoryTool.call(&ctx, json!({"runbook_name": "nonexistent"})).await.unwrap();
        assert!(r.output.contains("never run"));
    }

    #[tokio::test]
    async fn history_unknown_name_resolves_through_the_store_when_wired() {
        let rb = Runbook::parse(&runbook_src("DLQ backlog triage", &["dlq"])).unwrap();
        let store = RunbookStore::from_parsed("/nonexistent", vec![("dlq.md".into(), rb)]);
        let mut ctx = base_ctx();
        ctx.runbooks = Some(Arc::new(store));
        ctx.runbook_runs = Some(Arc::new(InMemoryDb::new()));

        let err = RunbookHistoryTool
            .call(&ctx, json!({"runbook_name": "totally made up"}))
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => {
                assert!(msg.contains("no runbook named"));
                assert!(msg.contains("DLQ backlog triage"), "names the real ones: {msg}");
            }
            _ => panic!("expected UserFacing"),
        }
    }

    #[tokio::test]
    async fn history_known_name_still_works_when_store_is_wired() {
        let rb = Runbook::parse(&runbook_src("DLQ backlog triage", &["dlq"])).unwrap();
        let store = RunbookStore::from_parsed("/nonexistent", vec![("dlq.md".into(), rb)]);
        let db = InMemoryDb::new();
        RunbookRunRepo::record_run(&db, &run("DLQ backlog triage", true)).await.unwrap();

        let mut ctx = base_ctx();
        ctx.runbooks = Some(Arc::new(store));
        ctx.runbook_runs = Some(Arc::new(db));

        let r = RunbookHistoryTool
            .call(&ctx, json!({"runbook_name": "DLQ backlog triage"}))
            .await
            .unwrap();
        assert!(r.output.contains("1/1 runs succeeded"));
    }

    #[tokio::test]
    async fn history_missing_name_argument_is_user_facing() {
        let mut ctx = base_ctx();
        ctx.runbook_runs = Some(Arc::new(InMemoryDb::new()));
        let err = RunbookHistoryTool.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[tokio::test]
    async fn history_missing_repo_is_internal_fault() {
        let ctx = base_ctx();
        let err = RunbookHistoryTool.call(&ctx, json!({"runbook_name": "x"})).await.unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }

    #[test]
    fn both_tools_are_read_only() {
        assert!(!RunbookListTool.is_action());
        assert!(!RunbookHistoryTool.is_action());
    }
}
