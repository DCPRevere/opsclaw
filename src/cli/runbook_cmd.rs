//! `opsclaw-cli runbook init/list/show/run` (brief §7: "`runbook
//! init/list/show/run --target ... --var k=v`").
//!
//! `list`/`show`'s directory-scan/parse logic DELEGATES to
//! `runbooks::RunbookStore` (the runbook definition store built for
//! `tools::runbooks_tool::RunbookListTool`) rather than duplicating it —
//! this file used to own that scan loop directly (before `RunbookStore`
//! existed, `runbooks/mod.rs` was explicitly "no filesystem-scanning
//! helper... anywhere in the library", so this was the one place it lived).
//! Public function signatures for `init`/`list`/`show`/`runbooks_dir` are
//! UNCHANGED (all still `&Path`-based) so `bin/cli/main.rs`'s existing call
//! sites need no changes.
//!
//! ## `run` — the execution engine
//!
//! Every step's command goes through `ctx.policy.execute` — the SAME choke
//! point every tool call goes through (DESIGN.md §4: "no tool owns a
//! connection; there is one execution path per target type, and audit and
//! policy live there"). This module composes NO new execution path: it
//! builds a `policy::CommandRequest` per rendered step (mirroring
//! `tools::executor::run_command`'s shape, but that helper isn't reused
//! directly — it takes a `ToolCtx`, which needs an LLM/tool-registry this
//! command has no business constructing for a plain "run this runbook"
//! invocation) and calls `Arc<dyn PolicyExecute>::execute` on it directly.
//! `CommandRequest.runbook` is set to the runbook's title, which is what
//! unlocks execution at `act_on_known` without a fresh per-step approval
//! (DESIGN.md §4 Runbooks: "a runbook match is the pre-approval that
//! unlocks `act_on_known`") — this is legitimate here because `run` is
//! itself an OPERATOR-INITIATED action naming an already-authored,
//! human-reviewed runbook by title, the exact trust boundary that
//! `runbook` front matter authoring is meant to establish; it is not a
//! model free-composing a command and merely claiming a runbook match.
//!
//! Needs the full daemon wiring (`boot::daemon_state` — same as `chat`),
//! not just a bare DB connection: real command execution needs the policy
//! engine, which needs the executor registry, e-stop, and audit writer.
//! `bin/cli/main.rs`'s `Runbook Run` arm boots it the same way `Chat` does.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::Result;
use crate::domain::{FqTarget, Principal};
use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
use crate::runbooks::{INIT_TEMPLATE, OnFail, Runbook, RunbookStore, StepOutcome, StepStatus};

/// Where `runbook` commands look for runbook files: `<opsclaw_home>/runbooks/`.
/// Matches `config::DaemonCfg::runbooks_dir`'s default — kept as a free
/// function (rather than requiring a `Config` here) since the CLI's local
/// commands work from `opsclaw_home` directly, independent of a loaded
/// `Config`.
pub fn runbooks_dir(opsclaw_home: &Path) -> PathBuf {
    opsclaw_home.join("runbooks")
}

/// Write a fresh starter file at `<runbooks_dir>/<name>.md`. Refuses to
/// overwrite an existing file (an operator's edited runbook is exactly the
/// kind of local knowledge `init` must never silently clobber).
pub fn init(opsclaw_home: &Path, name: &str) -> Result<PathBuf> {
    let dir = runbooks_dir(opsclaw_home);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{name}.md"));
    if path.exists() {
        return Err(crate::Error::Config(format!(
            "{} already exists — edit it directly rather than re-running init",
            path.display()
        )));
    }
    std::fs::write(&path, INIT_TEMPLATE)?;
    Ok(path)
}

#[derive(Debug, Serialize)]
pub struct RunbookSummary {
    pub file: String,
    pub title: String,
    pub steps: usize,
    pub alert_categories: Vec<String>,
    pub keywords: Vec<String>,
    pub target_glob: Option<String>,
    /// Success-rate join from run history (brief §7: "per-runbook
    /// success-rate tracking with low scorers surfaced for review").
    /// `None` when history isn't available — plain [`list`] without a DB,
    /// or a runbook that has never run — which the listing renders as no
    /// note at all, not "0% reliable".
    pub success: Option<SuccessSummary>,
}

/// One runbook's aggregated run history, as joined into [`RunbookSummary`]
/// by [`list_with_history`].
#[derive(Debug, Serialize)]
pub struct SuccessSummary {
    pub successful_runs: i64,
    pub total_runs: i64,
    pub rate: f64,
    /// The brief-§7 review flag: enough runs to be meaningful at a rate at
    /// or below the threshold (`runbooks::low_success_from_rate` — one rule
    /// shared with the `runbook_list` tool).
    pub low_success: bool,
}

/// List every runbook under the opsclaw home's runbooks dir, via
/// `RunbookStore`. A file that failed to parse is reported as an error
/// entry (`Err` in the returned vec's position) rather than aborting the
/// whole listing — one bad runbook must not hide every other one from
/// `list` — same contract as before the `RunbookStore` refactor, just
/// sourced from the store's `list()`/`errors()` instead of a bespoke scan.
/// Order: good runbooks first (store's title-sorted order), then errors —
/// this is a behavioural note for callers that cared about the OLD
/// per-directory-entry interleaved order: `main.rs`'s only consumer prints
/// each entry without depending on interleaving, so this is safe.
pub fn list(opsclaw_home: &Path) -> Result<Vec<std::result::Result<RunbookSummary, String>>> {
    let store = RunbookStore::load(runbooks_dir(opsclaw_home))?;
    let mut out: Vec<std::result::Result<RunbookSummary, String>> = store
        .list()
        .into_iter()
        .map(|lr| {
            Ok(RunbookSummary {
                file: lr.file,
                title: lr.runbook.front_matter.title.clone(),
                steps: lr.runbook.steps.len(),
                alert_categories: lr.runbook.front_matter.trigger.alert_categories.clone(),
                keywords: lr.runbook.front_matter.trigger.keywords.clone(),
                target_glob: lr.runbook.front_matter.trigger.target_glob.clone(),
                success: None,
            })
        })
        .collect();
    out.extend(store.errors().into_iter().map(|e| Err(format!("{}: {}", e.file, e.message))));
    Ok(out)
}

/// [`list`], plus a per-runbook success-rate join from `runs` (brief §7:
/// low scorers get surfaced for review — `main.rs` renders the flagged ones
/// with the `runbooks::low_success_marker` text). The join is best-effort,
/// same posture as `tools::runbooks_tool`'s rate note: a lookup failure or
/// a runbook with zero recorded runs just leaves `success` as `None` — it
/// must never fail the listing, which has to keep working on a host whose
/// daemon has barely (or never) run.
pub async fn list_with_history(
    opsclaw_home: &Path,
    runs: &Arc<dyn crate::db::RunbookRunRepo>,
) -> Result<Vec<std::result::Result<RunbookSummary, String>>> {
    let mut summaries = list(opsclaw_home)?;
    for entry in summaries.iter_mut().flatten() {
        if let Ok(rate) = runs.success_rate(&entry.title).await
            && rate.total_runs > 0
        {
            entry.success = Some(SuccessSummary {
                successful_runs: rate.successful_runs,
                total_runs: rate.total_runs,
                rate: rate.rate,
                low_success: crate::runbooks::low_success_from_rate(rate.total_runs, rate.rate),
            });
        }
    }
    Ok(summaries)
}

/// Parse and return one runbook by file stem (`show foo` reads
/// `<runbooks_dir>/foo.md`). Reads the file directly (not via the store's
/// title-keyed lookup) because `show`'s contract is "by file stem", and a
/// runbook's file name and its `title` front-matter field are deliberately
/// allowed to differ (the store's own doc: "the file path can move, the
/// title is what an operator recognizes") — looking this up by title
/// through the store would silently change `show`'s addressing scheme.
pub fn show(opsclaw_home: &Path, name: &str) -> Result<Runbook> {
    let path = runbooks_dir(opsclaw_home).join(format!("{name}.md"));
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| crate::Error::Config(format!("{}: {e}", path.display())))?;
    Runbook::parse(&raw)
}

/// One step's rendered command plus how it went — the human-facing
/// summary `run`'s caller prints; a parallel, denser shape to
/// `runbooks::StepOutcome` (which is what actually gets persisted) because
/// this one also carries the rendered command text (not persisted — the
/// front-matter + `--var`s that produced it already are, via the stored
/// `RunbookRun`... no: see `record_run`'s call site — the command text is
/// NOT separately persisted today, only in this in-process summary; a
/// future wave wanting it in history should extend `StepOutcome` itself
/// rather than have this module carry a shadow copy).
#[derive(Debug, Serialize)]
pub struct StepReport {
    pub index: usize,
    pub text: String,
    pub command: Option<String>,
    pub status: String,
    pub output: String,
}

#[derive(Debug, Serialize)]
pub struct RunOutcome {
    pub run_id: Uuid,
    pub runbook: String,
    pub target: String,
    pub steps: Vec<StepReport>,
    pub succeeded: bool,
}

fn step_status_str(s: StepStatus) -> &'static str {
    match s {
        StepStatus::Ok => "ok",
        StepStatus::Failed => "failed",
        StepStatus::Skipped => "skipped",
        StepStatus::Retried => "retried",
    }
}

/// Run every step of the runbook titled `title` against `target`,
/// substituting `cli_vars` (plus the runbook's own `default_vars` and
/// target-derived auto vars — see `Runbook::render_all`), executing each
/// step's command through `policy` (module doc: the one choke point), and
/// recording the full outcome via `runs` (`db::RunbookRunRepo`).
///
/// Per-step failure handling follows each step's own `(on-fail: ...)`
/// marker (`OnFail`, default `Abort`):
/// - `Abort` (default): stop the whole run at the first failure; later
///   steps are recorded `Skipped`, never attempted.
/// - `Continue`: record the failure and move on to the next step.
/// - `Retry`: run the step a second time immediately; if the retry also
///   fails, treat it as `Continue` (record `Failed`, keep going) — a
///   runbook step is not worth retrying forever from an interactive `run`
///   (unlike, say, a network client's transient-error backoff), and an
///   infinite/long retry loop would be a surprising thing for an operator
///   to be stuck waiting on.
///
/// A step with no `command` (pure prose, e.g. "confirm the signal before
/// acting") is recorded `Ok` with empty output — there is nothing to
/// execute, and a prose-only step must never block or fail a run.
pub async fn run(
    store: &RunbookStore,
    policy: &Arc<dyn PolicyExecute>,
    runs: &Arc<dyn crate::db::RunbookRunRepo>,
    principal: Principal,
    title: &str,
    target: &FqTarget,
    cli_vars: &BTreeMap<String, String>,
) -> Result<RunOutcome> {
    let loaded = store.get(title).ok_or_else(|| {
        crate::Error::Config(format!(
            "no runbook titled {title:?} — run `opsclaw-cli runbook list` to see what's loaded"
        ))
    })?;
    let rendered = loaded.runbook.render_all(Some(target), cli_vars)?;

    let run_id = Uuid::new_v4();
    let started_at = Utc::now();
    let mut reports = Vec::with_capacity(rendered.len());
    let mut outcomes = Vec::with_capacity(rendered.len());
    let mut aborted = false;

    for (index, (step, command)) in rendered.into_iter().enumerate() {
        if aborted {
            reports.push(StepReport {
                index,
                text: step.text.clone(),
                command: command.clone(),
                status: step_status_str(StepStatus::Skipped).to_string(),
                output: String::new(),
            });
            outcomes.push(StepOutcome {
                step_index: index,
                status: StepStatus::Skipped,
                output: String::new(),
            });
            continue;
        }

        let Some(cmd) = command else {
            // Prose-only step: nothing to run, always Ok (see doc above).
            reports.push(StepReport {
                index,
                text: step.text.clone(),
                command: None,
                status: step_status_str(StepStatus::Ok).to_string(),
                output: String::new(),
            });
            outcomes.push(StepOutcome {
                step_index: index,
                status: StepStatus::Ok,
                output: String::new(),
            });
            continue;
        };

        let (status, output) = run_one_step(policy, &principal, title, target, &cmd).await;

        let final_status = if status == StepStatus::Failed && step.on_fail == OnFail::Retry {
            // One immediate retry; a second failure is just Failed (module
            // doc: no unbounded retry from an interactive `run`).
            let (retry_status, retry_output) =
                run_one_step(policy, &principal, title, target, &cmd).await;
            if retry_status == StepStatus::Ok {
                reports.push(StepReport {
                    index,
                    text: step.text.clone(),
                    command: Some(cmd.clone()),
                    status: step_status_str(StepStatus::Retried).to_string(),
                    output: retry_output.clone(),
                });
                outcomes.push(StepOutcome {
                    step_index: index,
                    status: StepStatus::Retried,
                    output: retry_output,
                });
                continue;
            }
            retry_status
        } else {
            status
        };

        reports.push(StepReport {
            index,
            text: step.text.clone(),
            command: Some(cmd.clone()),
            status: step_status_str(final_status).to_string(),
            output: output.clone(),
        });
        outcomes.push(StepOutcome { step_index: index, status: final_status, output });

        if final_status == StepStatus::Failed && step.on_fail == OnFail::Abort {
            aborted = true;
        }
    }

    let record = crate::runbooks::RunbookRun {
        id: run_id,
        runbook: title.to_string(),
        target: target.clone(),
        principal: Some(principal),
        started_at,
        finished_at: Some(Utc::now()),
        steps: outcomes,
    };
    let succeeded = record.succeeded();
    runs.record_run(&record).await?;

    Ok(RunOutcome {
        run_id,
        runbook: title.to_string(),
        target: target.to_string(),
        steps: reports,
        succeeded,
    })
}

/// Execute one rendered command through the policy choke point and reduce
/// its `PolicyOutcome` to a `(StepStatus, output-for-humans)` pair. A
/// queued/blocked/e-stopped outcome is `Failed` from the runbook's
/// perspective (module doc's abort/continue/retry handling above treats
/// "did not run to completion" uniformly, whatever the reason) — but the
/// reason is preserved verbatim in `output` so an operator reading the run
/// report sees "blocked by policy: ..." rather than a bare "failed".
async fn run_one_step(
    policy: &Arc<dyn PolicyExecute>,
    principal: &Principal,
    runbook_title: &str,
    target: &FqTarget,
    command: &str,
) -> (StepStatus, String) {
    let req = CommandRequest {
        principal: principal.clone(),
        tool: "runbook".to_string(),
        target: target.clone(),
        command: command.to_string(),
        // Floor only — `policy::classify` raises based on the command's
        // own content regardless of what a caller declares (`CommandRequest
        // .declared_risk`'s own doc: "the classifier may raise (never
        // lower) it"), so declaring `Read` here costs nothing: a genuinely
        // destructive step still gets classified as such.
        declared_risk: crate::domain::RiskClass::Read,
        hypothesis: Some(format!("runbook {runbook_title:?} step")),
        runbook: Some(runbook_title.to_string()),
    };
    match policy.execute(req).await {
        Ok(PolicyOutcome::Executed(out)) => {
            let status = if out.exit_code == 0 { StepStatus::Ok } else { StepStatus::Failed };
            let mut text = format!("exit {} ({}ms)", out.exit_code, out.duration_ms);
            if !out.stdout.is_empty() {
                text.push_str(&format!("\nstdout:\n{}", out.stdout));
            }
            if !out.stderr.is_empty() {
                text.push_str(&format!("\nstderr:\n{}", out.stderr));
            }
            (status, text)
        }
        Ok(PolicyOutcome::NeedsApproval(id)) => {
            (StepStatus::Failed, format!("queued for human approval (request {id}) — did not run"))
        }
        Ok(PolicyOutcome::Blocked { reason, dry_run_logged }) => {
            let logged = if dry_run_logged { " (logged to the dry-run log)" } else { "" };
            (StepStatus::Failed, format!("blocked by policy: {reason}{logged}"))
        }
        Ok(PolicyOutcome::EStopped) => {
            (StepStatus::Failed, "blocked: the emergency stop is engaged".to_string())
        }
        Err(e) => (StepStatus::Failed, format!("policy engine error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_a_parseable_starter() {
        let dir = tempfile::tempdir().unwrap();
        let path = init(dir.path(), "dlq-backlog").unwrap();
        assert!(path.exists());
        let raw = std::fs::read_to_string(&path).unwrap();
        Runbook::parse(&raw).expect("init template must parse");
    }

    #[test]
    fn init_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "dlq-backlog").unwrap();
        let err = init(dir.path(), "dlq-backlog").unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn list_on_missing_dir_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let summaries = list(dir.path()).unwrap();
        assert!(summaries.is_empty());
    }

    #[test]
    fn list_summarizes_every_runbook() {
        // `init`'s starter template always titles itself "Untitled
        // runbook" — two files from `init` collide on TITLE, which is the
        // store's identity (matching `db::RunbookRunRepo`'s own title-
        // keyed convention). This is a BEHAVIOUR CHANGE from the pre-
        // RunbookStore version of this test (which asserted 2 distinct
        // entries for 2 same-titled files) — flagged in the runbook-store
        // report rather than silently changed: listing two files under one
        // undifferentiated title was already misleading (their run history
        // would already be indistinguishable), so collapsing to one entry
        // is more correct, not merely different. Give the second file a
        // distinct title so this test still exercises "two DIFFERENT
        // runbooks both appear".
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "a").unwrap();
        init(dir.path(), "b").unwrap();
        let b_path = runbooks_dir(dir.path()).join("b.md");
        let raw = std::fs::read_to_string(&b_path).unwrap();
        std::fs::write(&b_path, raw.replacen("Untitled runbook", "Second runbook", 1)).unwrap();

        let summaries = list(dir.path()).unwrap();
        assert_eq!(summaries.len(), 2);
        let titles: Vec<&str> =
            summaries.iter().map(|s| s.as_ref().expect("both valid").title.as_str()).collect();
        assert!(titles.contains(&"Untitled runbook"));
        assert!(titles.contains(&"Second runbook"));
        for s in &summaries {
            let s = s.as_ref().unwrap();
            assert!(s.steps > 0);
        }
    }

    #[test]
    fn list_collapses_same_titled_files_to_one_entry_last_sorted_wins() {
        // Documents the behaviour change directly: two files that both
        // declare the SAME title collapse to one listing entry (the
        // store's title-keyed identity), rather than showing as two
        // separate runbooks that would be indistinguishable in run history
        // anyway.
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "a").unwrap();
        init(dir.path(), "b").unwrap();
        let summaries = list(dir.path()).unwrap();
        assert_eq!(summaries.len(), 1, "same-titled files collapse to one entry");
    }

    #[test]
    fn list_reports_a_broken_runbook_without_hiding_the_others() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "good").unwrap();
        std::fs::write(runbooks_dir(dir.path()).join("bad.md"), "not even front matter").unwrap();

        let summaries = list(dir.path()).unwrap();
        assert_eq!(summaries.len(), 2);
        let ok_count = summaries.iter().filter(|r| r.is_ok()).count();
        let err_count = summaries.iter().filter(|r| r.is_err()).count();
        assert_eq!(ok_count, 1);
        assert_eq!(err_count, 1);
    }

    #[tokio::test]
    async fn list_with_history_flags_low_success_runbooks() {
        let dir = tempfile::tempdir().unwrap();
        let rb_dir = runbooks_dir(dir.path());
        std::fs::create_dir_all(&rb_dir).unwrap();
        std::fs::write(
            rb_dir.join("flaky.md"),
            "+++\ntitle = \"Flaky runbook\"\n\n[trigger]\nkeywords = [\"x\"]\n+++\n- step one\n",
        )
        .unwrap();

        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();
        // 2 ok / 5 runs = 40%: over the minimum sample, under the threshold.
        for ok in [true, true, false, false, false] {
            let record = crate::runbooks::RunbookRun {
                id: Uuid::new_v4(),
                runbook: "Flaky runbook".into(),
                target: test_target(),
                principal: None,
                started_at: Utc::now(),
                finished_at: Some(Utc::now()),
                steps: vec![StepOutcome {
                    step_index: 0,
                    status: if ok { StepStatus::Ok } else { StepStatus::Failed },
                    output: String::new(),
                }],
            };
            runs.record_run(&record).await.unwrap();
        }

        let summaries = list_with_history(dir.path(), &runs).await.unwrap();
        let s = summaries[0].as_ref().unwrap();
        let success = s.success.as_ref().expect("history join must populate success");
        assert_eq!(success.total_runs, 5);
        assert_eq!(success.successful_runs, 2);
        assert!(success.low_success, "40% over 5 runs must be flagged for review");
        assert_eq!(
            crate::runbooks::low_success_marker(success.total_runs, success.rate).as_deref(),
            Some("[low success: 40% over 5 runs]")
        );
    }

    #[tokio::test]
    async fn list_with_history_never_run_leaves_success_none() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "fresh").unwrap();
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let summaries = list_with_history(dir.path(), &runs).await.unwrap();
        assert!(
            summaries[0].as_ref().unwrap().success.is_none(),
            "no run history must read as no data, not 0% reliable"
        );
    }

    #[test]
    fn show_reads_and_parses_by_name() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "dlq-backlog").unwrap();
        let rb = show(dir.path(), "dlq-backlog").unwrap();
        assert_eq!(rb.front_matter.title, "Untitled runbook");
    }

    #[test]
    fn show_on_missing_file_errors_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let err = show(dir.path(), "nope").unwrap_err();
        assert!(err.to_string().contains("nope.md"));
    }

    // ---- `run` ----

    use async_trait::async_trait;
    use std::sync::Mutex;

    /// A `PolicyExecute` whose outcome is scripted per call (in order),
    /// repeating the last scripted outcome once the queue runs out — lets a
    /// test express "step 1 succeeds, step 2 fails" without a full fake
    /// executor. Also records every `CommandRequest` it saw, so tests can
    /// assert `runbook`/`principal`/`declared_risk` were threaded through
    /// correctly.
    struct ScriptedPolicy {
        outcomes: Mutex<std::collections::VecDeque<PolicyOutcome>>,
        seen: Mutex<Vec<CommandRequest>>,
    }

    impl ScriptedPolicy {
        fn new(outcomes: Vec<PolicyOutcome>) -> Self {
            ScriptedPolicy { outcomes: Mutex::new(outcomes.into()), seen: Mutex::new(Vec::new()) }
        }

        fn ok(exit_code: i32) -> PolicyOutcome {
            PolicyOutcome::Executed(crate::targets::ExecOutput {
                exit_code,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 1,
            })
        }
    }

    #[async_trait]
    impl PolicyExecute for ScriptedPolicy {
        async fn execute(&self, req: CommandRequest) -> crate::Result<PolicyOutcome> {
            self.seen.lock().unwrap().push(req);
            let mut q = self.outcomes.lock().unwrap();
            Ok(if q.len() > 1 { q.pop_front().unwrap() } else { clone_outcome(q.front().unwrap()) })
        }
    }

    // `PolicyOutcome` has no `Clone`; hand-roll the narrow clone this test
    // fake needs (only the variants these tests script).
    fn clone_outcome(o: &PolicyOutcome) -> PolicyOutcome {
        match o {
            PolicyOutcome::Executed(e) => PolicyOutcome::Executed(crate::targets::ExecOutput {
                exit_code: e.exit_code,
                stdout: e.stdout.clone(),
                stderr: e.stderr.clone(),
                duration_ms: e.duration_ms,
            }),
            PolicyOutcome::NeedsApproval(id) => PolicyOutcome::NeedsApproval(*id),
            PolicyOutcome::Blocked { reason, dry_run_logged } => {
                PolicyOutcome::Blocked { reason: reason.clone(), dry_run_logged: *dry_run_logged }
            }
            PolicyOutcome::EStopped => PolicyOutcome::EStopped,
        }
    }

    fn store_with(body: &str) -> RunbookStore {
        let rb = Runbook::parse(body).unwrap();
        RunbookStore::from_parsed(std::env::temp_dir(), vec![("test.md".to_string(), rb)])
    }

    fn test_target() -> FqTarget {
        FqTarget::new("remundo", "prod", "web-1")
    }

    #[tokio::test]
    async fn run_executes_every_step_and_records_a_successful_run() {
        let body = "+++\ntitle = \"t\"\n+++\n- step one\n  ```sh\n  echo one {target}\n  ```\n- step two\n  ```sh\n  echo two\n  ```\n";
        let store = store_with(body);
        let policy: Arc<dyn PolicyExecute> =
            Arc::new(ScriptedPolicy::new(vec![ScriptedPolicy::ok(0)]));
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let outcome =
            run(&store, &policy, &runs, Principal::System, "t", &test_target(), &BTreeMap::new())
                .await
                .unwrap();

        assert!(outcome.succeeded);
        assert_eq!(outcome.steps.len(), 2);
        assert_eq!(outcome.steps[0].status, "ok");
        assert_eq!(outcome.steps[1].status, "ok");

        let persisted =
            crate::db::RunbookRunRepo::get(runs.as_ref(), outcome.run_id).await.unwrap().unwrap();
        assert_eq!(persisted.runbook, "t");
        assert!(persisted.succeeded());
    }

    #[tokio::test]
    async fn run_renders_target_and_var_placeholders_before_executing() {
        let body = "+++\ntitle = \"t\"\n+++\n- one step\n  ```sh\n  restart {target} --queue {queue}\n  ```\n";
        let store = store_with(body);
        let policy = Arc::new(ScriptedPolicy::new(vec![ScriptedPolicy::ok(0)]));
        let policy_dyn: Arc<dyn PolicyExecute> = policy.clone();
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let mut vars = BTreeMap::new();
        vars.insert("queue".to_string(), "orders-dlq".to_string());

        run(&store, &policy_dyn, &runs, Principal::System, "t", &test_target(), &vars)
            .await
            .unwrap();

        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        // Leading whitespace inside the fenced block is preserved verbatim
        // by `steps::parse_steps` (see that module's own
        // `parses_command_block` test) — `render`/`render_all` only
        // substitute `{placeholder}`s, they don't reformat the command.
        assert_eq!(seen[0].command.trim(), "restart web-1 --queue orders-dlq");
        assert_eq!(seen[0].runbook.as_deref(), Some("t"));
    }

    #[tokio::test]
    async fn run_aborts_on_default_on_fail_and_skips_later_steps() {
        let body = "+++\ntitle = \"t\"\n+++\n- fails\n  ```sh\n  false\n  ```\n- never runs\n  ```sh\n  echo nope\n  ```\n";
        let store = store_with(body);
        let policy: Arc<dyn PolicyExecute> =
            Arc::new(ScriptedPolicy::new(vec![ScriptedPolicy::ok(1)]));
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let outcome =
            run(&store, &policy, &runs, Principal::System, "t", &test_target(), &BTreeMap::new())
                .await
                .unwrap();

        assert!(!outcome.succeeded);
        assert_eq!(outcome.steps[0].status, "failed");
        assert_eq!(outcome.steps[1].status, "skipped");
    }

    #[tokio::test]
    async fn run_continues_past_a_continue_marked_failure() {
        let body = "+++\ntitle = \"t\"\n+++\n- fails but continues (on-fail: continue)\n  ```sh\n  false\n  ```\n- still runs\n  ```sh\n  echo ok\n  ```\n";
        let store = store_with(body);
        let policy: Arc<dyn PolicyExecute> =
            Arc::new(ScriptedPolicy::new(vec![ScriptedPolicy::ok(1), ScriptedPolicy::ok(0)]));
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let outcome =
            run(&store, &policy, &runs, Principal::System, "t", &test_target(), &BTreeMap::new())
                .await
                .unwrap();

        assert_eq!(outcome.steps[0].status, "failed");
        assert_eq!(outcome.steps[1].status, "ok", "the second step must still have run");
        assert!(!outcome.succeeded, "a run with any failed step is not a success");
    }

    #[tokio::test]
    async fn run_retries_once_then_succeeds() {
        let body = "+++\ntitle = \"t\"\n+++\n- flaky (on-fail: retry)\n  ```sh\n  maybe\n  ```\n";
        let store = store_with(body);
        let policy: Arc<dyn PolicyExecute> =
            Arc::new(ScriptedPolicy::new(vec![ScriptedPolicy::ok(1), ScriptedPolicy::ok(0)]));
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let outcome =
            run(&store, &policy, &runs, Principal::System, "t", &test_target(), &BTreeMap::new())
                .await
                .unwrap();

        assert_eq!(outcome.steps[0].status, "retried");
        assert!(outcome.succeeded);
    }

    #[tokio::test]
    async fn run_retry_that_fails_twice_is_just_failed() {
        let body = "+++\ntitle = \"t\"\n+++\n- flaky (on-fail: retry)\n  ```sh\n  maybe\n  ```\n";
        let store = store_with(body);
        let policy: Arc<dyn PolicyExecute> =
            Arc::new(ScriptedPolicy::new(vec![ScriptedPolicy::ok(1)]));
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let outcome =
            run(&store, &policy, &runs, Principal::System, "t", &test_target(), &BTreeMap::new())
                .await
                .unwrap();

        assert_eq!(outcome.steps[0].status, "failed");
        assert!(!outcome.succeeded);
    }

    #[tokio::test]
    async fn run_unknown_title_errors_clearly() {
        let store = store_with("+++\ntitle = \"t\"\n+++\n- step\n");
        let policy: Arc<dyn PolicyExecute> =
            Arc::new(ScriptedPolicy::new(vec![ScriptedPolicy::ok(0)]));
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let err = run(
            &store,
            &policy,
            &runs,
            Principal::System,
            "does-not-exist",
            &test_target(),
            &BTreeMap::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("does-not-exist"));
    }

    #[tokio::test]
    async fn run_prose_only_step_is_ok_without_executing_anything() {
        let store = store_with("+++\ntitle = \"t\"\n+++\n- just look at the dashboard\n");
        let policy = Arc::new(ScriptedPolicy::new(vec![ScriptedPolicy::ok(0)]));
        let policy_dyn: Arc<dyn PolicyExecute> = policy.clone();
        let db = crate::db::Db::fake();
        let runs: Arc<dyn crate::db::RunbookRunRepo> = db.repos();

        let outcome = run(
            &store,
            &policy_dyn,
            &runs,
            Principal::System,
            "t",
            &test_target(),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.steps[0].status, "ok");
        assert!(outcome.succeeded);
        assert!(
            policy.seen.lock().unwrap().is_empty(),
            "a prose-only step must never call policy.execute"
        );
    }
}
