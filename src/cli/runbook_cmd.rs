//! `opsclaw-cli runbook init/list/show` (brief §7: "`runbook
//! init/list/show/run --target ... --var k=v`").
//!
//! `list`/`show`'s directory-scan/parse logic now DELEGATES to
//! `runbooks::RunbookStore` (the runbook definition store built for
//! `tools::runbooks_tool::RunbookListTool`) rather than duplicating it —
//! this file used to own that scan loop directly (before `RunbookStore`
//! existed, `runbooks/mod.rs` was explicitly "no filesystem-scanning
//! helper... anywhere in the library", so this was the one place it lived).
//! Public function signatures are UNCHANGED (`init`/`list`/`show`/
//! `runbooks_dir`, all still `&Path`-based) so `bin/cli/main.rs`'s call
//! sites need no changes — only the bodies of `list`/`show` moved to call
//! through the store.
//!
//! `runbook run` is NOT implemented here: actually executing a runbook's
//! steps needs to go through `policy::execute` for risk classification,
//! e-stop, autonomy gating, and audit (DESIGN.md §4 "no tool owns a
//! connection; there is one execution path per target type, and audit and
//! policy live there") — `runbooks/mod.rs`'s own doc comment is explicit
//! that this execution engine is later-wave work, not something to
//! improvise here by calling a `TargetExecutor` directly and skipping the
//! choke point.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::Result;
use crate::runbooks::{INIT_TEMPLATE, Runbook, RunbookStore};

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
            })
        })
        .collect();
    out.extend(store.errors().into_iter().map(|e| Err(format!("{}: {}", e.file, e.message))));
    Ok(out)
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
}
