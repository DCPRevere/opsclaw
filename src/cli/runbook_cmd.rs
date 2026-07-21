//! `opsclaw-cli runbook init/list/show` (brief §7: "`runbook
//! init/list/show/run --target ... --var k=v`"). `runbooks/` is deliberately
//! "pure parsing/matching/templating: no DB, no network, no executor"
//! (`runbooks/mod.rs`'s own doc comment) — there is no filesystem-scanning
//! helper or "the runbooks directory" config field anywhere in the library,
//! so this module owns both: a simple directory convention
//! (`<opsclaw_home>/runbooks/*.md`) and the glob/parse loop `list` needs.
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
use crate::runbooks::{INIT_TEMPLATE, Runbook};

/// Where `runbook` commands look for runbook files: `<opsclaw_home>/runbooks/`.
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

/// Parse every `*.md` file directly under the runbooks dir (non-recursive —
/// matches `init`'s flat layout) and summarize it. A file that fails to
/// parse is reported as an error entry (`Err` in the returned vec's position)
/// rather than aborting the whole listing — one bad runbook must not hide
/// every other one from `list`.
pub fn list(opsclaw_home: &Path) -> Result<Vec<std::result::Result<RunbookSummary, String>>> {
    let dir = runbooks_dir(opsclaw_home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        .collect();
    entries.sort();

    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let result = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|raw| Runbook::parse(&raw).map_err(|e| e.to_string()))
            .map(|rb| RunbookSummary {
                file: file_name.clone(),
                title: rb.front_matter.title.clone(),
                steps: rb.steps.len(),
                alert_categories: rb.front_matter.trigger.alert_categories.clone(),
                keywords: rb.front_matter.trigger.keywords.clone(),
                target_glob: rb.front_matter.trigger.target_glob.clone(),
            })
            .map_err(|e| format!("{file_name}: {e}"));
        out.push(result);
    }
    Ok(out)
}

/// Parse and return one runbook by file stem (`show foo` reads
/// `<runbooks_dir>/foo.md`).
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
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "a").unwrap();
        init(dir.path(), "b").unwrap();

        let summaries = list(dir.path()).unwrap();
        assert_eq!(summaries.len(), 2);
        for s in &summaries {
            let s = s.as_ref().expect("both runbooks are valid");
            assert_eq!(s.title, "Untitled runbook");
            assert!(s.steps > 0);
        }
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
