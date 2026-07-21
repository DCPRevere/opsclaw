//! [`RunbookStore`] — the runbook DEFINITION store (the gap flagged from
//! `tools::runbooks_tool`: previously there was no way for the agent to ask
//! "what runbooks do you have?", only "what did runbook X do historically"
//! via `db::RunbookRunRepo`, which needs a name the caller already knows).
//!
//! Loads every `*.md` file from a configured directory, parses each via
//! [`crate::runbooks::Runbook::parse`], and keeps title-keyed entries in
//! memory — matching `db::RunbookRunRepo`'s existing convention that a
//! runbook's TITLE (not its file path) is its stable identity
//! (`history.rs`: "the file path can move, the title is what an operator
//! recognizes"). A broken runbook file is recorded as a load error against
//! its filename and does not prevent the rest of the directory from
//! loading — `runbooks/mod.rs`'s own module doc already established this
//! module stays "pure parsing/matching/templating: no DB, no network, no
//! executor"; this store adds the ONE piece of IO (reading a directory)
//! that was missing, kept behind a narrow, easily-faked surface
//! (`RunbookStore::from_parsed` builds one directly from in-memory
//! `Runbook`s for tests with no filesystem at all).
//!
//! Ported/promoted from `cli::runbook_cmd`'s directory-scanning logic
//! (`runbooks_dir`/`list`/`show`), which had the exact same shape already —
//! see that module's doc for the refactor: the CLI command now calls
//! through this store instead of duplicating the scan.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::Result;
use crate::runbooks::Runbook;

/// One loaded (or failed-to-load) runbook file.
#[derive(Debug, Clone)]
pub struct LoadedRunbook {
    /// File name (not full path — stable and short for display).
    pub file: String,
    pub runbook: Runbook,
}

/// A file that failed to load or parse, kept alongside the good ones rather
/// than aborting the whole store — see module doc.
#[derive(Debug, Clone)]
pub struct LoadError {
    pub file: String,
    pub message: String,
}

/// In-memory snapshot of every runbook loaded from a directory, keyed by
/// title. `reload()` replaces the snapshot atomically (readers never see a
/// half-updated store) so the CLI/daemon can refresh after an operator
/// edits a file on disk without restarting.
pub struct RunbookStore {
    dir: PathBuf,
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    /// Keyed by title (`Runbook::title()`), not file name — see module doc.
    /// A `BTreeMap` so `list()` returns a stable, sorted order for free.
    by_title: BTreeMap<String, LoadedRunbook>,
    errors: Vec<LoadError>,
}

impl RunbookStore {
    /// Load every `*.md` file directly under `dir` (non-recursive, matching
    /// `runbook init`'s flat layout). A missing directory loads as empty,
    /// not an error — a fresh `opsclaw onboard` with no runbooks yet is a
    /// normal, valid state.
    pub fn load(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        let state = scan(&dir)?;
        Ok(RunbookStore { dir, state: RwLock::new(state) })
    }

    /// Build a store directly from already-parsed runbooks, with no
    /// filesystem access at all — for tests (and the fixture-backed seed
    /// path, if one is ever wanted) that don't need real files. `dir` is
    /// stored for `reload()`'s sake but never read by this constructor; a
    /// non-existent path is fine since nothing here touches disk.
    pub fn from_parsed(dir: impl Into<PathBuf>, runbooks: Vec<(String, Runbook)>) -> Self {
        let mut by_title = BTreeMap::new();
        for (file, runbook) in runbooks {
            by_title.insert(runbook.title().to_string(), LoadedRunbook { file, runbook });
        }
        RunbookStore {
            dir: dir.into(),
            state: RwLock::new(State { by_title, errors: Vec::new() }),
        }
    }

    /// Re-scan the configured directory, replacing the snapshot atomically.
    /// Called by the CLI (`runbook list` always reloads first — see
    /// `cli::runbook_cmd`) and available to the daemon for an operator-
    /// triggered refresh without a restart.
    pub fn reload(&self) -> Result<()> {
        let fresh = scan(&self.dir)?;
        *self.state.write().expect("runbook store lock poisoned") = fresh;
        Ok(())
    }

    /// The directory this store loads from.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every successfully loaded runbook, title-sorted (see `by_title`'s
    /// doc for why the map itself gives this for free).
    pub fn list(&self) -> Vec<LoadedRunbook> {
        self.state.read().expect("runbook store lock poisoned").by_title.values().cloned().collect()
    }

    /// Files that failed to load or parse on the last `load`/`reload` —
    /// surfaced alongside `list()` rather than swallowed, per module doc.
    pub fn errors(&self) -> Vec<LoadError> {
        self.state.read().expect("runbook store lock poisoned").errors.clone()
    }

    /// Look up one runbook by its exact title.
    pub fn get(&self, title: &str) -> Option<LoadedRunbook> {
        self.state.read().expect("runbook store lock poisoned").by_title.get(title).cloned()
    }

    /// All runbooks, for matching against an incoming signal — the shape
    /// `matching::best_match` wants (`&[Runbook]`), built fresh from the
    /// current snapshot each call since `best_match` takes a slice, not an
    /// iterator.
    pub fn runbooks_for_matching(&self) -> Vec<Runbook> {
        self.state
            .read()
            .expect("runbook store lock poisoned")
            .by_title
            .values()
            .map(|lr| lr.runbook.clone())
            .collect()
    }
}

/// The actual directory walk + parse loop, shared by `load` and `reload`.
fn scan(dir: &Path) -> Result<State> {
    if !dir.exists() {
        return Ok(State::default());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        .collect();
    entries.sort();

    let mut by_title = BTreeMap::new();
    let mut errors = Vec::new();
    for path in entries {
        let file = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let parsed = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|raw| Runbook::parse(&raw).map_err(|e| e.to_string()));
        match parsed {
            Ok(runbook) => {
                let title = runbook.title().to_string();
                // A later file (sorted order) with a DUPLICATE title
                // overwrites the earlier one rather than erroring — the
                // same last-write-wins a filesystem directory listing
                // naturally gives you; a real collision is an operator
                // mistake worth catching separately (not this store's job),
                // and refusing to load either file entirely would hide
                // both from `list()`, which is worse.
                by_title.insert(title, LoadedRunbook { file, runbook });
            }
            Err(message) => errors.push(LoadError { file: file.clone(), message }),
        }
    }
    Ok(State { by_title, errors })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runbooks::template::INIT_TEMPLATE;

    fn write_runbook(dir: &Path, name: &str, title: &str) {
        let src = format!(
            "+++\ntitle = \"{title}\"\n\n[trigger]\nkeywords = [\"x\"]\n+++\n- step one\n"
        );
        std::fs::write(dir.join(format!("{name}.md")), src).unwrap();
    }

    #[test]
    fn load_on_missing_dir_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let store = RunbookStore::load(&missing).unwrap();
        assert!(store.list().is_empty());
        assert!(store.errors().is_empty());
    }

    #[test]
    fn load_parses_every_runbook_title_keyed() {
        let dir = tempfile::tempdir().unwrap();
        write_runbook(dir.path(), "a", "Alpha runbook");
        write_runbook(dir.path(), "b", "Beta runbook");

        let store = RunbookStore::load(dir.path()).unwrap();
        let list = store.list();
        assert_eq!(list.len(), 2);
        assert!(store.get("Alpha runbook").is_some());
        assert!(store.get("Beta runbook").is_some());
        assert!(store.get("Nonexistent").is_none());
    }

    #[test]
    fn a_broken_file_is_reported_without_hiding_the_others() {
        let dir = tempfile::tempdir().unwrap();
        write_runbook(dir.path(), "good", "Good runbook");
        std::fs::write(dir.path().join("bad.md"), "not even front matter").unwrap();

        let store = RunbookStore::load(dir.path()).unwrap();
        assert_eq!(store.list().len(), 1);
        let errors = store.errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].file, "bad.md");
        assert!(!errors[0].message.is_empty());
    }

    #[test]
    fn reload_picks_up_a_newly_added_file() {
        let dir = tempfile::tempdir().unwrap();
        write_runbook(dir.path(), "a", "Alpha runbook");
        let store = RunbookStore::load(dir.path()).unwrap();
        assert_eq!(store.list().len(), 1);

        write_runbook(dir.path(), "b", "Beta runbook");
        store.reload().unwrap();
        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn reload_drops_a_removed_file() {
        let dir = tempfile::tempdir().unwrap();
        write_runbook(dir.path(), "a", "Alpha runbook");
        write_runbook(dir.path(), "b", "Beta runbook");
        let store = RunbookStore::load(dir.path()).unwrap();
        assert_eq!(store.list().len(), 2);

        std::fs::remove_file(dir.path().join("a.md")).unwrap();
        store.reload().unwrap();
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].runbook.title(), "Beta runbook");
    }

    #[test]
    fn reload_is_atomic_a_reader_never_sees_a_half_updated_store() {
        // Not a concurrency stress test (RwLock correctness is std's job) —
        // just pins that reload() fully replaces state in one write, so a
        // reader between two reload() calls sees either the old or the new
        // complete snapshot, never a partial one.
        let dir = tempfile::tempdir().unwrap();
        write_runbook(dir.path(), "a", "Alpha runbook");
        let store = RunbookStore::load(dir.path()).unwrap();
        let before = store.list();
        assert_eq!(before.len(), 1);
        store.reload().unwrap();
        let after = store.list();
        assert_eq!(after.len(), 1);
    }

    #[test]
    fn from_parsed_builds_a_store_with_no_filesystem() {
        let rb = Runbook::parse(INIT_TEMPLATE).unwrap();
        let store = RunbookStore::from_parsed(
            "/does/not/exist",
            vec![("seed.md".to_string(), rb.clone())],
        );
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.get(rb.title()).unwrap().file, "seed.md");
    }

    #[test]
    fn runbooks_for_matching_returns_every_loaded_runbook() {
        let dir = tempfile::tempdir().unwrap();
        write_runbook(dir.path(), "a", "Alpha runbook");
        write_runbook(dir.path(), "b", "Beta runbook");
        let store = RunbookStore::load(dir.path()).unwrap();
        let matching = store.runbooks_for_matching();
        assert_eq!(matching.len(), 2);
    }

    #[test]
    fn duplicate_titles_last_sorted_file_wins() {
        let dir = tempfile::tempdir().unwrap();
        // "a.md" sorts before "b.md"; both declare the same title.
        write_runbook(dir.path(), "a", "Same Title");
        write_runbook(dir.path(), "b", "Same Title");
        let store = RunbookStore::load(dir.path()).unwrap();
        assert_eq!(store.list().len(), 1, "one title -> one entry, not two");
        assert_eq!(store.get("Same Title").unwrap().file, "b.md", "later sorted file wins");
    }

    #[test]
    fn dir_accessor_returns_the_configured_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = RunbookStore::load(dir.path()).unwrap();
        assert_eq!(store.dir(), dir.path());
    }
}
