//! E-stop (DESIGN §4): two mechanisms so it works when the daemon misbehaves.
//! A sentinel *file* the CLI writes directly — no daemon round-trip, SSH to
//! the bastion works even when the daemon is wedged — plus a DB flag for the
//! remote paths (PWA / remote CLI / chat). The policy choke point re-reads
//! both before every command; either one engaged means nothing executes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;

use crate::Result;
use crate::db::ControlRepo;

/// Default sentinel location relative to the config dir (`~/.opsclaw/ESTOP`).
pub const SENTINEL_FILE: &str = "ESTOP";

pub struct EStop {
    sentinel: PathBuf,
    control: Arc<dyn ControlRepo>,
}

impl EStop {
    pub fn new(sentinel: PathBuf, control: Arc<dyn ControlRepo>) -> Self {
        EStop { sentinel, control }
    }

    pub fn sentinel_path(&self) -> &Path {
        &self.sentinel
    }

    /// True if either mechanism is engaged. The file check comes first and
    /// needs no DB: a wedged daemon still honours a hand-written sentinel.
    pub async fn engaged(&self) -> Result<bool> {
        if self.sentinel.exists() {
            return Ok(true);
        }
        self.control.estop_engaged().await
    }

    /// Engage both mechanisms. The file is written even if the DB write then
    /// fails — stopping must not depend on the DB being healthy.
    pub async fn engage(&self, reason: &str) -> Result<()> {
        write_sentinel(&self.sentinel, reason)?;
        self.control.set_estop(true).await
    }

    /// Clear both mechanisms (`estop resume`).
    pub async fn resume(&self) -> Result<()> {
        if self.sentinel.exists() {
            std::fs::remove_file(&self.sentinel)?;
        }
        self.control.set_estop(false).await
    }

    /// Engage the DB flag ONLY — the chat half of DESIGN §4's "Remote
    /// `estop` (PWA / remote CLI / chat)". Deliberately does NOT write the
    /// sentinel file: the file is the LOCAL operator's hand-written
    /// guarantee (see [`Self::resume_db_only`]), and a chat-engaged stop
    /// must stay resumable from chat — if engaging here wrote the file, the
    /// matching chat resume (which must never delete a sentinel) could not
    /// actually resume. The policy choke point honours the DB flag alone,
    /// so this is still a complete stop.
    pub async fn engage_db_only(&self) -> Result<()> {
        self.control.set_estop(true).await
    }

    /// Clear the DB flag ONLY, leaving any sentinel file untouched — a
    /// remote resume must not clear a hand-written sentinel (DESIGN §4: the
    /// file works "even when the daemon is wedged" precisely because only a
    /// hand on the host touches it; a remote caller undoing it would demote
    /// the local guarantee to a suggestion). Returns `true` when the
    /// sentinel still holds the stop engaged, so the caller can tell the
    /// operator how to clear it locally.
    pub async fn resume_db_only(&self) -> Result<bool> {
        self.control.set_estop(false).await?;
        Ok(self.sentinel.exists())
    }
}

/// Write the sentinel file directly — this is what the local CLI calls with no
/// daemon involved at all.
pub fn write_sentinel(path: &Path, reason: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, format!("engaged at {}\nreason: {reason}\n", Utc::now().to_rfc3339()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory::InMemoryDb;

    fn estop(dir: &tempfile::TempDir) -> EStop {
        EStop::new(dir.path().join(SENTINEL_FILE), Arc::new(InMemoryDb::new()))
    }

    #[tokio::test]
    async fn disengaged_by_default() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!estop(&dir).engaged().await.unwrap());
    }

    #[tokio::test]
    async fn sentinel_file_alone_engages() {
        let dir = tempfile::tempdir().unwrap();
        let e = estop(&dir);
        // The CLI path: file written directly, daemon/DB untouched.
        write_sentinel(e.sentinel_path(), "operator panic").unwrap();
        assert!(e.engaged().await.unwrap());
    }

    #[tokio::test]
    async fn db_flag_alone_engages() {
        let dir = tempfile::tempdir().unwrap();
        let control = Arc::new(InMemoryDb::new());
        let e = EStop::new(dir.path().join(SENTINEL_FILE), control.clone());
        control.set_estop(true).await.unwrap();
        assert!(e.engaged().await.unwrap());
    }

    #[tokio::test]
    async fn engage_db_only_never_writes_the_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let e = estop(&dir);
        e.engage_db_only().await.unwrap();
        assert!(e.engaged().await.unwrap());
        assert!(!e.sentinel_path().exists(), "the chat path must not write the local sentinel");
    }

    #[tokio::test]
    async fn resume_db_only_clears_the_flag_but_leaves_a_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let control = Arc::new(InMemoryDb::new());
        let e = EStop::new(dir.path().join(SENTINEL_FILE), control.clone());
        control.set_estop(true).await.unwrap();
        write_sentinel(e.sentinel_path(), "local operator").unwrap();

        let sentinel_holds = e.resume_db_only().await.unwrap();

        assert!(sentinel_holds, "must report the sentinel still engages the stop");
        assert!(e.sentinel_path().exists(), "a remote resume must never delete the sentinel");
        assert!(!control.estop_engaged().await.unwrap(), "the DB flag must be cleared");
        assert!(e.engaged().await.unwrap(), "overall still engaged via the sentinel");
    }

    #[tokio::test]
    async fn resume_db_only_fully_resumes_when_no_sentinel_exists() {
        let dir = tempfile::tempdir().unwrap();
        let e = estop(&dir);
        e.engage_db_only().await.unwrap();
        let sentinel_holds = e.resume_db_only().await.unwrap();
        assert!(!sentinel_holds);
        assert!(!e.engaged().await.unwrap());
    }

    #[tokio::test]
    async fn engage_resume_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let e = estop(&dir);
        e.engage("test").await.unwrap();
        assert!(e.engaged().await.unwrap());
        assert!(e.sentinel_path().exists());
        e.resume().await.unwrap();
        assert!(!e.engaged().await.unwrap());
        assert!(!e.sentinel_path().exists());
    }
}
