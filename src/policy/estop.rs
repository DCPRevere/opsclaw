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
