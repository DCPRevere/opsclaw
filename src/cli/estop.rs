//! `opsclaw-cli estop` / `estop --resume` — the local, no-daemon-required
//! path (DESIGN.md §4 "E-stop": "a sentinel file the CLI writes directly (no
//! daemon round-trip) ... SSH to the bastion works even when the daemon is
//! wedged"). This MUST work with the DB unreachable or absent entirely —
//! that's the entire point of the sentinel file existing — so the sentinel
//! write/remove happens unconditionally first, and the DB flag is best-effort
//! on top of it, never a precondition.

use std::path::Path;

use serde::Serialize;

use crate::Result;
use crate::policy::estop;

#[derive(Debug, Serialize)]
pub struct EstopOutcome {
    pub action: &'static str,
    pub sentinel_path: String,
    pub sentinel_written: bool,
    /// None when no DB was reachable at all — not a failure, the sentinel
    /// alone is a complete e-stop.
    pub db_flag_set: Option<bool>,
    pub db_error: Option<String>,
}

/// Engage the e-stop: write the sentinel file directly (always), then
/// best-effort flip the DB flag too if a database at `db_path` is reachable.
/// `db_path`: `None` skips the DB step entirely (e.g. no daemon has ever run
/// here yet); `Some(path)` attempts `Db::connect` and reports failure in
/// `db_error` without failing the overall command — a DB that can't be
/// reached is exactly the situation this command exists for.
pub async fn engage(
    sentinel_path: &Path,
    reason: &str,
    db_path: Option<&str>,
) -> Result<EstopOutcome> {
    estop::write_sentinel(sentinel_path, reason)?;
    let (db_flag_set, db_error) = try_set_db_flag(db_path, true).await;
    Ok(EstopOutcome {
        action: "engage",
        sentinel_path: sentinel_path.display().to_string(),
        sentinel_written: true,
        db_flag_set,
        db_error,
    })
}

/// Resume: remove the sentinel file (idempotent — fine if it was already
/// gone), then best-effort clear the DB flag.
pub async fn resume(sentinel_path: &Path, db_path: Option<&str>) -> Result<EstopOutcome> {
    let existed = sentinel_path.exists();
    if existed {
        std::fs::remove_file(sentinel_path)?;
    }
    let (db_flag_set, db_error) = try_set_db_flag(db_path, false).await;
    Ok(EstopOutcome {
        action: "resume",
        sentinel_path: sentinel_path.display().to_string(),
        sentinel_written: existed,
        db_flag_set,
        db_error,
    })
}

async fn try_set_db_flag(db_path: Option<&str>, engaged: bool) -> (Option<bool>, Option<String>) {
    let Some(path) = db_path else {
        return (None, None);
    };
    match crate::db::Db::connect(path).await {
        Ok(db) => match db.repos().set_estop(engaged).await {
            Ok(()) => (Some(true), None),
            Err(e) => (Some(false), Some(e.to_string())),
        },
        Err(e) => (Some(false), Some(format!("could not open database at {path}: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn engage_writes_sentinel_with_no_db() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("ESTOP");
        let outcome = engage(&sentinel, "test panic", None).await.unwrap();
        assert!(sentinel.exists());
        assert!(outcome.sentinel_written);
        assert_eq!(outcome.db_flag_set, None);
        assert_eq!(outcome.db_error, None);
    }

    #[tokio::test]
    async fn resume_removes_sentinel_with_no_db() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("ESTOP");
        engage(&sentinel, "test panic", None).await.unwrap();
        assert!(sentinel.exists());

        let outcome = resume(&sentinel, None).await.unwrap();
        assert!(!sentinel.exists());
        assert!(outcome.sentinel_written); // it existed and was removed
    }

    #[tokio::test]
    async fn resume_is_idempotent_when_sentinel_absent() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("ESTOP");
        let outcome = resume(&sentinel, None).await.unwrap();
        assert!(!outcome.sentinel_written);
    }

    #[tokio::test]
    async fn engage_also_sets_db_flag_when_db_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("ESTOP");
        let db_file = dir.path().join("test.db");
        let db_path = db_file.to_str().unwrap();

        let outcome = engage(&sentinel, "test panic", Some(db_path)).await.unwrap();
        assert_eq!(outcome.db_flag_set, Some(true));
        assert_eq!(outcome.db_error, None);

        let db = crate::db::Db::connect(db_path).await.unwrap();
        assert!(db.repos().estop_engaged().await.unwrap());
    }

    #[tokio::test]
    async fn engage_reports_db_error_without_failing() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("ESTOP");
        // A path with a nonexistent parent directory: sqlite create_if_missing
        // still fails because the containing directory doesn't exist.
        let bad_db_path = dir.path().join("no/such/dir/test.db");

        let outcome =
            engage(&sentinel, "test panic", Some(bad_db_path.to_str().unwrap())).await.unwrap();
        // The sentinel write must still have succeeded even though the DB path is bad.
        assert!(sentinel.exists());
        assert_eq!(outcome.db_flag_set, Some(false));
        assert!(outcome.db_error.is_some());
    }
}
