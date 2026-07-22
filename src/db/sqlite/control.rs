use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use super::SqliteDb;
use crate::Result;

const ESTOP_KEY: &str = "estop_engaged";

#[async_trait]
impl crate::db::ControlRepo for SqliteDb {
    async fn estop_engaged(&self) -> Result<bool> {
        let row = sqlx::query("SELECT value FROM control_state WHERE key = ?")
            .bind(ESTOP_KEY)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("value") == "true").unwrap_or(false))
    }

    async fn set_estop(&self, engaged: bool) -> Result<()> {
        sqlx::query(
            "INSERT INTO control_state (key, value) VALUES (?, ?)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(ESTOP_KEY)
        .bind(if engaged { "true" } else { "false" })
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn claim(&self, kind: &str, key: &str, at: DateTime<Utc>) -> Result<bool> {
        // INSERT OR IGNORE + UNIQUE(kind, key): the row lands only on the
        // FIRST claim for this (kind, key); a concurrent second caller's
        // insert is silently ignored by SQLite, so `rows_affected() == 0`
        // reliably means "someone else already claimed it" — exactly-once
        // under sequential OR concurrent re-claim.
        let res =
            sqlx::query("INSERT OR IGNORE INTO claims (kind, key, claimed_at) VALUES (?,?,?)")
                .bind(kind)
                .bind(key)
                .bind(at.to_rfc3339())
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn release(&self, kind: &str, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM claims WHERE kind = ? AND key = ?")
            .bind(kind)
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn prune_housekeeping(&self, now: DateTime<Utc>) -> Result<()> {
        // Claims are pure history once their occurrence has long passed;
        // keep 30 days so recent activity stays inspectable.
        sqlx::query("DELETE FROM claims WHERE claimed_at < ?")
            .bind((now - chrono::Duration::days(30)).to_rfc3339())
            .execute(&self.pool)
            .await?;
        // Job failure records are cleared on success or give-up, so they
        // normally don't linger; sweep any that somehow outlived their
        // occurrence as a safety net.
        sqlx::query("DELETE FROM job_failures WHERE first_failed_at < ?")
            .bind((now - chrono::Duration::days(30)).to_rfc3339())
            .execute(&self.pool)
            .await?;
        // Expired/decided approvals older than a retention window; the
        // pending set is untouched (only a state != 'pending' row ages out).
        sqlx::query("DELETE FROM approvals WHERE state != 'pending' AND requested_at < ?")
            .bind((now - chrono::Duration::days(90)).to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
