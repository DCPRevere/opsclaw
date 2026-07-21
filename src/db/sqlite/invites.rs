//! Teammate invites (additive, Wave 4 — see `db::repo`'s module doc for why
//! this exists with no Wave 0 analog).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::Result;
use crate::db::Invite;

fn row_to_invite(row: &SqliteRow) -> Invite {
    Invite {
        code: row.get("code"),
        issued_by: Uuid::parse_str(row.get("issued_by")).expect("stored uuid"),
        created_at: row.get::<String, _>("created_at").parse().expect("stored rfc3339"),
        expires_at: row.get::<String, _>("expires_at").parse().expect("stored rfc3339"),
    }
}

#[async_trait]
impl crate::db::InviteRepo for SqliteDb {
    async fn create_invite(&self, invite: &Invite) -> Result<()> {
        sqlx::query(
            "INSERT INTO invites (code, issued_by, created_at, expires_at, consumed_at)
             VALUES (?,?,?,?,NULL)",
        )
        .bind(&invite.code)
        .bind(invite.issued_by.to_string())
        .bind(invite.created_at.to_rfc3339())
        .bind(invite.expires_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_invite(&self, code: &str, now: DateTime<Utc>) -> Result<Option<Invite>> {
        let row = sqlx::query(
            "SELECT code, issued_by, created_at, expires_at FROM invites
             WHERE code = ? AND consumed_at IS NULL AND expires_at > ?",
        )
        .bind(code)
        .bind(now.to_rfc3339())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_invite))
    }

    async fn take_invite(&self, code: &str, now: DateTime<Utc>) -> Result<Option<Invite>> {
        // Atomic consume: UPDATE ... RETURNING only matches a row that is
        // still open (consumed_at IS NULL) AND unexpired — two concurrent
        // joins on the same code race this UPDATE, and only one of them
        // sees a row back (the loser's WHERE no longer matches once the
        // winner's write lands), closing the double-join TOCTOU window.
        let row = sqlx::query(
            "UPDATE invites SET consumed_at = ?
             WHERE code = ? AND consumed_at IS NULL AND expires_at > ?
             RETURNING code, issued_by, created_at, expires_at",
        )
        .bind(now.to_rfc3339())
        .bind(code)
        .bind(now.to_rfc3339())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_invite))
    }

    async fn list_open_invites(&self, now: DateTime<Utc>) -> Result<Vec<Invite>> {
        let rows = sqlx::query(
            "SELECT code, issued_by, created_at, expires_at FROM invites
             WHERE consumed_at IS NULL AND expires_at > ?
             ORDER BY created_at DESC",
        )
        .bind(now.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_invite).collect())
    }

    async fn revoke_invite(&self, code: &str) -> Result<bool> {
        // Revoke = mark consumed (never deleted — kept for audit, matching
        // the take_invite trail). Only an OPEN invite can be revoked.
        let res = sqlx::query(
            "UPDATE invites SET consumed_at = ? WHERE code = ? AND consumed_at IS NULL",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(code)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }
}
