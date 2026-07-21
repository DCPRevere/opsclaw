//! Remote-CLI personal access tokens (additive, Wave 4 — see `db::repo`'s
//! module doc for why this exists with no Wave 0 analog).

use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::Result;
use crate::db::CliToken;

fn row_to_token(row: &SqliteRow) -> CliToken {
    CliToken {
        id: Uuid::parse_str(row.get("id")).expect("stored uuid"),
        account: Uuid::parse_str(row.get("account_id")).expect("stored uuid"),
        name: row.get("name"),
        created_at: row.get::<String, _>("created_at").parse().expect("stored rfc3339"),
        last_used_at: row
            .get::<Option<String>, _>("last_used_at")
            .map(|s| s.parse().expect("stored rfc3339")),
    }
}

#[async_trait]
impl crate::db::TokenRepo for SqliteDb {
    async fn create_cli_token(&self, token: CliToken, token_hash: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO cli_tokens (id, account_id, name, token_hash, created_at, last_used_at)
             VALUES (?,?,?,?,?,?)",
        )
        .bind(token.id.to_string())
        .bind(token.account.to_string())
        .bind(&token.name)
        .bind(token_hash)
        .bind(token.created_at.to_rfc3339())
        .bind(token.last_used_at.map(|t| t.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_cli_token(&self, token_hash: &str) -> Result<Option<(Uuid, Uuid)>> {
        let row = sqlx::query("SELECT id, account_id FROM cli_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let id = Uuid::parse_str(row.get("id")).expect("stored uuid");
        let account = Uuid::parse_str(row.get("account_id")).expect("stored uuid");
        // Best-effort last-use bump: a failure here must not fail auth (the
        // token was already resolved above), so log and continue rather
        // than propagate.
        if let Err(e) = sqlx::query("UPDATE cli_tokens SET last_used_at = ? WHERE id = ?")
            .bind(Utc::now().to_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
        {
            tracing::warn!(token_id = %id, "cli_tokens last_used_at update failed: {e}");
        }
        Ok(Some((id, account)))
    }

    async fn list_cli_tokens(&self, account: Uuid) -> Result<Vec<CliToken>> {
        let rows = sqlx::query("SELECT * FROM cli_tokens WHERE account_id = ? ORDER BY created_at")
            .bind(account.to_string())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_token).collect())
    }

    async fn revoke_cli_token(&self, account: Uuid, token_id: Uuid) -> Result<bool> {
        let res = sqlx::query("DELETE FROM cli_tokens WHERE id = ? AND account_id = ?")
            .bind(token_id.to_string())
            .bind(account.to_string())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}
