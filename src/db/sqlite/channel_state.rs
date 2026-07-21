//! Persistent Telegram roster + generic channel key/value state (persistent
//! Telegram roster + poll offset task — see `db::repo`'s module doc for the
//! trait's provenance; replaces boot.rs's in-memory KNOWN LIMITATION).

use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

use super::SqliteDb;
use crate::Result;

#[async_trait]
impl crate::db::ChannelStateRepo for SqliteDb {
    async fn bind_telegram_chat(&self, chat_id: &str, operator_id: Uuid) -> Result<()> {
        sqlx::query(
            "INSERT INTO telegram_roster (chat_id, operator_id, created_at) VALUES (?,?,?)
             ON CONFLICT (chat_id) DO UPDATE SET operator_id = excluded.operator_id",
        )
        .bind(chat_id)
        .bind(operator_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn unbind_telegram_chat(&self, chat_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM telegram_roster WHERE chat_id = ?")
            .bind(chat_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn find_telegram_operator(&self, chat_id: &str) -> Result<Option<Uuid>> {
        let row = sqlx::query("SELECT operator_id FROM telegram_roster WHERE chat_id = ?")
            .bind(chat_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| Uuid::parse_str(r.get("operator_id")).expect("stored uuid")))
    }

    async fn telegram_chat_ids_for(&self, operator: Option<Uuid>) -> Result<Vec<String>> {
        let rows = match operator {
            None => {
                sqlx::query("SELECT chat_id FROM telegram_roster").fetch_all(&self.pool).await?
            }
            Some(op) => {
                sqlx::query("SELECT chat_id FROM telegram_roster WHERE operator_id = ?")
                    .bind(op.to_string())
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows.iter().map(|r| r.get::<String, _>("chat_id")).collect())
    }

    async fn get_channel_state(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM channel_state WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("value")))
    }

    async fn set_channel_state(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO channel_state (key, value) VALUES (?, ?)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
