//! Durable shared chat transcript (migration 0007 — see `db::repo`'s
//! `ChatRepo` doc for provenance).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use super::SqliteDb;
use crate::Result;
use crate::db::ChatMessage;

#[async_trait]
impl crate::db::ChatRepo for SqliteDb {
    async fn append_chat(
        &self,
        at: DateTime<Utc>,
        role: &str,
        speaker: &str,
        content: &str,
    ) -> Result<()> {
        sqlx::query("INSERT INTO chat_messages (ts, role, speaker, content) VALUES (?,?,?,?)")
            .bind(at.to_rfc3339())
            .bind(role)
            .bind(speaker)
            .bind(content)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn recent_chat(&self, limit: i64) -> Result<Vec<ChatMessage>> {
        // Newest page selected descending, then flipped: the log renders
        // oldest-of-the-page first (gianna's `recent_for_*` shape).
        let rows = sqlx::query(
            "SELECT seq, ts, role, speaker, content FROM chat_messages
             ORDER BY seq DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<ChatMessage> = rows
            .into_iter()
            .map(|r| ChatMessage {
                seq: r.get("seq"),
                at: DateTime::parse_from_rfc3339(r.get("ts"))
                    .expect("stored rfc3339 ts")
                    .with_timezone(&Utc),
                role: r.get("role"),
                speaker: r.get("speaker"),
                content: r.get("content"),
            })
            .collect();
        out.reverse();
        Ok(out)
    }
}
