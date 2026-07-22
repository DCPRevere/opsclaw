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
        Ok(page_ascending(rows))
    }

    async fn before_chat(&self, before_seq: i64, limit: i64) -> Result<Vec<ChatMessage>> {
        // Same newest-first-then-flip shape as `recent_chat`, anchored
        // below the caller's oldest rendered seq — the "Show earlier" page.
        let rows = sqlx::query(
            "SELECT seq, ts, role, speaker, content FROM chat_messages
             WHERE seq < ? ORDER BY seq DESC LIMIT ?",
        )
        .bind(before_seq)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(page_ascending(rows))
    }
}

/// Flip a newest-first selection into render order (ascending seq).
fn page_ascending(rows: Vec<sqlx::sqlite::SqliteRow>) -> Vec<ChatMessage> {
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
    out
}
