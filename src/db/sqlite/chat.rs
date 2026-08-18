//! Durable shared chat transcript (migration 0007 — see `db::repo`'s
//! `ChatRepo` doc for provenance).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use super::SqliteDb;
use crate::Result;
use crate::db::{ChatMessage, ChatRequestClaim};

#[async_trait]
impl crate::db::ChatRepo for SqliteDb {
    async fn claim_chat_request(
        &self,
        account: uuid::Uuid,
        conversation: &str,
        key: &str,
        started_at: DateTime<Utc>,
    ) -> Result<ChatRequestClaim> {
        let inserted = sqlx::query(
            "INSERT INTO chat_requests
             (account_id, idempotency_key, conversation, state, started_at)
             VALUES (?, ?, ?, 'pending', ?) ON CONFLICT DO NOTHING",
        )
        .bind(account.to_string())
        .bind(key)
        .bind(conversation)
        .bind(started_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        if inserted.rows_affected() == 1 {
            return Ok(ChatRequestClaim::Claimed);
        }
        let row = sqlx::query(
            "SELECT conversation, state, reply FROM chat_requests
             WHERE account_id = ? AND idempotency_key = ?",
        )
        .bind(account.to_string())
        .bind(key)
        .fetch_one(&self.pool)
        .await?;
        if row.get::<String, _>("conversation") != conversation {
            return Err(crate::Error::Conflict(
                "idempotency key belongs to a different chat conversation".into(),
            ));
        }
        match row.get::<String, _>("state").as_str() {
            "pending" => Ok(ChatRequestClaim::Pending),
            "complete" => Ok(ChatRequestClaim::Complete(row.try_get("reply")?)),
            "failed" => Ok(ChatRequestClaim::Failed),
            other => Err(crate::Error::other(format!("chat request has invalid state {other:?}"))),
        }
    }

    async fn complete_chat_request(
        &self,
        account: uuid::Uuid,
        key: &str,
        reply: &str,
        finished_at: DateTime<Utc>,
    ) -> Result<()> {
        finish(&self.pool, account, key, "complete", Some(reply), finished_at).await
    }

    async fn fail_chat_request(
        &self,
        account: uuid::Uuid,
        key: &str,
        finished_at: DateTime<Utc>,
    ) -> Result<()> {
        finish(&self.pool, account, key, "failed", None, finished_at).await
    }

    async fn append_chat(
        &self,
        conversation: &str,
        turn_id: Option<&str>,
        at: DateTime<Utc>,
        role: &str,
        speaker: &str,
        content: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO chat_messages
             (conversation, turn_id, ts, role, speaker, content) VALUES (?,?,?,?,?,?)",
        )
        .bind(conversation)
        .bind(turn_id)
        .bind(at.to_rfc3339())
        .bind(role)
        .bind(speaker)
        .bind(content)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn recent_chat(&self, conversation: &str, limit: i64) -> Result<Vec<ChatMessage>> {
        // Newest page selected descending, then flipped: the log renders
        // oldest-of-the-page first (gianna's `recent_for_*` shape).
        let rows = sqlx::query(
            "SELECT seq, ts, conversation, turn_id, role, speaker, content FROM chat_messages
             WHERE conversation = ? ORDER BY seq DESC LIMIT ?",
        )
        .bind(conversation)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(page_ascending(rows))
    }

    async fn before_chat(
        &self,
        conversation: &str,
        before_seq: i64,
        limit: i64,
    ) -> Result<Vec<ChatMessage>> {
        // Same newest-first-then-flip shape as `recent_chat`, anchored
        // below the caller's oldest rendered seq — the "Show earlier" page.
        let rows = sqlx::query(
            "SELECT seq, ts, conversation, turn_id, role, speaker, content FROM chat_messages
             WHERE conversation = ? AND seq < ? ORDER BY seq DESC LIMIT ?",
        )
        .bind(conversation)
        .bind(before_seq)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(page_ascending(rows))
    }
}

async fn finish(
    pool: &sqlx::SqlitePool,
    account: uuid::Uuid,
    key: &str,
    state: &str,
    reply: Option<&str>,
    finished_at: DateTime<Utc>,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE chat_requests SET state = ?, reply = ?, finished_at = ?
         WHERE account_id = ? AND idempotency_key = ? AND state = 'pending'",
    )
    .bind(state)
    .bind(reply)
    .bind(finished_at.to_rfc3339())
    .bind(account.to_string())
    .bind(key)
    .execute(pool)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(crate::Error::Conflict("chat request is missing or already terminal".into()))
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
            conversation: r.get("conversation"),
            turn_id: r.get("turn_id"),
            role: r.get("role"),
            speaker: r.get("speaker"),
            content: r.get("content"),
        })
        .collect();
    out.reverse();
    out
}
