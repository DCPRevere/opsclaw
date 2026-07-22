//! In-memory shared chat transcript (see `db::sqlite::chat` — SQLite is
//! the spec).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::InMemoryDb;
use crate::Result;
use crate::db::ChatMessage;

#[async_trait]
impl crate::db::ChatRepo for InMemoryDb {
    async fn append_chat(
        &self,
        at: DateTime<Utc>,
        role: &str,
        speaker: &str,
        content: &str,
    ) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        let seq = store.chat_messages.last().map(|m| m.seq + 1).unwrap_or(1);
        store.chat_messages.push(ChatMessage {
            seq,
            at,
            role: role.to_string(),
            speaker: speaker.to_string(),
            content: content.to_string(),
        });
        Ok(())
    }

    async fn recent_chat(&self, limit: i64) -> Result<Vec<ChatMessage>> {
        let store = self.store.lock().unwrap();
        let n = store.chat_messages.len();
        let start = n.saturating_sub(limit.max(0) as usize);
        Ok(store.chat_messages[start..].to_vec())
    }
}
