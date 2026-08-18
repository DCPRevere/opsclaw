//! In-memory shared chat transcript (see `db::sqlite::chat` — SQLite is
//! the spec).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::InMemoryDb;
use crate::Result;
use crate::db::{ChatMessage, ChatRequestClaim};

#[async_trait]
impl crate::db::ChatRepo for InMemoryDb {
    async fn claim_chat_request(
        &self,
        account: uuid::Uuid,
        key: &str,
        _started_at: DateTime<Utc>,
    ) -> Result<ChatRequestClaim> {
        use std::collections::hash_map::Entry;
        let mut store = self.store.lock().unwrap();
        match store.chat_requests.entry((account, key.to_string())) {
            Entry::Vacant(entry) => {
                entry.insert(ChatRequestClaim::Pending);
                Ok(ChatRequestClaim::Claimed)
            }
            Entry::Occupied(entry) => Ok(entry.get().clone()),
        }
    }

    async fn complete_chat_request(
        &self,
        account: uuid::Uuid,
        key: &str,
        reply: &str,
        _finished_at: DateTime<Utc>,
    ) -> Result<()> {
        finish(
            &mut self.store.lock().unwrap().chat_requests,
            account,
            key,
            ChatRequestClaim::Complete(reply.to_string()),
        )
    }

    async fn fail_chat_request(
        &self,
        account: uuid::Uuid,
        key: &str,
        _finished_at: DateTime<Utc>,
    ) -> Result<()> {
        finish(
            &mut self.store.lock().unwrap().chat_requests,
            account,
            key,
            ChatRequestClaim::Failed,
        )
    }

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

    async fn before_chat(&self, before_seq: i64, limit: i64) -> Result<Vec<ChatMessage>> {
        let store = self.store.lock().unwrap();
        let earlier: Vec<ChatMessage> =
            store.chat_messages.iter().filter(|m| m.seq < before_seq).cloned().collect();
        let start = earlier.len().saturating_sub(limit.max(0) as usize);
        Ok(earlier[start..].to_vec())
    }
}

fn finish(
    requests: &mut std::collections::HashMap<(uuid::Uuid, String), ChatRequestClaim>,
    account: uuid::Uuid,
    key: &str,
    outcome: ChatRequestClaim,
) -> Result<()> {
    let stored = requests
        .get_mut(&(account, key.to_string()))
        .ok_or_else(|| crate::Error::NotFound("chat request".into()))?;
    if *stored != ChatRequestClaim::Pending {
        return Err(crate::Error::Conflict("chat request is already terminal".into()));
    }
    *stored = outcome;
    Ok(())
}
