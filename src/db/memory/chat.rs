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
        conversation: &str,
        key: &str,
        _started_at: DateTime<Utc>,
    ) -> Result<ChatRequestClaim> {
        use std::collections::hash_map::Entry;
        let mut store = self.store.lock().unwrap();
        match store.chat_requests.entry((account, key.to_string())) {
            Entry::Vacant(entry) => {
                entry.insert((conversation.to_string(), ChatRequestClaim::Pending));
                Ok(ChatRequestClaim::Claimed)
            }
            Entry::Occupied(entry) if entry.get().0 == conversation => Ok(entry.get().1.clone()),
            Entry::Occupied(_) => Err(crate::Error::Conflict(
                "idempotency key belongs to a different chat conversation".into(),
            )),
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
        conversation: &str,
        turn_id: Option<&str>,
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
            conversation: conversation.to_string(),
            turn_id: turn_id.map(str::to_string),
            role: role.to_string(),
            speaker: speaker.to_string(),
            content: content.to_string(),
        });
        Ok(())
    }

    async fn recent_chat(&self, conversation: &str, limit: i64) -> Result<Vec<ChatMessage>> {
        let store = self.store.lock().unwrap();
        let rows: Vec<_> = store
            .chat_messages
            .iter()
            .filter(|message| message.conversation == conversation)
            .cloned()
            .collect();
        let n = rows.len();
        let start = n.saturating_sub(limit.max(0) as usize);
        Ok(rows[start..].to_vec())
    }

    async fn before_chat(
        &self,
        conversation: &str,
        before_seq: i64,
        limit: i64,
    ) -> Result<Vec<ChatMessage>> {
        let store = self.store.lock().unwrap();
        let earlier: Vec<ChatMessage> = store
            .chat_messages
            .iter()
            .filter(|m| m.conversation == conversation && m.seq < before_seq)
            .cloned()
            .collect();
        let start = earlier.len().saturating_sub(limit.max(0) as usize);
        Ok(earlier[start..].to_vec())
    }
}

fn finish(
    requests: &mut std::collections::HashMap<(uuid::Uuid, String), (String, ChatRequestClaim)>,
    account: uuid::Uuid,
    key: &str,
    outcome: ChatRequestClaim,
) -> Result<()> {
    let stored = requests
        .get_mut(&(account, key.to_string()))
        .ok_or_else(|| crate::Error::NotFound("chat request".into()))?;
    if stored.1 != ChatRequestClaim::Pending {
        return Err(crate::Error::Conflict("chat request is already terminal".into()));
    }
    stored.1 = outcome;
    Ok(())
}
