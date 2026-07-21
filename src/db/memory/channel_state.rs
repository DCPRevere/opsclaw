//! In-memory Telegram roster + generic channel state (see
//! `db::sqlite::channel_state`'s and `db::repo`'s doc comments for
//! provenance).

use async_trait::async_trait;
use uuid::Uuid;

use super::InMemoryDb;
use crate::Result;

#[async_trait]
impl crate::db::ChannelStateRepo for InMemoryDb {
    async fn bind_telegram_chat(&self, chat_id: &str, operator_id: Uuid) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.telegram_roster.insert(chat_id.to_string(), operator_id);
        Ok(())
    }

    async fn unbind_telegram_chat(&self, chat_id: &str) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.telegram_roster.remove(chat_id);
        Ok(())
    }

    async fn find_telegram_operator(&self, chat_id: &str) -> Result<Option<Uuid>> {
        let store = self.store.lock().unwrap();
        Ok(store.telegram_roster.get(chat_id).copied())
    }

    async fn telegram_chat_ids_for(&self, operator: Option<Uuid>) -> Result<Vec<String>> {
        let store = self.store.lock().unwrap();
        Ok(match operator {
            None => store.telegram_roster.keys().cloned().collect(),
            Some(op) => store
                .telegram_roster
                .iter()
                .filter(|(_, v)| **v == op)
                .map(|(k, _)| k.clone())
                .collect(),
        })
    }

    async fn get_channel_state(&self, key: &str) -> Result<Option<String>> {
        let store = self.store.lock().unwrap();
        Ok(store.channel_state.get(key).cloned())
    }

    async fn set_channel_state(&self, key: &str, value: &str) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.channel_state.insert(key.to_string(), value.to_string());
        Ok(())
    }
}
