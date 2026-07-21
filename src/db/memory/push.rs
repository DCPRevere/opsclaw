//! In-memory web-push subscription storage (see `db::sqlite::push`'s and
//! `db::repo`'s doc comments for provenance).

use async_trait::async_trait;

use super::InMemoryDb;
use crate::Result;
use crate::db::PushSubscription;

#[async_trait]
impl crate::db::PushSubscriptionRepo for InMemoryDb {
    async fn upsert_push_subscription(&self, sub: &PushSubscription) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.push_subscriptions.insert(sub.endpoint.clone(), sub.clone());
        Ok(())
    }

    async fn list_push_subscriptions(&self) -> Result<Vec<PushSubscription>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<PushSubscription> = store.push_subscriptions.values().cloned().collect();
        v.sort_by_key(|s| s.created_at);
        Ok(v)
    }

    async fn delete_push_subscription(&self, endpoint: &str) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.push_subscriptions.remove(endpoint);
        Ok(())
    }
}
