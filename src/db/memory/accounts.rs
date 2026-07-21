use async_trait::async_trait;
use uuid::Uuid;

use super::InMemoryDb;
use crate::Result;
use crate::db::Account;

#[async_trait]
impl crate::db::AccountRepo for InMemoryDb {
    async fn insert(&self, account: &Account) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.accounts.insert(account.id, account.clone());
        Ok(())
    }

    async fn by_email(&self, email: &str) -> Result<Option<Account>> {
        let store = self.store.lock().unwrap();
        Ok(store.accounts.values().find(|a| a.email == email).cloned())
    }

    async fn by_id(&self, id: Uuid) -> Result<Option<Account>> {
        let store = self.store.lock().unwrap();
        Ok(store.accounts.get(&id).cloned())
    }

    async fn bump_token_version(&self, id: Uuid) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        if let Some(a) = store.accounts.get_mut(&id) {
            a.token_version += 1;
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<Account>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<Account> = store.accounts.values().cloned().collect();
        v.sort_by_key(|a| a.created_at);
        Ok(v)
    }
}
