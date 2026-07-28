use async_trait::async_trait;
use uuid::Uuid;

use super::InMemoryDb;
use crate::Result;
use crate::db::Account;

#[async_trait]
impl crate::db::AccountRepo for InMemoryDb {
    async fn insert(&self, account: &Account) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        // Mirror migration 0009's partial unique index on
        // (auth_provider, external_subject). SQLite is the spec; without
        // this the fake silently accepts two accounts bound to the SAME
        // external identity, and `by_external_subject` then resolves
        // whichever the HashMap iterates first — so a test that double-links
        // a Hanko subject would pass against the fake and fail in
        // production. NULL subjects are exempt, matching the index
        // predicate (and SQL's treatment of NULLs as distinct).
        if let Some(subject) = account.external_subject.as_deref()
            && store.accounts.values().any(|a| {
                a.id != account.id
                    && a.auth_provider == account.auth_provider
                    && a.external_subject.as_deref() == Some(subject)
            })
        {
            return Err(crate::Error::Conflict(format!(
                "an account is already linked to {} subject {subject}",
                account.auth_provider
            )));
        }
        store.accounts.insert(account.id, account.clone());
        Ok(())
    }

    async fn by_email(&self, email: &str) -> Result<Option<Account>> {
        let store = self.store.lock().unwrap();
        Ok(store.accounts.values().find(|a| a.email == email).cloned())
    }

    async fn by_external_subject(&self, provider: &str, subject: &str) -> Result<Option<Account>> {
        // Exact equality on both columns, matching the SQLite predicate —
        // no case folding, since the subject is an opaque provider id.
        let store = self.store.lock().unwrap();
        Ok(store
            .accounts
            .values()
            .find(|a| a.auth_provider == provider && a.external_subject.as_deref() == Some(subject))
            .cloned())
    }

    async fn set_password_hash(&self, id: Uuid, password_hash: &str) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        if let Some(a) = store.accounts.get_mut(&id) {
            a.password_hash = password_hash.to_string();
        }
        Ok(())
    }

    async fn link_external_subject(
        &self,
        id: Uuid,
        provider: &str,
        subject: &str,
        password_hash: Option<&str>,
    ) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        // Same uniqueness rule as the SQLite index — SQLite is the spec.
        if store.accounts.values().any(|a| {
            a.id != id
                && a.auth_provider == provider
                && a.external_subject.as_deref() == Some(subject)
        }) {
            return Err(crate::Error::Conflict(format!(
                "another account is already linked to {provider} subject {subject}"
            )));
        }
        if let Some(a) = store.accounts.get_mut(&id) {
            a.auth_provider = provider.to_string();
            a.external_subject = Some(subject.to_string());
            // None keeps the existing hash — mirrors the SQLite COALESCE.
            if let Some(h) = password_hash {
                a.password_hash = h.to_string();
            }
        }
        Ok(())
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
