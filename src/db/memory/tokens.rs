//! Remote-CLI personal access tokens (additive, Wave 4 — see `db::repo`'s
//! module doc for why this exists with no Wave 0 analog).

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use super::InMemoryDb;
use crate::Result;
use crate::db::CliToken;

#[async_trait]
impl crate::db::TokenRepo for InMemoryDb {
    async fn create_cli_token(&self, token: CliToken, token_hash: &str) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.cli_tokens.insert(token_hash.to_string(), token);
        Ok(())
    }

    async fn find_cli_token(&self, token_hash: &str) -> Result<Option<(Uuid, Uuid)>> {
        let mut store = self.store.lock().unwrap();
        let Some(token) = store.cli_tokens.get_mut(token_hash) else { return Ok(None) };
        token.last_used_at = Some(Utc::now());
        Ok(Some((token.id, token.account)))
    }

    async fn list_cli_tokens(&self, account: Uuid) -> Result<Vec<CliToken>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<CliToken> =
            store.cli_tokens.values().filter(|t| t.account == account).cloned().collect();
        v.sort_by_key(|t| t.created_at);
        Ok(v)
    }

    async fn revoke_cli_token(&self, account: Uuid, token_id: Uuid) -> Result<bool> {
        let mut store = self.store.lock().unwrap();
        let hash = store
            .cli_tokens
            .iter()
            .find(|(_, t)| t.id == token_id && t.account == account)
            .map(|(h, _)| h.clone());
        match hash {
            Some(h) => {
                store.cli_tokens.remove(&h);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}
