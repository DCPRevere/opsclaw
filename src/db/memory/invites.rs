//! Teammate invites (additive, Wave 4 — see `db::repo`'s module doc for why
//! this exists with no Wave 0 analog).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::InMemoryDb;
use crate::Result;
use crate::db::Invite;

#[async_trait]
impl crate::db::InviteRepo for InMemoryDb {
    async fn create_invite(&self, invite: &Invite) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.invites.insert(invite.code.clone(), (invite.clone(), false));
        Ok(())
    }

    async fn get_invite(&self, code: &str, now: DateTime<Utc>) -> Result<Option<Invite>> {
        let store = self.store.lock().unwrap();
        Ok(store
            .invites
            .get(code)
            .filter(|(i, consumed)| !consumed && i.expires_at > now)
            .map(|(i, _)| i.clone()))
    }

    async fn take_invite(&self, code: &str, now: DateTime<Utc>) -> Result<Option<Invite>> {
        let mut store = self.store.lock().unwrap();
        let Some((invite, consumed)) = store.invites.get_mut(code) else { return Ok(None) };
        if *consumed || invite.expires_at <= now {
            return Ok(None);
        }
        *consumed = true;
        Ok(Some(invite.clone()))
    }

    async fn list_open_invites(&self, now: DateTime<Utc>) -> Result<Vec<Invite>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<Invite> = store
            .invites
            .values()
            .filter(|(i, consumed)| !consumed && i.expires_at > now)
            .map(|(i, _)| i.clone())
            .collect();
        v.sort_by_key(|i| std::cmp::Reverse(i.created_at));
        Ok(v)
    }

    async fn revoke_invite(&self, code: &str) -> Result<bool> {
        let mut store = self.store.lock().unwrap();
        match store.invites.get_mut(code) {
            Some((_, consumed)) if !*consumed => {
                *consumed = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
