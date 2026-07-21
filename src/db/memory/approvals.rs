use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::InMemoryDb;
use crate::domain::{ApprovalRequest, ApprovalState};
use crate::{Error, Result};

#[async_trait]
impl crate::db::ApprovalRepo for InMemoryDb {
    async fn insert(&self, req: &ApprovalRequest) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.approvals.insert(req.id, req.clone());
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ApprovalRequest>> {
        let store = self.store.lock().unwrap();
        Ok(store.approvals.get(&id).cloned())
    }

    async fn decide(&self, id: Uuid, state: ApprovalState, by: Uuid) -> Result<ApprovalRequest> {
        let mut store = self.store.lock().unwrap();
        match store.approvals.get_mut(&id) {
            Some(req) if req.state == ApprovalState::Pending => {
                req.state = state;
                req.decided_at = Some(Utc::now());
                req.decided_by = Some(by);
                Ok(req.clone())
            }
            Some(_) => Err(Error::Conflict(format!("approval {id} already decided"))),
            None => Err(Error::NotFound(format!("approval {id}"))),
        }
    }

    async fn mark_executed(&self, id: Uuid) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        if let Some(req) = store.approvals.get_mut(&id) {
            req.state = ApprovalState::Executed;
        }
        Ok(())
    }

    async fn list_pending(&self) -> Result<Vec<ApprovalRequest>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<ApprovalRequest> = store
            .approvals
            .values()
            .filter(|r| r.state == ApprovalState::Pending)
            .cloned()
            .collect();
        v.sort_by_key(|r| r.requested_at);
        Ok(v)
    }

    async fn expire_due(&self, now: DateTime<Utc>) -> Result<Vec<ApprovalRequest>> {
        let mut store = self.store.lock().unwrap();
        let mut expired = Vec::new();
        for req in store.approvals.values_mut() {
            if req.state == ApprovalState::Pending && req.expires_at <= now {
                req.state = ApprovalState::Expired;
                expired.push(req.clone());
            }
        }
        Ok(expired)
    }
}
