use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::InMemoryDb;
use crate::Result;
use crate::access::{Elevation, ElevationState, Label};

#[async_trait]
impl crate::db::AccessRepo for InMemoryDb {
    async fn set_groups(&self, account: Uuid, groups: &[String]) -> Result<()> {
        self.store.lock().unwrap().account_groups.insert(account, groups.to_vec());
        Ok(())
    }

    async fn groups(&self, account: Uuid) -> Result<Vec<String>> {
        Ok(self.store.lock().unwrap().account_groups.get(&account).cloned().unwrap_or_default())
    }

    async fn insert_elevation(&self, e: &Elevation) -> Result<()> {
        self.store.lock().unwrap().elevations.insert(e.id, e.clone());
        Ok(())
    }

    async fn elevation(&self, id: Uuid) -> Result<Option<Elevation>> {
        Ok(self.store.lock().unwrap().elevations.get(&id).cloned())
    }

    async fn elevations_for(&self, account: Uuid) -> Result<Vec<Elevation>> {
        let mut v: Vec<Elevation> = self
            .store
            .lock()
            .unwrap()
            .elevations
            .values()
            .filter(|e| e.account == account)
            .cloned()
            .collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.requested_at));
        Ok(v)
    }

    async fn list_elevations(&self) -> Result<Vec<Elevation>> {
        let mut v: Vec<Elevation> =
            self.store.lock().unwrap().elevations.values().cloned().collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.requested_at));
        Ok(v)
    }

    async fn decide_elevation(
        &self,
        id: Uuid,
        state: ElevationState,
        decided_by: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        let e = store
            .elevations
            .get_mut(&id)
            .ok_or_else(|| crate::Error::NotFound(format!("elevation {id}")))?;
        e.state = state;
        if decided_by.is_some() {
            e.decided_by = decided_by;
        }
        if let Some(t) = expires_at {
            e.expires_at = t;
        }
        Ok(())
    }

    async fn add_labels(&self, kind: &str, id: &str, labels: &[Label]) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        let entry = store.finding_labels.entry((kind.to_string(), id.to_string())).or_default();
        entry.0.extend(labels.iter().cloned());
        entry.0.sort();
        entry.0.dedup();
        Ok(())
    }

    async fn labels(&self, kind: &str, id: &str) -> Result<Vec<Label>> {
        let store = self.store.lock().unwrap();
        Ok(store
            .finding_labels
            .get(&(kind.to_string(), id.to_string()))
            .map(|e| e.0.clone())
            .unwrap_or_default())
    }

    async fn set_restricted(&self, kind: &str, id: &str, to: Option<&[String]>) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.finding_labels.entry((kind.to_string(), id.to_string())).or_default().1 =
            to.map(<[String]>::to_vec);
        Ok(())
    }

    async fn restricted(&self, kind: &str, id: &str) -> Result<Option<Vec<String>>> {
        let store = self.store.lock().unwrap();
        Ok(store.finding_labels.get(&(kind.to_string(), id.to_string())).and_then(|e| e.1.clone()))
    }
}
