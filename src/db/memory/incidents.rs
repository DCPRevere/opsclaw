use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::InMemoryDb;
use crate::Result;
use crate::domain::{Incident, IncidentState};

#[async_trait]
impl crate::db::IncidentRepo for InMemoryDb {
    async fn insert(&self, incident: &Incident) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.incidents.insert(incident.id, incident.clone());
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Incident>> {
        let store = self.store.lock().unwrap();
        Ok(store.incidents.get(&id).cloned())
    }

    async fn find_open_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Incident>> {
        let store = self.store.lock().unwrap();
        Ok(store
            .incidents
            .values()
            .filter(|i| {
                i.fingerprint == fingerprint
                    && matches!(i.state, IncidentState::Active | IncidentState::Acknowledged)
            })
            .max_by_key(|i| i.opened_at)
            .cloned())
    }

    async fn find_expired_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Incident>> {
        let store = self.store.lock().unwrap();
        Ok(store
            .incidents
            .values()
            .filter(|i| i.fingerprint == fingerprint && i.state == IncidentState::Expired)
            .max_by_key(|i| i.opened_at)
            .cloned())
    }

    async fn reopen(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        if let Some(i) = store.incidents.get_mut(&id) {
            i.state = IncidentState::Active;
            i.reopened_at = Some(at);
            i.escalation_step = 0;
            i.step_started_at = None;
        }
        Ok(())
    }

    async fn set_state(&self, id: Uuid, state: IncidentState, by: Option<Uuid>) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        if let Some(i) = store.incidents.get_mut(&id) {
            i.state = state;
            let now = Utc::now();
            match state {
                IncidentState::Acknowledged => {
                    i.acked_at = Some(now);
                    i.acked_by = by;
                }
                IncidentState::Resolved => {
                    i.resolved_at = Some(now);
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn accept(&self, id: Uuid, by: Option<Uuid>, at: DateTime<Utc>) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        if let Some(i) = store.incidents.get_mut(&id) {
            i.state = IncidentState::Acknowledged;
            if i.acked_at.is_none() {
                i.acked_at = Some(at);
                i.acked_by = by;
            }
            i.accepted_at = Some(at);
            i.accepted_by = by;
        }
        Ok(())
    }

    async fn unaccept(&self, id: Uuid) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        if let Some(i) = store.incidents.get_mut(&id) {
            i.accepted_at = None;
            i.accepted_by = None;
        }
        Ok(())
    }

    async fn record_notification(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
        step: i64,
        step_started_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        if let Some(i) = store.incidents.get_mut(&id) {
            i.last_notified_at = Some(at);
            i.notify_count += 1;
            i.escalation_step = step;
            i.step_started_at = Some(step_started_at);
        }
        Ok(())
    }

    async fn list(&self, include_closed: bool, limit: i64) -> Result<Vec<Incident>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<Incident> = store
            .incidents
            .values()
            .filter(|i| {
                include_closed
                    || matches!(i.state, IncidentState::Active | IncidentState::Acknowledged)
            })
            .cloned()
            .collect();
        v.sort_by_key(|i| std::cmp::Reverse(i.opened_at));
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }
}
