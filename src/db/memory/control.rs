use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::InMemoryDb;
use crate::Result;

#[async_trait]
impl crate::db::ControlRepo for InMemoryDb {
    async fn estop_engaged(&self) -> Result<bool> {
        let store = self.store.lock().unwrap();
        Ok(store.estop_engaged)
    }

    async fn set_estop(&self, engaged: bool) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.estop_engaged = engaged;
        Ok(())
    }

    async fn claim(&self, kind: &str, key: &str, _at: DateTime<Utc>) -> Result<bool> {
        let mut store = self.store.lock().unwrap();
        Ok(store.claims.insert((kind.to_string(), key.to_string())))
    }

    async fn release(&self, kind: &str, key: &str) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.claims.remove(&(kind.to_string(), key.to_string()));
        Ok(())
    }

    async fn prune_housekeeping(&self, _now: DateTime<Utc>) -> Result<()> {
        // The fake keeps no timestamps on claims/job_failures/approvals (it
        // stores none of the timing metadata SQLite ages on), so there is
        // nothing time-windowed to sweep here. This is a deliberate, narrow
        // gap: prune_housekeeping is exercised for its Ok(()) contract, not
        // for actually shrinking the fake's maps — SQLite is the spec for
        // retention behaviour (AGENTS.md).
        Ok(())
    }
}
