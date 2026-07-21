use async_trait::async_trait;
use uuid::Uuid;

use super::InMemoryDb;
use crate::Result;
use crate::db::{RunbookRun, RunbookSuccessRate};

#[async_trait]
impl crate::db::RunbookRunRepo for InMemoryDb {
    async fn record_run(&self, run: &RunbookRun) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.runbook_runs.insert(run.id, run.clone());
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<RunbookRun>> {
        let store = self.store.lock().unwrap();
        Ok(store.runbook_runs.get(&id).cloned())
    }

    async fn list_for_runbook(&self, runbook_name: &str, limit: i64) -> Result<Vec<RunbookRun>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<RunbookRun> =
            store.runbook_runs.values().filter(|r| r.runbook == runbook_name).cloned().collect();
        v.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn success_rate(&self, runbook_name: &str) -> Result<RunbookSuccessRate> {
        let store = self.store.lock().unwrap();
        let runs: Vec<&RunbookRun> =
            store.runbook_runs.values().filter(|r| r.runbook == runbook_name).collect();
        let total = runs.len() as i64;
        let successes = runs.iter().filter(|r| r.succeeded()).count() as i64;
        let rate = if total > 0 { successes as f64 / total as f64 } else { 0.0 };
        Ok(RunbookSuccessRate { total_runs: total, successful_runs: successes, rate })
    }
}
