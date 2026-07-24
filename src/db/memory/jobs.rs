use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::InMemoryDb;
use crate::db::JobFailure;
use crate::domain::Job;
use crate::{Error, Result};

#[async_trait]
impl crate::db::JobRepo for InMemoryDb {
    async fn insert(&self, job: &Job) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.jobs.insert(job.id, job.clone());
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Job>> {
        let store = self.store.lock().unwrap();
        Ok(store.jobs.get(&id).cloned())
    }

    async fn update(&self, job: &Job) -> Result<Job> {
        let mut store = self.store.lock().unwrap();
        match store.jobs.get_mut(&job.id) {
            Some(existing) if existing.version == job.version => {
                let mut updated = job.clone();
                updated.version += 1;
                *existing = updated.clone();
                Ok(updated)
            }
            Some(existing) => Err(Error::Conflict(format!(
                "job {} version mismatch (expected {}, stored {})",
                job.id, job.version, existing.version
            ))),
            None => Err(Error::NotFound(format!("job {}", job.id))),
        }
    }

    async fn due_jobs(&self, now: DateTime<Utc>) -> Result<Vec<Job>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<Job> = store.jobs.values().filter(|j| j.is_due(now)).cloned().collect();
        v.sort_by_key(|j| j.next_run_at);
        Ok(v)
    }

    async fn list(&self) -> Result<Vec<Job>> {
        let store = self.store.lock().unwrap();
        let mut v: Vec<Job> = store.jobs.values().cloned().collect();
        v.sort_by_key(|j| j.created_at);
        Ok(v)
    }

    async fn record_job_failure(
        &self,
        job_id: Uuid,
        occurrence_key: &str,
        error: &str,
        at: DateTime<Utc>,
    ) -> Result<JobFailure> {
        let mut store = self.store.lock().unwrap();
        let key = (job_id, occurrence_key.to_string());
        let entry = store.job_failures.entry(key).or_insert_with(|| JobFailure {
            job_id,
            occurrence_key: occurrence_key.to_string(),
            attempts: 0,
            first_failed_at: at,
            last_failed_at: at,
            last_error: error.to_string(),
        });
        entry.attempts += 1;
        entry.last_failed_at = at;
        entry.last_error = error.to_string();
        Ok(entry.clone())
    }

    async fn job_failure_state(
        &self,
        job_id: Uuid,
        occurrence_key: &str,
    ) -> Result<Option<JobFailure>> {
        let store = self.store.lock().unwrap();
        Ok(store.job_failures.get(&(job_id, occurrence_key.to_string())).cloned())
    }

    async fn clear_job_failure(&self, job_id: Uuid, occurrence_key: &str) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.job_failures.remove(&(job_id, occurrence_key.to_string()));
        Ok(())
    }

    async fn count_job_failures(&self, job_id: Uuid) -> Result<i64> {
        let store = self.store.lock().unwrap();
        Ok(store.job_failures.keys().filter(|(id, _)| *id == job_id).count() as i64)
    }

    async fn clear_job_failures_for_job(&self, job_id: Uuid) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.job_failures.retain(|(id, _), _| *id != job_id);
        Ok(())
    }

    async fn latest_job_failure(&self, job_id: Uuid) -> Result<Option<JobFailure>> {
        let store = self.store.lock().unwrap();
        Ok(store
            .job_failures
            .iter()
            .filter(|((id, _), _)| *id == job_id)
            .map(|(_, f)| f)
            .max_by_key(|f| f.last_failed_at)
            .cloned())
    }
}
