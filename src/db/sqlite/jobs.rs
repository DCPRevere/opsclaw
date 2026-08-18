use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::db::JobFailure;
use crate::domain::Job;
use crate::{Error, Result};

fn row_to_job(row: &SqliteRow) -> Job {
    let schedule_json: String = row.get("schedule");
    let payload_json: String = row.get("payload");
    Job {
        id: Uuid::parse_str(row.get("id")).expect("stored uuid"),
        name: row.get("name"),
        schedule: serde_json::from_str(&schedule_json).expect("stored Schedule json"),
        payload: serde_json::from_str(&payload_json).expect("stored Payload json"),
        enabled: row.get::<i64, _>("enabled") != 0,
        system: row.get::<i64, _>("system") != 0,
        next_run_at: row
            .get::<Option<String>, _>("next_run_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("stored rfc3339")),
        last_run_at: row
            .get::<Option<String>, _>("last_run_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("stored rfc3339")),
        created_at: row.get::<String, _>("created_at").parse().expect("stored rfc3339"),
        version: row.get("version"),
    }
}

fn row_to_failure(row: &SqliteRow) -> JobFailure {
    JobFailure {
        job_id: Uuid::parse_str(row.get("job_id")).expect("stored uuid"),
        occurrence_key: row.get("occurrence_key"),
        attempts: row.get("attempts"),
        first_failed_at: row.get::<String, _>("first_failed_at").parse().expect("stored rfc3339"),
        last_failed_at: row.get::<String, _>("last_failed_at").parse().expect("stored rfc3339"),
        last_error: row.get("last_error"),
    }
}

#[async_trait]
impl crate::db::JobRepo for SqliteDb {
    async fn insert(&self, job: &Job) -> Result<()> {
        let schedule_json = serde_json::to_string(&job.schedule)
            .map_err(|e| Error::Other(format!("encode schedule: {e}")))?;
        let payload_json = serde_json::to_string(&job.payload)
            .map_err(|e| Error::Other(format!("encode payload: {e}")))?;
        sqlx::query(
            "INSERT INTO jobs
               (id, name, schedule, payload, enabled, system, next_run_at, last_run_at,
                created_at, version)
             VALUES (?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(job.id.to_string())
        .bind(&job.name)
        .bind(schedule_json)
        .bind(payload_json)
        .bind(job.enabled)
        .bind(job.system)
        .bind(job.next_run_at.map(|t| t.to_rfc3339()))
        .bind(job.last_run_at.map(|t| t.to_rfc3339()))
        .bind(job.created_at.to_rfc3339())
        .bind(job.version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Job>> {
        let row = sqlx::query("SELECT * FROM jobs WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_job))
    }

    async fn update(&self, job: &Job) -> Result<Job> {
        let schedule_json = serde_json::to_string(&job.schedule)
            .map_err(|e| Error::Other(format!("encode schedule: {e}")))?;
        let payload_json = serde_json::to_string(&job.payload)
            .map_err(|e| Error::Other(format!("encode payload: {e}")))?;
        let new_version = job.version + 1;
        // Optimistic-concurrency CAS: only a writer whose `version` still
        // matches the stored row gets to write; the loser sees 0 rows
        // affected (RETURNING empty) and gets Conflict, never a silent
        // clobber of a concurrent writer's change.
        let row = sqlx::query(
            "UPDATE jobs SET name=?, schedule=?, payload=?, enabled=?, system=?,
                next_run_at=?, last_run_at=?, version=?
             WHERE id=? AND version=?
             RETURNING *",
        )
        .bind(&job.name)
        .bind(schedule_json)
        .bind(payload_json)
        .bind(job.enabled)
        .bind(job.system)
        .bind(job.next_run_at.map(|t| t.to_rfc3339()))
        .bind(job.last_run_at.map(|t| t.to_rfc3339()))
        .bind(new_version)
        .bind(job.id.to_string())
        .bind(job.version)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(row_to_job(&r)),
            None => {
                let exists = sqlx::query("SELECT 1 AS x FROM jobs WHERE id = ?")
                    .bind(job.id.to_string())
                    .fetch_optional(&self.pool)
                    .await?
                    .is_some();
                if exists {
                    Err(Error::Conflict(format!(
                        "job {} version mismatch (expected {})",
                        job.id, job.version
                    )))
                } else {
                    Err(Error::NotFound(format!("job {}", job.id)))
                }
            }
        }
    }

    async fn delete(&self, id: Uuid) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM job_failures WHERE job_id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        let removed = sqlx::query("DELETE FROM jobs WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?
            .rows_affected()
            > 0;
        tx.commit().await?;
        Ok(removed)
    }

    async fn due_jobs(&self, now: DateTime<Utc>) -> Result<Vec<Job>> {
        let rows = sqlx::query(
            "SELECT * FROM jobs WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?
             ORDER BY next_run_at",
        )
        .bind(now.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_job).collect())
    }

    async fn list(&self) -> Result<Vec<Job>> {
        let rows =
            sqlx::query("SELECT * FROM jobs ORDER BY created_at").fetch_all(&self.pool).await?;
        Ok(rows.iter().map(row_to_job).collect())
    }

    async fn record_job_failure(
        &self,
        job_id: Uuid,
        occurrence_key: &str,
        error: &str,
        at: DateTime<Utc>,
    ) -> Result<JobFailure> {
        let row = sqlx::query(
            "INSERT INTO job_failures (job_id, occurrence_key, attempts, first_failed_at, last_failed_at, last_error)
             VALUES (?,?,1,?,?,?)
             ON CONFLICT (job_id, occurrence_key) DO UPDATE SET
               attempts = job_failures.attempts + 1,
               last_failed_at = excluded.last_failed_at,
               last_error = excluded.last_error
             RETURNING *",
        )
        .bind(job_id.to_string())
        .bind(occurrence_key)
        .bind(at.to_rfc3339())
        .bind(at.to_rfc3339())
        .bind(error)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_to_failure(&row))
    }

    async fn job_failure_state(
        &self,
        job_id: Uuid,
        occurrence_key: &str,
    ) -> Result<Option<JobFailure>> {
        let row = sqlx::query("SELECT * FROM job_failures WHERE job_id = ? AND occurrence_key = ?")
            .bind(job_id.to_string())
            .bind(occurrence_key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_failure))
    }

    async fn clear_job_failure(&self, job_id: Uuid, occurrence_key: &str) -> Result<()> {
        sqlx::query("DELETE FROM job_failures WHERE job_id = ? AND occurrence_key = ?")
            .bind(job_id.to_string())
            .bind(occurrence_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn count_job_failures(&self, job_id: Uuid) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM job_failures WHERE job_id = ?")
            .bind(job_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("n"))
    }

    async fn clear_job_failures_for_job(&self, job_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM job_failures WHERE job_id = ?")
            .bind(job_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn latest_job_failure(&self, job_id: Uuid) -> Result<Option<JobFailure>> {
        let row = sqlx::query(
            "SELECT * FROM job_failures WHERE job_id = ? ORDER BY last_failed_at DESC LIMIT 1",
        )
        .bind(job_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_failure))
    }
}
