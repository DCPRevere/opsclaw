use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::db::{RunbookRun, RunbookSuccessRate};
use crate::{Error, Result};

fn row_to_run(row: &SqliteRow) -> RunbookRun {
    let principal_json: Option<String> = row.get("principal");
    let steps_json: String = row.get("steps");
    RunbookRun {
        id: Uuid::parse_str(row.get("id")).expect("stored uuid"),
        runbook: row.get("runbook_name"),
        target: crate::domain::FqTarget::parse(row.get("fq_target")).expect("stored fq target"),
        principal: principal_json.map(|j| serde_json::from_str(&j).expect("stored Principal json")),
        started_at: row.get::<String, _>("started_at").parse().expect("stored rfc3339"),
        finished_at: row
            .get::<Option<String>, _>("finished_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("stored rfc3339")),
        steps: serde_json::from_str(&steps_json).expect("stored steps json"),
    }
}

#[async_trait]
impl crate::db::RunbookRunRepo for SqliteDb {
    async fn record_run(&self, run: &RunbookRun) -> Result<()> {
        let principal_json = run
            .principal
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| Error::Other(format!("encode principal: {e}")))?;
        let steps_json = serde_json::to_string(&run.steps)
            .map_err(|e| Error::Other(format!("encode steps: {e}")))?;
        // `success` is derived from the run, not a field — stored as a column
        // so the success_rate aggregate stays a cheap SUM.
        sqlx::query(
            "INSERT INTO runbook_runs
               (id, runbook_name, fq_target, principal, started_at, finished_at, success, steps)
             VALUES (?,?,?,?,?,?,?,?)",
        )
        .bind(run.id.to_string())
        .bind(&run.runbook)
        .bind(run.target.to_string())
        .bind(principal_json)
        .bind(run.started_at.to_rfc3339())
        .bind(run.finished_at.map(|t| t.to_rfc3339()))
        .bind(run.succeeded() as i64)
        .bind(steps_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<RunbookRun>> {
        let row = sqlx::query("SELECT * FROM runbook_runs WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_run))
    }

    async fn list_for_runbook(&self, runbook_name: &str, limit: i64) -> Result<Vec<RunbookRun>> {
        let rows = sqlx::query(
            "SELECT * FROM runbook_runs WHERE runbook_name = ? ORDER BY started_at DESC LIMIT ?",
        )
        .bind(runbook_name)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_run).collect())
    }

    async fn success_rate(&self, runbook_name: &str) -> Result<RunbookSuccessRate> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS total, COALESCE(SUM(success), 0) AS successes
             FROM runbook_runs WHERE runbook_name = ?",
        )
        .bind(runbook_name)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.get("total");
        let successes: i64 = row.get("successes");
        let rate = if total > 0 { successes as f64 / total as f64 } else { 0.0 };
        Ok(RunbookSuccessRate { total_runs: total, successful_runs: successes, rate })
    }
}
