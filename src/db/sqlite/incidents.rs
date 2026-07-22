use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::Result;
use crate::domain::{Incident, IncidentState, Severity};

fn state_str(s: IncidentState) -> &'static str {
    match s {
        IncidentState::Active => "active",
        IncidentState::Acknowledged => "acknowledged",
        IncidentState::Resolved => "resolved",
        IncidentState::Expired => "expired",
    }
}

fn parse_state(s: &str) -> IncidentState {
    match s {
        "active" => IncidentState::Active,
        "acknowledged" => IncidentState::Acknowledged,
        "resolved" => IncidentState::Resolved,
        "expired" => IncidentState::Expired,
        // Written only from state_str; an unrecognized value means the row
        // was corrupted out-of-band. Fail loudly rather than silently
        // reclassify an incident's lifecycle state.
        other => panic!("incidents.state holds unrecognized value {other:?}"),
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "info" => Severity::Info,
        "warning" => Severity::Warning,
        "critical" => Severity::Critical,
        other => panic!("incidents.severity holds unrecognized value {other:?}"),
    }
}

fn row_to_incident(row: &SqliteRow) -> Incident {
    let target_json: String = row.get("target");
    Incident {
        id: Uuid::parse_str(row.get("id")).expect("stored uuid"),
        fingerprint: row.get("fingerprint"),
        fault_class: row.get("fault_class"),
        target: serde_json::from_str(&target_json).expect("stored FqTarget json"),
        severity: parse_severity(row.get::<String, _>("severity").as_str()),
        state: parse_state(row.get::<String, _>("state").as_str()),
        signals: row.get("signals"),
        hypothesis: row.get("hypothesis"),
        recommended_action: row.get("recommended_action"),
        opened_at: row.get::<String, _>("opened_at").parse().expect("stored rfc3339"),
        acked_at: row
            .get::<Option<String>, _>("acked_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("stored rfc3339")),
        acked_by: row.get::<Option<String>, _>("acked_by").map(|s| Uuid::parse_str(&s).unwrap()),
        resolved_at: row
            .get::<Option<String>, _>("resolved_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("stored rfc3339")),
        last_notified_at: row
            .get::<Option<String>, _>("last_notified_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("stored rfc3339")),
        notify_count: row.get("notify_count"),
        escalation_step: row.get("escalation_step"),
        step_started_at: row
            .get::<Option<String>, _>("step_started_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("stored rfc3339")),
    }
}

#[async_trait]
impl crate::db::IncidentRepo for SqliteDb {
    async fn insert(&self, incident: &Incident) -> Result<()> {
        let target_json = serde_json::to_string(&incident.target)
            .map_err(|e| crate::Error::Other(format!("encode target: {e}")))?;
        sqlx::query(
            "INSERT INTO incidents
               (id, fingerprint, fault_class, target, severity, state, signals,
                hypothesis, recommended_action, opened_at, acked_at, acked_by,
                resolved_at, last_notified_at, notify_count, escalation_step,
                step_started_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(incident.id.to_string())
        .bind(&incident.fingerprint)
        .bind(&incident.fault_class)
        .bind(target_json)
        .bind(severity_str(incident.severity))
        .bind(state_str(incident.state))
        .bind(&incident.signals)
        .bind(&incident.hypothesis)
        .bind(&incident.recommended_action)
        .bind(incident.opened_at.to_rfc3339())
        .bind(incident.acked_at.map(|t| t.to_rfc3339()))
        .bind(incident.acked_by.map(|u| u.to_string()))
        .bind(incident.resolved_at.map(|t| t.to_rfc3339()))
        .bind(incident.last_notified_at.map(|t| t.to_rfc3339()))
        .bind(incident.notify_count)
        .bind(incident.escalation_step)
        .bind(incident.step_started_at.map(|t| t.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Incident>> {
        let row = sqlx::query("SELECT * FROM incidents WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_incident))
    }

    async fn find_open_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Incident>> {
        let row = sqlx::query(
            "SELECT * FROM incidents
             WHERE fingerprint = ? AND state IN ('active','acknowledged')
             ORDER BY opened_at DESC LIMIT 1",
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_incident))
    }

    async fn set_state(&self, id: Uuid, state: IncidentState, by: Option<Uuid>) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        match state {
            IncidentState::Acknowledged => {
                sqlx::query(
                    "UPDATE incidents SET state = ?, acked_at = ?, acked_by = ? WHERE id = ?",
                )
                .bind(state_str(state))
                .bind(&now)
                .bind(by.map(|u| u.to_string()))
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
            }
            IncidentState::Resolved => {
                sqlx::query("UPDATE incidents SET state = ?, resolved_at = ? WHERE id = ?")
                    .bind(state_str(state))
                    .bind(&now)
                    .bind(id.to_string())
                    .execute(&self.pool)
                    .await?;
            }
            _ => {
                sqlx::query("UPDATE incidents SET state = ? WHERE id = ?")
                    .bind(state_str(state))
                    .bind(id.to_string())
                    .execute(&self.pool)
                    .await?;
            }
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
        sqlx::query(
            "UPDATE incidents SET last_notified_at = ?, notify_count = notify_count + 1,
                    escalation_step = ?, step_started_at = ?
             WHERE id = ?",
        )
        .bind(at.to_rfc3339())
        .bind(step)
        .bind(step_started_at.to_rfc3339())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list(&self, include_closed: bool, limit: i64) -> Result<Vec<Incident>> {
        let rows = if include_closed {
            sqlx::query("SELECT * FROM incidents ORDER BY opened_at DESC LIMIT ?")
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query(
                "SELECT * FROM incidents WHERE state IN ('active','acknowledged')
                 ORDER BY opened_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows.iter().map(row_to_incident).collect())
    }
}
