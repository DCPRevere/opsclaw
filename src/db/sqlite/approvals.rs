use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use super::SqliteDb;
use crate::domain::{ApprovalRequest, ApprovalState, RiskClass};
use crate::{Error, Result};

fn state_str(s: ApprovalState) -> &'static str {
    match s {
        ApprovalState::Pending => "pending",
        ApprovalState::Approved => "approved",
        ApprovalState::Denied => "denied",
        ApprovalState::Expired => "expired",
        ApprovalState::Executed => "executed",
    }
}

fn parse_state(s: &str) -> ApprovalState {
    match s {
        "pending" => ApprovalState::Pending,
        "approved" => ApprovalState::Approved,
        "denied" => ApprovalState::Denied,
        "expired" => ApprovalState::Expired,
        "executed" => ApprovalState::Executed,
        other => panic!("approvals.state holds unrecognized value {other:?}"),
    }
}

fn risk_str(r: RiskClass) -> &'static str {
    match r {
        RiskClass::Read => "read",
        RiskClass::Medium => "medium",
        RiskClass::High => "high",
        RiskClass::Destructive => "destructive",
    }
}

fn parse_risk(s: &str) -> RiskClass {
    match s {
        "read" => RiskClass::Read,
        "medium" => RiskClass::Medium,
        "high" => RiskClass::High,
        "destructive" => RiskClass::Destructive,
        other => panic!("approvals.risk holds unrecognized value {other:?}"),
    }
}

fn row_to_approval(row: &SqliteRow) -> ApprovalRequest {
    let requested_by_json: String = row.get("requested_by");
    let target_json: String = row.get("target");
    ApprovalRequest {
        id: Uuid::parse_str(row.get("id")).expect("stored uuid"),
        incident: row.get::<Option<String>, _>("incident").map(|s| Uuid::parse_str(&s).unwrap()),
        requested_by: serde_json::from_str(&requested_by_json).expect("stored Principal json"),
        target: serde_json::from_str(&target_json).expect("stored FqTarget json"),
        tool: row.get("tool"),
        command: row.get("command"),
        risk: parse_risk(row.get::<String, _>("risk").as_str()),
        hypothesis: row.get("hypothesis"),
        state: parse_state(row.get::<String, _>("state").as_str()),
        requested_at: row.get::<String, _>("requested_at").parse().expect("stored rfc3339"),
        expires_at: row.get::<String, _>("expires_at").parse().expect("stored rfc3339"),
        decided_at: row
            .get::<Option<String>, _>("decided_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("stored rfc3339")),
        decided_by: row
            .get::<Option<String>, _>("decided_by")
            .map(|s| Uuid::parse_str(&s).unwrap()),
    }
}

#[async_trait]
impl crate::db::ApprovalRepo for SqliteDb {
    async fn insert(&self, req: &ApprovalRequest) -> Result<()> {
        let requested_by_json = serde_json::to_string(&req.requested_by)
            .map_err(|e| Error::Other(format!("encode requested_by: {e}")))?;
        let target_json = serde_json::to_string(&req.target)
            .map_err(|e| Error::Other(format!("encode target: {e}")))?;
        sqlx::query(
            "INSERT INTO approvals
               (id, incident, requested_by, target, tool, command, risk, hypothesis,
                state, requested_at, expires_at, decided_at, decided_by)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(req.id.to_string())
        .bind(req.incident.map(|u| u.to_string()))
        .bind(requested_by_json)
        .bind(target_json)
        .bind(&req.tool)
        .bind(&req.command)
        .bind(risk_str(req.risk))
        .bind(&req.hypothesis)
        .bind(state_str(req.state))
        .bind(req.requested_at.to_rfc3339())
        .bind(req.expires_at.to_rfc3339())
        .bind(req.decided_at.map(|t| t.to_rfc3339()))
        .bind(req.decided_by.map(|u| u.to_string()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ApprovalRequest>> {
        let row = sqlx::query("SELECT * FROM approvals WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_approval))
    }

    async fn decide(&self, id: Uuid, state: ApprovalState, by: Uuid) -> Result<ApprovalRequest> {
        let now = Utc::now();
        // Atomic double-tap guard: the UPDATE only touches a row still
        // PENDING; RETURNING tells us whether it did. A second decide (or a
        // decide racing an expiry sweep) affects 0 rows and gets Conflict.
        let row = sqlx::query(
            "UPDATE approvals SET state = ?, decided_at = ?, decided_by = ?
             WHERE id = ? AND state = 'pending' AND expires_at > ?
             RETURNING *",
        )
        .bind(state_str(state))
        .bind(now.to_rfc3339())
        .bind(by.to_string())
        .bind(id.to_string())
        .bind(now.to_rfc3339())
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(row_to_approval(&r)),
            None => {
                // Distinguish "doesn't exist" / "already decided" / "past
                // its deadline" for a clearer error, but all three are
                // non-retryable the same way. The expiry arm matters for
                // safety, not just clarity: without the expires_at guard in
                // the UPDATE, a request the sweep hasn't reached yet would
                // stay approvable — and would execute a stale command —
                // arbitrarily long after its window closed.
                let existing = sqlx::query("SELECT state, expires_at FROM approvals WHERE id = ?")
                    .bind(id.to_string())
                    .fetch_optional(&self.pool)
                    .await?;
                match existing {
                    Some(r) if r.get::<String, _>("state") == "pending" => {
                        Err(Error::Conflict(format!(
                            "approval {id} expired at {} — re-request if still needed",
                            r.get::<String, _>("expires_at")
                        )))
                    }
                    Some(_) => Err(Error::Conflict(format!("approval {id} already decided"))),
                    None => Err(Error::NotFound(format!("approval {id}"))),
                }
            }
        }
    }

    async fn mark_executed(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE approvals SET state = 'executed' WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_pending(&self) -> Result<Vec<ApprovalRequest>> {
        let rows =
            sqlx::query("SELECT * FROM approvals WHERE state = 'pending' ORDER BY requested_at")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.iter().map(row_to_approval).collect())
    }

    async fn expire_due(&self, now: DateTime<Utc>) -> Result<Vec<ApprovalRequest>> {
        // RETURNING gives us exactly the rows this call flipped, so a
        // concurrent sweep (or a decide() racing in) can't double-count.
        let rows = sqlx::query(
            "UPDATE approvals SET state = 'expired'
             WHERE state = 'pending' AND expires_at <= ?
             RETURNING *",
        )
        .bind(now.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_approval).collect())
    }
}
