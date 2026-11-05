use async_trait::async_trait;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use super::SqliteDb;
use crate::audit::{AuditOutcome, AuditRecord};
use crate::domain::{Principal, RiskClass};
use crate::{Error, Result};

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
        other => panic!("audit_log.risk holds unrecognized value {other:?}"),
    }
}

fn outcome_str(o: AuditOutcome) -> &'static str {
    match o {
        AuditOutcome::Begun => "begun",
        AuditOutcome::Executed => "executed",
        AuditOutcome::Blocked => "blocked",
        AuditOutcome::Denied => "denied",
        AuditOutcome::ApprovalQueued => "approval_queued",
        AuditOutcome::EStopped => "estopped",
        AuditOutcome::Error => "error",
    }
}

fn parse_outcome(s: &str) -> AuditOutcome {
    match s {
        "begun" => AuditOutcome::Begun,
        "executed" => AuditOutcome::Executed,
        "blocked" => AuditOutcome::Blocked,
        "denied" => AuditOutcome::Denied,
        "approval_queued" => AuditOutcome::ApprovalQueued,
        "estopped" => AuditOutcome::EStopped,
        "error" => AuditOutcome::Error,
        other => panic!("audit_log.outcome holds unrecognized value {other:?}"),
    }
}

fn row_to_record(row: &SqliteRow) -> AuditRecord {
    let principal_json: String = row.get("principal");
    AuditRecord {
        id: uuid::Uuid::parse_str(row.get("id")).expect("stored uuid"),
        seq: row.get("seq"),
        ts: row.get::<String, _>("ts").parse().expect("stored rfc3339"),
        principal: serde_json::from_str::<Principal>(&principal_json)
            .expect("stored Principal json"),
        fq_target: row.get("fq_target"),
        tool: row.get("tool"),
        command: row.get("command"),
        risk: parse_risk(row.get::<String, _>("risk").as_str()),
        outcome: parse_outcome(row.get::<String, _>("outcome").as_str()),
        exit_code: row.get("exit_code"),
        prev_hash: row.get("prev_hash"),
        hash: row.get("hash"),
    }
}

#[async_trait]
impl crate::db::AuditRepo for SqliteDb {
    async fn append(&self, record: &AuditRecord) -> Result<()> {
        // Reject a seq that isn't exactly last+1 — the repo enforces chain
        // contiguity; the caller (audit layer) computes seq/prev_hash/hash.
        let last_seq: Option<i64> = sqlx::query("SELECT MAX(seq) AS m FROM audit_log")
            .fetch_one(&self.pool)
            .await?
            .get("m");
        let expected = last_seq.unwrap_or(0) + 1;
        if record.seq != expected {
            return Err(Error::Conflict(format!(
                "audit append: seq {} is not last+1 (expected {expected})",
                record.seq
            )));
        }
        let principal_json = serde_json::to_string(&record.principal)
            .map_err(|e| Error::Other(format!("encode principal: {e}")))?;
        // UNIQUE(seq) is the backstop against a lost race between the
        // MAX(seq) read above and this INSERT under concurrent appenders;
        // the audit layer is documented to serialize appends, but the
        // constraint makes the invariant hold even if that discipline slips.
        let res = sqlx::query(
            "INSERT INTO audit_log
               (id, seq, ts, principal, fq_target, tool, command, risk, outcome,
                exit_code, prev_hash, hash)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(record.id.to_string())
        .bind(record.seq)
        .bind(record.ts.to_rfc3339())
        .bind(principal_json)
        .bind(&record.fq_target)
        .bind(&record.tool)
        .bind(&record.command)
        .bind(risk_str(record.risk))
        .bind(outcome_str(record.outcome))
        .bind(record.exit_code)
        .bind(&record.prev_hash)
        .bind(&record.hash)
        .execute(&self.pool)
        .await;
        match res {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                Err(Error::Conflict(format!("audit append: seq {} already written", record.seq)))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn last(&self) -> Result<Option<AuditRecord>> {
        let row = sqlx::query("SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_record))
    }

    async fn range(&self, from_seq: i64, limit: i64) -> Result<Vec<AuditRecord>> {
        let rows = sqlx::query("SELECT * FROM audit_log WHERE seq >= ? ORDER BY seq LIMIT ?")
            .bind(from_seq)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_record).collect())
    }
}
