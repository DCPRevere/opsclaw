//! Serialized append onto the audit chain. Sealing needs the current tail, so
//! appends are one-at-a-time behind a lock — audit volume is human-scale
//! (commands, not packets) and correctness of the chain beats throughput.

use std::sync::Arc;

use chrono::Utc;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::{AuditOutcome, AuditRecord, chain};
use crate::Result;
use crate::db::AuditRepo;
use crate::domain::{Principal, RiskClass};

pub struct AuditWriter {
    repo: Arc<dyn AuditRepo>,
    /// Serializes read-tail → seal → append so seq/prev_hash can't race.
    append_lock: Mutex<()>,
}

impl AuditWriter {
    pub fn new(repo: Arc<dyn AuditRepo>) -> Self {
        AuditWriter { repo, append_lock: Mutex::new(()) }
    }

    /// Seal and append one record. `command` must already be scrubbed — this
    /// layer persists what it is given.
    #[allow(clippy::too_many_arguments)]
    pub async fn append(
        &self,
        principal: &Principal,
        fq_target: &str,
        tool: &str,
        command: &str,
        risk: RiskClass,
        outcome: AuditOutcome,
        exit_code: Option<i32>,
    ) -> Result<AuditRecord> {
        let _guard = self.append_lock.lock().await;
        let tail = self.repo.last().await?;
        let record = AuditRecord {
            id: Uuid::new_v4(),
            seq: tail.as_ref().map(|t| t.seq + 1).unwrap_or(1),
            ts: Utc::now(),
            principal: principal.clone(),
            fq_target: fq_target.to_string(),
            tool: tool.to_string(),
            command: command.to_string(),
            risk,
            outcome,
            exit_code,
            prev_hash: String::new(),
            hash: String::new(),
        };
        let sealed = chain::seal(record, tail.as_ref())?;
        self.repo.append(&sealed).await?;
        Ok(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory::InMemoryDb;

    #[tokio::test]
    async fn appended_records_chain_and_verify() {
        let db = Arc::new(InMemoryDb::new());
        let w = AuditWriter::new(db.clone());
        let p = Principal::System;
        for i in 0..5 {
            w.append(
                &p,
                "remundo::prod::cluster",
                "ssh",
                &format!("uptime # {i}"),
                RiskClass::Read,
                AuditOutcome::Executed,
                Some(0),
            )
            .await
            .unwrap();
        }
        let records = db.range(1, 100).await.unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(chain::verify(records.iter()).unwrap(), 5);
    }

    #[tokio::test]
    async fn concurrent_appends_never_collide() {
        let db = Arc::new(InMemoryDb::new());
        let w = Arc::new(AuditWriter::new(db.clone()));
        let mut handles = Vec::new();
        for i in 0..20 {
            let w = w.clone();
            handles.push(tokio::spawn(async move {
                w.append(
                    &Principal::System,
                    "p::e::t",
                    "shell",
                    &format!("echo {i}"),
                    RiskClass::Read,
                    AuditOutcome::Executed,
                    Some(0),
                )
                .await
                .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let records = db.range(1, 100).await.unwrap();
        assert_eq!(chain::verify(records.iter()).unwrap(), 20);
    }
}
