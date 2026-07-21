//! Hash-chained, append-only audit log (brief §5). Written by the policy
//! layer on both sides of execution; no bypass exists because the executor is
//! only reachable through policy. Chain verification: `opsclaw audit verify`.
//!
//! The chain structure is a STABLE FORMAT — changing the hashed field set or
//! order is a breaking change to `verify` and needs deliberate migration.
//! Chain implementation lands in Wave 2; the record shape is frozen here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{Principal, RiskClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Command ran; exit code recorded.
    Executed,
    Blocked,
    ApprovalQueued,
    EStopped,
    /// Transport/internal failure — the command may or may not have run.
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: Uuid,
    /// Monotonic position in the chain (rowid-backed).
    pub seq: i64,
    pub ts: DateTime<Utc>,
    pub principal: Principal,
    /// Fully-qualified target path, always (brief §4).
    pub fq_target: String,
    pub tool: String,
    /// The exact command line, post-scrubbing (secret values never land here).
    pub command: String,
    pub risk: RiskClass,
    pub outcome: AuditOutcome,
    pub exit_code: Option<i32>,
    /// SHA-256 of the previous record's `hash`; all-zero for the genesis record.
    pub prev_hash: String,
    /// SHA-256 over (seq, ts, principal, fq_target, tool, command, risk,
    /// outcome, exit_code, prev_hash) in canonical serialization.
    pub hash: String,
}
