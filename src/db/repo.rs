//! Repository traits — the persistence contracts frozen at Wave 0.
//!
//! Rules (gianna's, hard-won): implementations use runtime-checked sqlx (the
//! crate must build with no live DB); applied migrations are immutable; every
//! trait method is exercised by the parity suite against BOTH backends.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::Result;
use crate::audit::AuditRecord;
use crate::domain::{ApprovalRequest, ApprovalState, Incident, IncidentState};

#[async_trait]
pub trait IncidentRepo: Send + Sync {
    async fn insert(&self, incident: &Incident) -> Result<()>;
    async fn get(&self, id: Uuid) -> Result<Option<Incident>>;
    /// Open incident (Active/Acknowledged) matching this fingerprint, if any —
    /// the anti-spam lookup.
    async fn find_open_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Incident>>;
    async fn set_state(&self, id: Uuid, state: IncidentState, by: Option<Uuid>) -> Result<()>;
    async fn record_notification(&self, id: Uuid, at: DateTime<Utc>) -> Result<()>;
    async fn list(&self, include_closed: bool, limit: i64) -> Result<Vec<Incident>>;
}

#[async_trait]
pub trait ApprovalRepo: Send + Sync {
    async fn insert(&self, req: &ApprovalRequest) -> Result<()>;
    async fn get(&self, id: Uuid) -> Result<Option<ApprovalRequest>>;
    /// Atomically decide a PENDING request; returns the updated row or
    /// `Error::Conflict` if it was already decided/expired (double-tap guard).
    async fn decide(&self, id: Uuid, state: ApprovalState, by: Uuid) -> Result<ApprovalRequest>;
    async fn mark_executed(&self, id: Uuid) -> Result<()>;
    async fn list_pending(&self) -> Result<Vec<ApprovalRequest>>;
    /// Expire pending requests past their deadline; returns those expired
    /// (the scheduler sweep notifies about them).
    async fn expire_due(&self, now: DateTime<Utc>) -> Result<Vec<ApprovalRequest>>;
}

#[async_trait]
pub trait AuditRepo: Send + Sync {
    /// Append one record. The chain fields (`seq`, `prev_hash`, `hash`) are
    /// computed by the audit layer inside a serialized append — the repo only
    /// persists; it must reject a `seq` that isn't exactly last+1.
    async fn append(&self, record: &AuditRecord) -> Result<()>;
    async fn last(&self) -> Result<Option<AuditRecord>>;
    /// Page through the chain in seq order for `audit verify` and inspection.
    async fn range(&self, from_seq: i64, limit: i64) -> Result<Vec<AuditRecord>>;
}

/// Operator accounts (web UI auth; Wave 4 fills the auth stack around this).
#[derive(Debug, Clone)]
pub struct Account {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    /// Bumping invalidates all outstanding JWTs (gianna's revocation).
    pub token_version: i64,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait AccountRepo: Send + Sync {
    async fn insert(&self, account: &Account) -> Result<()>;
    async fn by_email(&self, email: &str) -> Result<Option<Account>>;
    async fn by_id(&self, id: Uuid) -> Result<Option<Account>>;
    async fn bump_token_version(&self, id: Uuid) -> Result<()>;
    async fn list(&self) -> Result<Vec<Account>>;
}

/// Daemon control state: e-stop flag, exactly-once claims, housekeeping.
#[async_trait]
pub trait ControlRepo: Send + Sync {
    /// DB half of the e-stop (the file sentinel is the other half).
    async fn estop_engaged(&self) -> Result<bool>;
    async fn set_estop(&self, engaged: bool) -> Result<()>;

    /// Crash-safe exactly-once claim (gianna's `digest_sends` generalized):
    /// returns true iff this (kind, key) was newly claimed. Claim BEFORE
    /// composing/sending, keyed per occurrence — never per calendar day.
    async fn claim(&self, kind: &str, key: &str, at: DateTime<Utc>) -> Result<bool>;

    /// Time-windowed cleanup of expired claims and similar bookkeeping.
    async fn prune_housekeeping(&self, now: DateTime<Utc>) -> Result<()>;
}
