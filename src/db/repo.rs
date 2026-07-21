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
use crate::domain::{ApprovalRequest, ApprovalState, Incident, IncidentState, Job};

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

/// A job occurrence's accumulated failure state — the retry budget for a job
/// whose fire keeps failing (gianna's per-household `JobFailure`, generalized
/// to opsclaw's single-tenant `(job_id, occurrence_key)` keying). Durable so
/// the budget survives restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobFailure {
    pub job_id: Uuid,
    pub occurrence_key: String,
    /// How many times this occurrence has failed (>= 1 once a row exists).
    pub attempts: i64,
    /// When it first failed — the clock a give-up policy measures against.
    pub first_failed_at: DateTime<Utc>,
    /// When it most recently failed — the clock a backoff window is measured
    /// against.
    pub last_failed_at: DateTime<Utc>,
    pub last_error: String,
}

/// Scheduled recurring jobs (the proactive/scan engine). See `domain::job`
/// for `Job`/`Schedule`/`Payload`.
#[async_trait]
pub trait JobRepo: Send + Sync {
    async fn insert(&self, job: &Job) -> Result<()>;
    async fn get(&self, id: Uuid) -> Result<Option<Job>>;
    /// Update a job, enforcing optimistic concurrency: the write applies only
    /// `WHERE version = job.version` (the value the caller read), then
    /// returns the row with `version` bumped. `Error::Conflict` if the row's
    /// stored version had already moved on (a concurrent writer won) — the
    /// caller re-reads via `get` and retries rather than clobbering.
    async fn update(&self, job: &Job) -> Result<Job>;
    /// Enabled jobs whose `next_run_at` has passed — the dispatcher drains
    /// these each tick.
    async fn due_jobs(&self, now: DateTime<Utc>) -> Result<Vec<Job>>;
    /// All jobs (management/listing; single-tenant daemon, so this is
    /// unscoped unlike gianna's per-household `list_for_household`).
    async fn list(&self) -> Result<Vec<Job>>;

    /// Record one failure of a job occurrence (keyed by `(job_id,
    /// occurrence_key)`). Inserts on first failure (attempts = 1) or
    /// increments attempts and updates `last_failed_at`/`last_error`
    /// thereafter. Returns the resulting state so the caller can decide
    /// backoff/give-up in one round-trip.
    async fn record_job_failure(
        &self,
        job_id: Uuid,
        occurrence_key: &str,
        error: &str,
        at: DateTime<Utc>,
    ) -> Result<JobFailure>;
    /// The current failure state for a job occurrence, or `None` if it has
    /// never failed (or was cleared on a prior success).
    async fn job_failure_state(
        &self,
        job_id: Uuid,
        occurrence_key: &str,
    ) -> Result<Option<JobFailure>>;
    /// Clear a job occurrence's failure record (called on successful fire,
    /// or when the occurrence is given up on).
    async fn clear_job_failure(&self, job_id: Uuid, occurrence_key: &str) -> Result<()>;
}

// Runbook run history uses the canonical domain types from `runbooks::history`
// (single source of truth — no parallel row struct). The repo stores and
// returns exactly `RunbookRun`/`StepOutcome`/`StepStatus`; only the aggregate
// query result below is a persistence-layer concern with no domain analog.
pub use crate::runbooks::history::{RunbookRun, StepOutcome, StepStatus};

/// Per-runbook success rate over its recorded run history.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RunbookSuccessRate {
    pub total_runs: i64,
    pub successful_runs: i64,
    /// `successful_runs as f64 / total_runs as f64`; 0.0 when `total_runs == 0`.
    pub rate: f64,
}

#[async_trait]
pub trait RunbookRunRepo: Send + Sync {
    /// Record a completed run (including its per-step outcomes) in one call
    /// — a run is written once, atomically, not built up step-by-step.
    async fn record_run(&self, run: &RunbookRun) -> Result<()>;
    async fn get(&self, id: Uuid) -> Result<Option<RunbookRun>>;
    /// A runbook's run history, most recent first, capped at `limit`.
    async fn list_for_runbook(&self, runbook_name: &str, limit: i64) -> Result<Vec<RunbookRun>>;
    /// Success rate for one runbook across its recorded history (brief §7:
    /// low-success runbooks get surfaced for review).
    async fn success_rate(&self, runbook_name: &str) -> Result<RunbookSuccessRate>;
}
