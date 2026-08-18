//! In-memory repository implementations (fakes mode / the fast half of the
//! parity suite). HashMap-backed behind a Mutex, implementing the same repo
//! traits as SQLite so the whole daemon runs and self-validates with no DB.
//!
//! SQLite is the spec (AGENTS.md): where the two disagree, this file is the
//! one that gets fixed.

mod accounts;
mod approvals;
mod audit;
mod channel_state;
mod chat;
mod control;
mod incidents;
mod invites;
mod jobs;
mod push;
mod runbook_runs;
mod tokens;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::db::{Account, CliToken, Invite, JobFailure, PushSubscription, RunbookRun};
use crate::domain::{ApprovalRequest, Incident, Job};

#[derive(Default)]
struct Store {
    incidents: HashMap<Uuid, Incident>,
    approvals: HashMap<Uuid, ApprovalRequest>,
    audit_log: Vec<crate::audit::AuditRecord>,
    accounts: HashMap<Uuid, Account>,
    jobs: HashMap<Uuid, Job>,
    job_failures: HashMap<(Uuid, String), JobFailure>,
    claims: std::collections::HashSet<(String, String)>,
    estop_engaged: bool,
    runbook_runs: HashMap<Uuid, RunbookRun>,
    /// Keyed by token HASH (never the plaintext) — mirrors the sqlite
    /// backend's unique-hash lookup.
    cli_tokens: HashMap<String, CliToken>,
    /// Keyed by invite code; the bool is "consumed" (kept, not removed, so
    /// a consumed/expired code stays inspectable — mirrors the sqlite
    /// backend's `consumed_at` column rather than a hard delete).
    invites: HashMap<String, (Invite, bool)>,
    /// Keyed by endpoint (the natural unique identity — see
    /// `PushSubscriptionRepo`'s doc comment).
    push_subscriptions: HashMap<String, PushSubscription>,
    /// Telegram chat id -> operator id (the persistent roster).
    telegram_roster: HashMap<String, Uuid>,
    /// Generic small durable channel state (the Telegram getUpdates offset
    /// today; kept general — see migration 0005's doc comment).
    channel_state: HashMap<String, String>,
    /// The durable shared chat log (append-only; `seq` assigned on append).
    chat_messages: Vec<crate::db::ChatMessage>,
}

/// A single in-memory store shared across all repo trait impls.
#[derive(Clone, Default)]
pub struct InMemoryDb {
    store: Arc<Mutex<Store>>,
}

impl InMemoryDb {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl crate::db::HealthRepo for InMemoryDb {
    async fn ping(&self) -> crate::Result<()> {
        Ok(())
    }
}
