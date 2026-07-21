//! In-memory repository implementations (fakes mode / the fast half of the
//! parity suite). HashMap-backed behind a Mutex, implementing the same repo
//! traits as SQLite so the whole daemon runs and self-validates with no DB.
//!
//! SQLite is the spec (AGENTS.md): where the two disagree, this file is the
//! one that gets fixed.

mod accounts;
mod approvals;
mod audit;
mod control;
mod incidents;
mod jobs;
mod runbook_runs;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::db::{Account, JobFailure, RunbookRun};
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
