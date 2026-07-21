//! ONE parity suite for the `Repo` traits, run against BOTH implementations.
//!
//! The persistence layer (`src/db/repo.rs`) has two implementations — the
//! SQLite repos (`src/db/sqlite/**`, the live/only backend, DESIGN.md §7.2)
//! and the in-memory fake (`src/db/memory/**`). Gianna's lesson (its own
//! module doc, `tests/repo_parity.rs`): a hand-duplicated suite per backend
//! drifts — ~35% of trait methods were never exercised against the real DB.
//! So here, as there, every test is written ONCE against a `&dyn RepoSuite`
//! handle (a supertrait union both `InMemoryDb` and `SqliteDb` implement).
//! `parity_tests!` expands each body into two `#[tokio::test]`s:
//!
//!   * `fake` — a fresh in-memory store.
//!   * `sqlite` — a fresh tempfile-backed SQLite database, freshly migrated.
//!
//! BOTH run unconditionally, always, under plain `cargo test` — no env var,
//! no throwaway container. This is a deliberate IMPROVEMENT over gianna's
//! `pg` tests (gated on `GIANNA_TEST_DATABASE_URL`, so a Postgres-less `cargo
//! test` silently skipped half the suite): opsclaw's spec backend is SQLite,
//! which needs no server, so there is no reason to ever skip it. SQLite is
//! the spec — where a behaviour disagrees between the two, the fake gets
//! fixed to match it (AGENTS.md).
//!
//! Run: `cargo test --test repo_parity`

use chrono::Utc;
use uuid::Uuid;

use opsclaw::audit::{AuditOutcome, AuditRecord};
use opsclaw::db::memory::InMemoryDb;
use opsclaw::db::sqlite::SqliteDb;
use opsclaw::db::{
    Account, AccountRepo, ApprovalRepo, AuditRepo, ControlRepo, IncidentRepo, JobRepo, RunbookRun,
    RunbookRunRepo, StepOutcome, StepStatus,
};
use opsclaw::domain::{
    ApprovalRequest, ApprovalState, FqTarget, Incident, IncidentState, Job, Payload, Principal,
    RiskClass, Schedule, Severity,
};

/// The union of every repo trait, so a single `&dyn RepoSuite` can drive a
/// whole test regardless of which implementation backs it.
pub trait RepoSuite:
    IncidentRepo + ApprovalRepo + AuditRepo + AccountRepo + ControlRepo + JobRepo + RunbookRunRepo
{
}
impl<T> RepoSuite for T where
    T: IncidentRepo
        + ApprovalRepo
        + AuditRepo
        + AccountRepo
        + ControlRepo
        + JobRepo
        + RunbookRunRepo
{
}

/// A fresh tempfile-backed, freshly-migrated SQLite database. Each call gets
/// its own file (and the TempDir must be kept alive for the pool's lifetime,
/// hence returning it alongside).
async fn sqlite() -> (SqliteDb, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join("opsclaw-test.sqlite3");
    let db = SqliteDb::connect(path.to_str().expect("utf8 path"))
        .await
        .expect("connect + migrate temp sqlite");
    (db, dir)
}

/// Emit, per `name => |db| { .. }`, a private `async fn name(&dyn RepoSuite)`
/// body plus a `mod name` holding a `fake` test (fresh `InMemoryDb`) and a
/// `sqlite` test (fresh tempfile SQLite) — both run unconditionally.
macro_rules! parity_tests {
    ( $( $name:ident => |$db:ident| $body:block )* ) => {
        $(
            async fn $name($db: &dyn RepoSuite) $body

            mod $name {
                #[tokio::test]
                async fn fake() {
                    let db = super::InMemoryDb::new();
                    super::$name(&db).await;
                }

                #[tokio::test]
                async fn sqlite() {
                    let (db, _dir) = super::sqlite().await;
                    super::$name(&db).await;
                }
            }
        )*
    };
}

// ---- fixtures ----

fn target(name: &str) -> FqTarget {
    FqTarget::new("remundo", "prod", name)
}

fn incident(id: Uuid, fingerprint: &str) -> Incident {
    Incident {
        id,
        fingerprint: fingerprint.into(),
        target: target("cluster"),
        severity: Severity::Warning,
        state: IncidentState::Active,
        signals: "cpu 98% for 5m".into(),
        hypothesis: "runaway process".into(),
        recommended_action: Some("restart service".into()),
        opened_at: Utc::now(),
        acked_at: None,
        acked_by: None,
        resolved_at: None,
        last_notified_at: None,
        notify_count: 0,
        escalation_step: 0,
        step_started_at: None,
    }
}

fn approval(id: Uuid) -> ApprovalRequest {
    let now = Utc::now();
    ApprovalRequest {
        id,
        incident: None,
        requested_by: Principal::Agent { job: None },
        target: target("web-1"),
        tool: "ssh".into(),
        command: "systemctl restart web".into(),
        risk: RiskClass::Medium,
        hypothesis: "stuck worker".into(),
        state: ApprovalState::Pending,
        requested_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        decided_at: None,
        decided_by: None,
    }
}

fn audit_record(seq: i64, prev_hash: &str) -> AuditRecord {
    AuditRecord {
        id: Uuid::new_v4(),
        seq,
        ts: Utc::now(),
        principal: Principal::System,
        fq_target: "remundo::prod::web-1".into(),
        tool: "ssh".into(),
        command: "uptime".into(),
        risk: RiskClass::Read,
        outcome: AuditOutcome::Executed,
        exit_code: Some(0),
        prev_hash: prev_hash.into(),
        hash: format!("hash-{seq}"),
    }
}

fn account(id: Uuid, email: &str) -> Account {
    Account {
        id,
        email: email.into(),
        display_name: "Operator".into(),
        password_hash: "x".into(),
        token_version: 0,
        created_at: Utc::now(),
    }
}

fn job(name: &str) -> Job {
    Job::new(name, Schedule::Interval { every_minutes: 5 }, Payload::Text("ping".into()))
}

fn runbook_run(id: Uuid, runbook_name: &str, success: bool) -> RunbookRun {
    RunbookRun {
        id,
        runbook: runbook_name.into(),
        target: opsclaw::domain::FqTarget::new("remundo", "prod", "web-1"),
        principal: Some(Principal::System),
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        steps: vec![StepOutcome {
            step_index: 0,
            status: if success { StepStatus::Ok } else { StepStatus::Failed },
            output: "ok".into(),
        }],
    }
}

parity_tests! {

// ---- Incidents ----

incident_roundtrip_and_list => |db| {
    let id = Uuid::new_v4();
    IncidentRepo::insert(db, &incident(id, "fp-1")).await.unwrap();

    let got = IncidentRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.fingerprint, "fp-1");
    assert_eq!(got.state, IncidentState::Active);

    assert!(IncidentRepo::get(db, Uuid::new_v4()).await.unwrap().is_none());

    let listed = IncidentRepo::list(db, true, 10).await.unwrap();
    assert_eq!(listed.len(), 1);
}

incident_find_open_by_fingerprint_is_dedup_lookup => |db| {
    let fp = "fp-dedup";
    let active = incident(Uuid::new_v4(), fp);
    IncidentRepo::insert(db, &active).await.unwrap();

    let found = db.find_open_by_fingerprint(fp).await.unwrap().unwrap();
    assert_eq!(found.id, active.id);

    // Resolve it: no longer "open", so the anti-spam lookup must miss —
    // a fresh occurrence of the same fault should open a NEW incident, not
    // silently reuse the closed one.
    db.set_state(active.id, IncidentState::Resolved, None).await.unwrap();
    assert!(db.find_open_by_fingerprint(fp).await.unwrap().is_none());

    assert!(db.find_open_by_fingerprint("no-such-fp").await.unwrap().is_none());
}

incident_set_state_stamps_ack_and_resolve => |db| {
    let id = Uuid::new_v4();
    IncidentRepo::insert(db, &incident(id, "fp-ack")).await.unwrap();
    let acker = Uuid::new_v4();

    db.set_state(id, IncidentState::Acknowledged, Some(acker)).await.unwrap();
    let got = IncidentRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.state, IncidentState::Acknowledged);
    assert!(got.acked_at.is_some());
    assert_eq!(got.acked_by, Some(acker));
    assert!(got.resolved_at.is_none());

    db.set_state(id, IncidentState::Resolved, None).await.unwrap();
    let got = IncidentRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.state, IncidentState::Resolved);
    assert!(got.resolved_at.is_some());
}

incident_record_notification_bumps_count_and_persists_chain_position => |db| {
    let id = Uuid::new_v4();
    IncidentRepo::insert(db, &incident(id, "fp-notify")).await.unwrap();

    // First notify: step 0, step clock starts.
    let t1 = Utc::now();
    db.record_notification(id, t1, 0, t1).await.unwrap();
    let got = IncidentRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.notify_count, 1);
    assert_eq!(got.last_notified_at.unwrap().timestamp(), t1.timestamp());
    assert_eq!(got.escalation_step, 0);
    assert_eq!(got.step_started_at.unwrap().timestamp(), t1.timestamp());

    // Escalate: step advances and its clock restarts.
    let t2 = Utc::now();
    db.record_notification(id, t2, 1, t2).await.unwrap();
    let got = IncidentRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.notify_count, 2);
    assert_eq!(got.escalation_step, 1);
    assert_eq!(got.step_started_at.unwrap().timestamp(), t2.timestamp());
}

incident_list_scopes_closed_and_respects_limit => |db| {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    IncidentRepo::insert(db, &incident(a, "fp-a")).await.unwrap();
    IncidentRepo::insert(db, &incident(b, "fp-b")).await.unwrap();
    db.set_state(b, IncidentState::Resolved, None).await.unwrap();

    let open_only = IncidentRepo::list(db, false, 10).await.unwrap();
    assert_eq!(open_only.len(), 1);
    assert_eq!(open_only[0].id, a);

    let all = IncidentRepo::list(db, true, 10).await.unwrap();
    assert_eq!(all.len(), 2);

    let capped = IncidentRepo::list(db, true, 1).await.unwrap();
    assert_eq!(capped.len(), 1);
}

// ---- Approvals ----

approval_roundtrip_and_list_pending => |db| {
    let id = Uuid::new_v4();
    ApprovalRepo::insert(db, &approval(id)).await.unwrap();

    let got = ApprovalRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.state, ApprovalState::Pending);

    let pending = db.list_pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
}

approval_decide_double_tap_conflicts => |db| {
    let id = Uuid::new_v4();
    ApprovalRepo::insert(db, &approval(id)).await.unwrap();
    let approver = Uuid::new_v4();

    let decided = db.decide(id, ApprovalState::Approved, approver).await.unwrap();
    assert_eq!(decided.state, ApprovalState::Approved);
    assert_eq!(decided.decided_by, Some(approver));
    assert!(decided.decided_at.is_some());

    // The double-tap: a second decide on the SAME (already-decided) request
    // must be rejected as a conflict, never silently overwrite the first
    // decision (e.g. flip an already-approved request to denied).
    let err = db.decide(id, ApprovalState::Denied, Uuid::new_v4()).await.unwrap_err();
    assert!(matches!(err, opsclaw::Error::Conflict(_)), "expected Conflict, got {err:?}");

    // The stored decision is unchanged by the rejected second attempt.
    let got = ApprovalRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.state, ApprovalState::Approved);
    assert_eq!(got.decided_by, Some(approver));
}

approval_decide_missing_is_not_found => |db| {
    let err = db.decide(Uuid::new_v4(), ApprovalState::Approved, Uuid::new_v4()).await.unwrap_err();
    assert!(matches!(err, opsclaw::Error::NotFound(_)), "expected NotFound, got {err:?}");
}

approval_mark_executed => |db| {
    let id = Uuid::new_v4();
    ApprovalRepo::insert(db, &approval(id)).await.unwrap();
    db.decide(id, ApprovalState::Approved, Uuid::new_v4()).await.unwrap();
    db.mark_executed(id).await.unwrap();
    let got = ApprovalRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.state, ApprovalState::Executed);
}

approval_expire_due_only_touches_pending_past_deadline => |db| {
    let expired_id = Uuid::new_v4();
    let mut expired = approval(expired_id);
    expired.expires_at = Utc::now() - chrono::Duration::minutes(1);
    ApprovalRepo::insert(db, &expired).await.unwrap();

    let future_id = Uuid::new_v4();
    ApprovalRepo::insert(db, &approval(future_id)).await.unwrap(); // expires in 15m

    let already_decided_id = Uuid::new_v4();
    let mut decided = approval(already_decided_id);
    decided.expires_at = Utc::now() - chrono::Duration::minutes(1);
    ApprovalRepo::insert(db, &decided).await.unwrap();
    db.decide(already_decided_id, ApprovalState::Approved, Uuid::new_v4()).await.unwrap();

    let swept = db.expire_due(Utc::now()).await.unwrap();
    assert_eq!(swept.len(), 1);
    assert_eq!(swept[0].id, expired_id);
    assert_eq!(swept[0].state, ApprovalState::Expired);

    // Not-yet-due request is untouched.
    let still_pending = ApprovalRepo::get(db, future_id).await.unwrap().unwrap();
    assert_eq!(still_pending.state, ApprovalState::Pending);

    // Already-decided request is untouched (still Approved, not Expired).
    let still_approved = ApprovalRepo::get(db, already_decided_id).await.unwrap().unwrap();
    assert_eq!(still_approved.state, ApprovalState::Approved);

    // Idempotent: a second sweep at the same instant finds nothing new.
    let swept_again = db.expire_due(Utc::now()).await.unwrap();
    assert!(swept_again.is_empty());
}

// ---- Audit ----

audit_append_enforces_contiguous_seq => |db| {
    assert!(db.last().await.unwrap().is_none());

    db.append(&audit_record(1, "0" .repeat(64).as_str())).await.unwrap();
    let last = db.last().await.unwrap().unwrap();
    assert_eq!(last.seq, 1);

    // Skipping ahead (seq=3 when last=1) must be rejected.
    let err = db.append(&audit_record(3, "hash-1")).await.unwrap_err();
    assert!(matches!(err, opsclaw::Error::Conflict(_)), "expected Conflict, got {err:?}");

    // Re-appending the same seq must also be rejected.
    let err = db.append(&audit_record(1, "hash-1")).await.unwrap_err();
    assert!(matches!(err, opsclaw::Error::Conflict(_)), "expected Conflict, got {err:?}");

    // The only valid next append is exactly last+1.
    db.append(&audit_record(2, "hash-1")).await.unwrap();
    assert_eq!(db.last().await.unwrap().unwrap().seq, 2);
}

audit_range_pages_in_seq_order => |db| {
    for i in 1..=5 {
        db.append(&audit_record(i, "h")).await.unwrap();
    }
    let page = db.range(2, 2).await.unwrap();
    assert_eq!(page.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![2, 3]);

    let rest = db.range(4, 100).await.unwrap();
    assert_eq!(rest.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![4, 5]);

    let none = db.range(100, 10).await.unwrap();
    assert!(none.is_empty());
}

// ---- Accounts ----

account_roundtrip_and_lookup => |db| {
    let id = Uuid::new_v4();
    AccountRepo::insert(db, &account(id, "op@example.com")).await.unwrap();

    let by_id = AccountRepo::by_id(db, id).await.unwrap().unwrap();
    assert_eq!(by_id.email, "op@example.com");

    let by_email = db.by_email("op@example.com").await.unwrap().unwrap();
    assert_eq!(by_email.id, id);

    assert!(db.by_email("nobody@example.com").await.unwrap().is_none());

    let all = AccountRepo::list(db).await.unwrap();
    assert_eq!(all.len(), 1);
}

account_bump_token_version_invalidates_sessions => |db| {
    let id = Uuid::new_v4();
    AccountRepo::insert(db, &account(id, "a@example.com")).await.unwrap();
    assert_eq!(AccountRepo::by_id(db, id).await.unwrap().unwrap().token_version, 0);

    db.bump_token_version(id).await.unwrap();
    db.bump_token_version(id).await.unwrap();
    assert_eq!(AccountRepo::by_id(db, id).await.unwrap().unwrap().token_version, 2);
}

// ---- Control: e-stop + claims ----

control_estop_toggles => |db| {
    assert!(!db.estop_engaged().await.unwrap());
    db.set_estop(true).await.unwrap();
    assert!(db.estop_engaged().await.unwrap());
    db.set_estop(false).await.unwrap();
    assert!(!db.estop_engaged().await.unwrap());
}

control_claim_is_exactly_once_under_sequential_reclaim => |db| {
    let now = Utc::now();
    // First claim of this (kind, key) wins.
    assert!(db.claim("scan", "remundo::prod::cluster:2026-07-21T10:00", now).await.unwrap());
    // Every subsequent claim of the SAME (kind, key) — even much later —
    // must lose: exactly-once is per-occurrence, not per-instant.
    assert!(!db.claim("scan", "remundo::prod::cluster:2026-07-21T10:00", now).await.unwrap());
    assert!(
        !db.claim(
            "scan",
            "remundo::prod::cluster:2026-07-21T10:00",
            now + chrono::Duration::hours(1)
        )
        .await
        .unwrap()
    );
    // A DIFFERENT key (different occurrence, or different kind) is unaffected.
    assert!(db.claim("scan", "remundo::prod::cluster:2026-07-21T10:05", now).await.unwrap());
    assert!(db.claim("digest", "remundo::prod::cluster:2026-07-21T10:00", now).await.unwrap());
}

control_prune_housekeeping_is_ok => |db| {
    // Not every backend has time-windowed state to sweep (the fake keeps no
    // claim/approval timestamps to age by design — see its module doc);
    // this just pins the contract that the call always succeeds.
    db.prune_housekeeping(Utc::now()).await.unwrap();
}

// ---- Jobs ----

job_insert_get_list => |db| {
    let j = job("remundo-scan");
    JobRepo::insert(db, &j).await.unwrap();

    let got = JobRepo::get(db, j.id).await.unwrap().unwrap();
    assert_eq!(got.name, "remundo-scan");
    assert_eq!(got.version, 0);

    assert!(JobRepo::get(db, Uuid::new_v4()).await.unwrap().is_none());

    let all = JobRepo::list(db).await.unwrap();
    assert_eq!(all.len(), 1);
}

job_update_version_cas_conflict => |db| {
    let j = job("cas-job");
    JobRepo::insert(db, &j).await.unwrap();

    // A writer holding the current version succeeds and gets version+1 back.
    let mut first_writer = j.clone();
    first_writer.name = "renamed-by-first".into();
    let updated = JobRepo::update(db, &first_writer).await.unwrap();
    assert_eq!(updated.version, 1);
    assert_eq!(updated.name, "renamed-by-first");

    // A second writer that read the OLD version (0) and tries to write now
    // loses: the row has already moved to version 1 underneath it.
    let mut stale_writer = j.clone();
    stale_writer.name = "renamed-by-stale-writer".into();
    let err = JobRepo::update(db, &stale_writer).await.unwrap_err();
    assert!(matches!(err, opsclaw::Error::Conflict(_)), "expected Conflict, got {err:?}");

    // The stale writer's change never landed.
    let got = JobRepo::get(db, j.id).await.unwrap().unwrap();
    assert_eq!(got.name, "renamed-by-first");
    assert_eq!(got.version, 1);

    // Updating a job that doesn't exist at all is NotFound, not Conflict.
    let ghost = job("ghost");
    let err = JobRepo::update(db, &ghost).await.unwrap_err();
    assert!(matches!(err, opsclaw::Error::NotFound(_)), "expected NotFound, got {err:?}");
}

job_due_jobs_filters_enabled_and_time => |db| {
    let now = Utc::now();

    let mut due = job("due-now");
    due.next_run_at = Some(now - chrono::Duration::minutes(1));
    JobRepo::insert(db, &due).await.unwrap();

    let mut future = job("not-yet-due");
    future.next_run_at = Some(now + chrono::Duration::hours(1));
    JobRepo::insert(db, &future).await.unwrap();

    let mut disabled = job("disabled-but-due");
    disabled.next_run_at = Some(now - chrono::Duration::minutes(1));
    disabled.enabled = false;
    JobRepo::insert(db, &disabled).await.unwrap();

    let mut no_next = job("no-next-run");
    no_next.next_run_at = None;
    JobRepo::insert(db, &no_next).await.unwrap();

    let due_jobs = db.due_jobs(now).await.unwrap();
    let names: Vec<&str> = due_jobs.iter().map(|j| j.name.as_str()).collect();
    assert_eq!(names, vec!["due-now"]);
}

job_failure_lifecycle => |db| {
    let job_id = Uuid::new_v4();
    let occurrence = "2026-07-21T10:00";

    assert!(db.job_failure_state(job_id, occurrence).await.unwrap().is_none());

    let f1 = db.record_job_failure(job_id, occurrence, "timeout", Utc::now()).await.unwrap();
    assert_eq!(f1.attempts, 1);
    assert_eq!(f1.last_error, "timeout");

    let f2 =
        db.record_job_failure(job_id, occurrence, "timeout again", Utc::now()).await.unwrap();
    assert_eq!(f2.attempts, 2);
    assert_eq!(f2.last_error, "timeout again");
    assert_eq!(f2.first_failed_at, f1.first_failed_at); // first-failed clock doesn't move

    let state = db.job_failure_state(job_id, occurrence).await.unwrap().unwrap();
    assert_eq!(state.attempts, 2);

    db.clear_job_failure(job_id, occurrence).await.unwrap();
    assert!(db.job_failure_state(job_id, occurrence).await.unwrap().is_none());

    // A DIFFERENT occurrence of the same job is independent.
    assert!(db.job_failure_state(job_id, "2026-07-21T10:05").await.unwrap().is_none());
}

// ---- Runbook runs ----

runbook_run_record_and_list => |db| {
    let id = Uuid::new_v4();
    db.record_run(&runbook_run(id, "restart-service", true)).await.unwrap();

    let got = RunbookRunRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.runbook, "restart-service");
    assert!(got.succeeded());
    assert_eq!(got.steps.len(), 1);

    assert!(RunbookRunRepo::get(db, Uuid::new_v4()).await.unwrap().is_none());

    let other_id = Uuid::new_v4();
    db.record_run(&runbook_run(other_id, "other-runbook", true)).await.unwrap();

    let listed = db.list_for_runbook("restart-service", 10).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id);
}

runbook_run_success_rate => |db| {
    // No runs yet: rate is well-defined at 0.0, not a divide-by-zero panic.
    let empty = db.success_rate("flaky-runbook").await.unwrap();
    assert_eq!(empty.total_runs, 0);
    assert_eq!(empty.rate, 0.0);

    db.record_run(&runbook_run(Uuid::new_v4(), "flaky-runbook", true)).await.unwrap();
    db.record_run(&runbook_run(Uuid::new_v4(), "flaky-runbook", true)).await.unwrap();
    db.record_run(&runbook_run(Uuid::new_v4(), "flaky-runbook", false)).await.unwrap();
    db.record_run(&runbook_run(Uuid::new_v4(), "flaky-runbook", true)).await.unwrap();

    let rate = db.success_rate("flaky-runbook").await.unwrap();
    assert_eq!(rate.total_runs, 4);
    assert_eq!(rate.successful_runs, 3);
    assert!((rate.rate - 0.75).abs() < f64::EPSILON);

    // A DIFFERENT runbook's history doesn't leak in.
    let unrelated = db.success_rate("never-run").await.unwrap();
    assert_eq!(unrelated.total_runs, 0);
}

}

/// Not a parity behaviour (no in-memory analog) — pins that `SqliteDb::connect`
/// actually applies the WAL mode + busy_timeout pragmas it claims to (its
/// module doc), rather than silently leaving the default rollback-journal
/// mode where concurrent readers block the writer.
#[tokio::test]
async fn sqlite_connect_sets_wal_mode_and_busy_timeout() {
    let (db, _dir) = sqlite().await;
    let mode: (String,) = sqlx::query_as("PRAGMA journal_mode").fetch_one(db.pool()).await.unwrap();
    assert_eq!(mode.0.to_lowercase(), "wal");
    let timeout: (i64,) = sqlx::query_as("PRAGMA busy_timeout").fetch_one(db.pool()).await.unwrap();
    assert_eq!(timeout.0, 5000);
}
