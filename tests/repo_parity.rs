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
    AUTH_PROVIDER_HANKO, AUTH_PROVIDER_LOCAL, Account, AccountRepo, ApprovalRepo, AuditRepo,
    ChannelStateRepo, ChatRepo, CliToken, ControlRepo, IncidentRepo, Invite, InviteRepo, JobRepo,
    PushSubscription, PushSubscriptionRepo, RunbookRun, RunbookRunRepo, StepOutcome, StepStatus,
    TokenRepo,
};
use opsclaw::domain::{
    ApprovalRequest, ApprovalState, FqTarget, Incident, IncidentState, Job, Payload, Principal,
    RiskClass, Schedule, Severity,
};

/// The union of every repo trait, so a single `&dyn RepoSuite` can drive a
/// whole test regardless of which implementation backs it.
pub trait RepoSuite:
    IncidentRepo
    + ApprovalRepo
    + AuditRepo
    + AccountRepo
    + ControlRepo
    + JobRepo
    + RunbookRunRepo
    + TokenRepo
    + InviteRepo
    + PushSubscriptionRepo
    + ChannelStateRepo
    + ChatRepo
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
        + TokenRepo
        + InviteRepo
        + PushSubscriptionRepo
        + ChannelStateRepo
        + ChatRepo
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
    FqTarget::try_new("example", "prod", name).unwrap()
}

fn incident(id: Uuid, fingerprint: &str) -> Incident {
    Incident {
        id,
        fingerprint: fingerprint.into(),
        fault_class: "cpu-saturation".into(),
        target: target("cluster"),
        severity: Severity::Warning,
        state: IncidentState::Active,
        signals: "cpu 98% for 5m".into(),
        hypothesis: "runaway process".into(),
        recommended_action: Some("restart service".into()),
        opened_at: Utc::now(),
        reopened_at: None,
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
        fq_target: "example::prod::web-1".into(),
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
        auth_provider: "local".into(),
        external_subject: None,
    }
}

fn job(name: &str) -> Job {
    Job::new(name, Schedule::Interval { every_minutes: 5 }, Payload::Text("ping".into()))
}

fn cli_token(id: Uuid, account: Uuid, name: &str) -> CliToken {
    CliToken { id, account, name: name.into(), created_at: Utc::now(), last_used_at: None }
}

fn invite(code: &str, issued_by: Uuid, ttl: chrono::Duration) -> Invite {
    let now = Utc::now();
    Invite { code: code.into(), issued_by, created_at: now, expires_at: now + ttl }
}

fn push_subscription(endpoint: &str, account_id: Uuid) -> PushSubscription {
    PushSubscription {
        endpoint: endpoint.into(),
        account_id,
        p256dh: "p256dh-key".into(),
        auth: "auth-secret".into(),
        created_at: Utc::now(),
    }
}

fn runbook_run(id: Uuid, runbook_name: &str, success: bool) -> RunbookRun {
    RunbookRun {
        id,
        runbook: runbook_name.into(),
        target: opsclaw::domain::FqTarget::try_new("example", "prod", "web-1").unwrap(),
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
    // fault_class persists in the clear (the eval harness's "named
    // correctly" check reads it back — not just the fingerprint hash).
    assert_eq!(IncidentRepo::get(db, id).await.unwrap().unwrap().fault_class, "cpu-saturation");

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

incident_find_expired_by_fingerprint_excludes_open_and_resolved => |db| {
    let fp = "fp-expired-lookup";
    let active = incident(Uuid::new_v4(), fp);
    IncidentRepo::insert(db, &active).await.unwrap();

    // Open: the re-open lookup must miss (find_open_by_fingerprint owns it).
    assert!(db.find_expired_by_fingerprint(fp).await.unwrap().is_none());

    // Expired: found.
    db.set_state(active.id, IncidentState::Expired, None).await.unwrap();
    let found = db.find_expired_by_fingerprint(fp).await.unwrap().unwrap();
    assert_eq!(found.id, active.id);
    assert_eq!(found.state, IncidentState::Expired);

    // Resolved: excluded — a fault back after a fix opens a NEW incident,
    // never re-opens the old row.
    let resolved = incident(Uuid::new_v4(), "fp-resolved-lookup");
    IncidentRepo::insert(db, &resolved).await.unwrap();
    db.set_state(resolved.id, IncidentState::Resolved, None).await.unwrap();
    assert!(db.find_expired_by_fingerprint("fp-resolved-lookup").await.unwrap().is_none());

    assert!(db.find_expired_by_fingerprint("no-such-fp").await.unwrap().is_none());
}

incident_reopen_reactivates_and_resets_the_chain_preserving_identity => |db| {
    let id = Uuid::new_v4();
    let mut row = incident(id, "fp-reopen");
    row.notify_count = 3;
    row.escalation_step = 1;
    row.last_notified_at = Some(Utc::now());
    row.step_started_at = Some(Utc::now());
    IncidentRepo::insert(db, &row).await.unwrap();
    db.set_state(id, IncidentState::Expired, None).await.unwrap();

    let at = Utc::now();
    db.reopen(id, at).await.unwrap();

    let got = IncidentRepo::get(db, id).await.unwrap().unwrap();
    assert_eq!(got.state, IncidentState::Active);
    assert_eq!(got.reopened_at.unwrap().timestamp(), at.timestamp());
    // Chain reset to the top: the driver's next action is a single Notify.
    assert_eq!(got.escalation_step, 0);
    assert!(got.step_started_at.is_none());
    // Identity and history preserved: same row, original opened_at for
    // age-tracking, cumulative notify_count (keeps claim keys unique).
    assert_eq!(got.opened_at.timestamp(), row.opened_at.timestamp());
    assert_eq!(got.notify_count, 3);

    // Re-opened means open again: the anti-spam lookup finds it, the
    // re-open lookup no longer does.
    assert!(db.find_open_by_fingerprint("fp-reopen").await.unwrap().is_some());
    assert!(db.find_expired_by_fingerprint("fp-reopen").await.unwrap().is_none());
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

    // Decided BEFORE its deadline (decide refuses expired rows), with a
    // deadline that will have passed by sweep time — proving the sweep
    // skips decided rows even when they're past their window.
    let already_decided_id = Uuid::new_v4();
    let mut decided = approval(already_decided_id);
    decided.expires_at = Utc::now() + chrono::Duration::minutes(1);
    ApprovalRepo::insert(db, &decided).await.unwrap();
    db.decide(already_decided_id, ApprovalState::Approved, Uuid::new_v4()).await.unwrap();

    let sweep_at = Utc::now() + chrono::Duration::minutes(2);
    let swept = db.expire_due(sweep_at).await.unwrap();
    assert_eq!(swept.len(), 1);
    assert_eq!(swept[0].id, expired_id);
    assert_eq!(swept[0].state, ApprovalState::Expired);

    // Not-yet-due request is untouched (expires in 15m, sweep at +2m).
    let still_pending = ApprovalRepo::get(db, future_id).await.unwrap().unwrap();
    assert_eq!(still_pending.state, ApprovalState::Pending);

    // Already-decided request is untouched (still Approved, not Expired),
    // even though its deadline has passed by sweep time.
    let still_approved = ApprovalRepo::get(db, already_decided_id).await.unwrap().unwrap();
    assert_eq!(still_approved.state, ApprovalState::Approved);

    // Idempotent: a second sweep at the same instant finds nothing new.
    let swept_again = db.expire_due(sweep_at).await.unwrap();
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

account_by_external_subject_is_provider_scoped => |db| {
    // A hanko-linked operator. The binding is the provider's SUBJECT, not
    // the email (migration 0009's header) — so the lookup is keyed on it.
    let hanko_id = Uuid::new_v4();
    let mut linked = account(hanko_id, "hanko@example.com");
    linked.auth_provider = AUTH_PROVIDER_HANKO.into();
    linked.external_subject = Some("sub-abc".into());
    AccountRepo::insert(db, &linked).await.unwrap();

    // An ordinary local operator, carrying no external identity at all.
    let local_id = Uuid::new_v4();
    AccountRepo::insert(db, &account(local_id, "local@example.com")).await.unwrap();

    let found = db.by_external_subject(AUTH_PROVIDER_HANKO, "sub-abc").await.unwrap().unwrap();
    assert_eq!(found.id, hanko_id);
    assert_eq!(found.auth_provider, AUTH_PROVIDER_HANKO);
    assert_eq!(found.external_subject.as_deref(), Some("sub-abc"));

    // Provider-scoped: the SAME subject string under a different provider
    // resolves nothing. A subject minted by one provider must never reach an
    // account linked to another — otherwise a provider swap (or a second
    // provider added later) would hand out someone else's session.
    assert!(db.by_external_subject(AUTH_PROVIDER_LOCAL, "sub-abc").await.unwrap().is_none());

    // An unknown subject under the right provider is a clean miss, not the
    // first row of the table: this is what makes the exchange route answer
    // 401 "no operator account is linked to this identity".
    assert!(db.by_external_subject(AUTH_PROVIDER_HANKO, "nope").await.unwrap().is_none());

    // Migration 0009's uniqueness index must never reach the local rows: any
    // number of them share a NULL subject. Today two guards hold that up — the
    // index predicate (`WHERE external_subject IS NOT NULL`) and SQLite's rule
    // that NULLs compare distinct inside a unique index. Either one alone is
    // enough, so this insert does NOT isolate the predicate; what it pins is
    // the behaviour that matters — a second password operator still joins once
    // Hanko is linked. It turns red the moment a later migration narrows the
    // column (say NOT NULL with an '' sentinel) and collapses both guards.
    let second_local = Uuid::new_v4();
    AccountRepo::insert(db, &account(second_local, "local-2@example.com")).await.unwrap();
    assert!(AccountRepo::by_id(db, second_local).await.unwrap().is_some());
    assert_eq!(AccountRepo::list(db).await.unwrap().len(), 3);

    // Those NULL-subject rows stay invisible to the external lookup. An empty
    // subject is a miss, not a match on them — the sentinel-shaped mistake
    // above would otherwise resolve an arbitrary local account.
    assert!(db.by_external_subject(AUTH_PROVIDER_LOCAL, "").await.unwrap().is_none());

    // One operator per external identity. Without this, two accounts can bind
    // the same Hanko subject and the exchange route resolves whichever the
    // store yields first — an arbitrary choice between two real operators.
    let dupe = {
        let mut a = account(Uuid::new_v4(), "dupe@example.com");
        a.auth_provider = AUTH_PROVIDER_HANKO.into();
        a.external_subject = Some("sub-abc".into());
        a
    };
    assert!(
        AccountRepo::insert(db, &dupe).await.is_err(),
        "a second account on the same (provider, subject) must be refused"
    );
    // The rejected insert leaves the original binding intact.
    assert_eq!(
        db.by_external_subject(AUTH_PROVIDER_HANKO, "sub-abc").await.unwrap().unwrap().id,
        hanko_id
    );

    // Linking an EXISTING local account is the pre-flip migration step:
    // without it, switching auth.provider locks out every operator who
    // already had a row.
    let password_before =
        AccountRepo::by_id(db, local_id).await.unwrap().unwrap().password_hash;
    AccountRepo::link_external_subject(db, local_id, AUTH_PROVIDER_HANKO, "sub-xyz", None)
        .await
        .unwrap();
    let linked = db.by_external_subject(AUTH_PROVIDER_HANKO, "sub-xyz").await.unwrap().unwrap();
    assert_eq!(linked.id, local_id);
    assert_eq!(linked.auth_provider, AUTH_PROVIDER_HANKO);
    // `None` KEEPS the password. This is load-bearing: linking happens while
    // the daemon is still on `local`, where the external path is refused, so
    // dropping the password here would leave the operator unable to sign in
    // by either method until the flip completed.
    assert_eq!(linked.password_hash, password_before, "linking must not disarm the account");

    // An explicit hash still replaces it, for a deployment that wants the
    // password gone once the flip is done.
    AccountRepo::link_external_subject(
        db,
        local_id,
        AUTH_PROVIDER_HANKO,
        "sub-xyz",
        Some("!no-password"),
    )
    .await
    .unwrap();
    assert_eq!(
        AccountRepo::by_id(db, local_id).await.unwrap().unwrap().password_hash,
        "!no-password"
    );

    // And the recovery path puts a usable password back — what makes rolling
    // off an external provider a config edit rather than a database restore.
    AccountRepo::set_password_hash(db, local_id, "$argon2id$replaced").await.unwrap();
    assert_eq!(
        AccountRepo::by_id(db, local_id).await.unwrap().unwrap().password_hash,
        "$argon2id$replaced"
    );

    // And it honours the same one-operator-per-identity rule.
    assert!(
        AccountRepo::link_external_subject(db, second_local, AUTH_PROVIDER_HANKO, "sub-xyz", None)
            .await
            .is_err(),
        "linking a second account to a taken subject must be refused"
    );
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
    assert!(db.claim("scan", "example::prod::cluster:2026-07-21T10:00", now).await.unwrap());
    // Every subsequent claim of the SAME (kind, key) — even much later —
    // must lose: exactly-once is per-occurrence, not per-instant.
    assert!(!db.claim("scan", "example::prod::cluster:2026-07-21T10:00", now).await.unwrap());
    assert!(
        !db.claim(
            "scan",
            "example::prod::cluster:2026-07-21T10:00",
            now + chrono::Duration::hours(1)
        )
        .await
        .unwrap()
    );
    // A DIFFERENT key (different occurrence, or different kind) is unaffected.
    assert!(db.claim("scan", "example::prod::cluster:2026-07-21T10:05", now).await.unwrap());
    assert!(db.claim("digest", "example::prod::cluster:2026-07-21T10:00", now).await.unwrap());
}

approval_past_its_deadline_is_undecidable => |db| {
    // The sweep may not have reached it yet, but a pending request past
    // expires_at must refuse approve/deny — otherwise a stale command
    // stays executable arbitrarily long after its window closed.
    let id = Uuid::new_v4();
    let mut stale = approval(id);
    stale.requested_at = Utc::now() - chrono::Duration::minutes(46);
    stale.expires_at = Utc::now() - chrono::Duration::minutes(31);
    ApprovalRepo::insert(db, &stale).await.unwrap();

    let err = db.decide(id, ApprovalState::Approved, Uuid::new_v4()).await.unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
    // Still pending on the row — the expiry sweep, not decide, owns the
    // state transition.
    assert_eq!(ApprovalRepo::get(db, id).await.unwrap().unwrap().state, ApprovalState::Pending);
}

control_release_reopens_a_claim_for_retry => |db| {
    let now = Utc::now();
    assert!(db.claim("esc", "fp:s0-n0", now).await.unwrap());
    // A failed send releases its claim; the same occurrence claims fresh.
    db.release("esc", "fp:s0-n0").await.unwrap();
    assert!(db.claim("esc", "fp:s0-n0", now).await.unwrap());
    // Release is scoped to the exact (kind, key): other claims survive it.
    assert!(db.claim("esc", "fp:s0-n1", now).await.unwrap());
    db.release("esc", "fp:s0-n0").await.unwrap();
    assert!(!db.claim("esc", "fp:s0-n1", now).await.unwrap());
    // Releasing a never-claimed key is a no-op, not an error.
    db.release("esc", "fp:never-claimed").await.unwrap();
}

control_prune_housekeeping_is_ok => |db| {
    // Not every backend has time-windowed state to sweep (the fake keeps no
    // claim/approval timestamps to age by design — see its module doc);
    // this just pins the contract that the call always succeeds.
    db.prune_housekeeping(Utc::now()).await.unwrap();
}

// ---- Jobs ----

job_insert_get_list => |db| {
    let j = job("example-scan");
    JobRepo::insert(db, &j).await.unwrap();

    let got = JobRepo::get(db, j.id).await.unwrap().unwrap();
    assert_eq!(got.name, "example-scan");
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

job_delete_removes_the_row_and_failure_history => |db| {
    let j = job("delete-me");
    JobRepo::insert(db, &j).await.unwrap();
    db.record_job_failure(j.id, "occurrence", "failed", Utc::now()).await.unwrap();

    assert!(JobRepo::delete(db, j.id).await.unwrap());
    assert!(JobRepo::get(db, j.id).await.unwrap().is_none());
    assert_eq!(db.count_job_failures(j.id).await.unwrap(), 0);
    assert!(!JobRepo::delete(db, j.id).await.unwrap());
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

job_failure_streak_counts_and_clears_per_job => |db| {
    let job_id = Uuid::new_v4();
    let other_job = Uuid::new_v4();
    assert_eq!(db.count_job_failures(job_id).await.unwrap(), 0);

    // Three distinct failed occurrences of one job (the recurring-outage
    // shape: schedule advances past each, records left behind at attempts=1)
    // plus an unrelated job's failure that must not pollute the count.
    for occ in ["10:00", "10:30", "11:00"] {
        db.record_job_failure(job_id, occ, "llm 403", Utc::now()).await.unwrap();
    }
    db.record_job_failure(other_job, "10:00", "unrelated", Utc::now()).await.unwrap();
    assert_eq!(db.count_job_failures(job_id).await.unwrap(), 3);
    assert_eq!(db.count_job_failures(other_job).await.unwrap(), 1);

    // Re-failing an EXISTING occurrence bumps attempts, not the streak.
    db.record_job_failure(job_id, "11:00", "llm 403 again", Utc::now()).await.unwrap();
    assert_eq!(db.count_job_failures(job_id).await.unwrap(), 3);

    // The latest failure (by last_failed_at) carries the freshest error.
    let latest = db.latest_job_failure(job_id).await.unwrap().unwrap();
    assert_eq!(latest.occurrence_key, "11:00");
    assert_eq!(latest.last_error, "llm 403 again");
    assert!(db.latest_job_failure(Uuid::new_v4()).await.unwrap().is_none());

    // The per-job wipe ends the streak and leaves other jobs untouched.
    db.clear_job_failures_for_job(job_id).await.unwrap();
    assert_eq!(db.count_job_failures(job_id).await.unwrap(), 0);
    assert!(db.job_failure_state(job_id, "10:00").await.unwrap().is_none());
    assert_eq!(db.count_job_failures(other_job).await.unwrap(), 1);
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

// ---- CLI tokens ----

cli_token_create_find_by_hash_bumps_last_used => |db| {
    let account = Uuid::new_v4();
    let id = Uuid::new_v4();
    assert!(db.find_cli_token("no-such-hash").await.unwrap().is_none());

    db.create_cli_token(cli_token(id, account, "laptop"), "hash-abc").await.unwrap();
    let found = db.find_cli_token("hash-abc").await.unwrap().unwrap();
    assert_eq!(found, (id, account));

    let listed = db.list_cli_tokens(account).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "laptop");
    // The plaintext/hash is never exposed on the listed row (CliToken has no
    // hash field at all — this is a type-level guarantee, not a runtime one,
    // but pin that the row's own identity fields round-trip correctly).
    assert_eq!(listed[0].id, id);

    // A DIFFERENT account never sees this token.
    assert!(db.list_cli_tokens(Uuid::new_v4()).await.unwrap().is_empty());
}

cli_token_revoke_is_scoped_to_owning_account => |db| {
    let owner = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let id = Uuid::new_v4();
    db.create_cli_token(cli_token(id, owner, "phone"), "hash-xyz").await.unwrap();

    // A different account can never revoke someone else's token.
    assert!(!db.revoke_cli_token(stranger, id).await.unwrap());
    assert!(db.find_cli_token("hash-xyz").await.unwrap().is_some());

    // The owner can.
    assert!(db.revoke_cli_token(owner, id).await.unwrap());
    assert!(db.find_cli_token("hash-xyz").await.unwrap().is_none());

    // Revoking again (already gone) is a clean false, not an error.
    assert!(!db.revoke_cli_token(owner, id).await.unwrap());
}

// ---- Invites ----

invite_create_get_and_open_listing => |db| {
    let issuer = Uuid::new_v4();
    let now = Utc::now();
    db.create_invite(&invite("ABC123", issuer, chrono::Duration::hours(1))).await.unwrap();

    let got = InviteRepo::get_invite(db, "ABC123", now).await.unwrap().unwrap();
    assert_eq!(got.issued_by, issuer);

    assert!(InviteRepo::get_invite(db, "NOSUCH", now).await.unwrap().is_none());

    let open = db.list_open_invites(now).await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].code, "ABC123");
}

invite_take_is_exactly_once_and_expiry_gated => |db| {
    let issuer = Uuid::new_v4();
    let now = Utc::now();
    db.create_invite(&invite("ONESHOT", issuer, chrono::Duration::hours(1))).await.unwrap();

    // First take wins.
    let taken = db.take_invite("ONESHOT", now).await.unwrap().unwrap();
    assert_eq!(taken.code, "ONESHOT");

    // A second take of the SAME code — even immediately after — must lose
    // (the double-join TOCTOU guard).
    assert!(db.take_invite("ONESHOT", now).await.unwrap().is_none());

    // A consumed invite no longer appears in the open listing or the
    // non-consuming lookup.
    assert!(InviteRepo::get_invite(db, "ONESHOT", now).await.unwrap().is_none());
    assert!(db.list_open_invites(now).await.unwrap().is_empty());

    // An expired (but never-taken) invite cannot be taken either.
    db.create_invite(&invite("EXPIRED", issuer, chrono::Duration::seconds(-1))).await.unwrap();
    assert!(db.take_invite("EXPIRED", now).await.unwrap().is_none());
    assert!(InviteRepo::get_invite(db, "EXPIRED", now).await.unwrap().is_none(), "expired invite must not resolve even before being taken");
}

invite_revoke_only_touches_open_invites => |db| {
    let issuer = Uuid::new_v4();
    let now = Utc::now();
    db.create_invite(&invite("REVOKEME", issuer, chrono::Duration::hours(1))).await.unwrap();

    assert!(db.revoke_invite("REVOKEME").await.unwrap());
    assert!(InviteRepo::get_invite(db, "REVOKEME", now).await.unwrap().is_none());
    assert!(db.list_open_invites(now).await.unwrap().is_empty());

    // Revoking again, or a code that never existed, is a clean false.
    assert!(!db.revoke_invite("REVOKEME").await.unwrap());
    assert!(!db.revoke_invite("NEVER-EXISTED").await.unwrap());
}

// ---- Push subscriptions ----

push_subscription_upsert_lists_and_deletes => |db| {
    let account = Uuid::new_v4();
    let sub = push_subscription("https://push.example/ep1", account);
    db.upsert_push_subscription(&sub).await.unwrap();

    let listed = db.list_push_subscriptions().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].endpoint, "https://push.example/ep1");
    assert_eq!(listed[0].account_id, account);
    assert_eq!(listed[0].p256dh, "p256dh-key");
    assert_eq!(listed[0].auth, "auth-secret");

    db.delete_push_subscription("https://push.example/ep1").await.unwrap();
    assert!(db.list_push_subscriptions().await.unwrap().is_empty());

    // Deleting an endpoint that never existed is a clean no-op.
    db.delete_push_subscription("https://push.example/never-existed").await.unwrap();
}

push_subscription_upsert_by_endpoint_overwrites_not_duplicates => |db| {
    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let endpoint = "https://push.example/ep-reused";

    let mut sub = push_subscription(endpoint, account_a);
    db.upsert_push_subscription(&sub).await.unwrap();

    // Same endpoint re-subscribing (e.g. after clearing site data) under a
    // DIFFERENT account/keys must overwrite the row, not create a second one.
    sub.account_id = account_b;
    sub.p256dh = "new-p256dh".into();
    sub.auth = "new-auth".into();
    db.upsert_push_subscription(&sub).await.unwrap();

    let listed = db.list_push_subscriptions().await.unwrap();
    assert_eq!(listed.len(), 1, "upsert must not duplicate rows for the same endpoint");
    assert_eq!(listed[0].account_id, account_b);
    assert_eq!(listed[0].p256dh, "new-p256dh");
    assert_eq!(listed[0].auth, "new-auth");
}

// ---- Channel state: Telegram roster + generic cursor store ----

telegram_roster_bind_find_and_unbind => |db| {
    let anna = Uuid::new_v4();
    assert!(db.find_telegram_operator("111").await.unwrap().is_none());

    db.bind_telegram_chat("111", anna).await.unwrap();
    assert_eq!(db.find_telegram_operator("111").await.unwrap(), Some(anna));

    db.unbind_telegram_chat("111").await.unwrap();
    assert!(db.find_telegram_operator("111").await.unwrap().is_none());

    // Unbinding an unknown chat id is a clean no-op.
    db.unbind_telegram_chat("never-bound").await.unwrap();
}

telegram_roster_bind_is_upsert_by_chat_id => |db| {
    let anna = Uuid::new_v4();
    let tom = Uuid::new_v4();
    db.bind_telegram_chat("222", anna).await.unwrap();
    // Re-binding the SAME chat id to a different operator overwrites, it
    // does not create a second binding (mirrors InMemoryRoster::bind).
    db.bind_telegram_chat("222", tom).await.unwrap();
    assert_eq!(db.find_telegram_operator("222").await.unwrap(), Some(tom));
    assert_eq!(db.telegram_chat_ids_for(Some(anna)).await.unwrap(), Vec::<String>::new());
    assert_eq!(db.telegram_chat_ids_for(Some(tom)).await.unwrap(), vec!["222"]);
}

telegram_roster_chat_ids_for_broadcast_and_targeted => |db| {
    let anna = Uuid::new_v4();
    let tom = Uuid::new_v4();
    db.bind_telegram_chat("111", anna).await.unwrap();
    db.bind_telegram_chat("222", tom).await.unwrap();

    let mut all = db.telegram_chat_ids_for(None).await.unwrap();
    all.sort();
    assert_eq!(all, vec!["111", "222"]);

    assert_eq!(db.telegram_chat_ids_for(Some(tom)).await.unwrap(), vec!["222"]);
    assert_eq!(db.telegram_chat_ids_for(Some(Uuid::new_v4())).await.unwrap(), Vec::<String>::new());
}

channel_state_get_set_roundtrip_and_overwrites => |db| {
    assert!(db.get_channel_state("telegram:getUpdates:offset").await.unwrap().is_none());

    db.set_channel_state("telegram:getUpdates:offset", "42").await.unwrap();
    assert_eq!(
        db.get_channel_state("telegram:getUpdates:offset").await.unwrap(),
        Some("42".to_string())
    );

    // A later set overwrites rather than erroring or duplicating.
    db.set_channel_state("telegram:getUpdates:offset", "101").await.unwrap();
    assert_eq!(
        db.get_channel_state("telegram:getUpdates:offset").await.unwrap(),
        Some("101".to_string())
    );

    // A DIFFERENT key is independent.
    assert!(db.get_channel_state("some:other:key").await.unwrap().is_none());
}

// ---- ChatRepo (migration 0007 — the durable shared chat transcript) ----

chat_log_appends_in_order_and_pages_the_newest => |db| {
    for i in 0..5 {
        let role = if i % 2 == 0 { "user" } else { "assistant" };
        db.append_chat(Utc::now(), role, "alice", &format!("m{i}")).await.unwrap();
    }
    db.append_chat(Utc::now(), "tool", "kubernetes", r#"{"command":"get pods"}"#).await.unwrap();

    // Full read: every row, ascending seq (render order), content intact.
    let all = db.recent_chat(50).await.unwrap();
    assert_eq!(all.len(), 6);
    assert!(all.windows(2).all(|w| w[0].seq < w[1].seq), "ascending seq");
    assert_eq!(all[0].content, "m0");
    assert_eq!((all[5].role.as_str(), all[5].speaker.as_str()), ("tool", "kubernetes"));

    // Limited read: the NEWEST page, still ascending within it.
    let page = db.recent_chat(2).await.unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].content, "m4");
    assert_eq!(page[1].role, "tool");

    // A zero/negative limit is empty, not an error.
    assert!(db.recent_chat(0).await.unwrap().is_empty());
}

chat_log_pages_backward_from_a_seq_anchor => |db| {
    for i in 0..6 {
        db.append_chat(Utc::now(), "user", "alice", &format!("m{i}")).await.unwrap();
    }
    // The client's anchor is the oldest seq it has rendered: after a
    // 2-row first page (m4, m5), `before` that anchor is the NEXT-newest
    // page (m2, m3), still ascending within it.
    let first = db.recent_chat(2).await.unwrap();
    let anchor = first[0].seq;
    let page = db.before_chat(anchor, 2).await.unwrap();
    assert_eq!(page.iter().map(|m| m.content.as_str()).collect::<Vec<_>>(), vec!["m2", "m3"]);
    assert!(page.windows(2).all(|w| w[0].seq < w[1].seq), "ascending seq");
    // The anchor row itself is EXCLUDED (strictly before) — no overlap,
    // no gap, whatever the page size.
    assert!(page.iter().all(|m| m.seq < anchor));
    // Over-asking returns just what's left; before the oldest is empty
    // (archive exhausted), and a zero limit is empty, not an error.
    let rest = db.before_chat(anchor, 50).await.unwrap();
    assert_eq!(rest.len(), 4);
    assert!(db.before_chat(rest[0].seq, 10).await.unwrap().is_empty());
    assert!(db.before_chat(anchor, 0).await.unwrap().is_empty());
}

}

/// Migration 0009's index, pinned against SQLite specifically for the ERROR
/// SHAPE the fake cannot reproduce.
///
/// Both backends now refuse the duplicate — the parity case above asserts that
/// on each — but only SQLite refuses it by hitting a real database constraint.
/// This test is what proves the index exists in the migration at all, rather
/// than the refusal being a Rust-side check that a hand-written SQL migration
/// could quietly drop.
#[tokio::test]
async fn sqlite_refuses_a_second_account_on_the_same_external_identity() {
    let (db, _dir) = sqlite().await;

    let mut first = account(Uuid::new_v4(), "first@example.com");
    first.auth_provider = AUTH_PROVIDER_HANKO.into();
    first.external_subject = Some("sub-dupe".into());
    AccountRepo::insert(&db, &first).await.unwrap();

    // One operator per external identity. Without this, a second link of the
    // same Hanko subject would fan an identity out across two accounts and the
    // exchange lookup would resolve whichever row the planner reached first.
    let mut second = account(Uuid::new_v4(), "second@example.com");
    second.auth_provider = AUTH_PROVIDER_HANKO.into();
    second.external_subject = Some("sub-dupe".into());
    let err = AccountRepo::insert(&db, &second).await.unwrap_err();
    assert!(matches!(err, opsclaw::Error::Database(_)), "expected Database, got {err:?}");
    assert!(err.to_string().contains("UNIQUE constraint failed"), "{err}");

    // The original binding survives the rejected insert untouched.
    let found = db.by_external_subject(AUTH_PROVIDER_HANKO, "sub-dupe").await.unwrap().unwrap();
    assert_eq!(found.id, first.id);

    // The index key is the PAIR: the same subject under a different provider
    // is a different identity and is accepted.
    let mut other_provider = account(Uuid::new_v4(), "third@example.com");
    other_provider.external_subject = Some("sub-dupe".into());
    AccountRepo::insert(&db, &other_provider).await.unwrap();
    assert_eq!(
        db.by_external_subject(AUTH_PROVIDER_LOCAL, "sub-dupe").await.unwrap().unwrap().id,
        other_provider.id
    );
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
