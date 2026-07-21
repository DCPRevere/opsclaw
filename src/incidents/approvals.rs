//! Approvals engine (brief §5, DESIGN.md §4 "Approvals"): gated mutations
//! awaiting a human decision. The load-bearing invariant is that `approve`
//! executes the STORED command verbatim through [`crate::policy::PolicyExecute`]
//! — never a fresh LLM interpretation of "yes, do it" — audited under both
//! the requesting agent's principal and the approving operator.
//!
//! This module composes `db::ApprovalRepo` + `policy::ExecuteApproved`; it
//! has no persistence or transport of its own.
//!
//! `ExecuteApproved` exists precisely for this call site: re-running an
//! approved command through `PolicyExecute::execute` would re-enter the
//! autonomy gate and queue a SECOND approval at `Suggest`. The approved path
//! skips only the gate (the human decision IS the gate) and keeps e-stop,
//! the hard-block list, rate caps, audit, and scrubbing — and it is a
//! separate trait so tools, which hold `Arc<dyn PolicyExecute>`, never have
//! a gate-skipping method within reach.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::Result;
use crate::db::ApprovalRepo;
use crate::domain::{ApprovalRequest, ApprovalState, FqTarget, Principal, RiskClass};
use crate::policy::{ExecuteApproved, PolicyOutcome};

/// Default window a pending approval stays open before the timeout sweep
/// expires it (DESIGN.md §4: "Timeouts cancel via a scheduler sweep").
/// Callers may pass an explicit `expires_at` via [`NewApproval`] instead.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::minutes(15);

/// Everything needed to open an approval request — the full decision context
/// a human needs to decide from a phone (brief §5): command, target, risk
/// class, hypothesis. Mirrors `policy::CommandRequest` closely because an
/// approval IS a `CommandRequest` that couldn't execute immediately; kept as
/// a separate type (rather than reusing `CommandRequest`) because an approval
/// additionally carries `incident` linkage and an explicit expiry.
#[derive(Debug, Clone)]
pub struct NewApproval {
    pub requested_by: Principal,
    pub incident: Option<Uuid>,
    pub target: FqTarget,
    pub tool: String,
    /// The exact command that will run on approval, verbatim.
    pub command: String,
    pub risk: RiskClass,
    pub hypothesis: String,
    /// `None` uses [`DEFAULT_APPROVAL_TIMEOUT`] from `now`.
    pub expires_in: Option<Duration>,
}

/// Build the persisted row for a new approval request. Pure construction —
/// callers pass this to `ApprovalRepo::insert`.
pub fn new_approval_request(req: NewApproval, now: DateTime<Utc>) -> ApprovalRequest {
    let expires_at = now + req.expires_in.unwrap_or(DEFAULT_APPROVAL_TIMEOUT);
    ApprovalRequest {
        id: Uuid::new_v4(),
        incident: req.incident,
        requested_by: req.requested_by,
        target: req.target,
        tool: req.tool,
        command: req.command,
        risk: req.risk,
        hypothesis: req.hypothesis,
        state: ApprovalState::Pending,
        requested_at: now,
        expires_at,
        decided_at: None,
        decided_by: None,
    }
}

/// Outcome of `approve`/`deny` beyond the repo's own row mutation — surfaced
/// to callers (chat reply, HTTP handler, CLI) so they can report what
/// actually happened, not just that the decision was recorded.
#[derive(Debug)]
pub enum DecisionOutcome {
    /// Approved and executed; carries the policy outcome of doing so.
    ApprovedAndExecuted(PolicyOutcome),
    Denied,
}

/// Approve a pending request and execute its stored command verbatim.
///
/// Sequence: atomically decide (repo rejects a double-tap via
/// `Error::Conflict` — `ApprovalRepo::decide` is documented to guard exactly
/// this), then hand the STORED row (never fresh input) to
/// `ExecuteApproved::execute_approved`, which runs the row's verbatim
/// command through the always-on protections with the autonomy gate
/// satisfied by the human decision. Both identities are on the record: the
/// agent that proposed it (`requested_by`, carried into every audit record
/// policy writes) and the operator that authorized it (the row's
/// `decided_by`) — satisfying "audited under both the agent principal and
/// the approving operator."
///
/// On a successful execute, marks the row `Executed`. A policy outcome other
/// than `Executed` (e.g. the e-stop engaged between approval and execution,
/// or policy re-blocks it) is surfaced via `DecisionOutcome` WITHOUT marking
/// the row executed — the approval's own state (`Approved`, not
/// `Executed`) then still tells the truth about what happened.
pub async fn approve(
    repo: &dyn ApprovalRepo,
    policy: &Arc<dyn ExecuteApproved>,
    id: Uuid,
    operator: Uuid,
) -> Result<DecisionOutcome> {
    let row = repo.decide(id, ApprovalState::Approved, operator).await?;

    let outcome = policy.execute_approved(&row, operator).await?;

    if matches!(outcome, PolicyOutcome::Executed(_)) {
        repo.mark_executed(id).await?;
    }

    Ok(DecisionOutcome::ApprovedAndExecuted(outcome))
}

/// Deny a pending request. No execution happens; the repo's `decide` is the
/// atomic guard against a double-tap (approve-then-deny or deny-then-deny)
/// racing another decision.
pub async fn deny(repo: &dyn ApprovalRepo, id: Uuid, operator: Uuid) -> Result<DecisionOutcome> {
    repo.decide(id, ApprovalState::Denied, operator).await?;
    Ok(DecisionOutcome::Denied)
}

/// Timeout sweep: expire every pending request past its deadline. Called by
/// the scheduler (DESIGN.md §4/§3: "Timeouts cancel via a scheduler sweep,
/// the same claim machinery"). Returns the rows that were expired so the
/// caller can notify about them (e.g. "approval for X timed out, treating as
/// denied"). Delegates the actual row mutation to
/// `ApprovalRepo::expire_due`, which is documented to only touch rows still
/// `Pending` past `now` — already-decided rows are untouched.
pub async fn sweep_expired(
    repo: &dyn ApprovalRepo,
    now: DateTime<Utc>,
) -> Result<Vec<ApprovalRequest>> {
    repo.expire_due(now).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory::InMemoryDb;
    use crate::domain::{ApprovalRequest, RiskClass};
    use crate::targets::ExecOutput;
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn target() -> FqTarget {
        FqTarget::new("remundo", "prod", "web-1")
    }

    fn base_request() -> NewApproval {
        NewApproval {
            requested_by: Principal::Agent { job: None },
            incident: None,
            target: target(),
            tool: "systemd".into(),
            command: "systemctl restart nginx".into(),
            risk: RiskClass::Medium,
            hypothesis: "nginx worker wedged, safe to bounce".into(),
            expires_in: None,
        }
    }

    /// Records the exact approval row it was handed and returns a scripted
    /// outcome — the "fake Policy that records requests" test double, so
    /// approve()'s "verbatim, not a fresh interpretation" contract is
    /// testable without a real engine.
    struct RecordingPolicy {
        seen: Mutex<Vec<ApprovalRequest>>,
        outcome: fn() -> PolicyOutcome,
    }

    impl RecordingPolicy {
        fn always_executes() -> Self {
            RecordingPolicy {
                seen: Mutex::new(Vec::new()),
                outcome: || {
                    PolicyOutcome::Executed(ExecOutput {
                        exit_code: 0,
                        stdout: "restarted".into(),
                        stderr: String::new(),
                        duration_ms: 12,
                    })
                },
            }
        }

        fn always_blocks() -> Self {
            RecordingPolicy { seen: Mutex::new(Vec::new()), outcome: || PolicyOutcome::EStopped }
        }
    }

    #[async_trait]
    impl ExecuteApproved for RecordingPolicy {
        async fn execute_approved(
            &self,
            approval: &ApprovalRequest,
            _operator: Uuid,
        ) -> Result<PolicyOutcome> {
            self.seen.lock().unwrap().push(approval.clone());
            Ok((self.outcome)())
        }
    }

    async fn seeded_repo(req: ApprovalRequest) -> InMemoryDb {
        let db = InMemoryDb::new();
        ApprovalRepo::insert(&db, &req).await.unwrap();
        db
    }

    #[test]
    fn new_approval_request_defaults_expiry() {
        let now = Utc::now();
        let row = new_approval_request(base_request(), now);
        assert_eq!(row.state, ApprovalState::Pending);
        assert_eq!(row.expires_at, now + DEFAULT_APPROVAL_TIMEOUT);
        assert_eq!(row.command, "systemctl restart nginx");
        assert!(row.decided_at.is_none());
    }

    #[test]
    fn new_approval_request_honors_explicit_expiry() {
        let now = Utc::now();
        let mut req = base_request();
        req.expires_in = Some(Duration::minutes(60));
        let row = new_approval_request(req, now);
        assert_eq!(row.expires_at, now + Duration::minutes(60));
    }

    #[tokio::test]
    async fn approve_executes_the_stored_command_verbatim() {
        let now = Utc::now();
        let row = new_approval_request(base_request(), now);
        let id = row.id;
        let db = seeded_repo(row).await;
        let policy: Arc<dyn ExecuteApproved> = Arc::new(RecordingPolicy::always_executes());
        let operator = Uuid::new_v4();

        let outcome = approve(&db, &policy, id, operator).await.unwrap();
        assert!(matches!(
            outcome,
            DecisionOutcome::ApprovedAndExecuted(PolicyOutcome::Executed(_))
        ));

        let updated = ApprovalRepo::get(&db, id).await.unwrap().unwrap();
        assert_eq!(updated.state, ApprovalState::Executed);
        assert_eq!(updated.decided_by, Some(operator));
    }

    #[tokio::test]
    async fn approve_passes_through_the_exact_stored_command_and_principal() {
        let now = Utc::now();
        let mut new = base_request();
        new.requested_by = Principal::Agent { job: Some(Uuid::new_v4()) };
        new.command = "kubectl rollout restart deploy/api -n prod".into();
        let row = new_approval_request(new, now);
        let id = row.id;
        let expected_principal = row.requested_by.clone();
        let expected_command = row.command.clone();
        let db = seeded_repo(row).await;

        let policy = Arc::new(RecordingPolicy::always_executes());
        let policy_dyn: Arc<dyn ExecuteApproved> = policy.clone();
        approve(&db, &policy_dyn, id, Uuid::new_v4()).await.unwrap();

        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].command, expected_command);
        assert_eq!(seen[0].requested_by, expected_principal);
    }

    #[tokio::test]
    async fn approve_does_not_mark_executed_when_policy_blocks() {
        let now = Utc::now();
        let row = new_approval_request(base_request(), now);
        let id = row.id;
        let db = seeded_repo(row).await;
        let policy: Arc<dyn ExecuteApproved> = Arc::new(RecordingPolicy::always_blocks());

        let outcome = approve(&db, &policy, id, Uuid::new_v4()).await.unwrap();
        assert!(matches!(outcome, DecisionOutcome::ApprovedAndExecuted(PolicyOutcome::EStopped)));

        let updated = ApprovalRepo::get(&db, id).await.unwrap().unwrap();
        // Approved (the human decision stands) but NOT executed (it didn't
        // actually run) — the row must not claim a false success.
        assert_eq!(updated.state, ApprovalState::Approved);
    }

    #[tokio::test]
    async fn approve_twice_returns_conflict() {
        let now = Utc::now();
        let row = new_approval_request(base_request(), now);
        let id = row.id;
        let db = seeded_repo(row).await;
        let policy: Arc<dyn ExecuteApproved> = Arc::new(RecordingPolicy::always_executes());

        approve(&db, &policy, id, Uuid::new_v4()).await.unwrap();
        let second = approve(&db, &policy, id, Uuid::new_v4()).await;
        assert!(second.is_err(), "double-approve must not silently re-execute");
    }

    #[tokio::test]
    async fn deny_marks_denied_without_executing() {
        let now = Utc::now();
        let row = new_approval_request(base_request(), now);
        let id = row.id;
        let db = seeded_repo(row).await;

        let outcome = deny(&db, id, Uuid::new_v4()).await.unwrap();
        assert!(matches!(outcome, DecisionOutcome::Denied));

        let updated = ApprovalRepo::get(&db, id).await.unwrap().unwrap();
        assert_eq!(updated.state, ApprovalState::Denied);
    }

    #[tokio::test]
    async fn sweep_expired_expires_only_past_deadline() {
        let now = Utc::now();
        let mut expiring = base_request();
        expiring.expires_in = Some(Duration::minutes(-1)); // already past
        let expiring_row = new_approval_request(expiring, now - Duration::minutes(5));

        let mut fresh = base_request();
        fresh.expires_in = Some(Duration::minutes(30));
        let fresh_row = new_approval_request(fresh, now);

        let db = InMemoryDb::new();
        ApprovalRepo::insert(&db, &expiring_row).await.unwrap();
        ApprovalRepo::insert(&db, &fresh_row).await.unwrap();

        let expired = sweep_expired(&db, now).await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, expiring_row.id);

        let still_pending = ApprovalRepo::get(&db, fresh_row.id).await.unwrap().unwrap();
        assert_eq!(still_pending.state, ApprovalState::Pending);
    }
}
