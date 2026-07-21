//! THE choke point. Every remote command passes through [`Policy::execute`]:
//!
//! ```text
//! tool call → resolve fq target → risk-classify (code, not LLM)
//!   → e-stop check → autonomy gate (level + runbook match)
//!   → rate cap → audit-begin → execute → audit-end
//! ```
//!
//! Nothing else may hold a `TargetExecutor`: tools see only
//! `Arc<dyn PolicyExecute>`, and the executor registry lives privately in
//! [`Policy`]. Every branch below writes an audit record before returning —
//! blocked, queued, and e-stopped decisions are evidence too.

pub mod classify;
pub mod estop;
pub mod scrub;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

pub use estop::EStop;
pub use scrub::Scrubber;

use crate::Result;
use crate::audit::{AuditOutcome, AuditWriter};
use crate::config::Config;
use crate::db::ApprovalRepo;
use crate::domain::{ApprovalRequest, ApprovalState, Autonomy, FqTarget, Principal, RiskClass};
use crate::targets::{Command, ExecOutput, TargetExecutor};

/// How long a queued approval stays decidable before the scheduler sweep
/// expires it. Constant for now; per-target overrides are a config addition
/// when someone needs one.
pub const APPROVAL_TTL_MINUTES: i64 = 30;

/// Wall-clock budget for a single remote command.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// A request to run a concrete command against a target. Built by the tool
/// dispatch layer — `principal` and `target` are trusted positional context,
/// never taken from model output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    pub principal: Principal,
    /// The tool that composed this command (audit context).
    pub tool: String,
    pub target: FqTarget,
    /// Exact command line; what the classifier sees and the audit records.
    pub command: String,
    /// The tool's self-declared coarse class; the classifier may raise (never
    /// lower) it based on the concrete command.
    pub declared_risk: RiskClass,
    /// Current working hypothesis, threaded into approval requests so a human
    /// can decide from a phone.
    pub hypothesis: Option<String>,
    /// Name of the matched runbook, set by the runbook engine (trusted
    /// positional context, like `principal`). A runbook match is the
    /// pre-approval that unlocks execution at `act_on_known` (DESIGN §4).
    #[serde(default)]
    pub runbook: Option<String>,
}

#[derive(Debug)]
pub enum PolicyOutcome {
    /// Ran within policy; output already scrubbed and audited.
    Executed(ExecOutput),
    /// Queued for human approval (suggest level, or act_on_known without a
    /// runbook match). The stored command runs verbatim on approval.
    NeedsApproval(Uuid),
    /// Refused by policy. At `observe`, mutations land in the dry-run log.
    Blocked { reason: String, dry_run_logged: bool },
    /// The e-stop is engaged; nothing executes anywhere.
    EStopped,
}

/// The choke point as a trait, so `ToolCtx` can hold `Arc<dyn PolicyExecute>`
/// and tool unit tests can substitute a recorder. The safety invariant holds:
/// the sole method is "classify, gate, audit, then maybe execute" — there is
/// no way to obtain a `TargetExecutor` from `ToolCtx`.
#[async_trait]
pub trait PolicyExecute: Send + Sync {
    async fn execute(&self, req: CommandRequest) -> Result<PolicyOutcome>;
}

/// Execution of a command a human has ALREADY approved. Deliberately a
/// separate trait from [`PolicyExecute`]: `ToolCtx` holds
/// `Arc<dyn PolicyExecute>`, and tools must never have a gate-skipping
/// method within reach. Only the approvals engine receives this trait.
///
/// The approved path skips exactly one thing — the autonomy gate (the human
/// decision IS the gate) — and keeps everything else: e-stop, the hard-block
/// list, the rate cap, audit-begin/end, and output scrubbing. It takes the
/// stored [`ApprovalRequest`] row, not a fresh `CommandRequest`, so the
/// command that runs is the row's verbatim string by construction.
#[async_trait]
pub trait ExecuteApproved: Send + Sync {
    async fn execute_approved(
        &self,
        approval: &ApprovalRequest,
        operator: Uuid,
    ) -> Result<PolicyOutcome>;
}

/// What the autonomy gate decided (pure; the engine acts on it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    Execute,
    Approval,
    Block,
}

/// The pure gate: risk × autonomy (× runbook match) → decision.
///
/// - Reads execute at every level — `observe` means look, don't touch.
/// - `observe` blocks every mutation (dry-run logged).
/// - `suggest` queues every mutation for approval.
/// - `act_on_known` executes Medium/High iff a runbook matched; otherwise
///   queues.
/// - `auto` executes Medium/High.
/// - Destructive commands never auto-execute at ANY level: outside `observe`
///   they always go to a human (hard-blocked patterns were already refused
///   before the gate).
fn gate(risk: RiskClass, autonomy: Autonomy, runbook_matched: bool) -> Gate {
    use Autonomy::*;
    use RiskClass::*;
    match (risk, autonomy) {
        (Read, _) => Gate::Execute,
        (_, Observe) => Gate::Block,
        (Destructive, _) => Gate::Approval,
        (_, Suggest) => Gate::Approval,
        (_, ActOnKnown) => {
            if runbook_matched {
                Gate::Execute
            } else {
                Gate::Approval
            }
        }
        (_, Auto) => Gate::Execute,
    }
}

/// The policy engine. Owns the executor registry — the ONLY reference to
/// `TargetExecutor`s in the daemon — plus the audit writer, e-stop, scrubber,
/// and the action-rate window.
pub struct Policy {
    /// Keyed by `project::env::target` (the fq path sans resource).
    executors: HashMap<String, Arc<dyn TargetExecutor>>,
    config: Arc<Config>,
    audit: Arc<AuditWriter>,
    estop: Arc<EStop>,
    approvals: Arc<dyn ApprovalRepo>,
    scrubber: Arc<Scrubber>,
    /// Sliding 1-hour window of executed mutations (`max_actions_per_hour`).
    /// In-memory: a restart resets the count, which under-throttles briefly —
    /// accepted for v1 and noted here so nobody mistakes it for durable.
    actions: Mutex<VecDeque<Instant>>,
}

impl Policy {
    pub fn new(
        config: Arc<Config>,
        executors: HashMap<String, Arc<dyn TargetExecutor>>,
        audit: Arc<AuditWriter>,
        estop: Arc<EStop>,
        approvals: Arc<dyn ApprovalRepo>,
        scrubber: Arc<Scrubber>,
    ) -> Self {
        Policy {
            executors,
            config,
            audit,
            estop,
            approvals,
            scrubber,
            actions: Mutex::new(VecDeque::new()),
        }
    }

    fn executor_key(target: &FqTarget) -> String {
        format!("{}::{}::{}", target.project, target.env, target.target)
    }

    /// Claim a slot in the mutation-rate window, BEFORE executing (the same
    /// claim-before-send direction as the scheduler: a crash after the claim
    /// wastes a slot; a crash before a post-hoc count double-spends one).
    async fn claim_action_slot(&self) -> bool {
        let cap = self.config.limits.max_actions_per_hour as usize;
        let mut window = self.actions.lock().await;
        if let Some(cutoff) = Instant::now().checked_sub(Duration::from_secs(3600)) {
            while window.front().is_some_and(|t| *t < cutoff) {
                window.pop_front();
            }
        }
        if window.len() >= cap {
            return false;
        }
        window.push_back(Instant::now());
        true
    }

    pub async fn execute(&self, req: CommandRequest) -> Result<PolicyOutcome> {
        let classification = classify::classify_command(&req.command);
        // The classifier may raise, never lower, the tool's declared class.
        let risk = classification.risk.max(req.declared_risk);
        let fq = req.target.to_string();
        let scrubbed_command = self.scrubber.scrub(&req.command);

        // E-stop before anything else — even hard-block bookkeeping waits.
        if self.estop.engaged().await? {
            self.audit_one(
                &req.principal,
                &fq,
                &req.tool,
                &scrubbed_command,
                risk,
                AuditOutcome::EStopped,
                None,
            )
            .await?;
            return Ok(PolicyOutcome::EStopped);
        }

        // Always-on block list: refused at every autonomy level.
        if classification.hard_blocked {
            self.audit_one(
                &req.principal,
                &fq,
                &req.tool,
                &scrubbed_command,
                risk,
                AuditOutcome::Blocked,
                None,
            )
            .await?;
            return Ok(PolicyOutcome::Blocked {
                reason: format!("hard-blocked pattern ({})", classification.rule),
                dry_run_logged: false,
            });
        }

        let autonomy =
            self.config.autonomy_for(&req.target.project, &req.target.env, &req.target.target);

        match gate(risk, autonomy, req.runbook.is_some()) {
            Gate::Block => {
                // The audit record IS the dry-run log: what would have run,
                // classified and attributed, at a level that forbids acting.
                self.audit_one(
                    &req.principal,
                    &fq,
                    &req.tool,
                    &scrubbed_command,
                    risk,
                    AuditOutcome::Blocked,
                    None,
                )
                .await?;
                Ok(PolicyOutcome::Blocked {
                    reason: format!(
                        "autonomy is {autonomy} for {fq}; {risk} commands are not executed"
                    ),
                    dry_run_logged: true,
                })
            }
            Gate::Approval => {
                let approval = ApprovalRequest {
                    id: Uuid::new_v4(),
                    incident: None,
                    requested_by: req.principal.clone(),
                    target: req.target.clone(),
                    tool: req.tool.clone(),
                    // Stored raw, not scrubbed: this exact string executes
                    // verbatim on approval. Audit gets the scrubbed form.
                    command: req.command.clone(),
                    risk,
                    hypothesis: req.hypothesis.clone().unwrap_or_default(),
                    state: ApprovalState::Pending,
                    requested_at: Utc::now(),
                    expires_at: Utc::now() + chrono::Duration::minutes(APPROVAL_TTL_MINUTES),
                    decided_at: None,
                    decided_by: None,
                };
                self.approvals.insert(&approval).await?;
                self.audit_one(
                    &req.principal,
                    &fq,
                    &req.tool,
                    &scrubbed_command,
                    risk,
                    AuditOutcome::ApprovalQueued,
                    None,
                )
                .await?;
                Ok(PolicyOutcome::NeedsApproval(approval.id))
            }
            Gate::Execute => {
                self.run_capped(
                    &req.principal,
                    &req.tool,
                    &req.target,
                    &req.command,
                    &scrubbed_command,
                    risk,
                )
                .await
            }
        }
    }

    /// The metered execution tail shared by the gated and approved paths:
    /// rate-cap claim → executor lookup → audit-begin → run → scrub →
    /// audit-end. Callers have already established the RIGHT to execute.
    async fn run_capped(
        &self,
        principal: &Principal,
        tool: &str,
        target: &FqTarget,
        command: &str,
        scrubbed_command: &str,
        risk: RiskClass,
    ) -> Result<PolicyOutcome> {
        let fq = target.to_string();
        // Reads are unmetered; mutations claim a rate slot first.
        if risk != RiskClass::Read && !self.claim_action_slot().await {
            self.audit_one(
                principal,
                &fq,
                tool,
                scrubbed_command,
                risk,
                AuditOutcome::Blocked,
                None,
            )
            .await?;
            return Ok(PolicyOutcome::Blocked {
                reason: format!(
                    "max_actions_per_hour ({}) reached",
                    self.config.limits.max_actions_per_hour
                ),
                dry_run_logged: false,
            });
        }
        // Resource-qualified registrations (endpoint executors, keyed by the
        // FULL fq path incl. resource) take precedence; the base target key
        // is the fallback for plain ssh/local/kubernetes commands.
        let executor = self
            .executors
            .get(&fq)
            .or_else(|| self.executors.get(&Self::executor_key(target)))
            .ok_or_else(|| crate::Error::NotFound(format!("no executor configured for {fq}")))?
            .clone();

        self.audit_one(principal, &fq, tool, scrubbed_command, risk, AuditOutcome::Begun, None)
            .await?;
        let cmd = Command { target: target.clone(), line: command.to_string() };
        match executor.run(&cmd, COMMAND_TIMEOUT).await {
            Ok(mut out) => {
                // Scrub BEFORE the output can reach LLM context, the caller,
                // or any log line.
                out.stdout = self.scrubber.scrub(&out.stdout);
                out.stderr = self.scrubber.scrub(&out.stderr);
                self.audit_one(
                    principal,
                    &fq,
                    tool,
                    scrubbed_command,
                    risk,
                    AuditOutcome::Executed,
                    Some(out.exit_code),
                )
                .await?;
                Ok(PolicyOutcome::Executed(out))
            }
            Err(e) => {
                self.audit_one(
                    principal,
                    &fq,
                    tool,
                    scrubbed_command,
                    risk,
                    AuditOutcome::Error,
                    None,
                )
                .await?;
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn audit_one(
        &self,
        principal: &Principal,
        fq_target: &str,
        tool: &str,
        scrubbed_command: &str,
        risk: RiskClass,
        outcome: AuditOutcome,
        exit_code: Option<i32>,
    ) -> Result<()> {
        self.audit
            .append(principal, fq_target, tool, scrubbed_command, risk, outcome, exit_code)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ExecuteApproved for Policy {
    async fn execute_approved(
        &self,
        approval: &ApprovalRequest,
        _operator: Uuid,
    ) -> Result<PolicyOutcome> {
        // Re-derive risk defensively; the human approved THIS command, but
        // the always-on protections still apply.
        let classification = classify::classify_command(&approval.command);
        let risk = classification.risk.max(approval.risk);
        let scrubbed = self.scrubber.scrub(&approval.command);
        // Audit records carry the ORIGINAL requester (who composed the
        // command); the approving operator is on the approval row's
        // `decided_by` — both identities are durably on record (DESIGN §4).
        let principal = &approval.requested_by;
        let fq = approval.target.to_string();

        if self.estop.engaged().await? {
            self.audit_one(
                principal,
                &fq,
                &approval.tool,
                &scrubbed,
                risk,
                AuditOutcome::EStopped,
                None,
            )
            .await?;
            return Ok(PolicyOutcome::EStopped);
        }
        if classification.hard_blocked {
            // Should be unreachable (a hard-blocked command never queues),
            // kept as defense in depth against a tampered approval row.
            self.audit_one(
                principal,
                &fq,
                &approval.tool,
                &scrubbed,
                risk,
                AuditOutcome::Blocked,
                None,
            )
            .await?;
            return Ok(PolicyOutcome::Blocked {
                reason: format!("hard-blocked pattern ({})", classification.rule),
                dry_run_logged: false,
            });
        }
        self.run_capped(
            principal,
            &approval.tool,
            &approval.target,
            &approval.command,
            &scrubbed,
            risk,
        )
        .await
    }
}

#[async_trait]
impl PolicyExecute for Policy {
    async fn execute(&self, req: CommandRequest) -> Result<PolicyOutcome> {
        Policy::execute(self, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain;
    use crate::db::AuditRepo;
    use crate::db::memory::InMemoryDb;
    use crate::targets::ProbeReport;

    /// Scripted executor: returns a fixed output, records every command it
    /// was asked to run.
    struct FakeExecutor {
        output: ExecOutput,
        ran: std::sync::Mutex<Vec<String>>,
    }

    impl FakeExecutor {
        fn ok(stdout: &str) -> Arc<Self> {
            Arc::new(FakeExecutor {
                output: ExecOutput {
                    exit_code: 0,
                    stdout: stdout.into(),
                    stderr: String::new(),
                    duration_ms: 1,
                },
                ran: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl TargetExecutor for FakeExecutor {
        async fn run(&self, cmd: &Command, _timeout: Duration) -> Result<ExecOutput> {
            self.ran.lock().unwrap().push(cmd.line.clone());
            Ok(self.output.clone())
        }
        async fn probe(&self) -> Result<ProbeReport> {
            Ok(ProbeReport { reachable: true, detail: "fake".into() })
        }
    }

    struct Rig {
        policy: Policy,
        db: Arc<InMemoryDb>,
        executor: Arc<FakeExecutor>,
        estop: Arc<EStop>,
        _dir: tempfile::TempDir,
    }

    fn rig_with(config: Config, executor: Arc<FakeExecutor>) -> Rig {
        let db = Arc::new(InMemoryDb::new());
        let dir = tempfile::tempdir().unwrap();
        let estop = Arc::new(EStop::new(dir.path().join("ESTOP"), db.clone()));
        let mut executors: HashMap<String, Arc<dyn TargetExecutor>> = HashMap::new();
        executors.insert("remundo::prod::bastion".into(), executor.clone());
        let policy = Policy::new(
            Arc::new(config),
            executors,
            Arc::new(AuditWriter::new(db.clone())),
            estop.clone(),
            db.clone(),
            Arc::new(Scrubber::new()),
        );
        Rig { policy, db, executor, estop, _dir: dir }
    }

    /// Config with one project/env/target at the given autonomy.
    fn config_at(autonomy: Autonomy) -> Config {
        let toml = format!(
            r#"
            [[project]]
            name = "remundo"
            autonomy = "{autonomy}"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "bastion"
            kind = "local"
            "#
        );
        toml::from_str(&toml).expect("test config parses")
    }

    fn request(command: &str, declared: RiskClass) -> CommandRequest {
        CommandRequest {
            principal: Principal::System,
            tool: "shell".into(),
            target: FqTarget::new("remundo", "prod", "bastion"),
            command: command.into(),
            declared_risk: declared,
            hypothesis: Some("test hypothesis".into()),
            runbook: None,
        }
    }

    async fn outcomes(db: &InMemoryDb) -> Vec<AuditOutcome> {
        db.range(1, 100).await.unwrap().iter().map(|r| r.outcome).collect()
    }

    // ---- the gate itself (pure) ------------------------------------------

    #[test]
    fn gate_matrix() {
        use Autonomy::*;
        use RiskClass::*;
        // Reads execute everywhere.
        for a in [Observe, Suggest, ActOnKnown, Auto] {
            assert_eq!(gate(Read, a, false), Gate::Execute);
        }
        // Observe blocks all mutations.
        for r in [Medium, High, Destructive] {
            assert_eq!(gate(r, Observe, false), Gate::Block);
        }
        // Suggest queues all mutations.
        for r in [Medium, High, Destructive] {
            assert_eq!(gate(r, Suggest, false), Gate::Approval);
        }
        // ActOnKnown: runbook match unlocks Medium/High, never Destructive.
        assert_eq!(gate(Medium, ActOnKnown, true), Gate::Execute);
        assert_eq!(gate(High, ActOnKnown, true), Gate::Execute);
        assert_eq!(gate(Medium, ActOnKnown, false), Gate::Approval);
        assert_eq!(gate(Destructive, ActOnKnown, true), Gate::Approval);
        // Auto executes Medium/High; Destructive still goes to a human.
        assert_eq!(gate(Medium, Auto, false), Gate::Execute);
        assert_eq!(gate(High, Auto, false), Gate::Execute);
        assert_eq!(gate(Destructive, Auto, false), Gate::Approval);
    }

    // ---- engine behaviour -------------------------------------------------

    #[tokio::test]
    async fn read_executes_even_at_observe_and_audits_begin_end() {
        let rig = rig_with(config_at(Autonomy::Observe), FakeExecutor::ok("14:02 up 3 days"));
        let out = rig.policy.execute(request("uptime", RiskClass::Read)).await.unwrap();
        assert!(matches!(out, PolicyOutcome::Executed(_)));
        assert_eq!(*rig.executor.ran.lock().unwrap(), vec!["uptime".to_string()]);
        assert_eq!(outcomes(&rig.db).await, vec![AuditOutcome::Begun, AuditOutcome::Executed]);
    }

    #[tokio::test]
    async fn observe_blocks_mutation_into_dry_run_log() {
        let rig = rig_with(config_at(Autonomy::Observe), FakeExecutor::ok(""));
        let out =
            rig.policy.execute(request("systemctl restart nginx", RiskClass::Read)).await.unwrap();
        match out {
            PolicyOutcome::Blocked { dry_run_logged, .. } => assert!(dry_run_logged),
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert!(rig.executor.ran.lock().unwrap().is_empty());
        assert_eq!(outcomes(&rig.db).await, vec![AuditOutcome::Blocked]);
    }

    #[tokio::test]
    async fn suggest_queues_approval_with_verbatim_command() {
        let rig = rig_with(config_at(Autonomy::Suggest), FakeExecutor::ok(""));
        let out =
            rig.policy.execute(request("systemctl restart nginx", RiskClass::Read)).await.unwrap();
        let id = match out {
            PolicyOutcome::NeedsApproval(id) => id,
            other => panic!("expected NeedsApproval, got {other:?}"),
        };
        let stored = ApprovalRepo::get(&*rig.db, id).await.unwrap().unwrap();
        assert_eq!(stored.command, "systemctl restart nginx");
        assert_eq!(stored.state, ApprovalState::Pending);
        assert_eq!(stored.hypothesis, "test hypothesis");
        assert!(rig.executor.ran.lock().unwrap().is_empty());
        assert_eq!(outcomes(&rig.db).await, vec![AuditOutcome::ApprovalQueued]);
    }

    #[tokio::test]
    async fn act_on_known_needs_the_runbook_match() {
        let rig = rig_with(config_at(Autonomy::ActOnKnown), FakeExecutor::ok(""));
        let bare = request("systemctl restart nginx", RiskClass::Read);
        assert!(matches!(rig.policy.execute(bare).await.unwrap(), PolicyOutcome::NeedsApproval(_)));
        let mut matched = request("systemctl restart nginx", RiskClass::Read);
        matched.runbook = Some("restart-flapping-service".into());
        assert!(matches!(rig.policy.execute(matched).await.unwrap(), PolicyOutcome::Executed(_)));
    }

    #[tokio::test]
    async fn destructive_never_auto_executes() {
        let rig = rig_with(config_at(Autonomy::Auto), FakeExecutor::ok(""));
        let out = rig
            .policy
            .execute(request("terraform destroy -auto-approve", RiskClass::Destructive))
            .await
            .unwrap();
        assert!(matches!(out, PolicyOutcome::NeedsApproval(_)));
        assert!(rig.executor.ran.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn hard_blocked_refused_even_at_auto() {
        let rig = rig_with(config_at(Autonomy::Auto), FakeExecutor::ok(""));
        let out = rig.policy.execute(request("rm -rf /", RiskClass::Read)).await.unwrap();
        match out {
            PolicyOutcome::Blocked { reason, dry_run_logged } => {
                assert!(reason.contains("hard-blocked"), "reason: {reason}");
                assert!(!dry_run_logged);
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert!(rig.executor.ran.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn estop_halts_everything_including_reads() {
        let rig = rig_with(config_at(Autonomy::Auto), FakeExecutor::ok(""));
        rig.estop.engage("test").await.unwrap();
        let out = rig.policy.execute(request("uptime", RiskClass::Read)).await.unwrap();
        assert!(matches!(out, PolicyOutcome::EStopped));
        assert!(rig.executor.ran.lock().unwrap().is_empty());
        assert_eq!(outcomes(&rig.db).await, vec![AuditOutcome::EStopped]);
        // Resume restores execution.
        rig.estop.resume().await.unwrap();
        let out = rig.policy.execute(request("uptime", RiskClass::Read)).await.unwrap();
        assert!(matches!(out, PolicyOutcome::Executed(_)));
    }

    #[tokio::test]
    async fn sentinel_file_alone_estops_with_no_db_flag() {
        let rig = rig_with(config_at(Autonomy::Auto), FakeExecutor::ok(""));
        estop::write_sentinel(rig.estop.sentinel_path(), "hand-written").unwrap();
        let out = rig.policy.execute(request("uptime", RiskClass::Read)).await.unwrap();
        assert!(matches!(out, PolicyOutcome::EStopped));
    }

    #[tokio::test]
    async fn classifier_raises_declared_risk_never_lowers() {
        // Tool declares Read, command is a mutation → gated as the mutation.
        let rig = rig_with(config_at(Autonomy::Suggest), FakeExecutor::ok(""));
        let out =
            rig.policy.execute(request("systemctl restart nginx", RiskClass::Read)).await.unwrap();
        assert!(matches!(out, PolicyOutcome::NeedsApproval(_)));
        // Tool declares High, command reads → still gated as High (declared
        // floor holds).
        let out = rig.policy.execute(request("uptime", RiskClass::High)).await.unwrap();
        assert!(matches!(out, PolicyOutcome::NeedsApproval(_)));
    }

    #[tokio::test]
    async fn rate_cap_blocks_mutations_not_reads() {
        let mut config = config_at(Autonomy::Auto);
        config.limits.max_actions_per_hour = 2;
        let rig = rig_with(config, FakeExecutor::ok(""));
        for _ in 0..2 {
            let out = rig
                .policy
                .execute(request("systemctl restart nginx", RiskClass::Read))
                .await
                .unwrap();
            assert!(matches!(out, PolicyOutcome::Executed(_)));
        }
        let out =
            rig.policy.execute(request("systemctl restart nginx", RiskClass::Read)).await.unwrap();
        match out {
            PolicyOutcome::Blocked { reason, .. } => {
                assert!(reason.contains("max_actions_per_hour"), "reason: {reason}")
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
        // Reads are unmetered.
        let out = rig.policy.execute(request("uptime", RiskClass::Read)).await.unwrap();
        assert!(matches!(out, PolicyOutcome::Executed(_)));
    }

    #[tokio::test]
    async fn secrets_scrubbed_from_output_and_audit_never_from_stored_command() {
        let db = Arc::new(InMemoryDb::new());
        let dir = tempfile::tempdir().unwrap();
        let estop = Arc::new(EStop::new(dir.path().join("ESTOP"), db.clone()));
        let scrubber = Arc::new(Scrubber::new());
        scrubber.register("DB_PASSWORD", "hunter22");
        let executor = FakeExecutor::ok("PGPASSWORD=hunter22\nHOME=/root");
        let mut executors: HashMap<String, Arc<dyn TargetExecutor>> = HashMap::new();
        executors.insert("remundo::prod::bastion".into(), executor.clone());
        let policy = Policy::new(
            Arc::new(config_at(Autonomy::Auto)),
            executors,
            Arc::new(AuditWriter::new(db.clone())),
            estop,
            db.clone(),
            scrubber,
        );

        // Executed path: env dump comes back scrubbed, audit line scrubbed.
        let out = policy.execute(request("env # hunter22", RiskClass::Read)).await.unwrap();
        match out {
            PolicyOutcome::Executed(o) => {
                assert!(!o.stdout.contains("hunter22"));
                assert!(o.stdout.contains("<redacted:DB_PASSWORD>"));
            }
            other => panic!("expected Executed, got {other:?}"),
        }
        for record in db.range(1, 100).await.unwrap() {
            assert!(!record.command.contains("hunter22"), "secret leaked into audit");
        }

        // Approval path: the STORED command stays verbatim (it must execute
        // exactly as approved), while its audit record is scrubbed.
        // Destructive so the request queues even at Auto (never auto-executes).
        let approval_req = CommandRequest {
            declared_risk: RiskClass::Destructive,
            command: "curl -H 'x-key: hunter22' https://api".into(),
            ..request("", RiskClass::Destructive)
        };
        let id = match policy.execute(approval_req).await.unwrap() {
            PolicyOutcome::NeedsApproval(id) => id,
            other => panic!("expected NeedsApproval, got {other:?}"),
        };
        let stored = ApprovalRepo::get(&*db, id).await.unwrap().unwrap();
        assert!(stored.command.contains("hunter22"));
        let last = AuditRepo::last(&*db).await.unwrap().unwrap();
        assert!(!last.command.contains("hunter22"));
    }

    #[tokio::test]
    async fn every_outcome_leaves_a_verifiable_chain() {
        let rig = rig_with(config_at(Autonomy::Suggest), FakeExecutor::ok("ok"));
        rig.policy.execute(request("uptime", RiskClass::Read)).await.unwrap(); // begun+executed
        rig.policy.execute(request("systemctl restart nginx", RiskClass::Read)).await.unwrap(); // queued
        rig.policy.execute(request("rm -rf /", RiskClass::Read)).await.unwrap(); // hard block
        rig.estop.engage("test").await.unwrap();
        rig.policy.execute(request("uptime", RiskClass::Read)).await.unwrap(); // estopped
        let records = rig.db.range(1, 100).await.unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(chain::verify(records.iter()).unwrap(), 5);
    }

    #[tokio::test]
    async fn approved_command_executes_at_suggest_instead_of_requeueing() {
        // The exact gap the incidents build surfaced: at Suggest, replaying
        // an approved command through execute() re-entered the gate and
        // queued a SECOND approval. execute_approved() must execute.
        let rig = rig_with(config_at(Autonomy::Suggest), FakeExecutor::ok("restarted"));
        let id = match rig
            .policy
            .execute(request("systemctl restart nginx", RiskClass::Read))
            .await
            .unwrap()
        {
            PolicyOutcome::NeedsApproval(id) => id,
            other => panic!("expected NeedsApproval, got {other:?}"),
        };
        let row = ApprovalRepo::get(&*rig.db, id).await.unwrap().unwrap();
        let out = rig.policy.execute_approved(&row, Uuid::new_v4()).await.unwrap();
        assert!(matches!(out, PolicyOutcome::Executed(_)), "got {out:?}");
        assert_eq!(*rig.executor.ran.lock().unwrap(), vec!["systemctl restart nginx".to_string()]);
        // Still guarded: e-stop halts the approved path too.
        rig.estop.engage("test").await.unwrap();
        let out = rig.policy.execute_approved(&row, Uuid::new_v4()).await.unwrap();
        assert!(matches!(out, PolicyOutcome::EStopped));
    }

    #[tokio::test]
    async fn approved_hard_blocked_command_still_refused() {
        // Defense in depth: a tampered approval row containing a hard-blocked
        // command must not execute even though "a human approved it".
        let rig = rig_with(config_at(Autonomy::Suggest), FakeExecutor::ok(""));
        let row = ApprovalRequest {
            id: Uuid::new_v4(),
            incident: None,
            requested_by: Principal::System,
            target: FqTarget::new("remundo", "prod", "bastion"),
            tool: "shell".into(),
            command: "rm -rf /".into(),
            risk: RiskClass::Read,
            hypothesis: String::new(),
            state: ApprovalState::Approved,
            requested_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(30),
            decided_at: Some(Utc::now()),
            decided_by: Some(Uuid::new_v4()),
        };
        let out = rig.policy.execute_approved(&row, Uuid::new_v4()).await.unwrap();
        assert!(matches!(out, PolicyOutcome::Blocked { .. }), "got {out:?}");
        assert!(rig.executor.ran.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn resource_qualified_executor_takes_precedence_over_base_target() {
        // The endpoint-mutation path (tools/argocd.rs rollback): an executor
        // registered under the FULL resource-qualified fq string handles the
        // command — inside audit-begin/end like any other — while plain
        // commands on the same target still hit the base executor.
        let rig = rig_with(config_at(Autonomy::Auto), FakeExecutor::ok("base"));
        let endpoint_exec = FakeExecutor::ok("rolled back");
        // rig_with holds Policy by value; rebuild with both registrations.
        let db = Arc::new(InMemoryDb::new());
        let dir = tempfile::tempdir().unwrap();
        let estop = Arc::new(EStop::new(dir.path().join("ESTOP"), db.clone()));
        let mut executors: HashMap<String, Arc<dyn TargetExecutor>> = HashMap::new();
        executors.insert("remundo::prod::bastion".into(), rig.executor.clone());
        let mut resource_target = FqTarget::new("remundo", "prod", "bastion");
        resource_target.resource = Some((crate::domain::ResourceType::Argocd, "main".into()));
        executors.insert(resource_target.to_string(), endpoint_exec.clone());
        let policy = Policy::new(
            Arc::new(config_at(Autonomy::Auto)),
            executors,
            Arc::new(AuditWriter::new(db.clone())),
            estop,
            db.clone(),
            Arc::new(Scrubber::new()),
        );

        let mut req = request("argocd app rollback guestbook 7", RiskClass::High);
        req.target = resource_target;
        let out = policy.execute(req).await.unwrap();
        assert!(matches!(out, PolicyOutcome::Executed(_)), "got {out:?}");
        assert_eq!(
            *endpoint_exec.ran.lock().unwrap(),
            vec!["argocd app rollback guestbook 7".to_string()]
        );
        assert!(rig.executor.ran.lock().unwrap().is_empty(), "base executor must not fire");
        // And it was audited: begin + executed, chain intact.
        let records = db.range(1, 10).await.unwrap();
        assert_eq!(
            records.iter().map(|r| r.outcome).collect::<Vec<_>>(),
            vec![AuditOutcome::Begun, AuditOutcome::Executed]
        );
        assert!(records[0].fq_target.contains("argocd"));
    }

    #[tokio::test]
    async fn missing_executor_is_an_error_not_a_silent_skip() {
        let rig = rig_with(config_at(Autonomy::Auto), FakeExecutor::ok(""));
        let mut req = request("uptime", RiskClass::Read);
        req.target = FqTarget::new("remundo", "prod", "unknown-target");
        assert!(rig.policy.execute(req).await.is_err());
    }
}
