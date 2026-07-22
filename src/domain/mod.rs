//! Pure domain types. No IO, no deps on other opsclaw modules.
//!
//! The hierarchy (brief §4): Project → Environment → Target → Resource.
//! Invariants: one Target = one credential set = one audit identity;
//! Environment is policy, Target is connection; policy attributes inherit
//! down the tree, credentials never do.

pub mod job;

pub use job::{JOB_GAP_MINUTES_MIN, JOB_INTERVAL_MINUTES_MAX, JOBS_MAX, Job, Payload, Schedule};

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Fully-qualified target path: `project::env::target`, optionally extended
/// with `::resource_type::name`. This is the audit identity — the audit log
/// always records the fully qualified form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FqTarget {
    pub project: String,
    pub env: String,
    pub target: String,
    /// Present when addressing a target-owned resource (postgres, rabbitmq…).
    pub resource: Option<(ResourceType, String)>,
}

impl FqTarget {
    pub fn new(
        project: impl Into<String>,
        env: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        FqTarget { project: project.into(), env: env.into(), target: target.into(), resource: None }
    }

    /// Parse `project::env::target` or `project::env::target::rtype::name`.
    pub fn parse(s: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = s.split("::").collect();
        match parts.as_slice() {
            [p, e, t] => Ok(FqTarget::new(*p, *e, *t)),
            [p, e, t, rt, name] => {
                let rtype = ResourceType::from_str(rt)
                    .map_err(|_| crate::Error::Config(format!("unknown resource type: {rt}")))?;
                Ok(FqTarget {
                    resource: Some((rtype, name.to_string())),
                    ..FqTarget::new(*p, *e, *t)
                })
            }
            _ => Err(crate::Error::Config(format!("malformed target path: {s}"))),
        }
    }
}

impl fmt::Display for FqTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", self.project, self.env, self.target)?;
        if let Some((rt, name)) = &self.resource {
            write!(f, "::{rt}::{name}")?;
        }
        Ok(())
    }
}

/// Target connection type. Environment is policy; this is connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TargetKind {
    Ssh,
    Local,
    Kubernetes,
    Cloud { provider: CloudProvider, region: Option<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Azure,
    // Provider-pluggable by design (remundo has a Scaleway plan on file).
    Scaleway,
}

/// Resource types a target can own (brief §4; the v1 set per DESIGN.md §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Elasticsearch,
    AzureServiceBus,
    Eventstore,
    Prometheus,
    Argocd,
    Postgres,
    Rabbitmq,
    Cloudflare,
    Github,
    Pagerduty,
    Loki,
    Jaeger,
    Sentry,
    Posthog,
}

impl FromStr for ResourceType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|_| ())
    }
}

impl fmt::Display for ResourceType {
    // Serde-derived snake_case is the single source of the wire/config/display
    // form — Display goes through it so the three can never diverge.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::String(s)) => f.write_str(&s),
            _ => Err(fmt::Error),
        }
    }
}

/// Autonomy level (brief §5). NOTE: deliberately no `Default` impl and a
/// strict `FromStr` — an unparseable level is a config error, never a silent
/// downgrade to anything but `Observe` (config::validate refuses to boot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Autonomy {
    Observe,
    Suggest,
    ActOnKnown,
    Auto,
}

impl FromStr for Autonomy {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "observe" => Ok(Autonomy::Observe),
            "suggest" => Ok(Autonomy::Suggest),
            "act_on_known" => Ok(Autonomy::ActOnKnown),
            "auto" => Ok(Autonomy::Auto),
            other => Err(crate::Error::Config(format!(
                "unknown autonomy level {other:?} (expected observe|suggest|act_on_known|auto)"
            ))),
        }
    }
}

impl fmt::Display for Autonomy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Must stay the exact inverse of FromStr (the config-file vocabulary).
        f.write_str(match self {
            Autonomy::Observe => "observe",
            Autonomy::Suggest => "suggest",
            Autonomy::ActOnKnown => "act_on_known",
            Autonomy::Auto => "auto",
        })
    }
}

/// Risk class of a concrete command. Classification is done in code (pattern
/// rules + tool self-declaration), never by the LLM. Ordered: later = riskier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Read,
    Medium,
    High,
    Destructive,
}

impl fmt::Display for RiskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RiskClass::Read => "read",
            RiskClass::Medium => "medium",
            RiskClass::High => "high",
            RiskClass::Destructive => "destructive",
        })
    }
}

/// Expected state of a target/environment — intentional states must not page
/// (remundo's sandbox cluster is normally stopped and wiped monthly).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedState {
    #[default]
    Running,
    Stopped,
    Ephemeral,
}

/// Who is acting. Carried through policy, audit, LLM usage attribution, and
/// approvals — never inferred from model output (gianna's DATA boundary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Principal {
    /// The agent acting autonomously; `job` set when inside a heartbeat run.
    Agent { job: Option<Uuid> },
    /// A human operator (accounts table id).
    Operator { account: Uuid },
    /// The daemon itself (housekeeping, doctor).
    System,
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::Agent { job: Some(j) } => write!(f, "agent(job:{j})"),
            Principal::Agent { job: None } => write!(f, "agent"),
            Principal::Operator { account } => write!(f, "operator:{account}"),
            Principal::System => write!(f, "system"),
        }
    }
}

/// Incident severity, carried in the structured escalation payload (brief §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Incident lifecycle (brief §6). Deliberately coarse (gianna's 3-state
/// billing lesson): extra nuance rides in fields, not states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Active,
    Acknowledged,
    Resolved,
    Expired,
}

/// One incident. `fingerprint` is the anti-spam identity: one fingerprint →
/// one alert, deduplicated across heartbeat ticks via the claim table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    /// Dedup identity: derived from (fq target, fault class, resource).
    pub fingerprint: String,
    /// The fault-kind label the incident was opened for ("disk-fill",
    /// "cpu_saturation", ...) — the same string hashed into `fingerprint`
    /// (`incidents::fingerprint_for`), persisted in the clear so displays
    /// and the sim harness's "named correctly" assertion don't have to
    /// re-derive it from a hash. Empty on rows predating the column.
    #[serde(default)]
    pub fault_class: String,
    pub target: FqTarget,
    pub severity: Severity,
    pub state: IncidentState,
    /// Observed signals with actual numbers, as shown to humans.
    pub signals: String,
    pub hypothesis: String,
    pub recommended_action: Option<String>,
    pub opened_at: DateTime<Utc>,
    /// When the incident was last re-opened out of `Expired` (the same fault
    /// re-detected after its chain exhausted unacked — see
    /// `IncidentRepo::reopen`). `opened_at` keeps the ORIGINAL detection for
    /// age-tracking; `None` on incidents never re-opened.
    #[serde(default)]
    pub reopened_at: Option<DateTime<Utc>>,
    pub acked_at: Option<DateTime<Utc>>,
    pub acked_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub last_notified_at: Option<DateTime<Utc>>,
    pub notify_count: i64,
    /// Index into the escalation chain's steps currently being notified
    /// (0-based). Together with `step_started_at`/`last_notified_at` this is
    /// the durable form of `incidents::escalation::EscalationState`, so the
    /// chain survives a daemon restart mid-escalation.
    pub escalation_step: i64,
    /// When the CURRENT escalation step was first notified (its `ack_timeout`
    /// clock). `None` until the chain's first notification.
    pub step_started_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    /// Approved and the stored command has been executed (verbatim — never a
    /// fresh LLM interpretation of the approval).
    Executed,
}

/// A gated mutation awaiting a human decision. Carries enough context to
/// decide from a phone (brief §5): command, target, risk, hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub incident: Option<Uuid>,
    pub requested_by: Principal,
    pub target: FqTarget,
    pub tool: String,
    /// The exact command that will run on approval, verbatim.
    pub command: String,
    pub risk: RiskClass,
    pub hypothesis: String,
    pub state: ApprovalState,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fq_target_roundtrip() {
        let t = FqTarget::parse("remundo::prod::cluster").unwrap();
        assert_eq!(t.to_string(), "remundo::prod::cluster");
        let r = FqTarget::parse("remundo::prod::cluster::elasticsearch::logs").unwrap();
        assert_eq!(r.resource, Some((ResourceType::Elasticsearch, "logs".into())));
        assert_eq!(r.to_string(), "remundo::prod::cluster::elasticsearch::logs");
        assert!(FqTarget::parse("just-a-name").is_err());
        assert!(FqTarget::parse("a::b::c::not_a_resource::x").is_err());
    }

    #[test]
    fn autonomy_is_strict() {
        assert_eq!("act_on_known".parse::<Autonomy>().unwrap(), Autonomy::ActOnKnown);
        assert!("full".parse::<Autonomy>().is_err()); // the old vocabulary must not parse
        assert!("readonly".parse::<Autonomy>().is_err());
    }

    #[test]
    fn risk_orders() {
        assert!(RiskClass::Read < RiskClass::Medium);
        assert!(RiskClass::High < RiskClass::Destructive);
    }
}
