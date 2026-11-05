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

/// A durable team conversation. `Operations` is the global coordination
/// room; an environment room is also the authorization boundary for tools.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ChatConversation {
    Operations,
    Environment {
        project: String,
        environment: String,
    },
    /// One incident's thread, inside its environment: `project::env#<id>`.
    /// Tools are scoped exactly as for the environment.
    Incident {
        project: String,
        environment: String,
        incident: uuid::Uuid,
    },
}

impl ChatConversation {
    pub const OPERATIONS_ID: &'static str = "operations";

    pub fn environment(project: impl Into<String>, environment: impl Into<String>) -> Self {
        Self::Environment { project: project.into(), environment: environment.into() }
    }

    pub fn id(&self) -> String {
        match self {
            Self::Operations => Self::OPERATIONS_ID.to_string(),
            Self::Environment { project, environment } => format!("{project}::{environment}"),
            Self::Incident { project, environment, incident } => {
                format!("{project}::{environment}#{incident}")
            }
        }
    }

    /// The thread for an incident on `target`.
    pub fn incident(target: &FqTarget, incident: uuid::Uuid) -> Self {
        Self::Incident {
            project: target.project.clone(),
            environment: target.env.clone(),
            incident,
        }
    }

    /// The environment a room or thread belongs to, if any.
    pub fn environment_of(&self) -> Option<(&str, &str)> {
        match self {
            Self::Operations => None,
            Self::Environment { project, environment }
            | Self::Incident { project, environment, .. } => Some((project, environment)),
        }
    }

    pub fn parse(value: &str) -> crate::Result<Self> {
        if value == Self::OPERATIONS_ID {
            return Ok(Self::Operations);
        }
        if let Some((env, id)) = value.split_once('#') {
            let incident = uuid::Uuid::parse_str(id).map_err(|_| {
                crate::Error::validation(format!("invalid chat conversation {value:?}"))
            })?;
            let Self::Environment { project, environment } = Self::parse(env)? else {
                return Err(crate::Error::validation(format!(
                    "invalid chat conversation {value:?}"
                )));
            };
            return Ok(Self::Incident { project, environment, incident });
        }
        let parts: Vec<_> = value.split("::").collect();
        match parts.as_slice() {
            [project, environment]
                if !project.is_empty()
                    && !environment.is_empty()
                    && !project.contains('/')
                    && !environment.contains('/') =>
            {
                Ok(Self::environment(*project, *environment))
            }
            _ => Err(crate::Error::validation(format!("invalid chat conversation {value:?}"))),
        }
    }

    pub fn contains(&self, target: &FqTarget) -> bool {
        match self {
            Self::Operations => false,
            Self::Environment { project, environment }
            | Self::Incident { project, environment, .. } => {
                target.project() == project && target.environment() == environment
            }
        }
    }
}

/// Fully-qualified target path: `project::env::target`, optionally extended
/// with `::resource_type::name`. This is the audit identity — the audit log
/// always records the fully qualified form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FqTarget {
    pub(crate) project: String,
    pub(crate) env: String,
    pub(crate) target: String,
    /// Present when addressing a target-owned resource (postgres, rabbitmq…).
    pub(crate) resource: Option<(ResourceType, String)>,
}

impl FqTarget {
    pub fn try_new(
        project: impl Into<String>,
        env: impl Into<String>,
        target: impl Into<String>,
    ) -> crate::Result<Self> {
        let candidate = FqTarget::new(project, env, target);
        FqTarget::parse(&candidate.to_string())
    }

    pub(crate) fn new(
        project: impl Into<String>,
        env: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        FqTarget { project: project.into(), env: env.into(), target: target.into(), resource: None }
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    pub fn environment(&self) -> &str {
        &self.env
    }

    pub fn target_name(&self) -> &str {
        &self.target
    }

    pub fn resource(&self) -> Option<(ResourceType, &str)> {
        self.resource.as_ref().map(|(kind, name)| (*kind, name.as_str()))
    }

    /// Parse `project::env::target` or `project::env::target::rtype::name`.
    pub fn parse(s: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = s.split("::").collect();
        if parts.iter().any(|part| part.trim().is_empty() || part.contains('/')) {
            return Err(crate::Error::Config(format!(
                "target path segments must be non-empty and contain no '/': {s}"
            )));
        }
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

/// Kubernetes authorization boundary represented by a target. Credentials
/// must enforce the same boundary; this value lets tools and executors fail
/// closed before asking the API server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "name")]
pub enum KubernetesScope {
    Namespace(String),
    Cluster,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Azure,
    // Provider-pluggable by design (example has a Scaleway plan on file).
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
    /// Grafana Tempo (traces).
    Tempo,
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
/// (example's sandbox cluster is normally stopped and wiped monthly).
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
    /// A person marked this a known, accepted fault ("known, leave it"). It
    /// stays open and acknowledged: re-detections attach to it, nothing is
    /// notified, and scans are told not to re-investigate it. Resolving it
    /// ends that; a fault that comes back after a resolve is new.
    #[serde(default)]
    pub accepted_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub accepted_by: Option<Uuid>,
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
        let t = FqTarget::parse("example::prod::cluster").unwrap();
        assert_eq!(t.to_string(), "example::prod::cluster");
        let r = FqTarget::parse("example::prod::cluster::elasticsearch::logs").unwrap();
        assert_eq!(r.resource, Some((ResourceType::Elasticsearch, "logs".into())));
        assert_eq!(r.to_string(), "example::prod::cluster::elasticsearch::logs");
        assert!(FqTarget::parse("just-a-name").is_err());
        assert!(FqTarget::parse("a::b::c::not_a_resource::x").is_err());
    }

    #[test]
    fn chat_conversation_roundtrip_and_target_scope() {
        let operations = ChatConversation::parse("operations").unwrap();
        assert_eq!(operations.id(), "operations");
        let production = ChatConversation::parse("example::prod").unwrap();
        assert_eq!(production.id(), "example::prod");
        assert!(production.contains(&FqTarget::parse("example::prod::api").unwrap()));
        assert!(!production.contains(&FqTarget::parse("example::dev::api").unwrap()));
        assert!(ChatConversation::parse("example::prod::api").is_err());
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
