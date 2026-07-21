//! The Tool trait and the v1 tool surface (brief §10, DESIGN.md §4 "Tool
//! surface"): everything the agent can do.
//!
//! Gianna lessons kept: capability metadata is SELF-DECLARED on each impl
//! (central name-lists caused silent gating bugs); the registry is rebuilt
//! per turn with context gating; argument schemas are hand-written JSON
//! Schema with prose aimed at steering the model.
//!
//! The safety invariant in types: `ToolCtx` carries a
//! `Arc<dyn crate::policy::PolicyExecute>` handle — never a `TargetExecutor`
//! — so a tool physically cannot execute an unaudited remote command.
//!
//! ## Module layout — the three-way division by what BACKS the tool
//!
//! - [`executor`] — shared plumbing for command-composing tools: builds a
//!   `policy::CommandRequest` and turns a `PolicyOutcome` into a
//!   `ToolResult`/`ToolError`. [`ssh`], [`shell`], [`monitor`], [`systemd`],
//!   [`docker`], and [`kubernetes`] all compose a concrete command line
//!   through this — they own VOCABULARY, never transport; the only path to
//!   an executor is `ctx.policy.execute`.
//! - Daemon-local, no remote side effect: [`notify`] (the one structured
//!   escalation tool), [`config_tool`] (read-only, secret-free inventory),
//!   [`memory_tools`] (store/recall/forget), [`incidents_tool`] (incident
//!   queries), [`runbooks_tool`] (runbook RUN HISTORY queries — see that
//!   module's doc for the gap: there is no runbook-definition store yet).
//! - [`endpoint`] — shared plumbing for endpoint-backed tools: an already-
//!   RESOLVED [`endpoint::EndpointAuth`] (base URL + optional bearer token)
//!   per resource, and [`endpoint::get_json`]/[`endpoint::post_json`]
//!   helpers with the same error-splitting discipline as [`executor`]. See
//!   that module's doc for the credential-wiring gap (config already
//!   declares resources; nothing yet resolves a `SecretRef` into a
//!   `ToolCtx.endpoints` registry). [`elasticsearch`], [`azure_service_bus`],
//!   [`eventstore`], [`prometheus`] are pure reads through it;
//!   [`argocd`]'s reads go the same way, but `rollback` is a MUTATION that
//!   composes a synthetic command line through [`executor::run_command`]
//!   exactly like an ssh/kubernetes tool — a rollback over HTTP is as
//!   classified, gated, and audited as a remote command (DESIGN.md §4).
//!
//! [`registry`] applies DESIGN.md §4's context-gating: read-only tools
//! register whenever their config section exists; mutating tools register
//! only when a matching target/resource is configured; heartbeat runs get
//! the `allowed_in_heartbeat` subset.

pub mod argocd;
pub mod azure_service_bus;
pub mod config_tool;
pub mod docker;
pub mod elasticsearch;
pub mod endpoint;
pub mod eventstore;
pub mod executor;
pub mod incidents_tool;
pub mod kubernetes;
pub mod memory_tools;
pub mod monitor;
pub mod notify;
pub mod prometheus;
pub mod runbooks_tool;
pub mod shell;
pub mod ssh;
pub mod systemd;

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::config::Config;
use crate::db::{ApprovalRepo, IncidentRepo, RunbookRunRepo};
use crate::domain::{FqTarget, Principal, ResourceType, RiskClass};
use crate::memory::Memory;
use crate::policy::PolicyExecute;
use crate::tools::endpoint::EndpointRegistry;

/// Per-turn tool context — everything a `Tool::call` may reach, and no more.
/// Constructed only by the agent dispatch layer, once per turn.
///
/// `policy` is `Arc<dyn PolicyExecute>`, not `Arc<Policy>` — a contract
/// change from the frozen sketch, made so tests can inject a recording fake
/// instead of the real (fail-closed stub) engine. See the doc comment on
/// `policy::PolicyExecute` for the full rationale. The safety invariant is
/// unchanged: this is still the ONLY handle a tool can reach, and its only
/// method is "classify, gate, audit, maybe execute" — there is no way to get
/// a `TargetExecutor` out of `ToolCtx`.
///
/// `known_targets` is the trusted allow-list for THIS turn: the set of
/// `project::env::target` paths the dispatcher has already resolved from
/// config and authorized for the current context. A command-composing tool
/// takes a target as a plain string ARGUMENT from the model (it has to — one
/// turn can address several different targets), but must resolve that
/// string by LOOKING IT UP here (`ToolCtx::resolve_target`), never by
/// constructing an `FqTarget` straight from the model's text
/// (`FqTarget::parse` is never called on model-supplied input in this
/// module) — mirrors how `CommandRequest.principal`/`.target` are trusted
/// positional context built by the caller, never taken from model output
/// (DESIGN.md §4 "Targets & executors").
#[derive(Clone)]
pub struct ToolCtx {
    pub principal: Principal,
    pub policy: Arc<dyn PolicyExecute>,
    pub known_targets: Vec<FqTarget>,
    pub incidents: Option<Arc<dyn IncidentRepo>>,
    pub approvals: Option<Arc<dyn ApprovalRepo>>,
    pub runbook_runs: Option<Arc<dyn RunbookRunRepo>>,
    pub memory: Option<Arc<Memory>>,
    pub config: Option<Arc<Config>>,
    /// Resolved endpoint credentials for configured `Resource`s
    /// (elasticsearch/azure_service_bus/eventstore/prometheus/argocd — see
    /// `endpoint`'s module doc for the wiring gap: this is `None` until a
    /// later wave resolves `ResourceCfg.credential` and populates it).
    pub endpoints: Option<Arc<EndpointRegistry>>,
}

impl ToolCtx {
    /// Resolve a model-supplied target STRING (`project::env::target`, the
    /// `FqTarget::Display` form) against the trusted allow-list — never
    /// parses/constructs a fresh `FqTarget` from it. Returns a user-facing
    /// error naming the valid choices when the string doesn't match one of
    /// them, so the model can self-correct instead of the tool silently
    /// picking something.
    pub fn resolve_target(&self, s: &str) -> std::result::Result<FqTarget, ToolError> {
        self.known_targets.iter().find(|t| t.to_string() == s).cloned().ok_or_else(|| {
            let valid: Vec<String> = self.known_targets.iter().map(|t| t.to_string()).collect();
            ToolError::UserFacing(format!(
                "unknown target {s:?}. Valid targets: {}.",
                if valid.is_empty() { "(none configured)".to_string() } else { valid.join(", ") }
            ))
        })
    }

    /// Resolve a model-supplied RESOURCE string (the resource-qualified
    /// `FqTarget::Display` form, `project::env::target::resource_type::name`)
    /// against `endpoints`, returning the target plus its resolved auth.
    /// Same closed-world discipline as `resolve_target`: the model can only
    /// ever pick a resource this context was told about.
    pub fn resolve_resource(
        &self,
        s: &str,
    ) -> std::result::Result<(FqTarget, &endpoint::EndpointAuth), ToolError> {
        let target = self.resolve_target(s)?;
        let endpoints = self.endpoints.as_ref().ok_or_else(|| {
            ToolError::Internal("called with no endpoint credentials wired".to_string())
        })?;
        let auth = endpoints.get(&target).ok_or_else(|| {
            ToolError::UserFacing(format!("no resolved credentials for resource {s:?}"))
        })?;
        Ok((target, auth))
    }
}

/// Result of a successful tool call, fed back into the model loop.
#[derive(Debug, Clone, Default)]
pub struct ToolResult {
    pub output: String,
}

/// Tool errors split user-facing (relayed to the model with detail) from
/// internal faults (scrubbed + "do NOT retry" so the model doesn't burn steps
/// hammering a dead backend) — gianna's error-splitting, kept verbatim.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("{0}")]
    UserFacing(String),
    #[error("internal fault: {0}")]
    Internal(String),
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    /// Prose for the model: what it does, when to use it, what not to do.
    fn description(&self) -> &str;
    /// Hand-written JSON Schema for the arguments.
    fn schema(&self) -> Value;
    /// Coarse self-declared risk; the policy classifier may RAISE (never
    /// lower) it per concrete command.
    fn risk(&self) -> RiskClass;
    /// True for tools with side effects. Mutating tools register only when a
    /// matching target/resource is configured.
    fn is_action(&self) -> bool;
    /// Deny-by-default subset for background heartbeat runs.
    fn allowed_in_heartbeat(&self) -> bool;

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError>;
}

/// The per-turn registry (DESIGN.md §4 "Tool surface", registration rules):
/// read-only tools register whenever their config section exists (here: the
/// daemon-local tools, always-on since they depend on repos/memory passed in
/// `ToolCtx` rather than config); MUTATING (command-composing) tools
/// register only when at least one matching target is configured — a `ssh`
/// tool with zero ssh targets can compose nothing, so it doesn't appear;
/// heartbeat runs additionally filter to `allowed_in_heartbeat`.
///
/// Which targets exist comes from `ctx.known_targets` (already resolved by
/// the dispatcher — see `ToolCtx`'s doc), keyed by `TargetKind` via
/// `ctx.config`; `docker`/`systemd`/`monitor` are vocabulary that runs over
/// ssh/local targets (any non-cloud, non-kubernetes target), not a distinct
/// target kind of their own, so they gate on "at least one ssh or local
/// target exists" rather than needing their own config section.
pub fn registry(ctx: &ToolCtx, heartbeat: bool) -> Vec<Box<dyn Tool>> {
    let mut tools: Vec<Box<dyn Tool>> = Vec::new();

    // --- Daemon-local: always register (no target/resource dependency). ---
    tools.push(Box::new(notify::NotifyTool));
    if ctx.config.is_some() {
        tools.push(Box::new(config_tool::ConfigTool));
    }
    if let Some(memory) = &ctx.memory {
        tools.push(Box::new(memory_tools::RecallMemoryTool { memory: memory.clone() }));
        tools.push(Box::new(memory_tools::StoreMemoryTool { memory: memory.clone() }));
        tools.push(Box::new(memory_tools::ForgetMemoryTool { memory: memory.clone() }));
    }
    if ctx.incidents.is_some() {
        tools.push(Box::new(incidents_tool::ListIncidentsTool));
    }
    if ctx.runbook_runs.is_some() {
        tools.push(Box::new(runbooks_tool::RunbookHistoryTool));
    }

    // --- Executor-backed: register only when a usable target exists. ---
    let has_ssh_or_local = ctx.known_targets.iter().any(|t| {
        ctx.config.as_ref().is_some_and(|c| target_kind_of(c, t).is_some_and(is_ssh_or_local))
    });
    let has_kubernetes = ctx.known_targets.iter().any(|t| {
        ctx.config.as_ref().is_some_and(|c| target_kind_of(c, t) == Some(RegistryTargetClass::Kubernetes))
    });

    if has_ssh_or_local {
        tools.push(Box::new(ssh::SshTool));
        tools.push(Box::new(shell::ShellTool));
        tools.push(Box::new(monitor::MonitorTool));
        tools.push(Box::new(systemd::SystemdTool));
        tools.push(Box::new(docker::DockerTool));
    }
    if has_kubernetes {
        tools.push(Box::new(kubernetes::KubernetesTool));
    }

    // --- Endpoint-backed: register per-resource-type, only when at least
    // one target's resource of that type has resolved credentials. ---
    if let Some(endpoints) = &ctx.endpoints {
        let has_resource = |rt: ResourceType| {
            ctx.known_targets
                .iter()
                .any(|t| t.resource.as_ref().is_some_and(|(r, _)| *r == rt) && endpoints.get(t).is_some())
        };
        if has_resource(ResourceType::Elasticsearch) {
            tools.push(Box::new(elasticsearch::ElasticsearchSearchTool));
            tools.push(Box::new(elasticsearch::ElasticsearchIndexStatsTool));
            tools.push(Box::new(elasticsearch::ElasticsearchClusterHealthTool));
        }
        if has_resource(ResourceType::AzureServiceBus) {
            tools.push(Box::new(azure_service_bus::QueueDepthTool));
            tools.push(Box::new(azure_service_bus::PeekMessagesTool));
        }
        if has_resource(ResourceType::Eventstore) {
            tools.push(Box::new(eventstore::ReadStreamTool));
            tools.push(Box::new(eventstore::ProjectionStatusTool));
        }
        if has_resource(ResourceType::Prometheus) {
            tools.push(Box::new(prometheus::InstantQueryTool));
            tools.push(Box::new(prometheus::RangeQueryTool));
        }
        if has_resource(ResourceType::Argocd) {
            tools.push(Box::new(argocd::ListAppsTool));
            tools.push(Box::new(argocd::SyncStatusTool));
            tools.push(Box::new(argocd::RollbackTool));
        }
    }

    if heartbeat {
        tools.retain(|t| t.allowed_in_heartbeat());
    }
    tools
}

/// Coarse target-kind classification used only for registry gating (not the
/// full `domain::TargetKind`, which carries cloud provider/region — gating
/// only needs to distinguish "reachable by ssh/local vocabulary" from
/// "kubernetes" from "cloud" from "config says nothing" defensively).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryTargetClass {
    SshOrLocal,
    Kubernetes,
    Cloud,
}

fn is_ssh_or_local(k: RegistryTargetClass) -> bool {
    k == RegistryTargetClass::SshOrLocal
}

/// Look up an `FqTarget`'s configured kind by walking `Config`'s
/// project/env/target tree. `None` if the target isn't found in config at
/// all — defensive; `known_targets` should already be config-derived, so
/// this is a belt-and-braces path, not the expected case.
fn target_kind_of(config: &Config, target: &FqTarget) -> Option<RegistryTargetClass> {
    use crate::config::TargetKindName;
    let project = config.projects.iter().find(|p| p.name == target.project)?;
    let env = project.envs.iter().find(|e| e.name == target.env)?;
    let t = env.targets.iter().find(|t| t.name == target.target)?;
    Some(match t.kind {
        TargetKindName::Ssh | TargetKindName::Local => RegistryTargetClass::SshOrLocal,
        TargetKindName::Kubernetes => RegistryTargetClass::Kubernetes,
        TargetKindName::Cloud => RegistryTargetClass::Cloud,
    })
}

/// Find a registered tool by name — the dispatch loop's lookup (kept here,
/// not duplicated per-caller) since more than one caller (the agent loop,
/// tests) needs "does a tool with this name exist in the registry".
pub fn find<'a>(registry: &'a [Box<dyn Tool>], name: &str) -> Option<&'a dyn Tool> {
    registry.iter().find(|t| t.name() == name).map(|t| t.as_ref())
}
