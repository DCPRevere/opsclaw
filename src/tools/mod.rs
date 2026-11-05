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
//!   [`docker`], [`firewall`], and [`kubernetes`] all compose a concrete
//!   command line through this — they own VOCABULARY, never transport; the
//!   only path to an executor is `ctx.policy.execute`. [`dns`] and [`cert`]
//!   compose through it too, with an OPTIONAL target (DESIGN.md §4:
//!   "resolve/check from a target's vantage or the daemon's" —
//!   `ToolCtx::resolve_vantage`).
//! - Daemon-local, no remote side effect: [`notify`] (the one structured
//!   escalation tool), [`config_tool`] (read-only, secret-free inventory),
//!   [`memory_tools`] (store/recall/forget), [`incidents_tool`] (incident
//!   queries), [`runbooks_tool`] (`runbook_list` over
//!   `crate::runbooks::RunbookStore` — the definition store — and
//!   `runbook_history` over `db::RunbookRunRepo` — execution history;
//!   discover-then-inspect), [`files`] (workspace-bounded
//!   `file_read`/`file_write`), [`web_fetch`] (public-URL GET with an SSRF
//!   guard; web SEARCH is deliberately deferred — see that module's doc).
//! - [`endpoint`] — shared plumbing for endpoint-backed tools:
//!   [`endpoint::get_json`]/[`endpoint::query_json`] compose canonical
//!   `endpoint-get`/`endpoint-query` READ lines and submit them through
//!   `ctx.policy` — endpoint reads pass the SAME choke point as ssh
//!   commands (e-stop, audit-begin/end, response scrubbing), landing on
//!   `targets::endpoint::EndpointExecutor`. [`elasticsearch`],
//!   [`azure_service_bus`], [`eventstore`], [`prometheus`] are pure reads
//!   through it; [`argocd`]'s reads go the same way, and its `rollback`
//!   MUTATION composes its own vocabulary line through
//!   [`executor::run_command`] — a rollback over HTTP is as classified,
//!   gated, and audited as a remote command (DESIGN.md §4).
//!
//! [`registry`] applies DESIGN.md §4's context-gating: read-only tools
//! register whenever their config section exists; mutating tools register
//! only when a matching target/resource is configured; heartbeat runs get
//! the `allowed_in_heartbeat` subset.

pub mod argocd;
pub mod azure_service_bus;
pub mod cert;
pub mod config_tool;
pub mod dns;
pub mod docker;
pub mod elasticsearch;
pub mod endpoint;
pub mod eventstore;
pub mod executor;
pub mod files;
pub mod firewall;
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
pub mod tempo;
pub mod web_fetch;

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
    /// The surface this turn came through and where its reads record
    /// labels (`crate::access`). Default: internal, no labels.
    pub call: CallAccess,
    pub policy: Arc<dyn PolicyExecute>,
    pub known_targets: Vec<FqTarget>,
    pub incidents: Option<Arc<dyn IncidentRepo>>,
    pub approvals: Option<Arc<dyn ApprovalRepo>>,
    pub runbook_runs: Option<Arc<dyn RunbookRunRepo>>,
    pub memory: Option<Arc<Memory>>,
    pub config: Option<Arc<Config>>,
    /// Resolved endpoint credentials for configured `Resource`s
    /// (elasticsearch/azure_service_bus/eventstore/prometheus/argocd),
    /// built by `tools::endpoint::registry_from_config` at boot. Used for
    /// resource-target validation and the known-address error listing —
    /// the actual HTTP transport for reads lives behind the policy choke
    /// point (`endpoint`'s module doc). `None` only in contexts that
    /// weren't given one (some tests).
    pub endpoints: Option<Arc<EndpointRegistry>>,
    /// The runbook DEFINITION store (title -> parsed `Runbook`, loaded from
    /// `config.daemon.runbooks_dir`) — distinct from `runbook_runs`, which
    /// is EXECUTION history. Wired by the daemon boot path once
    /// `RunbookStore::load` has run; `None` in a context that hasn't been
    /// given one (e.g. today's tests, or a caller that only needs history).
    pub runbooks: Option<Arc<crate::runbooks::RunbookStore>>,
}

/// Per-turn access context threaded into every `CommandRequest`.
#[derive(Clone, Default)]
pub struct CallAccess {
    pub via: crate::access::Via,
    pub labels: Option<crate::access::Labels>,
    /// Where tools that create findings (incidents) store the turn's
    /// labels on them.
    pub repo: Option<Arc<dyn crate::db::AccessRepo>>,
    /// The access engine, for tools that show findings to the asker.
    pub engine: Option<Arc<crate::access::Access>>,
}

impl std::fmt::Debug for CallAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallAccess")
            .field("via", &self.via)
            .field("labels", &self.labels)
            .field("repo", &self.repo.is_some())
            .field("engine", &self.engine.is_some())
            .finish()
    }
}

impl ToolCtx {
    /// A minimal, all-fakes `ToolCtx` for tests: `principal` and `policy`
    /// are the only two fields that can't have a sensible universal default
    /// (there is no meaningful "default" `Principal`, and every `policy`
    /// fake makes a different behavioural choice a test cares about), so
    /// callers supply those two and get every optional field defaulted to
    /// its honest off state (`None`/empty) — the same "everything is a fake
    /// by default" posture as `db::Db::fake()`. NOT `cfg(test)`-gated
    /// (mirrors `Db::fake`) so it's usable from doctests, other crates'
    /// integration tests, and this crate's binaries without a feature dance.
    ///
    /// Existing per-file `ToolCtx { ... }` test fixtures across `tools::`
    /// predate this constructor and weren't retrofitted (churn with no
    /// behavioural upside) — new test code should prefer this over a bare
    /// struct literal, since a struct literal breaks at every future
    /// additive `ToolCtx` field (this constructor is the fix for exactly
    /// the repeated `agent/mod.rs` fixture breakage from the last two
    /// waves).
    pub fn for_tests(principal: Principal, policy: Arc<dyn PolicyExecute>) -> Self {
        ToolCtx {
            call: Default::default(),
            principal,
            policy,
            known_targets: Vec::new(),
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        }
    }

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

    /// Resolve a target and require a compatible connection kind. The policy
    /// layer repeats this check as the final authority; doing it here gives
    /// the model a useful correction instead of a generic policy failure.
    pub fn resolve_target_for(
        &self,
        s: &str,
        tool: &str,
        allowed: &[crate::config::TargetKindName],
    ) -> std::result::Result<FqTarget, ToolError> {
        let target = self.resolve_target(s)?;
        if let Some(config) = &self.config {
            let actual = config.target_config(&target).map(|configured| configured.kind);
            if !actual.is_some_and(|kind| allowed.contains(&kind)) {
                return Err(ToolError::UserFacing(format!(
                    "{tool} cannot run against target {target} ({actual:?}); choose a compatible target"
                )));
            }
        }
        Ok(target)
    }

    /// Resolve the optional VANTAGE argument shared by `dns` and `cert`
    /// (DESIGN.md §4: they "accept an optional target (resolve/check from a
    /// target's vantage or the daemon's)"): an explicit target string goes
    /// through [`ToolCtx::resolve_target`] as usual; absent, fall back to
    /// the configured `local`-kind target — the daemon's own host. Zero or
    /// several local candidates is a user-facing error naming the fix (pass
    /// `target`), never a silent guess between hosts — the same closed-world
    /// discipline as `resolve_target`.
    pub fn resolve_vantage(&self, s: Option<&str>) -> std::result::Result<FqTarget, ToolError> {
        if let Some(s) = s {
            return self.resolve_target_for(
                s,
                "vantage tool",
                &[crate::config::TargetKindName::Ssh, crate::config::TargetKindName::Local],
            );
        }
        let locals: Vec<&FqTarget> = self
            .known_targets
            .iter()
            .filter(|t| t.resource.is_none())
            .filter(|t| {
                self.config.as_ref().is_some_and(|c| {
                    configured_kind(c, t) == Some(crate::config::TargetKindName::Local)
                })
            })
            .collect();
        match locals.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(ToolError::UserFacing(
                "no \"target\" given and no local-kind target is configured to act as the \
                 daemon's own vantage — pass \"target\" to name where to run from."
                    .to_string(),
            )),
            many => Err(ToolError::UserFacing(format!(
                "no \"target\" given and more than one local target is configured ({}) — pass \
                 \"target\" to pick the vantage.",
                many.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(", ")
            ))),
        }
    }

    /// Resolve a model-supplied RESOURCE string (the resource-qualified
    /// `FqTarget::Display` form, `project::env::target::resource_type::name`)
    /// against `endpoints`, returning the target plus its resolved auth.
    /// Same closed-world discipline as `resolve_target`: the model can only
    /// ever pick a resource this context was told about.
    pub fn resolve_resource(&self, s: &str) -> std::result::Result<FqTarget, ToolError> {
        let target = self.resolve_target(s)?;
        let endpoints = self.endpoints.as_ref().ok_or_else(|| {
            ToolError::Internal("called with no endpoint credentials wired".to_string())
        })?;
        if endpoints.get(&target).is_none() {
            // Name the valid choices — a model given only "no credentials"
            // burns tool-loop steps guessing address forms (observed live:
            // `cluster`, `cluster:logs`, … before the right one). The
            // resource-qualified form is not guessable from the base path.
            return Err(ToolError::UserFacing(format!(
                "no resolved credentials for resource {s:?} — resource-qualified targets with \
                 credentials: {}",
                endpoints.known_targets().join(", ")
            )));
        }
        Ok(target)
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

    /// True when THIS call (these arguments) only reads. Read-only calls in
    /// one model batch run concurrently, and don't count as the turn having
    /// acted. Tools mixing read and write verbs (kubernetes, docker,
    /// systemd) override this per action; when in doubt, return false: the
    /// call then runs alone, in order.
    fn reads_only(&self, _args: &Value) -> bool {
        !self.is_action()
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError>;
}

/// OpsClaw's `dcpr-agent` runtime: tools run against a [`ToolCtx`] and fail
/// with a [`ToolError`].
pub struct Ops;

impl dcpr_agent::Runtime for Ops {
    type Context = ToolCtx;
    type Error = ToolError;
    type Extra = ();
}

/// dcpr-agent's default argument check: coerce scalar spellings to the
/// schema's types, then refuse anything it doesn't allow.
fn prepare_args(mut args: Value, schema: &Value) -> Result<Value, dcpr_agent::ToolInputError> {
    if !args.is_object() {
        return Err(dcpr_agent::ToolInputError::new("expected a JSON object"));
    }
    dcpr_agent::coerce_args_to_schema(&mut args, schema);
    dcpr_agent::validate_args_against_schema(&args, schema, "arguments")?;
    Ok(args)
}

/// Every OpsClaw tool is a `dcpr-agent` tool: argument checking against its
/// schema, shared (concurrent) execution of reads, and MCP exposure come
/// from the library. Risk and heartbeat eligibility stay on [`Tool`]: they
/// are OpsClaw policy, not tool-loop mechanics.
#[async_trait]
impl dcpr_agent::Tool<Ops> for Box<dyn Tool> {
    fn name(&self) -> &str {
        Tool::name(self.as_ref())
    }

    fn description(&self) -> &str {
        Tool::description(self.as_ref())
    }

    fn parameters(&self) -> Value {
        Tool::schema(self.as_ref())
    }

    /// dcpr-agent's check, except that a top-level property declared as a
    /// bare `{"type": "object"}` (no `properties`) is free-form, such as
    /// an Elasticsearch Query DSL body. dcpr-agent 0.3.0 treats every object
    /// as closed, which refused every real query. Free-form values are
    /// checked to be objects and otherwise passed through untouched.
    fn prepare_arguments(&self, args: Value) -> Result<Value, dcpr_agent::ToolInputError> {
        let schema = Tool::schema(self.as_ref());
        let free_form: Vec<String> = schema["properties"]
            .as_object()
            .map(|props| {
                props
                    .iter()
                    .filter(|(_, p)| p["type"] == "object" && p.get("properties").is_none())
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default();
        if free_form.is_empty() {
            return prepare_args(args, &schema);
        }
        let Value::Object(mut map) = args else {
            return Err(dcpr_agent::ToolInputError::new("expected a JSON object"));
        };
        let mut held = serde_json::Map::new();
        let mut checked_schema = schema.clone();
        for key in &free_form {
            if let Some(value) = map.remove(key) {
                if !value.is_object() {
                    return Err(dcpr_agent::ToolInputError::new(format!(
                        "arguments.{key} must be an object"
                    )));
                }
                held.insert(key.clone(), value);
            }
            if let Some(props) = checked_schema["properties"].as_object_mut() {
                props.remove(key);
            }
            if let Some(required) = checked_schema["required"].as_array_mut() {
                required.retain(|r| r.as_str() != Some(key.as_str()));
            }
        }
        // A required free-form field still has to be there.
        for required in schema["required"].as_array().into_iter().flatten() {
            if let Some(key) = required.as_str()
                && free_form.iter().any(|f| f == key)
                && !held.contains_key(key)
            {
                return Err(dcpr_agent::ToolInputError::new(format!(
                    "arguments.{key} is required"
                )));
            }
        }
        let Value::Object(mut prepared) = prepare_args(Value::Object(map), &checked_schema)? else {
            return Err(dcpr_agent::ToolInputError::new("expected a JSON object"));
        };
        prepared.extend(held);
        Ok(Value::Object(prepared))
    }

    fn concurrency(&self) -> dcpr_agent::ToolConcurrency {
        if Tool::is_action(self.as_ref()) {
            dcpr_agent::ToolConcurrency::Exclusive
        } else {
            dcpr_agent::ToolConcurrency::Shared
        }
    }

    fn is_action(&self) -> bool {
        Tool::is_action(self.as_ref())
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<dcpr_agent::ToolResult, ToolError> {
        let read = Tool::reads_only(self.as_ref(), &args);
        let result = Tool::call(self.as_ref(), ctx, args).await?;
        Ok(if read {
            dcpr_agent::ToolResult::observed(result.output)
        } else {
            dcpr_agent::ToolResult::text(result.output)
        })
    }
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
/// `ctx.config`; `docker`/`systemd`/`monitor`/`dns`/`cert`/`firewall` are
/// vocabulary that runs over ssh/local targets (any non-cloud,
/// non-kubernetes target), not a distinct target kind of their own, so they
/// gate on "at least one ssh or local target exists" rather than needing
/// their own config section.
pub fn registry(ctx: &ToolCtx, heartbeat: bool) -> Vec<Box<dyn Tool>> {
    let mut tools: Vec<Box<dyn Tool>> = Vec::new();

    // --- Daemon-local: always register (no target/resource dependency). ---
    tools.push(Box::new(notify::NotifyTool));
    tools.push(Box::new(web_fetch::WebFetchTool));
    if ctx.config.is_some() {
        tools.push(Box::new(config_tool::ConfigTool));
        // The file tools resolve their workspace root from config
        // (`daemon.workspace_dir`), so they gate on config the same way
        // `opsclaw_config` does — daemon-local, but not context-free.
        tools.push(Box::new(files::FileReadTool));
        tools.push(Box::new(files::FileWriteTool));
    }
    if let Some(memory) = &ctx.memory {
        tools.push(Box::new(memory_tools::RecallMemoryTool { memory: memory.clone() }));
        tools.push(Box::new(memory_tools::StoreMemoryTool { memory: memory.clone() }));
        tools.push(Box::new(memory_tools::ForgetMemoryTool { memory: memory.clone() }));
    }
    if ctx.incidents.is_some() {
        tools.push(Box::new(incidents_tool::ListIncidentsTool));
    }
    if ctx.runbooks.is_some() {
        tools.push(Box::new(runbooks_tool::RunbookListTool));
    }
    if ctx.runbook_runs.is_some() {
        tools.push(Box::new(runbooks_tool::RunbookHistoryTool));
    }

    // --- Executor-backed: register only when a usable target exists. ---
    let has_ssh = ctx.known_targets.iter().any(|t| {
        ctx.config
            .as_ref()
            .is_some_and(|c| configured_kind(c, t) == Some(crate::config::TargetKindName::Ssh))
    });
    let has_local = ctx.known_targets.iter().any(|t| {
        ctx.config
            .as_ref()
            .is_some_and(|c| configured_kind(c, t) == Some(crate::config::TargetKindName::Local))
    });
    let has_kubernetes = ctx.known_targets.iter().any(|t| {
        ctx.config
            .as_ref()
            .is_some_and(|c| target_kind_of(c, t) == Some(RegistryTargetClass::Kubernetes))
    });

    if has_ssh {
        tools.push(Box::new(ssh::SshTool));
    }
    if has_local {
        tools.push(Box::new(shell::ShellTool));
    }
    if has_ssh || has_local {
        tools.push(Box::new(monitor::MonitorTool));
        tools.push(Box::new(systemd::SystemdTool));
        tools.push(Box::new(docker::DockerTool));
        tools.push(Box::new(dns::DnsTool));
        tools.push(Box::new(cert::CertTool));
        tools.push(Box::new(firewall::FirewallTool));
    }
    if has_kubernetes {
        tools.push(Box::new(kubernetes::KubernetesTool));
    }

    // --- Endpoint-backed: register per-resource-type, only when at least
    // one target's resource of that type has resolved credentials. ---
    if let Some(endpoints) = &ctx.endpoints {
        let has_resource = |rt: ResourceType| {
            ctx.known_targets.iter().any(|t| {
                t.resource.as_ref().is_some_and(|(r, _)| *r == rt) && endpoints.get(t).is_some()
            })
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
        if has_resource(ResourceType::Tempo) {
            tools.push(Box::new(tempo::SearchTool));
            tools.push(Box::new(tempo::TraceTool));
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

/// Look up an `FqTarget`'s configured kind by walking `Config`'s
/// project/env/target tree. `None` if the target isn't found in config at
/// all — defensive; `known_targets` should already be config-derived, so
/// this is a belt-and-braces path, not the expected case.
fn target_kind_of(config: &Config, target: &FqTarget) -> Option<RegistryTargetClass> {
    use crate::config::TargetKindName;
    Some(match configured_kind(config, target)? {
        TargetKindName::Ssh | TargetKindName::Local => RegistryTargetClass::SshOrLocal,
        TargetKindName::Kubernetes => RegistryTargetClass::Kubernetes,
        TargetKindName::Cloud => RegistryTargetClass::Cloud,
    })
}

/// The raw configured kind name for an `FqTarget` — the shared tree walk
/// behind [`target_kind_of`]'s coarse gating classes, exposed separately
/// because [`ToolCtx::resolve_vantage`] needs specifically `Local` (the
/// daemon's own host), which the coarse `SshOrLocal` class erases.
fn configured_kind(config: &Config, target: &FqTarget) -> Option<crate::config::TargetKindName> {
    config.target_config(target).map(|configured| configured.kind)
}

/// Find a registered tool by name — the dispatch loop's lookup (kept here,
/// not duplicated per-caller) since more than one caller (the agent loop,
/// tests) needs "does a tool with this name exist in the registry".
pub fn find<'a>(registry: &'a [Box<dyn Tool>], name: &str) -> Option<&'a dyn Tool> {
    registry.iter().find(|t| t.name() == name).map(|t| t.as_ref())
}

/// Test-support: a `ToolCtx` whose reads run through the PRODUCTION wiring
/// in miniature — a real `Policy` (disengaged e-stop, fresh scrubber,
/// in-memory audit) driving a real `targets::endpoint::EndpointExecutor` at
/// `base_url`. Endpoint tool tests use this so they prove their reads
/// survive the choke point, not just that their HTTP paths are right.
/// Returns the ctx plus the e-stop sentinel dir (dropping it deletes the
/// sentinel path — hold it for the test's lifetime).
#[cfg(test)]
pub(crate) fn endpoint_test_ctx(
    target: crate::domain::FqTarget,
    base_url: &str,
    token: Option<&str>,
) -> (ToolCtx, tempfile::TempDir) {
    use std::sync::Arc;
    let (kind, _) =
        target.resource.clone().expect("endpoint_test_ctx needs a resource-qualified target");
    let db = Arc::new(crate::db::memory::InMemoryDb::new());
    let dir = tempfile::tempdir().unwrap();
    let estop = Arc::new(crate::policy::EStop::new(dir.path().join("estop"), db.clone()));
    let auth = endpoint::EndpointAuth::new(base_url, token.map(str::to_string));
    let mut executors: std::collections::HashMap<String, Arc<dyn crate::targets::TargetExecutor>> =
        std::collections::HashMap::new();
    executors.insert(
        target.to_string(),
        Arc::new(crate::targets::endpoint::EndpointExecutor::new(kind, auth.clone())),
    );
    let policy = Arc::new(crate::policy::Policy::new(
        Arc::new(crate::config::Config::default()),
        executors,
        Arc::new(crate::audit::AuditWriter::new(db.clone())),
        estop,
        db.clone(),
        Arc::new(crate::policy::Scrubber::new()),
    ));
    let mut reg = endpoint::EndpointRegistry::new();
    reg.insert(&target, auth);
    let ctx = ToolCtx {
        call: Default::default(),
        principal: crate::domain::Principal::Agent { job: None },
        policy,
        known_targets: vec![target],
        incidents: None,
        approvals: None,
        runbook_runs: None,
        memory: None,
        config: None,
        endpoints: Some(Arc::new(reg)),
        runbooks: None,
    };
    (ctx, dir)
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    /// Every tool OpsClaw ships, whatever config would register.
    fn every_tool() -> Vec<Box<dyn Tool>> {
        let memory = Arc::new(Memory::disabled());
        vec![
            Box::new(notify::NotifyTool),
            Box::new(web_fetch::WebFetchTool),
            Box::new(config_tool::ConfigTool),
            Box::new(files::FileReadTool),
            Box::new(files::FileWriteTool),
            Box::new(memory_tools::RecallMemoryTool { memory: memory.clone() }),
            Box::new(memory_tools::StoreMemoryTool { memory: memory.clone() }),
            Box::new(memory_tools::ForgetMemoryTool { memory }),
            Box::new(incidents_tool::ListIncidentsTool),
            Box::new(runbooks_tool::RunbookListTool),
            Box::new(runbooks_tool::RunbookHistoryTool),
            Box::new(ssh::SshTool),
            Box::new(shell::ShellTool),
            Box::new(monitor::MonitorTool),
            Box::new(systemd::SystemdTool),
            Box::new(docker::DockerTool),
            Box::new(dns::DnsTool),
            Box::new(cert::CertTool),
            Box::new(firewall::FirewallTool),
            Box::new(kubernetes::KubernetesTool),
            Box::new(elasticsearch::ElasticsearchSearchTool),
            Box::new(elasticsearch::ElasticsearchIndexStatsTool),
            Box::new(elasticsearch::ElasticsearchClusterHealthTool),
            Box::new(azure_service_bus::QueueDepthTool),
            Box::new(azure_service_bus::PeekMessagesTool),
            Box::new(eventstore::ReadStreamTool),
            Box::new(eventstore::ProjectionStatusTool),
            Box::new(prometheus::InstantQueryTool),
            Box::new(prometheus::RangeQueryTool),
            Box::new(argocd::ListAppsTool),
            Box::new(argocd::SyncStatusTool),
            Box::new(argocd::RollbackTool),
        ]
    }

    /// The agent loop rejects any argument a schema doesn't declare, so a
    /// schema without `properties` would make its tool uncallable.
    #[test]
    fn every_schema_declares_its_arguments() {
        for tool in every_tool() {
            let schema = tool.schema();
            let name = tool.name();
            assert_eq!(schema["type"], "object", "{name}");
            let props = schema["properties"].as_object().unwrap_or_else(|| {
                panic!("{name}: no properties, so every argument would be rejected")
            });
            for required in schema["required"].as_array().into_iter().flatten() {
                let required = required.as_str().unwrap();
                assert!(
                    props.contains_key(required),
                    "{name}: required {required:?} is undeclared"
                );
            }
        }
    }

    #[test]
    fn a_query_dsl_body_is_free_form_but_the_rest_is_still_checked() {
        let es: Box<dyn Tool> = Box::new(elasticsearch::ElasticsearchSearchTool);
        let query = serde_json::json!({
            "bool": {"filter": [{"range": {"@timestamp": {"gte": "now-1h"}}}]},
            "_source": ["message"], "aggs": {"by_ns": {"terms": {"field": "kubernetes.namespace"}}}
        });
        let args = dcpr_agent::Tool::<Ops>::prepare_arguments(
            &es,
            serde_json::json!({"resource": "r", "index": "fb-ds-*", "query": query, "size": "5"}),
        )
        .unwrap();
        assert_eq!(args["query"], query, "the DSL passes through untouched");
        assert_eq!(args["size"], 5, "the other fields are still coerced");
        for bad in [
            serde_json::json!({"resource": "r", "index": "i", "query": "match_all"}),
            serde_json::json!({"resource": "r", "index": "i"}),
            serde_json::json!({"resource": "r", "index": "i", "query": {}, "bogus": 1}),
        ] {
            assert!(dcpr_agent::Tool::<Ops>::prepare_arguments(&es, bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn real_arguments_pass_the_loop_check_and_are_coerced() {
        let kubernetes: Box<dyn Tool> = Box::new(kubernetes::KubernetesTool);
        let args = dcpr_agent::Tool::<Ops>::prepare_arguments(
            &kubernetes,
            serde_json::json!({
                "target": "example::sandbox::aks", "action": "logs", "name": "api-7d8f",
                "namespace": "app", "previous": "true", "tail": "50"
            }),
        )
        .unwrap();
        assert_eq!(args["previous"], true);
        assert_eq!(args["tail"], 50);
        assert!(kubernetes.reads_only(&args));
        assert!(!kubernetes.reads_only(&serde_json::json!({"action": "delete_pod"})));
        assert!(!kubernetes.reads_only(&serde_json::json!({"action": "something-new"})));
    }
}
