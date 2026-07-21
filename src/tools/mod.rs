//! The Tool trait: everything the agent can do (brief §10).
//!
//! Gianna lessons kept: capability metadata is SELF-DECLARED on each impl
//! (central name-lists caused silent gating bugs); the registry is rebuilt
//! per turn with context gating; argument schemas are hand-written JSON
//! Schema with prose aimed at steering the model.
//!
//! The safety invariant in types: `ToolCtx` carries a [`crate::policy::Policy`]
//! handle — never a `TargetExecutor` — so a tool physically cannot execute an
//! unaudited remote command.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::domain::{Principal, RiskClass};
use crate::policy::PolicyExecute;

/// Per-turn tool context. Grows as waves land (repos, memory, incident store);
/// constructed only by the agent dispatch layer.
///
/// `policy` is `Arc<dyn PolicyExecute>`, not `Arc<Policy>` — a contract
/// change from the frozen sketch, made so tests can inject a recording fake
/// instead of the real (fail-closed stub) engine. See the doc comment on
/// `policy::PolicyExecute` for the full rationale. The safety invariant is
/// unchanged: this is still the ONLY handle a tool can reach, and its only
/// method is "classify, gate, audit, maybe execute" — there is no way to get
/// a `TargetExecutor` out of `ToolCtx`.
#[derive(Clone)]
pub struct ToolCtx {
    pub principal: Principal,
    pub policy: Arc<dyn PolicyExecute>,
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

/// The per-turn registry. Wave 3 populates it (context-gated registration:
/// read-only tools when their config section exists, mutating tools only when
/// a matching target is configured).
pub fn registry(_ctx: &ToolCtx) -> Vec<Box<dyn Tool>> {
    Vec::new()
}
