//! THE choke point. Every remote command passes through [`Policy::execute`]:
//!
//! ```text
//! tool call → resolve fq target → risk-classify (code, not LLM)
//!   → e-stop check → autonomy gate (level + allow/deny + runbook match)
//!   → rate & cost caps → audit-begin → execute → audit-end
//! ```
//!
//! Nothing else may hold a `TargetExecutor`. The engine itself is Wave 2;
//! this module currently freezes the request/outcome contract so every other
//! module builds against it. Until the engine lands, `execute` fails CLOSED
//! (blocks everything) — the safe direction.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Result;
use crate::domain::{FqTarget, Principal, RiskClass};
use crate::targets::ExecOutput;

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
}

#[derive(Debug)]
pub enum PolicyOutcome {
    /// Ran within policy; output already audited.
    Executed(ExecOutput),
    /// Queued for human approval (suggest level, or act_on_known without a
    /// runbook match). The stored command runs verbatim on approval.
    NeedsApproval(Uuid),
    /// Refused by policy. At `observe`, mutations land in the dry-run log.
    Blocked { reason: String, dry_run_logged: bool },
    /// The e-stop is engaged; nothing executes anywhere.
    EStopped,
}

/// The policy engine handle threaded through `ToolCtx`. Wave 2 gives it the
/// executor registry, audit chain, e-stop sentinel, caps, and scrubber.
pub struct Policy {}

impl Policy {
    pub fn new() -> Self {
        Policy {}
    }

    pub async fn execute(&self, req: CommandRequest) -> Result<PolicyOutcome> {
        // Wave 2 implements the engine. Failing closed until then.
        Ok(PolicyOutcome::Blocked {
            reason: format!(
                "policy engine not yet implemented (refusing {} on {})",
                req.tool, req.target
            ),
            dry_run_logged: false,
        })
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}
