//! Memory tools (brief §10, DESIGN.md §4 item 3): `recall_memory`,
//! `store_memory`, `forget_memory` over `memory::Memory`. Honest
//! `is_enabled()` no-op per that module's doc — a tool call against a
//! disabled backend tells the model plainly that memory isn't configured
//! rather than silently pretending to have recalled/saved/forgotten
//! something.

use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::domain::{Principal, RiskClass};
use crate::memory::Memory;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

/// The speaker name woven into a stored fact's framing
/// (`"{speaker} said: …"`, per `memory::Memory::retain`'s doc). `store_memory`
/// is always an explicit agent-initiated save (the persona instructs the
/// model to call it, DESIGN.md §3), so it's framed as coming from the agent
/// unless a human operator is the acting principal — mirrors the same
/// attribution discipline the agent loop's `retain_turn_detached` uses for
/// passive per-turn retention.
fn speaker_for(principal: &Principal) -> String {
    match principal {
        Principal::Operator { account } => format!("operator:{account}"),
        Principal::Agent { .. } | Principal::System => "agent".to_string(),
    }
}

/// Recall over the team bank. Retrieval is HYBRID keyword + semantic (brief
/// §8's requirement) by the backend's own design — Hindsight's recall runs
/// semantic, BM25 keyword, graph, and temporal strategies in parallel and
/// rank-fuses them, driven by the query alone (see
/// `memory::hindsight::HindsightClient::recall`) — so this tool needs no
/// retrieval-mode argument and none exists to pass.
pub struct RecallMemoryTool {
    pub memory: Arc<Memory>,
}

#[async_trait]
impl Tool for RecallMemoryTool {
    fn name(&self) -> &'static str {
        "recall_memory"
    }

    fn description(&self) -> &str {
        "Recall facts the team has previously learned — target quirks, past incident \
         resolutions, operator preferences — relevant to a query. Call this before \
         answering (or saying you don't know) anything the team may have told OpsClaw \
         before; you do not have this pre-loaded into context. Omit `query` for a broad \
         'what do we know?' recall."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "what to recall; omit for a broad recall"},
                "limit": {"type": "integer", "description": "max facts to return (default 10)"}
            }
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        false
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, _ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        if !self.memory.is_enabled() {
            return Ok(ToolResult {
                output: "memory is not configured for this deployment — I have no standing \
                         knowledge beyond this conversation."
                    .to_string(),
            });
        }
        let limit = args["limit"].as_u64().unwrap_or(10) as usize;
        let query = args["query"].as_str().unwrap_or("");
        let records = if query.is_empty() {
            self.memory.all(limit).await
        } else {
            self.memory.recall(query, limit).await
        }
        .map_err(|e| ToolError::Internal(format!("memory recall failed: {e}")))?;

        if records.is_empty() {
            return Ok(ToolResult { output: "no matching facts found.".to_string() });
        }
        let out = records.iter().map(|r| format!("- {}", r.fact)).collect::<Vec<_>>().join("\n");
        Ok(ToolResult { output: out })
    }
}

pub struct StoreMemoryTool {
    pub memory: Arc<Memory>,
}

#[async_trait]
impl Tool for StoreMemoryTool {
    fn name(&self) -> &'static str {
        "store_memory"
    }

    fn description(&self) -> &str {
        "Explicitly remember a durable fact — a target quirk, an incident resolution that \
         worked, an operator preference. Use for something worth recalling in a future \
         conversation, not for routine chatter. State it as a plain fact in the `fact` \
         argument."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {"fact": {"type": "string"}},
            "required": ["fact"]
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let fact = args["fact"].as_str().ok_or_else(|| {
            ToolError::UserFacing("store_memory requires a \"fact\" argument".to_string())
        })?;
        if !self.memory.is_enabled() {
            return Ok(ToolResult {
                output: "memory is not configured for this deployment — I can't actually save \
                         this."
                    .to_string(),
            });
        }
        let speaker = speaker_for(&ctx.principal);
        self.memory
            .store_fact(&speaker, fact)
            .await
            .map_err(|e| ToolError::Internal(format!("memory store failed: {e}")))?;
        Ok(ToolResult { output: "saved.".to_string() })
    }
}

pub struct ForgetMemoryTool {
    pub memory: Arc<Memory>,
}

#[async_trait]
impl Tool for ForgetMemoryTool {
    fn name(&self) -> &'static str {
        "forget_memory"
    }

    fn description(&self) -> &str {
        "Retire one previously stored fact by its id (from recall_memory's results) — use \
         when a fact turns out to be wrong or outdated. This does NOT wipe the whole memory \
         bank, only the one fact. Provide `reason` briefly for the audit trail."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "memory_id": {"type": "string"},
                "reason": {"type": "string"}
            },
            "required": ["memory_id", "reason"]
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        false
    }

    async fn call(&self, _ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let memory_id = args["memory_id"].as_str().ok_or_else(|| {
            ToolError::UserFacing("forget_memory requires a \"memory_id\" argument".to_string())
        })?;
        let reason = args["reason"].as_str().ok_or_else(|| {
            ToolError::UserFacing("forget_memory requires a \"reason\" argument".to_string())
        })?;
        if !self.memory.is_enabled() {
            return Ok(ToolResult {
                output: "memory is not configured for this deployment — there is nothing to \
                         forget."
                    .to_string(),
            });
        }
        self.memory
            .forget(memory_id, reason)
            .await
            .map_err(|e| ToolError::Internal(format!("memory forget failed: {e}")))?;
        Ok(ToolResult { output: "forgotten.".to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ToolCtx {
        use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
        struct NoopPolicy;
        #[async_trait]
        impl PolicyExecute for NoopPolicy {
            async fn execute(&self, _req: CommandRequest) -> crate::Result<PolicyOutcome> {
                Ok(PolicyOutcome::EStopped)
            }
        }
        ToolCtx {
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        }
    }

    #[tokio::test]
    async fn recall_is_honest_when_memory_disabled() {
        let tool = RecallMemoryTool { memory: Arc::new(Memory::disabled()) };
        let r = tool.call(&ctx(), json!({"query": "web-1"})).await.unwrap();
        assert!(r.output.contains("not configured"));
    }

    #[tokio::test]
    async fn store_is_honest_when_memory_disabled() {
        let tool = StoreMemoryTool { memory: Arc::new(Memory::disabled()) };
        let r = tool.call(&ctx(), json!({"fact": "web-1 OOMs above 400 req/s"})).await.unwrap();
        assert!(r.output.contains("can't actually save"));
    }

    #[tokio::test]
    async fn forget_is_honest_when_memory_disabled() {
        let tool = ForgetMemoryTool { memory: Arc::new(Memory::disabled()) };
        let r = tool.call(&ctx(), json!({"memory_id": "abc", "reason": "wrong"})).await.unwrap();
        assert!(r.output.contains("nothing to forget"));
    }

    #[tokio::test]
    async fn store_requires_fact_argument() {
        let tool = StoreMemoryTool { memory: Arc::new(Memory::disabled()) };
        let err = tool.call(&ctx(), json!({})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[tokio::test]
    async fn forget_requires_both_arguments() {
        let tool = ForgetMemoryTool { memory: Arc::new(Memory::disabled()) };
        let err = tool.call(&ctx(), json!({"memory_id": "abc"})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[test]
    fn speaker_attribution_by_principal() {
        assert_eq!(speaker_for(&Principal::Agent { job: None }), "agent");
        assert_eq!(speaker_for(&Principal::System), "agent");
        let account = uuid::Uuid::nil();
        assert_eq!(speaker_for(&Principal::Operator { account }), format!("operator:{account}"));
    }

    #[test]
    fn forget_is_not_allowed_in_heartbeat_but_recall_and_store_are() {
        let recall = RecallMemoryTool { memory: Arc::new(Memory::disabled()) };
        let store = StoreMemoryTool { memory: Arc::new(Memory::disabled()) };
        let forget = ForgetMemoryTool { memory: Arc::new(Memory::disabled()) };
        assert!(recall.allowed_in_heartbeat());
        assert!(store.allowed_in_heartbeat());
        assert!(!forget.allowed_in_heartbeat());
    }
}
