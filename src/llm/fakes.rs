//! The zero-network model a fakes-mode daemon boots with.
//!
//! Tests that drive the tool loop through specific steps use `dcpr-llm`'s
//! [`ScriptedModel`](crate::llm::ScriptedModel) instead.

use async_trait::async_trait;

use crate::domain::Principal;
use crate::llm::{ChatModel, ChatStep, SystemPrompt, ToolTurn};

/// A deterministic, zero-network fake. Always returns the same canned
/// no-tool text reply, regardless of input — enough to boot and self-validate
/// a fully-faked daemon (`Config::default()`, no LLM credentials) without
/// ever making a real call.
#[derive(Debug, Clone)]
pub struct FakeLlm {
    reply: String,
}

impl FakeLlm {
    pub fn new() -> Self {
        Self { reply: "OK (fake LLM — no provider configured).".to_string() }
    }
}

impl Default for FakeLlm {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChatModel<Principal> for FakeLlm {
    fn model_id(&self) -> &str {
        "fake"
    }

    async fn chat_step(
        &self,
        _principal: &Principal,
        _system: SystemPrompt<'_>,
        _history: &[ToolTurn],
        _tools: &[serde_json::Value],
    ) -> dcpr_llm::Result<ChatStep> {
        Ok(ChatStep::Text(self.reply.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal() -> Principal {
        Principal::Agent { job: None }
    }

    #[tokio::test]
    async fn fake_llm_returns_a_canned_no_tool_step_deterministically() {
        let llm = FakeLlm::new();
        let a = llm.chat_step(&principal(), "sys".into(), &[], &[]).await.unwrap();
        let b = llm.chat_step(&principal(), "sys".into(), &[], &[]).await.unwrap();
        match (a, b) {
            (ChatStep::Text(a), ChatStep::Text(b)) => assert_eq!(a, b, "deterministic"),
            other => panic!("expected two text steps, got {other:?}"),
        }
    }
}
