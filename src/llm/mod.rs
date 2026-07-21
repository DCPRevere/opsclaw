//! Multi-provider LLM abstraction. Ported from gianna in Wave 1
//! (`src/llm.rs` + `src/llm_providers/`): `AnthropicProvider`,
//! `OpenAiCompatProvider` (OpenAI/OpenRouter in one struct), `FallbackLlm`
//! (jittered-backoff retry then fall-through; context-overflow fails fast),
//! `FakeLlm` and `ScriptedLlm` test doubles, and the per-model price table.
//!
//! Shipped default (DESIGN §7 #13): OpenRouter only, its server-side ordered
//! model list, wrapped in FallbackLlm for retry/backoff.
//!
//! This module currently freezes the trait contract. The Wave 1 port agent
//! adapts gianna's proven wire types onto these shapes; where they conflict,
//! gianna's shape wins and the delta is reported for main-session integration.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Result;
use crate::domain::Principal;

/// Provider-neutral tool spec `{name, description, parameters}`. Each provider
/// reshapes at the wire boundary (Anthropic: `input_schema`; OpenAI-compat:
/// `{type:"function", function:{...}}`) — gianna shipped an outage by leaking
/// one provider's key to another; the reshaping is not optional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

/// One entry in the replayable conversation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "role")]
pub enum Turn {
    User { content: String },
    Assistant { content: String, tool_calls: Vec<ToolCall> },
    ToolResult { call_id: String, name: String, output: String },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Provider-reported cost in cents when available (OpenRouter reports
    /// truth; otherwise priced from the hand-maintained table).
    pub cost_cents: Option<f64>,
}

/// One step of the tool loop: the model's text and/or tool calls.
#[derive(Debug, Clone, Default)]
pub struct ChatStep {
    pub text: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// One non-streaming step of the native tool-calling loop. `principal` is
    /// carried for usage attribution (gianna's nil-household billing lesson:
    /// typed principal, not a bare id).
    async fn chat_step(
        &self,
        principal: &Principal,
        system: &str,
        history: &[Turn],
        tools: &[ToolSpec],
    ) -> Result<ChatStep>;

    fn name(&self) -> &str;
}
