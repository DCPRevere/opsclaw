//! Multi-provider LLM abstraction. Ported from gianna in Wave 1
//! (`src/llm.rs` + `src/llm_providers/`): `AnthropicProvider`,
//! `OpenAiCompatProvider` (OpenAI/OpenRouter in one struct), `FallbackLlm`
//! (jittered-backoff retry then fall-through; context-overflow fails fast),
//! `FakeLlm` and `ScriptedLlm` test doubles, and the per-model price table.
//!
//! Shipped default (DESIGN §7 #13): OpenRouter only, its server-side ordered
//! model list, wrapped in FallbackLlm for retry/backoff. See
//! [`chain::build_chain`].
//!
//! ## Contract deltas from the Wave 0 sketch (reported per the port brief)
//!
//! The Wave 0 sketch froze the trait signature and the shapes below as
//! sketches; gianna's proven wire types won where they conflicted. What
//! changed making the port real:
//!
//! - **`ChatStep` stayed a struct** (`{ text, tool_calls, usage }`), not
//!   gianna's `enum ChatStep { Text(String), ToolCalls(Vec<ToolCall>) }`. The
//!   struct shape was already load-bearing in the sketch (callers match on
//!   `text.is_some()` / `!tool_calls.is_empty()`); gianna's providers are
//!   adapted to emit it (mutually-exclusive-in-practice, but the struct
//!   allows a step with only usage and no text, e.g. an empty reply — treated
//!   as `text: None`).
//! - **No `intent`/`classify` fallback path.** Gianna's `LlmProvider` also
//!   carried `classify`, `resolve_timezone`, `interpret_onboarding`,
//!   `extract_onboarding_fields` and a keyword-heuristic `Intent` enum — the
//!   tool-less fallback used when the native tool loop couldn't be trusted.
//!   Opsclaw has no such fallback mode (brief: "no tool-less production
//!   mode"), so NONE of that is ported: no `Intent` type, no `classify`
//!   method on the trait, `FakeLlm` redesigned to not need it.
//! - **`Turn` has no image variant.** Gianna's `ToolTurn::UserWithImages` /
//!   `InputImage` (vision-model routing) are not ported — the frozen `Turn`
//!   enum has no image variant and nothing in the opsclaw brief calls for
//!   vision input. `OpenAiCompatProvider::model_for` / `with_vision_model`
//!   are dropped accordingly. If a vision need surfaces later, `Turn` needs a
//!   new variant — flagged here so it isn't silently reinvented per-provider.
//! - **`TokenUsage` has no separate `cache_read_tokens` field.** Gianna's
//!   `Usage` splits cached vs uncached input tokens (cached billed at a 0.1x
//!   discount). The frozen `TokenUsage` only has `input_tokens`/
//!   `output_tokens`/`cost_cents`. The port folds cached tokens into
//!   `input_tokens` (conservative: prices the cached portion at the FULL
//!   input rate when falling back to the price table, i.e. slightly
//!   overcounts cost — never undercounts). `pricing::cost_cents` still
//!   accepts a `cache_read_tokens` parameter for a caller that has the
//!   provider's cached-token count and wants the discount; `TokenUsage` just
//!   doesn't carry it through today. Extending `TokenUsage` with a
//!   `cache_read_tokens: u64` field would let `price_usage` apply the
//!   discount automatically — left as a follow-up, not done unilaterally
//!   since it touches the frozen struct's wire/serde shape.
//! - **`Principal` replaces gianna's bare `Uuid household`.** Already implied
//!   by the frozen contract; noted because it's the reason `pricing::UsageSink`
//!   takes `&Principal` (Agent/Operator/System) rather than a household id —
//!   there is no household concept in opsclaw.
//! - **`UsageSink` is new** (not in gianna, which persisted through
//!   `ControlRepo`/`Analytics`/PostHog directly from `UsageRecorder`). A
//!   minimal fire-and-forget trait + a `NoopUsageSink` stand in until a later
//!   wave wires a DB-backed sink (`src/db/` is explicitly off-limits for this
//!   port).
//! - **`crate::Error` gained `Llm { message, retryable, retry_after_secs }`
//!   and `LlmContextOverflow(String)` variants** (`src/error.rs`, NOT under
//!   `src/llm/`) — the frozen `LlmProvider::chat_step` signature returns
//!   `crate::Result<ChatStep>`, and the retry/hard/context-overflow
//!   distinction `FallbackLlm` depends on has nowhere else to live in
//!   opsclaw's single flat error enum (unlike gianna's, which already had
//!   this shape). This is the one edit this port makes outside `src/llm/`;
//!   called out per "REPORT every delta prominently."

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Result;
use crate::domain::Principal;

pub mod anthropic;
pub mod chain;
pub mod cost_guard;
pub mod fakes;
pub mod fallback;
pub mod openai_compat;
pub mod pricing;

pub use anthropic::{AnthropicAuth, AnthropicProvider};
pub use chain::build_chain;
pub use cost_guard::CostGuard;
pub use fakes::{FakeLlm, ScriptedLlm};
pub use fallback::FallbackLlm;
pub use openai_compat::OpenAiCompatProvider;

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
