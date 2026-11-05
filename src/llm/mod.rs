//! The LLM layer, built on `dcpr-llm` (from dcpr-ai-rs).
//!
//! `dcpr-llm` owns the wire: the OpenAI-compatible / OpenRouter client,
//! error classification, the retrying [`Fallback`] chain, prompt caching and
//! the [`ScriptedModel`] test double. OpsClaw keeps only what is its own:
//!
//! - [`build_chain`] — the shipped chain from config (DESIGN §7 #13:
//!   OpenRouter only, `llm.models` as its server-side fallback list).
//! - [`CostGuard`] — the daily spend cap around the whole chain, fed by
//!   [`SpendMeter`] (the chain's `UsageSink`).
//! - [`FakeLlm`] — the zero-network model a fakes-mode daemon boots with.
//! - [`pricing`] — `PricedUsage` over the built-in list prices, plus the
//!   expensive default for a model with no price.
//!
//! Every model call is made for a [`Principal`], which is the `dcpr-llm`
//! caller identity: it scopes OpenRouter's session id and is handed to the
//! usage sink.

use crate::domain::Principal;

pub mod chain;
pub mod cost_guard;
pub mod fakes;
pub mod pricing;

pub use chain::build_chain;
pub use cost_guard::{CostGuard, SpendMeter, SpendSnapshot, hindsight_metrics_url};
pub use dcpr_llm::{
    ChatModel, ChatStep, Fallback, ScriptedModel, SystemPrompt, ToolCall, ToolTurn, Usage,
    UsageSink,
};
pub use fakes::FakeLlm;

/// The model type every OpsClaw component holds: a `dcpr-llm` chat model
/// whose calls are attributed to a [`Principal`].
pub type Llm = dyn ChatModel<Principal>;

/// Output-token ceiling for one tool step. A heartbeat sweep's final report
/// can run long; `dcpr-llm`'s 4k default truncates it.
const TOOL_STEP_OUTPUT_TOKENS: u32 = 16_384;

impl dcpr_llm::Caller for Principal {
    fn tool_step_output_tokens(&self) -> Option<u32> {
        Some(TOOL_STEP_OUTPUT_TOKENS)
    }
}
