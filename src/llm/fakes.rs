//! Test doubles for [`LlmProvider`].
//!
//! `ScriptedLlm` is ported fully from gianna's `src/llm.rs` (queue-driven,
//! for deterministic multi-turn tool-loop tests). `FakeLlm` is REDESIGNED
//! minimal for opsclaw: gianna's `FakeLlm` drove an entire keyword-heuristic
//! Intent-classification fallback path (`classify`, `resolve_timezone`,
//! `interpret_onboarding`, `extract_onboarding_fields` — none of which exist
//! in the frozen [`LlmProvider`] contract). Opsclaw has no tool-less
//! production mode, so none of that machinery is ported: `FakeLlm` here is
//! just a deterministic, zero-network provider that returns a canned no-tool
//! text step, for booting the fakes-mode daemon (`Config::default()`).

use async_trait::async_trait;

use crate::Result;
use crate::domain::Principal;
use crate::llm::{ChatStep, LlmProvider, ToolSpec, Turn};

/// A deterministic, zero-network fake. Always returns the same canned
/// no-tool text reply, regardless of input — enough to boot and self-validate
/// a fully-faked daemon (`Config::default()`, no LLM credentials) without
/// ever making a real call. Not a substitute for `ScriptedLlm` in tests that
/// need to drive the tool loop through specific steps.
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
impl LlmProvider for FakeLlm {
    async fn chat_step(
        &self,
        _principal: &Principal,
        _system: &str,
        _history: &[Turn],
        _tools: &[ToolSpec],
    ) -> Result<ChatStep> {
        Ok(ChatStep {
            text: Some(self.reply.clone()),
            tool_calls: Vec::new(),
            usage: Default::default(),
        })
    }

    fn name(&self) -> &str {
        "fake"
    }
}

/// A queue-driven fake for DETERMINISTIC multi-turn tool-loop tests. Ported
/// verbatim (contract-adapted) from gianna's `src/llm.rs`.
///
/// Build it with the `push_*` API, then hand it to the agent loop. It panics
/// with a clear message if the conversation asks for more steps than were
/// scripted (a test bug — an unbounded loop or a miscount), and `remaining()`
/// lets a test assert the script was fully consumed.
pub struct ScriptedLlm {
    steps: std::sync::Mutex<std::collections::VecDeque<Result<ChatStep>>>,
}

impl ScriptedLlm {
    pub fn new() -> Self {
        Self { steps: std::sync::Mutex::new(std::collections::VecDeque::new()) }
    }

    /// Push a plain-text assistant reply (ends the tool loop when reached).
    pub fn push_text(&mut self, text: impl Into<String>) -> &mut Self {
        self.steps.get_mut().unwrap().push_back(Ok(ChatStep {
            text: Some(text.into()),
            tool_calls: Vec::new(),
            usage: Default::default(),
        }));
        self
    }

    /// Push a single tool call. Ids are auto-assigned (`call_1`, `call_2`, ...)
    /// in push order so tests don't have to invent them.
    pub fn push_tool_call(
        &mut self,
        name: impl Into<String>,
        args: serde_json::Value,
    ) -> &mut Self {
        self.push_tool_calls(vec![(name.into(), args)])
    }

    /// Push ONE assistant turn that requests SEVERAL tool calls at once.
    pub fn push_tool_calls(&mut self, calls: Vec<(String, serde_json::Value)>) -> &mut Self {
        let q = self.steps.get_mut().unwrap();
        let base = q.len();
        let calls = calls
            .into_iter()
            .enumerate()
            .map(|(i, (name, args))| crate::llm::ToolCall {
                id: format!("call_{}", base + i + 1),
                name,
                args,
            })
            .collect();
        q.push_back(Ok(ChatStep { text: None, tool_calls: calls, usage: Default::default() }));
        self
    }

    /// Push an error step — the provider fails on this `chat_step` (a
    /// simulated 529/timeout). Use after a tool-call step to exercise the
    /// "failed mid-loop AFTER acting" path without a bespoke stub.
    pub fn push_error(&mut self, error: crate::Error) -> &mut Self {
        self.steps.get_mut().unwrap().push_back(Err(error));
        self
    }

    /// How many scripted steps are still unconsumed. A test asserts `== 0`
    /// after the turn to prove the whole script was used (no dead steps, no
    /// early exit).
    pub fn remaining(&self) -> usize {
        self.steps.lock().unwrap().len()
    }
}

impl Default for ScriptedLlm {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmProvider for ScriptedLlm {
    async fn chat_step(
        &self,
        _principal: &Principal,
        _system: &str,
        _history: &[Turn],
        _tools: &[ToolSpec],
    ) -> Result<ChatStep> {
        self.steps.lock().unwrap().pop_front().unwrap_or_else(|| {
            panic!(
                "ScriptedLlm ran out of scripted steps — the conversation asked \
                 for more chat_step calls than were pushed. This is a test bug: \
                 script another step, or the loop is not terminating."
            )
        })
    }

    fn name(&self) -> &str {
        "scripted"
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
        let a = llm.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        let b = llm.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        assert_eq!(a.text, b.text, "deterministic across calls");
        assert!(a.text.is_some());
        assert!(
            a.tool_calls.is_empty(),
            "no tool calls — opsclaw has no fallback path to exercise"
        );
    }

    #[tokio::test]
    async fn scripted_llm_pops_steps_in_order() {
        let mut llm = ScriptedLlm::new();
        llm.push_text("hello").push_tool_call("list_incidents", serde_json::json!({"limit": 5}));
        assert_eq!(llm.remaining(), 2);

        let s1 = llm.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        assert_eq!(s1.text.as_deref(), Some("hello"));

        let s2 = llm.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        assert_eq!(s2.tool_calls.len(), 1);
        assert_eq!(s2.tool_calls[0].name, "list_incidents");
        assert_eq!(s2.tool_calls[0].id, "call_2");

        assert_eq!(llm.remaining(), 0);
    }

    #[tokio::test]
    async fn scripted_llm_multi_call_turn_ids_are_sequential() {
        let mut llm = ScriptedLlm::new();
        llm.push_tool_calls(vec![
            ("list_incidents".into(), serde_json::json!({})),
            ("list_approvals".into(), serde_json::json!({})),
        ]);
        let step = llm.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        assert_eq!(step.tool_calls.len(), 2);
        assert_eq!(step.tool_calls[0].id, "call_1");
        assert_eq!(step.tool_calls[1].id, "call_2");
    }

    #[tokio::test]
    async fn scripted_llm_error_step_surfaces_after_a_tool_call() {
        let mut llm = ScriptedLlm::new();
        llm.push_tool_call("list_incidents", serde_json::json!({}))
            .push_error(crate::Error::llm_transient("simulated 529"));
        llm.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        let err = llm.chat_step(&principal(), "sys", &[], &[]).await.unwrap_err();
        assert!(err.is_retryable());
    }

    #[tokio::test]
    #[should_panic(expected = "ran out of scripted steps")]
    async fn scripted_llm_panics_when_under_scripted() {
        let llm = ScriptedLlm::new();
        let _ = llm.chat_step(&principal(), "sys", &[], &[]).await;
    }
}
