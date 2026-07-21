//! Anthropic provider. Ported from gianna's `src/llm_providers/anthropic.rs`
//! (native tool-calling path only — gianna's classify/onboarding/timezone
//! methods are gianna's Intent-fallback machinery, dropped per the port
//! brief: opsclaw has no tool-less production mode).
//!
//! Supports two credential modes (selected by which is configured):
//! - **API key**: header `x-api-key: <key>` (the supported path).
//! - **OAuth token**: header `Authorization: Bearer <token>` plus the
//!   `anthropic-beta: oauth-2025-04-20` flag. The caller supplies the token
//!   directly (no OAuth flow is implemented here).

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::Principal;
use crate::llm::{ChatStep, LlmProvider, ToolCall, ToolSpec, Turn};
use crate::{Error, Result};

const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const OAUTH_BETA: &str = "oauth-2025-04-20";

/// Per-request total timeout for `chat_step` — big agent-loop generations run
/// well past the connect/small-call budget; killing them just retries into
/// the same wall.
const CHAT_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);

#[derive(Clone)]
pub enum AnthropicAuth {
    ApiKey(String),
    OAuthToken(String),
}

/// Reshape a provider-neutral [`ToolSpec`] into Anthropic's tool shape, which
/// reads the JSON Schema from `input_schema`. Gianna shipped a production
/// outage by leaking one provider's schema key to another — this reshape (and
/// its OpenAI-compat counterpart) is not optional.
fn anthropic_tool(spec: &ToolSpec) -> Value {
    let input_schema = if spec.parameters.is_null() {
        json!({ "type": "object", "properties": {} })
    } else {
        spec.parameters.clone()
    };
    json!({
        "name": spec.name,
        "description": spec.description,
        "input_schema": input_schema,
    })
}

#[derive(Clone)]
pub struct AnthropicProvider {
    client: reqwest::Client,
    auth: AnthropicAuth,
    model: String,
    /// The Messages API endpoint. Defaults to the real Anthropic URL;
    /// overridden in tests to point at a wiremock server.
    url: String,
}

impl AnthropicProvider {
    pub fn new(auth: AnthropicAuth, model: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client builds");
        Self { client, auth, model: model.into(), url: ANTHROPIC_URL.to_string() }
    }

    /// Point at an arbitrary Messages-API-compatible URL (wiremock tests).
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn chat_step(
        &self,
        principal: &Principal,
        system: &str,
        history: &[Turn],
        tools: &[ToolSpec],
    ) -> Result<ChatStep> {
        // Build the Anthropic messages array from the turn history.
        let mut messages: Vec<Value> = Vec::new();
        for turn in history {
            match turn {
                Turn::User { content } => {
                    messages.push(json!({"role":"user","content":content}));
                }
                Turn::Assistant { content, tool_calls } if tool_calls.is_empty() => {
                    messages.push(json!({"role":"assistant","content":content}));
                }
                Turn::Assistant { tool_calls, .. } => {
                    let content: Vec<Value> = tool_calls
                        .iter()
                        .map(|c| json!({"type":"tool_use","id":c.id,"name":c.name,"input":c.args}))
                        .collect();
                    messages.push(json!({"role":"assistant","content":content}));
                }
                Turn::ToolResult { call_id, output, .. } => {
                    messages.push(json!({"role":"user","content":[
                        {"type":"tool_result","tool_use_id":call_id,"content":output}
                    ]}));
                }
            }
        }

        // Reshape each neutral spec into Anthropic's {..., input_schema} form,
        // then mark the LAST tool with a cache_control breakpoint: Anthropic
        // prompt caching is strictly opt-in, and a breakpoint on the final
        // tool caches the whole (large, stable) tool-spec prefix that is
        // resent on every step of every tool loop.
        let mut anthropic_tools: Vec<Value> = tools.iter().map(anthropic_tool).collect();
        if let Some(last) = anthropic_tools.last_mut() {
            last["cache_control"] = json!({ "type": "ephemeral" });
        }
        let body = json!({
            "model": self.model,
            "max_tokens": 8192,
            "system": [{
                "type": "text",
                "text": system,
                "cache_control": { "type": "ephemeral" },
            }],
            "messages": messages,
            "tools": anthropic_tools,
        });

        let mut req = self
            .client
            .post(&self.url)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json");
        req = match &self.auth {
            AnthropicAuth::ApiKey(k) => req.header("x-api-key", k),
            AnthropicAuth::OAuthToken(t) => req
                .header("authorization", format!("Bearer {t}"))
                .header("anthropic-beta", OAUTH_BETA),
        };

        tracing::debug!(%principal, model = %self.model, "anthropic tools request");
        let started = std::time::Instant::now();
        let resp = req.timeout(CHAT_STEP_TIMEOUT).json(&body).send().await.map_err(|e| {
            tracing::warn!(
                %principal, model = %self.model,
                latency_ms = started.elapsed().as_millis() as u64,
                "anthropic request failed (transient): {e}"
            );
            Error::llm_transient(format!("anthropic request failed: {e}"))
        })?;
        let status = resp.status();
        let retry_after = crate::llm::openai_compat::parse_retry_after(resp.headers());
        let raw = resp.text().await.map_err(|e| {
            tracing::warn!(
                %principal, model = %self.model, status = status.as_u16(),
                "anthropic could not read response body: {e}"
            );
            Error::llm_transient(format!("anthropic read body: {e}"))
        })?;
        if !status.is_success() {
            let msg = serde_json::from_str::<Value>(&raw)
                .ok()
                .and_then(|b| b["error"]["message"].as_str().map(str::to_string))
                .unwrap_or_else(|| raw.chars().take(200).collect());
            tracing::warn!(
                %principal, model = %self.model, status = status.as_u16(),
                latency_ms = started.elapsed().as_millis() as u64,
                "anthropic call failed: {msg}"
            );
            return Err(Error::from_llm_status(
                status.as_u16(),
                format!("anthropic {status}: {msg}"),
                retry_after,
            ));
        }
        let payload: Value = serde_json::from_str(&raw).map_err(|e| {
            tracing::warn!(
                %principal, model = %self.model, status = status.as_u16(),
                "anthropic response was not valid JSON: {e}"
            );
            Error::llm_transient(format!("anthropic bad json: {e}"))
        })?;

        let mut usage = crate::llm::TokenUsage::default();
        if let Some(u) = payload.get("usage") {
            usage.input_tokens = u["input_tokens"].as_u64().unwrap_or(0);
            usage.output_tokens = u["output_tokens"].as_u64().unwrap_or(0);
        }
        crate::llm::pricing::price_usage(&mut usage, &self.model);

        match payload["stop_reason"].as_str() {
            Some("max_tokens") => tracing::warn!(
                %principal, model = %self.model,
                "anthropic reply hit the max_tokens ceiling (stop_reason=max_tokens) — text may be truncated"
            ),
            Some(sr @ ("refusal" | "content_filter")) => tracing::warn!(
                %principal, model = %self.model, stop_reason = sr,
                "anthropic reply stopped on a refusal/content filter — partial/blocked output"
            ),
            _ => {}
        }

        let blocks = payload["content"].as_array().cloned().unwrap_or_default();
        let mut calls = Vec::new();
        let mut text = String::new();
        for b in &blocks {
            match b["type"].as_str() {
                Some("tool_use") => calls.push(ToolCall {
                    id: b["id"].as_str().unwrap_or("").to_string(),
                    name: b["name"].as_str().unwrap_or("").to_string(),
                    args: b["input"].clone(),
                }),
                Some("text") => text.push_str(b["text"].as_str().unwrap_or("")),
                _ => {}
            }
        }
        tracing::debug!(
            %principal, model = %self.model,
            latency_ms = started.elapsed().as_millis() as u64,
            in_tokens = usage.input_tokens,
            out_tokens = usage.output_tokens,
            tool_calls = calls.len(),
            "anthropic tools step ok"
        );
        let text = if text.trim().is_empty() { None } else { Some(text.trim().to_string()) };
        Ok(ChatStep { text, tool_calls: calls, usage })
    }

    fn name(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_tool_reshapes_parameters_to_input_schema() {
        // The production outage gianna shipped: the schema must land under
        // `input_schema`, never leak an OpenAI-shaped `parameters` key.
        let spec = ToolSpec {
            name: "set_reminder".into(),
            description: "Set a reminder.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": { "body": {"type":"string"} },
                "required": ["body"]
            }),
        };
        let t = anthropic_tool(&spec);
        assert_eq!(t["name"], "set_reminder");
        assert_eq!(t["input_schema"]["required"], serde_json::json!(["body"]));
        assert!(t.get("parameters").is_none(), "parameters must not leak onto the Anthropic wire");
    }

    #[test]
    fn anthropic_tool_supplies_empty_schema_when_null() {
        let spec = ToolSpec {
            name: "list_tasks".into(),
            description: "List.".into(),
            parameters: Value::Null,
        };
        let t = anthropic_tool(&spec);
        assert_eq!(t["input_schema"], serde_json::json!({ "type": "object", "properties": {} }));
    }
}
