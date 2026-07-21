//! OpenAI-compatible provider — covers OpenAI and OpenRouter (and any other
//! OpenAI Chat-Completions-shaped endpoint), which differ only in base URL,
//! auth, and a few OpenRouter-only quirks. Ported from gianna's
//! `src/llm_providers/openai_compat.rs` (native tool-calling path only —
//! gianna's classify/onboarding/timezone methods are the Intent-fallback
//! machinery, dropped per the port brief).
//!
//! - **OpenAI**: `https://api.openai.com/v1`, `Authorization: Bearer <api key>`.
//! - **OpenRouter**: `https://openrouter.ai/api/v1`, `Authorization: Bearer <key>`.
//!
//! Both return usage as `usage.prompt_tokens` / `completion_tokens`.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::Principal;
use crate::llm::{ChatStep, LlmProvider, ToolCall, ToolSpec, Turn};
use crate::{Error, Result};

/// Per-request total timeout for `chat_step`. A generous output ceiling means
/// a big structured tool call legitimately runs well past a small-call
/// budget; killing it just retries into the same wall.
const CHAT_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);

/// Parse a `Retry-After` header (seconds form) into a bounded number of
/// seconds. Providers overwhelmingly send the delta-seconds form on a
/// 429/529; the HTTP-date form is rare here and deliberately ignored (falls
/// back to jitter). Capped at 5 minutes so a hostile/absurd value can't wedge
/// the retry loop.
pub(crate) fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|secs| secs.min(300))
}

#[derive(Clone)]
pub struct OpenAiCompatProvider {
    client: reqwest::Client,
    base_url: String,
    bearer: String,
    model: String,
    /// Optional extra headers (OpenRouter likes Referer/X-Title; harmless if
    /// unset).
    referer: Option<String>,
    /// OpenRouter fallback models, in priority order, tried after `model` if
    /// it errors (rate-limit, downtime, deprecation). Sent as the `models`
    /// array; OpenRouter does the failover server-side and bills for
    /// whichever model actually ran. Empty (the default) = no fallback. Only
    /// honoured on the OpenRouter endpoint (OpenAI proper rejects the field).
    fallback_models: Vec<String>,
}

impl OpenAiCompatProvider {
    pub fn new(
        base_url: impl Into<String>,
        bearer: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client builds");
        Self {
            client,
            base_url: base_url.into(),
            bearer: bearer.into(),
            model: model.into(),
            referer: None,
            fallback_models: Vec::new(),
        }
    }

    /// Set OpenRouter fallback models (priority order). No-op off the
    /// OpenRouter endpoint. The primary `model` is always tried first; these
    /// follow it.
    pub fn with_fallback_models(mut self, models: Vec<String>) -> Self {
        self.fallback_models = models;
        self
    }

    pub fn with_referer(mut self, referer: impl Into<String>) -> Self {
        self.referer = Some(referer.into());
        self
    }

    /// OpenRouter turns reasoning ON by default for reasoning-capable models.
    /// The reasoning stream then consumes the token budget and
    /// `message.content` comes back empty — and this provider reads only
    /// `content`. Disable it. OpenAI proper rejects unknown parameters, so
    /// the field is sent to OpenRouter only.
    pub(crate) fn apply_provider_quirks(&self, body: &mut Value) {
        if self.base_url.contains("openrouter") {
            body["reasoning"] = json!({ "enabled": false });
            // Ask OpenRouter to return the exact upstream cost (and
            // cached-token details) in the response `usage` block, so we
            // record provider-truth cost rather than the hand-maintained
            // price table — which a routed/renamed model id would silently
            // mis-price.
            body["usage"] = json!({ "include": true });
            // Fallback models: try `model` first, then each fallback in
            // order, so a deprecated/down/rate-limited primary doesn't take
            // us offline. OpenRouter does the failover server-side and bills
            // the model that actually ran (returned in the response's
            // `model`).
            if !self.fallback_models.is_empty() {
                let primary = body["model"].as_str().unwrap_or(&self.model).to_string();
                let mut models = vec![primary];
                models.extend(self.fallback_models.iter().cloned());
                body["models"] = json!(models);
            }
        }
    }
}

#[async_trait]
impl LlmProvider for OpenAiCompatProvider {
    async fn chat_step(
        &self,
        principal: &Principal,
        system: &str,
        history: &[Turn],
        tools: &[ToolSpec],
    ) -> Result<ChatStep> {
        // Build the OpenAI messages array from the turn history.
        let mut messages: Vec<Value> = vec![json!({ "role": "system", "content": system })];
        for turn in history {
            match turn {
                Turn::User { content } => {
                    messages.push(json!({ "role": "user", "content": content }))
                }
                Turn::Assistant { content, tool_calls } if tool_calls.is_empty() => {
                    messages.push(json!({ "role": "assistant", "content": content }));
                }
                Turn::Assistant { tool_calls, .. } => {
                    let wire_calls: Vec<Value> = tool_calls
                        .iter()
                        .map(|c| {
                            json!({
                                "id": c.id,
                                "type": "function",
                                "function": { "name": c.name, "arguments": c.args.to_string() }
                            })
                        })
                        .collect();
                    messages.push(
                        json!({ "role": "assistant", "content": null, "tool_calls": wire_calls }),
                    );
                }
                Turn::ToolResult { call_id, output, .. } => {
                    messages.push(
                        json!({ "role": "tool", "tool_call_id": call_id, "content": output }),
                    );
                }
            }
        }

        // Wrap each provider-neutral spec into the OpenAI `function` shape,
        // with the schema under `function.parameters`. Getting this key wrong
        // leaves the model with no declared parameters and forces it to guess
        // argument names — the production tool-calling outage.
        let oai_tools: Vec<Value> = tools.iter().map(oai_function).collect();

        let mut body = json!({
            "model": self.model,
            // Generous output ceiling. A TRUNCATED tool call is the worst
            // outcome — it's dropped as unparseable and the whole multi-step
            // run is wasted, so a tight budget actively costs more than a
            // loose one (you only pay for tokens actually generated).
            "max_tokens": 16384,
            "messages": messages,
            "tools": oai_tools,
        });
        self.apply_provider_quirks(&mut body);

        let mut req = self
            .client
            .post(format!("{}/chat/completions", self.base_url.trim_end_matches('/')))
            .header("authorization", format!("Bearer {}", self.bearer))
            .header("content-type", "application/json");
        if let Some(r) = &self.referer {
            req = req.header("HTTP-Referer", r).header("X-Title", "OpsClaw");
        }
        tracing::debug!(%principal, model = %self.model, "openai-compat tools request");
        let resp = req.timeout(CHAT_STEP_TIMEOUT).json(&body).send().await.map_err(|e| {
            Error::llm_transient(format!("openai-compat tools request failed: {e}"))
        })?;
        let status = resp.status();
        let retry_after = parse_retry_after(resp.headers());
        let raw = resp
            .text()
            .await
            .map_err(|e| Error::llm_transient(format!("openai-compat tools read body: {e}")))?;
        if !status.is_success() {
            let msg = serde_json::from_str::<Value>(&raw)
                .ok()
                .and_then(|b| b["error"]["message"].as_str().map(str::to_string))
                .unwrap_or_else(|| raw.chars().take(200).collect());
            return Err(Error::from_llm_status(
                status.as_u16(),
                format!("openai-compat {status}: {msg}"),
                retry_after,
            ));
        }
        let payload: Value = serde_json::from_str(&raw)
            .map_err(|e| Error::llm_transient(format!("openai-compat tools bad json: {e}")))?;

        let mut usage = crate::llm::TokenUsage::default();
        let mut ran_model = self.model.clone();
        if let Some(u) = payload.get("usage") {
            ran_model = payload["model"].as_str().unwrap_or(&self.model).to_string();
            // Cached prompt tokens: OpenAI/OpenRouter report them under
            // prompt_tokens_details.cached_tokens; DeepSeek uses
            // prompt_cache_hit_tokens. Count them separately and subtract
            // from input tokens (opsclaw's TokenUsage has no separate cached
            // field, so fold both into input — the pricing table's
            // cache_read_tokens split is priced at the pricing module for
            // callers that supply it separately; here we conservatively fold
            // the full prompt into input_tokens).
            let prompt = u["prompt_tokens"].as_u64().unwrap_or(0);
            usage.input_tokens = prompt;
            usage.output_tokens = u["completion_tokens"].as_u64().unwrap_or(0);
            // OpenRouter's usage.cost (USD) -> cents; recorded as truth over
            // the price table.
            usage.cost_cents = u["cost"].as_f64().map(|usd| usd * 100.0);
        }
        crate::llm::pricing::price_usage(&mut usage, &ran_model);

        // A `length`/content-filter finish is a TRUNCATED or filtered reply —
        // WARN so a silently-cut answer is visible.
        match payload["choices"][0]["finish_reason"].as_str() {
            Some("length") => tracing::warn!(
                %principal, model = %ran_model,
                "openai-compat reply hit the max_tokens ceiling (finish_reason=length) — text may be truncated"
            ),
            Some(fr @ ("content_filter" | "content-filter")) => tracing::warn!(
                %principal, model = %ran_model, finish_reason = fr,
                "openai-compat reply stopped on a content filter — partial/blocked output"
            ),
            _ => {}
        }

        let msg = payload
            .get("choices")
            .and_then(|c| c.get(0))
            .map(|c| &c["message"])
            .ok_or_else(|| Error::llm_transient("openai-compat: response had no choices"))?;
        let (step, parse) = interpret_tool_message(msg, usage);
        // Surface the XML-recovery path: it means the provider's native
        // tool_calls were unusable. A WARN here makes a recurrence (new
        // model, provider regression) visible in prod immediately.
        if parse != ToolParse::Native {
            let detail = match parse {
                ToolParse::DroppedNative => {
                    "native tool_calls were malformed and no XML fallback was present — tool call LOST"
                }
                ToolParse::PartialDroppedNative => {
                    "some parallel native tool_calls were malformed and DROPPED — proceeding with the survivors"
                }
                _ => {
                    "recovered tool call from Hermes XML — provider's native tool_calls were unusable"
                }
            };
            tracing::warn!(%principal, model = %ran_model, parse = ?parse, "{detail}");
        }
        Ok(step)
    }

    fn name(&self) -> &str {
        &self.model
    }
}

/// How a tool call was recovered from the response — for observability. The
/// XML variants mean the provider's native `tool_calls` field was unusable
/// and we fell back to parsing Hermes XML out of `content`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolParse {
    /// Clean native `tool_calls` (or a plain-text reply) — the healthy path.
    Native,
    /// Native `tool_calls` were present but malformed; recovered from XML.
    XmlAfterMalformedNative,
    /// No native `tool_calls`; the call was Hermes XML in `content`.
    XmlNoNative,
    /// Native `tool_calls` were present but ALL malformed, AND there was no
    /// XML to recover from — the tool call is lost.
    DroppedNative,
    /// SOME of several parallel native `tool_calls` were malformed (truncated
    /// args) and dropped, but at least one sibling parsed and no better XML
    /// was available, so we proceed with the survivors.
    PartialDroppedNative,
}

/// Wrap a provider-neutral [`ToolSpec`] into an OpenAI/OpenRouter `function`
/// tool. The schema MUST land under `function.parameters` — the key the
/// OpenAI tool-calling contract reads it from. (Shipping it under any other
/// key leaves the model with no declared parameters and forces it to guess
/// argument names — the production outage.) A spec without a schema still
/// gets a valid empty object schema so the function is well-formed.
fn oai_function(spec: &ToolSpec) -> Value {
    let parameters = if spec.parameters.is_null() {
        json!({ "type": "object", "properties": {} })
    } else {
        spec.parameters.clone()
    };
    json!({
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": parameters,
        }
    })
}

/// Test-only re-export so other tests can assert the real spec()->wire shape
/// across the provider seam.
#[cfg(test)]
pub(crate) fn oai_function_for_test(spec: &ToolSpec) -> Value {
    oai_function(spec)
}

fn interpret_tool_message(msg: &Value, usage: crate::llm::TokenUsage) -> (ChatStep, ToolParse) {
    let content = msg["content"].as_str().unwrap_or("");
    if let Some(tcs) = msg["tool_calls"].as_array().filter(|a| !a.is_empty()) {
        // Count named entries (an entry with no name is not a call the model
        // made, just filler) so a truncation-drop shows up as survivors < named.
        let named =
            tcs.iter().filter(|c| !c["function"]["name"].as_str().unwrap_or("").is_empty()).count();
        let calls: Vec<ToolCall> = tcs
            .iter()
            .enumerate()
            .filter_map(|(i, c)| {
                let name = c["function"]["name"].as_str().unwrap_or("");
                if name.is_empty() {
                    return None;
                }
                // Arguments is a STRING of JSON (OpenAI spec). An EMPTY
                // string is a param-less call (some providers send "" instead
                // of "{}") — treat it as the empty object, not as unusable.
                // A non-empty but unparseable string is genuine truncation.
                let args_str = c["function"]["arguments"].as_str().unwrap_or("").trim();
                let args: Value = if args_str.is_empty() {
                    Value::Object(Default::default())
                } else {
                    serde_json::from_str(args_str).ok()?
                };
                // Synthesize an id when the provider omits one, so two
                // parallel calls can't collapse to the same empty
                // tool_call_id on the result turn.
                let id = match c["id"].as_str().unwrap_or("") {
                    "" => format!("call_{name}_{i}"),
                    s => s.to_string(),
                };
                Some(ToolCall { id, name: name.to_string(), args })
            })
            .collect();
        // ALL named calls parsed cleanly — this wins outright, content is
        // never consulted (clean native beats any XML in content).
        if !calls.is_empty() && calls.len() == named {
            return (ChatStep { text: None, tool_calls: calls, usage }, ToolParse::Native);
        }
        // Some (or all) named calls were MALFORMED. The complete calls may be
        // the Hermes-XML in content, so consult it. Only prefer XML when it
        // recovers MORE calls than the native survivors.
        let xml_recovered = parse_hermes_tool_calls(content);
        if let Some(xml_calls) = &xml_recovered
            && xml_calls.len() > calls.len()
        {
            return (
                ChatStep { text: None, tool_calls: xml_calls.clone(), usage },
                ToolParse::XmlAfterMalformedNative,
            );
        }
        // XML didn't beat the survivors. If we DO have survivors, proceed
        // with them but tag the drop so it's counted and the WARN fires.
        if !calls.is_empty() {
            return (
                ChatStep { text: None, tool_calls: calls, usage },
                ToolParse::PartialDroppedNative,
            );
        }
        // No survivors and no bigger XML — fall through to whatever XML exists.
        if let Some(xml_calls) = xml_recovered {
            return (
                ChatStep { text: None, tool_calls: xml_calls, usage },
                ToolParse::XmlAfterMalformedNative,
            );
        }
        // Malformed native calls AND no XML to recover from — the tool call
        // is lost. Tag DroppedNative so the WARN fires; return the content as
        // text so the caller can still surface something.
        let text = content.trim();
        let text = if text.is_empty() { None } else { Some(text.to_string()) };
        return (ChatStep { text, tool_calls: Vec::new(), usage }, ToolParse::DroppedNative);
    }
    // No native tool_calls at all. The model may still have emitted a
    // Hermes-XML call in `content`; otherwise it's a plain text reply.
    if let Some(xml_calls) = parse_hermes_tool_calls(content) {
        return (ChatStep { text: None, tool_calls: xml_calls, usage }, ToolParse::XmlNoNative);
    }
    let text = content.trim();
    let text = if text.is_empty() { None } else { Some(text.to_string()) };
    (ChatStep { text, tool_calls: Vec::new(), usage }, ToolParse::Native)
}

/// Parse Hermes / Qwen-style XML tool calls that open models emit in the
/// message `content` instead of (or alongside a broken copy of) the OpenAI
/// `tool_calls` field. The shape is:
///   <tool_call>
///   <function=start_scan>
///   <parameter=target>remundo::prod::cluster</parameter>
///   </function>
///   </tool_call>
/// Returns None when no `<tool_call>` block is present. Best-effort and
/// tolerant of whitespace; values are taken verbatim and assembled into a
/// JSON object.
fn parse_hermes_tool_calls(content: &str) -> Option<Vec<ToolCall>> {
    if !content.contains("<tool_call>") {
        return None;
    }
    let mut calls = Vec::new();
    // Each <tool_call> ... </tool_call> block (tolerate a missing close at EOF).
    for block in content.split("<tool_call>").skip(1) {
        let block = block.split("</tool_call>").next().unwrap_or(block);
        // Function name: <function=NAME>
        let Some(name) = block
            .split_once("<function=")
            .and_then(|(_, rest)| rest.split_once('>').map(|(n, _)| n.trim()))
            .filter(|n| !n.is_empty())
        else {
            continue;
        };
        // Parameters: each <parameter=KEY>VALUE</parameter>. XML carries no
        // type, so every value arrives as a string. We deliberately do NOT
        // guess types here — type reconciliation happens schema-aware at
        // dispatch (the tools layer).
        let mut args = serde_json::Map::new();
        for piece in block.split("<parameter=").skip(1) {
            let Some((key, after)) = piece.split_once('>') else { continue };
            let value = after.split("</parameter>").next().unwrap_or("").trim();
            args.insert(key.trim().to_string(), Value::String(value.to_string()));
        }
        calls.push(ToolCall {
            // Open models rarely supply a call id; synthesize a stable-ish
            // one so the tool-result turn can reference it.
            id: format!("call_{}_{}", name, calls.len()),
            name: name.to_string(),
            args: Value::Object(args),
        });
    }
    if calls.is_empty() { None } else { Some(calls) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oai_function_puts_the_real_schema_under_parameters() {
        // The production outage: the model received tools with NO declared
        // parameters (the schema shipped under the wrong key) and guessed
        // argument names. Drive this from the ACTUAL neutral spec shape, so
        // a regression in either the tool layer or oai_function fails here.
        let spec = ToolSpec {
            name: "set_reminder".into(),
            description: "Set a reminder.".into(),
            parameters: json!({
                "type": "object",
                "properties": { "body": {"type":"string"}, "when": {"type":"string"} },
                "required": ["body", "when"]
            }),
        };
        let f = oai_function_for_test(&spec);
        assert_eq!(f["type"], "function");
        assert_eq!(f["function"]["name"], "set_reminder");
        assert_eq!(f["function"]["parameters"]["required"], json!(["body", "when"]));
        assert!(
            f["function"]["parameters"]["properties"].get("body").is_some(),
            "the real `body` parameter must reach the model"
        );
        assert!(f["function"].get("input_schema").is_none(), "input_schema must not be sent");
        assert!(f.get("input_schema").is_none());
    }

    #[test]
    fn oai_function_supplies_an_empty_schema_when_a_tool_has_no_params() {
        let spec = ToolSpec {
            name: "list_tasks".into(),
            description: "List tasks.".into(),
            parameters: Value::Null,
        };
        let f = oai_function_for_test(&spec);
        assert_eq!(f["function"]["parameters"], json!({ "type": "object", "properties": {} }));
    }

    #[test]
    fn parses_hermes_xml_tool_call_from_content() {
        let content = "<tool_call>\n<function=start_scan>\n\
            <parameter=target>remundo::prod::cluster</parameter>\n\
            <parameter=when>today</parameter>\n\
            </function>\n</tool_call>";
        let calls = parse_hermes_tool_calls(content).expect("a tool call");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "start_scan");
        assert_eq!(calls[0].args["target"], "remundo::prod::cluster");
        assert_eq!(calls[0].args["when"], "today");
    }

    #[test]
    fn parses_multiple_hermes_tool_calls() {
        let content = "<tool_call>\n<function=list_incidents>\n</function>\n</tool_call>\n\
            <tool_call>\n<function=list_incidents>\n</function>\n</tool_call>";
        let calls = parse_hermes_tool_calls(content).expect("two calls");
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|c| c.name == "list_incidents"));
        assert_ne!(calls[0].id, calls[1].id);
    }

    #[test]
    fn hermes_call_with_no_parameters() {
        let content = "<tool_call>\n<function=list_incidents>\n</function>\n</tool_call>";
        let calls = parse_hermes_tool_calls(content).expect("a call");
        assert_eq!(calls[0].name, "list_incidents");
        assert!(calls[0].args.as_object().unwrap().is_empty());
    }

    #[test]
    fn plain_text_is_not_a_tool_call() {
        assert!(parse_hermes_tool_calls("The scan found no issues.").is_none());
        assert!(parse_hermes_tool_calls("").is_none());
    }

    #[test]
    fn clean_native_tool_calls_win_and_content_is_ignored() {
        let msg = json!({
            "content": "Sure — calling <tool_call><function=other>...</tool_call> for you.",
            "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": { "name": "list_incidents", "arguments": "{\"limit\": 5}" }
            }]
        });
        let (step, parse) = interpret_tool_message(&msg, Default::default());
        assert_eq!(parse, ToolParse::Native, "a clean model must not hit the XML fallback");
        assert_eq!(step.tool_calls.len(), 1);
        assert_eq!(step.tool_calls[0].name, "list_incidents", "the NATIVE call wins, not the XML");
        assert_eq!(step.tool_calls[0].args["limit"], 5);
    }

    #[test]
    fn xml_fallback_only_fires_when_native_calls_are_unusable() {
        let msg = json!({
            "content": "<tool_call><function=list_incidents><parameter=limit>5</parameter></function></tool_call>",
            "tool_calls": [{
                "id": "c", "type": "function",
                "function": { "name": "list_incidents", "arguments": "{\"limit\": " }  // truncated
            }]
        });
        let (step, parse) = interpret_tool_message(&msg, Default::default());
        assert_eq!(parse, ToolParse::XmlAfterMalformedNative, "recovered from XML, and flagged it");
        assert_eq!(step.tool_calls[0].args["limit"], "5");

        let msg = json!({ "content": "The scan found no issues." });
        let (step, parse) = interpret_tool_message(&msg, Default::default());
        assert!(step.tool_calls.is_empty());
        assert_eq!(step.text.as_deref(), Some("The scan found no issues."));
        assert_eq!(parse, ToolParse::Native);
    }

    #[test]
    fn empty_arguments_string_is_treated_as_an_empty_object_not_dropped() {
        let msg = json!({
            "tool_calls": [{
                "id": "c1", "type": "function",
                "function": { "name": "list_incidents", "arguments": "" }
            }]
        });
        let (step, parse) = interpret_tool_message(&msg, Default::default());
        assert_eq!(parse, ToolParse::Native);
        assert_eq!(step.tool_calls.len(), 1, "the param-less call must not be dropped");
        assert_eq!(step.tool_calls[0].name, "list_incidents");
        assert!(step.tool_calls[0].args.is_object());
    }

    #[test]
    fn missing_native_id_is_synthesized_distinctly() {
        let msg = json!({
            "tool_calls": [
                { "type": "function", "function": { "name": "list_incidents", "arguments": "{}" } },
                { "type": "function", "function": { "name": "list_approvals", "arguments": "{}" } }
            ]
        });
        let (step, _) = interpret_tool_message(&msg, Default::default());
        assert_eq!(step.tool_calls.len(), 2);
        assert!(!step.tool_calls[0].id.is_empty() && !step.tool_calls[1].id.is_empty());
        assert_ne!(step.tool_calls[0].id, step.tool_calls[1].id);
    }

    #[test]
    fn malformed_native_with_no_xml_is_tagged_dropped_not_native() {
        let msg = json!({
            "content": "",
            "tool_calls": [{
                "id": "c", "type": "function",
                "function": { "name": "list_incidents", "arguments": "{\"limit\": " }  // truncated, no XML
            }]
        });
        let (step, parse) = interpret_tool_message(&msg, Default::default());
        assert_eq!(parse, ToolParse::DroppedNative, "a lost tool call must be visible, not silent");
        assert!(step.tool_calls.is_empty());
    }

    #[test]
    fn partial_malformed_parallel_calls_are_counted_not_silently_dropped() {
        let msg = json!({
            "content": "<tool_call><function=list_incidents><parameter=limit>5</parameter></function></tool_call>",
            "tool_calls": [
                { "id": "c1", "type": "function",
                  "function": { "name": "list_incidents", "arguments": "{\"limit\": 5}" } },
                { "id": "c2", "type": "function",
                  "function": { "name": "list_approvals", "arguments": "{\"state\": " } }  // truncated
            ]
        });
        let (step, parse) = interpret_tool_message(&msg, Default::default());
        assert_eq!(parse, ToolParse::PartialDroppedNative, "a dropped sibling must be observable");
        assert_eq!(step.tool_calls.len(), 1, "the healthy survivor is kept");
        assert_eq!(step.tool_calls[0].name, "list_incidents");

        // If the XML holds BOTH complete calls (more than the one native
        // survivor), it wins.
        let msg = json!({
            "content": "<tool_call><function=list_incidents><parameter=limit>5</parameter></function></tool_call>\
                        <tool_call><function=list_approvals><parameter=state>pending</parameter></function></tool_call>",
            "tool_calls": [
                { "id": "c1", "type": "function",
                  "function": { "name": "list_incidents", "arguments": "{\"limit\": 5}" } },
                { "id": "c2", "type": "function",
                  "function": { "name": "list_approvals", "arguments": "{\"state\": " } }  // truncated
            ]
        });
        let (step, parse) = interpret_tool_message(&msg, Default::default());
        assert_eq!(
            parse,
            ToolParse::XmlAfterMalformedNative,
            "XML wins when it recovers MORE calls"
        );
        assert_eq!(step.tool_calls.len(), 2, "both calls recovered from XML");
    }

    #[test]
    fn hermes_params_stay_verbatim_strings() {
        let content = "<tool_call>\n<function=list_incidents>\n\
            <parameter=limit>30</parameter>\n\
            <parameter=verbose>true</parameter>\n</function>\n</tool_call>";
        let calls = parse_hermes_tool_calls(content).unwrap();
        let a = &calls[0].args;
        assert_eq!(a["limit"].as_str(), Some("30"), "kept verbatim as a string");
        assert_eq!(a["verbose"].as_str(), Some("true"), "kept verbatim as a string");
    }

    fn provider_at(base_url: &str) -> OpenAiCompatProvider {
        OpenAiCompatProvider::new(base_url, "k", "m")
    }

    #[test]
    fn fallback_models_become_an_ordered_list_on_openrouter() {
        let p = OpenAiCompatProvider::new("https://openrouter.ai/api/v1", "k", "primary/model")
            .with_fallback_models(vec!["vendor/backup-1".into(), "vendor/backup-2".into()]);
        let mut body = json!({ "model": "primary/model" });
        p.apply_provider_quirks(&mut body);
        assert_eq!(body["models"], json!(["primary/model", "vendor/backup-1", "vendor/backup-2"]));
    }

    #[test]
    fn no_models_array_without_fallbacks_or_off_openrouter() {
        let p = OpenAiCompatProvider::new("https://openrouter.ai/api/v1", "k", "primary/model");
        let mut body = json!({ "model": "primary/model" });
        p.apply_provider_quirks(&mut body);
        assert!(body.get("models").is_none());

        let p = provider_at("https://api.openai.com/v1").with_fallback_models(vec!["a".into()]);
        let mut body = json!({ "model": "m" });
        p.apply_provider_quirks(&mut body);
        assert!(body.get("models").is_none(), "OpenAI rejects the models field");
    }

    #[test]
    fn openrouter_requests_disable_reasoning() {
        let p = provider_at("https://openrouter.ai/api/v1");
        let mut body = json!({ "model": "m" });
        p.apply_provider_quirks(&mut body);
        assert_eq!(body["reasoning"], json!({ "enabled": false }));
    }

    #[test]
    fn openai_requests_carry_no_reasoning_field() {
        let p = provider_at("https://api.openai.com/v1");
        let mut body = json!({ "model": "m" });
        p.apply_provider_quirks(&mut body);
        assert!(body.get("reasoning").is_none(), "OpenAI rejects unknown params");
    }

    #[test]
    fn openrouter_requests_provider_reported_usage() {
        let p = provider_at("https://openrouter.ai/api/v1");
        let mut body = json!({ "model": "m" });
        p.apply_provider_quirks(&mut body);
        assert_eq!(body["usage"], json!({ "include": true }));
    }
}
