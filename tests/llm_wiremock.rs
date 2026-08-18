//! Wiremock integration tests for the llm/ port: real HTTP wire shapes for
//! `AnthropicProvider` and `OpenAiCompatProvider`, retry/backoff behaviour,
//! fallback ordering, context-overflow fast-fail, and Hermes-XML recovery —
//! all driven through `FallbackLlm`/the providers against a local mock
//! server, never a real network call. Ported/adapted from gianna's provider
//! test style (gianna itself had no dedicated wiremock LLM suite file; these
//! assertions mirror what its `llm_providers/{anthropic,openai_compat}.rs`
//! unit tests and `fallback.rs` covered, exercised here over real HTTP).

use std::sync::Arc;

use opsclaw::domain::Principal;
use opsclaw::llm::{
    AnthropicAuth, AnthropicProvider, FallbackLlm, LlmProvider, OpenAiCompatProvider, ToolSpec,
    Turn,
};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn principal() -> Principal {
    Principal::Agent { job: None }
}

fn a_tool() -> ToolSpec {
    ToolSpec {
        name: "list_incidents".into(),
        description: "List open incidents.".into(),
        parameters: json!({
            "type": "object",
            "properties": { "limit": { "type": "integer" } },
            "required": []
        }),
    }
}

// ---------------------------------------------------------------------
// Anthropic wire shape
// ---------------------------------------------------------------------

#[tokio::test]
async fn anthropic_sends_input_schema_and_x_api_key_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "test-key"))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{ "type": "text", "text": "no incidents open" }],
            "usage": { "input_tokens": 100, "output_tokens": 20 },
            "stop_reason": "end_turn",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        AnthropicProvider::new(AnthropicAuth::ApiKey("test-key".into()), "claude-haiku-4-5")
            .with_url(format!("{}/v1/messages", server.uri()));

    let step = provider
        .chat_step(
            &principal(),
            "system prompt",
            &[Turn::User { content: "status?".into() }],
            &[a_tool()],
        )
        .await
        .unwrap();
    assert_eq!(step.text.as_deref(), Some("no incidents open"));
    assert_eq!(step.usage.input_tokens, 100);
    assert_eq!(step.usage.output_tokens, 20);
}

#[tokio::test]
async fn anthropic_reshapes_tool_spec_to_input_schema_on_the_wire() {
    let server = MockServer::start().await;
    // Assert the EXACT tool shape the request body carries: `input_schema`,
    // never an OpenAI-shaped `parameters` key. This is the outage gianna
    // shipped — pin the real wire body, not just the unit-level reshape fn.
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let tool = &body["tools"][0];
            assert_eq!(tool["name"], "list_incidents");
            assert!(tool.get("input_schema").is_some(), "input_schema must be present: {tool}");
            assert!(
                tool.get("parameters").is_none(),
                "parameters must not leak onto the wire: {tool}"
            );
            ResponseTemplate::new(200).set_body_json(json!({
                "content": [{ "type": "text", "text": "ok" }],
                "usage": { "input_tokens": 1, "output_tokens": 1 },
            }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = AnthropicProvider::new(AnthropicAuth::ApiKey("k".into()), "claude-haiku-4-5")
        .with_url(format!("{}/v1/messages", server.uri()));
    provider.chat_step(&principal(), "sys", &[], &[a_tool()]).await.unwrap();
}

#[tokio::test]
async fn anthropic_parses_tool_use_blocks_into_tool_calls() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{
                "type": "tool_use", "id": "toolu_1", "name": "list_incidents", "input": { "limit": 5 }
            }],
            "usage": { "input_tokens": 10, "output_tokens": 5 },
        })))
        .mount(&server)
        .await;

    let provider = AnthropicProvider::new(AnthropicAuth::ApiKey("k".into()), "claude-haiku-4-5")
        .with_url(format!("{}/v1/messages", server.uri()));
    let step = provider.chat_step(&principal(), "sys", &[], &[a_tool()]).await.unwrap();
    assert_eq!(step.tool_calls.len(), 1);
    assert_eq!(step.tool_calls[0].name, "list_incidents");
    assert_eq!(step.tool_calls[0].args["limit"], 5);
    assert!(step.text.is_none());
}

// ---------------------------------------------------------------------
// OpenAI-compat wire shape
// ---------------------------------------------------------------------

#[tokio::test]
async fn openai_compat_sends_function_tools_and_bearer_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let tool = &body["tools"][0];
            assert_eq!(tool["type"], "function");
            assert_eq!(tool["function"]["name"], "list_incidents");
            assert!(
                tool["function"]["parameters"]["properties"].get("limit").is_some(),
                "schema must land under function.parameters: {tool}"
            );
            ResponseTemplate::new(200).set_body_json(json!({
                "model": "vendor/model",
                "choices": [{ "message": { "content": "all clear" }, "finish_reason": "stop" }],
                "usage": { "prompt_tokens": 50, "completion_tokens": 10 },
            }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = OpenAiCompatProvider::new(server.uri(), "test-key", "vendor/model");
    let step = provider.chat_step(&principal(), "sys", &[], &[a_tool()]).await.unwrap();
    assert_eq!(step.text.as_deref(), Some("all clear"));
    assert_eq!(step.usage.input_tokens, 50);
    assert_eq!(step.usage.output_tokens, 10);
}

#[tokio::test]
async fn openai_compat_preserves_an_embedded_error_from_an_http_200() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).insert_header("retry-after", "11").set_body_json(
            json!({
                "error": {
                    "code": 429,
                    "message": "upstream capacity exhausted"
                }
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let provider = OpenAiCompatProvider::new(server.uri(), "test-key", "vendor/model");
    let error = provider.chat_step(&principal(), "sys", &[], &[a_tool()]).await.unwrap_err();
    assert!(error.is_retryable());
    assert_eq!(error.llm_retry_after_secs(), Some(11));
    assert!(error.to_string().contains("embedded error 429"));
}

#[tokio::test]
async fn openrouter_base_url_disables_reasoning_and_requests_cost() {
    let server = MockServer::start().await;
    // The base_url must literally contain "openrouter" for the quirks to
    // fire; point the mock at a path that satisfies that substring check.
    Mock::given(method("POST"))
        .and(path("/openrouter/chat/completions"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["reasoning"], json!({ "enabled": false }));
            assert_eq!(body["usage"], json!({ "include": true }));
            ResponseTemplate::new(200).set_body_json(json!({
                "model": "vendor/model",
                "choices": [{ "message": { "content": "ok" }, "finish_reason": "stop" }],
                "usage": { "prompt_tokens": 1, "completion_tokens": 1, "cost": 0.0035 },
            }))
        })
        .mount(&server)
        .await;

    let base = format!("{}/openrouter", server.uri());
    let provider = OpenAiCompatProvider::new(base, "k", "vendor/model");
    let step = provider.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
    // Provider-reported cost (usage.cost, USD) wins over the price table:
    // 0.0035 USD == 0.35 cents.
    assert!((step.usage.cost_cents.unwrap() - 0.35).abs() < 1e-9);
}

#[tokio::test]
async fn openai_compat_recovers_hermes_xml_when_native_tool_calls_are_truncated() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": "<tool_call><function=list_incidents><parameter=limit>5</parameter></function></tool_call>",
                    "tool_calls": [{
                        "id": "c1", "type": "function",
                        "function": { "name": "list_incidents", "arguments": "{\"limit\": " }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1 },
        })))
        .mount(&server)
        .await;

    let provider = OpenAiCompatProvider::new(server.uri(), "k", "vendor/model");
    let step = provider.chat_step(&principal(), "sys", &[], &[a_tool()]).await.unwrap();
    assert_eq!(step.tool_calls.len(), 1);
    assert_eq!(step.tool_calls[0].name, "list_incidents");
    assert_eq!(step.tool_calls[0].args["limit"], "5", "recovered from the Hermes XML in content");
}

// ---------------------------------------------------------------------
// FallbackLlm: retry/backoff counts, fallthrough ordering, context-overflow
// ---------------------------------------------------------------------

#[tokio::test]
async fn fallback_retries_a_429_with_retry_after_then_succeeds_on_same_provider() {
    let server = MockServer::start().await;
    // First response: 429 with Retry-After: 0 (so the test doesn't actually
    // wait out a multi-second jittered backoff). Second: success.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string(r#"{"error":{"message":"rate limited"}}"#),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "content": "recovered" }, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1 },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = Arc::new(OpenAiCompatProvider::new(server.uri(), "k", "vendor/model"));
    let chain = FallbackLlm::new(vec![provider]);
    let step = chain.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
    assert_eq!(step.text.as_deref(), Some("recovered"));
    // Both mocks' `.expect(1)` are verified on server drop / explicit
    // verify(); reaching here already proves exactly 2 calls were made (the
    // first mock only matches once via up_to_n_times).
    server.verify().await;
}

#[tokio::test]
async fn fallback_falls_through_to_next_provider_on_a_hard_401() {
    let bad = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(401).set_body_string(r#"{"error":{"message":"bad key"}}"#),
        )
        .expect(1)
        .mount(&bad)
        .await;

    let good = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "content": "from the good provider" }, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1 },
        })))
        .expect(1)
        .mount(&good)
        .await;

    let p1 = Arc::new(OpenAiCompatProvider::new(bad.uri(), "k", "bad/model"));
    let p2 = Arc::new(OpenAiCompatProvider::new(good.uri(), "k", "good/model"));
    let chain = FallbackLlm::new(vec![p1, p2]);
    let step = chain.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
    assert_eq!(step.text.as_deref(), Some("from the good provider"));
    bad.verify().await;
    good.verify().await;
}

#[tokio::test]
async fn fallback_fails_fast_on_context_overflow_never_touching_the_next_provider() {
    let overflow = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            r#"{"error":{"message":"This model's maximum context length is 8192 tokens."}}"#,
        ))
        .expect(1)
        .mount(&overflow)
        .await;

    let never_called = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "content": "should never be reached" }, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1 },
        })))
        .expect(0)
        .mount(&never_called)
        .await;

    let p1 = Arc::new(OpenAiCompatProvider::new(overflow.uri(), "k", "big/model"));
    let p2 = Arc::new(OpenAiCompatProvider::new(never_called.uri(), "k", "backup/model"));
    let chain = FallbackLlm::new(vec![p1, p2]);
    let err = chain.chat_step(&principal(), "sys", &[], &[]).await.unwrap_err();
    assert!(err.is_context_overflow(), "{err}");
    overflow.verify().await;
    never_called.verify().await;
}
