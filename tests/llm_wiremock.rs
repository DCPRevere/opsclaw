//! Wiremock integration tests for the shipped model chain: `build_chain`
//! (dcpr-llm's OpenRouter client inside its `Fallback`) wrapped in the
//! `CostGuard`, exactly as boot wires it, against a local mock OpenRouter.
//! The client's own wire behaviour is dcpr-llm's to test; these pin what
//! OpsClaw configures on top of it and how spend reaches the daily cap.

use std::sync::Arc;

use opsclaw::config::{LlmCfg, SecretRef, SecretStore};
use opsclaw::db::Db;
use opsclaw::domain::Principal;
use opsclaw::llm::{ChatStep, CostGuard, Llm, SpendMeter, ToolTurn, build_chain};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The mock's path prefix. dcpr-llm applies OpenRouter's request options
/// only to an OpenRouter base URL, which it recognises by name.
const API: &str = "/openrouter/api/v1";

fn principal() -> Principal {
    Principal::Agent { job: None }
}

fn a_tool() -> Value {
    json!({
        "name": "list_incidents",
        "description": "List open incidents.",
        "parameters": {
            "type": "object",
            "properties": { "limit": { "type": "integer" } },
            "required": []
        }
    })
}

fn text_reply(text: &str, cost_usd: f64) -> Value {
    json!({
        "model": "vendor/primary",
        "choices": [{
            "message": { "role": "assistant", "content": text },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 100, "completion_tokens": 10, "cost": cost_usd }
    })
}

/// The chain plus the guard around it, wired the way `boot` wires them.
/// The key is resolved through the same `SecretRef::Env` path as
/// production config; each test uses its own variable.
fn shipped(server: &MockServer, key_var: &str, cap_cents: u32) -> (Arc<CostGuard>, Arc<Llm>) {
    unsafe { std::env::set_var(key_var, "sk-test") };
    let dir = tempfile::tempdir().unwrap();
    let store = SecretStore::open(dir.path()).unwrap();
    let cfg = LlmCfg {
        api_key: Some(SecretRef::env(key_var)),
        models: vec!["vendor/primary".into(), "vendor/backup".into()],
        base_url: Some(format!("{}{API}", server.uri())),
    };
    let meter = Arc::new(SpendMeter::new());
    let chain = build_chain(&cfg, &store, opsclaw::llm::pricing::priced(meter.clone())).unwrap();
    let guard = Arc::new(CostGuard::new(chain, meter, Db::fake().repos(), cap_cents));
    let llm: Arc<Llm> = guard.clone();
    (guard, llm)
}

async fn step(llm: &Llm) -> dcpr_llm::Result<ChatStep> {
    llm.chat_step(&principal(), "sys".into(), &[ToolTurn::User("hi".into())], &[a_tool()]).await
}

async fn only_request(server: &MockServer) -> Request {
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "expected exactly one request");
    requests.into_iter().next().unwrap()
}

#[tokio::test]
async fn shipped_chain_sends_openrouter_options_and_parses_tool_calls() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/chat/completions")))
        .and(header("authorization", "Bearer sk-test"))
        .and(header("http-referer", "https://opsclaw.dev"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "vendor/primary",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "list_incidents", "arguments": "{\"limit\": 5}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": { "prompt_tokens": 100, "completion_tokens": 10, "cost": 0.0 }
        })))
        .mount(&server)
        .await;

    let (_guard, llm) = shipped(&server, "OPSCLAW_WIRE_KEY_OPTIONS", 1_000);
    match step(llm.as_ref()).await.unwrap() {
        ChatStep::ToolCalls(calls) => {
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].name, "list_incidents");
            assert_eq!(calls[0].arguments, json!({"limit": 5}));
        }
        other => panic!("expected a tool call, got {other:?}"),
    }

    let body: Value = serde_json::from_slice(&only_request(&server).await.body).unwrap();
    assert_eq!(body["model"], "vendor/primary");
    assert_eq!(body["models"], json!(["vendor/primary", "vendor/backup"]));
    assert_eq!(body["provider"]["data_collection"], "deny");
    assert_eq!(body["reasoning"], json!({"enabled": false}));
    assert_eq!(body["max_tokens"], 16_384, "OpsClaw's tool-step output ceiling");
    assert_eq!(body["tools"][0]["type"], "function");
    assert_eq!(body["tools"][0]["function"]["name"], "list_incidents");
}

#[tokio::test]
async fn reported_cost_reaches_the_daily_cap() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/chat/completions")))
        // $0.03 per call = 3¢.
        .respond_with(ResponseTemplate::new(200).set_body_json(text_reply("ok", 0.03)))
        .mount(&server)
        .await;

    let (guard, llm) = shipped(&server, "OPSCLAW_WIRE_KEY_COST", 5);
    step(llm.as_ref()).await.unwrap();
    assert!((guard.spent_today_cents().await - 3.0).abs() < 1e-9);
    step(llm.as_ref()).await.unwrap(); // 6¢ spent: over the 5¢ cap
    let err = step(llm.as_ref()).await.unwrap_err();
    assert!(err.to_string().contains("cost cap"), "{err}");
    assert!(!err.is_retryable(), "the cap refusal must be hard");
    assert_eq!(server.received_requests().await.unwrap().len(), 2, "refused before the wire");
}

#[tokio::test]
async fn a_rate_limited_call_is_retried_and_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/chat/completions")))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1")
                .set_body_json(json!({"error": {"message": "rate limited", "code": 429}})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/chat/completions")))
        .respond_with(ResponseTemplate::new(200).set_body_json(text_reply("recovered", 0.0)))
        .mount(&server)
        .await;

    let (_guard, llm) = shipped(&server, "OPSCLAW_WIRE_KEY_RETRY", 1_000);
    match step(llm.as_ref()).await.unwrap() {
        ChatStep::Text(text) => assert_eq!(text, "recovered"),
        other => panic!("expected text, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_context_overflow_fails_fast_without_retrying() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/chat/completions")))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": { "message": "This model's maximum context length is 8192 tokens", "code": 400 }
        })))
        .mount(&server)
        .await;

    let (_guard, llm) = shipped(&server, "OPSCLAW_WIRE_KEY_OVERFLOW", 1_000);
    let err = step(llm.as_ref()).await.unwrap_err();
    assert!(err.is_context_overflow(), "{err}");
    only_request(&server).await;
}
