//! A2A inbound server — receives tasks from remote A2A agents.
//!
//! Provides a lightweight axum HTTP server with:
//! - `GET /.well-known/agent-card.json` — auto-generated agent card
//! - `POST /a2a` — JSON-RPC 2.0 endpoint for task lifecycle

use super::a2a_types::*;
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

/// Re-export from zeroclaw config (canonical definition lives there for schema generation).
pub use zeroclaw::config::schema::A2aServerConfig;

/// Shared state for the A2A server.
#[derive(Clone)]
struct A2aState {
    config: A2aServerConfig,
    tasks: Arc<Mutex<HashMap<String, Task>>>,
}

/// Start the A2A server. Blocks until the server shuts down.
pub async fn run_a2a_server(config: A2aServerConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .context("invalid A2A server bind address")?;

    let state = A2aState {
        config,
        tasks: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/.well-known/agent-card.json", get(handle_agent_card))
        .route("/a2a", post(handle_a2a_rpc))
        .with_state(state);

    tracing::info!("A2A server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("A2A server error")
}

// ── Handlers ────────────────────────────────────────────────────

async fn handle_agent_card(State(state): State<A2aState>) -> impl IntoResponse {
    let card = AgentCard {
        name: state.config.agent_name.clone(),
        description: state.config.agent_description.clone(),
        url: format!("http://{}:{}", state.config.bind, state.config.port),
        skills: state
            .config
            .skills
            .iter()
            .map(|s| AgentSkill {
                name: s.name.clone(),
                description: s.description.clone(),
            })
            .collect(),
        auth: AgentAuth {
            scheme: "bearer".to_string(),
        },
        version: "0.3.0".to_string(),
    };
    Json(card)
}

async fn handle_a2a_rpc(
    State(state): State<A2aState>,
    headers: HeaderMap,
    Json(req): Json<A2aRequest>,
) -> impl IntoResponse {
    // Validate bearer token
    if !state.config.token.is_empty() {
        let authorized = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map_or(false, |t| constant_time_eq(t, &state.config.token));

        if !authorized {
            let resp = A2aResponse::error(&req.id, A2A_UNAUTHORIZED, "unauthorized");
            return (StatusCode::UNAUTHORIZED, Json(resp));
        }
    }

    let resp = match req.method.as_str() {
        "tasks/send" => handle_tasks_send(&state, &req),
        "tasks/get" => handle_tasks_get(&state, &req),
        "tasks/cancel" => handle_tasks_cancel(&state, &req),
        _ => A2aResponse::error(&req.id, JSONRPC_METHOD_NOT_FOUND, "method not found"),
    };

    let status = if resp.error.is_some() {
        StatusCode::OK // JSON-RPC errors are still 200
    } else {
        StatusCode::OK
    };
    (status, Json(resp))
}

fn handle_tasks_send(state: &A2aState, req: &A2aRequest) -> A2aResponse {
    let message = req.params.get("message").and_then(|v| v.as_str());
    let task = Task {
        id: Uuid::new_v4().to_string(),
        status: TaskStatus::Submitted,
        message: message.map(String::from),
        artifacts: Vec::new(),
    };

    state.tasks.lock().insert(task.id.clone(), task.clone());
    tracing::info!(task_id = %task.id, "A2A task submitted");

    A2aResponse::success(&req.id, serde_json::to_value(&task).unwrap_or_default())
}

fn handle_tasks_get(state: &A2aState, req: &A2aRequest) -> A2aResponse {
    let task_id = req
        .params
        .get("task_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if task_id.is_empty() {
        return A2aResponse::error(&req.id, JSONRPC_INVALID_PARAMS, "missing task_id");
    }

    let tasks = state.tasks.lock();
    match tasks.get(task_id) {
        Some(task) => A2aResponse::success(&req.id, serde_json::to_value(task).unwrap_or_default()),
        None => A2aResponse::error(&req.id, A2A_TASK_NOT_FOUND, "task not found"),
    }
}

fn handle_tasks_cancel(state: &A2aState, req: &A2aRequest) -> A2aResponse {
    let task_id = req
        .params
        .get("task_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if task_id.is_empty() {
        return A2aResponse::error(&req.id, JSONRPC_INVALID_PARAMS, "missing task_id");
    }

    let mut tasks = state.tasks.lock();
    match tasks.get_mut(task_id) {
        Some(task) => {
            task.status = TaskStatus::Cancelled;
            tracing::info!(task_id, "A2A task cancelled");
            A2aResponse::success(&req.id, serde_json::to_value(&*task).unwrap_or_default())
        }
        None => A2aResponse::error(&req.id, A2A_TASK_NOT_FOUND, "task not found"),
    }
}

/// Constant-time string comparison to prevent timing attacks on token validation.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_config() -> A2aServerConfig {
        A2aServerConfig {
            enabled: true,
            port: 0,
            bind: "127.0.0.1".into(),
            token: "test-token".into(),
            agent_name: "TestAgent".into(),
            agent_description: "A test agent".into(),
            skills: vec![AgentSkill {
                name: "echo".into(),
                description: "Echoes input".into(),
            }],
        }
    }

    fn test_app() -> Router {
        let state = A2aState {
            config: test_config(),
            tasks: Arc::new(Mutex::new(HashMap::new())),
        };
        Router::new()
            .route("/.well-known/agent-card.json", get(handle_agent_card))
            .route("/a2a", post(handle_a2a_rpc))
            .with_state(state)
    }

    #[tokio::test]
    async fn agent_card_endpoint() {
        let app = test_app();
        let req = Request::builder()
            .uri("/.well-known/agent-card.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .unwrap();
        let card: AgentCard = serde_json::from_slice(&body).unwrap();
        assert_eq!(card.name, "TestAgent");
        assert_eq!(card.auth.scheme, "bearer");
        assert_eq!(card.skills.len(), 1);
    }

    #[tokio::test]
    async fn unauthorized_without_token() {
        let app = test_app();
        let rpc = A2aRequest::new("tasks/send", "r1", serde_json::json!({"message": "hi"}));
        let req = Request::builder()
            .method("POST")
            .uri("/a2a")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&rpc).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn task_lifecycle_submit_get_cancel() {
        let state = A2aState {
            config: test_config(),
            tasks: Arc::new(Mutex::new(HashMap::new())),
        };
        let app = Router::new()
            .route("/.well-known/agent-card.json", get(handle_agent_card))
            .route("/a2a", post(handle_a2a_rpc))
            .with_state(state);

        // Submit
        let rpc = A2aRequest::new("tasks/send", "r1", serde_json::json!({"message": "hello"}));
        let req = Request::builder()
            .method("POST")
            .uri("/a2a")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer test-token")
            .body(Body::from(serde_json::to_string(&rpc).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .unwrap();
        let a2a_resp: A2aResponse = serde_json::from_slice(&body).unwrap();
        assert!(a2a_resp.error.is_none());
        let task: Task = serde_json::from_value(a2a_resp.result.unwrap()).unwrap();
        assert_eq!(task.status, TaskStatus::Submitted);
        let task_id = task.id.clone();

        // Get
        let rpc = A2aRequest::new("tasks/get", "r2", serde_json::json!({"task_id": task_id}));
        let req = Request::builder()
            .method("POST")
            .uri("/a2a")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer test-token")
            .body(Body::from(serde_json::to_string(&rpc).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .unwrap();
        let a2a_resp: A2aResponse = serde_json::from_slice(&body).unwrap();
        let task: Task = serde_json::from_value(a2a_resp.result.unwrap()).unwrap();
        assert_eq!(task.status, TaskStatus::Submitted);

        // Cancel
        let rpc = A2aRequest::new(
            "tasks/cancel",
            "r3",
            serde_json::json!({"task_id": task_id}),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/a2a")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer test-token")
            .body(Body::from(serde_json::to_string(&rpc).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .unwrap();
        let a2a_resp: A2aResponse = serde_json::from_slice(&body).unwrap();
        let task: Task = serde_json::from_value(a2a_resp.result.unwrap()).unwrap();
        assert_eq!(task.status, TaskStatus::Cancelled);

        // Get after cancel
        let rpc = A2aRequest::new("tasks/get", "r4", serde_json::json!({"task_id": task_id}));
        let req = Request::builder()
            .method("POST")
            .uri("/a2a")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer test-token")
            .body(Body::from(serde_json::to_string(&rpc).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .unwrap();
        let a2a_resp: A2aResponse = serde_json::from_slice(&body).unwrap();
        let task: Task = serde_json::from_value(a2a_resp.result.unwrap()).unwrap();
        assert_eq!(task.status, TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn method_not_found() {
        let app = test_app();
        let rpc = A2aRequest::new("tasks/unknown", "r1", serde_json::json!({}));
        let req = Request::builder()
            .method("POST")
            .uri("/a2a")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer test-token")
            .body(Body::from(serde_json::to_string(&rpc).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .unwrap();
        let a2a_resp: A2aResponse = serde_json::from_slice(&body).unwrap();
        assert!(a2a_resp.error.is_some());
        assert_eq!(a2a_resp.error.unwrap().code, JSONRPC_METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn task_not_found() {
        let app = test_app();
        let rpc = A2aRequest::new(
            "tasks/get",
            "r1",
            serde_json::json!({"task_id": "nonexistent"}),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/a2a")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer test-token")
            .body(Body::from(serde_json::to_string(&rpc).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .unwrap();
        let a2a_resp: A2aResponse = serde_json::from_slice(&body).unwrap();
        assert!(a2a_resp.error.is_some());
        assert_eq!(a2a_resp.error.unwrap().code, A2A_TASK_NOT_FOUND);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn default_config() {
        let cfg = A2aServerConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.port, 42618);
        assert_eq!(cfg.bind, "127.0.0.1");
    }
}
