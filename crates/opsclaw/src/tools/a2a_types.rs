//! A2A (Agent-to-Agent) protocol types per the A2A spec v0.3.0+.
//!
//! Defines JSON-RPC 2.0 message types, agent card, task lifecycle,
//! and artifact structures for inter-agent communication.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Agent Card published at `/.well-known/agent-card.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct AgentCard {
    pub name: String,
    pub description: String,
    pub url: String,
    pub skills: Vec<AgentSkill>,
    pub auth: AgentAuth,
    pub version: String,
}

/// A capability advertised by an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct AgentSkill {
    pub name: String,
    pub description: String,
}

/// Authentication scheme required by the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct AgentAuth {
    pub scheme: String,
}

/// JSON-RPC 2.0 request envelope for A2A.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct A2aRequest {
    pub jsonrpc: String,
    pub method: String,
    pub id: String,
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response envelope for A2A.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct A2aResponse {
    pub jsonrpc: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<A2aError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct A2aError {
    pub code: i32,
    pub message: String,
}

/// A task managed by the A2A protocol.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Task {
    pub id: String,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
}

/// Lifecycle status of an A2A task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Submitted,
    Working,
    Completed,
    Failed,
    Cancelled,
}

/// An artifact produced by a task.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Artifact {
    pub name: String,
    pub content: String,
    pub mime_type: String,
}

// ── JSON-RPC helpers ────────────────────────────────────────────

impl A2aRequest {
    pub fn new(method: &str, id: &str, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            id: id.to_string(),
            params,
        }
    }
}

impl A2aResponse {
    pub fn success(id: &str, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.to_string(),
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: &str, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.to_string(),
            result: None,
            error: Some(A2aError {
                code,
                message: message.to_string(),
            }),
        }
    }
}

// ── Standard JSON-RPC error codes ───────────────────────────────

pub const JSONRPC_PARSE_ERROR: i32 = -32700;
pub const JSONRPC_INVALID_REQUEST: i32 = -32600;
pub const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
pub const JSONRPC_INVALID_PARAMS: i32 = -32602;
pub const JSONRPC_INTERNAL_ERROR: i32 = -32603;

/// Application-level: task not found.
pub const A2A_TASK_NOT_FOUND: i32 = -32000;
/// Application-level: unauthorized.
pub const A2A_UNAUTHORIZED: i32 = -32001;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_card_roundtrip() {
        let card = AgentCard {
            name: "test-agent".into(),
            description: "A test agent".into(),
            url: "https://example.com".into(),
            skills: vec![AgentSkill {
                name: "echo".into(),
                description: "Echoes input".into(),
            }],
            auth: AgentAuth {
                scheme: "bearer".into(),
            },
            version: "0.3.0".into(),
        };
        let json = serde_json::to_string(&card).unwrap();
        let parsed: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(card, parsed);
    }

    #[test]
    fn a2a_request_jsonrpc_format() {
        let req = A2aRequest::new(
            "tasks/send",
            "req-1",
            serde_json::json!({"message": "hello"}),
        );
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "tasks/send");
        assert_eq!(json["id"], "req-1");
        assert_eq!(json["params"]["message"], "hello");
    }

    #[test]
    fn a2a_response_success_format() {
        let resp = A2aResponse::success("req-1", serde_json::json!({"task_id": "t1"}));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], "req-1");
        assert!(json["result"].is_object());
        assert!(json.get("error").is_none());
    }

    #[test]
    fn a2a_response_error_format() {
        let resp = A2aResponse::error("req-1", JSONRPC_METHOD_NOT_FOUND, "method not found");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["error"]["code"], -32601);
        assert_eq!(json["error"]["message"], "method not found");
        assert!(json.get("result").is_none());
    }

    #[test]
    fn task_status_serde() {
        let task = Task {
            id: "t1".into(),
            status: TaskStatus::Submitted,
            message: Some("do something".into()),
            artifacts: vec![],
        };
        let json = serde_json::to_string(&task).unwrap();
        assert!(json.contains("\"submitted\""));
        let parsed: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, TaskStatus::Submitted);
    }

    #[test]
    fn task_with_artifacts_roundtrip() {
        let task = Task {
            id: "t2".into(),
            status: TaskStatus::Completed,
            message: None,
            artifacts: vec![Artifact {
                name: "result.txt".into(),
                content: "hello world".into(),
                mime_type: "text/plain".into(),
            }],
        };
        let json = serde_json::to_string(&task).unwrap();
        let parsed: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.artifacts.len(), 1);
        assert_eq!(parsed.artifacts[0].name, "result.txt");
    }
}
