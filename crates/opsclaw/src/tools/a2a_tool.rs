//! A2A client tool — send tasks to remote A2A-compliant agents.
//!
//! Implements the [`Tool`] trait so the LLM can invoke remote agents
//! via the A2A protocol (JSON-RPC 2.0 over HTTP).

use super::a2a_types::{A2aRequest, A2aResponse, AgentCard, Task};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::json;
use std::time::Duration;
use zeroclaw::tools::traits::{Tool, ToolResult};

/// HTTP client for the A2A protocol.
pub struct A2aClient {
    http: reqwest::Client,
}

impl A2aClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self { http }
    }

    /// Fetch the agent card from `{base_url}/.well-known/agent-card.json`.
    pub async fn discover(&self, base_url: &str) -> Result<AgentCard> {
        let url = format!(
            "{}/.well-known/agent-card.json",
            base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .context("failed to fetch agent card")?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("agent card request failed: HTTP {status}");
        }
        resp.json::<AgentCard>()
            .await
            .context("failed to parse agent card")
    }

    /// Send a task to the remote agent via `tasks/send`.
    pub async fn send_task(&self, base_url: &str, token: &str, message: &str) -> Result<Task> {
        let req = A2aRequest::new(
            "tasks/send",
            &uuid::Uuid::new_v4().to_string(),
            json!({ "message": message }),
        );
        self.rpc_call(base_url, token, &req).await
    }

    /// Get the status of a task via `tasks/get`.
    pub async fn get_task(&self, base_url: &str, token: &str, task_id: &str) -> Result<Task> {
        let req = A2aRequest::new(
            "tasks/get",
            &uuid::Uuid::new_v4().to_string(),
            json!({ "task_id": task_id }),
        );
        self.rpc_call(base_url, token, &req).await
    }

    /// Cancel a task via `tasks/cancel`.
    pub async fn cancel_task(&self, base_url: &str, token: &str, task_id: &str) -> Result<Task> {
        let req = A2aRequest::new(
            "tasks/cancel",
            &uuid::Uuid::new_v4().to_string(),
            json!({ "task_id": task_id }),
        );
        self.rpc_call(base_url, token, &req).await
    }

    async fn rpc_call(&self, base_url: &str, token: &str, req: &A2aRequest) -> Result<Task> {
        let url = format!("{}/a2a", base_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .json(req)
            .send()
            .await
            .context("A2A RPC call failed")?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("A2A RPC request failed: HTTP {status}");
        }

        let a2a_resp: A2aResponse = resp.json().await.context("failed to parse A2A response")?;
        if let Some(err) = a2a_resp.error {
            anyhow::bail!("A2A error {}: {}", err.code, err.message);
        }
        let result = a2a_resp.result.context("A2A response missing result")?;
        serde_json::from_value(result).context("failed to parse task from A2A result")
    }
}

/// Tool wrapper exposing A2A client capabilities to the LLM.
pub struct A2aTool {
    client: A2aClient,
}

impl A2aTool {
    pub fn new() -> Self {
        Self {
            client: A2aClient::new(),
        }
    }
}

#[async_trait]
impl Tool for A2aTool {
    fn name(&self) -> &str {
        "a2a"
    }

    fn description(&self) -> &str {
        "Communicate with remote A2A-compliant agents. Actions: discover (fetch agent card), \
         send (send a task), get (check task status), cancel (cancel a task)."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["discover", "send", "get", "cancel"],
                    "description": "The A2A action to perform"
                },
                "url": {
                    "type": "string",
                    "description": "Base URL of the remote A2A agent"
                },
                "token": {
                    "type": "string",
                    "description": "Bearer token for authentication"
                },
                "message": {
                    "type": "string",
                    "description": "Message to send (for 'send' action)"
                },
                "task_id": {
                    "type": "string",
                    "description": "Task ID (for 'get' and 'cancel' actions)"
                }
            },
            "required": ["action", "url"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let action = args["action"].as_str().unwrap_or_default();
        let url = args["url"].as_str().unwrap_or_default();

        if url.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("'url' parameter is required".into()),
            });
        }

        match action {
            "discover" => match self.client.discover(url).await {
                Ok(card) => Ok(ToolResult {
                    success: true,
                    output: serde_json::to_string_pretty(&card)
                        .unwrap_or_else(|_| format!("{card:?}")),
                    error: None,
                }),
                Err(e) => Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("discover failed: {e}")),
                }),
            },
            "send" => {
                let token = args["token"].as_str().unwrap_or_default();
                let message = args["message"].as_str().unwrap_or_default();
                if message.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("'message' parameter is required for send".into()),
                    });
                }
                match self.client.send_task(url, token, message).await {
                    Ok(task) => Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string_pretty(&task)
                            .unwrap_or_else(|_| format!("{task:?}")),
                        error: None,
                    }),
                    Err(e) => Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("send failed: {e}")),
                    }),
                }
            }
            "get" => {
                let token = args["token"].as_str().unwrap_or_default();
                let task_id = args["task_id"].as_str().unwrap_or_default();
                if task_id.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("'task_id' parameter is required for get".into()),
                    });
                }
                match self.client.get_task(url, token, task_id).await {
                    Ok(task) => Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string_pretty(&task)
                            .unwrap_or_else(|_| format!("{task:?}")),
                        error: None,
                    }),
                    Err(e) => Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("get failed: {e}")),
                    }),
                }
            }
            "cancel" => {
                let token = args["token"].as_str().unwrap_or_default();
                let task_id = args["task_id"].as_str().unwrap_or_default();
                if task_id.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("'task_id' parameter is required for cancel".into()),
                    });
                }
                match self.client.cancel_task(url, token, task_id).await {
                    Ok(task) => Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string_pretty(&task)
                            .unwrap_or_else(|_| format!("{task:?}")),
                        error: None,
                    }),
                    Err(e) => Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("cancel failed: {e}")),
                    }),
                }
            }
            _ => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "unknown action '{action}'; expected: discover, send, get, cancel"
                )),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a2a_client_constructs() {
        let _client = A2aClient::new();
    }

    #[test]
    fn a2a_tool_metadata() {
        let tool = A2aTool::new();
        assert_eq!(tool.name(), "a2a");
        assert!(!tool.description().is_empty());
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["action"].is_object());
        assert!(schema["properties"]["url"].is_object());
    }

    #[tokio::test]
    async fn a2a_tool_rejects_missing_url() {
        let tool = A2aTool::new();
        let result = tool
            .execute(json!({"action": "discover", "url": ""}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("url"));
    }

    #[tokio::test]
    async fn a2a_tool_rejects_unknown_action() {
        let tool = A2aTool::new();
        let result = tool
            .execute(json!({"action": "nope", "url": "http://localhost"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("unknown action"));
    }

    #[tokio::test]
    async fn a2a_tool_send_requires_message() {
        let tool = A2aTool::new();
        let result = tool
            .execute(json!({"action": "send", "url": "http://localhost", "token": "t"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("message"));
    }

    #[tokio::test]
    async fn a2a_tool_get_requires_task_id() {
        let tool = A2aTool::new();
        let result = tool
            .execute(json!({"action": "get", "url": "http://localhost", "token": "t"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("task_id"));
    }

    #[tokio::test]
    async fn a2a_tool_send_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/a2a"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {"id": "t-123", "status": "submitted"}
            })))
            .mount(&server)
            .await;
        let tool = A2aTool::new();
        let r = tool
            .execute(json!({
                "action": "send", "url": server.uri(),
                "token": "tok", "message": "hi"
            }))
            .await
            .unwrap();
        assert!(r.success, "error: {:?}", r.error);
        assert!(r.output.contains("t-123"));
    }

    #[tokio::test]
    async fn a2a_tool_send_server_500() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/a2a"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let tool = A2aTool::new();
        let r = tool
            .execute(json!({
                "action": "send", "url": server.uri(),
                "token": "tok", "message": "hi"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn a2a_tool_send_malformed_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/a2a"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not jsonrpc"))
            .mount(&server)
            .await;
        let tool = A2aTool::new();
        let r = tool
            .execute(json!({
                "action": "send", "url": server.uri(),
                "token": "tok", "message": "hi"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }
}
