//! Elasticsearch / OpenSearch query tool. Read-only: search, count,
//! indices, health.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

const MAX_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct ElkEndpoint {
    pub name: String,
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_key: Option<String>,
    pub default_index: Option<String>,
}

pub struct ElkTool {
    endpoints: HashMap<String, ElkEndpoint>,
    client: reqwest::Client,
}

impl ElkTool {
    pub fn new(endpoints: Vec<ElkEndpoint>) -> Self {
        let map = endpoints.into_iter().map(|e| (e.name.clone(), e)).collect();
        Self {
            endpoints: map,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    fn endpoint_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.endpoints.keys().cloned().collect();
        v.sort();
        v
    }

    fn apply_auth(
        &self,
        req: reqwest::RequestBuilder,
        ep: &ElkEndpoint,
    ) -> reqwest::RequestBuilder {
        if let Some(key) = &ep.api_key {
            req.header("Authorization", format!("ApiKey {key}"))
        } else if let (Some(u), Some(p)) = (&ep.username, &ep.password) {
            req.basic_auth(u, Some(p))
        } else if let Some(u) = &ep.username {
            req.basic_auth(u, None::<&str>)
        } else {
            req
        }
    }
}

#[async_trait]
impl Tool for ElkTool {
    fn name(&self) -> &str {
        "elk"
    }

    fn description(&self) -> &str {
        "Query Elasticsearch / OpenSearch. action=search (Lucene 'query' or \
         raw 'body'), count, indices, or health. Read-only. Returns compact \
         text, not raw JSON."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "action": {"type": "string", "enum": ["search", "count", "indices", "health"]},
                "index": {"type": "string"},
                "query": {"type": "string", "description": "Lucene query string"},
                "body": {"type": "object", "description": "Raw Query DSL body"},
                "size": {"type": "integer", "default": 20},
                "from": {"type": "integer", "default": 0},
                "sort": {"type": "string", "description": "e.g. @timestamp:desc"},
                "fields": {"type": "string", "description": "comma-separated fields for _source filtering"}
            },
            "required": ["endpoint", "action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let endpoint_name = match args.get("endpoint").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("missing 'endpoint' parameter".into()),
                });
            }
        };
        let endpoint = match self.endpoints.get(endpoint_name) {
            Some(e) => e,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "unknown endpoint '{endpoint_name}'. Available: {}",
                        self.endpoint_names().join(", ")
                    )),
                });
            }
        };

        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("missing 'action'".into()),
                });
            }
        };

        let base = endpoint.url.trim_end_matches('/').to_string();

        let (req, kind) = match action {
            "search" | "count" => {
                let index = args
                    .get("index")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| endpoint.default_index.clone())
                    .unwrap_or_else(|| "_all".into());
                let suffix = if action == "search" {
                    "_search"
                } else {
                    "_count"
                };
                let url = format!("{base}/{index}/{suffix}");

                let mut final_body = if let Some(b) = args.get("body") {
                    b.clone()
                } else if let Some(q) = args.get("query").and_then(|v| v.as_str()) {
                    json!({"query": {"query_string": {"query": q}}})
                } else {
                    json!({"query": {"match_all": {}}})
                };

                if action == "search" {
                    let size = args
                        .get("size")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(20)
                        .min(500);
                    let from = args.get("from").and_then(|v| v.as_u64()).unwrap_or(0);
                    if let Some(obj) = final_body.as_object_mut() {
                        obj.entry("size").or_insert(json!(size));
                        if from > 0 {
                            obj.insert("from".into(), json!(from));
                        }
                        if let Some(fields) = args.get("fields").and_then(|v| v.as_str()) {
                            let list: Vec<&str> = fields.split(',').map(str::trim).collect();
                            obj.insert("_source".into(), json!(list));
                        }
                    }
                }

                let mut req = self
                    .client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&final_body);
                if action == "search" {
                    if let Some(sort) = args.get("sort").and_then(|v| v.as_str()) {
                        req = req.query(&[("sort", sort)]);
                    }
                }
                (self.apply_auth(req, endpoint), action)
            }
            "indices" => {
                let url = format!("{base}/_cat/indices");
                let req = self.client.get(&url).query(&[
                    ("format", "json"),
                    ("h", "index,docs.count,store.size,health"),
                ]);
                (self.apply_auth(req, endpoint), "indices")
            }
            "health" => {
                let url = format!("{base}/_cluster/health");
                let req = self.client.get(&url);
                (self.apply_auth(req, endpoint), "health")
            }
            other => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("unknown action '{other}'")),
                });
            }
        };

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("request failed: {e}")),
                });
            }
        };
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let snippet = &body_text[..body_text.len().min(500)];
            let tag = if status == 401 || status == 403 {
                "auth"
            } else {
                "query"
            };
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("[{tag}] {status}: {snippet}")),
            });
        }

        let rendered = match kind {
            "search" => render_search(&body_text),
            "count" => render_count(&body_text),
            "indices" => render_indices(&body_text),
            "health" => render_health(&body_text),
            _ => body_text,
        };

        Ok(ToolResult {
            success: true,
            output: truncate(rendered),
            error: None,
        })
    }
}

fn render_search(body: &str) -> String {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };
    let mut out = String::new();
    let total = v
        .get("hits")
        .and_then(|h| h.get("total"))
        .and_then(|t| {
            t.get("value")
                .and_then(|x| x.as_u64())
                .or_else(|| t.as_u64())
        })
        .unwrap_or(0);
    writeln!(out, "total_hits: {total}").ok();
    if let Some(hits) = v
        .get("hits")
        .and_then(|h| h.get("hits"))
        .and_then(|h| h.as_array())
    {
        for h in hits {
            let src = h.get("_source").cloned().unwrap_or(Value::Null);
            let ts = src.get("@timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let compact = serde_json::to_string(&src).unwrap_or_default();
            let truncated: String = compact.chars().take(200).collect();
            writeln!(out, "  {ts} {truncated}").ok();
        }
    }
    out
}

fn render_count(body: &str) -> String {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };
    let count = v.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
    format!("count: {count}\n")
}

fn render_indices(body: &str) -> String {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };
    let mut out = String::new();
    writeln!(out, "INDEX\tDOCS\tSIZE\tHEALTH").ok();
    if let Some(arr) = v.as_array() {
        for row in arr {
            let index = row.get("index").and_then(|v| v.as_str()).unwrap_or("");
            let docs = row.get("docs.count").and_then(|v| v.as_str()).unwrap_or("");
            let size = row.get("store.size").and_then(|v| v.as_str()).unwrap_or("");
            let health = row.get("health").and_then(|v| v.as_str()).unwrap_or("");
            writeln!(out, "{index}\t{docs}\t{size}\t{health}").ok();
        }
    }
    out
}

fn render_health(body: &str) -> String {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };
    let mut out = String::new();
    for key in [
        "cluster_name",
        "status",
        "number_of_nodes",
        "active_shards",
        "unassigned_shards",
        "relocating_shards",
        "initializing_shards",
    ] {
        if let Some(val) = v.get(key) {
            writeln!(out, "{key}: {val}").ok();
        }
    }
    out
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_OUTPUT_BYTES {
        let mut cut = MAX_OUTPUT_BYTES;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n... [truncated]");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tool_for(
        server: &MockServer,
        user: Option<&str>,
        pass: Option<&str>,
        key: Option<&str>,
    ) -> ElkTool {
        ElkTool::new(vec![ElkEndpoint {
            name: "test".into(),
            url: server.uri(),
            username: user.map(String::from),
            password: pass.map(String::from),
            api_key: key.map(String::from),
            default_index: Some("logs-*".into()),
        }])
    }

    #[tokio::test]
    async fn search_lucene_query() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/logs-*/_search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hits": {
                    "total": {"value": 2},
                    "hits": [
                        {"_source": {"@timestamp": "2025-01-01T00:00:00Z", "msg": "hi"}},
                        {"_source": {"@timestamp": "2025-01-01T00:00:01Z", "msg": "bye"}}
                    ]
                }
            })))
            .mount(&server)
            .await;
        let t = tool_for(&server, None, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "action": "search", "query": "msg:hi"}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("total_hits: 2"));
        assert!(r.output.contains("hi"));
    }

    #[tokio::test]
    async fn count_action() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/logs-*/_count"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"count": 42})))
            .mount(&server)
            .await;
        let t = tool_for(&server, None, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "action": "count"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.contains("count: 42"));
    }

    #[tokio::test]
    async fn api_key_auth() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_cluster/health"))
            .and(header("authorization", "ApiKey SECRET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "green"})))
            .mount(&server)
            .await;
        let t = tool_for(&server, None, None, Some("SECRET"));
        let r = t
            .execute(json!({"endpoint": "test", "action": "health"}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("green"));
    }

    #[tokio::test]
    async fn basic_auth_fallback() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_cluster/health"))
            .and(header("authorization", "Basic dXNlcjpwdw=="))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "yellow"})))
            .mount(&server)
            .await;
        let t = tool_for(&server, Some("user"), Some("pw"), None);
        let r = t
            .execute(json!({"endpoint": "test", "action": "health"}))
            .await
            .unwrap();
        assert!(r.success);
    }

    #[tokio::test]
    async fn auth_error_tagged() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_cluster/health"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "nope"})))
            .mount(&server)
            .await;
        let t = tool_for(&server, None, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "action": "health"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("[auth]"));
    }

    #[tokio::test]
    async fn server_500_surfaces_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_cluster/health"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let t = tool_for(&server, None, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "action": "health"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn unknown_endpoint_rejected() {
        let server = MockServer::start().await;
        let t = tool_for(&server, None, None, None);
        let r = t
            .execute(json!({"endpoint": "other", "action": "health"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn unknown_action_rejected() {
        let server = MockServer::start().await;
        let t = tool_for(&server, None, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "action": "nuke_cluster"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }
}
