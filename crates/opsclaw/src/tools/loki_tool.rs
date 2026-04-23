//! Loki log-query tool. Read-only.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use zeroclaw::tools::traits::{Tool, ToolResult};

const MAX_OUTPUT_BYTES: usize = 16 * 1024;
const DEFAULT_LIMIT: u64 = 100;
const MAX_LIMIT: u64 = 5000;

#[derive(Debug, Clone)]
pub struct LokiEndpoint {
    pub name: String,
    pub url: String,
    pub bearer_token: Option<String>,
    pub org_id: Option<String>,
}

pub struct LokiTool {
    endpoints: HashMap<String, LokiEndpoint>,
    client: reqwest::Client,
}

impl LokiTool {
    pub fn new(endpoints: Vec<LokiEndpoint>) -> Self {
        let map = endpoints
            .into_iter()
            .map(|e| (e.name.clone(), e))
            .collect();
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
}

#[async_trait]
impl Tool for LokiTool {
    fn name(&self) -> &str {
        "loki"
    }

    fn description(&self) -> &str {
        "Query Loki. mode=range (default) uses /loki/api/v1/query_range; \
         other modes: instant, labels, label_values (requires 'label'), \
         series. Returns compact text — logs as timestamp+labels+line, \
         metrics as min/max/mean per series, labels as newline-separated \
         list."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "query": {"type": "string", "description": "LogQL (not needed for labels mode)"},
                "mode": {
                    "type": "string",
                    "enum": ["range", "instant", "labels", "label_values", "series"],
                    "default": "range"
                },
                "start": {"type": "string"},
                "end": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
                "direction": {"type": "string", "enum": ["forward", "backward"], "default": "backward"},
                "label": {"type": "string", "description": "label_values mode"}
            },
            "required": ["endpoint"]
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

        let mode = args.get("mode").and_then(|v| v.as_str()).unwrap_or("range");

        let (path, params) = match mode {
            "range" | "instant" => {
                let query = match args.get("query").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("missing 'query' parameter".into()),
                        });
                    }
                };
                let mut p = vec![("query".to_string(), query)];
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(DEFAULT_LIMIT)
                    .min(MAX_LIMIT);
                p.push(("limit".to_string(), limit.to_string()));
                if let Some(d) = args.get("direction").and_then(|v| v.as_str()) {
                    p.push(("direction".to_string(), d.to_string()));
                }
                if let Some(s) = args.get("start").and_then(|v| v.as_str()) {
                    p.push(("start".to_string(), s.to_string()));
                }
                if let Some(e) = args.get("end").and_then(|v| v.as_str()) {
                    p.push(("end".to_string(), e.to_string()));
                }
                let path = if mode == "range" {
                    "loki/api/v1/query_range"
                } else {
                    "loki/api/v1/query"
                };
                (path.to_string(), p)
            }
            "labels" => {
                let mut p = Vec::new();
                if let Some(s) = args.get("start").and_then(|v| v.as_str()) {
                    p.push(("start".to_string(), s.to_string()));
                }
                if let Some(e) = args.get("end").and_then(|v| v.as_str()) {
                    p.push(("end".to_string(), e.to_string()));
                }
                ("loki/api/v1/labels".to_string(), p)
            }
            "label_values" => {
                let label = match args.get("label").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s,
                    _ => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("label_values mode requires 'label'".into()),
                        });
                    }
                };
                (format!("loki/api/v1/label/{label}/values"), Vec::new())
            }
            "series" => {
                let query = match args.get("query").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("series mode requires 'query'".into()),
                        });
                    }
                };
                let mut p = vec![("match[]".to_string(), query)];
                if let Some(s) = args.get("start").and_then(|v| v.as_str()) {
                    p.push(("start".to_string(), s.to_string()));
                }
                if let Some(e) = args.get("end").and_then(|v| v.as_str()) {
                    p.push(("end".to_string(), e.to_string()));
                }
                ("loki/api/v1/series".to_string(), p)
            }
            other => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("unknown mode '{other}'")),
                });
            }
        };

        let url = format!("{}/{}", endpoint.url.trim_end_matches('/'), path);
        let mut req = self.client.get(&url).query(&params);
        if let Some(tok) = &endpoint.bearer_token {
            req = req.bearer_auth(tok);
        }
        if let Some(org) = &endpoint.org_id {
            req = req.header("X-Scope-OrgID", org);
        }

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
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("rate-limited (429)".into()),
            });
        }
        if !status.is_success() {
            let snippet = &body_text[..body_text.len().min(500)];
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("{status}: {snippet}")),
            });
        }

        let body: Value = match serde_json::from_str(&body_text) {
            Ok(v) => v,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("invalid JSON: {e}")),
                });
            }
        };

        let rendered = match mode {
            "range" | "instant" => render_logs_or_metrics(&body),
            "labels" | "label_values" => render_string_list(&body),
            "series" => render_series(&body),
            _ => String::new(),
        };

        Ok(ToolResult {
            success: true,
            output: truncate(rendered),
            error: None,
        })
    }
}

fn render_logs_or_metrics(body: &Value) -> String {
    let mut out = String::new();
    let data = match body.get("data") {
        Some(d) => d,
        None => {
            writeln!(out, "(no data)").ok();
            return out;
        }
    };
    let result_type = data
        .get("resultType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let result = match data.get("result").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            writeln!(out, "(no result)").ok();
            return out;
        }
    };
    writeln!(out, "resultType: {result_type}  series: {}", result.len()).ok();

    match result_type {
        "streams" => {
            for stream in result {
                let labels = stream
                    .get("stream")
                    .and_then(|v| v.as_object())
                    .map(|m| {
                        let mut v: Vec<String> =
                            m.iter().map(|(k, val)| format!("{k}={}", val.as_str().unwrap_or(""))).collect();
                        v.sort();
                        v.join(",")
                    })
                    .unwrap_or_default();
                if let Some(values) = stream.get("values").and_then(|v| v.as_array()) {
                    for v in values {
                        let arr = v.as_array();
                        let ts = arr
                            .and_then(|a| a.first())
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let line = arr
                            .and_then(|a| a.get(1))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        writeln!(out, "  {ts} {{{labels}}} {line}").ok();
                    }
                }
            }
        }
        "matrix" | "vector" => {
            for item in result {
                let labels = item
                    .get("metric")
                    .and_then(|v| v.as_object())
                    .map(|m| {
                        let mut v: Vec<String> =
                            m.iter().map(|(k, val)| format!("{k}={}", val.as_str().unwrap_or(""))).collect();
                        v.sort();
                        v.join(",")
                    })
                    .unwrap_or_default();
                if result_type == "matrix" {
                    let (min, max, mean, n) = matrix_stats(item.get("values").and_then(|v| v.as_array()));
                    writeln!(
                        out,
                        "  {{{labels}}} n={n} min={min:.4} max={max:.4} mean={mean:.4}"
                    )
                    .ok();
                } else {
                    let value = item
                        .get("value")
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.get(1))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    writeln!(out, "  {{{labels}}} {value}").ok();
                }
            }
        }
        _ => {
            writeln!(out, "(unknown resultType: {result_type})").ok();
        }
    }
    out
}

fn render_string_list(body: &Value) -> String {
    let mut out = String::new();
    if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                writeln!(out, "{s}").ok();
            }
        }
    }
    out
}

fn render_series(body: &Value) -> String {
    let mut out = String::new();
    if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
        for series in arr {
            if let Some(m) = series.as_object() {
                let mut labels: Vec<String> = m
                    .iter()
                    .map(|(k, val)| format!("{k}={}", val.as_str().unwrap_or("")))
                    .collect();
                labels.sort();
                writeln!(out, "{{{}}}", labels.join(",")).ok();
            }
        }
    }
    out
}

fn matrix_stats(values: Option<&Vec<Value>>) -> (f64, f64, f64, usize) {
    let Some(arr) = values else {
        return (0.0, 0.0, 0.0, 0);
    };
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    let mut sum = 0.0;
    let mut n = 0;
    for pair in arr {
        if let Some(v) = pair
            .as_array()
            .and_then(|a| a.get(1))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<f64>().ok())
        {
            min = min.min(v);
            max = max.max(v);
            sum += v;
            n += 1;
        }
    }
    if n == 0 {
        (0.0, 0.0, 0.0, 0)
    } else {
        (min, max, sum / n as f64, n)
    }
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

    fn tool_for(server: &MockServer, org: Option<&str>, tok: Option<&str>) -> LokiTool {
        LokiTool::new(vec![LokiEndpoint {
            name: "test".into(),
            url: server.uri(),
            bearer_token: tok.map(String::from),
            org_id: org.map(String::from),
        }])
    }

    #[tokio::test]
    async fn range_query_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/loki/api/v1/query_range"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [{
                        "stream": {"app": "web"},
                        "values": [["1700000000000000000", "hello world"]]
                    }]
                }
            })))
            .mount(&server)
            .await;
        let t = tool_for(&server, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "query": "{app=\"web\"}"}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("hello world"));
        assert!(r.output.contains("app=web"));
    }

    #[tokio::test]
    async fn labels_list() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/loki/api/v1/labels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success",
                "data": ["app", "job"]
            })))
            .mount(&server)
            .await;
        let t = tool_for(&server, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "mode": "labels"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.contains("app"));
        assert!(r.output.contains("job"));
    }

    #[tokio::test]
    async fn auth_and_org_id_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/loki/api/v1/labels"))
            .and(header("authorization", "Bearer tok"))
            .and(header("x-scope-orgid", "tenant-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success", "data": []
            })))
            .mount(&server)
            .await;
        let t = tool_for(&server, Some("tenant-1"), Some("tok"));
        let r = t
            .execute(json!({"endpoint": "test", "mode": "labels"}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
    }

    #[tokio::test]
    async fn rate_limit_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/loki/api/v1/query_range"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let t = tool_for(&server, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "query": "{x=\"y\"}"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("rate-limited"));
    }

    #[tokio::test]
    async fn label_values_requires_label() {
        let server = MockServer::start().await;
        let t = tool_for(&server, None, None);
        let r = t
            .execute(json!({"endpoint": "test", "mode": "label_values"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("label"));
    }
}
