//! Prometheus query tool. Supports instant and range queries against a
//! configured list of Prometheus endpoints. Read-only.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

const MAX_OUTPUT_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct PrometheusEndpoint {
    pub name: String,
    pub url: String,
    pub bearer_token: Option<String>,
}

pub struct PrometheusTool {
    endpoints: HashMap<String, PrometheusEndpoint>,
    client: reqwest::Client,
}

impl PrometheusTool {
    pub fn new(endpoints: Vec<PrometheusEndpoint>) -> Self {
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
}

#[async_trait]
impl Tool for PrometheusTool {
    fn name(&self) -> &str {
        "prometheus"
    }

    fn description(&self) -> &str {
        "Query Prometheus. mode=instant uses /api/v1/query; mode=range uses \
         /api/v1/query_range with start/end/step. Returns a compact text \
         summary of the result (not raw JSON)."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "configured endpoint name"},
                "query": {"type": "string", "description": "PromQL expression"},
                "mode": {"type": "string", "enum": ["instant", "range"], "default": "instant"},
                "start": {"type": "string", "description": "RFC3339 or unix seconds (range mode)"},
                "end": {"type": "string", "description": "RFC3339 or unix seconds (range mode)"},
                "step": {"type": "string", "description": "step duration (e.g. 30s, 5m)"}
            },
            "required": ["endpoint", "query"]
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

        let query = match args.get("query").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("missing 'query' parameter".into()),
                });
            }
        };

        let mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("instant");

        let (path, params) = match mode {
            "instant" => {
                let p = vec![("query", query.to_string())];
                ("api/v1/query", p)
            }
            "range" => {
                let start = args.get("start").and_then(|v| v.as_str()).unwrap_or("");
                let end = args.get("end").and_then(|v| v.as_str()).unwrap_or("");
                let step = args.get("step").and_then(|v| v.as_str()).unwrap_or("60s");
                if start.is_empty() || end.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("range mode requires 'start' and 'end'".into()),
                    });
                }
                let p = vec![
                    ("query", query.to_string()),
                    ("start", start.to_string()),
                    ("end", end.to_string()),
                    ("step", step.to_string()),
                ];
                ("api/v1/query_range", p)
            }
            other => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("unknown mode '{other}' (expected instant|range)")),
                });
            }
        };

        let url = format!("{}/{}", endpoint.url.trim_end_matches('/'), path);
        let mut req = self.client.get(&url).query(&params);
        if let Some(tok) = &endpoint.bearer_token {
            req = req.bearer_auth(tok);
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
        let body: Value = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("{status}: invalid JSON: {e}")),
                });
            }
        };
        if !status.is_success() {
            let snippet = body.to_string();
            let snippet = &snippet[..snippet.len().min(500)];
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("{status}: {snippet}")),
            });
        }

        let out = render_prom_result(&body);
        Ok(ToolResult {
            success: true,
            output: truncate(out),
            error: None,
        })
    }
}

fn render_prom_result(body: &Value) -> String {
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
            writeln!(out, "(no result array)").ok();
            return out;
        }
    };

    writeln!(out, "resultType: {result_type}  series: {}", result.len()).ok();

    match result_type {
        "vector" | "scalar" => {
            for item in result {
                let metric = format_metric(item.get("metric"));
                let value = item
                    .get("value")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.get(1))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                writeln!(out, "  {metric} {value}").ok();
            }
        }
        "matrix" => {
            for item in result {
                let metric = format_metric(item.get("metric"));
                let values = item.get("values").and_then(|v| v.as_array());
                let (min, max, mean, n) = matrix_stats(values);
                writeln!(
                    out,
                    "  {metric} n={n} min={min:.4} max={max:.4} mean={mean:.4}"
                )
                .ok();
            }
        }
        _ => {
            writeln!(out, "(unknown resultType: {result_type})").ok();
        }
    }
    out
}

fn format_metric(metric: Option<&Value>) -> String {
    let m = match metric.and_then(|v| v.as_object()) {
        Some(m) => m,
        None => return "{}".into(),
    };
    let name = m.get("__name__").and_then(|v| v.as_str()).unwrap_or("");
    let mut labels: Vec<String> = m
        .iter()
        .filter(|(k, _)| *k != "__name__")
        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
        .collect();
    labels.sort();
    format!("{name}{{{}}}", labels.join(","))
}

fn matrix_stats(values: Option<&Vec<Value>>) -> (f64, f64, f64, usize) {
    let Some(arr) = values else {
        return (0.0, 0.0, 0.0, 0);
    };
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    let mut sum = 0.0;
    let mut n = 0usize;
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
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tool_for(server: &MockServer) -> PrometheusTool {
        PrometheusTool::new(vec![PrometheusEndpoint {
            name: "test".into(),
            url: server.uri(),
            bearer_token: None,
        }])
    }

    #[tokio::test]
    async fn instant_query_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .and(query_param("query", "up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        {"metric": {"__name__": "up", "job": "node"}, "value": [0, "1"]}
                    ]
                }
            })))
            .mount(&server)
            .await;
        let t = tool_for(&server);
        let r = t
            .execute(json!({"endpoint": "test", "query": "up"}))
            .await
            .unwrap();
        assert!(r.success, "error: {:?}", r.error);
        assert!(r.output.contains("up{job=node}"));
    }

    #[tokio::test]
    async fn range_query_requires_start_end() {
        let server = MockServer::start().await;
        let t = tool_for(&server);
        let r = t
            .execute(json!({"endpoint": "test", "query": "up", "mode": "range"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("start"));
    }

    #[tokio::test]
    async fn unknown_endpoint_lists_available() {
        let server = MockServer::start().await;
        let t = tool_for(&server);
        let r = t
            .execute(json!({"endpoint": "other", "query": "up"}))
            .await
            .unwrap();
        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("unknown endpoint"));
        assert!(err.contains("test"));
    }

    #[tokio::test]
    async fn http_error_surfaces_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({"status": "error", "error": "bad query"})),
            )
            .mount(&server)
            .await;
        let t = tool_for(&server);
        let r = t
            .execute(json!({"endpoint": "test", "query": "!!!"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("bad query"));
    }

    #[tokio::test]
    async fn range_matrix_rendering() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/query_range"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success",
                "data": {
                    "resultType": "matrix",
                    "result": [{
                        "metric": {"__name__": "cpu"},
                        "values": [[0, "1"], [1, "2"], [2, "3"]]
                    }]
                }
            })))
            .mount(&server)
            .await;
        let t = tool_for(&server);
        let r = t
            .execute(json!({
                "endpoint": "test",
                "query": "cpu",
                "mode": "range",
                "start": "2024-01-01T00:00:00Z",
                "end": "2024-01-01T00:05:00Z",
                "step": "60s"
            }))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("min=1.0000"));
        assert!(r.output.contains("max=3.0000"));
        assert!(r.output.contains("mean=2.0000"));
    }

    #[tokio::test]
    async fn server_500_surfaces_structured_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
            .mount(&server)
            .await;
        let t = tool_for(&server);
        let r = t
            .execute(json!({"endpoint": "test", "query": "up"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn malformed_json_is_handled_gracefully() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
            .mount(&server)
            .await;
        let t = tool_for(&server);
        let r = t
            .execute(json!({"endpoint": "test", "query": "up"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn empty_vector_result() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success",
                "data": {"resultType": "vector", "result": []}
            })))
            .mount(&server)
            .await;
        let t = tool_for(&server);
        let r = t
            .execute(json!({"endpoint": "test", "query": "nothing_matches"}))
            .await
            .unwrap();
        assert!(r.success, "error: {:?}", r.error);
    }

    #[tokio::test]
    async fn missing_query_arg() {
        let server = MockServer::start().await;
        let t = tool_for(&server);
        let r = t.execute(json!({"endpoint": "test"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }
}
