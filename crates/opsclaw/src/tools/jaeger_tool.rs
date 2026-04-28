//! Jaeger query tool. Read-only HTTP client against the Jaeger query
//! service (`/api/services`, `/api/traces`, etc.). Works against Jaeger
//! v1 query and Tempo's Jaeger-compatible API.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

const MAX_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct JaegerEndpoint {
    pub name: String,
    pub url: String,
    pub bearer_token: Option<String>,
}

pub struct JaegerTool {
    endpoints: HashMap<String, JaegerEndpoint>,
    client: reqwest::Client,
}

impl JaegerTool {
    pub fn new(endpoints: Vec<JaegerEndpoint>) -> Self {
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

    fn get(&self, endpoint: &JaegerEndpoint, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}/{}", endpoint.url.trim_end_matches('/'), path);
        let mut req = self.client.get(&url);
        if let Some(t) = &endpoint.bearer_token {
            req = req.bearer_auth(t);
        }
        req
    }
}

#[async_trait]
impl Tool for JaegerTool {
    fn name(&self) -> &str {
        "jaeger"
    }

    fn description(&self) -> &str {
        "Query Jaeger (or a Jaeger-compatible API like Grafana Tempo). \
         Actions: list_services, list_operations (requires 'service'), \
         search_traces (service + optional operation/tags/lookback/ \
         min_duration/max_duration/limit), get_trace (trace_id), \
         dependencies. Returns compact text summaries, not raw JSON."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["list_services", "list_operations", "search_traces",
                             "get_trace", "dependencies"]
                },
                "service": {"type": "string"},
                "operation": {"type": "string"},
                "tags": {"type": "string", "description": "JSON object of tag filters, e.g. {\"error\":\"true\"}"},
                "lookback": {"type": "string", "description": "e.g. 1h, 30m (default 1h)"},
                "min_duration": {"type": "string", "description": "e.g. 100ms, 2s"},
                "max_duration": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
                "trace_id": {"type": "string"}
            },
            "required": ["endpoint", "action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let endpoint_name = match args.get("endpoint").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'endpoint'")),
        };
        let endpoint = match self.endpoints.get(endpoint_name) {
            Some(e) => e,
            None => {
                return Ok(err(format!(
                    "unknown endpoint '{endpoint_name}'. Available: {}",
                    self.endpoint_names().join(", ")
                )));
            }
        };

        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'action'")),
        };

        match action {
            "list_services" => self.list_services(endpoint).await,
            "list_operations" => self.list_operations(endpoint, &args).await,
            "search_traces" => self.search_traces(endpoint, &args).await,
            "get_trace" => self.get_trace(endpoint, &args).await,
            "dependencies" => self.dependencies(endpoint, &args).await,
            other => Ok(err(format!("unknown action '{other}'"))),
        }
    }
}

impl JaegerTool {
    async fn list_services(&self, ep: &JaegerEndpoint) -> anyhow::Result<ToolResult> {
        let resp = self.get(ep, "api/services").send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
            writeln!(out, "count: {}", arr.len()).ok();
            for s in arr {
                if let Some(name) = s.as_str() {
                    writeln!(out, "  {name}").ok();
                }
            }
        }
        Ok(ok_res(out))
    }

    async fn list_operations(
        &self,
        ep: &JaegerEndpoint,
        args: &Value,
    ) -> anyhow::Result<ToolResult> {
        let service = match args.get("service").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(err("list_operations requires 'service'")),
        };
        let path = format!("api/services/{}/operations", urlencode(service));
        let resp = self.get(ep, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
            writeln!(out, "service: {service}  count: {}", arr.len()).ok();
            for op in arr {
                if let Some(name) = op.as_str() {
                    writeln!(out, "  {name}").ok();
                }
            }
        }
        Ok(ok_res(out))
    }

    async fn search_traces(&self, ep: &JaegerEndpoint, args: &Value) -> anyhow::Result<ToolResult> {
        let service = match args.get("service").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(err("search_traces requires 'service'")),
        };
        let mut params: Vec<(&str, String)> = vec![("service", service.to_string())];
        if let Some(op) = args.get("operation").and_then(|v| v.as_str()) {
            params.push(("operation", op.to_string()));
        }
        if let Some(t) = args.get("tags").and_then(|v| v.as_str()) {
            params.push(("tags", t.to_string()));
        }
        let lookback = args
            .get("lookback")
            .and_then(|v| v.as_str())
            .unwrap_or("1h");
        params.push(("lookback", lookback.to_string()));
        if let Some(m) = args.get("min_duration").and_then(|v| v.as_str()) {
            params.push(("minDuration", m.to_string()));
        }
        if let Some(m) = args.get("max_duration").and_then(|v| v.as_str()) {
            params.push(("maxDuration", m.to_string()));
        }
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20);
        params.push(("limit", limit.to_string()));

        let resp = self.get(ep, "api/traces").query(&params).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
            writeln!(out, "traces: {}", arr.len()).ok();
            for t in arr {
                let id = t.get("traceID").and_then(|v| v.as_str()).unwrap_or("");
                let spans = t
                    .get("spans")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let (root_op, root_service, start, duration_us, error_count) = summarise_trace(t);
                writeln!(
                    out,
                    "  {id} spans={spans} svc={root_service} op={root_op} \
                     start={start} dur={}ms errors={error_count}",
                    duration_us / 1000
                )
                .ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn get_trace(&self, ep: &JaegerEndpoint, args: &Value) -> anyhow::Result<ToolResult> {
        let id = match args.get("trace_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(err("missing 'trace_id'")),
        };
        let path = format!("api/traces/{}", urlencode(id));
        let resp = self.get(ep, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        // The /api/traces/{id} endpoint returns `{"data": [trace]}`.
        let trace = v
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(v.clone());

        writeln!(out, "trace_id: {id}").ok();
        let spans = trace
            .get("spans")
            .and_then(|s| s.as_array())
            .cloned()
            .unwrap_or_default();
        writeln!(out, "spans: {}", spans.len()).ok();
        let (root_op, root_service, start, duration_us, error_count) = summarise_trace(&trace);
        writeln!(
            out,
            "root: {root_service}:{root_op}  start: {start}  duration: {}ms  errors: {error_count}",
            duration_us / 1000
        )
        .ok();

        // Process map — span.process references processes by id; map id → serviceName.
        let processes = trace
            .get("processes")
            .and_then(|p| p.as_object())
            .cloned()
            .unwrap_or_default();
        let service_of = |pid: &str| -> String {
            processes
                .get(pid)
                .and_then(|p| p.get("serviceName"))
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string()
        };

        // Top N slowest spans.
        let mut sorted: Vec<&Value> = spans.iter().collect();
        sorted.sort_by_key(|s| {
            std::cmp::Reverse(s.get("duration").and_then(|v| v.as_i64()).unwrap_or(0))
        });
        writeln!(out, "slowest spans:").ok();
        for s in sorted.iter().take(10) {
            let op = s
                .get("operationName")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let dur = s.get("duration").and_then(|v| v.as_i64()).unwrap_or(0);
            let pid = s.get("processID").and_then(|v| v.as_str()).unwrap_or("");
            let svc = service_of(pid);
            let has_error = has_error_tag(s);
            let marker = if has_error { " [error]" } else { "" };
            writeln!(out, "  {svc}:{op} {}ms{marker}", dur / 1000).ok();
        }
        Ok(ok_res(out))
    }

    async fn dependencies(&self, ep: &JaegerEndpoint, args: &Value) -> anyhow::Result<ToolResult> {
        // Jaeger wants an endTs (ms) + lookback (ms). Default: now, 1h.
        let lookback_ms: u64 = parse_duration_to_ms(
            args.get("lookback")
                .and_then(|v| v.as_str())
                .unwrap_or("1h"),
        )
        .unwrap_or(3_600_000);
        let end_ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let params = [
            ("endTs", end_ts_ms.to_string()),
            ("lookback", lookback_ms.to_string()),
        ];
        let resp = self
            .get(ep, "api/dependencies")
            .query(&params)
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
            writeln!(out, "edges: {}", arr.len()).ok();
            for e in arr {
                let parent = e.get("parent").and_then(|v| v.as_str()).unwrap_or("");
                let child = e.get("child").and_then(|v| v.as_str()).unwrap_or("");
                let calls = e.get("callCount").and_then(|v| v.as_u64()).unwrap_or(0);
                writeln!(out, "  {parent} → {child} calls={calls}").ok();
            }
        }
        Ok(ok_res(out))
    }
}

/// Extract (root_op, root_service, start_iso, duration_us, error_count) from a trace object.
fn summarise_trace(trace: &Value) -> (String, String, String, i64, u64) {
    let spans = trace
        .get("spans")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    let processes = trace
        .get("processes")
        .and_then(|p| p.as_object())
        .cloned()
        .unwrap_or_default();

    // Root = span with no child-of reference inside this trace.
    let root = spans.iter().find(|s| {
        s.get("references")
            .and_then(|r| r.as_array())
            .map(|a| {
                !a.iter()
                    .any(|ref_| ref_.get("refType").and_then(|v| v.as_str()) == Some("CHILD_OF"))
            })
            .unwrap_or(true)
    });

    let root_op = root
        .and_then(|s| s.get("operationName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let root_service = root
        .and_then(|s| s.get("processID"))
        .and_then(|v| v.as_str())
        .and_then(|pid| {
            processes
                .get(pid)
                .and_then(|p| p.get("serviceName"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
        .to_string();

    let start_us = root
        .and_then(|s| s.get("startTime"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let duration_us = root
        .and_then(|s| s.get("duration"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let start_iso = format_micros_as_iso(start_us);
    let error_count = spans.iter().filter(|s| has_error_tag(s)).count() as u64;
    (root_op, root_service, start_iso, duration_us, error_count)
}

fn has_error_tag(span: &Value) -> bool {
    span.get("tags")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter().any(|tag| {
                tag.get("key").and_then(|v| v.as_str()) == Some("error")
                    && matches!(
                        tag.get("value"),
                        Some(Value::Bool(true)) | Some(Value::String(_))
                    )
                    && tag
                        .get("value")
                        .map(|v| match v {
                            Value::Bool(b) => *b,
                            Value::String(s) => s != "false" && !s.is_empty(),
                            _ => false,
                        })
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn format_micros_as_iso(micros: i64) -> String {
    if micros <= 0 {
        return String::new();
    }
    let secs = micros / 1_000_000;
    let nanos = ((micros % 1_000_000) * 1000) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

fn parse_duration_to_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_part, unit) = s
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| (&s[..i], &s[i..]))
        .unwrap_or((s, ""));
    let n: u64 = num_part.parse().ok()?;
    let mult = match unit {
        "" | "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return None,
    };
    Some(n * mult)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            }
            _ => {
                write!(out, "%{:02X}", c).ok();
            }
        }
    }
    out
}

async fn consume(resp: reqwest::Response) -> (bool, reqwest::StatusCode, String) {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (status.is_success(), status, text)
}

fn snippet(s: &str) -> &str {
    &s[..s.len().min(500)]
}

fn err<S: Into<String>>(msg: S) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(msg.into()),
    }
}

fn ok_res(mut s: String) -> ToolResult {
    if s.len() > MAX_OUTPUT_BYTES {
        let mut cut = MAX_OUTPUT_BYTES;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n... [truncated]");
    }
    ToolResult {
        success: true,
        output: s,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tool(server: &MockServer) -> JaegerTool {
        JaegerTool::new(vec![JaegerEndpoint {
            name: "test".into(),
            url: server.uri(),
            bearer_token: None,
        }])
    }

    #[test]
    fn parse_duration_variants() {
        assert_eq!(parse_duration_to_ms("1h"), Some(3_600_000));
        assert_eq!(parse_duration_to_ms("30m"), Some(1_800_000));
        assert_eq!(parse_duration_to_ms("500ms"), Some(500));
        assert_eq!(parse_duration_to_ms("2s"), Some(2_000));
        assert_eq!(parse_duration_to_ms("nonsense"), None);
    }

    #[tokio::test]
    async fn list_services_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/services"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": ["checkout", "cart", "payments"]
            })))
            .mount(&server)
            .await;
        let t = tool(&server);
        let r = t
            .execute(json!({"endpoint": "test", "action": "list_services"}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("count: 3"));
        assert!(r.output.contains("checkout"));
    }

    #[tokio::test]
    async fn list_operations_requires_service() {
        let server = MockServer::start().await;
        let t = tool(&server);
        let r = t
            .execute(json!({"endpoint": "test", "action": "list_operations"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("service"));
    }

    #[tokio::test]
    async fn search_traces_compact_summary() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/traces"))
            .and(query_param("service", "checkout"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{
                    "traceID": "abc123",
                    "spans": [
                        {
                            "operationName": "POST /checkout",
                            "processID": "p1",
                            "startTime": 1_700_000_000_000_000i64,
                            "duration": 123_000,
                            "tags": [{"key": "error", "value": true}],
                            "references": []
                        },
                        {
                            "operationName": "db.query",
                            "processID": "p2",
                            "startTime": 1_700_000_000_010_000i64,
                            "duration": 40_000,
                            "references": [{"refType": "CHILD_OF"}]
                        }
                    ],
                    "processes": {
                        "p1": {"serviceName": "checkout"},
                        "p2": {"serviceName": "db"}
                    }
                }]
            })))
            .mount(&server)
            .await;
        let t = tool(&server);
        let r = t
            .execute(json!({
                "endpoint": "test", "action": "search_traces",
                "service": "checkout"
            }))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("abc123"));
        assert!(r.output.contains("spans=2"));
        assert!(r.output.contains("svc=checkout"));
        assert!(r.output.contains("errors=1"));
    }

    #[tokio::test]
    async fn get_trace_shows_slowest_spans() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/traces/abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{
                    "traceID": "abc123",
                    "spans": [
                        {"operationName": "fast", "processID": "p1", "duration": 5_000, "references": []},
                        {"operationName": "slow", "processID": "p1", "duration": 500_000, "references": [{"refType": "CHILD_OF"}]}
                    ],
                    "processes": {"p1": {"serviceName": "svc"}}
                }]
            })))
            .mount(&server)
            .await;
        let t = tool(&server);
        let r = t
            .execute(json!({
                "endpoint": "test", "action": "get_trace", "trace_id": "abc123"
            }))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.contains("spans: 2"));
        // In the slowest-spans section, 'slow' (500ms) should appear before 'fast' (5ms).
        let slowest_block = r.output.split("slowest spans:").nth(1).unwrap();
        let slow_idx = slowest_block.find("svc:slow").unwrap();
        let fast_idx = slowest_block.find("svc:fast").unwrap();
        assert!(slow_idx < fast_idx);
    }

    #[tokio::test]
    async fn unknown_endpoint_lists_available() {
        let server = MockServer::start().await;
        let t = tool(&server);
        let r = t
            .execute(json!({"endpoint": "other", "action": "list_services"}))
            .await
            .unwrap();
        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("unknown endpoint"));
        assert!(err.contains("test"));
    }

    #[tokio::test]
    async fn http_error_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/services"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream dead"))
            .mount(&server)
            .await;
        let t = tool(&server);
        let r = t
            .execute(json!({"endpoint": "test", "action": "list_services"}))
            .await
            .unwrap();
        assert!(!r.success);
        let e = r.error.unwrap();
        assert!(e.contains("503"));
        assert!(e.contains("upstream dead"));
    }

    #[tokio::test]
    async fn malformed_json_returns_empty_output() {
        // The tool treats malformed JSON as Value::Null and renders no data;
        // it does not fail the call. This matches current behavior — see
        // `list_services`. Call still succeeds with empty output.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/services"))
            .respond_with(ResponseTemplate::new(200).set_body_string("}{not json"))
            .mount(&server)
            .await;
        let t = tool(&server);
        let r = t
            .execute(json!({"endpoint": "test", "action": "list_services"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.is_empty() || !r.output.contains("count:"));
    }

    #[tokio::test]
    async fn unknown_action_rejected() {
        let server = MockServer::start().await;
        let t = tool(&server);
        let r = t
            .execute(json!({"endpoint": "test", "action": "nuke"}))
            .await
            .unwrap();
        assert!(!r.success);
    }
}
