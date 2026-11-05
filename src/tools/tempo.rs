//! `tempo` — distributed traces from Grafana Tempo: search with TraceQL,
//! and fetch one trace as a compact span list. Read-only (Tempo's HTTP API
//! has no mutation surface we call).
//!
//! Tempo returns OTLP JSON, which is far too verbose for a model: a trace
//! comes back as one line per span (service, operation, duration, status,
//! and the attributes that matter for diagnosis), slowest and failing
//! spans first.

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::endpoint::get_json;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

const MAX_SPANS: usize = 150;

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// `"30m"`, `"2h"`, `"1d"` → seconds.
fn parse_since(s: &str) -> Result<i64, ToolError> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num
        .parse()
        .map_err(|_| ToolError::UserFacing(format!("since {s:?}: use e.g. 30m, 2h, 1d")))?;
    let mult = match unit {
        "s" => 1,
        "m" | "" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(ToolError::UserFacing(format!("since {s:?}: use e.g. 30m, 2h, 1d"))),
    };
    Ok((n * mult).clamp(60, 7 * 86_400))
}

fn req_str<'a>(args: &'a Value, key: &str, tool: &str) -> Result<&'a str, ToolError> {
    args[key]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ToolError::UserFacing(format!("{tool} requires \"{key}\"")))
}

/// Search traces with TraceQL.
pub struct SearchTool;

#[async_trait]
impl Tool for SearchTool {
    fn name(&self) -> &'static str {
        "tempo_search"
    }

    fn description(&self) -> &str {
        "Search distributed traces (Grafana Tempo) with TraceQL. Examples: \
         '{ status = error }' for failing requests; '{ resource.service.name = \"example-api\" \
         && duration > 2s }' for slow ones; '{ span.http.status_code >= 500 }'. Returns trace \
         ids with root service, operation and duration; fetch one with tempo_trace. Omit \
         `query` to list the services that report traces."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "query": {"type": "string", "description": "TraceQL; omit to list services"},
                "since": {"type": "string", "description": "look back this far: 30m, 2h, 1d (default 1h)"},
                "limit": {"type": "integer", "description": "max traces (default 20, max 50)"}
            },
            "required": ["resource"]
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        false
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let resource = req_str(&args, "resource", self.name())?;
        let target = ctx.resolve_resource(resource)?;
        let Some(query) = args["query"].as_str().filter(|q| !q.trim().is_empty()) else {
            let v = get_json(
                ctx,
                &target,
                self.name(),
                "/api/v2/search/tag/resource.service.name/values",
            )
            .await?;
            let names: Vec<&str> = v["tagValues"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t["value"].as_str())
                .collect();
            return Ok(ToolResult {
                output: format!("services reporting traces: {}", names.join(", ")),
            });
        };
        let since = parse_since(args["since"].as_str().unwrap_or("1h"))?;
        let limit = args["limit"].as_u64().unwrap_or(20).clamp(1, 50);
        let end = Utc::now().timestamp();
        let path = format!(
            "/api/search?q={}&start={}&end={end}&limit={limit}&spss=3",
            enc(query),
            end - since
        );
        let v = get_json(ctx, &target, self.name(), &path).await?;
        Ok(ToolResult { output: render_search(&v) })
    }
}

fn render_search(v: &Value) -> String {
    let traces = v["traces"].as_array().cloned().unwrap_or_default();
    if traces.is_empty() {
        return "no traces matched".into();
    }
    let mut out = vec![format!("{} trace(s):", traces.len())];
    for t in &traces {
        let start = t["startTimeUnixNano"]
            .as_str()
            .and_then(|n| n.parse::<i64>().ok())
            .map(|n| chrono::DateTime::from_timestamp_nanos(n).format("%H:%M:%S").to_string())
            .unwrap_or_default();
        let matched: Vec<String> = t["spanSets"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|s| s["spans"].as_array().cloned().unwrap_or_default())
            .take(3)
            .map(|s| {
                let ms =
                    s["durationNanos"].as_str().and_then(|d| d.parse::<f64>().ok()).unwrap_or(0.0)
                        / 1e6;
                format!("{} {:.0}ms", s["name"].as_str().unwrap_or("?"), ms)
            })
            .collect();
        out.push(format!(
            "- {} {start} {} \"{}\" {}ms{}",
            t["traceID"].as_str().unwrap_or("?"),
            t["rootServiceName"].as_str().unwrap_or("?"),
            t["rootTraceName"].as_str().unwrap_or("?"),
            t["durationMs"].as_u64().map(|d| d.to_string()).unwrap_or_else(|| "<1".into()),
            if matched.is_empty() {
                String::new()
            } else {
                format!(" matched: {}", matched.join("; "))
            }
        ));
    }
    out.join("\n")
}

/// Fetch one trace, summarised.
pub struct TraceTool;

#[async_trait]
impl Tool for TraceTool {
    fn name(&self) -> &'static str {
        "tempo_trace"
    }

    fn description(&self) -> &str {
        "Fetch one distributed trace by id (from tempo_search, or a trace id in a log line) \
         as a span list: service, operation, duration, status and key attributes (HTTP \
         route and status, database, exception messages), failing and slowest spans first."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "trace_id": {"type": "string"}
            },
            "required": ["resource", "trace_id"]
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        false
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let resource = req_str(&args, "resource", self.name())?;
        let id = req_str(&args, "trace_id", self.name())?;
        if !id.chars().all(|c| c.is_ascii_hexdigit()) || id.len() > 32 {
            return Err(ToolError::UserFacing(format!("{id:?} is not a trace id (hex, up to 32)")));
        }
        let target = ctx.resolve_resource(resource)?;
        let v = get_json(ctx, &target, self.name(), &format!("/api/v2/traces/{id}")).await?;
        Ok(ToolResult { output: render_trace(&v) })
    }
}

struct Span {
    service: String,
    name: String,
    ms: f64,
    error: bool,
    detail: Vec<String>,
}

const KEY_ATTRS: &[&str] = &[
    "http.route",
    "http.target",
    "url.path",
    "http.method",
    "http.request.method",
    "http.status_code",
    "http.response.status_code",
    "db.system",
    "db.name",
    "db.operation",
    "messaging.destination.name",
    "messaging.destination",
    "rpc.method",
    "peer.service",
    "server.address",
    "error.type",
];

fn attr_value(v: &Value) -> String {
    for k in ["stringValue", "intValue", "doubleValue", "boolValue"] {
        if let Some(x) = v.get(k) {
            return x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string());
        }
    }
    v.to_string()
}

fn render_trace(v: &Value) -> String {
    // v2 wraps in {"trace": {...}}; batches/resourceSpans both appear.
    let root = if v.get("trace").is_some() { &v["trace"] } else { v };
    let batches = root["resourceSpans"]
        .as_array()
        .or(root["batches"].as_array())
        .cloned()
        .unwrap_or_default();
    let mut spans = Vec::new();
    for b in &batches {
        let service = b["resource"]["attributes"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|a| a["key"] == "service.name")
            .map(|a| attr_value(&a["value"]))
            .unwrap_or_else(|| "?".into());
        let scopes = b["scopeSpans"]
            .as_array()
            .or(b["instrumentationLibrarySpans"].as_array())
            .cloned()
            .unwrap_or_default();
        for sc in &scopes {
            for s in sc["spans"].as_array().into_iter().flatten() {
                let start = s["startTimeUnixNano"]
                    .as_str()
                    .and_then(|n| n.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let end = s["endTimeUnixNano"]
                    .as_str()
                    .and_then(|n| n.parse::<f64>().ok())
                    .unwrap_or(start);
                let code = &s["status"]["code"];
                let error = code == "STATUS_CODE_ERROR" || code == 2;
                let mut detail: Vec<String> = s["attributes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|a| KEY_ATTRS.contains(&a["key"].as_str().unwrap_or("")))
                    .map(|a| {
                        format!("{}={}", a["key"].as_str().unwrap_or(""), attr_value(&a["value"]))
                    })
                    .collect();
                if let Some(msg) = s["status"]["message"].as_str().filter(|m| !m.is_empty()) {
                    detail.push(format!("status: {}", truncate(msg, 300)));
                }
                for e in s["events"].as_array().into_iter().flatten() {
                    for a in e["attributes"].as_array().into_iter().flatten() {
                        if matches!(a["key"].as_str(), Some("exception.message" | "exception.type"))
                        {
                            detail.push(format!(
                                "{}={}",
                                a["key"].as_str().unwrap_or(""),
                                truncate(&attr_value(&a["value"]), 300)
                            ));
                        }
                    }
                }
                spans.push(Span {
                    service: service.clone(),
                    name: s["name"].as_str().unwrap_or("?").to_string(),
                    ms: (end - start) / 1e6,
                    error,
                    detail,
                });
            }
        }
    }
    if spans.is_empty() {
        return "trace not found (or it has no spans yet)".into();
    }
    let total = spans.len();
    let errors = spans.iter().filter(|s| s.error).count();
    let services: std::collections::BTreeSet<String> =
        spans.iter().map(|s| s.service.clone()).collect();
    spans.sort_by(|a, b| {
        b.error.cmp(&a.error).then(b.ms.partial_cmp(&a.ms).unwrap_or(std::cmp::Ordering::Equal))
    });
    let mut out = vec![format!(
        "{total} span(s), {errors} failing, across {}: {}",
        services.len(),
        services.into_iter().collect::<Vec<_>>().join(", ")
    )];
    for s in spans.iter().take(MAX_SPANS) {
        out.push(format!(
            "- {}{} {} {:.1}ms{}",
            if s.error { "ERROR " } else { "" },
            s.service,
            s.name,
            s.ms,
            if s.detail.is_empty() { String::new() } else { format!(" [{}]", s.detail.join(", ")) }
        ));
    }
    if total > MAX_SPANS {
        out.push(format!("… {} more span(s) not shown", total - MAX_SPANS));
    }
    out.join("\n")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_parses_and_clamps() {
        assert_eq!(parse_since("30m").unwrap(), 1800);
        assert_eq!(parse_since("2h").unwrap(), 7200);
        assert_eq!(parse_since("30d").unwrap(), 7 * 86_400);
        assert!(parse_since("soon").is_err());
    }

    #[test]
    fn search_results_are_one_line_per_trace() {
        let v = json!({"traces": [{
            "traceID": "abc123", "rootServiceName": "example-api", "rootTraceName": "GET /x",
            "startTimeUnixNano": "1793836800000000000", "durationMs": 2400,
            "spanSets": [{"spans": [{"name": "SELECT", "durationNanos": "2000000000"}]}]
        }]});
        let out = render_search(&v);
        assert!(out.contains("abc123") && out.contains("example-api \"GET /x\" 2400ms"), "{out}");
        assert!(out.contains("matched: SELECT 2000ms"), "{out}");
        assert_eq!(render_search(&json!({"traces": []})), "no traces matched");
    }

    #[test]
    fn traces_put_failing_and_slow_spans_first_with_key_attributes() {
        let v = json!({"trace": {"resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "managing"}}]},
            "scopeSpans": [{"spans": [
                {"name": "fast", "startTimeUnixNano": "0", "endTimeUnixNano": "1000000", "status": {}},
                {"name": "POST /pay", "startTimeUnixNano": "0", "endTimeUnixNano": "5000000",
                 "status": {"code": "STATUS_CODE_ERROR", "message": "boom"},
                 "attributes": [{"key": "http.status_code", "value": {"intValue": "500"}},
                                {"key": "user.email", "value": {"stringValue": "x@y.com"}}],
                 "events": [{"attributes": [{"key": "exception.message", "value": {"stringValue": "NullReference"}}]}]}
            ]}]
        }]}});
        let out = render_trace(&v);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("2 span(s), 1 failing, across 1: managing"), "{out}");
        assert!(lines[1].starts_with("- ERROR managing POST /pay 5.0ms"), "{out}");
        assert!(
            lines[1].contains("http.status_code=500")
                && lines[1].contains("exception.message=NullReference"),
            "{out}"
        );
        assert!(!out.contains("x@y.com"), "only key attributes are shown: {out}");
    }
}
