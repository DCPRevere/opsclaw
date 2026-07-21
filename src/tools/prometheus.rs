//! `prometheus` — instant and range PromQL queries (DESIGN.md §4 item 2;
//! docs/REMUNDO.md: "Metrics: kube-prometheus-stack"). Standard Prometheus
//! HTTP API shape (`/api/v1/query`, `/api/v1/query_range`) — read-only, no
//! mutation surface.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::endpoint::get_json;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

fn client() -> reqwest::Client {
    crate::tools::endpoint::client()
}

/// A single point-in-time PromQL evaluation.
pub struct InstantQueryTool;

#[async_trait]
impl Tool for InstantQueryTool {
    fn name(&self) -> &'static str {
        "prometheus_instant_query"
    }

    fn description(&self) -> &str {
        "Evaluate a PromQL expression at a single point in time (now, unless `time` is \
         given as an RFC3339 timestamp). Use for a current-value check, e.g. \
         'rate(http_requests_total{job=\"api\"}[5m])'."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "query": {"type": "string", "description": "PromQL expression"},
                "time": {"type": "string", "description": "RFC3339 timestamp; omit for now"}
            },
            "required": ["resource", "query"]
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
        let resource = args["resource"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "prometheus_instant_query requires a \"resource\" argument".to_string(),
            )
        })?;
        let query = args["query"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "prometheus_instant_query requires a \"query\" argument".to_string(),
            )
        })?;
        let (_, auth) = ctx.resolve_resource(resource)?;

        let encoded = urlencode(query);
        let mut path = format!("/api/v1/query?query={encoded}");
        if let Some(time) = args["time"].as_str() {
            path.push_str(&format!("&time={}", urlencode(time)));
        }
        let result = get_json(&client(), auth, self.name(), &path).await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

/// A PromQL evaluation over a time range — trend evidence, not just a
/// single reading (environment scepticism: a single point-in-time value
/// corroborates less than a trend does).
pub struct RangeQueryTool;

#[async_trait]
impl Tool for RangeQueryTool {
    fn name(&self) -> &'static str {
        "prometheus_range_query"
    }

    fn description(&self) -> &str {
        "Evaluate a PromQL expression over a time range — for trend evidence (is this rising, \
         or was it always this level?) rather than a single reading. `start`/`end` are \
         RFC3339 timestamps, `step` a duration like '30s' or '5m'."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "query": {"type": "string"},
                "start": {"type": "string", "description": "RFC3339 start"},
                "end": {"type": "string", "description": "RFC3339 end"},
                "step": {"type": "string", "description": "step duration, e.g. 30s"}
            },
            "required": ["resource", "query", "start", "end", "step"]
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
        let resource = args["resource"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "prometheus_range_query requires a \"resource\" argument".to_string(),
            )
        })?;
        let query = args["query"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "prometheus_range_query requires a \"query\" argument".to_string(),
            )
        })?;
        let start = args["start"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "prometheus_range_query requires a \"start\" argument".to_string(),
            )
        })?;
        let end = args["end"].as_str().ok_or_else(|| {
            ToolError::UserFacing("prometheus_range_query requires an \"end\" argument".to_string())
        })?;
        let step = args["step"].as_str().ok_or_else(|| {
            ToolError::UserFacing("prometheus_range_query requires a \"step\" argument".to_string())
        })?;
        let (_, auth) = ctx.resolve_resource(resource)?;

        let path = format!(
            "/api/v1/query_range?query={}&start={}&end={}&step={}",
            urlencode(query),
            urlencode(start),
            urlencode(end),
            urlencode(step)
        );
        let result = get_json(&client(), auth, self.name(), &path).await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

/// Minimal query-string percent-encoding for the characters PromQL
/// expressions and RFC3339 timestamps actually contain (`{`, `}`, `"`,
/// space, `:`, `+`) — avoids pulling in a URL-encoding crate dependency
/// (none is in Cargo.toml) for what `reqwest`'s own query-param builder
/// would otherwise do; used here because the query string is built by hand
/// (juggling `?`/`&` for the optional `time` param reads more plainly this
/// way than constructing a `Vec<(&str, &str)>` for one call site).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FqTarget, Principal, ResourceType};
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use crate::tools::endpoint::{EndpointAuth, EndpointRegistry};
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct NoopPolicy;
    #[async_trait]
    impl PolicyExecute for NoopPolicy {
        async fn execute(&self, _req: CommandRequest) -> crate::Result<PolicyOutcome> {
            Ok(PolicyOutcome::EStopped)
        }
    }

    fn target() -> FqTarget {
        FqTarget {
            project: "remundo".into(),
            env: "prod".into(),
            target: "cluster".into(),
            resource: Some((ResourceType::Prometheus, "metrics".into())),
        }
    }

    fn ctx_with(base_url: &str, token: Option<&str>) -> ToolCtx {
        let mut reg = EndpointRegistry::new();
        reg.insert(&target(), EndpointAuth::new(base_url, token.map(str::to_string)));
        ToolCtx {
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![target()],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: Some(Arc::new(reg)),
            runbooks: None,
        }
    }

    #[test]
    fn urlencode_handles_promql_special_chars() {
        assert_eq!(urlencode("up{job=\"api\"}"), "up%7Bjob%3D%22api%22%7D");
        assert_eq!(urlencode("2026-07-21T10:00:00Z"), "2026-07-21T10%3A00%3A00Z");
    }

    #[tokio::test]
    async fn instant_query_sends_bearer_auth_and_encodes_query() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/query$"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "success"})))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), Some("tok"));
        let r = InstantQueryTool
            .call(&ctx, json!({"resource": target().to_string(), "query": "up{job=\"api\"}"}))
            .await
            .unwrap();
        assert!(r.output.contains("success"));
    }

    #[tokio::test]
    async fn range_query_requires_all_of_start_end_step() {
        let ctx = ctx_with("http://unused", None);
        let err = RangeQueryTool
            .call(
                &ctx,
                json!({"resource": target().to_string(), "query": "up", "start": "x", "end": "y"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[tokio::test]
    async fn range_query_hits_query_range_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/query_range$"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"status": "success", "data": {}})),
            )
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let r = RangeQueryTool
            .call(
                &ctx,
                json!({
                    "resource": target().to_string(),
                    "query": "up",
                    "start": "2026-07-21T00:00:00Z",
                    "end": "2026-07-21T01:00:00Z",
                    "step": "30s"
                }),
            )
            .await
            .unwrap();
        assert!(r.output.contains("success"));
    }

    #[tokio::test]
    async fn non_2xx_is_user_facing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/query$"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad promql"))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let err = InstantQueryTool
            .call(&ctx, json!({"resource": target().to_string(), "query": "invalid("}))
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("400")),
            _ => panic!("expected UserFacing"),
        }
    }

    #[tokio::test]
    async fn connection_refusal_is_internal() {
        let ctx = ctx_with("http://127.0.0.1:1", None);
        let err = InstantQueryTool
            .call(&ctx, json!({"resource": target().to_string(), "query": "up"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }

    #[test]
    fn both_tools_are_read_only() {
        assert!(!InstantQueryTool.is_action());
        assert!(!RangeQueryTool.is_action());
    }
}
