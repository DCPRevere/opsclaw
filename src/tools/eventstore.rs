//! `eventstore` — stream read and subscription/projection status
//! (DESIGN.md §4 item 2; docs/REMUNDO.md: "read-only v1" — the estate is
//! "mid 3-shard migration" and "2 of the 9 real postmortems are EventStore
//! incidents"). KurrentDB (the EventStoreDB successor) exposes an HTTP
//! Atom-feed API compatible with this shape; no mutation surface here —
//! scavenge/backup are CronJobs (REMUNDO.md), not an agent action.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::endpoint::get_json;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};


/// Read events from a stream (most recent first, capped) — the
/// synchroniser-lag diagnostic starting point (REMUNDO.md: "Synchroniser
/// lag: position vs head").
pub struct ReadStreamTool;

#[async_trait]
impl Tool for ReadStreamTool {
    fn name(&self) -> &'static str {
        "eventstore_read_stream"
    }

    fn description(&self) -> &str {
        "Read events from a KurrentDB/EventStore stream, most recent first. Use to check a \
         stream's current head position, or to inspect recent events when diagnosing \
         projection/synchroniser lag."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "stream": {"type": "string", "description": "stream name"},
                "count": {"type": "integer", "description": "max events to return (default 20)"}
            },
            "required": ["resource", "stream"]
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
                "eventstore_read_stream requires a \"resource\" argument".to_string(),
            )
        })?;
        let stream = args["stream"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "eventstore_read_stream requires a \"stream\" argument".to_string(),
            )
        })?;
        let count = args["count"].as_i64().unwrap_or(20);
        let target = ctx.resolve_resource(resource)?;
        let result = get_json(
            ctx,
            &target,
            self.name(),
            &format!("/streams/{stream}/head/backward/{count}?embed=body"),
        )
        .await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

/// Subscription/projection status — position vs stream head, running state.
pub struct ProjectionStatusTool;

#[async_trait]
impl Tool for ProjectionStatusTool {
    fn name(&self) -> &'static str {
        "eventstore_projection_status"
    }

    fn description(&self) -> &str {
        "Get a projection or catch-up subscription's status (position, running/stopped/ \
         faulted state). Remundo.Synchroniser runs ~55 catch-up subscriptions at replicas=1 \
         — a crash-loop here stalls every read model with no error anywhere else, so compare \
         position against the stream head before assuming the data itself is wrong."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "name": {"type": "string", "description": "projection/subscription name"}
            },
            "required": ["resource", "name"]
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
                "eventstore_projection_status requires a \"resource\" argument".to_string(),
            )
        })?;
        let name = args["name"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "eventstore_projection_status requires a \"name\" argument".to_string(),
            )
        })?;
        let target = ctx.resolve_resource(resource)?;
        let result = get_json(ctx, &target, self.name(), &format!("/projection/{name}")).await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FqTarget, ResourceType};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn target() -> FqTarget {
        FqTarget {
            project: "remundo".into(),
            env: "prod".into(),
            target: "es-cluster".into(),
            resource: Some((ResourceType::Eventstore, "primary".into())),
        }
    }

    fn ctx_with(base_url: &str, token: Option<&str>) -> ToolCtx {
        // Real Policy over a real EndpointExecutor (choke-point wiring in
        // miniature) — reads here prove they survive e-stop/audit/scrub,
        // not just that the HTTP path is right. The TempDir is the e-stop
        // sentinel dir; dropping it leaves the sentinel absent = disengaged.
        crate::tools::endpoint_test_ctx(target(), base_url, token).0
    }

    #[tokio::test]
    async fn read_stream_sends_bearer_auth_and_count() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/streams/orders-123/head/backward/5"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entries": []})))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), Some("tok"));
        let r = ReadStreamTool
            .call(
                &ctx,
                json!({"resource": target().to_string(), "stream": "orders-123", "count": 5}),
            )
            .await
            .unwrap();
        assert!(r.output.contains("entries"));
    }

    #[tokio::test]
    async fn projection_status_hits_projection_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/projection/orders-projection"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"status": "Running", "position": 12345})),
            )
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let r = ProjectionStatusTool
            .call(&ctx, json!({"resource": target().to_string(), "name": "orders-projection"}))
            .await
            .unwrap();
        assert!(r.output.contains("Running"));
        assert!(r.output.contains("12345"));
    }

    #[tokio::test]
    async fn non_2xx_is_user_facing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/projection/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let err = ProjectionStatusTool
            .call(&ctx, json!({"resource": target().to_string(), "name": "missing"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[tokio::test]
    async fn connection_refusal_is_internal() {
        let ctx = ctx_with("http://127.0.0.1:1", None);
        let err = ReadStreamTool
            .call(&ctx, json!({"resource": target().to_string(), "stream": "x"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }

    #[test]
    fn both_tools_are_read_only() {
        assert!(!ReadStreamTool.is_action());
        assert!(!ProjectionStatusTool.is_action());
    }
}
