//! `azure_service_bus` — queue/DLQ depth and peek (DESIGN.md §4 item 2;
//! docs/REMUNDO.md: "DLQ depth/peek is daily on-call work" and "DLQ
//! backlog: peek → classify poison vs transient → resubmit via Reprocessor
//! strategy"). v1 is read-only per the brief's `azure_service_bus` scope —
//! resubmit/purge (a genuine mutation) is a later addition once that
//! workflow is scoped; this tool only informs the DECISION, matching
//! REMUNDO.md's actual runbook shape where resubmission goes through
//! `Remundo.Reprocessor`, not a direct queue mutation from the agent.
//!
//! Plain HTTP against the Service Bus management/REST API shape (Atom feed
//! over HTTPS) rather than an Azure SDK — DESIGN.md's "no azure SDK dep"
//! constraint for v1; `EndpointAuth.token` carries a SAS/bearer credential
//! resolved the same way as every other endpoint tool.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::endpoint::get_json;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

fn client() -> reqwest::Client {
    crate::tools::endpoint::client()
}

/// Active + dead-letter message counts for a queue.
pub struct QueueDepthTool;

#[async_trait]
impl Tool for QueueDepthTool {
    fn name(&self) -> &'static str {
        "azure_service_bus_queue_depth"
    }

    fn description(&self) -> &str {
        "Get active and dead-letter message counts for an Azure Service Bus queue. DLQ \
         backlog growth means either the daily Reprocessor CronJob is failing, or messages \
         are truly dead and recycling on the retry-count config — check both before \
         concluding."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "queue": {"type": "string", "description": "queue name"}
            },
            "required": ["resource", "queue"]
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
                "azure_service_bus_queue_depth requires a \"resource\" argument".to_string(),
            )
        })?;
        let queue = args["queue"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "azure_service_bus_queue_depth requires a \"queue\" argument".to_string(),
            )
        })?;
        let (_, auth) = ctx.resolve_resource(resource)?;
        let result =
            get_json(&client(), auth, self.name(), &format!("/{queue}?api-version=2021-05"))
                .await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

/// Peek (non-destructively read, without locking/removing) messages from a
/// queue or its dead-letter subqueue.
pub struct PeekMessagesTool;

#[async_trait]
impl Tool for PeekMessagesTool {
    fn name(&self) -> &'static str {
        "azure_service_bus_peek"
    }

    fn description(&self) -> &str {
        "Peek messages from a queue (or its dead-letter subqueue with dead_letter=true) — a \
         non-destructive read (nothing is locked or removed). Use to classify DLQ contents \
         as poison vs transient before deciding what the Reprocessor should do with them."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "queue": {"type": "string"},
                "dead_letter": {"type": "boolean", "description": "peek the dead-letter subqueue (default false)"},
                "count": {"type": "integer", "description": "max messages to peek (default 10)"}
            },
            "required": ["resource", "queue"]
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
                "azure_service_bus_peek requires a \"resource\" argument".to_string(),
            )
        })?;
        let queue = args["queue"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "azure_service_bus_peek requires a \"queue\" argument".to_string(),
            )
        })?;
        let dead_letter = args["dead_letter"].as_bool().unwrap_or(false);
        let count = args["count"].as_i64().unwrap_or(10);
        let (_, auth) = ctx.resolve_resource(resource)?;

        let sub_path =
            if dead_letter { format!("{queue}/$deadletterqueue") } else { queue.to_string() };
        let result = get_json(
            &client(),
            auth,
            self.name(),
            &format!("/{sub_path}/messages/head?api-version=2021-05&count={count}"),
        )
        .await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FqTarget, Principal, ResourceType};
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use crate::tools::endpoint::{EndpointAuth, EndpointRegistry};
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
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
            target: "sb-worker".into(),
            resource: Some((ResourceType::AzureServiceBus, "orders".into())),
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

    #[tokio::test]
    async fn queue_depth_sends_bearer_auth() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orders-dlq"))
            .and(header("authorization", "Bearer sas-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"activeMessageCount": 42})),
            )
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), Some("sas-token"));
        let r = QueueDepthTool
            .call(&ctx, json!({"resource": target().to_string(), "queue": "orders-dlq"}))
            .await
            .unwrap();
        assert!(r.output.contains("42"));
    }

    #[tokio::test]
    async fn peek_default_targets_the_queue_not_dlq() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orders/messages/head"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        PeekMessagesTool
            .call(&ctx, json!({"resource": target().to_string(), "queue": "orders"}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn peek_dead_letter_targets_the_subqueue() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orders/$deadletterqueue/messages/head"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"body": "poison"}])))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let r = PeekMessagesTool
            .call(
                &ctx,
                json!({"resource": target().to_string(), "queue": "orders", "dead_letter": true}),
            )
            .await
            .unwrap();
        assert!(r.output.contains("poison"));
    }

    #[tokio::test]
    async fn non_2xx_is_user_facing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orders-dlq"))
            .respond_with(ResponseTemplate::new(404).set_body_string("queue not found"))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let err = QueueDepthTool
            .call(&ctx, json!({"resource": target().to_string(), "queue": "orders-dlq"}))
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("404")),
            _ => panic!("expected UserFacing"),
        }
    }

    #[tokio::test]
    async fn connection_refusal_is_internal() {
        // Port 1: reserved/privileged, reliably unbound (see endpoint.rs's
        // equivalent test for why this beats dropping a MockServer).
        let ctx = ctx_with("http://127.0.0.1:1", None);
        let err = QueueDepthTool
            .call(&ctx, json!({"resource": target().to_string(), "queue": "x"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }

    #[test]
    fn both_tools_are_read_only() {
        assert!(!QueueDepthTool.is_action());
        assert!(!PeekMessagesTool.is_action());
    }
}
