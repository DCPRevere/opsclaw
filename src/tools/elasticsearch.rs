//! `elasticsearch` — search, index stats, cluster health (DESIGN.md §4 item
//! 2; docs/REMUNDO.md: "it's read models AND logs — remundo ships logs via
//! Filebeat into ES, so log search is an ES query and `loki` stays a
//! stub"). All three operations are reads — no mutation surface here.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::endpoint::{get_json, query_json};
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

/// `_search` against an index or index pattern — the vocabulary for both
/// read-model queries and log search (REMUNDO.md: same ES instance serves
/// both).
pub struct ElasticsearchSearchTool;

#[async_trait]
impl Tool for ElasticsearchSearchTool {
    fn name(&self) -> &'static str {
        "elasticsearch_search"
    }

    fn description(&self) -> &str {
        "Run an Elasticsearch _search query against an index/index-pattern — for both read \
         model queries and log search (logs ship via Filebeat into ES, ECS fields; there is \
         no separate log store). `query` is the raw Elasticsearch Query DSL body (e.g. \
         {\"query\":{\"match\":{\"message\":\"connection refused\"}}})."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string", "description": "fully-qualified elasticsearch resource"},
                "index": {"type": "string", "description": "index name or pattern, e.g. remundo-logs-*"},
                "query": {"type": "object", "description": "Elasticsearch Query DSL body"},
                "size": {"type": "integer", "description": "max hits to return (default 20)"}
            },
            "required": ["resource", "index", "query"]
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
                "elasticsearch_search requires a \"resource\" argument".to_string(),
            )
        })?;
        let index = args["index"].as_str().ok_or_else(|| {
            ToolError::UserFacing("elasticsearch_search requires an \"index\" argument".to_string())
        })?;
        let query = args.get("query").cloned().ok_or_else(|| {
            ToolError::UserFacing("elasticsearch_search requires a \"query\" argument".to_string())
        })?;
        let size = args["size"].as_i64().unwrap_or(20);

        let target = ctx.resolve_resource(resource)?;
        let mut body = query;
        if let Value::Object(map) = &mut body {
            map.entry("size").or_insert(json!(size));
        }
        let result =
            query_json(ctx, &target, self.name(), &format!("/{index}/_search"), &body).await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

/// `_stats` for an index/pattern — size, doc count, health at the index
/// level (finer-grained than `_cluster/health`).
pub struct ElasticsearchIndexStatsTool;

#[async_trait]
impl Tool for ElasticsearchIndexStatsTool {
    fn name(&self) -> &'static str {
        "elasticsearch_index_stats"
    }

    fn description(&self) -> &str {
        "Get index-level stats (doc count, size, health) for an index or index pattern. Use \
         to check whether a synchroniser projection index is growing/shrinking as expected."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "index": {"type": "string", "description": "index name or pattern"}
            },
            "required": ["resource", "index"]
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
                "elasticsearch_index_stats requires a \"resource\" argument".to_string(),
            )
        })?;
        let index = args["index"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "elasticsearch_index_stats requires an \"index\" argument".to_string(),
            )
        })?;
        let target = ctx.resolve_resource(resource)?;
        let result = get_json(ctx, &target, self.name(), &format!("/{index}/_stats")).await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

/// `_cluster/health` — cluster-wide status (green/yellow/red), shard
/// counts. The first thing to check before trusting a "read model looks
/// stale" hypothesis is about data vs about the cluster itself.
pub struct ElasticsearchClusterHealthTool;

#[async_trait]
impl Tool for ElasticsearchClusterHealthTool {
    fn name(&self) -> &'static str {
        "elasticsearch_cluster_health"
    }

    fn description(&self) -> &str {
        "Get Elasticsearch cluster health (status green/yellow/red, node/shard counts). Check \
         this before assuming a data problem is application-level — a yellow/red cluster \
         explains a lot on its own."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {"resource": {"type": "string"}},
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
        let resource = args["resource"].as_str().ok_or_else(|| {
            ToolError::UserFacing(
                "elasticsearch_cluster_health requires a \"resource\" argument".to_string(),
            )
        })?;
        let target = ctx.resolve_resource(resource)?;
        let result = get_json(ctx, &target, self.name(), "/_cluster/health").await?;
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
            target: "cluster".into(),
            resource: Some((ResourceType::Elasticsearch, "logs".into())),
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
    async fn search_sends_bearer_auth_and_posts_query_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/remundo-logs-*/_search"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits": {"total": 3}})))
            .mount(&server)
            .await;

        let ctx = ctx_with(&server.uri(), Some("tok"));
        let r = ElasticsearchSearchTool
            .call(
                &ctx,
                json!({
                    "resource": target().to_string(),
                    "index": "remundo-logs-*",
                    "query": {"query": {"match": {"message": "timeout"}}}
                }),
            )
            .await
            .unwrap();
        assert!(r.output.contains("\"total\":3"));
    }

    #[tokio::test]
    async fn index_stats_hits_stats_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/remundo-read-model/_stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"_all": {"total": {}}})))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let r = ElasticsearchIndexStatsTool
            .call(&ctx, json!({"resource": target().to_string(), "index": "remundo-read-model"}))
            .await
            .unwrap();
        assert!(r.output.contains("_all"));
    }

    #[tokio::test]
    async fn cluster_health_hits_health_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_cluster/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "yellow"})))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let r = ElasticsearchClusterHealthTool
            .call(&ctx, json!({"resource": target().to_string()}))
            .await
            .unwrap();
        assert!(r.output.contains("yellow"));
    }

    #[tokio::test]
    async fn non_2xx_is_user_facing_with_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_cluster/health"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&server)
            .await;
        let ctx = ctx_with(&server.uri(), None);
        let err = ElasticsearchClusterHealthTool
            .call(&ctx, json!({"resource": target().to_string()}))
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("503")),
            _ => panic!("expected UserFacing"),
        }
    }

    #[tokio::test]
    async fn connection_refusal_is_internal_do_not_retry() {
        let ctx = ctx_with("http://127.0.0.1:1", None);
        let err = ElasticsearchClusterHealthTool
            .call(&ctx, json!({"resource": target().to_string()}))
            .await
            .unwrap_err();
        match err {
            ToolError::Internal(msg) => assert!(msg.contains("do NOT retry")),
            _ => panic!("expected Internal"),
        }
    }

    #[tokio::test]
    async fn unresolved_resource_is_user_facing() {
        let ctx = ctx_with("http://unused", None);
        let err = ElasticsearchClusterHealthTool
            .call(&ctx, json!({"resource": "nonexistent::env::target::elasticsearch::x"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[test]
    fn all_three_tools_are_read_only() {
        assert!(!ElasticsearchSearchTool.is_action());
        assert!(!ElasticsearchIndexStatsTool.is_action());
        assert!(!ElasticsearchClusterHealthTool.is_action());
        assert_eq!(ElasticsearchSearchTool.risk(), RiskClass::Read);
    }
}
