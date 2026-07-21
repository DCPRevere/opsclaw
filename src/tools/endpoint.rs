//! Shared plumbing for endpoint-backed tools (DESIGN.md §4 "Tool surface",
//! item 2): protocol/HTTP clients against declared `Resource`s
//! (elasticsearch, azure_service_bus, eventstore, prometheus, argocd).
//!
//! ## Credential resolution — NOT wired yet, documented gap
//!
//! `config::ResourceCfg` already carries `url: Option<String>` and
//! `credential: Option<SecretRef>` (config/mod.rs) — the config-side
//! declaration exists. What does NOT exist yet is the daemon-wiring code
//! that resolves each declared resource's `SecretRef` to an actual value
//! (via `SecretStore`), registers that value with the policy layer's output
//! `Scrubber` (`policy::scrub::Scrubber`, so a leaked token in a response
//! body gets redacted the same way a leaked ssh credential does), and hands
//! the RESOLVED [`EndpointAuth`] to `ToolCtx`. That wiring lives wherever
//! `AppState`/the daemon boot path constructs `ToolCtx` — out of scope for
//! `tools/` (this module has no `SecretStore` or `Scrubber` access, and
//! shouldn't: a tool holding a `SecretRef` would have to resolve it itself
//! on every call, duplicating scrubber registration per tool instead of
//! once at boot). Until that wiring lands, `ToolCtx.endpoints` is `None` and
//! every endpoint-backed tool in this module is absent from the registry
//! (see `tools::registry`'s gating) — same fail-closed shape as
//! `ctx.memory`/`ctx.incidents` being `None` today.
//!
//! ## Shape
//!
//! [`EndpointAuth`] is a RESOLVED base URL + optional bearer token — the
//! same "already resolved, never a reference" shape
//! `memory::hindsight::HindsightClient::new` takes, so nothing in `tools/`
//! ever sees a `SecretRef`. [`EndpointRegistry`] maps a resource's fully-
//! qualified target string (`FqTarget::to_string()`, resource-qualified
//! form: `project::env::target::resource_type::name`) to its
//! `EndpointAuth`, so one daemon can hold several resources of the same
//! type (two elasticsearch clusters) without collision. [`get_json`] is the
//! one authenticated-GET-return-JSON helper every read-only endpoint
//! operation uses; mutation operations (argocd rollback) do NOT use this
//! module at all — they compose a synthetic command line and go through
//! `tools::executor::run_command` exactly like an ssh/kubernetes tool
//! (DESIGN.md §4: "a rollback over an HTTP client is as classified, gated,
//! and audited as an ssh command").

use std::collections::HashMap;

use serde_json::Value;

use crate::domain::FqTarget;
use crate::tools::ToolError;

/// A resolved endpoint credential — never a `SecretRef`. See module doc for
/// why resolution happens outside `tools/`.
#[derive(Debug, Clone)]
pub struct EndpointAuth {
    /// Already trimmed of a trailing slash.
    pub base_url: String,
    /// `None` for an endpoint with no auth configured (a local dev
    /// prometheus, say) — not every resource requires a credential.
    pub token: Option<String>,
}

impl EndpointAuth {
    pub fn new(base_url: impl Into<String>, token: Option<String>) -> Self {
        EndpointAuth { base_url: base_url.into().trim_end_matches('/').to_string(), token }
    }
}

/// Resolved endpoint credentials for every configured resource this daemon
/// knows about, keyed by the resource's fully-qualified target string
/// (`FqTarget::to_string()`, resource-qualified form). Built once at daemon
/// wiring time (not yet — see module doc) and handed to `ToolCtx` as
/// `Option<Arc<EndpointRegistry>>`.
#[derive(Debug, Clone, Default)]
pub struct EndpointRegistry {
    by_target: HashMap<String, EndpointAuth>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, target: &FqTarget, auth: EndpointAuth) {
        self.by_target.insert(target.to_string(), auth);
    }

    pub fn get(&self, target: &FqTarget) -> Option<&EndpointAuth> {
        self.by_target.get(&target.to_string())
    }

    /// Every resource-qualified target this registry has credentials for —
    /// used by `resolve_target`-style lookups so a tool can name the valid
    /// choices in its error message.
    pub fn known_targets(&self) -> Vec<String> {
        let mut v: Vec<String> = self.by_target.keys().cloned().collect();
        v.sort();
        v
    }
}

/// Authenticated GET, JSON response. `path` is appended to `auth.base_url`
/// as-is (callers build the full path including query string). Maps a
/// non-2xx response to `ToolError::UserFacing` (the status/body is useful
/// for the model to see and react to — a 404 vs a 500 mean different
/// things), and a transport-level failure (connection refused, DNS,
/// timeout) to `ToolError::Internal` with the standard do-not-retry framing
/// — mirrors the executor-backed tools' error-splitting discipline exactly.
pub async fn get_json(
    client: &reqwest::Client,
    auth: &EndpointAuth,
    tool: &str,
    path: &str,
) -> Result<Value, ToolError> {
    let mut req = client.get(format!("{}{path}", auth.base_url));
    if let Some(token) = &auth.token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(|e| {
        ToolError::Internal(format!(
            "{tool} is temporarily unreachable ({e}) — do NOT retry it this turn"
        ))
    })?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(500).collect();
        return Err(ToolError::UserFacing(format!(
            "{tool} returned HTTP {} for {path}: {snippet}",
            status.as_u16()
        )));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| ToolError::Internal(format!("{tool} returned unparseable JSON: {e}")))
}

/// Authenticated POST with a JSON body, JSON response — same error-splitting
/// as [`get_json`]. Used by read operations that are POST-shaped (an ES
/// `_search` query body, a prometheus range query) but are NOT mutations —
/// callers must not use this for anything that changes remote state; a
/// mutation goes through `tools::executor::run_command`, never this helper.
pub async fn post_json(
    client: &reqwest::Client,
    auth: &EndpointAuth,
    tool: &str,
    path: &str,
    body: &Value,
) -> Result<Value, ToolError> {
    let mut req = client.post(format!("{}{path}", auth.base_url)).json(body);
    if let Some(token) = &auth.token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(|e| {
        ToolError::Internal(format!(
            "{tool} is temporarily unreachable ({e}) — do NOT retry it this turn"
        ))
    })?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(500).collect();
        return Err(ToolError::UserFacing(format!(
            "{tool} returned HTTP {} for {path}: {snippet}",
            status.as_u16()
        )));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| ToolError::Internal(format!("{tool} returned unparseable JSON: {e}")))
}

/// A `reqwest::Client` with a bounded per-request timeout — endpoint calls
/// happen inside the agent tool loop (like `memory::hindsight`'s
/// `READ_TIMEOUT`), so a hung backend must not stall the whole turn.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest builds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn auth(base_url: &str, token: Option<&str>) -> EndpointAuth {
        EndpointAuth::new(base_url, token.map(str::to_string))
    }

    #[test]
    fn base_url_trims_trailing_slash() {
        let a = EndpointAuth::new("http://example.com/", None);
        assert_eq!(a.base_url, "http://example.com");
    }

    #[tokio::test]
    async fn get_json_sends_bearer_auth_and_parses_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "green"})))
            .mount(&server)
            .await;

        let result =
            get_json(&client(), &auth(&server.uri(), Some("secret-token")), "es", "/health")
                .await
                .unwrap();
        assert_eq!(result["status"], "green");
    }

    #[tokio::test]
    async fn get_json_without_token_sends_no_auth_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        // No `header("authorization", ...)` matcher — a request WITH an auth
        // header would still match this mock (wiremock doesn't assert
        // absence by default), so the real assertion is that the call
        // succeeds with no token configured, proving the header is skipped
        // without erroring.
        let result = get_json(&client(), &auth(&server.uri(), None), "es", "/health").await.unwrap();
        assert_eq!(result["ok"], true);
    }

    #[tokio::test]
    async fn non_2xx_becomes_user_facing_with_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(503).set_body_string("cluster unavailable"))
            .mount(&server)
            .await;

        let err = get_json(&client(), &auth(&server.uri(), None), "es", "/health")
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => {
                assert!(msg.contains("503"));
                assert!(msg.contains("cluster unavailable"));
            }
            _ => panic!("expected UserFacing"),
        }
    }

    #[tokio::test]
    async fn connection_refusal_becomes_internal_do_not_retry() {
        // Port 1 is a reserved/privileged port essentially never bound by an
        // ordinary process — a reliable "nothing is listening here" target,
        // unlike dropping a MockServer (the OS can keep the socket usable
        // briefly after Drop, making that pattern flaky).
        let err = get_json(&client(), &auth("http://127.0.0.1:1", None), "es", "/health")
            .await
            .unwrap_err();
        match err {
            ToolError::Internal(msg) => assert!(msg.contains("do NOT retry")),
            _ => panic!("expected Internal, got {err:?}"),
        }
    }

    #[tokio::test]
    async fn post_json_sends_body_and_bearer_auth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/query"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"result": []})))
            .mount(&server)
            .await;

        let body = serde_json::json!({"query": "up"});
        let result = post_json(&client(), &auth(&server.uri(), Some("tok")), "prometheus", "/query", &body)
            .await
            .unwrap();
        assert_eq!(result["result"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn post_json_non_2xx_is_user_facing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/query"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad promql"))
            .mount(&server)
            .await;
        let err = post_json(&client(), &auth(&server.uri(), None), "prometheus", "/query", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[test]
    fn registry_get_and_insert_by_fq_target() {
        let mut reg = EndpointRegistry::new();
        let target = FqTarget {
            project: "remundo".into(),
            env: "prod".into(),
            target: "cluster".into(),
            resource: Some((crate::domain::ResourceType::Elasticsearch, "logs".into())),
        };
        reg.insert(&target, EndpointAuth::new("http://es:9200", None));
        assert!(reg.get(&target).is_some());
        assert_eq!(reg.get(&target).unwrap().base_url, "http://es:9200");

        let other = FqTarget {
            project: "remundo".into(),
            env: "prod".into(),
            target: "cluster".into(),
            resource: Some((crate::domain::ResourceType::Elasticsearch, "other".into())),
        };
        assert!(reg.get(&other).is_none());
    }

    #[test]
    fn registry_known_targets_is_sorted() {
        let mut reg = EndpointRegistry::new();
        let t1 = FqTarget {
            project: "b".into(),
            env: "e".into(),
            target: "t".into(),
            resource: Some((crate::domain::ResourceType::Prometheus, "metrics".into())),
        };
        let t2 = FqTarget {
            project: "a".into(),
            env: "e".into(),
            target: "t".into(),
            resource: Some((crate::domain::ResourceType::Prometheus, "metrics".into())),
        };
        reg.insert(&t1, EndpointAuth::new("http://x", None));
        reg.insert(&t2, EndpointAuth::new("http://y", None));
        let known = reg.known_targets();
        assert_eq!(known, vec![t2.to_string(), t1.to_string()]);
    }
}
