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

use crate::config::{Config, SecretStore};
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

/// Build an `EndpointRegistry` from config, resolving every declared
/// resource's credential via `store` — the SAME walk
/// `targets::wiring::build_executors` uses to build its `ExecutorMap`
/// (project → env → target → resource), so a resource that gets an
/// executor there gets read-tool credentials here too, with no drift
/// between the two.
///
/// Deliberately does NOT register resolved tokens with the policy
/// `Scrubber` — `targets::wiring::build_executors` already does that for
/// every resource with a URL at boot time (before any executor that could
/// echo the value exists), and scrubber registration is idempotent per
/// (name, value) but keyed by a caller-chosen NAME
/// (`"{rtype}_{rname}_TOKEN"` there); calling it a second time from here
/// with a DIFFERENT name for the same value would register the same secret
/// under two names, which is harmless for redaction (either name catches
/// it) but a needless divergence from "register once, at the one
/// composition root". This function's caller (agent dispatch, `src/agent/
/// dispatch.rs`) is expected to run `build_executors` (or equivalent) first
/// so scrubber registration has already happened by the time any tool call
/// could echo a token back.
///
/// A resource with no `url` is skipped (nothing to build an `EndpointAuth`
/// around) — mirrors `build_executors`'s "no url -> warning, no executor"
/// rule, but this function has no warnings channel of its own (the caller
/// already gets those from `build_executors` for the same resources; a
/// second, identical warning here would be redundant, not new
/// information). A resource whose credential fails to resolve is a boot
/// ERROR, same fail-closed direction as `build_executors` — a half-wired
/// registry must not silently grant read access with no auth where a
/// credential was declared but unreadable.
pub fn registry_from_config(config: &Config, store: &SecretStore) -> crate::Result<EndpointRegistry> {
    let mut registry = EndpointRegistry::new();
    for project in &config.projects {
        for env in &project.envs {
            for target in &env.targets {
                let base = FqTarget::new(&project.name, &env.name, &target.name);
                for resource in &target.resources {
                    let Some(url) = &resource.url else {
                        continue; // no url -> no executor either; nothing to wire here
                    };
                    let token = match &resource.credential {
                        Some(r) => Some(r.resolve(store)?),
                        None => None,
                    };
                    let mut fq = base.clone();
                    fq.resource = Some((resource.rtype, resource.name.clone()));
                    registry.insert(&fq, EndpointAuth::new(url, token));
                }
            }
        }
    }
    Ok(registry)
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

    fn config_from(toml: &str) -> Config {
        toml::from_str(toml).expect("test config parses")
    }

    fn secret_store() -> (tempfile::TempDir, SecretStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn registry_from_config_wires_resource_qualified_endpoints() {
        unsafe { std::env::set_var("ENDPOINT_TEST_ARGOCD_TOKEN", "argo-secret") };
        let config = config_from(
            r#"
            [[project]]
            name = "remundo"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "bastion"
            kind = "local"
            [[project.env.target.resource]]
            type = "argocd"
            name = "main"
            url = "https://argocd.example"
            credential = "env:ENDPOINT_TEST_ARGOCD_TOKEN"
            "#,
        );
        let (_dir, store) = secret_store();
        let reg = registry_from_config(&config, &store).unwrap();
        let target = FqTarget {
            project: "remundo".into(),
            env: "prod".into(),
            target: "bastion".into(),
            resource: Some((crate::domain::ResourceType::Argocd, "main".into())),
        };
        let auth = reg.get(&target).expect("registered");
        assert_eq!(auth.base_url, "https://argocd.example");
        assert_eq!(auth.token.as_deref(), Some("argo-secret"));
    }

    #[test]
    fn registry_from_config_skips_a_resource_with_no_url() {
        let config = config_from(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "local"
            [[project.env.target.resource]]
            type = "prometheus"
            name = "prom"
            "#,
        );
        let (_dir, store) = secret_store();
        let reg = registry_from_config(&config, &store).unwrap();
        assert!(reg.known_targets().is_empty());
    }

    #[test]
    fn registry_from_config_unresolvable_credential_is_a_boot_error() {
        let config = config_from(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "local"
            [[project.env.target.resource]]
            type = "prometheus"
            name = "prom"
            url = "http://prom.example"
            credential = "env:ENDPOINT_TEST_DEFINITELY_UNSET"
            "#,
        );
        let (_dir, store) = secret_store();
        let err = registry_from_config(&config, &store).unwrap_err();
        assert!(err.to_string().contains("not set"), "{err}");
    }

    #[test]
    fn registry_from_config_resource_with_no_credential_has_no_token() {
        let config = config_from(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "local"
            [[project.env.target.resource]]
            type = "prometheus"
            name = "prom"
            url = "http://prom.example"
            "#,
        );
        let (_dir, store) = secret_store();
        let reg = registry_from_config(&config, &store).unwrap();
        let target = FqTarget {
            project: "p".into(),
            env: "e".into(),
            target: "t".into(),
            resource: Some((crate::domain::ResourceType::Prometheus, "prom".into())),
        };
        assert!(reg.get(&target).unwrap().token.is_none());
    }
}
