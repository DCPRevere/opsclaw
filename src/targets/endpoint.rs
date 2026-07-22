//! HTTP-endpoint executor: the ONE transport for commands against declared
//! Resources — reads and mutations both. Endpoint tools compose a canonical
//! command line through the policy choke point exactly like ssh, and this
//! executor is what a favorable gate decision lands on — registered in the
//! policy executor map under the RESOURCE-QUALIFIED fq path
//! (`project::env::target::elasticsearch::logs`), so every HTTP call happens
//! inside audit-begin/audit-end, behind the e-stop check, with its response
//! scrubbed before it can reach LLM context (policy's `run_capped` does all
//! three) — an ES query is as audited and e-stoppable as an ssh command
//! (DESIGN §4: "no tool owns a connection; there is one execution path per
//! target type, and audit and policy live there").
//!
//! The canonical line is the contract between composer (tool) and performer
//! (this executor), the same way a shell command line is the contract with
//! sshd:
//!
//! - `endpoint-get <path>` — an authenticated GET returning the body.
//! - `endpoint-query <path> <json-body>` — a POST-SHAPED READ (an ES
//!   `_search` body, say); the path must be on the kind's query allowlist,
//!   so the "query" verb can never smuggle a mutation.
//! - `argocd app rollback <app> <id>` — the one v1 endpoint MUTATION.
//!
//! Parsing is strict: a line this executor doesn't recognize is an error,
//! never a guess — new vocabulary is added here deliberately, in step with
//! the composing tool and the risk classifier (`classify.rs` classifies
//! `endpoint-get`/`endpoint-query` lines as Read WITHOUT shell-segment
//! splitting; the read-safety guarantee lives HERE, in
//! [`read_path_allowed`]/[`query_path_allowed`], not in pattern-matching a
//! URL as if it were shell).

use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use super::{Command, ExecOutput, ProbeReport, TargetExecutor};
use crate::Result;
use crate::domain::ResourceType;
use crate::tools::endpoint::EndpointAuth;

pub struct EndpointExecutor {
    kind: ResourceType,
    /// Resolved connection: base url, credential, auth scheme, and the
    /// per-resource TLS client. The SAME auth the read registry hands to
    /// `ToolCtx` — built once by `targets::wiring`, so a resource that can
    /// be read can be acted on with identical trust and credentials.
    auth: EndpointAuth,
}

impl EndpointExecutor {
    pub fn new(kind: ResourceType, auth: EndpointAuth) -> Self {
        EndpointExecutor { kind, auth }
    }

    /// Perform one recognized command. Non-2xx is a FAILED COMMAND (exit 1,
    /// status + body on stderr — the command ran and failed, like a nonzero
    /// ssh exit), not a transport error; only failing to reach the endpoint
    /// at all is `Err`.
    async fn perform(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        timeout: Duration,
    ) -> Result<ExecOutput> {
        let started = std::time::Instant::now();
        let url = format!("{}{path}", self.auth.base_url);
        let mut req = self.auth.apply_auth(self.auth.client.request(method, &url)).timeout(timeout);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| crate::Error::Policy(format!("endpoint {url} unreachable: {e}")))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let duration_ms = started.elapsed().as_millis() as u64;
        if status.is_success() {
            Ok(ExecOutput { exit_code: 0, stdout: text, stderr: String::new(), duration_ms })
        } else {
            Ok(ExecOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: format!("HTTP {status}: {text}"),
                duration_ms,
            })
        }
    }
}

/// Substrings that mark a path as NOT a read regardless of kind or verb —
/// defence in depth under the strict vocabulary: even if a composing tool
/// let a hostile fragment through into a `<path>`, the executor refuses it.
const READ_DENY_FRAGMENTS: &[&str] = &[
    "_delete",
    "_update",
    "_reindex",
    "_forcemerge",
    "_shutdown",
    "_shrink",
    "_split",
    "_clone",
    "/admin/",
];

fn deny_fragment(path: &str) -> Option<&'static str> {
    READ_DENY_FRAGMENTS.iter().find(|f| path.contains(**f)).copied()
}

/// Is `path` an acceptable GET for this resource kind? GETs are reads on
/// every v1 endpoint API, so the per-kind rule is a prefix sanity check
/// (plus the global deny list); stub kinds have no read vocabulary at all.
fn read_path_allowed(kind: ResourceType, path: &str) -> std::result::Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("endpoint path {path:?} must start with '/'"));
    }
    if let Some(f) = deny_fragment(path) {
        return Err(format!("endpoint path {path:?} contains {f:?} — not a read"));
    }
    match kind {
        ResourceType::Elasticsearch | ResourceType::Eventstore | ResourceType::AzureServiceBus => {
            Ok(())
        }
        ResourceType::Prometheus | ResourceType::Argocd => {
            if path.starts_with("/api/v1/") {
                Ok(())
            } else {
                Err(format!("{kind} reads live under /api/v1/, got {path:?}"))
            }
        }
        other => Err(format!("{other} has no endpoint read vocabulary yet")),
    }
}

/// Is `path` an acceptable POST-shaped READ (`endpoint-query`)? Much
/// stricter than GET: only search/count-style ES endpoints qualify — a POST
/// anywhere else is a mutation and must arrive as its own explicit
/// vocabulary line (like argocd rollback), never through the query verb.
fn query_path_allowed(kind: ResourceType, path: &str) -> std::result::Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("endpoint path {path:?} must start with '/'"));
    }
    if let Some(f) = deny_fragment(path) {
        return Err(format!("endpoint path {path:?} contains {f:?} — not a read"));
    }
    let last = path.rsplit('/').next().unwrap_or("");
    let last = last.split('?').next().unwrap_or(""); // tolerate ?size=…
    match kind {
        ResourceType::Elasticsearch if matches!(last, "_search" | "_count" | "_msearch") => Ok(()),
        ResourceType::Elasticsearch => Err(format!(
            "elasticsearch endpoint-query only accepts _search/_count/_msearch paths, got {path:?}"
        )),
        other => Err(format!("{other} has no POST-shaped read vocabulary")),
    }
}

#[async_trait]
impl TargetExecutor for EndpointExecutor {
    async fn run(&self, cmd: &Command, timeout: Duration) -> Result<ExecOutput> {
        let parts: Vec<&str> = cmd.line.split_whitespace().collect();
        match (self.kind, parts.as_slice()) {
            // Reads (composed by tools/endpoint.rs::{get_json, query_json}).
            (kind, ["endpoint-get", path]) => {
                read_path_allowed(kind, path).map_err(crate::Error::Policy)?;
                self.perform(reqwest::Method::GET, path, None, timeout).await
            }
            (kind, ["endpoint-query", path, ..]) => {
                query_path_allowed(kind, path).map_err(crate::Error::Policy)?;
                // The body is everything after the path, verbatim (JSON has
                // spaces; re-join what whitespace-split tore apart is wrong
                // — slice the original line instead).
                let body_start =
                    cmd.line.find(path).map(|i| i + path.len()).unwrap_or(cmd.line.len());
                let raw = cmd.line[body_start..].trim();
                let body: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
                    crate::Error::Policy(format!("endpoint-query body is not valid JSON: {e}"))
                })?;
                self.perform(reqwest::Method::POST, path, Some(body), timeout).await
            }
            // The one v1 endpoint mutation (DESIGN §4 decision 7): composed by
            // tools/argocd.rs as `argocd app rollback <app> <history-id>`.
            (ResourceType::Argocd, ["argocd", "app", "rollback", app, id]) => {
                let id: i64 = id.parse().map_err(|_| {
                    crate::Error::Policy(format!(
                        "argocd rollback: history id {id:?} is not a number"
                    ))
                })?;
                self.perform(
                    reqwest::Method::POST,
                    &format!("/api/v1/applications/{app}/rollback"),
                    Some(json!({ "id": id })),
                    timeout,
                )
                .await
            }
            _ => Err(crate::Error::Policy(format!(
                "endpoint executor ({:?}) does not recognize command {:?} — \
                 vocabulary is added here in step with the composing tool",
                self.kind, cmd.line
            ))),
        }
    }

    async fn probe(&self) -> Result<ProbeReport> {
        let path = match self.kind {
            ResourceType::Argocd => "/healthz",
            _ => "/",
        };
        let url = format!("{}{path}", self.auth.base_url);
        match self
            .auth
            .apply_auth(self.auth.client.get(&url))
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => Ok(ProbeReport {
                reachable: resp.status().is_success(),
                detail: format!("{url} -> {}", resp.status()),
            }),
            Err(e) => Ok(ProbeReport { reachable: false, detail: format!("{url}: {e}") }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::FqTarget;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn exec(kind: ResourceType, base_url: &str, token: Option<&str>) -> EndpointExecutor {
        EndpointExecutor::new(kind, EndpointAuth::new(base_url, token.map(str::to_string)))
    }

    fn cmd(line: &str) -> Command {
        let mut target = FqTarget::new("remundo", "prod", "cluster");
        target.resource = Some((ResourceType::Argocd, "main".into()));
        Command { target, line: line.into() }
    }

    #[tokio::test]
    async fn rollback_posts_the_parsed_app_and_id_with_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/guestbook/rollback"))
            .and(header("authorization", "Bearer sekret-token"))
            .and(body_json(serde_json::json!({ "id": 7 })))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .expect(1)
            .mount(&server)
            .await;
        let ex = exec(ResourceType::Argocd, &server.uri(), Some("sekret-token"));
        let out =
            ex.run(&cmd("argocd app rollback guestbook 7"), Duration::from_secs(5)).await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("ok"));
    }

    #[tokio::test]
    async fn non_2xx_is_a_failed_command_not_a_transport_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(409).set_body_string("rollback conflict"))
            .mount(&server)
            .await;
        let ex = exec(ResourceType::Argocd, &server.uri(), None);
        let out =
            ex.run(&cmd("argocd app rollback guestbook 7"), Duration::from_secs(5)).await.unwrap();
        assert_eq!(out.exit_code, 1);
        assert!(out.stderr.contains("409"), "stderr: {}", out.stderr);
        assert!(out.stderr.contains("rollback conflict"));
    }

    #[tokio::test]
    async fn unrecognized_line_is_an_error_never_a_guess() {
        let ex = exec(ResourceType::Argocd, "http://127.0.0.1:1", None);
        let err =
            ex.run(&cmd("argocd app delete guestbook"), Duration::from_secs(1)).await.unwrap_err();
        assert!(err.to_string().contains("does not recognize"), "{err}");
    }

    #[tokio::test]
    async fn bad_history_id_is_rejected_before_any_request() {
        let ex = exec(ResourceType::Argocd, "http://127.0.0.1:1", None);
        let err = ex
            .run(&cmd("argocd app rollback guestbook seven"), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not a number"), "{err}");
    }

    #[tokio::test]
    async fn endpoint_get_performs_an_authenticated_read() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_cluster/health"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"status\":\"green\"}"))
            .mount(&server)
            .await;
        let ex = exec(ResourceType::Elasticsearch, &server.uri(), Some("tok"));
        let out =
            ex.run(&cmd("endpoint-get /_cluster/health"), Duration::from_secs(5)).await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("green"));
    }

    #[tokio::test]
    async fn endpoint_query_posts_the_json_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/logs-2026/_search"))
            .and(body_json(serde_json::json!({"query": {"match_all": {}}, "size": 5})))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"hits\":{\"total\":0}}"))
            .mount(&server)
            .await;
        let ex = exec(ResourceType::Elasticsearch, &server.uri(), None);
        let out = ex
            .run(
                &cmd(
                    r#"endpoint-query /logs-2026/_search {"query": {"match_all": {}}, "size": 5}"#,
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
        assert!(out.stdout.contains("hits"));
    }

    #[tokio::test]
    async fn endpoint_query_refuses_a_non_search_path() {
        // The "query" verb must never smuggle a mutation: a POST path off
        // the search allowlist is refused BEFORE any request happens (the
        // executor points at an unroutable address — reaching it would Err
        // differently).
        let ex = exec(ResourceType::Elasticsearch, "http://127.0.0.1:1", None);
        let err = ex
            .run(&cmd(r#"endpoint-query /logs-2026/_doc {"evil": true}"#), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("_search"), "{err}");
    }

    #[tokio::test]
    async fn endpoint_get_refuses_deny_fragments_and_bad_prefixes() {
        let es = exec(ResourceType::Elasticsearch, "http://127.0.0.1:1", None);
        let err = es
            .run(&cmd("endpoint-get /logs/_delete_by_query"), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not a read"), "{err}");

        let prom = exec(ResourceType::Prometheus, "http://127.0.0.1:1", None);
        let err = prom.run(&cmd("endpoint-get /-/quit"), Duration::from_secs(1)).await.unwrap_err();
        assert!(err.to_string().contains("/api/v1/"), "{err}");
    }

    #[tokio::test]
    async fn stub_kinds_have_no_read_vocabulary() {
        let ex = exec(ResourceType::Postgres, "http://127.0.0.1:1", None);
        let err = ex.run(&cmd("endpoint-get /anything"), Duration::from_secs(1)).await.unwrap_err();
        assert!(err.to_string().contains("no endpoint read vocabulary"), "{err}");
    }

    #[tokio::test]
    async fn probe_reports_health() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/healthz"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let ex = exec(ResourceType::Argocd, &server.uri(), None);
        let report = ex.probe().await.unwrap();
        assert!(report.reachable);
    }
}
