//! HTTP-endpoint executor: the transport for MUTATIONS against declared
//! Resources (argocd rollback, and future endpoint mutations). Closes the gap
//! documented in `tools/argocd.rs`: endpoint tools compose a canonical
//! command line ("argocd app rollback <app> <id>") through the policy choke
//! point exactly like ssh, and this executor is what a favorable gate
//! decision lands on — registered in the policy executor map under the
//! RESOURCE-QUALIFIED fq path (`project::env::target::argocd::name`), so the
//! HTTP call happens inside audit-begin/audit-end like every other command.
//!
//! The canonical line is the contract between composer (tool) and performer
//! (this executor), the same way a shell command line is the contract with
//! sshd. Parsing is strict: a line this executor doesn't recognize is an
//! error, never a guess — new vocabulary is added here deliberately, in step
//! with the composing tool and the risk classifier.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use super::{Command, ExecOutput, ProbeReport, TargetExecutor};
use crate::Result;
use crate::domain::ResourceType;

pub struct EndpointExecutor {
    kind: ResourceType,
    /// Trimmed of any trailing slash.
    base_url: String,
    /// Bearer token, already resolved (and registered with the scrubber by
    /// whoever built this executor). `None` for unauthenticated endpoints.
    token: Option<String>,
    client: reqwest::Client,
}

impl EndpointExecutor {
    pub fn new(kind: ResourceType, base_url: &str, token: Option<String>) -> Self {
        EndpointExecutor {
            kind,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client: reqwest::Client::new(),
        }
    }

    fn bearer(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    /// Perform one recognized mutation. Non-2xx is a FAILED COMMAND (exit 1,
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
        let url = format!("{}{path}", self.base_url);
        let mut req = self.bearer(self.client.request(method, &url)).timeout(timeout);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| {
            crate::Error::Policy(format!("endpoint {url} unreachable: {e}"))
        })?;
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

#[async_trait]
impl TargetExecutor for EndpointExecutor {
    async fn run(&self, cmd: &Command, timeout: Duration) -> Result<ExecOutput> {
        let parts: Vec<&str> = cmd.line.split_whitespace().collect();
        match (self.kind, parts.as_slice()) {
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
        let url = format!("{}{path}", self.base_url);
        match self.bearer(self.client.get(&url)).timeout(Duration::from_secs(5)).send().await {
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
        let ex =
            EndpointExecutor::new(ResourceType::Argocd, &server.uri(), Some("sekret-token".into()));
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
        let ex = EndpointExecutor::new(ResourceType::Argocd, &server.uri(), None);
        let out =
            ex.run(&cmd("argocd app rollback guestbook 7"), Duration::from_secs(5)).await.unwrap();
        assert_eq!(out.exit_code, 1);
        assert!(out.stderr.contains("409"), "stderr: {}", out.stderr);
        assert!(out.stderr.contains("rollback conflict"));
    }

    #[tokio::test]
    async fn unrecognized_line_is_an_error_never_a_guess() {
        let ex = EndpointExecutor::new(ResourceType::Argocd, "http://127.0.0.1:1", None);
        let err = ex
            .run(&cmd("argocd app delete guestbook"), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not recognize"), "{err}");
    }

    #[tokio::test]
    async fn bad_history_id_is_rejected_before_any_request() {
        let ex = EndpointExecutor::new(ResourceType::Argocd, "http://127.0.0.1:1", None);
        let err = ex
            .run(&cmd("argocd app rollback guestbook seven"), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not a number"), "{err}");
    }

    #[tokio::test]
    async fn probe_reports_health() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/healthz"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let ex = EndpointExecutor::new(ResourceType::Argocd, &server.uri(), None);
        let report = ex.probe().await.unwrap();
        assert!(report.reachable);
    }
}
