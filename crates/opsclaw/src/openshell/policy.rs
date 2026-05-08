//! Policy enforcement via the OpenShell policy engine.
//!
//! Before executing a remediation action, OpsClaw can ask the OpenShell policy
//! engine whether the action is permitted. If OpenShell is active, lookup
//! failures deny the action.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::OpenShellContext;

#[derive(Serialize)]
struct PolicyRequest<'a> {
    action: &'a str,
    target: &'a str,
}

#[derive(Deserialize)]
struct PolicyResponse {
    allowed: bool,
}

/// Ask the OpenShell policy engine whether `action` on `target` is allowed.
///
/// Returns `Ok(true)` only when OpenShell is inactive or the active policy
/// endpoint returns a successful, parseable `{ "allowed": true }` response.
pub async fn check_policy(ctx: &OpenShellContext, action: &str, target: &str) -> Result<bool> {
    if !ctx.is_active() {
        return Ok(true);
    }

    let Some(endpoint) = ctx.policy_endpoint.as_deref() else {
        warn!("OpenShell active but no policy endpoint configured — denying action");
        return Ok(false);
    };

    let url = format!("{endpoint}/api/check");
    let body = PolicyRequest { action, target };

    let result = reqwest::Client::new().post(&url).json(&body).send().await;

    match result {
        Ok(resp) if resp.status().is_success() => match resp.json::<PolicyResponse>().await {
            Ok(policy) => Ok(policy.allowed),
            Err(e) => {
                warn!(error = %e, "OpenShell policy response parse failed — denying action");
                Ok(false)
            }
        },
        Ok(resp) => {
            warn!(
                status = %resp.status(),
                "OpenShell policy endpoint returned non-success — denying action"
            );
            Ok(false)
        }
        Err(e) => {
            warn!(error = %e, "Failed to reach OpenShell policy engine — denying action");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inactive_context_always_allows() {
        let ctx = OpenShellContext {
            active: false,
            sandbox_id: None,
            policy_endpoint: None,
            audit_endpoint: None,
        };
        assert!(check_policy(&ctx, "restart", "web-1").await.unwrap());
    }

    #[tokio::test]
    async fn active_without_endpoint_denies() {
        let ctx = OpenShellContext {
            active: true,
            sandbox_id: Some("test".into()),
            policy_endpoint: None,
            audit_endpoint: None,
        };
        assert!(!check_policy(&ctx, "restart", "web-1").await.unwrap());
    }

    #[tokio::test]
    async fn unreachable_endpoint_fails_closed() {
        let ctx = OpenShellContext {
            active: true,
            sandbox_id: Some("test".into()),
            policy_endpoint: Some("http://127.0.0.1:1".into()),
            audit_endpoint: None,
        };
        assert!(!check_policy(&ctx, "restart", "web-1").await.unwrap());
    }

    #[tokio::test]
    async fn malformed_success_response_fails_closed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/check"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let ctx = OpenShellContext {
            active: true,
            sandbox_id: Some("test".into()),
            policy_endpoint: Some(server.uri()),
            audit_endpoint: None,
        };
        assert!(!check_policy(&ctx, "restart", "web-1").await.unwrap());
    }
}
