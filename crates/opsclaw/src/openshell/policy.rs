//! Policy enforcement via the OpenShell policy engine.
//!
//! Before executing a remediation action, OpsClaw can ask the OpenShell policy
//! engine whether the action is permitted.  If OpenShell is not active the
//! check is a no-op that always returns `Ok(true)`.

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
/// Returns `Ok(true)` when:
/// - OpenShell is not active (fall back to internal autonomy)
/// - The policy engine approves the action
/// - The policy engine is unreachable (fail-open; Phase 2 can add fail-closed)
///
/// Returns `Ok(false)` only when the policy engine explicitly denies the action.
pub async fn check_policy(ctx: &OpenShellContext, action: &str, target: &str) -> Result<bool> {
    if !ctx.is_active() {
        return Ok(true);
    }

    let Some(endpoint) = ctx.policy_endpoint.as_deref() else {
        warn!("OpenShell active but no policy endpoint configured — allowing action");
        return Ok(true);
    };

    let url = format!("{endpoint}/api/check");
    let body = PolicyRequest { action, target };

    let result = reqwest::Client::new().post(&url).json(&body).send().await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            let policy: PolicyResponse = resp.json().await.unwrap_or(PolicyResponse { allowed: true });
            Ok(policy.allowed)
        }
        Ok(resp) => {
            warn!(
                status = %resp.status(),
                "OpenShell policy endpoint returned non-success — failing open"
            );
            Ok(true)
        }
        Err(e) => {
            warn!(error = %e, "Failed to reach OpenShell policy engine — failing open");
            Ok(true)
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
    async fn active_without_endpoint_allows() {
        let ctx = OpenShellContext {
            active: true,
            sandbox_id: Some("test".into()),
            policy_endpoint: None,
            audit_endpoint: None,
        };
        assert!(check_policy(&ctx, "restart", "web-1").await.unwrap());
    }

    #[tokio::test]
    async fn unreachable_endpoint_fails_open() {
        let ctx = OpenShellContext {
            active: true,
            sandbox_id: Some("test".into()),
            policy_endpoint: Some("http://127.0.0.1:1".into()),
            audit_endpoint: None,
        };
        assert!(check_policy(&ctx, "restart", "web-1").await.unwrap());
    }
}
