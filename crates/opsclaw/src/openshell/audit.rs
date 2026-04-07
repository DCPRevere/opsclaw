//! Audit event emission for OpenShell.
//!
//! When running inside an OpenShell sandbox, significant actions are forwarded
//! to the audit endpoint as JSON.  If the endpoint is unavailable the event is
//! logged locally and execution continues — audit is always best-effort.

use serde::Serialize;
use tracing::warn;

use super::OpenShellContext;

/// A single audit event to be sent to the OpenShell audit endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub action: String,
    pub target: String,
    /// `"approved"`, `"denied"`, or `"executed"`.
    pub outcome: String,
    pub details: serde_json::Value,
}

/// Post an audit event to the OpenShell audit endpoint.
///
/// If the context has no audit endpoint configured, or if the HTTP call fails,
/// a warning is logged and execution continues — this function never panics or
/// returns an error.
pub async fn emit_audit_event(ctx: &OpenShellContext, event: &AuditEvent) {
    let Some(endpoint) = ctx.audit_endpoint.as_deref() else {
        warn!("OpenShell audit endpoint not configured — skipping audit event");
        return;
    };

    let url = format!("{endpoint}/api/audit");

    let result = reqwest::Client::new().post(&url).json(event).send().await;

    match result {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            warn!(
                status = %resp.status(),
                "OpenShell audit endpoint returned non-success status"
            );
        }
        Err(e) => {
            warn!(error = %e, "Failed to send audit event to OpenShell");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emit_skips_when_no_endpoint() {
        let ctx = OpenShellContext {
            active: true,
            sandbox_id: Some("test".into()),
            policy_endpoint: None,
            audit_endpoint: None,
        };
        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            action: "restart".into(),
            target: "web-1".into(),
            outcome: "approved".into(),
            details: serde_json::json!({}),
        };
        // Should not panic — just logs a warning.
        emit_audit_event(&ctx, &event).await;
    }

    #[tokio::test]
    async fn emit_tolerates_unreachable_endpoint() {
        let ctx = OpenShellContext {
            active: true,
            sandbox_id: Some("test".into()),
            policy_endpoint: None,
            audit_endpoint: Some("http://127.0.0.1:1".into()),
        };
        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            action: "restart".into(),
            target: "web-1".into(),
            outcome: "executed".into(),
            details: serde_json::json!({"cmd": "systemctl restart nginx"}),
        };
        // Should not panic — logs a warning about connection failure.
        emit_audit_event(&ctx, &event).await;
    }
}
