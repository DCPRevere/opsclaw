//! Audit event emission for OpenShell.
//!
//! OpenShell audit events are funnelled through the upstream zeroclaw
//! [`AuditLogger`](zeroclaw_runtime::security::AuditLogger), which writes a
//! Merkle-hash-chained, append-only JSONL log. That way OpenShell actions land
//! in the same tamper-evident trail as every other security event.
//!
//! Audit is best-effort: if the logger cannot be constructed or a write fails,
//! a warning is logged and execution continues — never panics, never returns
//! an error to the caller.

use serde::Serialize;
use tracing::warn;

use zeroclaw_config::schema::AuditConfig;
use zeroclaw_runtime::security::{AuditEvent as ZcAuditEvent, AuditEventType, AuditLogger};

use super::OpenShellContext;

/// A single OpenShell audit event. Callers describe *what* happened; the
/// emitter translates this into a chained entry in the zeroclaw audit log.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub action: String,
    pub target: String,
    /// `"approved"`, `"denied"`, or `"executed"`.
    pub outcome: String,
    pub details: serde_json::Value,
}

/// Append an OpenShell audit event to the zeroclaw audit log.
///
/// The log lives at `<zeroclaw_dir>/<audit.log_path>` (default: `audit.log`)
/// and is hash-chained — each entry is `SHA-256(prev_hash || content)`, so
/// tampering invalidates every subsequent entry.
///
/// If the logger cannot be constructed (missing signing key, unreadable
/// directory) or the write fails, a warning is logged and the function
/// returns without error. Audit is best-effort by design.
pub async fn emit_audit_event(ctx: &OpenShellContext, event: &AuditEvent) {
    let zeroclaw_dir = match resolve_zeroclaw_dir() {
        Some(d) => d,
        None => {
            warn!("Cannot resolve zeroclaw dir — OpenShell audit event dropped");
            return;
        }
    };

    let logger = match AuditLogger::new(AuditConfig::default(), zeroclaw_dir) {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, "Failed to open audit logger — OpenShell audit event dropped");
            return;
        }
    };

    let sandbox = ctx.sandbox_id.clone();
    let zc_event = ZcAuditEvent::new(AuditEventType::SecurityEvent)
        .with_actor("openshell".to_string(), sandbox.clone(), sandbox)
        .with_action(
            event.action.clone(),
            String::new(),
            matches!(event.outcome.as_str(), "approved" | "executed"),
            !matches!(event.outcome.as_str(), "denied"),
        )
        .with_result(
            !matches!(event.outcome.as_str(), "denied"),
            None,
            0,
            None,
        )
        .with_security(Some(format!(
            "openshell:{}:{}:{}",
            event.target, event.outcome, event.details
        )));

    if let Err(e) = logger.log(&zc_event) {
        warn!(error = %e, "Failed to write OpenShell audit event to chained log");
    }
}

/// Resolve the zeroclaw config dir (mirrors `zeroclaw::Config::default_path`'s
/// parent). Prefers `ZEROCLAW_CONFIG_DIR`, then `$HOME/.zeroclaw`.
fn resolve_zeroclaw_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("ZEROCLAW_CONFIG_DIR") {
        return Some(std::path::PathBuf::from(dir));
    }
    directories::UserDirs::new().map(|u| u.home_dir().join(".zeroclaw"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emit_tolerates_missing_zeroclaw_dir() {
        let saved_home = std::env::var("HOME").ok();
        let saved_dir = std::env::var("ZEROCLAW_CONFIG_DIR").ok();
        std::env::remove_var("HOME");
        std::env::remove_var("ZEROCLAW_CONFIG_DIR");

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

        if let Some(v) = saved_home {
            std::env::set_var("HOME", v);
        }
        if let Some(v) = saved_dir {
            std::env::set_var("ZEROCLAW_CONFIG_DIR", v);
        }
    }

    #[tokio::test]
    async fn emit_writes_to_temp_audit_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let saved = std::env::var("ZEROCLAW_CONFIG_DIR").ok();
        std::env::set_var("ZEROCLAW_CONFIG_DIR", tmp.path());

        let ctx = OpenShellContext {
            active: true,
            sandbox_id: Some("sb-1".into()),
            policy_endpoint: None,
            audit_endpoint: None,
        };
        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            action: "restart".into(),
            target: "web-1".into(),
            outcome: "executed".into(),
            details: serde_json::json!({"cmd": "systemctl restart nginx"}),
        };
        emit_audit_event(&ctx, &event).await;

        let log = tmp.path().join("audit.log");
        assert!(log.exists(), "audit log should be written to zeroclaw dir");
        let contents = std::fs::read_to_string(&log).expect("read log");
        assert!(contents.contains("\"entry_hash\""));
        assert!(contents.contains("\"prev_hash\""));

        match saved {
            Some(v) => std::env::set_var("ZEROCLAW_CONFIG_DIR", v),
            None => std::env::remove_var("ZEROCLAW_CONFIG_DIR"),
        }
    }
}
