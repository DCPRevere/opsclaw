//! Optional OpenShell integration.
//!
//! OpenShell (NVIDIA, Apache 2.0) is an out-of-process policy enforcement
//! runtime for agents.  When OpsClaw runs inside an OpenShell sandbox the
//! runtime sets a handful of environment variables.  This module detects them
//! at startup and exposes the context to the rest of the crate so that policy
//! checks and audit logging can be performed transparently.
//!
//! If OpenShell is **not** present every helper falls back to a no-op — zero
//! behaviour change.

pub mod audit;
pub mod policy;

/// Captured OpenShell environment detected at startup.
#[derive(Debug, Clone)]
pub struct OpenShellContext {
    pub active: bool,
    pub sandbox_id: Option<String>,
    /// Policy engine endpoint, e.g. `http://localhost:7070`.
    pub policy_endpoint: Option<String>,
    /// Audit log endpoint.
    pub audit_endpoint: Option<String>,
}

impl OpenShellContext {
    /// Detect OpenShell at startup by reading environment variables set by the
    /// OpenShell runtime.
    ///
    /// Checks:
    /// 1. `OPENSHELL_ACTIVE` — presence activates integration
    /// 2. `OPENSHELL_SANDBOX_ID`
    /// 3. `OPENSHELL_POLICY_ENDPOINT`
    /// 4. `OPENSHELL_AUDIT_ENDPOINT`
    pub fn detect() -> Self {
        let active = std::env::var("OPENSHELL_ACTIVE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if !active {
            return Self {
                active: false,
                sandbox_id: None,
                policy_endpoint: None,
                audit_endpoint: None,
            };
        }

        Self {
            active: true,
            sandbox_id: std::env::var("OPENSHELL_SANDBOX_ID").ok(),
            policy_endpoint: std::env::var("OPENSHELL_POLICY_ENDPOINT").ok(),
            audit_endpoint: std::env::var("OPENSHELL_AUDIT_ENDPOINT").ok(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_inactive_when_env_unset() {
        // With no env vars set the context should be inactive.
        // (Other tests may have set them, so we clear first.)
        unsafe { std::env::remove_var("OPENSHELL_ACTIVE"); }
        let ctx = OpenShellContext::detect();
        assert!(!ctx.is_active());
        assert!(ctx.sandbox_id.is_none());
    }

    #[test]
    fn detect_active_with_env_vars() {
        unsafe { std::env::set_var("OPENSHELL_ACTIVE", "1"); }
        unsafe { std::env::set_var("OPENSHELL_SANDBOX_ID", "sandbox-42"); }
        unsafe { std::env::set_var("OPENSHELL_POLICY_ENDPOINT", "http://localhost:7070"); }
        unsafe { std::env::set_var("OPENSHELL_AUDIT_ENDPOINT", "http://localhost:7071"); }

        let ctx = OpenShellContext::detect();
        assert!(ctx.is_active());
        assert_eq!(ctx.sandbox_id.as_deref(), Some("sandbox-42"));
        assert_eq!(
            ctx.policy_endpoint.as_deref(),
            Some("http://localhost:7070")
        );
        assert_eq!(ctx.audit_endpoint.as_deref(), Some("http://localhost:7071"));

        // Cleanup
        unsafe { std::env::remove_var("OPENSHELL_ACTIVE"); }
        unsafe { std::env::remove_var("OPENSHELL_SANDBOX_ID"); }
        unsafe { std::env::remove_var("OPENSHELL_POLICY_ENDPOINT"); }
        unsafe { std::env::remove_var("OPENSHELL_AUDIT_ENDPOINT"); }
    }
}
