//! `cert` — TLS certificate check vocabulary (brief §10 "Diagnostic",
//! DESIGN.md §4: "`dns`/`cert` sit here too but accept an optional target
//! (resolve/check from a target's vantage or the daemon's)"). Composes the
//! standard openssl one-liner — `s_client` to fetch the presented chain,
//! piped into `x509 -noout -dates -subject -issuer` — from a validated
//! host and port, never free-text shell, and runs it through the policy
//! choke point on the chosen VANTAGE target: which certificate a host
//! PRESENTS can differ per vantage (SNI-routed proxies, split-horizon DNS,
//! an internal CA on the private leg), so the tool takes an optional
//! target and falls back to the daemon's own `local`-kind target
//! (`ToolCtx::resolve_vantage`) when none is given.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct CertTool;

/// Same loose shape check as `dns`'s name validation (alnum plus `.-_`,
/// no leading dash): enough to keep shell metacharacters and option
/// injection out of the composed openssl line. Covers hostnames and IPv4
/// literals; IPv6 literals are not accepted in v1 (colons would need
/// bracket handling in `-connect`).
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && host.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
}

fn compose(host: &str, port: u16) -> Result<String, ToolError> {
    if !valid_host(host) {
        return Err(ToolError::UserFacing(format!(
            "invalid host {host:?} — expected a plain hostname or IPv4 address (letters, \
             digits, .-_ only, not starting with a dash)"
        )));
    }
    // `</dev/null` closes s_client's stdin so it exits after the handshake
    // instead of waiting for input; stderr is dropped because s_client
    // narrates the handshake there and the x509 summary on stdout is the
    // evidence the model needs.
    Ok(format!(
        "openssl s_client -servername {host} -connect {host}:{port} </dev/null 2>/dev/null \
         | openssl x509 -noout -dates -subject -issuer"
    ))
}

#[async_trait]
impl Tool for CertTool {
    fn name(&self) -> &'static str {
        "cert"
    }

    fn description(&self) -> &str {
        "Check the TLS certificate a host presents: validity dates, subject, and issuer \
         (openssl s_client | x509). Pass \"target\" to check from that host's vantage — an \
         SNI proxy or split-horizon DNS can present a different certificate per vantage; \
         omit it to check from the daemon's own host. Use this to confirm an expiry \
         hypothesis with the actual notAfter date before escalating."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "hostname to connect to (also sent as SNI), e.g. api.example.com"},
                "port": {"type": "integer", "description": "TLS port; defaults to 443"},
                "target": {"type": "string", "description": "fully-qualified target to check FROM; omit to use the daemon's own host"}
            },
            "required": ["host"]
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
        let host = args["host"].as_str().ok_or_else(|| {
            ToolError::UserFacing("cert requires a \"host\" argument".to_string())
        })?;
        let port = match args.get("port") {
            None | Some(Value::Null) => 443u16,
            Some(v) => {
                v.as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0).ok_or_else(
                    || ToolError::UserFacing(format!("invalid port {v} — expected 1-65535")),
                )?
            }
        };
        let command = compose(host, port)?;
        let target = ctx.resolve_vantage(args["target"].as_str())?;
        run_command(ctx, self.name(), target, command, self.risk(), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FqTarget, Principal};
    use crate::policy::PolicyExecute;
    use crate::tools::executor::tests::RecordingPolicy;
    use std::sync::Arc;

    fn target() -> FqTarget {
        FqTarget::new("remundo", "prod", "web-1")
    }

    fn ctx_with(policy: Arc<dyn PolicyExecute>) -> ToolCtx {
        let mut ctx = ToolCtx::for_tests(Principal::Agent { job: None }, policy);
        ctx.known_targets = vec![target()];
        ctx
    }

    #[tokio::test]
    async fn composes_the_openssl_pipeline_with_default_port() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, "notAfter=..."));
        let ctx = ctx_with(policy.clone());
        CertTool
            .call(&ctx, json!({"target": "remundo::prod::web-1", "host": "api.example.com"}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(
            seen[0].command,
            "openssl s_client -servername api.example.com -connect api.example.com:443 \
             </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer"
        );
        assert_eq!(seen[0].declared_risk, RiskClass::Read);
    }

    #[tokio::test]
    async fn explicit_port_lands_in_the_connect_argument() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        CertTool
            .call(
                &ctx,
                json!({"target": "remundo::prod::web-1", "host": "db.internal", "port": 8443}),
            )
            .await
            .unwrap();
        assert!(policy.seen.lock().unwrap()[0].command.contains("-connect db.internal:8443"));
    }

    #[tokio::test]
    async fn host_with_shell_metacharacters_is_rejected() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = CertTool
            .call(&ctx, json!({"target": "remundo::prod::web-1", "host": "example.com;id"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty(), "must never reach policy");
    }

    #[tokio::test]
    async fn out_of_range_port_is_user_facing() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        for bad in [json!(0), json!(70000), json!("https")] {
            let err = CertTool
                .call(
                    &ctx,
                    json!({"target": "remundo::prod::web-1", "host": "example.com", "port": bad}),
                )
                .await
                .unwrap_err();
            assert!(matches!(err, ToolError::UserFacing(_)));
        }
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_target_and_no_local_target_errors_clearly() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = CertTool.call(&ctx, json!({"host": "example.com"})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn is_read_only() {
        assert!(!CertTool.is_action());
        assert_eq!(CertTool.risk(), RiskClass::Read);
        assert!(CertTool.allowed_in_heartbeat());
    }
}
