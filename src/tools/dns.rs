//! `dns` — DNS lookup vocabulary (brief §10 "Diagnostic", DESIGN.md §4:
//! "`dns`/`cert` sit here too but accept an optional target (resolve/check
//! from a target's vantage or the daemon's)"). Composes `dig +short <type>
//! <name>` — a fixed shape from an allow-listed record-type set, never
//! free-text shell — and runs it through the policy choke point on the
//! chosen VANTAGE target: split-horizon DNS means "what does this name
//! resolve to" has a different true answer per host, so the tool takes an
//! optional target and falls back to the daemon's own `local`-kind target
//! (`ToolCtx::resolve_vantage`) when none is given.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct DnsTool;

/// The record types the tool will compose. An allow-list (like `systemd`'s
/// verb set) rather than pass-through: the classifier then only ever sees
/// `dig +short <KNOWN-TYPE> <validated-name>` shapes.
const RECORD_TYPES: &[&str] =
    &["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA"];

/// Validate the DNS name loosely (alnum plus `.-_` — underscores are load-
/// bearing for service/TXT names like `_dmarc.example.com`), so a name
/// can't inject shell metacharacters into the composed `dig` line. A
/// leading `-` is rejected separately: `dig` would read it as a flag, not
/// a name.
fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
}

fn compose(name: &str, record_type: &str) -> Result<String, ToolError> {
    if !valid_dns_name(name) {
        return Err(ToolError::UserFacing(format!(
            "invalid DNS name {name:?} — expected a plain name (letters, digits, .-_ only, \
             not starting with a dash)"
        )));
    }
    let rtype = record_type.to_ascii_uppercase();
    if !RECORD_TYPES.contains(&rtype.as_str()) {
        return Err(ToolError::UserFacing(format!(
            "unknown record type {record_type:?}. Valid types: {}.",
            RECORD_TYPES.join(", ")
        )));
    }
    Ok(format!("dig +short {rtype} {name}"))
}

#[async_trait]
impl Tool for DnsTool {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn description(&self) -> &str {
        "Resolve a DNS name (dig +short) from a chosen vantage point. Pass \"target\" to \
         resolve from that host — what a name resolves to can legitimately differ per host \
         (split-horizon DNS, /etc/hosts overrides, broken resolvers); omit it to resolve \
         from the daemon's own host. An empty result means the name did not resolve to that \
         record type from that vantage — corroborate from a second vantage before concluding \
         a name is globally broken."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "the DNS name to resolve, e.g. api.example.com"},
                "record_type": {"type": "string", "enum": RECORD_TYPES, "description": "record type to query; defaults to A"},
                "target": {"type": "string", "description": "fully-qualified target to resolve FROM; omit to use the daemon's own host"}
            },
            "required": ["name"]
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
        let name = args["name"]
            .as_str()
            .ok_or_else(|| ToolError::UserFacing("dns requires a \"name\" argument".to_string()))?;
        let record_type = args["record_type"].as_str().unwrap_or("A");
        let command = compose(name, record_type)?;
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
        FqTarget::new("example", "prod", "web-1")
    }

    fn ctx_with(policy: Arc<dyn PolicyExecute>) -> ToolCtx {
        let mut ctx = ToolCtx::for_tests(Principal::Agent { job: None }, policy);
        ctx.known_targets = vec![target()];
        ctx
    }

    /// A ctx whose config declares `bastion` as a `local`-kind target, so
    /// the vantage fallback has something to fall back TO.
    fn ctx_with_local(policy: Arc<dyn PolicyExecute>) -> ToolCtx {
        let config: crate::config::Config = toml::from_str(
            r#"
            [[project]]
            name = "example"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "bastion"
            kind = "local"
            "#,
        )
        .unwrap();
        let mut ctx = ToolCtx::for_tests(Principal::Agent { job: None }, policy);
        ctx.known_targets = vec![FqTarget::new("example", "prod", "bastion")];
        ctx.config = Some(Arc::new(config));
        ctx
    }

    #[tokio::test]
    async fn composes_dig_with_default_type_a() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, "93.184.216.34"));
        let ctx = ctx_with(policy.clone());
        DnsTool
            .call(&ctx, json!({"target": "example::prod::web-1", "name": "api.example.com"}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].command, "dig +short A api.example.com");
        assert_eq!(seen[0].declared_risk, RiskClass::Read);
        assert_eq!(seen[0].target, target());
    }

    #[tokio::test]
    async fn record_type_is_uppercased_into_the_command() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        DnsTool
            .call(
                &ctx,
                json!({"target": "example::prod::web-1", "name": "example.com", "record_type": "txt"}),
            )
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].command, "dig +short TXT example.com");
    }

    #[tokio::test]
    async fn no_target_falls_back_to_the_local_target() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with_local(policy.clone());
        DnsTool.call(&ctx, json!({"name": "example.com"})).await.unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].target, FqTarget::new("example", "prod", "bastion"));
    }

    #[tokio::test]
    async fn no_target_and_no_local_target_errors_clearly() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone()); // web-1 only, no config ⇒ no local
        let err = DnsTool.call(&ctx, json!({"name": "example.com"})).await.unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("target"), "{msg}"),
            other => panic!("expected UserFacing, got {other:?}"),
        }
        assert!(policy.seen.lock().unwrap().is_empty(), "must never reach policy");
    }

    #[tokio::test]
    async fn name_with_shell_metacharacters_is_rejected() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = DnsTool
            .call(&ctx, json!({"target": "example::prod::web-1", "name": "example.com; rm -rf /"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty(), "must never reach policy");
    }

    #[tokio::test]
    async fn name_starting_with_a_dash_is_rejected_as_a_flag_injection() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = DnsTool
            .call(&ctx, json!({"target": "example::prod::web-1", "name": "-f"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unknown_record_type_is_user_facing() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy);
        let err = DnsTool
            .call(
                &ctx,
                json!({"target": "example::prod::web-1", "name": "example.com", "record_type": "AXFR"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[test]
    fn is_read_only() {
        assert!(!DnsTool.is_action());
        assert_eq!(DnsTool.risk(), RiskClass::Read);
        assert!(DnsTool.allowed_in_heartbeat());
    }
}
