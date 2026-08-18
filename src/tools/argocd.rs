//! `argocd` — app list, sync status (reads), and `rollback` (the ONE gated
//! mutation) — DESIGN.md §4 item 2; docs/REFERENCE.md: "GitOps shop:
//! remediation is a revert, not `kubectl apply`", "sync status `Unknown`
//! fleet-wide = repo credential problem", "`ComparisonError: repository not
//! found` on a private repo means credential, not missing repo."
//!
//! ## Rollback: a known execution gap, not silently routed around
//!
//! DESIGN.md's instruction is that a rollback over HTTP must be "as
//! classified, gated, and audited as an ssh command" — i.e. it should go
//! through `policy::PolicyExecute::execute` exactly like
//! `tools::executor::run_command` does for ssh/kubernetes, composing a
//! synthetic descriptive command line (`argocd app rollback <app>
//! <revision>`) so the classifier/audit trail have a stable string.
//!
//! [`RollbackTool`] does exactly that. But `Policy::execute`'s `Gate::Execute`
//! arm (policy/mod.rs) looks up a `TargetExecutor` by the request's
//! `FqTarget` and RUNS the command through it — there is no `TargetExecutor`
//! for an argocd HTTP resource (`domain::TargetKind` has no HTTP-endpoint
//! variant; argocd lives under a target as a `Resource`, not a target kind
//! of its own), so a gate decision of "execute" would hit
//! `Error::NotFound("no executor configured for ...")` inside `policy::`
//! rather than actually rolling anything back.
//!
//! This module does NOT work around that by performing the HTTP rollback
//! itself after a favorable gate decision — doing so would execute a
//! mutation with no entry in the hash-chained audit log (the chain is only
//! written by `policy::` around an actual `TargetExecutor.run()`), breaking
//! DESIGN.md's audit invariant ("no bypass exists") for the sake of making
//! the tool *appear* functional. Instead: `rollback` submits the synthetic
//! command through `ctx.policy.execute` for CLASSIFICATION AND GATING as
//! specified — `Blocked`/`NeedsApproval`/`EStopped` outcomes are reported
//! faithfully (a human decision correctly never executes an HTTP call
//! either way, so those paths are already correct and safe). Only the
//! `Executed` path is a real gap: it will currently return an internal
//! fault ("no executor configured") instead of performing the rollback,
//! reported here rather than silently worked around. The fix belongs to
//! whoever owns `policy`/`targets`: either an HTTP-capable `TargetExecutor`
//! variant, or a second `PolicyExecute` method for "gate this, then hand me
//! the go/no-go so I can execute it myself and you audit the result" —
//! analogous to the `ExecuteApproved` trait already added for the
//! approvals engine's post-approval execution gap.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::endpoint::get_json;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

/// List applications and their sync/health status for the fleet (or a
/// filtered subset).
pub struct ListAppsTool;

#[async_trait]
impl Tool for ListAppsTool {
    fn name(&self) -> &'static str {
        "argocd_list_apps"
    }

    fn description(&self) -> &str {
        "List ArgoCD applications with their sync and health status. A sync status of \
         Unknown across the WHOLE fleet usually means a repo credential problem, not that \
         every app is individually broken — check that before diffing individual apps."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {"resource": {"type": "string"}}
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
        let resource = args["resource"].as_str().ok_or_else(|| {
            ToolError::UserFacing("argocd_list_apps requires a \"resource\" argument".to_string())
        })?;
        let target = ctx.resolve_resource(resource)?;
        let result = get_json(ctx, &target, self.name(), "/api/v1/applications").await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

/// Detailed sync status for one named app: current revision, target
/// revision, comparison state (a `ComparisonError` on a private repo means
/// credential, not missing repo — REFERENCE.md).
pub struct SyncStatusTool;

#[async_trait]
impl Tool for SyncStatusTool {
    fn name(&self) -> &'static str {
        "argocd_sync_status"
    }

    fn description(&self) -> &str {
        "Get detailed sync status for one named ArgoCD application: current/target revision, \
         comparison state, any ComparisonError. A ComparisonError on a private repo typically \
         means a credential problem, not that the repository is actually missing."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "app": {"type": "string", "description": "application name"}
            },
            "required": ["resource", "app"]
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
        let resource = args["resource"].as_str().ok_or_else(|| {
            ToolError::UserFacing("argocd_sync_status requires a \"resource\" argument".to_string())
        })?;
        let app = args["app"].as_str().ok_or_else(|| {
            ToolError::UserFacing("argocd_sync_status requires an \"app\" argument".to_string())
        })?;
        let target = ctx.resolve_resource(resource)?;
        let result =
            get_json(ctx, &target, self.name(), &format!("/api/v1/applications/{app}")).await?;
        Ok(ToolResult { output: result.to_string() })
    }
}

/// The ONE gated mutation: roll an application back to a prior deployed
/// revision (a GitOps shop's remediation lever — a revert, not `kubectl
/// apply`, per REFERENCE.md). Routes through `ctx.policy.execute` with a
/// synthetic command line for classification/gating; see the module doc for
/// the real execution gap on the `Executed` path.
pub struct RollbackTool;

#[async_trait]
impl Tool for RollbackTool {
    fn name(&self) -> &'static str {
        "argocd_rollback"
    }

    fn description(&self) -> &str {
        "Roll an ArgoCD application back to a prior deployed revision — the standard \
         remediation in a GitOps shop (a revert, never a direct kubectl apply). Requires the \
         target `revision` (the history id/SHA to roll back to, from the app's deployment \
         history) and a `hypothesis` explaining why. This is a MUTATION and is classified/ \
         gated by policy exactly like a remote command — it may require human approval."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "app": {"type": "string", "description": "application name"},
                "revision": {"type": "string", "description": "the deployment-history revision id/SHA to roll back to"},
                "hypothesis": {"type": "string", "description": "why this rollback is warranted"}
            },
            "required": ["resource", "app", "revision", "hypothesis"]
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::High
    }

    fn is_action(&self) -> bool {
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        // A rollback is exactly the kind of mutation a heartbeat scan
        // should not perform unattended without a human's explicit ask —
        // the gate itself would likely require approval anyway at any
        // sane autonomy level, but keeping it out of the heartbeat subset
        // is the same "deny-by-default for mutations in job runs" rule
        // ssh/systemd/docker/kubernetes already follow at the tool-surface
        // level, applied here too even though the true gate is downstream.
        false
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let resource = args["resource"].as_str().ok_or_else(|| {
            ToolError::UserFacing("argocd_rollback requires a \"resource\" argument".to_string())
        })?;
        let app = args["app"].as_str().ok_or_else(|| {
            ToolError::UserFacing("argocd_rollback requires an \"app\" argument".to_string())
        })?;
        let revision = args["revision"].as_str().ok_or_else(|| {
            ToolError::UserFacing("argocd_rollback requires a \"revision\" argument".to_string())
        })?;
        let hypothesis = args["hypothesis"].as_str().map(str::to_string);

        let target = ctx.resolve_resource(resource)?;
        // Synthetic, stable, descriptive command line — not literally
        // runnable shell, but exactly what the classifier/audit need: a
        // deterministic string naming the app and target revision (see
        // module doc for why this stops at the gate decision today).
        let command = format!("argocd app rollback {app} {revision}");
        run_command(ctx, self.name(), target, command, self.risk(), hypothesis).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FqTarget, Principal, ResourceType};
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use crate::tools::endpoint::{EndpointAuth, EndpointRegistry};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn target() -> FqTarget {
        FqTarget {
            project: "example".into(),
            env: "prod".into(),
            target: "cluster".into(),
            resource: Some((ResourceType::Argocd, "gitops".into())),
        }
    }

    fn ctx_with_policy(
        base_url: &str,
        token: Option<&str>,
        policy: Arc<dyn PolicyExecute>,
    ) -> ToolCtx {
        let mut reg = EndpointRegistry::new();
        reg.insert(&target(), EndpointAuth::new(base_url, token.map(str::to_string)));
        ToolCtx {
            principal: Principal::Agent { job: None },
            policy,
            known_targets: vec![target()],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: Some(Arc::new(reg)),
            runbooks: None,
        }
    }

    #[tokio::test]
    async fn list_apps_sends_bearer_auth() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        let (ctx, _dir) = crate::tools::endpoint_test_ctx(target(), &server.uri(), Some("tok"));
        let r = ListAppsTool.call(&ctx, json!({"resource": target().to_string()})).await.unwrap();
        assert!(r.output.contains("items"));
    }

    #[tokio::test]
    async fn sync_status_hits_the_named_app() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/api-service"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"status": {"sync": {"status": "Synced"}}})),
            )
            .mount(&server)
            .await;
        let (ctx, _dir) = crate::tools::endpoint_test_ctx(target(), &server.uri(), None);
        let r = SyncStatusTool
            .call(&ctx, json!({"resource": target().to_string(), "app": "api-service"}))
            .await
            .unwrap();
        assert!(r.output.contains("Synced"));
    }

    #[tokio::test]
    async fn non_2xx_read_is_user_facing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;
        let (ctx, _dir) = crate::tools::endpoint_test_ctx(target(), &server.uri(), None);
        let err =
            ListAppsTool.call(&ctx, json!({"resource": target().to_string()})).await.unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("403")),
            _ => panic!("expected UserFacing"),
        }
    }

    /// Records every `CommandRequest` it's handed — proves `argocd_rollback`
    /// composes the exact synthetic command line and routes through the
    /// SAME choke point ssh/kubernetes/etc. use, per DESIGN.md's
    /// requirement.
    struct RecordingPolicy {
        seen: Mutex<Vec<CommandRequest>>,
        outcome: Box<dyn Fn() -> PolicyOutcome + Send + Sync>,
    }

    #[async_trait]
    impl PolicyExecute for RecordingPolicy {
        async fn execute(&self, req: CommandRequest) -> crate::Result<PolicyOutcome> {
            self.seen.lock().unwrap().push(req);
            Ok((self.outcome)())
        }
    }

    #[tokio::test]
    async fn rollback_composes_the_exact_synthetic_command_and_routes_through_policy() {
        let policy = Arc::new(RecordingPolicy {
            seen: Mutex::new(Vec::new()),
            outcome: Box::new(|| PolicyOutcome::NeedsApproval(uuid::Uuid::nil())),
        });
        let ctx = ctx_with_policy("http://unused", None, policy.clone());
        let r = RollbackTool
            .call(
                &ctx,
                json!({
                    "resource": target().to_string(),
                    "app": "api-service",
                    "revision": "a1b2c3d",
                    "hypothesis": "bad deploy at 14:03, rolling back to last-known-good"
                }),
            )
            .await
            .unwrap();

        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].tool, "argocd_rollback");
        assert_eq!(seen[0].command, "argocd app rollback api-service a1b2c3d");
        assert_eq!(seen[0].declared_risk, RiskClass::High);
        assert_eq!(seen[0].target, target());
        assert!(seen[0].hypothesis.as_deref().unwrap().contains("bad deploy"),);
        // A gated mutation with no HTTP call made — this test's server (if
        // any were mounted) would show zero requests; here there is no
        // server at all, which would panic on a real HTTP attempt, proving
        // rollback never touches the network on a non-executed outcome.
        assert!(r.output.contains("NOT run yet"));
    }

    #[tokio::test]
    async fn rollback_blocked_outcome_is_reported_and_never_hits_the_network() {
        let policy = Arc::new(RecordingPolicy {
            seen: Mutex::new(Vec::new()),
            outcome: Box::new(|| PolicyOutcome::Blocked {
                reason: "observe autonomy".into(),
                dry_run_logged: true,
            }),
        });
        // Deliberately unreachable base_url — if rollback ever tried an
        // HTTP call on a Blocked outcome, this would surface as a
        // connection-refused Internal error instead of the Blocked text.
        let ctx = ctx_with_policy("http://127.0.0.1:1", None, policy);
        let r = RollbackTool
            .call(
                &ctx,
                json!({
                    "resource": target().to_string(),
                    "app": "api-service",
                    "revision": "a1b2c3d",
                    "hypothesis": "test"
                }),
            )
            .await
            .unwrap();
        assert!(r.output.contains("did NOT run"));
        assert!(r.output.contains("observe autonomy"));
    }

    #[test]
    fn rollback_is_high_risk_action_and_not_allowed_in_heartbeat() {
        assert!(RollbackTool.is_action());
        assert_eq!(RollbackTool.risk(), RiskClass::High);
        assert!(!RollbackTool.allowed_in_heartbeat());
    }

    #[test]
    fn reads_are_read_only_and_allowed_in_heartbeat() {
        assert!(!ListAppsTool.is_action());
        assert!(!SyncStatusTool.is_action());
        assert!(ListAppsTool.allowed_in_heartbeat());
        assert!(SyncStatusTool.allowed_in_heartbeat());
    }
}
