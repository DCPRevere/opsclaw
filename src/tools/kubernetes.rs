//! `kubernetes` — the exec-path tool over a kubernetes target (DESIGN.md §4
//! item 1, brief §10: "`kubernetes` is one tool"). Composes a plain
//! `kubectl` subcommand line (no leading `kubectl` — the
//! `targets::KubernetesExecutor` supplies the binary and
//! `--kubeconfig`/`--context` flags itself, see that module's doc) from a
//! small verb set: get/describe/logs (read), rollout-restart/delete-pod
//! (mutating). Read-model/API-side kubernetes access (watch, list across
//! namespaces via `kube-rs`) is a later endpoint-backed tool per DESIGN.md
//! §4; this is the exec path only.

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::executor::run_command;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct KubernetesTool;

/// Loose validation for a resource name / namespace: kubernetes names are
/// lowercase alnum plus `-.`, so this both catches obvious injection
/// attempts and matches the real naming rules closely enough to be a useful
/// early error.
fn valid_k8s_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-.".contains(c))
}

fn compose(
    action: &str,
    resource: Option<&str>,
    name: Option<&str>,
    namespace: Option<&str>,
    all_namespaces: bool,
) -> Result<String, ToolError> {
    // "all-namespaces"/"all" pass valid_k8s_name and kubectl treats them as a
    // LITERAL namespace — empty output, exit 0, and the model concludes the
    // cluster is quiet (observed live: a scan swept 12 namespaces one call at
    // a time after this silent miss). Catch the intent and redirect it.
    if let Some(ns) = namespace
        && matches!(ns, "all" | "all-namespaces" | "*")
    {
        return Err(ToolError::UserFacing(format!(
            "{ns:?} is not a namespace — pass all_namespaces: true to sweep every namespace \
             in one call"
        )));
    }
    let ns_flag = if all_namespaces {
        if !matches!(action, "get" | "describe") {
            return Err(ToolError::UserFacing(format!(
                "all_namespaces only applies to get/describe, not {action:?} — pass the pod's \
                 own namespace"
            )));
        }
        if namespace.is_some_and(|ns| !ns.is_empty()) {
            return Err(ToolError::UserFacing(
                "pass either \"namespace\" or all_namespaces: true, not both".to_string(),
            ));
        }
        " -A".to_string()
    } else {
        match namespace {
            Some(ns) if !ns.is_empty() => {
                if !valid_k8s_name(ns) {
                    return Err(ToolError::UserFacing(format!("invalid namespace {ns:?}")));
                }
                format!(" -n {ns}")
            }
            _ => String::new(),
        }
    };

    match action {
        "get" | "describe" => {
            let resource = resource.ok_or_else(|| {
                ToolError::UserFacing(format!(
                    "kubernetes {action} requires a \"resource\" argument"
                ))
            })?;
            if !valid_k8s_name(resource) {
                return Err(ToolError::UserFacing(format!("invalid resource type {resource:?}")));
            }
            let mut cmd = format!("{action} {resource}");
            if let Some(n) = name {
                if !valid_k8s_name(n) {
                    return Err(ToolError::UserFacing(format!("invalid resource name {n:?}")));
                }
                cmd.push(' ');
                cmd.push_str(n);
            }
            cmd.push_str(&ns_flag);
            Ok(cmd)
        }
        "logs" => {
            let name = name.ok_or_else(|| {
                ToolError::UserFacing(
                    "kubernetes logs requires a \"name\" argument (the pod name)".to_string(),
                )
            })?;
            if !valid_k8s_name(name) {
                return Err(ToolError::UserFacing(format!("invalid pod name {name:?}")));
            }
            Ok(format!("logs {name} --tail=200{ns_flag}"))
        }
        "rollout_restart" => {
            let resource = resource.ok_or_else(|| {
                ToolError::UserFacing(
                    "kubernetes rollout_restart requires a \"resource\" argument, e.g. deploy/api"
                        .to_string(),
                )
            })?;
            // resource here is a slash-form ref (deploy/api) — validate each
            // segment rather than the whole string.
            if !resource.split('/').all(valid_k8s_name) || !resource.contains('/') {
                return Err(ToolError::UserFacing(format!(
                    "invalid rollout resource {resource:?} — expected kind/name, e.g. deploy/api"
                )));
            }
            Ok(format!("rollout restart {resource}{ns_flag}"))
        }
        "delete_pod" => {
            let name = name.ok_or_else(|| {
                ToolError::UserFacing(
                    "kubernetes delete_pod requires a \"name\" argument".to_string(),
                )
            })?;
            if !valid_k8s_name(name) {
                return Err(ToolError::UserFacing(format!("invalid pod name {name:?}")));
            }
            Ok(format!("delete pod {name}{ns_flag}"))
        }
        other => Err(ToolError::UserFacing(format!(
            "unknown kubernetes action {other:?}. Valid actions: get, describe, logs, \
             rollout_restart, delete_pod."
        ))),
    }
}

fn risk_for(action: &str) -> RiskClass {
    match action {
        "get" | "describe" | "logs" => RiskClass::Read,
        "delete_pod" => RiskClass::High,
        _ => RiskClass::Medium,
    }
}

#[async_trait]
impl Tool for KubernetesTool {
    fn name(&self) -> &'static str {
        "kubernetes"
    }

    fn description(&self) -> &str {
        "Inspect or act on kubernetes resources via kubectl: get/describe (read-only; \
         all_namespaces: true sweeps every namespace in one call), logs \
         (read-only, last 200 lines), rollout_restart (restart a deployment/statefulset — \
         resource as kind/name, e.g. deploy/api), delete_pod (force a pod to reschedule; \
         prefer rollout_restart for a whole deployment). A namespace-scoped ServiceAccount \
         kubeconfig means this tool can only reach what its target's credential was scoped \
         to — a 'namespace not found'-shaped failure there may mean wrong target, not wrong \
         namespace name."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "fully-qualified kubernetes target"},
                "action": {"type": "string", "enum": ["get", "describe", "logs", "rollout_restart", "delete_pod"]},
                "resource": {"type": "string", "description": "resource type for get/describe (e.g. pods), or kind/name for rollout_restart (e.g. deploy/api)"},
                "name": {"type": "string", "description": "resource name (pod name for logs/delete_pod, or a specific resource for get/describe)"},
                "namespace": {"type": "string", "description": "kubernetes namespace, if not the target's default"},
                "all_namespaces": {"type": "boolean", "description": "get/describe across every namespace in one call (kubectl -A) — use this for cluster-wide sweeps instead of iterating namespaces"},
                "hypothesis": {"type": "string", "description": "why you're taking this action (required for mutations)"}
            },
            "required": ["target", "action"]
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Medium
    }

    fn is_action(&self) -> bool {
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let target_str = args["target"].as_str().ok_or_else(|| {
            ToolError::UserFacing("kubernetes requires a \"target\" argument".to_string())
        })?;
        let action = args["action"].as_str().ok_or_else(|| {
            ToolError::UserFacing("kubernetes requires an \"action\" argument".to_string())
        })?;
        let resource = args["resource"].as_str();
        let name = args["name"].as_str();
        let namespace = args["namespace"].as_str();
        let all_namespaces = args["all_namespaces"].as_bool().unwrap_or(false);
        let hypothesis = args["hypothesis"].as_str().map(str::to_string);
        let command = compose(action, resource, name, namespace, all_namespaces)?;
        let target = ctx.resolve_target(target_str)?;
        run_command(ctx, self.name(), target, command, risk_for(action), hypothesis).await
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
        FqTarget::new("remundo", "prod", "cluster")
    }

    fn ctx_with(policy: Arc<dyn PolicyExecute>) -> ToolCtx {
        ToolCtx {
            principal: Principal::Agent { job: None },
            policy,
            known_targets: vec![target()],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        }
    }

    #[tokio::test]
    async fn get_composes_a_plain_kubectl_subcommand_no_leading_binary() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "get", "resource": "pods", "namespace": "prod"}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].command, "get pods -n prod");
        assert!(!seen[0].command.starts_with("kubectl"), "executor supplies the binary itself");
        assert_eq!(seen[0].declared_risk, RiskClass::Read);
    }

    #[tokio::test]
    async fn logs_composes_tail_200() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "logs", "name": "api-7d8f", "namespace": "prod"}))
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].command, "logs api-7d8f --tail=200 -n prod");
    }

    #[tokio::test]
    async fn rollout_restart_uses_kind_slash_name() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "rollout_restart", "resource": "deploy/api"}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].command, "rollout restart deploy/api");
        assert_eq!(seen[0].declared_risk, RiskClass::Medium);
    }

    #[tokio::test]
    async fn rollout_restart_rejects_a_bare_name_without_kind() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "rollout_restart", "resource": "api"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_pod_is_high_risk() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "delete_pod", "name": "api-7d8f"}))
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].declared_risk, RiskClass::High);
    }

    #[tokio::test]
    async fn all_namespaces_composes_dash_a_for_get() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "get", "resource": "pods", "all_namespaces": true}))
            .await
            .unwrap();
        let seen = policy.seen.lock().unwrap();
        assert_eq!(seen[0].command, "get pods -A");
        assert_eq!(seen[0].declared_risk, RiskClass::Read);
    }

    #[tokio::test]
    async fn all_namespaces_rejects_non_read_actions_and_a_namespace_combo() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        // logs -A is not a kubectl thing; the pod's namespace is required.
        let err = KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "logs", "name": "api-7d8f", "all_namespaces": true}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        // Both a namespace and -A is a contradiction, not a preference.
        let err = KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "get", "resource": "pods", "namespace": "prod", "all_namespaces": true}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn literal_all_namespaces_namespace_redirects_to_the_flag() {
        // Observed live: the model passed namespace "all-namespaces", kubectl
        // returned empty output with exit 0, and the scan concluded quiet. The
        // error must teach the flag, not just refuse.
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "get", "resource": "pods", "namespace": "all-namespaces"}))
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("all_namespaces: true")),
            other => panic!("expected UserFacing, got {other:?}"),
        }
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn resource_with_injection_attempt_is_rejected() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = KubernetesTool
            .call(&ctx, json!({"target": "remundo::prod::cluster", "action": "get", "resource": "pods; rm -rf /"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty());
    }
}
