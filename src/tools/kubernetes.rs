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

/// Default and maximum `logs` line counts. Crash reasons usually sit in the
/// last few dozen lines; the cap keeps one call from flooding the context.
const DEFAULT_LOG_TAIL: u64 = 200;
const MAX_LOG_TAIL: u64 = 2_000;

/// Options that only apply to `logs`.
#[derive(Debug, Default)]
struct LogOpts<'a> {
    /// The previous container instance (`--previous`): where a crashlooping
    /// pod's crash reason lives.
    previous: bool,
    /// One container of a multi-container pod (`-c`).
    container: Option<&'a str>,
    /// Every container, each line prefixed with its source.
    all_containers: bool,
    /// Only lines newer than a duration such as `15m` or `1h30m`.
    since: Option<&'a str>,
    tail: Option<u64>,
}

/// What `kubectl logs` reads from: a pod name, or `kind/name` for a
/// workload (kubectl picks one of its pods).
fn valid_log_source(s: &str) -> bool {
    const KINDS: &[&str] = &[
        "pod",
        "pods",
        "deploy",
        "deployment",
        "job",
        "statefulset",
        "sts",
        "daemonset",
        "ds",
        "replicaset",
        "rs",
    ];
    match s.split_once('/') {
        Some((kind, name)) => KINDS.contains(&kind) && valid_k8s_name(name),
        None => valid_k8s_name(s),
    }
}

/// A kubectl duration: one or more `<digits><s|m|h>` groups.
fn valid_since(s: &str) -> bool {
    let mut digits = false;
    for c in s.chars() {
        match c {
            '0'..='9' => digits = true,
            's' | 'm' | 'h' if digits => digits = false,
            _ => return false,
        }
    }
    !s.is_empty() && !digits
}

impl LogOpts<'_> {
    fn flags(&self) -> Result<String, ToolError> {
        let tail = self.tail.unwrap_or(DEFAULT_LOG_TAIL);
        if tail == 0 || tail > MAX_LOG_TAIL {
            return Err(ToolError::UserFacing(format!(
                "tail must be between 1 and {MAX_LOG_TAIL}, not {tail}"
            )));
        }
        let mut flags = format!(" --tail={tail}");
        if self.previous {
            flags.push_str(" --previous");
        }
        match (self.container, self.all_containers) {
            (Some(_), true) => {
                return Err(ToolError::UserFacing(
                    "pass either \"container\" or all_containers: true, not both".to_string(),
                ));
            }
            (Some(c), false) => {
                if !valid_k8s_name(c) {
                    return Err(ToolError::UserFacing(format!("invalid container name {c:?}")));
                }
                flags.push_str(&format!(" -c {c}"));
            }
            (None, true) => flags.push_str(" --all-containers=true --prefix=true"),
            (None, false) => {}
        }
        if let Some(since) = self.since {
            if !valid_since(since) {
                return Err(ToolError::UserFacing(format!(
                    "invalid since {since:?} — use a duration such as 15m, 2h or 1h30m"
                )));
            }
            flags.push_str(&format!(" --since={since}"));
        }
        Ok(flags)
    }
}

fn compose(
    action: &str,
    resource: Option<&str>,
    name: Option<&str>,
    namespace: Option<&str>,
    all_namespaces: bool,
    wide: bool,
    logs: &LogOpts<'_>,
) -> Result<String, ToolError> {
    // Log options are ignored for every other action. Models often fill
    // every field with a default (`tail: 200`, `previous: false`); refusing
    // that would fail a plain `get`.
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
            // kubectl takes several types at once: "pods,events".
            if !resource.split(',').all(valid_k8s_name) {
                return Err(ToolError::UserFacing(format!(
                    "invalid resource type {resource:?} — a type such as pods, or several \
                     separated by commas (pods,events); output options go in their own fields"
                )));
            }
            if resource.contains(',') && name.is_some() {
                return Err(ToolError::UserFacing(
                    "a name only goes with a single resource type".to_string(),
                ));
            }
            let mut cmd = format!("{action} {resource}");
            if let Some(n) = name {
                if !valid_k8s_name(n) {
                    return Err(ToolError::UserFacing(format!("invalid resource name {n:?}")));
                }
                cmd.push(' ');
                cmd.push_str(n);
            }
            if wide && action == "get" {
                cmd.push_str(" -o wide");
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
            if !valid_log_source(name) {
                return Err(ToolError::UserFacing(format!(
                    "invalid log source {name:?} — a pod name, or kind/name for a workload \
                     (deploy/api, job/nightly-1234, statefulset/db)"
                )));
            }
            Ok(format!("logs {name}{}{ns_flag}", logs.flags()?))
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

fn constrain_scope<'a>(
    namespace: Option<&'a str>,
    all_namespaces: bool,
    scope: Option<&'a crate::domain::KubernetesScope>,
) -> Result<(Option<&'a str>, bool), ToolError> {
    let Some(crate::domain::KubernetesScope::Namespace(expected)) = scope else {
        return Ok((namespace, all_namespaces));
    };
    if all_namespaces {
        return Err(ToolError::UserFacing(format!(
            "target is scoped to namespace {expected:?}; all_namespaces would cross that boundary"
        )));
    }
    if let Some(actual) = namespace
        && actual != expected
    {
        return Err(ToolError::UserFacing(format!(
            "target is scoped to namespace {expected:?}, not {actual:?}"
        )));
    }
    Ok((Some(expected.as_str()), false))
}

#[async_trait]
impl Tool for KubernetesTool {
    fn name(&self) -> &'static str {
        "kubernetes"
    }

    fn description(&self) -> &str {
        "Inspect or act on kubernetes resources via kubectl: get/describe (read-only; \
         all_namespaces: true sweeps every namespace in one call), logs \
         (read-only; last 200 lines by default; previous: true for the container instance \
         that crashed, which is where a crashloop's reason is; container or \
         all_containers for multi-container pods; since: e.g. 15m), rollout_restart (restart a deployment/statefulset — \
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
                "resource": {"type": "string", "description": "resource type for get/describe (e.g. pods, or several at once: pods,events), or kind/name for rollout_restart (e.g. deploy/api)"},
                "name": {"type": "string", "description": "resource name: for logs a pod, or kind/name of a workload (job/nightly-1234, deploy/api); for delete_pod a pod; for get/describe one specific resource"},
                "wide": {"type": "boolean", "description": "get only: kubectl -o wide (node, IPs, nominated node)"},
                "namespace": {"type": "string", "description": "kubernetes namespace, if not the target's default"},
                "all_namespaces": {"type": "boolean", "description": "get/describe across every namespace in one call (kubectl -A) — use this for cluster-wide sweeps instead of iterating namespaces"},
                "previous": {"type": "boolean", "description": "logs only: the previous (crashed) container instance — check this first for a CrashLoopBackOff or a restart count above 0"},
                "container": {"type": "string", "description": "logs only: the container, for a pod with more than one"},
                "all_containers": {"type": "boolean", "description": "logs only: every container in the pod, each line prefixed with its container"},
                "since": {"type": "string", "description": "logs only: only lines newer than this duration, e.g. 15m, 2h, 1h30m"},
                "tail": {"type": "integer", "minimum": 1, "maximum": 2000, "description": "logs only: how many recent lines (default 200)"},
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

    fn reads_only(&self, args: &Value) -> bool {
        risk_for(args["action"].as_str().unwrap_or_default()) == RiskClass::Read
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
        // An empty string is "not given": models fill unused fields with "".
        let resource = args["resource"].as_str().filter(|s| !s.is_empty());
        let name = args["name"].as_str().filter(|s| !s.is_empty());
        let requested_namespace = args["namespace"].as_str();
        let requested_all_namespaces = args["all_namespaces"].as_bool().unwrap_or(false);
        let hypothesis = args["hypothesis"].as_str().map(str::to_string);
        let logs = LogOpts {
            previous: args["previous"].as_bool().unwrap_or(false),
            container: args["container"].as_str().filter(|c| !c.is_empty()),
            all_containers: args["all_containers"].as_bool().unwrap_or(false),
            since: args["since"].as_str().filter(|s| !s.is_empty()),
            tail: args["tail"].as_u64(),
        };
        let target = ctx.resolve_target_for(
            target_str,
            self.name(),
            &[crate::config::TargetKindName::Kubernetes],
        )?;
        let scope = ctx
            .config
            .as_ref()
            .and_then(|config| config.target_config(&target))
            .and_then(|configured| configured.kubernetes.as_ref())
            .map(|kubernetes| kubernetes.scope());
        let (namespace, all_namespaces) =
            constrain_scope(requested_namespace, requested_all_namespaces, scope.as_ref())?;
        let wide = args["wide"].as_bool().unwrap_or(false);
        let command = compose(action, resource, name, namespace, all_namespaces, wide, &logs)?;
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
        FqTarget::new("example", "prod", "cluster")
    }

    fn ctx_with(policy: Arc<dyn PolicyExecute>) -> ToolCtx {
        ToolCtx {
            call: Default::default(),
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
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "get", "resource": "pods", "namespace": "prod"}))
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
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "logs", "name": "api-7d8f", "namespace": "prod"}))
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].command, "logs api-7d8f --tail=200 -n prod");
    }

    async fn logs_command(extra: Value) -> std::result::Result<String, ToolError> {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let mut args = json!({"target": "example::prod::cluster", "action": "logs", "name": "api-7d8f", "namespace": "prod"});
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        KubernetesTool.call(&ctx, args).await?;
        let seen = policy.seen.lock().unwrap();
        Ok(seen[0].command.clone())
    }

    #[tokio::test]
    async fn logs_reads_the_crashed_container_of_one_container_since_a_duration() {
        let cmd = logs_command(
            json!({"previous": true, "container": "app", "since": "1h30m", "tail": 50}),
        )
        .await
        .unwrap();
        assert_eq!(cmd, "logs api-7d8f --tail=50 --previous -c app --since=1h30m -n prod");
    }

    #[tokio::test]
    async fn logs_can_read_every_container_with_a_prefix() {
        let cmd = logs_command(json!({"all_containers": true})).await.unwrap();
        assert_eq!(cmd, "logs api-7d8f --tail=200 --all-containers=true --prefix=true -n prod");
    }

    #[tokio::test]
    async fn logs_options_are_validated() {
        for (bad, why) in [
            (json!({"container": "app", "all_containers": true}), "container and all_containers"),
            (json!({"container": "app; rm -rf /"}), "injection in container"),
            (json!({"since": "1d"}), "days are not a kubectl duration"),
            (json!({"since": "15"}), "a duration needs a unit"),
            (json!({"since": "m"}), "a unit needs digits"),
            (json!({"since": "5m --all-namespaces"}), "injection in since"),
            (json!({"tail": 0}), "tail below 1"),
            (json!({"tail": 2_001}), "tail above the cap"),
        ] {
            assert!(logs_command(bad).await.is_err(), "{why} must be rejected");
        }
    }

    async fn command_for(args: Value) -> std::result::Result<String, ToolError> {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let mut full = json!({"target": "example::prod::cluster", "namespace": "prod"});
        for (k, v) in args.as_object().unwrap() {
            full[k] = v.clone();
        }
        KubernetesTool.call(&ctx, full).await?;
        let seen = policy.seen.lock().unwrap();
        Ok(seen[0].command.clone())
    }

    #[tokio::test]
    async fn several_types_wide_output_and_workload_logs_compose_as_kubectl_expects() {
        assert_eq!(
            command_for(json!({"action": "get", "resource": "pods,events"})).await.unwrap(),
            "get pods,events -n prod"
        );
        assert_eq!(
            command_for(json!({"action": "get", "resource": "pods", "wide": true})).await.unwrap(),
            "get pods -o wide -n prod"
        );
        assert_eq!(
            command_for(json!({"action": "logs", "name": "job/nightly-29895840", "tail": 50}))
                .await
                .unwrap(),
            "logs job/nightly-29895840 --tail=50 -n prod"
        );
        for bad in [
            json!({"action": "get", "resource": "pods -o wide"}),
            json!({"action": "get", "resource": "pods,events", "name": "api"}),
            json!({"action": "get", "resource": "pods,"}),
            json!({"action": "logs", "name": "secret/db-password"}),
            json!({"action": "logs", "name": "job/a/b"}),
        ] {
            assert!(command_for(bad.clone()).await.is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn empty_strings_for_unused_fields_mean_not_given() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(
                &ctx,
                json!({"target": "example::prod::cluster", "action": "get", "resource": "pods",
                       "name": "", "namespace": "", "all_namespaces": true, "hypothesis": ""}),
            )
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].command, "get pods -A");
    }

    #[tokio::test]
    async fn log_options_are_ignored_outside_logs() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(
                &ctx,
                json!({"target": "example::prod::cluster", "action": "get", "resource": "pods",
                       "namespace": "prod", "previous": false, "tail": 200, "since": "", "container": ""}),
            )
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].command, "get pods -n prod");
    }

    #[tokio::test]
    async fn rollout_restart_uses_kind_slash_name() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "rollout_restart", "resource": "deploy/api"}))
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
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "rollout_restart", "resource": "api"}))
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
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "delete_pod", "name": "api-7d8f"}))
            .await
            .unwrap();
        assert_eq!(policy.seen.lock().unwrap()[0].declared_risk, RiskClass::High);
    }

    #[tokio::test]
    async fn all_namespaces_composes_dash_a_for_get() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        KubernetesTool
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "get", "resource": "pods", "all_namespaces": true}))
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
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "logs", "name": "api-7d8f", "all_namespaces": true}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        // Both a namespace and -A is a contradiction, not a preference.
        let err = KubernetesTool
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "get", "resource": "pods", "namespace": "prod", "all_namespaces": true}))
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
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "get", "resource": "pods", "namespace": "all-namespaces"}))
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("all_namespaces: true")),
            other => panic!("expected UserFacing, got {other:?}"),
        }
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn namespace_scope_rejects_dev_to_prod_and_cluster_sweeps() {
        let scope = crate::domain::KubernetesScope::Namespace("dev".into());
        assert!(constrain_scope(Some("prod"), false, Some(&scope)).is_err());
        assert!(constrain_scope(None, true, Some(&scope)).is_err());
        assert_eq!(constrain_scope(None, false, Some(&scope)).unwrap(), (Some("dev"), false));
    }

    #[tokio::test]
    async fn resource_with_injection_attempt_is_rejected() {
        let policy = Arc::new(RecordingPolicy::always_executes(0, ""));
        let ctx = ctx_with(policy.clone());
        let err = KubernetesTool
            .call(&ctx, json!({"target": "example::prod::cluster", "action": "get", "resource": "pods; rm -rf /"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(policy.seen.lock().unwrap().is_empty());
    }
}
