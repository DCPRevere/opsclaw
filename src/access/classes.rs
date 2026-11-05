//! Data classes: what kind of information a tool call returns.
//!
//! Classification is code, never model output, and it runs on the composed
//! command (the same string the policy classifies and the audit records),
//! so it can't be talked around.

use super::config::AccessCfg;

pub const STATE: &str = "state";
pub const METRICS: &str = "metrics";
pub const CHANGES: &str = "changes";
pub const CONFIG: &str = "config";
pub const LOGS: &str = "logs";
pub const MESSAGES: &str = "messages";
/// Distributed traces: request paths, ids, and span attributes.
pub const TRACES: &str = "traces";
/// Free-form commands and file reads on a host: they can read anything.
pub const HOST: &str = "host";
/// Secret values. No grant can include it; refused for every person.
pub const SECRETS: &str = "secrets";

/// The built-in classes and whether their results are redacted unless raw.
pub const BUILT_IN: &[(&str, bool)] = &[
    (STATE, false),
    (METRICS, false),
    (CHANGES, false),
    (CONFIG, true),
    (LOGS, true),
    (MESSAGES, true),
    (TRACES, true),
    (HOST, true),
    (SECRETS, true),
];

/// Known classes and their redaction flag, built-ins plus `[[access.class]]`.
#[derive(Debug, Clone)]
pub struct ClassTable {
    classes: Vec<(String, bool)>,
}

impl ClassTable {
    pub fn new(cfg: &AccessCfg) -> Self {
        let mut classes: Vec<(String, bool)> =
            BUILT_IN.iter().map(|(n, r)| (n.to_string(), *r)).collect();
        for c in &cfg.classes {
            classes.push((c.name.clone(), c.redact));
        }
        ClassTable { classes }
    }

    pub fn exists(&self, class: &str) -> bool {
        self.classes.iter().any(|(n, _)| n == class)
    }

    pub fn redacted(&self, class: &str) -> bool {
        self.classes.iter().find(|(n, _)| n == class).is_none_or(|(_, r)| *r)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.classes.iter().map(|(n, _)| n.as_str())
    }
}

/// The class of one tool call. `target` is the fq path (for `where` on
/// class rules); `command` is the composed line.
pub fn classify(cfg: &AccessCfg, tool: &str, target: &str, command: &str) -> String {
    for rule in &cfg.class_rules {
        if rule.tool != tool {
            continue;
        }
        if let Some(needle) = &rule.contains
            && !command.contains(needle.as_str())
        {
            continue;
        }
        if let Some(prefix) = &rule.r#where
            && !super::scope_covers(prefix, target)
        {
            continue;
        }
        return rule.class.clone();
    }
    built_in(tool, command).to_string()
}

fn built_in(tool: &str, command: &str) -> &'static str {
    match tool {
        t if t.starts_with("elasticsearch_") => {
            if t == "elasticsearch_search" {
                LOGS
            } else {
                STATE
            }
        }
        t if t.starts_with("prometheus_") => METRICS,
        t if t.starts_with("tempo_") => TRACES,
        t if t.starts_with("argocd_") => CHANGES,
        "eventstore_read_stream" => MESSAGES,
        t if t.starts_with("eventstore_") => STATE,
        "azure_service_bus_peek" => MESSAGES,
        t if t.starts_with("azure_service_bus_") => STATE,
        "kubernetes" => kubectl(command),
        "monitor" => METRICS,
        "dns" | "cert" | "firewall" => STATE,
        "systemd" => {
            if command.contains("journalctl") {
                LOGS
            } else {
                STATE
            }
        }
        "docker" => {
            if words(command).any(|w| w == "logs") {
                LOGS
            } else {
                STATE
            }
        }
        // ssh, shell, file_read, runbook, and anything new: assume the
        // broadest class until someone classifies it.
        _ => HOST,
    }
}

fn words(command: &str) -> impl Iterator<Item = &str> {
    command.split_whitespace()
}

fn kubectl(command: &str) -> &'static str {
    let mut verb = None;
    let mut kinds = Vec::new();
    let mut skip_next = false;
    for w in words(command).skip_while(|w| *w == "kubectl") {
        if skip_next {
            skip_next = false;
            continue;
        }
        if w.starts_with('-') {
            // `--context x`, `-n x`; `--flag=value` carries its own value.
            skip_next = !w.contains('=')
                && matches!(
                    w,
                    "-n" | "--namespace"
                        | "--context"
                        | "--kubeconfig"
                        | "-o"
                        | "--output"
                        | "-c"
                        | "--container"
                        | "--since"
                        | "--tail"
                        | "-l"
                        | "--selector"
                );
            continue;
        }
        if verb.is_none() {
            verb = Some(w);
        } else {
            kinds.extend(w.split(',').map(|k| k.split('/').next().unwrap_or(k)));
        }
    }
    match verb {
        Some("logs") => LOGS,
        Some("get" | "describe") => {
            let is = |names: &[&str]| kinds.iter().any(|k| names.contains(k));
            if is(&["secret", "secrets"]) {
                SECRETS
            } else if is(&["configmap", "configmaps", "cm"]) {
                CONFIG
            } else {
                STATE
            }
        }
        Some("rollout" | "delete") => STATE,
        _ => HOST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::config::ClassRuleCfg;

    fn c(tool: &str, cmd: &str) -> String {
        classify(&AccessCfg::default(), tool, "p::e::t", cmd)
    }

    #[test]
    fn kubectl_commands_are_classified_by_verb_and_kind() {
        assert_eq!(c("kubernetes", "kubectl --context x -n ns get pods"), STATE);
        assert_eq!(c("kubernetes", "kubectl -n ns logs pod/a --previous"), LOGS);
        assert_eq!(c("kubernetes", "kubectl get pods,configmaps -n x"), CONFIG);
        assert_eq!(c("kubernetes", "kubectl --context=x describe cm/app"), CONFIG);
        assert_eq!(c("kubernetes", "kubectl get secret/db -o yaml"), SECRETS);
        assert_eq!(c("kubernetes", "kubectl rollout restart deploy/a"), STATE);
    }

    #[test]
    fn resource_tools_and_hosts() {
        assert_eq!(c("elasticsearch_search", "endpoint-query /x {}"), LOGS);
        assert_eq!(c("elasticsearch_cluster_health", "endpoint-get /_cluster/health"), STATE);
        assert_eq!(c("prometheus_instant_query", "endpoint-get /api"), METRICS);
        assert_eq!(c("argocd_list_apps", "endpoint-get /api"), CHANGES);
        assert_eq!(c("azure_service_bus_peek", "endpoint-get /q"), MESSAGES);
        assert_eq!(c("ssh", "cat /etc/hosts"), HOST);
        assert_eq!(c("systemd", "journalctl -u nginx"), LOGS);
        assert_eq!(c("docker", "docker logs web"), LOGS);
    }

    #[test]
    fn class_rules_come_first_and_can_be_scoped() {
        let cfg = AccessCfg {
            class_rules: vec![ClassRuleCfg {
                tool: "elasticsearch_search".into(),
                contains: Some("payroll".into()),
                r#where: Some("acme::prod".into()),
                class: "pii".into(),
            }],
            ..Default::default()
        };
        let q = "endpoint-query /fb-ds-payroll/_search {}";
        assert_eq!(classify(&cfg, "elasticsearch_search", "acme::prod::aks::es", q), "pii");
        assert_eq!(classify(&cfg, "elasticsearch_search", "acme::dev::aks::es", q), LOGS);
    }
}
