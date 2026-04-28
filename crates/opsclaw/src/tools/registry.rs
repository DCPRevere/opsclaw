//! OpsClaw tool registry — creates SRE-specific tools from [`OpsConfig`]
//! for injection into the ZeroClaw agent loop.
//!
//! Shared endpoint pools (prometheus, loki, elk, jaeger, pagerduty, github,
//! cloudflare, rabbitmq, azure_service_bus) are gathered from every
//! `projects[*].environments[*].endpoints` entry. `Vec<T>` pools are merged
//! with a uniqueness check on `name`; singleton pools error if more than one
//! environment declares them.

use anyhow::{Context, Result, bail};
use zeroclaw::tools::Tool;

use crate::ops_config::{
    AzureServiceBusConfig, CloudflareConfig, ConnectionType, ElkEndpointConfig, GithubConfig,
    JaegerEndpointConfig, LokiEndpointConfig, OpsConfig, PagerDutyConfig, PostHogConfig,
    PrometheusEndpointConfig, RabbitMqConfig,
};
use crate::tools::a2a_tool::A2aTool;
use crate::tools::azure_service_bus_tool::{AzureServiceBusTool, AzureServiceBusToolConfig};
use crate::tools::cert_tool::CertTool;
use crate::tools::cloudflare_tool::{CloudflareTool, CloudflareToolConfig};
use crate::tools::dns_tool::DnsTool;
use crate::tools::docker_tool::{DockerTool, DockerToolConfig};
use crate::tools::elk_tool::{ElkEndpoint, ElkTool};
use crate::tools::firewall_tool::{FirewallTool, FirewallToolConfig};
use crate::tools::github_tool::{GithubTool, GithubToolConfig};
use crate::tools::jaeger_tool::{JaegerEndpoint, JaegerTool};
use crate::tools::kube_tool::{KubeTool, KubeToolConfig};
use crate::tools::loki_tool::{LokiEndpoint, LokiTool};
use crate::tools::monitor_tool::MonitorTool;
use crate::tools::pagerduty_tool::{PagerDutyTool, PagerDutyToolConfig};
use crate::tools::postgres_tool::{PostgresInstance, PostgresTool, PostgresToolConfig};
use crate::tools::posthog_tool::{PostHogTool, PostHogToolConfig};
use crate::tools::prometheus_tool::{PrometheusEndpoint, PrometheusTool};
use crate::tools::rabbitmq_tool::{RabbitMqTool, RabbitMqToolConfig};
use crate::tools::ssh_tool::{SshTool, SshToolConfig, TargetEntry};
use crate::tools::systemd_tool::{SystemdTool, SystemdToolConfig};

/// Build OpsClaw-specific tools from the current configuration.
///
/// These are injected into the ZeroClaw agent loop via the `extra_tools`
/// parameter, following the same pattern as `create_peripheral_tools()`.
///
/// Async because secret resolution may read from mounted k8s Secret
/// volumes; the upstream peripheral-tools hook already returns a future.
pub async fn create_opsclaw_tools(config: &OpsConfig) -> Result<Vec<Box<dyn Tool>>> {
    let mut tools: Vec<Box<dyn Tool>> = Vec::new();

    // SSH + systemd + firewall + docker share the same project entries.
    let ssh_targets = build_ssh_entries(config).await?;
    if !ssh_targets.is_empty() {
        tools.push(Box::new(SshTool::new(SshToolConfig {
            targets: ssh_targets.clone(),
        })));
        tools.push(Box::new(SystemdTool::new(SystemdToolConfig {
            targets: ssh_targets.clone(),
        })));
        tools.push(Box::new(FirewallTool::new(FirewallToolConfig {
            targets: ssh_targets.clone(),
        })));
        tools.push(Box::new(DockerTool::new(DockerToolConfig {
            targets: ssh_targets,
        })));
    }

    // Monitor tool — wraps discovery scan + health check.
    tools.push(Box::new(MonitorTool::new(config.clone())));

    // OpsClaw notify — opsclaw-owned outbound alert over a webhook.
    // Sibling to zeroclaw's escalate_to_human; see opsclaw_notify.rs.
    tools.push(Box::new(
        crate::tools::opsclaw_notify::OpsClawNotifyTool::new(config),
    ));

    // DNS tool — ad-hoc lookups, no config required.
    tools.push(Box::new(DnsTool::new()));

    // Cert tool — TLS cert inspection, no config required.
    tools.push(Box::new(CertTool::new()));

    // A2A client — send tasks to remote A2A-compliant agents.
    tools.push(Box::new(A2aTool::new()));

    // Kubernetes — typed cluster operations.
    let kube_targets = KubeTool::targets_from_config(config);
    if !kube_targets.is_empty() {
        tools.push(Box::new(KubeTool::new(KubeToolConfig {
            targets: kube_targets,
        })));
    }

    // Gather endpoint pools from every environment.
    let pools = gather_endpoints(config)?;

    // Prometheus.
    if !pools.prometheus.is_empty() {
        let mut endpoints: Vec<PrometheusEndpoint> = Vec::with_capacity(pools.prometheus.len());
        for e in &pools.prometheus {
            endpoints.push(PrometheusEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token: decrypt_optional(
                    config,
                    e.bearer_token.as_deref(),
                    "prometheus bearer_token",
                )
                .await?,
            });
        }
        tools.push(Box::new(PrometheusTool::new(endpoints)));
    }

    // Loki.
    if !pools.loki.is_empty() {
        let mut endpoints: Vec<LokiEndpoint> = Vec::with_capacity(pools.loki.len());
        for e in &pools.loki {
            endpoints.push(LokiEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token: decrypt_optional(
                    config,
                    e.bearer_token.as_deref(),
                    "loki bearer_token",
                )
                .await?,
                org_id: e.org_id.clone(),
            });
        }
        tools.push(Box::new(LokiTool::new(endpoints)));
    }

    // Elk.
    if !pools.elk.is_empty() {
        let mut endpoints: Vec<ElkEndpoint> = Vec::with_capacity(pools.elk.len());
        for e in &pools.elk {
            endpoints.push(ElkEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                username: e.username.clone(),
                password: decrypt_optional(config, e.password.as_deref(), "elk password").await?,
                api_key: decrypt_optional(config, e.api_key.as_deref(), "elk api_key").await?,
                default_index: e.default_index.clone(),
            });
        }
        tools.push(Box::new(ElkTool::new(endpoints)));
    }

    // PagerDuty.
    if let Some(pd) = pools.pagerduty.as_ref() {
        let api_key = config
            .decrypt_secret(&pd.api_key)
            .await
            .context("Failed to resolve PagerDuty api_key")?;
        let mut cfg = PagerDutyToolConfig::new(api_key);
        cfg.default_service_id = pd.default_service_id.clone();
        cfg.default_from = pd.default_from.clone();
        cfg.autonomy = pd.autonomy;
        tools.push(Box::new(PagerDutyTool::new(cfg)));
    }

    // GitHub.
    if let Some(gh) = pools.github.as_ref() {
        let token = config
            .decrypt_secret(&gh.token)
            .await
            .context("Failed to resolve GitHub token")?;
        let mut cfg = GithubToolConfig::new(token);
        cfg.default_owner = gh.default_owner.clone();
        cfg.default_repo = gh.default_repo.clone();
        cfg.autonomy = gh.autonomy;
        tools.push(Box::new(GithubTool::new(cfg)));
    }

    // Cloudflare.
    if let Some(cf) = pools.cloudflare.as_ref() {
        let tok = config
            .decrypt_secret(&cf.api_token)
            .await
            .context("Failed to resolve Cloudflare api_token")?;
        let mut cfg = CloudflareToolConfig::new(tok);
        cfg.default_zone_id = cf.default_zone_id.clone();
        cfg.default_account_id = cf.default_account_id.clone();
        cfg.autonomy = cf.autonomy;
        tools.push(Box::new(CloudflareTool::new(cfg)));
    }

    // PostHog.
    if let Some(ph) = pools.posthog.as_ref() {
        let api_key = config
            .decrypt_secret(&ph.api_key)
            .await
            .context("Failed to resolve PostHog api_key")?;
        let mut cfg = PostHogToolConfig::new(api_key, ph.project_id.clone(), ph.host.clone());
        cfg.autonomy = ph.autonomy;
        tools.push(Box::new(PostHogTool::new(cfg)));
    }

    // RabbitMQ.
    if let Some(rmq) = pools.rabbitmq.as_ref() {
        let password = config
            .decrypt_secret(&rmq.password)
            .await
            .context("Failed to resolve RabbitMQ password")?;
        let mut cfg = RabbitMqToolConfig::new(rmq.api_base.clone(), rmq.username.clone(), password);
        cfg.default_vhost = rmq.default_vhost.clone();
        cfg.autonomy = rmq.autonomy;
        tools.push(Box::new(RabbitMqTool::new(cfg)));
    }

    // Jaeger.
    if !pools.jaeger.is_empty() {
        let mut endpoints: Vec<JaegerEndpoint> = Vec::with_capacity(pools.jaeger.len());
        for e in &pools.jaeger {
            endpoints.push(JaegerEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token: decrypt_optional(
                    config,
                    e.bearer_token.as_deref(),
                    "jaeger bearer_token",
                )
                .await?,
            });
        }
        tools.push(Box::new(JaegerTool::new(endpoints)));
    }

    // Postgres (driver-based). Still at the root — no environment slot yet.
    if let Some(pgs) = config.postgres.as_ref() {
        let mut instances: Vec<PostgresInstance> = Vec::with_capacity(pgs.len());
        for p in pgs {
            let dsn = config.decrypt_secret(&p.dsn).await.with_context(|| {
                format!("Failed to resolve DSN for postgres instance '{}'", p.name)
            })?;
            instances.push(PostgresInstance {
                name: p.name.clone(),
                dsn,
                autonomy: p.autonomy,
            });
        }
        if !instances.is_empty() {
            tools.push(Box::new(PostgresTool::new(PostgresToolConfig {
                instances,
            })));
        }
    }

    // Azure Service Bus.
    if let Some(sb) = pools.azure_service_bus.as_ref() {
        let key = config
            .decrypt_secret(&sb.sas_key)
            .await
            .context("Failed to resolve Azure Service Bus sas_key")?;
        let mut cfg =
            AzureServiceBusToolConfig::new(sb.namespace.clone(), sb.sas_key_name.clone(), key);
        cfg.autonomy = sb.autonomy;
        tools.push(Box::new(AzureServiceBusTool::new(cfg)));
    }

    Ok(tools)
}

/// Resolve an optional secret reference. Returns `Ok(None)` when the input is
/// `None`; returns an error when decryption fails so the caller can surface it.
async fn decrypt_optional(
    config: &OpsConfig,
    value: Option<&str>,
    field: &str,
) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(v) => {
            let plain = config
                .decrypt_secret(v)
                .await
                .with_context(|| format!("Failed to resolve {field}"))?;
            Ok(Some(plain))
        }
    }
}

/// Flattened endpoint pools gathered across every environment in the config.
#[derive(Default)]
struct GatheredEndpoints<'a> {
    prometheus: Vec<&'a PrometheusEndpointConfig>,
    loki: Vec<&'a LokiEndpointConfig>,
    elk: Vec<&'a ElkEndpointConfig>,
    jaeger: Vec<&'a JaegerEndpointConfig>,
    pagerduty: Option<&'a PagerDutyConfig>,
    github: Option<&'a GithubConfig>,
    cloudflare: Option<&'a CloudflareConfig>,
    rabbitmq: Option<&'a RabbitMqConfig>,
    azure_service_bus: Option<&'a AzureServiceBusConfig>,
    posthog: Option<&'a PostHogConfig>,
}

/// Walk every environment and collect endpoint pools. `Vec<T>` pools merge
/// with a uniqueness check on `name`; singleton pools error if more than one
/// environment declares them.
fn gather_endpoints(config: &OpsConfig) -> Result<GatheredEndpoints<'_>> {
    let mut out = GatheredEndpoints::default();
    let mut seen_prom = std::collections::HashSet::new();
    let mut seen_loki = std::collections::HashSet::new();
    let mut seen_elk = std::collections::HashSet::new();
    let mut seen_jaeger = std::collections::HashSet::new();
    let mut pagerduty_origin: Option<String> = None;
    let mut github_origin: Option<String> = None;
    let mut cloudflare_origin: Option<String> = None;
    let mut rabbitmq_origin: Option<String> = None;
    let mut asb_origin: Option<String> = None;
    let mut posthog_origin: Option<String> = None;

    for project in &config.projects {
        for env in &project.environments {
            let origin = format!("{}::{}", project.name, env.name);
            let eps = &env.endpoints;

            if let Some(list) = eps.prometheus.as_ref() {
                for e in list {
                    if !seen_prom.insert(e.name.clone()) {
                        bail!(
                            "Duplicate prometheus endpoint '{}' in environment {origin}",
                            e.name
                        );
                    }
                    out.prometheus.push(e);
                }
            }
            if let Some(list) = eps.loki.as_ref() {
                for e in list {
                    if !seen_loki.insert(e.name.clone()) {
                        bail!(
                            "Duplicate loki endpoint '{}' in environment {origin}",
                            e.name
                        );
                    }
                    out.loki.push(e);
                }
            }
            if let Some(list) = eps.elk.as_ref() {
                for e in list {
                    if !seen_elk.insert(e.name.clone()) {
                        bail!(
                            "Duplicate elk endpoint '{}' in environment {origin}",
                            e.name
                        );
                    }
                    out.elk.push(e);
                }
            }
            if let Some(list) = eps.jaeger.as_ref() {
                for e in list {
                    if !seen_jaeger.insert(e.name.clone()) {
                        bail!(
                            "Duplicate jaeger endpoint '{}' in environment {origin}",
                            e.name
                        );
                    }
                    out.jaeger.push(e);
                }
            }

            set_singleton(
                &mut out.pagerduty,
                eps.pagerduty.as_ref(),
                &mut pagerduty_origin,
                &origin,
                "pagerduty",
            )?;
            set_singleton(
                &mut out.github,
                eps.github.as_ref(),
                &mut github_origin,
                &origin,
                "github",
            )?;
            set_singleton(
                &mut out.cloudflare,
                eps.cloudflare.as_ref(),
                &mut cloudflare_origin,
                &origin,
                "cloudflare",
            )?;
            set_singleton(
                &mut out.rabbitmq,
                eps.rabbitmq.as_ref(),
                &mut rabbitmq_origin,
                &origin,
                "rabbitmq",
            )?;
            set_singleton(
                &mut out.azure_service_bus,
                eps.azure_service_bus.as_ref(),
                &mut asb_origin,
                &origin,
                "azure_service_bus",
            )?;
            set_singleton(
                &mut out.posthog,
                eps.posthog.as_ref(),
                &mut posthog_origin,
                &origin,
                "posthog",
            )?;
        }
    }

    Ok(out)
}

fn set_singleton<'a, T>(
    slot: &mut Option<&'a T>,
    incoming: Option<&'a T>,
    origin_slot: &mut Option<String>,
    origin: &str,
    name: &str,
) -> Result<()> {
    let Some(cfg) = incoming else {
        return Ok(());
    };
    if let Some(prev) = origin_slot.as_deref() {
        bail!(
            "Duplicate {name} config: declared in environment {prev} and {origin}. \
             Only one environment may declare a singleton pool."
        );
    }
    *slot = Some(cfg);
    *origin_slot = Some(origin.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_str: &str) -> OpsConfig {
        toml::from_str(toml_str).expect("valid TOML")
    }

    /// Construct a config rooted at a real temporary directory so
    /// `decrypt_secret` (which reads `config_path.parent()`) succeeds. The
    /// returned `_tmp` keeps the directory alive for the duration of the test.
    fn parse_with_tmp(toml_str: &str) -> (OpsConfig, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut cfg: OpsConfig = toml::from_str(toml_str).expect("valid TOML");
        cfg.config_path = tmp.path().join("config.toml");
        (cfg, tmp)
    }

    // ── gather_endpoints ──────────────────────────────────────────

    #[test]
    fn gather_endpoints_empty_config_returns_empty_pools() {
        let cfg = OpsConfig::default();
        let pools = gather_endpoints(&cfg).expect("gather");
        assert!(pools.prometheus.is_empty());
        assert!(pools.loki.is_empty());
        assert!(pools.elk.is_empty());
        assert!(pools.jaeger.is_empty());
        assert!(pools.pagerduty.is_none());
        assert!(pools.github.is_none());
        assert!(pools.cloudflare.is_none());
        assert!(pools.rabbitmq.is_none());
        assert!(pools.azure_service_bus.is_none());
    }

    #[test]
    fn gather_endpoints_merges_vec_pools_across_environments() {
        let cfg = parse(
            r#"
workspace_dir = "/tmp/x"

[[projects]]
name = "shopfront"

  [[projects.environments]]
  name = "dev"
  [[projects.environments.endpoints.prometheus]]
  name = "dev-prom"
  url = "http://prom-dev:9090"

  [[projects.environments]]
  name = "prod"
  [[projects.environments.endpoints.prometheus]]
  name = "prod-prom"
  url = "http://prom-prod:9090"
"#,
        );
        let pools = gather_endpoints(&cfg).expect("gather");
        assert_eq!(pools.prometheus.len(), 2);
        let names: Vec<&str> = pools.prometheus.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"dev-prom"));
        assert!(names.contains(&"prod-prom"));
    }

    #[test]
    fn gather_endpoints_errors_on_duplicate_vec_pool_name() {
        let cfg = parse(
            r#"
workspace_dir = "/tmp/x"

[[projects]]
name = "shopfront"

  [[projects.environments]]
  name = "dev"
  [[projects.environments.endpoints.prometheus]]
  name = "shared"
  url = "http://a:9090"

  [[projects.environments]]
  name = "prod"
  [[projects.environments.endpoints.prometheus]]
  name = "shared"
  url = "http://b:9090"
"#,
        );
        let err = match gather_endpoints(&cfg) {
            Ok(_) => panic!("expected duplicate-name error"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("Duplicate prometheus endpoint 'shared'"),
            "got: {err}"
        );
    }

    #[test]
    fn gather_endpoints_errors_on_duplicate_singleton_across_environments() {
        let cfg = parse(
            r#"
workspace_dir = "/tmp/x"

[[projects]]
name = "shopfront"

  [[projects.environments]]
  name = "dev"
  [projects.environments.endpoints.pagerduty]
  api_key = "k1"

  [[projects.environments]]
  name = "prod"
  [projects.environments.endpoints.pagerduty]
  api_key = "k2"
"#,
        );
        let err = match gather_endpoints(&cfg) {
            Ok(_) => panic!("expected singleton-collision error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("Duplicate pagerduty config"), "got: {err}");
        assert!(err.contains("shopfront::dev"));
        assert!(err.contains("shopfront::prod"));
    }

    #[test]
    fn gather_endpoints_singleton_set_once_resolves() {
        let cfg = parse(
            r#"
workspace_dir = "/tmp/x"

[[projects]]
name = "shopfront"

  [[projects.environments]]
  name = "dev"

  [[projects.environments]]
  name = "prod"
  [projects.environments.endpoints.pagerduty]
  api_key = "only-here"
  default_service_id = "PSVC1"
"#,
        );
        let pools = gather_endpoints(&cfg).expect("gather");
        let pd = pools.pagerduty.expect("pagerduty present");
        assert_eq!(pd.api_key, "only-here");
        assert_eq!(pd.default_service_id.as_deref(), Some("PSVC1"));
    }

    // ── build_ssh_entries ─────────────────────────────────────────

    #[tokio::test]
    async fn build_ssh_entries_walks_flat_and_hierarchical() {
        let (cfg, _tmp) = parse_with_tmp(
            r#"
workspace_dir = "/tmp/x"

[[projects]]
name = "shopfront"

  [[projects.environments]]
  name = "prod"

    [[projects.environments.targets]]
    name = "hier-host"
    type = "ssh"
    host = "10.0.0.2"
    user = "ops"
    key_secret = "fake-pem-bytes"
"#,
        );
        let entries = build_ssh_entries(&cfg).await.expect("build");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hier-host");
        assert_eq!(entries[0].host, "10.0.0.2");
        assert_eq!(entries[0].port, 22);
    }

    #[tokio::test]
    async fn build_ssh_entries_skips_non_ssh_and_incomplete_targets() {
        let (cfg, _tmp) = parse_with_tmp(
            r#"
workspace_dir = "/tmp/x"

[[targets]]
name = "local-only"
type = "local"

[[targets]]
name = "k8s-thing"
type = "kubernetes"

[[targets]]
name = "ssh-no-host"
type = "ssh"
user = "ops"
key_secret = "k"

[[targets]]
name = "ssh-no-user"
type = "ssh"
host = "10.0.0.3"
key_secret = "k"

[[targets]]
name = "ssh-no-key"
type = "ssh"
host = "10.0.0.4"
user = "ops"

[[targets]]
name = "ssh-good"
type = "ssh"
host = "10.0.0.5"
user = "ops"
key_secret = "fake-pem"
"#,
        );
        let entries = build_ssh_entries(&cfg).await.expect("build");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ssh-good");
    }
}

/// Extract SSH project entries from config, resolving key secrets as needed.
///
/// Reads both the flat `targets` list and every
/// `projects[*].environments[*].targets` list.
async fn build_ssh_entries(config: &OpsConfig) -> Result<Vec<TargetEntry>> {
    let mut entries = Vec::new();

    let mut all_targets: Vec<&crate::ops_config::TargetConfig> = Vec::new();
    all_targets.extend(config.targets.as_deref().unwrap_or_default().iter());
    for project in &config.projects {
        for env in &project.environments {
            all_targets.extend(env.targets.iter());
        }
    }

    for project in all_targets {
        if project.connection_type != ConnectionType::Ssh {
            continue;
        }

        let host = match project.host.as_ref() {
            Some(h) => h.clone(),
            None => continue,
        };
        let user = match project.user.as_ref() {
            Some(u) => u.clone(),
            None => continue,
        };
        let raw_key = match project.key_secret.as_ref() {
            Some(k) => k,
            None => continue,
        };

        let key_pem = config
            .decrypt_secret(raw_key)
            .await
            .with_context(|| format!("Failed to resolve SSH key for target '{}'", project.name))?;

        entries.push(TargetEntry {
            name: project.name.clone(),
            host,
            port: project.port.unwrap_or(22),
            user,
            private_key_pem: key_pem,
            autonomy: project.autonomy,
        });
    }

    Ok(entries)
}
