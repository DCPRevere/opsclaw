//! OpsClaw tool registry — creates SRE-specific tools from [`OpsConfig`]
//! for injection into the ZeroClaw agent loop.

use anyhow::Result;
use zeroclaw::tools::Tool;

use crate::ops_config::{OpsConfig, ConnectionType};
use crate::tools::azure_service_bus_tool::{AzureServiceBusTool, AzureServiceBusToolConfig};
use crate::tools::cert_tool::CertTool;
use crate::tools::cloudflare_tool::{CloudflareTool, CloudflareToolConfig};
use crate::tools::dns_tool::DnsTool;
use crate::tools::docker_tool::{DockerTool, DockerToolConfig};
use crate::tools::elk_tool::{ElkEndpoint, ElkTool};
use crate::tools::firewall_tool::{FirewallTool, FirewallToolConfig};
use crate::tools::github_tool::{GithubTool, GithubToolConfig};
use crate::tools::a2a_tool::A2aTool;
use crate::tools::jaeger_tool::{JaegerEndpoint, JaegerTool};
use crate::tools::kube_tool::{KubeTool, KubeToolConfig};
use crate::tools::loki_tool::{LokiEndpoint, LokiTool};
use crate::tools::postgres_tool::{PostgresInstance, PostgresTool, PostgresToolConfig};
use crate::tools::monitor_tool::MonitorTool;
use crate::tools::pagerduty_tool::{PagerDutyTool, PagerDutyToolConfig};
use crate::tools::prometheus_tool::{PrometheusEndpoint, PrometheusTool};
use crate::tools::rabbitmq_tool::{RabbitMqTool, RabbitMqToolConfig};
use crate::tools::ssh_tool::{TargetEntry, SshTool, SshToolConfig};
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

    // Prometheus — one tool with all configured endpoints.
    if let Some(eps) = config.prometheus.as_ref() {
        let mut endpoints: Vec<PrometheusEndpoint> = Vec::with_capacity(eps.len());
        for e in eps {
            let bearer_token = match e.bearer_token.as_ref() {
                Some(t) => config.decrypt_secret(t).await.ok(),
                None => None,
            };
            endpoints.push(PrometheusEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token,
            });
        }
        if !endpoints.is_empty() {
            tools.push(Box::new(PrometheusTool::new(endpoints)));
        }
    }

    // Loki.
    if let Some(eps) = config.loki.as_ref() {
        let mut endpoints: Vec<LokiEndpoint> = Vec::with_capacity(eps.len());
        for e in eps {
            let bearer_token = match e.bearer_token.as_ref() {
                Some(t) => config.decrypt_secret(t).await.ok(),
                None => None,
            };
            endpoints.push(LokiEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token,
                org_id: e.org_id.clone(),
            });
        }
        if !endpoints.is_empty() {
            tools.push(Box::new(LokiTool::new(endpoints)));
        }
    }

    // Elk.
    if let Some(eps) = config.elk.as_ref() {
        let mut endpoints: Vec<ElkEndpoint> = Vec::with_capacity(eps.len());
        for e in eps {
            let password = match e.password.as_ref() {
                Some(p) => config.decrypt_secret(p).await.ok(),
                None => None,
            };
            let api_key = match e.api_key.as_ref() {
                Some(k) => config.decrypt_secret(k).await.ok(),
                None => None,
            };
            endpoints.push(ElkEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                username: e.username.clone(),
                password,
                api_key,
                default_index: e.default_index.clone(),
            });
        }
        if !endpoints.is_empty() {
            tools.push(Box::new(ElkTool::new(endpoints)));
        }
    }

    // PagerDuty.
    if let Some(pd) = config.pagerduty.as_ref() {
        match config.decrypt_secret(&pd.api_key).await {
            Ok(api_key) => {
                let mut cfg = PagerDutyToolConfig::new(api_key);
                cfg.default_service_id = pd.default_service_id.clone();
                cfg.default_from = pd.default_from.clone();
                cfg.autonomy = pd.autonomy;
                tools.push(Box::new(PagerDutyTool::new(cfg)));
            }
            Err(e) => {
                tracing::warn!("Skipping PagerDuty tool — failed to resolve api_key: {e}");
            }
        }
    }

    // GitHub.
    if let Some(gh) = config.github.as_ref() {
        match config.decrypt_secret(&gh.token).await {
            Ok(token) => {
                let mut cfg = GithubToolConfig::new(token);
                cfg.default_owner = gh.default_owner.clone();
                cfg.default_repo = gh.default_repo.clone();
                cfg.autonomy = gh.autonomy;
                tools.push(Box::new(GithubTool::new(cfg)));
            }
            Err(e) => {
                tracing::warn!("Skipping GitHub tool — failed to resolve token: {e}");
            }
        }
    }

    // Cloudflare.
    if let Some(cf) = config.cloudflare.as_ref() {
        match config.decrypt_secret(&cf.api_token).await {
            Ok(tok) => {
                let mut cfg = CloudflareToolConfig::new(tok);
                cfg.default_zone_id = cf.default_zone_id.clone();
                cfg.default_account_id = cf.default_account_id.clone();
                cfg.autonomy = cf.autonomy;
                tools.push(Box::new(CloudflareTool::new(cfg)));
            }
            Err(e) => {
                tracing::warn!("Skipping Cloudflare tool — failed to resolve api_token: {e}");
            }
        }
    }

    // RabbitMQ.
    if let Some(rmq) = config.rabbitmq.as_ref() {
        let password = config
            .decrypt_secret(&rmq.password)
            .await
            .unwrap_or_else(|_| rmq.password.clone());
        let mut cfg =
            RabbitMqToolConfig::new(rmq.api_base.clone(), rmq.username.clone(), password);
        cfg.default_vhost = rmq.default_vhost.clone();
        cfg.autonomy = rmq.autonomy;
        tools.push(Box::new(RabbitMqTool::new(cfg)));
    }

    // Jaeger.
    if let Some(eps) = config.jaeger.as_ref() {
        let mut endpoints: Vec<JaegerEndpoint> = Vec::with_capacity(eps.len());
        for e in eps {
            let bearer_token = match e.bearer_token.as_ref() {
                Some(t) => config.decrypt_secret(t).await.ok(),
                None => None,
            };
            endpoints.push(JaegerEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token,
            });
        }
        if !endpoints.is_empty() {
            tools.push(Box::new(JaegerTool::new(endpoints)));
        }
    }

    // Postgres (driver-based).
    if let Some(pgs) = config.postgres.as_ref() {
        let mut instances: Vec<PostgresInstance> = Vec::with_capacity(pgs.len());
        for p in pgs {
            let dsn = config
                .decrypt_secret(&p.dsn)
                .await
                .unwrap_or_else(|_| p.dsn.clone());
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
    if let Some(sb) = config.azure_service_bus.as_ref() {
        match config.decrypt_secret(&sb.sas_key).await {
            Ok(key) => {
                let mut cfg = AzureServiceBusToolConfig::new(
                    sb.namespace.clone(),
                    sb.sas_key_name.clone(),
                    key,
                );
                cfg.autonomy = sb.autonomy;
                tools.push(Box::new(AzureServiceBusTool::new(cfg)));
            }
            Err(e) => {
                tracing::warn!("Skipping Azure Service Bus tool — failed to resolve sas_key: {e}");
            }
        }
    }

    Ok(tools)
}

/// Extract SSH project entries from config, resolving key secrets as needed.
async fn build_ssh_entries(config: &OpsConfig) -> Result<Vec<TargetEntry>> {
    let projects = config.targets.as_deref().unwrap_or_default();
    let mut entries = Vec::new();

    for project in projects {
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

        let key_pem = match config.decrypt_secret(raw_key).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    project = project.name,
                    "Skipping SSH project — failed to resolve key: {e}"
                );
                continue;
            }
        };

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
