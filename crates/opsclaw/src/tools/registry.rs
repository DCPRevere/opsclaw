//! OpsClaw tool registry — creates SRE-specific tools from [`OpsConfig`]
//! for injection into the ZeroClaw agent loop.

use anyhow::Result;
use zeroclaw::tools::Tool;

use crate::ops_config::{OpsConfig, ConnectionType};
use crate::tools::azure_service_bus_tool::{AzureServiceBusTool, AzureServiceBusToolConfig};
use crate::tools::cert_tool::CertTool;
use crate::tools::cloudflare_tool::{CloudflareTool, CloudflareToolConfig};
use crate::tools::dns_tool::DnsTool;
use crate::tools::elk_tool::{ElkEndpoint, ElkTool};
use crate::tools::firewall_tool::{FirewallTool, FirewallToolConfig};
use crate::tools::github_tool::{GithubTool, GithubToolConfig};
use crate::tools::jaeger_tool::{JaegerEndpoint, JaegerTool};
use crate::tools::loki_tool::{LokiEndpoint, LokiTool};
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
pub fn create_opsclaw_tools(config: &OpsConfig) -> Result<Vec<Box<dyn Tool>>> {
    let mut tools: Vec<Box<dyn Tool>> = Vec::new();

    // SSH + systemd + firewall share the same project entries.
    let ssh_targets = build_ssh_entries(config)?;
    if !ssh_targets.is_empty() {
        tools.push(Box::new(SshTool::new(SshToolConfig {
            targets: ssh_targets.clone(),
        })));
        tools.push(Box::new(SystemdTool::new(SystemdToolConfig {
            targets: ssh_targets.clone(),
        })));
        tools.push(Box::new(FirewallTool::new(FirewallToolConfig {
            targets: ssh_targets,
        })));
    }

    // Monitor tool — wraps discovery scan + health check.
    tools.push(Box::new(MonitorTool::new(config.clone())));

    // DNS tool — ad-hoc lookups, no config required.
    tools.push(Box::new(DnsTool::new()));

    // Cert tool — TLS cert inspection, no config required.
    tools.push(Box::new(CertTool::new()));

    // Prometheus — one tool with all configured endpoints.
    if let Some(eps) = config.prometheus.as_ref() {
        let endpoints: Vec<PrometheusEndpoint> = eps
            .iter()
            .map(|e| PrometheusEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token: e
                    .bearer_token
                    .as_ref()
                    .and_then(|t| config.decrypt_secret(t).ok()),
            })
            .collect();
        if !endpoints.is_empty() {
            tools.push(Box::new(PrometheusTool::new(endpoints)));
        }
    }

    // Loki.
    if let Some(eps) = config.loki.as_ref() {
        let endpoints: Vec<LokiEndpoint> = eps
            .iter()
            .map(|e| LokiEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token: e
                    .bearer_token
                    .as_ref()
                    .and_then(|t| config.decrypt_secret(t).ok()),
                org_id: e.org_id.clone(),
            })
            .collect();
        if !endpoints.is_empty() {
            tools.push(Box::new(LokiTool::new(endpoints)));
        }
    }

    // Elk.
    if let Some(eps) = config.elk.as_ref() {
        let endpoints: Vec<ElkEndpoint> = eps
            .iter()
            .map(|e| ElkEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                username: e.username.clone(),
                password: e
                    .password
                    .as_ref()
                    .and_then(|p| config.decrypt_secret(p).ok()),
                api_key: e
                    .api_key
                    .as_ref()
                    .and_then(|k| config.decrypt_secret(k).ok()),
                default_index: e.default_index.clone(),
            })
            .collect();
        if !endpoints.is_empty() {
            tools.push(Box::new(ElkTool::new(endpoints)));
        }
    }

    // PagerDuty.
    if let Some(pd) = config.pagerduty.as_ref() {
        if let Ok(api_key) = config.decrypt_secret(&pd.api_key) {
            let mut cfg = PagerDutyToolConfig::new(api_key);
            cfg.default_service_id = pd.default_service_id.clone();
            cfg.default_from = pd.default_from.clone();
            cfg.autonomy = pd.autonomy;
            tools.push(Box::new(PagerDutyTool::new(cfg)));
        } else {
            tracing::warn!("Skipping PagerDuty tool — failed to decrypt api_key");
        }
    }

    // GitHub.
    if let Some(gh) = config.github.as_ref() {
        if let Ok(token) = config.decrypt_secret(&gh.token) {
            let mut cfg = GithubToolConfig::new(token);
            cfg.default_owner = gh.default_owner.clone();
            cfg.default_repo = gh.default_repo.clone();
            cfg.autonomy = gh.autonomy;
            tools.push(Box::new(GithubTool::new(cfg)));
        } else {
            tracing::warn!("Skipping GitHub tool — failed to decrypt token");
        }
    }

    // Cloudflare.
    if let Some(cf) = config.cloudflare.as_ref() {
        if let Ok(tok) = config.decrypt_secret(&cf.api_token) {
            let mut cfg = CloudflareToolConfig::new(tok);
            cfg.default_zone_id = cf.default_zone_id.clone();
            cfg.default_account_id = cf.default_account_id.clone();
            cfg.autonomy = cf.autonomy;
            tools.push(Box::new(CloudflareTool::new(cfg)));
        } else {
            tracing::warn!("Skipping Cloudflare tool — failed to decrypt api_token");
        }
    }

    // RabbitMQ.
    if let Some(rmq) = config.rabbitmq.as_ref() {
        let password = config
            .decrypt_secret(&rmq.password)
            .unwrap_or_else(|_| rmq.password.clone());
        let mut cfg =
            RabbitMqToolConfig::new(rmq.api_base.clone(), rmq.username.clone(), password);
        cfg.default_vhost = rmq.default_vhost.clone();
        cfg.autonomy = rmq.autonomy;
        tools.push(Box::new(RabbitMqTool::new(cfg)));
    }

    // Jaeger.
    if let Some(eps) = config.jaeger.as_ref() {
        let endpoints: Vec<JaegerEndpoint> = eps
            .iter()
            .map(|e| JaegerEndpoint {
                name: e.name.clone(),
                url: e.url.clone(),
                bearer_token: e
                    .bearer_token
                    .as_ref()
                    .and_then(|t| config.decrypt_secret(t).ok()),
            })
            .collect();
        if !endpoints.is_empty() {
            tools.push(Box::new(JaegerTool::new(endpoints)));
        }
    }

    // Azure Service Bus.
    if let Some(sb) = config.azure_service_bus.as_ref() {
        if let Ok(key) = config.decrypt_secret(&sb.sas_key) {
            let mut cfg = AzureServiceBusToolConfig::new(
                sb.namespace.clone(),
                sb.sas_key_name.clone(),
                key,
            );
            cfg.autonomy = sb.autonomy;
            tools.push(Box::new(AzureServiceBusTool::new(cfg)));
        } else {
            tracing::warn!("Skipping Azure Service Bus tool — failed to decrypt sas_key");
        }
    }

    Ok(tools)
}

/// Extract SSH project entries from config, decrypting keys as needed.
fn build_ssh_entries(config: &OpsConfig) -> Result<Vec<TargetEntry>> {
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

        let key_pem = match config.decrypt_secret(raw_key) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    project = project.name,
                    "Skipping SSH project — failed to decrypt key: {e}"
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
