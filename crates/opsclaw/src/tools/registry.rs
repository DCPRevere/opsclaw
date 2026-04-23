//! OpsClaw tool registry — creates SRE-specific tools from [`OpsConfig`]
//! for injection into the ZeroClaw agent loop.

use anyhow::Result;
use zeroclaw::tools::Tool;

use crate::ops_config::{OpsConfig, ProjectType};
use crate::tools::cert_tool::CertTool;
use crate::tools::dns_tool::DnsTool;
use crate::tools::elk_tool::{ElkEndpoint, ElkTool};
use crate::tools::loki_tool::{LokiEndpoint, LokiTool};
use crate::tools::monitor_tool::MonitorTool;
use crate::tools::pagerduty_tool::{PagerDutyTool, PagerDutyToolConfig};
use crate::tools::prometheus_tool::{PrometheusEndpoint, PrometheusTool};
use crate::tools::ssh_tool::{ProjectEntry, SshTool, SshToolConfig};
use crate::tools::systemd_tool::{SystemdTool, SystemdToolConfig};

/// Build OpsClaw-specific tools from the current configuration.
///
/// These are injected into the ZeroClaw agent loop via the `extra_tools`
/// parameter, following the same pattern as `create_peripheral_tools()`.
pub fn create_opsclaw_tools(config: &OpsConfig) -> Result<Vec<Box<dyn Tool>>> {
    let mut tools: Vec<Box<dyn Tool>> = Vec::new();

    // SSH + systemd share the same project entries.
    let ssh_projects = build_ssh_entries(config)?;
    if !ssh_projects.is_empty() {
        tools.push(Box::new(SshTool::new(SshToolConfig {
            projects: ssh_projects.clone(),
        })));
        tools.push(Box::new(SystemdTool::new(SystemdToolConfig {
            projects: ssh_projects,
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

    Ok(tools)
}

/// Extract SSH project entries from config, decrypting keys as needed.
fn build_ssh_entries(config: &OpsConfig) -> Result<Vec<ProjectEntry>> {
    let projects = config.projects.as_deref().unwrap_or_default();
    let mut entries = Vec::new();

    for project in projects {
        if project.project_type != ProjectType::Ssh {
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

        entries.push(ProjectEntry {
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
