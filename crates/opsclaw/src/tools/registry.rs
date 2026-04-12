//! OpsClaw tool registry — creates SRE-specific tools from [`OpsConfig`]
//! for injection into the ZeroClaw agent loop.

use anyhow::Result;
use zeroclaw::tools::Tool;

use crate::ops_config::{OpsConfig, ProjectType};
use crate::tools::monitor_tool::MonitorTool;
use crate::tools::ssh_tool::{ProjectEntry, SshTool, SshToolConfig};

/// Build OpsClaw-specific tools from the current configuration.
///
/// These are injected into the ZeroClaw agent loop via the `extra_tools`
/// parameter, following the same pattern as `create_peripheral_tools()`.
pub fn create_opsclaw_tools(config: &OpsConfig) -> Result<Vec<Box<dyn Tool>>> {
    let mut tools: Vec<Box<dyn Tool>> = Vec::new();

    // SSH tool — one tool instance with all SSH project entries.
    let ssh_projects = build_ssh_entries(config)?;
    if !ssh_projects.is_empty() {
        tools.push(Box::new(SshTool::new(SshToolConfig {
            projects: ssh_projects,
        })));
    }

    // Monitor tool — wraps discovery scan + health check.
    tools.push(Box::new(MonitorTool::new(config.clone())));

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
