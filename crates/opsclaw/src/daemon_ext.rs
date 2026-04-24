//! OpsClaw daemon extensions — thin glue on top of the upstream zeroclaw
//! daemon so every agent run launched by the heartbeat worker sees
//! OpsClaw's SRE tools and has a project-scoped scan task to run.
//!
//! No upstream code is copied or modified; we piggy-back on the
//! runtime's existing peripheral-tools factory hook, which is already
//! invoked unconditionally at the start of each agent run. The
//! `PeripheralsConfig` argument is ignored — the mechanism is generic,
//! only the name is peripheral-flavoured.

use anyhow::Result;
use std::path::Path;

use crate::ops_config::{OpsConfig, ConnectionType};
use crate::tools::registry::create_opsclaw_tools;

/// Register the opsclaw SRE tools with the runtime via the existing
/// peripheral-tools factory slot. Safe to call once at daemon startup.
/// OpsClaw does not use hardware peripherals, so the slot is free.
pub fn register_sre_tools(ops_config: OpsConfig) {
    zeroclaw_runtime::agent::loop_::register_peripheral_tools_fn(Box::new(move |_peripherals_cfg| {
        let ops = ops_config.clone();
        Box::pin(async move {
            create_opsclaw_tools(&ops).await.map_err(|e| {
                tracing::error!(
                    error = %e,
                    "Failed to build opsclaw SRE tools for agent run — aborting so the agent does not run without its SRE toolset",
                );
                e
            })
        })
    }));
}

/// Seed HEARTBEAT.md with one scan task per configured project, but only
/// when the file is missing or still contains the upstream default
/// placeholder. A user-authored file is never rewritten.
pub async fn seed_heartbeat_file(workspace_dir: &Path, ops_config: &OpsConfig) -> Result<()> {
    let path = workspace_dir.join("HEARTBEAT.md");
    let existing = tokio::fs::read_to_string(&path).await.ok();

    let should_seed = match existing.as_deref() {
        None => true,
        Some(contents) => is_default_heartbeat(contents),
    };

    if !should_seed {
        return Ok(());
    }

    let projects = ops_config.targets.as_deref().unwrap_or_default();
    let scan_targets: Vec<&str> = projects
        .iter()
        .filter(|p| p.connection_type == ConnectionType::Ssh)
        .map(|p| p.name.as_str())
        .collect();

    if scan_targets.is_empty() {
        return Ok(());
    }

    let mut body = String::from(
        "# OpsClaw Heartbeat Tasks\n\n\
         # One task per configured project. Edit freely: the daemon only\n\
         # seeds this file when it's missing or still contains the upstream\n\
         # default placeholder.\n\n",
    );
    for name in scan_targets {
        body.push_str(&format!(
            "- [high] Run a health check on target '{name}' using the monitor tool. \
             Inspect the snapshot and use the ssh tool to investigate further when \
             anything looks concerning (high memory/disk/load, missing containers or \
             services, unusual state). When you confirm a real problem, you MUST call \
             the escalate_to_human tool with a one-line summary, the relevant context, \
             and an appropriate urgency (warning → medium, critical → high). Do not \
             just describe the problem in your final reply: an unsent escalation is a \
             missed alert. If everything looks healthy, say so briefly and do not \
             escalate.\n"
        ));
    }

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    tokio::fs::write(&path, body).await?;
    tracing::info!(path = %path.display(), "Seeded HEARTBEAT.md with per-project scan tasks");
    Ok(())
}

fn is_default_heartbeat(contents: &str) -> bool {
    let trimmed = contents.trim();
    trimmed.is_empty() || trimmed.starts_with("# Periodic Tasks")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_upstream_default_placeholder() {
        let default = "# Periodic Tasks\n\n# Add tasks below\n";
        assert!(is_default_heartbeat(default));
    }

    #[test]
    fn empty_file_is_treated_as_default() {
        assert!(is_default_heartbeat(""));
        assert!(is_default_heartbeat("   \n\n"));
    }

    #[test]
    fn user_authored_file_is_preserved() {
        let user = "# My tasks\n\n- [high] Do the thing\n";
        assert!(!is_default_heartbeat(user));
    }
}
