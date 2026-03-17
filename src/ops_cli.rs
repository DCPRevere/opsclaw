//! OpsClaw CLI command handlers: scan, monitor, watch.

use std::fs;

use anyhow::{bail, Context, Result};
use tracing::info;

use crate::config::schema::{TargetConfig, TargetType};
use crate::config::Config;

// Re-import from the same crate tree the binary uses — discovery/monitoring
// types are fine because they don't reference Config.
use zeroclaw::ops::diagnosis::MonitoringAgent;
use zeroclaw::ops::event_stream::{self, EventStreamManager};
use zeroclaw::ops::{monitor_log, snapshots};
use zeroclaw::tools::discovery::{self, CommandOutput, CommandRunner};
use zeroclaw::tools::monitoring;
use zeroclaw::tools::ssh_command_runner::SshCommandRunner;
use zeroclaw::tools::ssh_tool::{OpsClawAutonomy, RealSshExecutor, TargetEntry};

// ---------------------------------------------------------------------------
// Local command runner (runs commands on the local machine)
// ---------------------------------------------------------------------------

struct LocalCommandRunner;

#[async_trait::async_trait]
impl CommandRunner for LocalCommandRunner {
    async fn run(&self, command: &str) -> Result<CommandOutput> {
        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .await
            .with_context(|| format!("Failed to execute: {command}"))?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

// ---------------------------------------------------------------------------
// Runner factory
// ---------------------------------------------------------------------------

/// Build a [`CommandRunner`] for a target config, loading SSH keys from disk.
fn make_runner(target: &TargetConfig) -> Result<Box<dyn CommandRunner>> {
    match target.target_type {
        TargetType::Local => Ok(Box::new(LocalCommandRunner)),
        TargetType::Ssh => {
            let host = target.host.clone().unwrap_or_default();
            let user = target.user.clone().unwrap_or_default();
            let port = target.port.unwrap_or(22);

            // Resolve SSH key: key_secret holds a file path (possibly with ~)
            let key_pem = match &target.key_secret {
                Some(path) => {
                    let expanded = expand_tilde(path);
                    fs::read_to_string(&expanded)
                        .with_context(|| format!("Failed to read SSH key from {expanded}"))?
                }
                None => {
                    // Fall back to ~/.ssh/id_rsa
                    let default_key = expand_tilde("~/.ssh/id_rsa");
                    fs::read_to_string(&default_key)
                        .with_context(|| "No key_secret configured and ~/.ssh/id_rsa not found".to_string())?
                }
            };

            let entry = TargetEntry {
                name: target.name.clone(),
                host,
                port,
                user,
                private_key_pem: key_pem,
                autonomy: convert_autonomy(target.autonomy),
            };

            Ok(Box::new(SshCommandRunner::new(entry, Box::new(RealSshExecutor))))
        }
    }
}

/// Convert config schema autonomy to ssh_tool autonomy.
fn convert_autonomy(a: crate::config::schema::OpsClawAutonomy) -> OpsClawAutonomy {
    match a {
        crate::config::schema::OpsClawAutonomy::Observe => OpsClawAutonomy::Observe,
        crate::config::schema::OpsClawAutonomy::Suggest => OpsClawAutonomy::Suggest,
        crate::config::schema::OpsClawAutonomy::ActOnKnown => OpsClawAutonomy::ActOnKnown,
        crate::config::schema::OpsClawAutonomy::FullAuto => OpsClawAutonomy::FullAuto,
    }
}

/// Expand a leading `~` to the home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_owned()
}

// ---------------------------------------------------------------------------
// scan command
// ---------------------------------------------------------------------------

pub async fn handle_scan(config: &Config, target: Option<String>, all: bool) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), all)?;

    for t in &targets {
        info!("Scanning target: {}", t.name);
        let runner = make_runner(t)?;
        let snapshot = discovery::run_discovery_scan(runner.as_ref())
            .await
            .with_context(|| format!("Scan failed for target '{}'", t.name))?;

        snapshots::save_snapshot(&t.name, &snapshot)?;
        let path = snapshots::snapshot_path(&t.name)?;
        info!("Snapshot saved to {}", path.display());

        let md = discovery::snapshot_to_markdown(&snapshot);
        println!("{md}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// monitor command
// ---------------------------------------------------------------------------

pub async fn handle_monitor(
    config: &Config,
    target: Option<String>,
    interval_secs: u64,
    once: bool,
) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), target.is_none())?;

    if targets.is_empty() {
        bail!("No targets configured. Add [[targets]] to your config.");
    }

    loop {
        for t in &targets {
            let runner = make_runner(t)?;
            let current = match discovery::run_discovery_scan(runner.as_ref()).await {
                Ok(snap) => snap,
                Err(e) => {
                    eprintln!(
                        "[{}] Scan error for {}: {e}",
                        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                        t.name
                    );
                    continue;
                }
            };

            let baseline = snapshots::load_snapshot(&t.name)?;

            match baseline {
                None => {
                    snapshots::save_snapshot(&t.name, &current)?;
                    info!("Baseline established for {}", t.name);
                    println!(
                        "[{}] {} baseline established ({} containers, {} services)",
                        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                        t.name,
                        current.containers.len(),
                        current.services.len()
                    );
                }
                Some(ref baseline) => {
                    let hc = monitoring::check_health(&t.name, baseline, &current);
                    let log_line = monitor_log::format_log_line(&hc);
                    println!("{log_line}");
                    monitor_log::append_log(&hc)?;

                    if hc.status != monitoring::HealthStatus::Healthy {
                        let md = monitoring::health_check_to_markdown(&hc);
                        eprintln!("{md}");

                        // LLM diagnosis when an API key is available.
                        if let Some(agent) = make_monitoring_agent() {
                            match agent.diagnose(&hc, None).await {
                                Ok(Some(diag)) => {
                                    eprintln!(
                                        "\u{1f50d} Diagnosis: {}",
                                        diag.llm_assessment
                                    );
                                    eprintln!(
                                        "   Actions: {}",
                                        diag.suggested_actions.join(", ")
                                    );
                                    eprintln!(
                                        "   Severity: {}",
                                        diag.severity
                                    );
                                    if let Err(e) = agent.record_incident(&diag) {
                                        eprintln!("   Warning: failed to record incident: {e}");
                                    } else {
                                        let date = diag.timestamp.format("%Y-%m-%d").to_string();
                                        let path = agent.incident_log_path(&t.name, &date);
                                        eprintln!(
                                            "   Incident ID: {} logged to {}",
                                            diag.incident_id,
                                            path.display()
                                        );
                                    }
                                }
                                Ok(None) => {} // healthy — shouldn't happen here
                                Err(e) => {
                                    eprintln!("   Diagnosis skipped (LLM error): {e}");
                                }
                            }
                        }
                    }
                }
            }
        }

        if once {
            break;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// watch command
// ---------------------------------------------------------------------------

pub async fn handle_watch(config: &Config, target: Option<String>) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), target.is_none())?;

    if targets.is_empty() {
        bail!("No targets configured. Add [[targets]] to your config.");
    }

    let mut manager = EventStreamManager::new();

    for t in &targets {
        match t.target_type {
            TargetType::Local => {
                info!("Adding Docker + systemd event sources for local target '{}'", t.name);
                manager.add_docker_source();
                manager.add_systemd_source();
            }
            TargetType::Ssh => {
                // SSH streaming not yet wired — skip with a warning.
                eprintln!(
                    "Warning: SSH event streaming not yet supported, skipping target '{}'",
                    t.name
                );
            }
        }
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);

    // Spawn the manager in a background task.
    let manager_handle = tokio::spawn(async move {
        if let Err(e) = manager.run(tx).await {
            tracing::error!("Event stream manager error: {e}");
        }
    });

    // Read events from the channel and print / alert.
    while let Some(event) = rx.recv().await {
        let line = event_stream::format_event(&event);
        println!("{line}");

        if let Some(alert_msg) = event_stream::event_to_alert(&event) {
            tracing::warn!("ALERT: {alert_msg}");
        }
    }

    let _ = manager_handle.await;
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Create a [`MonitoringAgent`] if `ANTHROPIC_API_KEY` is set.
fn make_monitoring_agent() -> Option<MonitoringAgent> {
    let api_key = std::env::var("ANTHROPIC_API_KEY").ok()?;
    if api_key.is_empty() {
        return None;
    }
    let model = std::env::var("OPSCLAW_DIAGNOSIS_MODEL")
        .unwrap_or_else(|_| "claude-sonnet-4-20250514".to_string());
    Some(MonitoringAgent::new(model, api_key))
}

fn resolve_targets<'a>(
    config: &'a Config,
    target_name: Option<&str>,
    all: bool,
) -> Result<Vec<&'a TargetConfig>> {
    let targets = config.targets.as_deref().unwrap_or_default();

    if targets.is_empty() {
        bail!("No [[targets]] defined in config. Add at least one target.");
    }

    if let Some(name) = target_name {
        let t = targets
            .iter()
            .find(|t| t.name == name)
            .with_context(|| format!("Target '{name}' not found in config"))?;
        Ok(vec![t])
    } else if all {
        Ok(targets.iter().collect())
    } else {
        bail!("Specify a target name or use --all");
    }
}
