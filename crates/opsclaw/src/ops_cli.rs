//! OpsClaw CLI command handlers: scan, monitor, watch.

use std::fs;

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use tokio::signal;
use tracing::info;

use zeroclaw::config::schema::{TargetConfig, TargetType};
use zeroclaw::config::Config;

/// Runbook subcommands
#[derive(Subcommand, Debug)]
pub enum RunbookActions {
    /// List all runbooks
    List,
    /// Show runbook details and steps
    Show {
        /// Runbook ID
        id: String,
    },
    /// Install default runbooks
    Init,
    /// Manually execute a runbook against a target
    Run {
        /// Runbook ID
        id: String,
        /// Target name (from config [[targets]])
        #[arg(long)]
        target: String,
    },
}

// Re-import from the same crate tree the binary uses — discovery/monitoring
// types are fine because they don't reference Config.
use crate::ops::baseline::{self, anomalies_to_alerts, extract_metrics, BaselineStore};
use crate::ops::diagnosis::{Diagnosis, MonitoringAgent};
use crate::ops::event_stream::{self, EventStreamManager};
use crate::ops::incident_search::IncidentIndex;
use crate::ops::log_sources::{self, LogLevel, LogSourceType};
use crate::ops::notifier::{AlertNotifier, NullNotifier, TelegramNotifier};
use crate::ops::runbooks::{self, RunbookStore};
use crate::ops::{monitor_log, probes, snapshots};
use crate::tools::discovery::{self, CommandRunner};
use crate::tools::monitoring::{self, HealthCheck};
use crate::tools::ssh_command_runner::{DryRunCommandRunner, LocalCommandRunner, SshCommandRunner};
use crate::tools::ssh_tool::{OpsClawAutonomy, RealSshExecutor, TargetEntry};
use zeroclaw::config::schema::parse_min_severity;

// ---------------------------------------------------------------------------
// Runner factory
// ---------------------------------------------------------------------------

/// Convert binary-crate `ProbeConfig` values to lib-crate `ProbeConfig` values.
///
/// The binary and library compile `config::schema` independently, so their
/// struct types are distinct even though the source is identical. A
/// serde round-trip bridges the gap.
fn convert_probes(
    bin_probes: &[zeroclaw::config::schema::ProbeConfig],
) -> Vec<zeroclaw::config::schema::ProbeConfig> {
    let json = serde_json::to_value(bin_probes).expect("ProbeConfig serializes");
    serde_json::from_value(json).expect("ProbeConfig deserializes")
}

/// Build a [`CommandRunner`] for a target config, loading SSH keys from disk.
///
/// In `DryRun` mode the runner is wrapped with [`DryRunCommandRunner`] so that
/// write commands are logged instead of executed.
fn make_runner(target: &TargetConfig) -> Result<Box<dyn CommandRunner>> {
    let autonomy = convert_autonomy(target.autonomy);

    let runner: Box<dyn CommandRunner> = match target.target_type {
        TargetType::Local => Box::new(LocalCommandRunner::new(autonomy, target.name.clone())),
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
                    fs::read_to_string(&default_key).with_context(|| {
                        "No key_secret configured and ~/.ssh/id_rsa not found".to_string()
                    })?
                }
            };

            let entry = TargetEntry {
                name: target.name.clone(),
                host,
                port,
                user,
                private_key_pem: key_pem,
                autonomy,
            };

            Box::new(SshCommandRunner::new(entry, Box::new(RealSshExecutor)))
        }
    };

    match target.autonomy {
        zeroclaw::config::schema::OpsClawAutonomy::DryRun => {
            let opsclaw_dir = opsclaw_dir()?;
            let dry_run_log = opsclaw_dir.join("dry-run.log");
            Ok(Box::new(DryRunCommandRunner::new(runner, dry_run_log)))
        }
        // Approve: approval gate is at a higher level (Phase 3); pass through.
        zeroclaw::config::schema::OpsClawAutonomy::Approve => Ok(runner),
        // Auto: no restrictions.
        zeroclaw::config::schema::OpsClawAutonomy::Auto => Ok(runner),
    }
}

/// Return the `~/.opsclaw` directory path.
fn opsclaw_dir() -> Result<std::path::PathBuf> {
    let home = directories::UserDirs::new()
        .map(|u| u.home_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    Ok(home.join(".opsclaw"))
}

/// Convert config schema autonomy to ssh_tool autonomy.
fn convert_autonomy(a: zeroclaw::config::schema::OpsClawAutonomy) -> OpsClawAutonomy {
    match a {
        zeroclaw::config::schema::OpsClawAutonomy::DryRun => OpsClawAutonomy::DryRun,
        zeroclaw::config::schema::OpsClawAutonomy::Approve => OpsClawAutonomy::Approve,
        zeroclaw::config::schema::OpsClawAutonomy::Auto => OpsClawAutonomy::Auto,
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
// dry-run-log command
// ---------------------------------------------------------------------------

pub fn handle_dry_run_log(tail: Option<usize>, clear: bool) -> Result<()> {
    let log_path = opsclaw_dir()?.join("dry-run.log");

    if clear {
        if log_path.exists() {
            fs::remove_file(&log_path)?;
            println!("Dry-run log cleared.");
        } else {
            println!("No dry-run log to clear.");
        }
        return Ok(());
    }

    if !log_path.exists() {
        println!("No dry-run log yet. Set a target's autonomy to 'dry-run' and run a scan or monitor cycle.");
        return Ok(());
    }

    let content = fs::read_to_string(&log_path)?;
    let lines: Vec<&str> = content.lines().collect();

    let output = match tail {
        Some(n) => lines
            .iter()
            .rev()
            .take(n)
            .rev()
            .copied()
            .collect::<Vec<_>>(),
        None => lines,
    };

    for line in output {
        println!("{line}");
    }
    Ok(())
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
// logs command
// ---------------------------------------------------------------------------

pub async fn handle_logs(
    config: &Config,
    target: Option<String>,
    source_filter: Option<String>,
    lines: usize,
    level_filter: Option<String>,
) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), target.is_none())?;

    let min_level = level_filter
        .as_deref()
        .map(parse_log_level_filter)
        .transpose()?;

    for t in &targets {
        let runner = make_runner(t)?;

        // Try loading an existing snapshot; fall back to a fresh scan.
        let snapshot = match snapshots::load_snapshot(&t.name)? {
            Some(snap) => snap,
            None => {
                info!("No snapshot for '{}', running discovery scan…", t.name);
                let snap = discovery::run_discovery_scan(runner.as_ref()).await?;
                snapshots::save_snapshot(&t.name, &snap)?;
                snap
            }
        };

        let all_sources = log_sources::discover_log_sources(&snapshot);
        let sources: Vec<_> = match source_filter.as_deref() {
            Some("docker") => all_sources
                .into_iter()
                .filter(|s| matches!(s, LogSourceType::DockerContainer { .. }))
                .collect(),
            Some("systemd") => all_sources
                .into_iter()
                .filter(|s| matches!(s, LogSourceType::SystemdUnit { .. }))
                .collect(),
            Some("file") => all_sources
                .into_iter()
                .filter(|s| matches!(s, LogSourceType::File { .. }))
                .collect(),
            Some(other) => {
                bail!("Unknown source type '{other}'. Use: docker, systemd, file");
            }
            None => all_sources,
        };

        for source in &sources {
            match log_sources::collect_logs(runner.as_ref(), source, lines, None).await {
                Ok(entries) => {
                    let filtered: Vec<_> = if let Some(ref min) = min_level {
                        entries
                            .into_iter()
                            .filter(|e| e.level.as_ref().map_or(false, |l| l >= min))
                            .collect()
                    } else {
                        entries
                    };
                    for entry in &filtered {
                        println!("{}", log_sources::format_log_entry(entry));
                    }
                }
                Err(e) => {
                    // Non-fatal — source may not exist (e.g. log file not present).
                    tracing::debug!("Skipping {source}: {e}");
                }
            }
        }
    }

    Ok(())
}

fn parse_log_level_filter(s: &str) -> Result<LogLevel> {
    match s.to_lowercase().as_str() {
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warn" | "warning" => Ok(LogLevel::Warn),
        "error" => Ok(LogLevel::Error),
        "fatal" | "critical" => Ok(LogLevel::Fatal),
        _ => bail!("Unknown log level '{s}'. Use: debug, info, warn, error, fatal"),
    }
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

    let notifier = make_notifier(config);
    let mut failure_counts: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();

    loop {
        for t in &targets {
            let runner = make_runner(t)?;
            let current = match discovery::run_discovery_scan(runner.as_ref()).await {
                Ok(snap) => {
                    failure_counts.remove(&t.name);
                    snap
                }
                Err(e) => {
                    let count = failure_counts.entry(t.name.clone()).or_insert(0);
                    *count += 1;
                    eprintln!(
                        "[{}] Scan error for {}: {e}",
                        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                        t.name
                    );
                    if *count >= 3 {
                        let msg = format!(
                            "\u{26a0}\u{fe0f} Cannot reach target '{}' \u{2014} {} consecutive scan failures. Last error: {}",
                            t.name, count, e
                        );
                        if let Err(ne) = notifier.notify_text(&t.name, &msg).await {
                            eprintln!("   Warning: escalation notification failed: {ne}");
                        }
                    }
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
                    let mut hc = monitoring::check_health(&t.name, baseline, &current);

                    // Run configured + auto-discovered probes
                    let configured_probes = convert_probes(t.probes.as_deref().unwrap_or_default());
                    let discovered = probes::discover_probes(&current, t.host.as_deref());

                    let mut probe_results = Vec::new();
                    for probe in configured_probes.iter().chain(discovered.iter()) {
                        match probes::run_probe(runner.as_ref(), probe).await {
                            Ok(result) => {
                                if let Some(alert) = probes::probe_result_to_alert(&result) {
                                    hc.alerts.push(alert);
                                }
                                probe_results.push(result);
                            }
                            Err(e) => {
                                eprintln!("   Probe '{}' error: {e}", probe.name);
                            }
                        }
                    }

                    // --- Baseline learning: extract metrics, record, detect anomalies ---
                    let metrics = extract_metrics(&current);
                    let bl_path = baseline::baseline_path(&t.name)?;
                    let mut bl_store = BaselineStore::load(&bl_path)?;
                    let anomalies = bl_store.check_anomalies(&t.name, &metrics, 3.0);
                    bl_store.record(&t.name, &metrics);
                    bl_store.save()?;

                    if !anomalies.is_empty() {
                        let anomaly_alerts = anomalies_to_alerts(&anomalies);
                        hc.alerts.extend(anomaly_alerts);
                    }
                    let baseline_summary = bl_store.summary(&t.name);
                    // --- End baseline learning ---

                    // Recalculate status after all alerts (probes + baselines)
                    hc.status = if hc
                        .alerts
                        .iter()
                        .any(|a| a.severity == monitoring::AlertSeverity::Critical)
                    {
                        monitoring::HealthStatus::Critical
                    } else if hc
                        .alerts
                        .iter()
                        .any(|a| a.severity == monitoring::AlertSeverity::Warning)
                    {
                        monitoring::HealthStatus::Warning
                    } else {
                        monitoring::HealthStatus::Healthy
                    };

                    let log_line = monitor_log::format_log_line(&hc);
                    println!("{log_line}");
                    monitor_log::append_log(&hc)?;

                    if hc.status != monitoring::HealthStatus::Healthy {
                        let mut md = monitoring::health_check_to_markdown(&hc);
                        if !probe_results.is_empty() {
                            md.push_str(&probes::probe_results_to_markdown(&probe_results));
                        }
                        eprintln!("{md}");

                        // Collect recent error logs for diagnosis context.
                        let error_log_context =
                            collect_error_logs_for_diagnosis(runner.as_ref(), &current).await;

                        if let Err(e) = notifier.notify(&t.name, &hc).await {
                            eprintln!("   Warning: notification failed: {e}");
                        }

                        // LLM diagnosis when an API key is available.
                        if let Some(agent) = make_monitoring_agent(config) {
                            // Load target context file if configured.
                            let mut context_content = t
                                .context_file
                                .as_ref()
                                .and_then(|path| std::fs::read_to_string(expand_tilde(path)).ok());

                            // Append error logs to context for the LLM.
                            if !error_log_context.is_empty() {
                                let combined = context_content.unwrap_or_default();
                                context_content = Some(format!(
                                    "{combined}\n\n## Recent Error Logs\n\n{error_log_context}"
                                ));
                            }

                            // Append baseline summary to context.
                            let context_with_baselines = match context_content {
                                Some(ctx) => format!("{ctx}\n\n{baseline_summary}"),
                                None => baseline_summary.clone(),
                            };

                            // Search past incidents for similar issues.
                            let incident_context = match IncidentIndex::load(&t.name) {
                                Ok(index) => {
                                    let similar = index.search_similar(&hc.alerts, 3);
                                    if similar.is_empty() {
                                        String::new()
                                    } else {
                                        eprintln!(
                                            "   Found {} similar past incident(s)",
                                            similar.len()
                                        );
                                        IncidentIndex::format_context(&similar)
                                    }
                                }
                                Err(e) => {
                                    eprintln!("   Warning: failed to load past incidents: {e}");
                                    String::new()
                                }
                            };

                            let full_context = if incident_context.is_empty() {
                                context_with_baselines
                            } else {
                                format!("{context_with_baselines}\n\n{incident_context}")
                            };

                            match agent.diagnose(&hc, Some(&full_context)).await {
                                Ok(Some(diag)) => {
                                    eprintln!("\u{1f50d} Diagnosis: {}", diag.llm_assessment);
                                    eprintln!("   Actions: {}", diag.suggested_actions.join(", "));
                                    eprintln!("   Severity: {}", diag.severity);

                                    // Send diagnosis to notification channel.
                                    let alert_text = format_diagnosis_alert(&hc, &diag);
                                    if let Err(e) = notifier.notify_text(&t.name, &alert_text).await
                                    {
                                        eprintln!("   Warning: diagnosis notification failed: {e}");
                                    }

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
                        } else {
                            tracing::info!("no LLM provider configured, skipping diagnosis");
                        }

                        // --- Runbook matching ---
                        if let Ok(store) = RunbookStore::default_dir().map(RunbookStore::new) {
                            if let Ok(matched) = store.match_alerts(&hc.alerts, &t.name) {
                                for rb in &matched {
                                    match t.autonomy {
                                        zeroclaw::config::schema::OpsClawAutonomy::DryRun => {
                                            eprintln!(
                                                "   WOULD_EXECUTE_RUNBOOK: {} ({})",
                                                rb.name, rb.id
                                            );
                                            for (i, step) in rb.steps.iter().enumerate() {
                                                eprintln!(
                                                    "     Step {}: {}{}",
                                                    i + 1,
                                                    step.description,
                                                    step.command
                                                        .as_deref()
                                                        .map(|c| format!(" — `{c}`"))
                                                        .unwrap_or_default()
                                                );
                                            }
                                        }
                                        zeroclaw::config::schema::OpsClawAutonomy::Approve => {
                                            eprintln!(
                                                "   Found matching runbook '{}'. Requesting approval...",
                                                rb.name
                                            );
                                            let action_desc = format!(
                                                "runbook '{}': {}",
                                                rb.name, rb.description
                                            );
                                            let approved = crate::ops::approval::request_approval(
                                                notifier.as_ref(),
                                                &t.name,
                                                &action_desc,
                                                120,
                                            )
                                            .await
                                            .unwrap_or(false);

                                            if approved {
                                                eprintln!(
                                                    "   Approved — executing runbook: {} ...",
                                                    rb.name
                                                );
                                                match runbooks::execute_runbook(
                                                    runner.as_ref(),
                                                    rb,
                                                    &t.name,
                                                    &hc.alerts,
                                                )
                                                .await
                                                {
                                                    Ok(exec) => {
                                                        let exec_md =
                                                            runbooks::execution_to_markdown(
                                                                &exec, &rb.name,
                                                            );
                                                        eprintln!("{exec_md}");
                                                        if let Err(e) = notifier
                                                            .notify_text(&t.name, &exec_md)
                                                            .await
                                                        {
                                                            eprintln!(
                                                                "   Warning: runbook notification failed: {e}"
                                                            );
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!(
                                                            "   Runbook execution failed: {e}"
                                                        );
                                                    }
                                                }
                                            } else {
                                                eprintln!(
                                                    "   Approval denied/timed out for runbook '{}' — skipping",
                                                    rb.name
                                                );
                                            }
                                        }
                                        zeroclaw::config::schema::OpsClawAutonomy::Auto => {
                                            eprintln!("   Executing runbook: {} ...", rb.name);
                                            match runbooks::execute_runbook(
                                                runner.as_ref(),
                                                rb,
                                                &t.name,
                                                &hc.alerts,
                                            )
                                            .await
                                            {
                                                Ok(exec) => {
                                                    let exec_md = runbooks::execution_to_markdown(
                                                        &exec, &rb.name,
                                                    );
                                                    eprintln!("{exec_md}");
                                                    if let Err(e) = notifier
                                                        .notify_text(&t.name, &exec_md)
                                                        .await
                                                    {
                                                        eprintln!(
                                                            "   Warning: runbook notification failed: {e}"
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!("   Runbook execution failed: {e}");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // --- End runbook matching ---
                    }
                }
            }
        }

        if once {
            break;
        }

        // Wait for the next interval OR a shutdown signal.
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)) => {}
            _ = shutdown_signal() => {
                eprintln!("Shutting down OpsClaw...");
                break;
            }
        }
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

    let notifier = make_notifier(config);

    let mut manager = EventStreamManager::new();

    for t in &targets {
        match t.target_type {
            TargetType::Local => {
                info!(
                    "Adding Docker + systemd event sources for local target '{}'",
                    t.name
                );
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

    // Read events from the channel until shutdown.
    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else { break };
                let line = event_stream::format_event(&event);
                println!("{line}");

                if let Some(alert_msg) = event_stream::event_to_alert(&event) {
                    tracing::warn!("ALERT: {alert_msg}");
                    let target_str = targets.first().map_or("unknown", |t| t.name.as_str());
                    let _ = notifier.notify_text(target_str, &alert_msg).await;
                }
            }
            _ = shutdown_signal() => {
                eprintln!("Shutting down OpsClaw...");
                break;
            }
        }
    }

    manager_handle.abort();
    Ok(())
}

// ---------------------------------------------------------------------------
// probe command
// ---------------------------------------------------------------------------

pub async fn handle_probe(
    config: &Config,
    target: Option<String>,
    all: bool,
    url: Option<String>,
) -> Result<()> {
    // Quick one-off HTTP probe
    if let Some(url) = url {
        let runner = crate::tools::ssh_command_runner::LocalCommandRunner::new(
            OpsClawAutonomy::DryRun,
            "local".to_string(),
        );
        let probe = zeroclaw::config::schema::ProbeConfig {
            name: "one-off-http".to_string(),
            probe_type: zeroclaw::config::schema::ProbeType::Http {
                url,
                expected_status: Some(200),
                timeout_secs: 10,
            },
        };
        let result = probes::run_probe(&runner, &probe).await?;
        print_probe_result(&result);
        return Ok(());
    }

    let targets = resolve_targets(config, target.as_deref(), all)?;

    for t in &targets {
        println!("--- Probes for target: {} ---", t.name);
        let runner = make_runner(t)?;

        // Gather configured + auto-discovered probes
        let configured = convert_probes(t.probes.as_deref().unwrap_or_default());
        let discovered = match snapshots::load_snapshot(&t.name)? {
            Some(snap) => probes::discover_probes(&snap, t.host.as_deref()),
            None => vec![],
        };

        if configured.is_empty() && discovered.is_empty() {
            println!("  No probes configured or discovered for '{}'", t.name);
            continue;
        }

        for probe in configured.iter().chain(discovered.iter()) {
            match probes::run_probe(runner.as_ref(), probe).await {
                Ok(result) => print_probe_result(&result),
                Err(e) => eprintln!("  [ERR] {}: {e}", probe.name),
            }
        }
    }

    Ok(())
}

fn print_probe_result(r: &probes::ProbeResult) {
    let icon = if r.success { "OK" } else { "FAIL" };
    println!(
        "  [{icon}] {name} ({ptype}): {msg}",
        name = r.probe_name,
        ptype = r.probe_type,
        msg = r.message,
    );
    if let Some(ref d) = r.details {
        if !d.is_empty() && !r.success {
            println!("        Details: {d}");
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Collect recent error/fatal logs from all discovered sources for LLM diagnosis context.
async fn collect_error_logs_for_diagnosis(
    runner: &dyn CommandRunner,
    snapshot: &discovery::TargetSnapshot,
) -> String {
    let sources = log_sources::discover_log_sources(snapshot);
    let mut error_lines = Vec::new();

    for source in &sources {
        match log_sources::collect_logs(runner, source, 50, None).await {
            Ok(entries) => {
                for entry in entries {
                    if matches!(entry.level, Some(LogLevel::Error) | Some(LogLevel::Fatal)) {
                        error_lines.push(log_sources::format_log_entry(&entry));
                    }
                }
            }
            Err(_) => {
                // Skip sources that fail (e.g. missing log files).
            }
        }
    }

    error_lines.join("\n")
}

/// Build a notifier from config. Returns `TelegramNotifier` if configured, `NullNotifier` otherwise.
fn make_notifier(config: &Config) -> Box<dyn AlertNotifier> {
    if let Some(notif_config) = config.notifications.as_ref() {
        if let (Some(token), Some(chat_id)) = (
            notif_config.telegram_bot_token.as_ref(),
            notif_config.telegram_chat_id.as_ref(),
        ) {
            let severity = parse_min_severity(&notif_config.min_severity);
            return Box::new(TelegramNotifier::new(
                token.clone(),
                chat_id.clone(),
                severity,
            ));
        }
    }
    Box::new(NullNotifier)
}

/// Create a [`MonitoringAgent`] from config, falling back to env vars.
fn make_monitoring_agent(config: &Config) -> Option<MonitoringAgent> {
    let api_key = config
        .diagnosis
        .api_key
        .clone()
        .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
        .filter(|k| !k.is_empty())?;
    let model = config
        .diagnosis
        .model
        .clone()
        .or_else(|| std::env::var("OPSCLAW_DIAGNOSIS_MODEL").ok())
        .unwrap_or_else(|| "claude-sonnet-4-20250514".to_string());
    Some(MonitoringAgent::new(model, api_key))
}

/// Format a Telegram-friendly diagnosis alert combining health summary and LLM assessment.
fn format_diagnosis_alert(hc: &HealthCheck, diag: &Diagnosis) -> String {
    let mut msg = format!("🔍 *Diagnosis* — {}\n", hc.target_name);
    msg.push_str(&format!("Severity: *{}*\n\n", diag.severity));
    msg.push_str(&diag.llm_assessment);
    if !diag.suggested_actions.is_empty() {
        msg.push_str("\n\n*Suggested actions:*\n");
        for action in &diag.suggested_actions {
            msg.push_str(&format!("• {action}\n"));
        }
    }
    msg.push_str(&format!("\nIncident: `{}`", diag.incident_id));
    msg
}

// ---------------------------------------------------------------------------
// baseline command
// ---------------------------------------------------------------------------

pub async fn handle_baseline(config: &Config, target: Option<String>, reset: bool) -> Result<()> {
    let targets = config.targets.as_deref().unwrap_or_default();

    if targets.is_empty() {
        bail!("No [[targets]] defined in config. Add at least one target.");
    }

    let selected: Vec<&TargetConfig> = if let Some(ref name) = target {
        let t = targets
            .iter()
            .find(|t| &t.name == name)
            .with_context(|| format!("Target '{name}' not found in config"))?;
        vec![t]
    } else {
        targets.iter().collect()
    };

    for t in &selected {
        let bl_path = baseline::baseline_path(&t.name)?;
        let mut store = BaselineStore::load(&bl_path)?;

        if reset {
            store.reset_target(&t.name);
            store.save()?;
            println!("Baseline data cleared for '{}'.", t.name);
        } else {
            let summary = store.summary(&t.name);
            println!("{summary}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// incidents command
// ---------------------------------------------------------------------------

pub fn handle_incidents(
    target: Option<String>,
    search_query: Option<String>,
    resolve_id: Option<String>,
    resolve_msg: Option<String>,
) -> Result<()> {
    // Resolve an incident.
    if let Some(id) = resolve_id {
        let resolution = resolve_msg.unwrap_or_else(|| "Resolved".to_string());
        let target_name = target
            .ok_or_else(|| anyhow::anyhow!("--target is required when resolving an incident"))?;
        crate::ops::incident_search::mark_resolved(&target_name, &id, &resolution)?;
        println!("Incident {id} marked as resolved.");
        return Ok(());
    }

    // Search by keyword.
    if let Some(query) = search_query {
        if let Some(ref name) = target {
            let index = IncidentIndex::load(name)?;
            let results = index.search_by_keyword(&query, 10);
            print_incidents(&results);
        } else {
            // Search across all target dirs.
            let results = search_all_targets(&query)?;
            print_incidents(&results.iter().collect::<Vec<_>>());
        }
        return Ok(());
    }

    // List recent incidents.
    if let Some(ref name) = target {
        let index = IncidentIndex::load(name)?;
        let all = index.incidents();
        let recent: Vec<_> = all.iter().rev().take(20).collect();
        print_incidents(&recent);
    } else {
        let all = load_all_targets()?;
        let recent: Vec<_> = all.iter().rev().take(20).collect();
        print_incidents(&recent.iter().copied().collect::<Vec<_>>());
    }

    Ok(())
}

fn print_incidents(incidents: &[&crate::ops::incident_search::IncidentRecord]) {
    if incidents.is_empty() {
        println!("No incidents found.");
        return;
    }

    for inc in incidents {
        let date = inc.timestamp.format("%Y-%m-%d %H:%M");
        let resolved = if inc.resolution.is_some() {
            " [resolved]"
        } else {
            ""
        };
        println!(
            "{} {} ({}){} — {}",
            inc.incident_id, inc.target_name, inc.severity, resolved, date
        );
        println!("  Symptoms: {}", inc.symptoms);
        println!("  Diagnosis: {}", truncate(&inc.llm_assessment, 120));
        if let Some(ref res) = inc.resolution {
            println!("  Resolution: {res}");
        }
        println!();
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        let end = s.char_indices().nth(max).map_or(s.len(), |(i, _)| i);
        &s[..end]
    }
}

fn load_all_targets() -> Result<Vec<crate::ops::incident_search::IncidentRecord>> {
    let home = directories::UserDirs::new()
        .map(|u| u.home_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let base = home.join(".opsclaw").join("incidents");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut all = Vec::new();
    for entry in std::fs::read_dir(&base)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let index = IncidentIndex::load_from_dir(&entry.path())?;
            all.extend(index.incidents().to_vec());
        }
    }
    all.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(all)
}

fn search_all_targets(query: &str) -> Result<Vec<crate::ops::incident_search::IncidentRecord>> {
    let home = directories::UserDirs::new()
        .map(|u| u.home_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let base = home.join(".opsclaw").join("incidents");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut all = Vec::new();
    for entry in std::fs::read_dir(&base)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let index = IncidentIndex::load_from_dir(&entry.path())?;
            let matches = index.search_by_keyword(query, 10);
            all.extend(matches.into_iter().cloned());
        }
    }
    Ok(all)
}

// ---------------------------------------------------------------------------
// runbook command
// ---------------------------------------------------------------------------

pub async fn handle_runbook(config: &Config, action: RunbookActions) -> Result<()> {
    let store = RunbookStore::new(RunbookStore::default_dir()?);

    match action {
        RunbookActions::List => {
            let runbooks = store.load_all()?;
            if runbooks.is_empty() {
                println!("No runbooks found. Run `opsclaw runbook init` to install defaults.");
                return Ok(());
            }
            println!(
                "{:<22} {:<25} {:<6} {}",
                "ID", "NAME", "RUNS", "DESCRIPTION"
            );
            println!("{}", "-".repeat(80));
            for rb in &runbooks {
                println!(
                    "{:<22} {:<25} {:<6} {}",
                    rb.id,
                    truncate(&rb.name, 24),
                    rb.execution_count,
                    truncate(&rb.description, 40)
                );
            }
        }
        RunbookActions::Show { id } => {
            let rb = store.load(&id)?;
            println!("Runbook: {} ({})", rb.name, rb.id);
            println!("Description: {}", rb.description);
            println!();
            println!("Trigger:");
            if !rb.trigger.alert_categories.is_empty() {
                println!("  Categories: {}", rb.trigger.alert_categories.join(", "));
            }
            if !rb.trigger.keywords.is_empty() {
                println!("  Keywords: {}", rb.trigger.keywords.join(", "));
            }
            if let Some(ref pat) = rb.trigger.target_pattern {
                println!("  Target pattern: {}", pat);
            }
            println!();
            println!("Steps:");
            for (i, step) in rb.steps.iter().enumerate() {
                println!("  {}. {}", i + 1, step.description);
                if let Some(ref cmd) = step.command {
                    println!("     Command: `{}`", cmd);
                }
                println!(
                    "     On failure: {:?}  Timeout: {}s",
                    step.on_failure, step.timeout_secs
                );
            }
            println!();
            println!(
                "Executions: {}  Success rate: {:.0}%",
                rb.execution_count,
                rb.success_rate * 100.0
            );
        }
        RunbookActions::Init => {
            let defaults = runbooks::default_runbooks();
            let mut count = 0;
            for rb in &defaults {
                store.save(rb)?;
                count += 1;
                println!("  Installed: {} ({})", rb.name, rb.id);
            }
            println!("{} default runbook(s) installed.", count);
        }
        RunbookActions::Run { id, target } => {
            let targets = config.targets.as_deref().unwrap_or_default();
            let t = targets
                .iter()
                .find(|t| t.name == target)
                .with_context(|| format!("Target '{}' not found in config", target))?;
            let runner = make_runner(t)?;
            let rb = store.load(&id)?;
            println!("Executing runbook '{}' on target '{}'...", rb.name, target);
            let exec = runbooks::execute_runbook(runner.as_ref(), &rb, &target, &[]).await?;
            let md = runbooks::execution_to_markdown(&exec, &rb.name);
            println!("{md}");
        }
    }

    Ok(())
}

pub async fn handle_sources(config: &Config, target: Option<String>, all: bool) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), all)?;

    for t in &targets {
        println!("━━ {} ━━", t.name);

        let ds_cfg = parse_data_sources_config(t);

        let runner: Option<Box<dyn CommandRunner>> = match make_runner(t) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!("could not create runner for {}: {e:#}", t.name);
                None
            }
        };

        let snap =
            crate::ops::data_sources::collect_all(&ds_cfg, runner.as_ref().map(|r| r.as_ref()))
                .await;

        crate::ops::data_sources::print_summary(&snap);
        println!();
    }

    Ok(())
}

/// Parse the opaque `data_sources` JSON value from a target into our typed config.
fn parse_data_sources_config(target: &TargetConfig) -> crate::ops::data_sources::DataSourcesConfig {
    target
        .data_sources
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
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

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

/// Wait for SIGINT (Ctrl+C) or SIGTERM (Unix only).
async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("SIGTERM listener");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
