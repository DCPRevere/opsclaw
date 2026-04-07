//! OpsClaw CLI command handlers: scan, monitor, watch.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use tokio::signal;
use tracing::info;

use crate::ops_config::{ProjectConfig, ProjectType};

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
        /// Project name (from config [[projects]])
        #[arg(long)]
        target: String,
    },
}

// Re-import from the same crate tree the binary uses — discovery/monitoring
// types are fine because they don't reference Config.
use crate::ops::baseline::{self, anomalies_to_alerts, extract_metrics, BaselineStore};
use crate::ops::diagnosis::{Diagnosis, MonitoringAgent};
use crate::ops::digest::{DigestReport, ProjectInput};
use crate::ops::escalation::{
    format_escalation_message, EscalationAction, EscalationManager, EscalationPolicy,
};
use crate::ops::event_stream::{self, EventStreamManager};
use crate::ops::incident_search::IncidentIndex;
use crate::ops::log_sources::{self, LogLevel, LogSourceType};
use crate::ops::notifier::{AlertNotifier, NullNotifier, TelegramNotifier, WebhookNotifier};
use crate::ops::runbooks::{self, RunbookStore};
use crate::ops::{monitor_log, probes, snapshots};
use crate::tools::discovery::{self, CommandRunner, TargetSnapshot};
use crate::tools::kube_tool::KubeClient;
use crate::tools::monitoring::{self, HealthCheck};
use crate::tools::ssh_command_runner::{DryRunCommandRunner, LocalCommandRunner, SshCommandRunner};
use crate::tools::ssh_tool::{RealSshExecutor, ProjectEntry};
use crate::ops_config::{parse_min_severity, OpsClawAutonomy, OpsConfig};

// ---------------------------------------------------------------------------
// Runner factory
// ---------------------------------------------------------------------------

/// Build a [`CommandRunner`] for a project config, decrypting secrets as needed.
///
/// In `DryRun` mode the runner is wrapped with [`DryRunCommandRunner`] so that
/// write commands are logged instead of executed.
fn make_runner(config: &OpsConfig, project: &ProjectConfig) -> Result<Box<dyn CommandRunner>> {
    let runner: Box<dyn CommandRunner> = match project.project_type {
        ProjectType::Local => Box::new(LocalCommandRunner::new(project.autonomy, project.name.clone())),
        ProjectType::Kubernetes => {
            bail!("Kubernetes projects use the kube API client, not a command runner");
        }
        ProjectType::Ssh => {
            let host = project.host.clone().unwrap_or_default();
            let user = project.user.clone().unwrap_or_default();
            let port = project.port.unwrap_or(22);

            let raw_key = project
                .key_secret
                .as_deref()
                .context("SSH project requires key_secret (encrypted PEM in config)")?;
            let key_pem = config.decrypt_secret(raw_key)
                .context("Failed to decrypt SSH private key")?;

            let entry = ProjectEntry {
                name: project.name.clone(),
                host,
                port,
                user,
                private_key_pem: key_pem,
                autonomy: project.autonomy,
            };

            Box::new(SshCommandRunner::new(entry, Box::new(RealSshExecutor)))
        }
    };

    match project.autonomy {
        OpsClawAutonomy::DryRun => {
            let opsclaw_dir = opsclaw_dir()?;
            let dry_run_log = opsclaw_dir.join("dry-run.log");
            Ok(Box::new(DryRunCommandRunner::new(runner, dry_run_log)))
        }
        // Approve / Auto: pass through (approval gate is at a higher level).
        OpsClawAutonomy::Approve
        | OpsClawAutonomy::Auto => Ok(runner),
    }
}

/// Return the `~/.opsclaw` directory path.
fn opsclaw_dir() -> Result<std::path::PathBuf> {
    let home = directories::UserDirs::new()
        .map(|u| u.home_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    Ok(home.join(".opsclaw"))
}

/// Run a discovery scan for a project, using the kube API for Kubernetes
/// projects and a [`CommandRunner`] for everything else.
async fn scan_target(config: &OpsConfig, project: &ProjectConfig) -> Result<TargetSnapshot> {
    if project.project_type == ProjectType::Kubernetes {
        let kube = KubeClient::new(project.kubeconfig.as_deref()).await?;
        return kube.discover_snapshot().await;
    }
    let runner = make_runner(config, project)?;
    discovery::run_discovery_scan(runner.as_ref()).await
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
// context edit command
// ---------------------------------------------------------------------------

const CONTEXT_TEMPLATE: &str = "\
# Project Context

Describe this project so OpsClaw understands how to operate it.

## Services
- (list key services running on this project)

## Notes
- (anything OpsClaw should know when diagnosing or remediating issues)
";

/// Open a project's context file in `$EDITOR` for editing.
pub async fn handle_context_edit(config: &OpsConfig, target: &str) -> Result<()> {
    // Validate the project exists in config.
    let project_cfg = config
        .projects
        .as_ref()
        .and_then(|projects| projects.iter().find(|t| t.name == target))
        .with_context(|| format!("project '{}' not found in config", target))?;

    // Resolve the context file path.
    let tilde_path = project_cfg
        .context_file
        .clone()
        .unwrap_or_else(|| format!("~/.opsclaw/context/{}.md", target));
    let abs_path = PathBuf::from(expand_tilde(&tilde_path));

    // Create file with template if it does not exist.
    if !abs_path.exists() {
        if let Some(parent) = abs_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create directory: {}", parent.display()))?;
        }
        fs::write(&abs_path, CONTEXT_TEMPLATE)
            .with_context(|| format!("cannot write context file: {}", abs_path.display()))?;
        println!("Created new context file: {}", abs_path.display());
    }

    // Determine editor.
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| {
            // Prefer nano, fall back to vi.
            if which::which("nano").is_ok() {
                "nano".to_string()
            } else {
                "vi".to_string()
            }
        });

    // Open editor.
    let status = tokio::process::Command::new(&editor)
        .arg(&abs_path)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("failed to launch editor '{}'", editor))?;

    if !status.success() {
        bail!("editor '{}' exited with {}", editor, status);
    }

    // Read back and confirm.
    let content = fs::read_to_string(&abs_path)
        .with_context(|| format!("failed to read context file: {}", abs_path.display()))?;
    let line_count = content.lines().count();
    println!(
        "Context file saved: {} ({} lines)",
        abs_path.display(),
        line_count
    );

    Ok(())
}

pub fn handle_context_print(config: &OpsConfig, target: &str) -> Result<()> {
    let project_cfg = config
        .projects
        .as_ref()
        .and_then(|projects| projects.iter().find(|t| t.name == target))
        .with_context(|| format!("project '{}' not found in config", target))?;

    let tilde_path = project_cfg
        .context_file
        .clone()
        .unwrap_or_else(|| format!("~/.opsclaw/context/{}.md", target));
    let abs_path = PathBuf::from(expand_tilde(&tilde_path));

    if !abs_path.exists() {
        println!("No context file for '{}'. Run `project context edit {}` to create one.", target, target);
        return Ok(());
    }

    let content = fs::read_to_string(&abs_path)
        .with_context(|| format!("failed to read context file: {}", abs_path.display()))?;
    print!("{content}");
    Ok(())
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
        println!("No dry-run log yet. Set a project's autonomy to 'dry-run' and run a scan or monitor cycle.");
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

pub async fn handle_scan(config: &OpsConfig, target: Option<String>, all: bool) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), all)?;

    for t in &targets {
        info!("Scanning project: {}", t.name);
        let snapshot = scan_target(config, t)
            .await
            .with_context(|| format!("Scan failed for project '{}'", t.name))?;

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
    config: &OpsConfig,
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
        // Try loading an existing snapshot; fall back to a fresh scan.
        let snapshot = match snapshots::load_snapshot(&t.name)? {
            Some(snap) => snap,
            None => {
                info!("No snapshot for '{}', running discovery scan…", t.name);
                let snap = scan_target(config, t).await?;
                snapshots::save_snapshot(&t.name, &snap)?;
                snap
            }
        };
        let runner = match make_runner(config, t) {
            Ok(r) => r,
            Err(_) if t.project_type == ProjectType::Kubernetes => {
                info!("Kubernetes project '{}': use `opsclaw logs` with kube API (skipping shell-based log collection)", t.name);
                continue;
            }
            Err(e) => return Err(e),
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
    config: &OpsConfig,
    target: Option<String>,
    interval_secs: u64,
    once: bool,
    openshell_ctx: &crate::openshell::OpenShellContext,
) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), target.is_none())?;

    if targets.is_empty() {
        bail!("No projects configured. Add [[projects]] to your config.");
    }

    let notifier = make_notifier(config);
    let mut failure_counts: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();

    // Initialise escalation managers for targets that have an escalation policy.
    let mut escalation_managers: std::collections::HashMap<String, EscalationManager> =
        std::collections::HashMap::new();
    for t in &targets {
        if let Some(policy) = parse_escalation_policy(t) {
            let store_path = escalation_store_path(&t.name)?;
            let mgr = if store_path.exists() {
                match EscalationManager::load(&store_path) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!(
                            "   Warning: failed to load escalation state for '{}': {e}",
                            t.name
                        );
                        EscalationManager::new(policy, store_path)
                    }
                }
            } else {
                EscalationManager::new(policy, store_path)
            };
            escalation_managers.insert(t.name.clone(), mgr);
        }
    }

    loop {
        for t in &targets {
            // Build a command runner for projects that support it (SSH/local).
            // Kubernetes projects use the kube API for scanning, so runner is None.
            let runner: Option<Box<dyn CommandRunner>> = match make_runner(config, t) {
                Ok(r) => Some(r),
                Err(_) if t.project_type == ProjectType::Kubernetes => None,
                Err(e) => return Err(e),
            };

            let current = match scan_target(config, t).await {
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
                            "\u{26a0}\u{fe0f} Cannot reach project '{}' \u{2014} {} consecutive scan failures. Last error: {}",
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
                    let configured_probes = t.probes.clone().unwrap_or_default();
                    let discovered = probes::discover_probes(&current, t.host.as_deref());

                    let mut probe_results = Vec::new();
                    for probe in configured_probes.iter().chain(discovered.iter()) {
                        let Some(ref runner) = runner else { continue };
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
                        let error_log_context = if let Some(ref r) = runner {
                            collect_error_logs_for_diagnosis(r.as_ref(), &current).await
                        } else {
                            String::new()
                        };

                        // Collect git deploy correlation context.
                        let deploy_context = if let Some(ref r) = runner {
                            let ds_cfg = t.data_sources.clone().unwrap_or_default();
                            collect_deploy_context(r.as_ref(), &ds_cfg).await
                        } else {
                            String::new()
                        };

                        // Fetch all configured data sources for diagnosis enrichment.
                        let ds_snapshot = crate::ops::data_sources::fetch_all(
                            t,
                            runner.as_ref().map(|r| r.as_ref()),
                        )
                        .await;
                        let ds_context =
                            crate::ops::data_sources::format_for_diagnosis(&ds_snapshot);

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

                            // Append deploy correlation context for the LLM.
                            if !deploy_context.is_empty() {
                                let combined = context_content.unwrap_or_default();
                                context_content = Some(format!("{combined}\n\n{deploy_context}"));
                            }

                            // Append external data sources context for the LLM.
                            if !ds_context.is_empty() {
                                let combined = context_content.unwrap_or_default();
                                context_content = Some(format!("{combined}\n\n{ds_context}"));
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

                        // --- Runbook matching (requires a command runner) ---
                        if let Some(runner) = &runner {
                            if let Ok(store) = RunbookStore::default_dir().map(RunbookStore::new)
                        {
                            if let Ok(matched) = store.match_alerts(&hc.alerts, &t.name) {
                                for rb in &matched {
                                    match t.autonomy {
                                        OpsClawAutonomy::DryRun => {
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
                                        OpsClawAutonomy::Approve => {
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
                                                openshell_ctx,
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
                                        OpsClawAutonomy::Auto => {
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
                        } else {
                            tracing::info!(
                                "Skipping runbook execution for Kubernetes project '{}'",
                                t.name
                            );
                        }
                        // --- End runbook matching ---

                        // --- Escalation: create for unhealthy targets ---
                        if let Some(mgr) = escalation_managers.get_mut(&t.name) {
                            let alert_summary: Vec<String> =
                                hc.alerts.iter().map(|a| a.message.clone()).collect();
                            let diagnosis_text = alert_summary.join("; ");
                            let incident_id = format!(
                                "{}-{}",
                                t.name,
                                chrono::Utc::now().format("%Y%m%dT%H%M%S")
                            );
                            mgr.create(&incident_id, &t.name, &diagnosis_text, &alert_summary);

                            // Send initial notification to the first contact.
                            let actions = mgr.check_timeouts(chrono::Utc::now());
                            for action in actions {
                                process_escalation_action(notifier.as_ref(), mgr, action).await;
                            }
                            if let Err(e) = mgr.save() {
                                eprintln!("   Warning: failed to save escalation state: {e}");
                            }
                        }
                        // --- End escalation ---
                    }
                }
            }
        }

        // --- Escalation: check timeouts for all managers ---
        for (target_name, mgr) in &mut escalation_managers {
            let actions = mgr.check_timeouts(chrono::Utc::now());
            if !actions.is_empty() {
                for action in actions {
                    process_escalation_action(notifier.as_ref(), mgr, action).await;
                }
                if let Err(e) = mgr.save() {
                    eprintln!(
                        "   Warning: failed to save escalation state for '{target_name}': {e}"
                    );
                }
            }
        }

        if once {
            break;
        }

        // Wait for the next interval OR a shutdown signal.
        tokio::select! {
            () = tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)) => {}
            () = shutdown_signal() => {
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

pub async fn handle_watch(
    config: &OpsConfig,
    target: Option<String>,
) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), target.is_none())?;

    if targets.is_empty() {
        bail!("No projects configured. Add [[projects]] to your config.");
    }

    let notifier = make_notifier(config);

    let mut manager = EventStreamManager::new();

    // Temp key files cleaned up when the watch session ends.
    let mut ssh_key_paths: Vec<PathBuf> = Vec::new();

    for t in &targets {
        match t.project_type {
            ProjectType::Local => {
                info!(
                    "Adding Docker + systemd event sources for local project '{}'",
                    t.name
                );
                manager.add_docker_source();
                manager.add_systemd_source();
            }
            ProjectType::Ssh => {
                let host = t
                    .host
                    .as_deref()
                    .context(format!("SSH project '{}' missing host", t.name))?;
                let user = t
                    .user
                    .as_deref()
                    .context(format!("SSH project '{}' missing user", t.name))?;
                let raw_pem = t
                    .key_secret
                    .as_deref()
                    .context(format!("SSH project '{}' missing key_secret", t.name))?;
                let pem = config.decrypt_secret(raw_pem)
                    .context("Failed to decrypt SSH private key")?;
                let port = t.port.unwrap_or(22);

                // Write the PEM to a temp file so `ssh -i` can use it.
                let key_path = std::env::temp_dir().join(format!(
                    "opsclaw-watch-key-{}-{}",
                    t.name,
                    std::process::id()
                ));
                {
                    let mut f = fs::File::create(&key_path)
                        .context("failed to create temp file for SSH key")?;
                    f.write_all(pem.as_bytes())?;
                    f.flush()?;
                }

                // Restrict permissions (ssh refuses keys with open perms).
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
                }

                let key_path_str = key_path.to_string_lossy().to_string();
                ssh_key_paths.push(key_path);

                info!(
                    "Adding SSH event sources for project '{}' ({}@{}:{})",
                    t.name, user, host, port
                );
                manager.add_ssh_source(
                    host.to_string(),
                    user.to_string(),
                    key_path_str,
                    port,
                    t.name.clone(),
                );
            }
            ProjectType::Kubernetes => {
                info!("Adding Kubernetes event source for project '{}'", t.name);
                // Kubernetes events are polled via the kube API at each
                // monitor interval rather than streamed here.  Log intent
                // so operators see the target was recognised.
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
                    let source = event.source_name();
                    let _ = notifier.notify_text(source, &alert_msg).await;
                }
            }
            () = shutdown_signal() => {
                eprintln!("Shutting down OpsClaw...");
                break;
            }
        }
    }

    manager_handle.abort();

    // Clean up temp SSH key files.
    for path in &ssh_key_paths {
        let _ = fs::remove_file(path);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// probe command
// ---------------------------------------------------------------------------

pub async fn handle_probe(
    config: &OpsConfig,
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
        let probe = crate::ops_config::ProbeConfig {
            name: "one-off-http".to_string(),
            probe_type: crate::ops_config::ProbeType::Http {
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
        println!("--- Probes for project: {} ---", t.name);
        let runner = make_runner(config, t)?;

        // Gather configured + auto-discovered probes
        let configured = t.probes.clone().unwrap_or_default();
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
                    if matches!(entry.level, Some(LogLevel::Error | LogLevel::Fatal)) {
                        error_lines.push(log_sources::format_log_entry(&entry));
                    }
                }
            }
            Err(e) => {
                tracing::debug!(source = ?source, error = %e, "Skipping log source");
            }
        }
    }

    error_lines.join("\n")
}

/// Collect git deploy correlation context for LLM diagnosis.
async fn collect_deploy_context(
    runner: &dyn CommandRunner,
    ds_cfg: &crate::ops::data_sources::DataSourcesConfig,
) -> String {
    let paths = match &ds_cfg.git_paths {
        Some(p) if !p.is_empty() => p,
        _ => return String::new(),
    };

    // Fetch docker deploy timestamps if containers are configured.
    let docker_deploys = if let Some(containers) = &ds_cfg.docker_containers {
        crate::ops::data_sources::docker_inspect::fetch_start_times(runner, containers)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    match crate::ops::data_sources::git_deploy::fetch_git_deploy_snapshot(
        runner,
        paths,
        &docker_deploys,
        None,
    )
    .await
    {
        Ok(snap) => crate::ops::data_sources::git_deploy::format_as_markdown(&snap, 24),
        Err(e) => {
            tracing::warn!("git deploy context failed: {e:#}");
            String::new()
        }
    }
}

/// Build a notifier from config. Returns `TelegramNotifier` if configured, `NullNotifier` otherwise.
fn make_notifier(config: &OpsConfig) -> Box<dyn AlertNotifier> {
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
        if let Some(url) = notif_config.webhook_url.as_ref() {
            if !url.is_empty() {
                let severity = parse_min_severity(&notif_config.min_severity);
                return Box::new(WebhookNotifier::new(
                    url.clone(),
                    notif_config.webhook_bearer_token.clone(),
                    severity,
                ));
            }
        }
    }
    Box::new(NullNotifier)
}

/// Create a [`MonitoringAgent`] from config, falling back to env vars.
fn make_monitoring_agent(config: &OpsConfig) -> Option<MonitoringAgent> {
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
    let _ = write!(msg, "Severity: *{}*\n\n", diag.severity);
    msg.push_str(&diag.llm_assessment);
    if !diag.suggested_actions.is_empty() {
        msg.push_str("\n\n*Suggested actions:*\n");
        for action in &diag.suggested_actions {
            let _ = writeln!(msg, "• {action}");
        }
    }
    let _ = write!(msg, "\nIncident: `{}`", diag.incident_id);
    msg
}

// ---------------------------------------------------------------------------
// baseline command
// ---------------------------------------------------------------------------

pub fn handle_baseline(config: &OpsConfig, target: Option<&str>, reset: bool) -> Result<()> {
    let targets = config.projects.as_deref().unwrap_or_default();

    if targets.is_empty() {
        bail!("No [[projects]] defined in config. Add at least one project.");
    }

    let selected: Vec<&ProjectConfig> = if let Some(name) = target {
        let t = targets
            .iter()
            .find(|t| t.name == name)
            .with_context(|| format!("Project '{name}' not found in config"))?;
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
        print_incidents(&recent.to_vec());
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
// postmortem command
// ---------------------------------------------------------------------------

pub fn handle_postmortem(incident_id: &str, output: Option<&std::path::Path>) -> Result<()> {
    use crate::ops::postmortem::PostMortem;

    let all = load_all_targets()?;
    let incident = all
        .iter()
        .find(|inc| inc.incident_id == incident_id)
        .ok_or_else(|| anyhow::anyhow!("Incident '{incident_id}' not found"))?;

    let pm = PostMortem::generate(incident, &[]);
    let md = pm.to_markdown();

    if let Some(path) = output {
        std::fs::write(path, &md)
            .with_context(|| format!("Failed to write to {}", path.display()))?;
        println!("Post-mortem written to {}", path.display());
    } else {
        print!("{md}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// runbook command
// ---------------------------------------------------------------------------

pub async fn handle_runbook(config: &OpsConfig, action: RunbookActions) -> Result<()> {
    let store = RunbookStore::new(RunbookStore::default_dir()?);

    match action {
        RunbookActions::List => {
            let runbooks = store.load_all()?;
            if runbooks.is_empty() {
                println!("No runbooks found. Run `opsclaw runbook init` to install defaults.");
                return Ok(());
            }
            println!(
                "{:<22} {:<25} {:<6} DESCRIPTION",
                "ID", "NAME", "RUNS"
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
            let targets = config.projects.as_deref().unwrap_or_default();
            let t = targets
                .iter()
                .find(|t| t.name == target)
                .with_context(|| format!("Project '{}' not found in config", target))?;
            let runner = make_runner(config, t)?;
            let rb = store.load(&id)?;
            println!("Executing runbook '{}' on project '{}'...", rb.name, target);
            let exec = runbooks::execute_runbook(runner.as_ref(), &rb, &target, &[]).await?;
            let md = runbooks::execution_to_markdown(&exec, &rb.name);
            println!("{md}");
        }
    }

    Ok(())
}

pub async fn handle_sources(config: &OpsConfig, target: Option<String>, all: bool) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), all)?;

    for t in &targets {
        println!("━━ {} ━━", t.name);

        let ds_cfg = t.data_sources.clone().unwrap_or_default();

        let runner: Option<Box<dyn CommandRunner>> = match make_runner(config, t) {
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

/// Process a single [`EscalationAction`] by sending the appropriate notification.
async fn process_escalation_action(
    notifier: &dyn AlertNotifier,
    mgr: &mut EscalationManager,
    action: EscalationAction,
) {
    match action {
        EscalationAction::NotifyContact {
            ref escalation_id,
            ref contact,
            ref message,
        } => {
            eprintln!(
                "   Escalation: notifying {} via {}",
                contact.name, contact.channel
            );
            if let Err(e) = notifier.notify_text(&contact.name, message).await {
                eprintln!("   Warning: escalation notification failed: {e}");
            }
            let _ = mgr.record_notification(escalation_id, &contact.name, &contact.channel, None);
        }
        EscalationAction::EscalateToNext {
            ref escalation_id,
            ref next_contact,
        } => {
            eprintln!(
                "   Escalation: escalating to {} via {}",
                next_contact.name, next_contact.channel
            );
            // Build message from the escalation record.
            if let Some(esc) = mgr.get(escalation_id) {
                let msg = format_escalation_message(esc, std::slice::from_ref(next_contact), false);
                if let Err(e) = notifier.notify_text(&next_contact.name, &msg).await {
                    eprintln!("   Warning: escalation notification failed: {e}");
                }
            }
            let _ = mgr.record_notification(
                escalation_id,
                &next_contact.name,
                &next_contact.channel,
                None,
            );
        }
        EscalationAction::Expired { ref escalation_id } => {
            eprintln!("   Escalation {escalation_id}: all contacts exhausted, marking expired");
        }
    }
}

/// Parse the opaque `escalation` JSON value from a project into an [`EscalationPolicy`].
fn parse_escalation_policy(target: &ProjectConfig) -> Option<EscalationPolicy> {
    target
        .escalation
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .filter(|p: &EscalationPolicy| !p.contacts.is_empty())
}

/// Return the path where escalation state is persisted for a target.
fn escalation_store_path(target_name: &str) -> Result<std::path::PathBuf> {
    let dir = opsclaw_dir()?.join("escalations");
    Ok(dir.join(format!("{target_name}.json")))
}


// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

pub async fn handle_digest(
    config: &OpsConfig,
    target: Option<String>,
    hours: u32,
    notify: bool,
) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), true)?;

    let mut inputs: Vec<ProjectInput> = Vec::new();

    for t in &targets {
        // Incidents
        let incidents = match IncidentIndex::load(&t.name) {
            Ok(index) => index.incidents().to_vec(),
            Err(e) => {
                tracing::warn!("digest: failed to load incidents for {}: {e:#}", t.name);
                Vec::new()
            }
        };

        // Baseline anomalies
        let anomalies = match baseline::baseline_path(&t.name) {
            Ok(bl_path) => match BaselineStore::load(&bl_path) {
                Ok(store) => {
                    // Run a quick discovery to get current metrics for anomaly check
                    let snapshot = scan_target(config, t).await?;
                    let metrics = extract_metrics(&snapshot);
                    store.check_anomalies(&t.name, &metrics, 3.0)
                }
                Err(e) => {
                    tracing::warn!("digest: failed to load baseline for {}: {e:#}", t.name);
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!("digest: failed to resolve baseline path for {}: {e:#}", t.name);
                Vec::new()
            }
        };

        // Derive health status from incidents and anomalies
        let health = if incidents
            .iter()
            .any(|i| i.severity == "critical" && i.resolution.is_none())
        {
            monitoring::HealthStatus::Critical
        } else if !anomalies.is_empty() || incidents.iter().any(|i| i.resolution.is_none()) {
            monitoring::HealthStatus::Warning
        } else {
            monitoring::HealthStatus::Healthy
        };

        // Collect alert strings from recent anomalies
        let alerts: Vec<String> = anomalies.iter().map(|a| a.message.clone()).collect();

        inputs.push(ProjectInput {
            name: t.name.clone(),
            health_status: health,
            incidents,
            alerts,
            baseline_anomalies: anomalies,
            probe_failures: 0,
        });
    }

    let report = DigestReport::generate(inputs, hours);
    println!("{}", report.to_markdown());

    if notify {
        let notifier = make_notifier(config);
        let summary = report.to_short_summary();
        notifier.notify_text("digest", &summary).await?;
        println!("Digest sent via notifier.");
    }

    Ok(())
}

fn resolve_targets<'a>(
    config: &'a OpsConfig,
    target_name: Option<&str>,
    all: bool,
) -> Result<Vec<&'a ProjectConfig>> {
    let projects = config.projects.as_deref().unwrap_or_default();

    if projects.is_empty() {
        bail!("No [[projects]] defined in config. Add at least one project.");
    }

    if let Some(name) = target_name {
        let t = projects
            .iter()
            .find(|t| t.name == name)
            .with_context(|| format!("Project '{name}' not found in config"))?;
        Ok(vec![t])
    } else if all {
        Ok(projects.iter().collect())
    } else {
        bail!("Specify a project name or use --all");
    }
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// infra setup-user
// ---------------------------------------------------------------------------

/// Provision a restricted `opsclaw` SSH service account on a remote project.
///
/// Connects to the project as the currently configured user, creates the
/// `opsclaw` user, generates a local ed25519 keypair, uploads the public
/// key, and configures a minimal sudoers policy.
pub async fn handle_infra_setup_user(config: &OpsConfig, target_name: &str) -> Result<()> {
    let projects = config.projects.as_deref().unwrap_or_default();
    let target = projects
        .iter()
        .find(|t| t.name == target_name)
        .with_context(|| format!("Project '{target_name}' not found in config"))?;

    if target.project_type != ProjectType::Ssh {
        bail!("infra setup-user only works on SSH projects (project '{target_name}' is {:?})", target.project_type);
    }

    // Build a runner that bypasses dry-run (this is an explicit admin action).
    let runner = make_runner_for_setup(config, target)?;

    println!("Connecting to {target_name}…");

    // 1. Create the opsclaw user (skip if it already exists).
    println!("  Creating user 'opsclaw'…");
    let out = runner
        .run("id -u opsclaw >/dev/null 2>&1 || useradd -m -s /bin/bash opsclaw")
        .await?;
    if !out.stderr.is_empty() {
        info!("useradd stderr: {}", out.stderr.trim());
    }

    // 2. Ensure .ssh directory exists with correct permissions.
    println!("  Setting up /home/opsclaw/.ssh…");
    runner
        .run("mkdir -p /home/opsclaw/.ssh && chmod 700 /home/opsclaw/.ssh")
        .await?;

    // 3. Generate a local ed25519 keypair.
    let keys_dir = opsclaw_dir()?.join("keys");
    fs::create_dir_all(&keys_dir)
        .with_context(|| format!("failed to create {}", keys_dir.display()))?;

    let key_stem = format!("{target_name}_opsclaw_ed25519");
    let private_key_path = keys_dir.join(&key_stem);
    let public_key_path = keys_dir.join(format!("{key_stem}.pub"));

    if private_key_path.exists() {
        println!("  Keypair already exists at {}", private_key_path.display());
    } else {
        println!("  Generating ed25519 keypair…");
        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-t", "ed25519",
                "-f", &private_key_path.to_string_lossy(),
                "-N", "",
                "-C", &format!("opsclaw@{target_name}"),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .context("failed to run ssh-keygen")?;
        if !status.success() {
            bail!("ssh-keygen exited with status {status}");
        }
    }

    // 4. Upload the public key.
    let pubkey = fs::read_to_string(&public_key_path)
        .with_context(|| format!("failed to read {}", public_key_path.display()))?;
    let pubkey = pubkey.trim();

    println!("  Uploading public key…");
    // Append if not already present, then fix ownership.
    let escaped_pubkey = pubkey.replace('\'', "'\\''");
    let upload_cmd = format!(
        "grep -qF '{escaped_pubkey}' /home/opsclaw/.ssh/authorized_keys 2>/dev/null \
         || echo '{escaped_pubkey}' >> /home/opsclaw/.ssh/authorized_keys"
    );
    runner.run(&upload_cmd).await?;

    // 5. Set permissions.
    println!("  Setting permissions…");
    runner
        .run("chown -R opsclaw:opsclaw /home/opsclaw/.ssh && chmod 600 /home/opsclaw/.ssh/authorized_keys")
        .await?;

    // 6. Add sudoers rule.
    println!("  Configuring sudoers…");
    runner
        .run(
            "echo 'opsclaw ALL=(ALL) NOPASSWD: /usr/bin/docker, /bin/journalctl, /bin/systemctl status *' \
             > /etc/sudoers.d/opsclaw && chmod 440 /etc/sudoers.d/opsclaw",
        )
        .await?;

    println!();
    println!("Done! The opsclaw service account is ready on '{target_name}'.");
    println!();
    println!("Private key: {}", private_key_path.display());
    println!();
    println!("Update your project config to use the new account:");
    println!("  [[projects]]");
    println!("  name = \"{target_name}\"");
    println!("  user = \"opsclaw\"");
    println!(
        "  key_file = \"~/.opsclaw/keys/{key_stem}\""
    );

    Ok(())
}

/// Build an [`SshCommandRunner`] for infra provisioning.
///
/// Uses `Auto` autonomy so that write commands are not blocked — this is an
/// explicit administrator action, not an autonomous agent decision.
fn make_runner_for_setup(config: &OpsConfig, target: &ProjectConfig) -> Result<Box<dyn CommandRunner>> {
    let host = target.host.clone().unwrap_or_default();
    let user = target.user.clone().unwrap_or_default();
    let port = target.port.unwrap_or(22);

    let raw_key = target
        .key_secret
        .as_deref()
        .context("SSH project requires key_secret (encrypted PEM in config)")?;
    let key_pem = config.decrypt_secret(raw_key)
        .context("Failed to decrypt SSH private key")?;

    let entry = ProjectEntry {
        name: target.name.clone(),
        host,
        port,
        user,
        private_key_pem: key_pem,
        autonomy: OpsClawAutonomy::Auto,
    };

    Ok(Box::new(SshCommandRunner::new(
        entry,
        Box::new(RealSshExecutor),
    )))
}

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

// ---------------------------------------------------------------------------
// SkillForge
// ---------------------------------------------------------------------------

pub async fn handle_skills_forge(config: &OpsConfig, dry_run: bool) -> Result<()> {
    use crate::skillforge::{SkillForge, SkillForgeConfig};
    use crate::skillforge::evaluate::Recommendation;

    let mut forge_cfg = SkillForgeConfig::default();
    // Enable the pipeline for this CLI-driven run.
    forge_cfg.enabled = true;
    // In dry-run mode, disable auto-integration so nothing is written.
    if dry_run {
        forge_cfg.auto_integrate = false;
    }
    // Resolve output directory relative to the workspace.
    forge_cfg.output_dir = config
        .workspace_dir
        .join("skills")
        .to_string_lossy()
        .into_owned();

    let forge = SkillForge::new(forge_cfg);
    let report = forge.forge().await?;

    println!("SkillForge discovery complete");
    println!("  Discovered : {}", report.discovered);
    println!("  Evaluated  : {}", report.evaluated);
    if dry_run {
        println!("  (dry-run — no skills were integrated)");
    } else {
        println!("  Integrated : {}", report.auto_integrated);
    }
    println!("  Review     : {}", report.manual_review);
    println!("  Skipped    : {}", report.skipped);

    if !report.results.is_empty() {
        println!();
        for res in &report.results {
            let tag = match res.recommendation {
                Recommendation::Auto => "AUTO",
                Recommendation::Manual => "REVIEW",
                Recommendation::Skip => "SKIP",
            };
            println!(
                "  [{tag:^6}] {} (score: {:.2}) — {}",
                res.candidate.name, res.total_score, res.candidate.url,
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// project commands
// ---------------------------------------------------------------------------

/// Interactive wizard to add a new project (target) to the config.
pub async fn handle_project_add(_config: &OpsConfig) -> Result<()> {
    use crate::ops::setup::{
        load_existing_config, opsclaw_config_path, step_autonomy, step_data_sources,
        step_discovery_scan, step_kubernetes_project, step_local_project, step_ssh_project,
        step_project_context, step_project_type,
    };
    use console::style;
    use crate::ops_config::ProjectType;

    println!();
    println!("  {}", style("Add Project").cyan().bold());
    println!(
        "  {}",
        style("Configure a new project for OpsClaw to monitor.").dim()
    );

    let project_type = step_project_type()?;
    let mut project_result = match project_type {
        ProjectType::Ssh => step_ssh_project().await?,
        ProjectType::Local => step_local_project()?,
        ProjectType::Kubernetes => step_kubernetes_project()?,
    };

    project_result.config.context_file = step_project_context(&project_result.config.name)?;
    project_result.config.autonomy = step_autonomy()?;

    if let Some(ref runner) = project_result.runner {
        step_discovery_scan(&project_result.config.name, runner.as_ref()).await;
    } else {
        println!("  Skipping shell-based discovery scan (Kubernetes projects use the kube API).");
    }

    project_result.config.data_sources = step_data_sources()?;

    let config_path = opsclaw_config_path()?;
    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut cfg = load_existing_config(&config_path);
    cfg.config_path = config_path.clone();

    let projects = cfg.projects.get_or_insert_with(Vec::new);
    let name = project_result.config.name.clone();
    if let Some(pos) = projects.iter().position(|t| t.name == name) {
        projects[pos] = project_result.config;
    } else {
        projects.push(project_result.config);
    }

    cfg.save().await?;

    println!();
    println!(
        "  {} Project '{}' added and saved to {}",
        style("✓").green().bold(),
        name,
        style(config_path.display()).underlined()
    );
    println!(
        "  {}",
        style("Run 'opsclaw monitor --all' to start monitoring.").dim()
    );
    println!();

    Ok(())
}

/// List all configured projects.
pub fn handle_project_show(config: &OpsConfig, name: &str) -> Result<()> {
    use console::style;

    let project = config
        .projects
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|p| p.name == name)
        .with_context(|| format!("Project '{}' not found", name))?;

    println!();
    println!("  {}", style(&project.name).white().bold());
    println!(
        "  {} type: {}",
        style("›").cyan(),
        format!("{:?}", project.project_type).to_lowercase()
    );
    println!(
        "  {} autonomy: {}",
        style("›").cyan(),
        format!("{:?}", project.autonomy).to_lowercase()
    );

    if let Some(host) = &project.host {
        let port = project.port.unwrap_or(22);
        let user = project.user.as_deref().unwrap_or("root");
        println!("  {} host: {}@{}:{}", style("›").cyan(), user, host, port);
    }

    if let Some(kube) = &project.kubeconfig {
        println!("  {} kubeconfig: {}", style("›").cyan(), kube);
    }
    if let Some(ns) = &project.namespace {
        println!("  {} namespace: {}", style("›").cyan(), ns);
    }

    println!(
        "  {} ssh key: {}",
        style("›").cyan(),
        if project.key_secret.is_some() { "configured" } else { "none" }
    );

    if let Some(ctx) = &project.context_file {
        println!("  {} context file: {}", style("›").cyan(), ctx);
    }

    if let Some(ds) = &project.data_sources {
        println!("  {} data sources:", style("›").cyan());
        if let Some(p) = &ds.prometheus {
            println!("      prometheus: {}", p.url);
        }
        if let Some(s) = &ds.seq {
            println!("      seq: {}", s.url);
        }
        if let Some(j) = &ds.jaeger {
            println!("      jaeger: {}", j.url);
        }
        if let Some(g) = &ds.github {
            println!("      github: {}", g.repo);
        }
        if let Some(e) = &ds.elasticsearch {
            println!("      elasticsearch: {}", e.url);
        }
    }

    if let Some(probes) = &project.probes {
        if !probes.is_empty() {
            println!("  {} probes: {}", style("›").cyan(), probes.len());
            for p in probes {
                println!("      {}", p.name);
            }
        }
    }

    println!();
    Ok(())
}

pub fn handle_project_list(config: &OpsConfig) -> Result<()> {
    use console::style;

    let targets = config.projects.as_deref().unwrap_or_default();
    if targets.is_empty() {
        println!("No projects configured. Run 'opsclaw project add' to add one.");
        return Ok(());
    }

    println!();
    println!("  {}", style("Configured projects:").white().bold());
    println!();
    for t in targets {
        let kind = format!("{:?}", t.project_type);
        let host = t.host.as_deref().unwrap_or("—");
        let autonomy = format!("{:?}", t.autonomy);
        println!(
            "  {} {}  [{}]  host: {}  autonomy: {}",
            style("›").cyan(),
            style(&t.name).white().bold(),
            style(&kind).dim(),
            host,
            autonomy,
        );
    }
    println!();

    Ok(())
}

/// Remove a project from the config by name.
pub async fn handle_project_remove(config: &OpsConfig, name: &str) -> Result<()> {
    use crate::ops::setup::{load_existing_config, opsclaw_config_path};
    use console::style;

    let config_path = opsclaw_config_path()?;
    let mut cfg = load_existing_config(&config_path);
    cfg.config_path = config_path.clone();

    let targets = cfg.projects.get_or_insert_with(Vec::new);
    let before = targets.len();
    targets.retain(|t| t.name != name);

    if targets.len() == before {
        anyhow::bail!("No project named '{}' found in config.", name);
    }

    cfg.save().await?;

    println!(
        "  {} Project '{}' removed from {}",
        style("✓").green().bold(),
        name,
        style(config_path.display()).underlined()
    );

    // Suppress unused warning — config is passed for consistency with other handlers
    let _ = config;

    Ok(())
}
