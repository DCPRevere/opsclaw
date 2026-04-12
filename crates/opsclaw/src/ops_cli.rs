//! OpsClaw CLI command handlers: scan, monitor, watch.

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
use crate::ops::escalation::{
    format_escalation_message, EscalationAction, EscalationManager, EscalationPolicy,
};
use crate::ops::event_stream::{self, EventStreamManager};
use crate::ops::incident_search::IncidentIndex;
use crate::ops::log_sources::{self, LogLevel, LogSourceType};
use crate::ops::notifier::{AlertNotifier, NullNotifier, TelegramNotifier, WebhookNotifier};
use crate::ops::runbooks::{self, RunbookStore};
use crate::ops::probes;
use crate::tools::discovery::{self, CommandRunner, TargetSnapshot};
use crate::tools::kube_tool::KubeClient;
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
pub async fn scan_target(config: &OpsConfig, project: &ProjectConfig) -> Result<TargetSnapshot> {
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
        let snapshot = scan_target(config, t).await?;
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
    _openshell_ctx: &crate::openshell::OpenShellContext,
) -> Result<()> {
    let targets = resolve_targets(config, target.as_deref(), target.is_none())?;

    if targets.is_empty() {
        bail!("No projects configured. Add [[projects]] to your config.");
    }

    let project_names: Vec<String> = targets.iter().map(|t| t.name.clone()).collect();

    loop {
        for name in &project_names {
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

            let prompt = format!(
                "You are OpsClaw, an autonomous SRE agent.\n\n\
                 Run a health check on project '{name}' using the monitor tool. \
                 Examine the snapshot carefully. If anything looks concerning \
                 (high memory/disk/load, missing containers or services, \
                 unusual state), investigate further using the ssh tool. \
                 Store important observations in memory for future reference.\n\n\
                 If everything looks healthy, say so briefly."
            );

            let extra_tools = crate::tools::registry::create_opsclaw_tools(config).ok();
            let allowed = Some(vec![
                "ssh".to_string(),
                "monitor".to_string(),
                "memory_store".to_string(),
                "memory_recall".to_string(),
            ]);

            println!("[{ts}] Checking {name}...");

            match Box::pin(zeroclaw::agent::run(
                config.inner.clone(),
                Some(prompt),
                None,
                config.diagnosis.model.clone(),
                0.0,
                vec![],
                false,
                None,
                allowed,
                extra_tools,
            ))
            .await
            {
                Ok(response) => {
                    println!("[{ts}] {name}: {}", response.lines().next().unwrap_or(&response));
                    if response.to_lowercase().contains("concern")
                        || response.to_lowercase().contains("critical")
                        || response.to_lowercase().contains("warning")
                        || response.to_lowercase().contains("issue")
                        || response.to_lowercase().contains("alert")
                    {
                        eprintln!("{response}");
                    }
                }
                Err(e) => {
                    eprintln!("[{ts}] {name}: agent error — {e}");
                }
            }
        }

        if once {
            break;
        }

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
        let discovered = match scan_target(config, t).await {
            Ok(snap) => probes::discover_probes(&snap, t.host.as_deref()),
            Err(_) => vec![],
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
