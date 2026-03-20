//! Interactive setup wizard for OpsClaw first-run configuration.
//!
//! Walks the user through adding a target, running a discovery scan,
//! setting an autonomy level, and configuring a notification channel.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use console::style;
use dialoguer::{Confirm, Input, Select};

use crate::ops::snapshots;
use crate::tools::discovery::{self, CommandRunner, TargetSnapshot};
use crate::tools::ssh_command_runner::{LocalCommandRunner, SshCommandRunner};
use crate::tools::ssh_tool::RealSshExecutor;
use crate::tools::ssh_tool::TargetEntry;
use zeroclaw::config::schema::{
    OpsClawAutonomy, OpsClawNotificationConfig, TargetConfig, TargetType,
};

// ---------------------------------------------------------------------------
// Step helpers (mirrors onboard/wizard.rs style)
// ---------------------------------------------------------------------------

fn print_step(current: u8, total: u8, title: &str) {
    println!();
    println!(
        "  {} {}",
        style(format!("[{current}/{total}]")).cyan().bold(),
        style(title).white().bold()
    );
    println!("  {}", style("─".repeat(50)).dim());
}

fn print_bullet(text: &str) {
    println!("  {} {}", style("›").cyan(), text);
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
// Config file helpers
// ---------------------------------------------------------------------------

fn opsclaw_config_path() -> Result<PathBuf> {
    let user_dirs = directories::UserDirs::new().context("Cannot determine home directory")?;
    let dir = user_dirs.home_dir().join(".opsclaw");
    Ok(dir.join("config.toml"))
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Cannot create directory: {}", parent.display()))?;
    }
    Ok(())
}

/// Minimal TOML representation we write (avoids coupling to the full Config struct).
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct SetupConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    targets: Vec<TargetConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notifications: Option<OpsClawNotificationConfig>,
}

fn load_existing_config(path: &Path) -> SetupConfig {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// SSH connection test
// ---------------------------------------------------------------------------

async fn test_ssh_connection(host: &str, user: &str, port: u16) -> bool {
    let result = tokio::process::Command::new("ssh")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{user}@{host}"))
        .arg("echo ok")
        .output()
        .await;

    match result {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Individual wizard steps
// ---------------------------------------------------------------------------

struct TargetResult {
    config: TargetConfig,
    runner: Option<Box<dyn CommandRunner>>,
}

fn step_target_type() -> Result<TargetType> {
    let items = &["Remote (SSH)", "Local (this machine)", "Kubernetes cluster"];
    let selection = Select::new()
        .with_prompt("Where is the server you want to monitor?")
        .items(items)
        .default(0)
        .interact()?;
    Ok(match selection {
        0 => TargetType::Ssh,
        1 => TargetType::Local,
        _ => TargetType::Kubernetes,
    })
}

async fn step_ssh_target() -> Result<TargetResult> {
    let host: String = Input::new().with_prompt("SSH host").interact_text()?;

    let user: String = Input::new()
        .with_prompt("SSH user")
        .default("root".into())
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("SSH port")
        .default(22)
        .interact_text()?;

    let key_path: String = Input::new()
        .with_prompt("SSH key path")
        .default("~/.ssh/id_rsa".into())
        .interact_text()?;

    let name: String = Input::new().with_prompt("Target name").interact_text()?;

    // Test connection
    print_bullet(&format!(
        "Testing SSH connection to {user}@{host}:{port}..."
    ));

    let mut connected = test_ssh_connection(&host, &user, port).await;
    if connected {
        println!("  {} Connection successful", style("✓").green().bold());
    } else {
        println!("  {} Connection failed", style("✗").red().bold());
        let retry_items = &["Retry", "Skip (continue without testing)"];
        let choice = Select::new()
            .with_prompt("What would you like to do?")
            .items(retry_items)
            .default(0)
            .interact()?;
        if choice == 0 {
            connected = test_ssh_connection(&host, &user, port).await;
            if connected {
                println!("  {} Connection successful", style("✓").green().bold());
            } else {
                println!(
                    "  {} Connection still failing — continuing anyway",
                    style("✗").red().bold()
                );
            }
        }
    }

    // Read the SSH key content — stored inline (encrypted by Config::save()).
    let key_pem_result = fs::read_to_string(expand_tilde(&key_path));

    let runner: Box<dyn CommandRunner> = match &key_pem_result {
        Ok(key_pem) => {
            let entry = TargetEntry {
                name: name.clone(),
                host: host.clone(),
                port,
                user: user.clone(),
                private_key_pem: key_pem.clone(),
                autonomy: crate::tools::ssh_tool::OpsClawAutonomy::DryRun,
            };
            Box::new(SshCommandRunner::new(entry, Box::new(RealSshExecutor)))
        }
        Err(e) => {
            println!(
                "  {} Could not read SSH key ({}): using stub for scan",
                style("\u{26a0}").yellow(),
                e
            );
            // Graceful fallback: scan will be skipped, not crash
            Box::new(LocalCommandRunner::new(
                crate::tools::ssh_tool::OpsClawAutonomy::DryRun,
                name.clone(),
            ))
        }
    };

    // Store key PEM content (plain text here; Config::save() encrypts it as enc2:...).
    let key_secret = key_pem_result.ok();

    let config = TargetConfig {
        name,
        target_type: TargetType::Ssh,
        host: Some(host),
        port: Some(port),
        user: Some(user),
        key_secret,
        autonomy: OpsClawAutonomy::default(),
        context_file: None,
        probes: None,
        data_sources: None,
        escalation: None,
        databases: None,
        kubeconfig: None,
        namespace: None,
    };

    Ok(TargetResult {
        config,
        runner: Some(runner),
    })
}

fn step_local_target() -> Result<TargetResult> {
    let name: String = Input::new()
        .with_prompt("Target name")
        .default("this-box".into())
        .interact_text()?;

    let runner: Box<dyn CommandRunner> = Box::new(LocalCommandRunner::new(
        crate::tools::ssh_tool::OpsClawAutonomy::DryRun,
        name.clone(),
    ));

    let config = TargetConfig {
        name,
        target_type: TargetType::Local,
        host: None,
        port: None,
        user: None,
        key_secret: None,
        autonomy: OpsClawAutonomy::default(),
        context_file: None,
        probes: None,
        data_sources: None,
        escalation: None,
        databases: None,
        kubeconfig: None,
        namespace: None,
    };

    Ok(TargetResult {
        config,
        runner: Some(runner),
    })
}

fn step_kubernetes_target() -> Result<TargetResult> {
    let name: String = Input::new()
        .with_prompt("Target name")
        .default("k8s-cluster".into())
        .interact_text()?;

    let kubeconfig: String = Input::new()
        .with_prompt("Path to kubeconfig (leave blank for default)")
        .allow_empty(true)
        .interact_text()?;

    let namespace: String = Input::new()
        .with_prompt("Default namespace (leave blank for all namespaces)")
        .allow_empty(true)
        .interact_text()?;

    let config = TargetConfig {
        name,
        target_type: TargetType::Kubernetes,
        host: None,
        port: None,
        user: None,
        key_secret: None,
        autonomy: OpsClawAutonomy::default(),
        context_file: None,
        probes: None,
        data_sources: None,
        escalation: None,
        databases: None,
        kubeconfig: if kubeconfig.is_empty() {
            None
        } else {
            Some(kubeconfig)
        },
        namespace: if namespace.is_empty() {
            None
        } else {
            Some(namespace)
        },
    };

    Ok(TargetResult {
        config,
        runner: None,
    })
}

/// Ask the user for optional target context and persist it to a file.
///
/// Returns `Some(path)` (using `~/` prefix) if context was provided, `None` otherwise.
fn step_target_context(target_name: &str) -> Result<Option<String>> {
    println!();
    println!(
        "  {}",
        style("Optionally describe this target for OpsClaw (things the scan can't infer).").dim()
    );
    println!(
        "  {}",
        style("Examples: \"Redis is for sessions only\", \"batch job runs at 02:00\"").dim()
    );

    let context_input: String = Input::new()
        .with_prompt("  Target context (Enter to skip)")
        .allow_empty(true)
        .interact_text()?;

    if context_input.trim().is_empty() {
        return Ok(None);
    }

    let path = write_context_file(target_name, context_input.trim())?;
    println!(
        "  {} Context saved to {}",
        style("✓").green().bold(),
        style(&path).underlined()
    );
    Ok(Some(path))
}

/// Write context content to `~/.opsclaw/context/{target_name}.md`, creating the directory
/// if needed. Returns the path in `~/` form.
fn write_context_file(target_name: &str, content: &str) -> Result<String> {
    let user_dirs = directories::UserDirs::new().context("Cannot determine home directory")?;
    let context_dir = user_dirs.home_dir().join(".opsclaw").join("context");
    std::fs::create_dir_all(&context_dir)
        .with_context(|| format!("Cannot create directory: {}", context_dir.display()))?;

    let file_path = context_dir.join(format!("{target_name}.md"));
    std::fs::write(&file_path, content)
        .with_context(|| format!("Failed to write context file: {}", file_path.display()))?;

    // Return tilde-prefixed path for config portability.
    Ok(format!("~/.opsclaw/context/{target_name}.md"))
}

fn step_autonomy() -> Result<OpsClawAutonomy> {
    let items = &[
        "Dry-run  — evaluate OpsClaw first (recommended for new targets)",
        "Approve  — ask me before taking any action",
        "Auto     — fix things automatically (I trust OpsClaw)",
    ];
    let selection = Select::new()
        .with_prompt("Autonomy level for this target")
        .items(items)
        .default(1)
        .interact()?;
    Ok(match selection {
        0 => OpsClawAutonomy::DryRun,
        1 => OpsClawAutonomy::Approve,
        _ => OpsClawAutonomy::Auto,
    })
}

async fn step_discovery_scan(
    target_name: &str,
    runner: &dyn CommandRunner,
) -> Option<TargetSnapshot> {
    print_bullet(&format!("Running discovery scan on {target_name}..."));

    match discovery::run_discovery_scan(runner).await {
        Ok(snapshot) => {
            println!("  {} Scan complete", style("✓").green().bold());
            print_bullet(&format!(
                "OS: {} {}",
                snapshot.os.distro_name, snapshot.os.distro_version
            ));
            print_bullet(&format!(
                "Containers: {} ({})",
                snapshot.containers.len(),
                snapshot
                    .containers
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            print_bullet(&format!("Services: {} active", snapshot.services.len()));
            print_bullet(&format!(
                "Ports: {}",
                snapshot
                    .listening_ports
                    .iter()
                    .map(|p| p.port.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            // Summarise disk from the root mount or first entry
            if let Some(d) = snapshot.disk.first() {
                print_bullet(&format!(
                    "Disk: {} / {} ({}% used)",
                    d.used, d.size, d.use_percent
                ));
            }

            // Save snapshot for future monitoring baselines
            if let Err(e) = snapshots::save_snapshot(target_name, &snapshot) {
                eprintln!("  Warning: could not save snapshot: {e}");
            }

            Some(snapshot)
        }
        Err(e) => {
            println!("  {} Scan failed: {}", style("✗").yellow().bold(), e);
            print_bullet("You can re-run later with: opsclaw scan");
            None
        }
    }
}

enum NotificationChoice {
    Telegram { bot_token: String, chat_id: String },
    Slack { webhook_url: String },
    Webhook { url: String, bearer_token: Option<String> },
    Skip,
}

fn step_notification() -> Result<NotificationChoice> {
    let items = &[
        "Telegram",
        "Slack",
        "Email (coming soon)",
        "Webhook",
        "Skip for now",
    ];
    let selection = Select::new()
        .with_prompt("How should OpsClaw alert you?")
        .items(items)
        .default(0)
        .interact()?;

    match selection {
        0 => {
            let bot_token: String = Input::new()
                .with_prompt("Telegram bot token")
                .interact_text()?;
            let chat_id: String = Input::new()
                .with_prompt("Telegram chat ID")
                .interact_text()?;
            Ok(NotificationChoice::Telegram { bot_token, chat_id })
        }
        1 => {
            let webhook_url: String = Input::new()
                .with_prompt("Slack webhook URL")
                .validate_with(|input: &String| -> Result<(), String> {
                    if input.starts_with("https://hooks.slack.com/") {
                        Ok(())
                    } else {
                        Err("URL must start with https://hooks.slack.com/".into())
                    }
                })
                .interact_text()?;
            Ok(NotificationChoice::Slack { webhook_url })
        }
        3 => {
            let url: String = Input::new()
                .with_prompt("Webhook URL")
                .validate_with(|input: &String| -> Result<(), String> {
                    if input.starts_with("https://") || input.starts_with("http://") {
                        Ok(())
                    } else {
                        Err("URL must start with https:// or http://".into())
                    }
                })
                .interact_text()?;
            let bearer_token = if Confirm::new()
                .with_prompt("Add a bearer token?")
                .default(false)
                .interact()?
            {
                let token: String = Input::new()
                    .with_prompt("Bearer token")
                    .interact_text()?;
                Some(token)
            } else {
                None
            };
            Ok(NotificationChoice::Webhook { url, bearer_token })
        }
        4 => {
            print_bullet("You can configure notifications later in ~/.opsclaw/config.toml");
            Ok(NotificationChoice::Skip)
        }
        _ => {
            print_bullet(
                "This channel is not yet available. You can configure it later in ~/.opsclaw/config.toml",
            );
            Ok(NotificationChoice::Skip)
        }
    }
}

fn step_data_sources() -> Result<Option<serde_json::Value>> {
    println!();
    println!(
        "  {}",
        style("Configure endpoints for observability services (all optional).").dim()
    );

    let mut sources = serde_json::Map::new();

    // Prometheus
    if Confirm::new()
        .with_prompt("Do you have Prometheus running?")
        .default(false)
        .interact()?
    {
        let url: String = Input::new()
            .with_prompt("Prometheus URL")
            .default("http://localhost:9090".into())
            .interact_text()?;
        sources.insert(
            "prometheus".into(),
            serde_json::json!({ "url": url }),
        );
    }

    // Seq
    if Confirm::new()
        .with_prompt("Do you have Seq running?")
        .default(false)
        .interact()?
    {
        let url: String = Input::new()
            .with_prompt("Seq URL")
            .default("http://localhost:5341".into())
            .interact_text()?;
        let api_key: String = Input::new()
            .with_prompt("Seq API key (leave blank for none)")
            .allow_empty(true)
            .interact_text()?;
        let mut entry = serde_json::Map::new();
        entry.insert("url".into(), serde_json::Value::String(url));
        if !api_key.is_empty() {
            entry.insert("api_key".into(), serde_json::Value::String(api_key));
        }
        sources.insert("seq".into(), serde_json::Value::Object(entry));
    }

    // Jaeger
    if Confirm::new()
        .with_prompt("Do you have Jaeger running?")
        .default(false)
        .interact()?
    {
        let url: String = Input::new()
            .with_prompt("Jaeger URL")
            .default("http://localhost:16686".into())
            .interact_text()?;
        sources.insert(
            "jaeger".into(),
            serde_json::json!({ "url": url }),
        );
    }

    if sources.is_empty() {
        Ok(None)
    } else {
        Ok(Some(serde_json::Value::Object(sources)))
    }
}

// ---------------------------------------------------------------------------
// Write config
// ---------------------------------------------------------------------------

fn write_config(
    path: &Path,
    target: &TargetConfig,
    notification: &NotificationChoice,
) -> Result<()> {
    ensure_parent_dir(path)?;

    let mut cfg = load_existing_config(path);

    // Replace target with same name, or append
    if let Some(pos) = cfg.targets.iter().position(|t| t.name == target.name) {
        cfg.targets[pos] = target.clone();
    } else {
        cfg.targets.push(target.clone());
    }

    match notification {
        NotificationChoice::Telegram { bot_token, chat_id } => {
            cfg.notifications = Some(OpsClawNotificationConfig {
                telegram_bot_token: Some(bot_token.clone()),
                telegram_chat_id: Some(chat_id.clone()),
                ..OpsClawNotificationConfig::default()
            });
        }
        NotificationChoice::Slack { webhook_url } => {
            cfg.notifications = Some(OpsClawNotificationConfig {
                slack_webhook_url: Some(webhook_url.clone()),
                ..OpsClawNotificationConfig::default()
            });
        }
        NotificationChoice::Webhook { url, bearer_token } => {
            cfg.notifications = Some(OpsClawNotificationConfig {
                webhook_url: Some(url.clone()),
                webhook_bearer_token: bearer_token.clone(),
                ..OpsClawNotificationConfig::default()
            });
        }
        NotificationChoice::Skip => {}
    }

    let toml_str = toml::to_string_pretty(&cfg).context("Failed to serialize config")?;
    std::fs::write(path, &toml_str)
        .with_context(|| format!("Failed to write config to {}", path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run the interactive OpsClaw setup wizard.
pub async fn run_opsclaw_setup() -> Result<()> {
    println!();
    println!("  {}", style("OpsClaw Setup Wizard").cyan().bold());
    println!(
        "  {}",
        style("Configure a target, run discovery, and set up alerts.").dim()
    );

    // Step 1: Target type
    print_step(1, 7, "Target");
    let target_type = step_target_type()?;

    // Step 2: Connection details
    let mut target_result = match target_type {
        TargetType::Ssh => step_ssh_target().await?,
        TargetType::Local => step_local_target()?,
        TargetType::Kubernetes => step_kubernetes_target()?,
    };

    // Step 3: Target context (optional)
    print_step(2, 7, "Target Context");
    target_result.config.context_file = step_target_context(&target_result.config.name)?;

    // Step 4: Autonomy level
    print_step(3, 7, "Autonomy Level");
    target_result.config.autonomy = step_autonomy()?;

    // Step 5: Discovery scan
    print_step(4, 7, "Discovery Scan");
    if let Some(ref runner) = target_result.runner {
        step_discovery_scan(&target_result.config.name, runner.as_ref()).await;
    } else {
        println!("Skipping shell-based discovery scan (Kubernetes targets use kube API).");
    }

    // Step 6: Notification channel
    print_step(5, 7, "Notification Channel");
    let notification = step_notification()?;

    // Step 7: Data sources (optional)
    print_step(6, 7, "Data Sources (optional)");
    target_result.config.data_sources = step_data_sources()?;

    // Step 8: Write config
    print_step(7, 7, "Write Config");
    let config_path = opsclaw_config_path()?;
    write_config(&config_path, &target_result.config, &notification)?;

    println!(
        "  {} Config written to {}",
        style("✓").green().bold(),
        style(config_path.display()).underlined()
    );
    println!();

    // Print summary
    let toml_str = toml::to_string_pretty(&target_result.config).unwrap_or_default();
    println!("{toml_str}");

    if let NotificationChoice::Telegram { bot_token, chat_id } = &notification {
        println!("[notifications]");
        println!("telegram_bot_token = \"{bot_token}\"");
        println!("telegram_chat_id = \"{chat_id}\"");
        println!();
    }

    println!(
        "  {}",
        style("Run 'opsclaw monitor --all' to start monitoring.").dim()
    );
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_existing_config_missing_file() {
        let cfg = load_existing_config(Path::new("/nonexistent/config.toml"));
        assert!(cfg.targets.is_empty());
        assert!(cfg.notifications.is_none());
    }

    #[test]
    fn test_write_and_reload_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let target = TargetConfig {
            name: "test-box".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::DryRun,
            context_file: None,
            probes: None,
            data_sources: None,
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        };

        write_config(&path, &target, &NotificationChoice::Skip).unwrap();

        let cfg = load_existing_config(&path);
        assert_eq!(cfg.targets.len(), 1);
        assert_eq!(cfg.targets[0].name, "test-box");
        assert!(cfg.notifications.is_none());
    }

    #[test]
    fn test_write_config_with_telegram() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let target = TargetConfig {
            name: "prod-web-1".to_string(),
            target_type: TargetType::Ssh,
            host: Some("203.0.113.10".to_string()),
            port: Some(22),
            user: Some("root".to_string()),
            key_secret: Some("~/.ssh/id_rsa".to_string()),
            autonomy: OpsClawAutonomy::Approve,
            context_file: None,
            probes: None,
            data_sources: None,
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        };

        let notif = NotificationChoice::Telegram {
            bot_token: "123:ABC".to_string(),
            chat_id: "-100123".to_string(),
        };

        write_config(&path, &target, &notif).unwrap();

        let cfg = load_existing_config(&path);
        assert_eq!(cfg.targets.len(), 1);
        assert_eq!(cfg.targets[0].name, "prod-web-1");
        let n = cfg.notifications.unwrap();
        assert_eq!(n.telegram_bot_token.unwrap(), "123:ABC");
        assert_eq!(n.telegram_chat_id.unwrap(), "-100123");
    }

    #[test]
    fn test_write_config_appends_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let t1 = TargetConfig {
            name: "box-1".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::DryRun,
            context_file: None,
            probes: None,
            data_sources: None,
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        };
        write_config(&path, &t1, &NotificationChoice::Skip).unwrap();

        let t2 = TargetConfig {
            name: "box-2".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::Auto,
            context_file: None,
            probes: None,
            data_sources: None,
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        };
        write_config(&path, &t2, &NotificationChoice::Skip).unwrap();

        let cfg = load_existing_config(&path);
        assert_eq!(cfg.targets.len(), 2);
        assert_eq!(cfg.targets[0].name, "box-1");
        assert_eq!(cfg.targets[1].name, "box-2");
    }

    #[test]
    fn test_write_config_replaces_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let t1 = TargetConfig {
            name: "box-1".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::DryRun,
            context_file: None,
            probes: None,
            data_sources: None,
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        };
        write_config(&path, &t1, &NotificationChoice::Skip).unwrap();

        let t1_updated = TargetConfig {
            name: "box-1".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::Auto,
            context_file: None,
            probes: None,
            data_sources: None,
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        };
        write_config(&path, &t1_updated, &NotificationChoice::Skip).unwrap();

        let cfg = load_existing_config(&path);
        assert_eq!(cfg.targets.len(), 1);
    }

    #[test]
    fn test_write_context_file_creates_and_returns_path() {
        let home = tempfile::tempdir().unwrap();
        // Override HOME so write_context_file uses the temp dir.
        std::env::set_var("HOME", home.path());
        let path = write_context_file("my-server", "Redis is for sessions only").unwrap();
        assert_eq!(path, "~/.opsclaw/context/my-server.md");

        let abs_path = home.path().join(".opsclaw/context/my-server.md");
        let content = std::fs::read_to_string(&abs_path).unwrap();
        assert_eq!(content, "Redis is for sessions only");
    }

    #[test]
    fn test_write_config_with_context_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let target = TargetConfig {
            name: "ctx-box".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::DryRun,
            context_file: Some("~/.opsclaw/context/ctx-box.md".to_string()),
            probes: None,
            data_sources: None,
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        };

        write_config(&path, &target, &NotificationChoice::Skip).unwrap();

        let cfg = load_existing_config(&path);
        assert_eq!(cfg.targets.len(), 1);
        assert_eq!(
            cfg.targets[0].context_file.as_deref(),
            Some("~/.opsclaw/context/ctx-box.md")
        );
    }

    #[test]
    fn test_write_config_with_data_sources() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let ds = serde_json::json!({
            "prometheus": { "url": "http://localhost:9090" },
            "seq": { "url": "http://localhost:5341", "api_key": "abc123" },
            "jaeger": { "url": "http://localhost:16686" },
        });

        let target = TargetConfig {
            name: "ds-box".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::DryRun,
            context_file: None,
            probes: None,
            data_sources: Some(ds.clone()),
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        };

        write_config(&path, &target, &NotificationChoice::Skip).unwrap();

        let cfg = load_existing_config(&path);
        assert_eq!(cfg.targets.len(), 1);
        let loaded_ds = cfg.targets[0].data_sources.as_ref().unwrap();
        assert_eq!(loaded_ds["prometheus"]["url"], "http://localhost:9090");
        assert_eq!(loaded_ds["seq"]["url"], "http://localhost:5341");
        assert_eq!(loaded_ds["seq"]["api_key"], "abc123");
        assert_eq!(loaded_ds["jaeger"]["url"], "http://localhost:16686");
    }
}
