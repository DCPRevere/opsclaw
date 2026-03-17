//! Interactive setup wizard for OpsClaw first-run configuration.
//!
//! Walks the user through adding a target, running a discovery scan,
//! setting an autonomy level, and configuring a notification channel.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use console::style;
use dialoguer::{Input, Select};

use crate::config::schema::{
    OpsClawAutonomy, OpsClawNotificationConfig, TargetConfig, TargetType,
};
use crate::ops::snapshots;
use crate::tools::discovery::{self, CommandOutput, CommandRunner, TargetSnapshot};

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

// ---------------------------------------------------------------------------
// Command runners (local + SSH test)
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

struct SshCommandRunnerStub {
    host: String,
    user: String,
    port: u16,
}

#[async_trait::async_trait]
impl CommandRunner for SshCommandRunnerStub {
    async fn run(&self, command: &str) -> Result<CommandOutput> {
        let output = tokio::process::Command::new("ssh")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-p")
            .arg(self.port.to_string())
            .arg(format!("{}@{}", self.user, self.host))
            .arg(command)
            .output()
            .await
            .with_context(|| {
                format!(
                    "SSH command failed: {}@{}:{} '{}'",
                    self.user, self.host, self.port, command
                )
            })?;
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

// ---------------------------------------------------------------------------
// Config file helpers
// ---------------------------------------------------------------------------

fn opsclaw_config_path() -> Result<PathBuf> {
    let user_dirs =
        directories::UserDirs::new().context("Cannot determine home directory")?;
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
    runner: Box<dyn CommandRunner>,
}

fn step_target_type() -> Result<TargetType> {
    let items = &["Remote (SSH)", "Local (this machine)"];
    let selection = Select::new()
        .with_prompt("Where is the server you want to monitor?")
        .items(items)
        .default(0)
        .interact()?;
    Ok(if selection == 0 {
        TargetType::Ssh
    } else {
        TargetType::Local
    })
}

async fn step_ssh_target() -> Result<TargetResult> {
    let host: String = Input::new()
        .with_prompt("SSH host")
        .interact_text()?;

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

    let name: String = Input::new()
        .with_prompt("Target name")
        .interact_text()?;

    // Test connection
    print_bullet(&format!("Testing SSH connection to {user}@{host}:{port}..."));

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

    let config = TargetConfig {
        name,
        target_type: TargetType::Ssh,
        host: Some(host.clone()),
        port: Some(port),
        user: Some(user.clone()),
        key_secret: Some(key_path),
        autonomy: OpsClawAutonomy::default(),
        context_file: None,
    };

    let runner: Box<dyn CommandRunner> = Box::new(SshCommandRunnerStub {
        host,
        user,
        port,
    });

    Ok(TargetResult { config, runner })
}

fn step_local_target() -> Result<TargetResult> {
    let name: String = Input::new()
        .with_prompt("Target name")
        .default("this-box".into())
        .interact_text()?;

    let config = TargetConfig {
        name,
        target_type: TargetType::Local,
        host: None,
        port: None,
        user: None,
        key_secret: None,
        autonomy: OpsClawAutonomy::default(),
        context_file: None,
    };

    let runner: Box<dyn CommandRunner> = Box::new(LocalCommandRunner);
    Ok(TargetResult { config, runner })
}

fn step_autonomy() -> Result<OpsClawAutonomy> {
    let items = &[
        "Observe      — read-only commands only",
        "Suggest      — all commands, but approve writes",
        "Act on known — run matched runbooks automatically",
        "Full auto    — unrestricted",
    ];
    let selection = Select::new()
        .with_prompt("Autonomy level for this target")
        .items(items)
        .default(0)
        .interact()?;
    Ok(match selection {
        0 => OpsClawAutonomy::Observe,
        1 => OpsClawAutonomy::Suggest,
        2 => OpsClawAutonomy::ActOnKnown,
        _ => OpsClawAutonomy::FullAuto,
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
            print_bullet(&format!(
                "Services: {} active",
                snapshot.services.len()
            ));
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
                print_bullet(&format!("Disk: {} / {} ({}% used)", d.used, d.size, d.use_percent));
            }

            // Save snapshot for future monitoring baselines
            if let Err(e) = snapshots::save_snapshot(target_name, &snapshot) {
                eprintln!("  Warning: could not save snapshot: {e}");
            }

            Some(snapshot)
        }
        Err(e) => {
            println!(
                "  {} Scan failed: {}",
                style("✗").yellow().bold(),
                e
            );
            print_bullet("You can re-run later with: opsclaw scan");
            None
        }
    }
}

enum NotificationChoice {
    Telegram { bot_token: String, chat_id: String },
    Skip,
}

fn step_notification() -> Result<NotificationChoice> {
    let items = &["Telegram", "Slack (coming soon)", "Email (coming soon)", "Webhook (coming soon)", "Skip for now"];
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
        _ => {
            if selection == 4 {
                print_bullet("You can configure notifications later in ~/.opsclaw/config.toml");
            } else {
                print_bullet("This channel is not yet available. You can configure it later in ~/.opsclaw/config.toml");
            }
            Ok(NotificationChoice::Skip)
        }
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

    if let NotificationChoice::Telegram { bot_token, chat_id } = notification {
        cfg.notifications = Some(OpsClawNotificationConfig {
            telegram_bot_token: Some(bot_token.clone()),
            telegram_chat_id: Some(chat_id.clone()),
            ..OpsClawNotificationConfig::default()
        });
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
    println!(
        "  {}",
        style("OpsClaw Setup Wizard").cyan().bold()
    );
    println!(
        "  {}",
        style("Configure a target, run discovery, and set up alerts.").dim()
    );

    // Step 1: Target type
    print_step(1, 5, "Target");
    let target_type = step_target_type()?;

    // Step 2: Connection details
    let mut target_result = match target_type {
        TargetType::Ssh => step_ssh_target().await?,
        TargetType::Local => step_local_target()?,
    };

    // Step 3: Autonomy level
    print_step(2, 5, "Autonomy Level");
    target_result.config.autonomy = step_autonomy()?;

    // Step 4: Discovery scan
    print_step(3, 5, "Discovery Scan");
    step_discovery_scan(&target_result.config.name, target_result.runner.as_ref()).await;

    // Step 5: Notification channel
    print_step(4, 5, "Notification Channel");
    let notification = step_notification()?;

    // Step 6: Write config
    print_step(5, 5, "Write Config");
    let config_path = opsclaw_config_path()?;
    write_config(&config_path, &target_result.config, &notification)?;

    println!(
        "  {} Config written to {}",
        style("✓").green().bold(),
        style(config_path.display()).underlined()
    );
    println!();

    // Print summary
    let toml_str =
        toml::to_string_pretty(&target_result.config).unwrap_or_default();
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
            autonomy: OpsClawAutonomy::Observe,
            context_file: None,
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
            autonomy: OpsClawAutonomy::Suggest,
            context_file: None,
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
            autonomy: OpsClawAutonomy::Observe,
            context_file: None,
        };
        write_config(&path, &t1, &NotificationChoice::Skip).unwrap();

        let t2 = TargetConfig {
            name: "box-2".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::FullAuto,
            context_file: None,
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
            autonomy: OpsClawAutonomy::Observe,
            context_file: None,
        };
        write_config(&path, &t1, &NotificationChoice::Skip).unwrap();

        let t1_updated = TargetConfig {
            name: "box-1".to_string(),
            target_type: TargetType::Local,
            host: None,
            port: None,
            user: None,
            key_secret: None,
            autonomy: OpsClawAutonomy::FullAuto,
            context_file: None,
        };
        write_config(&path, &t1_updated, &NotificationChoice::Skip).unwrap();

        let cfg = load_existing_config(&path);
        assert_eq!(cfg.targets.len(), 1);
    }
}
