//! Interactive setup wizard for OpsClaw first-run configuration.
//!
//! Walks the user through adding a target, running a discovery scan,
//! setting an autonomy level, and configuring a notification channel.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use console::style;
use dialoguer::{Input, Select};

use crate::ops_config::OpsConfig;
use crate::ops_config::{ConnectionType, OpsClawAutonomy, TargetConfig};

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

pub fn opsclaw_config_path() -> Result<PathBuf> {
    let user_dirs = directories::UserDirs::new().context("Cannot determine home directory")?;
    let dir = user_dirs.home_dir().join(".opsclaw");
    Ok(dir.join("config.toml"))
}

pub fn load_existing_config(path: &Path) -> OpsConfig {
    match std::fs::read_to_string(path) {
        Err(_) => {
            let mut cfg = OpsConfig::default();
            cfg.inner.config_path = path.to_path_buf();
            cfg
        }
        Ok(s) => match toml::from_str::<OpsConfig>(&s) {
            Ok(mut cfg) => {
                cfg.inner.config_path = path.to_path_buf();
                cfg
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Failed to parse existing config, starting fresh");
                let mut cfg = OpsConfig::default();
                cfg.inner.config_path = path.to_path_buf();
                cfg
            }
        },
    }
}

// ---------------------------------------------------------------------------
// SSH connection test
// ---------------------------------------------------------------------------

async fn test_ssh_connection(host: &str, user: &str, port: u16, key_path: Option<&str>) -> bool {
    let mut cmd = tokio::process::Command::new("ssh");
    cmd.arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("BatchMode=yes");
    if let Some(key) = key_path {
        // Expand ~ to home directory
        let expanded = if key.starts_with("~/") {
            std::env::var("HOME")
                .map(|h| format!("{}/{}", h, &key[2..]))
                .unwrap_or_else(|_| key.to_string())
        } else {
            key.to_string()
        };
        cmd.arg("-i").arg(expanded);
    }
    let result = cmd
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{user}@{host}"))
        .arg("echo ok")
        .output()
        .await;

    match result {
        Ok(output) => {
            if output.status.success() {
                true
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                tracing::info!(
                    host = %host,
                    user = %user,
                    port = port,
                    status = ?output.status,
                    stderr = %stderr.trim(),
                    stdout = %stdout.trim(),
                    "SSH connection test failed"
                );
                false
            }
        }
        Err(e) => {
            tracing::info!(error = %e, "Failed to spawn ssh process");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Individual wizard steps
// ---------------------------------------------------------------------------

pub struct TargetResult {
    pub config: TargetConfig,
}

pub fn step_connection_type() -> Result<ConnectionType> {
    let items = &["Remote (SSH)", "Local (this machine)", "Kubernetes cluster"];
    let selection = Select::new()
        .with_prompt("Where is the server you want to monitor?")
        .items(items)
        .default(0)
        .interact()?;
    Ok(match selection {
        0 => ConnectionType::Ssh,
        1 => ConnectionType::Local,
        _ => ConnectionType::Kubernetes,
    })
}

pub async fn step_ssh_target() -> Result<TargetResult> {
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

    let mut connected = test_ssh_connection(&host, &user, port, Some(&key_path)).await;
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
            connected = test_ssh_connection(&host, &user, port, Some(&key_path)).await;
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

    if let Err(e) = &key_pem_result {
        println!(
            "  {} Could not read SSH key ({}): target will be saved without a key",
            style("\u{26a0}").yellow(),
            e
        );
    }

    // Store key PEM content (plain text here; Config::save() encrypts it as enc2:...).
    let key_secret = key_pem_result.ok();

    let config = TargetConfig {
        name,
        connection_type: ConnectionType::Ssh,
        host: Some(host),
        port: Some(port),
        user: Some(user),
        key_secret,
        autonomy: OpsClawAutonomy::default(),
        context_file: None,
        probes: None,
        data_sources: None,
        escalation: None,
        kubeconfig: None,
        context: None,
        namespace: None,
    };

    Ok(TargetResult { config })
}

pub fn step_local_target() -> Result<TargetResult> {
    let name: String = Input::new()
        .with_prompt("Target name")
        .default("this-box".into())
        .interact_text()?;

    let config = TargetConfig {
        name,
        connection_type: ConnectionType::Local,
        host: None,
        port: None,
        user: None,
        key_secret: None,
        autonomy: OpsClawAutonomy::default(),
        context_file: None,
        probes: None,
        data_sources: None,
        escalation: None,
        kubeconfig: None,
        context: None,
        namespace: None,
    };

    Ok(TargetResult { config })
}

pub fn step_kubernetes_target() -> Result<TargetResult> {
    let name: String = Input::new()
        .with_prompt("Target name")
        .default("k8s-cluster".into())
        .interact_text()?;

    let kubeconfig: String = Input::new()
        .with_prompt("Path to kubeconfig (leave blank for default lookup: KUBECONFIG, ~/.kube/config, or in-cluster)")
        .allow_empty(true)
        .interact_text()?;

    let context: String = Input::new()
        .with_prompt("Kubernetes context (leave blank for kubeconfig current-context)")
        .allow_empty(true)
        .interact_text()?;

    let namespace: String = Input::new()
        .with_prompt("Default namespace (leave blank for all namespaces)")
        .allow_empty(true)
        .interact_text()?;

    let config = TargetConfig {
        name,
        connection_type: ConnectionType::Kubernetes,
        host: None,
        port: None,
        user: None,
        key_secret: None,
        autonomy: OpsClawAutonomy::default(),
        context_file: None,
        probes: None,
        data_sources: None,
        escalation: None,
        kubeconfig: if kubeconfig.trim().is_empty() {
            None
        } else {
            Some(kubeconfig.trim().to_string())
        },
        context: if context.trim().is_empty() {
            None
        } else {
            Some(context.trim().to_string())
        },
        namespace: if namespace.trim().is_empty() {
            None
        } else {
            Some(namespace.trim().to_string())
        },
    };

    Ok(TargetResult { config })
}

/// Ask the user for optional project context and persist it to a file.
///
/// Returns `Some(path)` (using `~/` prefix) if context was provided, `None` otherwise.
pub fn step_target_context(target_name: &str) -> Result<Option<String>> {
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

pub fn step_autonomy() -> Result<OpsClawAutonomy> {
    let items = &[
        "Dry-run  — evaluate OpsClaw first (recommended for new projects)",
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_existing_config_missing_file() {
        let cfg = load_existing_config(Path::new("/nonexistent/config.toml"));
        assert!(cfg.targets.as_ref().map_or(true, |t| t.is_empty()));
        assert!(cfg.notifications.is_none());
    }

    #[test]
    fn test_write_context_file_creates_and_returns_path() {
        let home = tempfile::tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let result = std::panic::catch_unwind(|| {
            let path = write_context_file("my-server", "Redis is for sessions only").unwrap();
            assert_eq!(path, "~/.opsclaw/context/my-server.md");
            let abs_path = home.path().join(".opsclaw/context/my-server.md");
            let content = std::fs::read_to_string(&abs_path).unwrap();
            assert_eq!(content, "Redis is for sessions only");
        });
        // SAFETY: test-only restore of HOME captured at the start of the test.
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        result.unwrap();
    }
}
