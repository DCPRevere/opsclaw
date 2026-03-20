use crate::security::OpsClawSecretStore;
use crate::tools::ssh_tool::{SshCommandRunner, TargetEntry};
use anyhow::{bail, Context, Result};
use std::path::Path;
use zeroclaw::config::schema::{OpsClawAutonomy, TargetConfig, TargetType};
use zeroclaw::config::Config;

/// Central wiring struct that connects Config, secrets, and SSH tooling.
pub struct OpsClawContext {
    pub config: Config,
    pub secrets: OpsClawSecretStore,
}

impl OpsClawContext {
    /// Load config and secrets from disk using default paths.
    pub async fn load() -> Result<Self> {
        let config = Box::pin(Config::load_or_init()).await?;
        let opsclaw_dir = config
            .config_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let secrets = OpsClawSecretStore::new(opsclaw_dir);
        Ok(Self { config, secrets })
    }

    /// Construct from pre-built config and secret store (useful for testing).
    pub fn new(config: Config, secrets: OpsClawSecretStore) -> Self {
        Self { config, secrets }
    }

    /// Return the configured targets (empty slice if none).
    pub fn targets(&self) -> &[TargetConfig] {
        match &self.config.targets {
            Some(targets) => targets,
            None => &[],
        }
    }

    /// Look up a target by name, resolve its SSH key from the secret store,
    /// and return a configured `SshCommandRunner` ready to execute commands.
    pub fn ssh_runner_for(&self, target_name: &str) -> Result<SshCommandRunner> {
        let target = self.find_target(target_name)?;

        if target.target_type != TargetType::Ssh {
            bail!("target '{}' is not an SSH target", target_name);
        }

        let host = target
            .host
            .as_deref()
            .context(format!("SSH target '{}' missing host", target_name))?;
        let user = target
            .user
            .as_deref()
            .context(format!("SSH target '{}' missing user", target_name))?;
        let key_secret_name = target
            .key_secret
            .as_deref()
            .context(format!("SSH target '{}' missing key_secret", target_name))?;

        let private_key_pem = self.secrets.get(key_secret_name)?.context(format!(
            "secret '{}' not found in secret store",
            key_secret_name
        ))?;

        let entry = TargetEntry {
            name: target.name.clone(),
            host: host.to_string(),
            port: target.port.unwrap_or(22),
            user: user.to_string(),
            private_key_pem,
            autonomy: convert_autonomy(target.autonomy),
        };

        Ok(SshCommandRunner::new(entry))
    }

    /// Read the context file for a target and return its contents.
    pub fn context_for(&self, target_name: &str) -> Result<String> {
        let target = self.find_target(target_name)?;

        let context_path = target.context_file.as_deref().context(format!(
            "target '{}' has no context_file configured",
            target_name
        ))?;

        std::fs::read_to_string(context_path)
            .context(format!("failed to read context file '{}'", context_path))
    }

    fn find_target(&self, name: &str) -> Result<&TargetConfig> {
        self.targets()
            .iter()
            .find(|t| t.name == name)
            .context(format!("target '{}' not found in config", name))
    }
}

/// Convert from config autonomy enum to ssh_tool autonomy enum.
fn convert_autonomy(
    autonomy: zeroclaw::config::schema::OpsClawAutonomy,
) -> crate::tools::ssh_tool::OpsClawAutonomy {
    match autonomy {
        OpsClawAutonomy::DryRun => crate::tools::ssh_tool::OpsClawAutonomy::DryRun,
        OpsClawAutonomy::Approve => crate::tools::ssh_tool::OpsClawAutonomy::Approve,
        OpsClawAutonomy::Auto => crate::tools::ssh_tool::OpsClawAutonomy::Auto,
    }
}
