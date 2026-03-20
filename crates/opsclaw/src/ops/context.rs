use crate::openshell::OpenShellContext;
use crate::tools::ssh_tool::{SshCommandRunner, TargetEntry};
use anyhow::{bail, Context, Result};
use zeroclaw::config::schema::{OpsClawAutonomy, TargetConfig, TargetType};
use zeroclaw::config::Config;

/// Central wiring struct that connects Config and SSH tooling.
pub struct OpsClawContext {
    pub config: Config,
    pub openshell: OpenShellContext,
}

impl OpsClawContext {
    /// Load config from disk using default paths.
    pub async fn load() -> Result<Self> {
        let config = Box::pin(Config::load_or_init()).await?;
        let openshell = OpenShellContext::detect();
        Ok(Self { config, openshell })
    }

    /// Construct from pre-built config (useful for testing).
    pub fn new(config: Config) -> Self {
        Self {
            config,
            openshell: OpenShellContext::detect(),
        }
    }

    /// Return the configured targets (empty slice if none).
    pub fn targets(&self) -> &[TargetConfig] {
        match &self.config.targets {
            Some(targets) => targets,
            None => &[],
        }
    }

    /// Look up a target by name, read the decrypted SSH key from config,
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
        let private_key_pem = target
            .key_secret
            .clone()
            .context(format!("SSH target '{}' missing key_secret", target_name))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw::config::schema::{OpsClawAutonomy, TargetConfig, TargetType};

    fn config_with_targets(targets: Vec<TargetConfig>) -> Config {
        let mut cfg = Config::default();
        cfg.targets = Some(targets);
        cfg
    }

    fn ssh_target(name: &str, host: Option<&str>, user: Option<&str>, key: Option<&str>) -> TargetConfig {
        TargetConfig {
            name: name.to_string(),
            target_type: TargetType::Ssh,
            host: host.map(|s| s.to_string()),
            port: None,
            user: user.map(|s| s.to_string()),
            key_secret: key.map(|s| s.to_string()),
            autonomy: OpsClawAutonomy::DryRun,
            context_file: None,
            probes: None,
            data_sources: None,
            escalation: None,
            databases: None,
            kubeconfig: None,
            namespace: None,
        }
    }

    #[test]
    fn ssh_runner_for_missing_host_returns_error() {
        let target = ssh_target("no-host", None, Some("root"), Some("fake-key"));
        let ctx = OpsClawContext::new(config_with_targets(vec![target]));

        let err = ctx.ssh_runner_for("no-host").unwrap_err();
        assert!(err.to_string().contains("missing host"));
    }

    #[test]
    fn ssh_runner_for_valid_ssh_target_returns_runner() {
        let target = ssh_target("prod", Some("10.0.0.1"), Some("deploy"), Some("fake-key-pem"));
        let ctx = OpsClawContext::new(config_with_targets(vec![target]));

        assert!(ctx.ssh_runner_for("prod").is_ok());
    }
}
