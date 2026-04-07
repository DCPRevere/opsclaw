use crate::openshell::OpenShellContext;
use crate::tools::ssh_tool::{SshCommandRunner, ProjectEntry};
use anyhow::{bail, Context, Result};
use crate::ops_config::{OpsConfig, ProjectConfig, ProjectType};
use zeroclaw::config::Config;

/// Central wiring struct that connects Config and SSH tooling.
pub struct OpsClawContext {
    pub config: OpsConfig,
    pub openshell: OpenShellContext,
}

impl OpsClawContext {
    /// Load config from disk using default paths.
    pub async fn load() -> Result<Self> {
        let inner = Box::pin(Config::load_or_init()).await?;
        let config = OpsConfig {
            inner,
            projects: None,
            notifications: None,
            diagnosis: Default::default(),
            a2a: None,
        };
        let openshell = OpenShellContext::detect();
        Ok(Self { config, openshell })
    }

    /// Construct from pre-built config (useful for testing).
    pub fn new(config: OpsConfig) -> Self {
        Self {
            config,
            openshell: OpenShellContext::detect(),
        }
    }

    /// Return the configured projects (empty slice if none).
    pub fn projects(&self) -> &[ProjectConfig] {
        match &self.config.projects {
            Some(projects) => projects,
            None => &[],
        }
    }

    /// Look up a project by name, read the decrypted SSH key from config,
    /// and return a configured `SshCommandRunner` ready to execute commands.
    pub fn ssh_runner_for(&self, project_name: &str) -> Result<SshCommandRunner> {
        let project = self.find_project(project_name)?;

        if project.project_type != ProjectType::Ssh {
            bail!("project '{}' is not an SSH project", project_name);
        }

        let host = project
            .host
            .as_deref()
            .context(format!("SSH project '{}' missing host", project_name))?;
        let user = project
            .user
            .as_deref()
            .context(format!("SSH project '{}' missing user", project_name))?;
        let private_key_pem = project
            .key_secret
            .clone()
            .context(format!("SSH project '{}' missing key_secret", project_name))?;

        let entry = ProjectEntry {
            name: project.name.clone(),
            host: host.to_string(),
            port: project.port.unwrap_or(22),
            user: user.to_string(),
            private_key_pem,
            autonomy: project.autonomy,
        };

        Ok(SshCommandRunner::new(entry))
    }

    /// Read the context file for a project and return its contents.
    pub fn context_for(&self, project_name: &str) -> Result<String> {
        let project = self.find_project(project_name)?;

        let context_path = project.context_file.as_deref().context(format!(
            "project '{}' has no context_file configured",
            project_name
        ))?;

        std::fs::read_to_string(context_path)
            .context(format!("failed to read context file '{}'", context_path))
    }

    fn find_project(&self, name: &str) -> Result<&ProjectConfig> {
        self.projects()
            .iter()
            .find(|t| t.name == name)
            .context(format!("project '{}' not found in config", name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
use crate::ops_config::{OpsClawAutonomy, ProjectConfig, ProjectType};
use crate::ops_config::OpsConfig;

    fn config_with_projects(projects: Vec<ProjectConfig>) -> OpsConfig {
        let mut cfg = OpsConfig::default();
        cfg.projects = Some(projects);
        cfg
    }

    fn ssh_project(name: &str, host: Option<&str>, user: Option<&str>, key: Option<&str>) -> ProjectConfig {
        ProjectConfig {
            name: name.to_string(),
            project_type: ProjectType::Ssh,
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
        let project = ssh_project("no-host", None, Some("root"), Some("fake-key"));
        let ctx = OpsClawContext::new(config_with_projects(vec![project]));

        let err = ctx.ssh_runner_for("no-host").unwrap_err();
        assert!(err.to_string().contains("missing host"));
    }

    #[test]
    fn ssh_runner_for_valid_ssh_target_returns_runner() {
        let project = ssh_project("prod", Some("10.0.0.1"), Some("deploy"), Some("fake-key-pem"));
        let ctx = OpsClawContext::new(config_with_projects(vec![project]));

        assert!(ctx.ssh_runner_for("prod").is_ok());
    }
}
