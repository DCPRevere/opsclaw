//! Monitor tool — runs a discovery scan on a project and returns the raw
//! snapshot as text for the agent to interpret.

use async_trait::async_trait;
use serde_json::json;
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::{OpsConfig, TargetConfig};
use crate::tools::discovery;

/// A tool that scans a project's current state via SSH or Kubernetes and
/// returns the raw snapshot for the agent to analyse.
pub struct MonitorTool {
    config: OpsConfig,
}

impl MonitorTool {
    pub fn new(config: OpsConfig) -> Self {
        Self { config }
    }

    fn resolve_targets(&self, name: &str) -> Result<Vec<&TargetConfig>, String> {
        if name.trim().is_empty() {
            return Err(format!(
                "Unknown project/target '{name}'. {}",
                self.available()
            ));
        }

        if !self.config.projects.is_empty() {
            if let Some(project) = self.config.projects.iter().find(|p| p.name == name) {
                let targets: Vec<&TargetConfig> = project
                    .environments
                    .iter()
                    .flat_map(|env| env.targets.iter())
                    .collect();
                if targets.is_empty() {
                    return Err(format!("Project '{name}' has no targets configured"));
                }
                return Ok(targets);
            }
        }

        match self.config.resolve_target(name) {
            Ok(resolved) => Ok(vec![resolved.target]),
            Err(_) => Err(format!(
                "Unknown project/target '{name}'. {}",
                self.available()
            )),
        }
    }

    fn available(&self) -> String {
        let mut entries = Vec::new();
        for project in &self.config.projects {
            entries.push(project.name.clone());
            for env in &project.environments {
                for target in &env.targets {
                    entries.push(format!("{}::{}::{}", project.name, env.name, target.name));
                    entries.push(target.name.clone());
                }
            }
        }
        if let Some(targets) = self.config.targets.as_ref() {
            entries.extend(targets.iter().map(|target| target.name.clone()));
        }
        entries.sort();
        entries.dedup();

        if entries.is_empty() {
            "Available: none".to_string()
        } else {
            format!("Available: {}", entries.join(", "))
        }
    }
}

#[async_trait]
impl Tool for MonitorTool {
    fn name(&self) -> &str {
        "monitor"
    }

    fn description(&self) -> &str {
        "Scan a project's current state via SSH or Kubernetes. Returns OS info, \
         running containers, services, listening ports, disk usage, memory, load, \
         and Kubernetes resources. Use this to check on the health of a project."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "Name of the project to scan (from config [[projects]])"
                }
            },
            "required": ["project"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let project_name = args
            .get("project")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'project' parameter"))?;

        let targets = match self.resolve_targets(project_name) {
            Ok(targets) => targets,
            Err(error) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(error),
                });
            }
        };

        let mut output = String::new();
        for target in targets {
            let snapshot = match crate::ops_cli::scan_target(&self.config, target).await {
                Ok(snap) => snap,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Scan failed for '{}': {e}", target.name)),
                    });
                }
            };
            if !output.is_empty() {
                output.push_str("\n\n");
            }
            output.push_str(&format!("## Target: {}\n\n", target.name));
            output.push_str(&discovery::snapshot_to_markdown(&snapshot));
        }

        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops_config::{ConnectionType, EnvironmentConfig, OpsClawAutonomy, ProjectConfig};

    fn project(name: &str, connection_type: ConnectionType) -> TargetConfig {
        TargetConfig {
            name: name.to_string(),
            connection_type,
            host: Some("127.0.0.1".into()),
            port: Some(22),
            user: Some("nobody".into()),
            key_secret: None,
            autonomy: OpsClawAutonomy::DryRun,
            context_file: None,
            probes: None,
            data_sources: None,
            escalation: None,
            kubeconfig: None,
            context: None,
            namespace: None,
        }
    }

    fn config_with(targets: Vec<TargetConfig>) -> OpsConfig {
        OpsConfig {
            targets: Some(targets),
            ..OpsConfig::default()
        }
    }

    fn hierarchical_config(project_name: &str, target: TargetConfig) -> OpsConfig {
        let mut config = OpsConfig::default();
        config.projects.push(ProjectConfig {
            name: project_name.to_string(),
            description: None,
            context_file: None,
            owners: None,
            environments: vec![EnvironmentConfig {
                name: "prod".to_string(),
                targets: vec![target],
                ..EnvironmentConfig::default()
            }],
        });
        config
    }

    #[test]
    fn tool_spec_is_valid() {
        let config = OpsConfig::default();
        let tool = MonitorTool::new(config);
        assert_eq!(tool.name(), "monitor");
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["project"].is_object());
        assert_eq!(schema["required"][0], "project");
    }

    #[tokio::test]
    async fn missing_project_arg_is_anyhow_error() {
        let tool = MonitorTool::new(OpsConfig::default());
        let err = tool.execute(json!({})).await.unwrap_err();
        assert!(err.to_string().contains("Missing 'project'"));
    }

    #[tokio::test]
    async fn unknown_project_returns_structured_error_with_available_list() {
        let config = config_with(vec![
            project("web", ConnectionType::Ssh),
            project("db", ConnectionType::Ssh),
        ]);
        let tool = MonitorTool::new(config);
        let r = tool.execute(json!({"project": "nope"})).await.unwrap();
        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("nope"));
        assert!(err.contains("web"));
        assert!(err.contains("db"));
    }

    #[tokio::test]
    async fn unknown_project_when_no_projects_configured() {
        let tool = MonitorTool::new(OpsConfig::default());
        let r = tool.execute(json!({"project": "web"})).await.unwrap();
        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("web"));
        assert!(err.contains("Available:"));
    }

    #[tokio::test]
    async fn unknown_project_lists_hierarchical_projects_and_targets() {
        let tool = MonitorTool::new(hierarchical_config(
            "sacra",
            project("vega", ConnectionType::Ssh),
        ));

        let r = tool.execute(json!({"project": "ghost"})).await.unwrap();

        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("ghost"));
        assert!(err.contains("sacra"));
        assert!(err.contains("sacra::prod::vega"));
        assert!(err.contains("vega"));
    }

    #[tokio::test]
    async fn scan_failure_surfaces_structured_error() {
        // A Kubernetes project with an intentionally bad kubeconfig path —
        // scan_target will fail to build the client, and the tool must wrap
        // that as success=false with a "Scan failed" message.
        let mut p = project("k8s", ConnectionType::Kubernetes);
        p.kubeconfig = Some("/nonexistent/kubeconfig/path".into());
        let tool = MonitorTool::new(config_with(vec![p]));
        let r = tool.execute(json!({"project": "k8s"})).await.unwrap();
        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("Scan failed"));
        assert!(err.contains("k8s"));
    }

    #[tokio::test]
    async fn hierarchical_project_name_resolves_to_project_target() {
        let mut p = project("k8s", ConnectionType::Kubernetes);
        p.kubeconfig = Some("/nonexistent/kubeconfig/path".into());
        let tool = MonitorTool::new(hierarchical_config("sacra", p));

        let r = tool.execute(json!({"project": "sacra"})).await.unwrap();

        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("Scan failed"));
        assert!(err.contains("k8s"));
    }

    #[tokio::test]
    async fn empty_project_name_is_treated_as_unknown() {
        let config = config_with(vec![project("web", ConnectionType::Ssh)]);
        let tool = MonitorTool::new(config);
        let r = tool.execute(json!({"project": ""})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("Unknown project"));
    }
}
