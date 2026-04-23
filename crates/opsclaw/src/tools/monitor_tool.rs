//! Monitor tool — runs a discovery scan on a project and returns the raw
//! snapshot as text for the agent to interpret.

use async_trait::async_trait;
use serde_json::json;
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsConfig;
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

        let projects = self.config.targets.as_deref().unwrap_or_default();
        let project = match projects.iter().find(|p| p.name == project_name) {
            Some(p) => p,
            None => {
                let available: Vec<&str> = projects.iter().map(|p| p.name.as_str()).collect();
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Unknown project '{project_name}'. Available: {}",
                        available.join(", ")
                    )),
                });
            }
        };

        let snapshot = match crate::ops_cli::scan_target(&self.config, project).await {
            Ok(snap) => snap,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Scan failed for '{project_name}': {e}")),
                });
            }
        };

        let output = discovery::snapshot_to_markdown(&snapshot);

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

    #[test]
    fn tool_spec_is_valid() {
        let config = OpsConfig::default();
        let tool = MonitorTool::new(config);
        assert_eq!(tool.name(), "monitor");
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["project"].is_object());
    }
}
