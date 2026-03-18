//! Docker inspect deploy-timestamp data source.
//!
//! Runs `docker inspect {container}` via the existing SSH/local command runner
//! and parses `.State.StartedAt` to determine when each container last started.
//! This provides zero-config deploy timestamps without CI integration.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::tools::discovery::CommandRunner;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStartTime {
    pub container: String,
    pub started_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Docker inspect JSON shape (minimal)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InspectOutput {
    #[serde(rename = "State")]
    state: InspectState,
}

#[derive(Debug, Deserialize)]
struct InspectState {
    #[serde(rename = "StartedAt")]
    started_at: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run `docker inspect` for each container and return start times.
pub async fn fetch_start_times(
    runner: &dyn CommandRunner,
    containers: &[String],
) -> Result<Vec<ContainerStartTime>> {
    let mut results = Vec::new();

    for name in containers {
        let cmd = format!("docker inspect {name}");
        let output = match runner.run(&cmd).await {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("docker inspect {name} failed: {e:#}");
                continue;
            }
        };

        // docker inspect returns a JSON array with one element.
        let items: Vec<InspectOutput> = match serde_json::from_str(&output.stdout) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("failed to parse docker inspect output for {name}: {e:#}");
                continue;
            }
        };

        if let Some(item) = items.first() {
            let started_at = DateTime::parse_from_rfc3339(&item.state.started_at)
                .map(|dt| dt.with_timezone(&Utc))
                .context(format!(
                    "failed to parse StartedAt for container {name}: {}",
                    item.state.started_at
                ))?;

            results.push(ContainerStartTime {
                container: name.clone(),
                started_at,
            });
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::discovery::CommandOutput;
    use async_trait::async_trait;

    struct MockRunner {
        response: String,
    }

    #[async_trait]
    impl CommandRunner for MockRunner {
        async fn run(&self, _command: &str) -> Result<CommandOutput> {
            Ok(CommandOutput {
                stdout: self.response.clone(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }

    #[tokio::test]
    async fn parse_docker_inspect_output() {
        let json = r#"[{"State":{"StartedAt":"2024-03-17T12:00:00.123456789Z"}}]"#;
        let runner = MockRunner {
            response: json.into(),
        };

        let results = fetch_start_times(&runner, &["my-app".into()])
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].container, "my-app");
        assert_eq!(results[0].started_at.timestamp(), 1710676800);
    }

    #[test]
    fn deserialize_inspect_output() {
        let json = r#"{"State":{"StartedAt":"2024-03-17T12:00:00Z"}}"#;
        let item: InspectOutput = serde_json::from_str(json).unwrap();
        assert_eq!(item.state.started_at, "2024-03-17T12:00:00Z");
    }
}
