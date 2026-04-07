//! Runbook engine — executable remediation procedures with trigger matching,
//! placeholder resolution, and a persistent JSON store.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::tools::discovery::CommandOutput;
use crate::tools::monitoring::{Alert, AlertCategory};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Runbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trigger: RunbookTrigger,
    pub steps: Vec<RunbookStep>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_executed: Option<DateTime<Utc>>,
    pub execution_count: u32,
    pub success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookTrigger {
    pub alert_categories: Vec<String>,
    pub keywords: Vec<String>,
    pub target_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookStep {
    pub description: String,
    pub command: Option<String>,
    pub expect_exit_code: Option<i32>,
    pub on_failure: StepFailureAction,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepFailureAction {
    Abort,
    Continue,
    Retry { max_attempts: u32, delay_secs: u64 },
}

// ---------------------------------------------------------------------------
// Execution model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookExecution {
    pub runbook_id: String,
    pub target_name: String,
    pub started_at: DateTime<Utc>,
    pub steps_completed: Vec<StepResult>,
    pub status: ExecutionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_index: usize,
    pub description: String,
    pub command: Option<String>,
    pub output: Option<CommandOutput>,
    pub success: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed { step: usize, error: String },
    Aborted,
}

// ---------------------------------------------------------------------------
// Placeholder resolution
// ---------------------------------------------------------------------------

pub struct PlaceholderContext {
    pub values: HashMap<String, String>,
}

impl PlaceholderContext {
    pub fn from_alerts(alerts: &[Alert], target_name: &str) -> Self {
        let mut values = HashMap::new();
        values.insert("target".to_string(), target_name.to_string());
        values.insert("timestamp".to_string(), Utc::now().to_rfc3339());

        // Extract container/service names from alert messages.
        for alert in alerts {
            match alert.category {
                AlertCategory::ContainerDown | AlertCategory::ContainerRestarted => {
                    if let Some(name) = extract_quoted_name(&alert.message) {
                        values.entry("container".to_string()).or_insert(name);
                    }
                }
                AlertCategory::ServiceStopped => {
                    if let Some(name) = extract_quoted_name(&alert.message) {
                        values.entry("service".to_string()).or_insert(name);
                    }
                }
                _ => {}
            }
        }

        Self { values }
    }
}

/// Extract a single-quoted name from an alert message like "Container 'api' is down".
fn extract_quoted_name(msg: &str) -> Option<String> {
    let start = msg.find('\'')?;
    let rest = &msg[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

pub fn resolve_placeholders(command: &str, context: &PlaceholderContext) -> String {
    let mut result = command.to_string();
    for (key, value) in &context.values {
        result = result.replace(&format!("{{{key}}}"), value);
    }
    result
}

// ---------------------------------------------------------------------------
// Trigger matching
// ---------------------------------------------------------------------------

fn alert_category_name(cat: &AlertCategory) -> String {
    // Use serde serialization to get the variant name.
    serde_json::to_value(cat)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn trigger_matches(trigger: &RunbookTrigger, alerts: &[Alert], target_name: &str) -> bool {
    // Check target pattern (glob-style with simple '*' matching).
    if let Some(ref pattern) = trigger.target_pattern {
        if !glob_match(pattern, target_name) {
            return false;
        }
    }

    // Check alert categories.
    let category_match = trigger.alert_categories.is_empty()
        || alerts.iter().any(|a| {
            let name = alert_category_name(&a.category);
            trigger.alert_categories.iter().any(|tc| tc == &name)
        });

    // Check keywords against alert messages.
    let keyword_match = trigger.keywords.is_empty()
        || alerts.iter().any(|a| {
            let msg_lower = a.message.to_lowercase();
            trigger
                .keywords
                .iter()
                .any(|kw| msg_lower.contains(&kw.to_lowercase()))
        });

    category_match && keyword_match
}

/// Simple glob matching: `*` matches any sequence of characters.
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => {
                if i == 0 && idx != 0 {
                    return false; // pattern doesn't start with *, must match from beginning
                }
                pos += idx + part.len();
            }
            None => return false,
        }
    }
    // If pattern doesn't end with *, text must end exactly
    if !pattern.ends_with('*') {
        return text.ends_with(parts.last().unwrap_or(&""));
    }
    true
}

// ---------------------------------------------------------------------------
// Runbook store
// ---------------------------------------------------------------------------

pub struct RunbookStore {
    dir: PathBuf,
}

impl RunbookStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn default_dir() -> Result<PathBuf> {
        let home = directories::UserDirs::new()
            .map(|u| u.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(home.join(".opsclaw").join("runbooks"))
    }

    pub fn load_all(&self) -> Result<Vec<Runbook>> {
        if !self.dir.exists() {
            return Ok(vec![]);
        }
        let mut runbooks = Vec::new();
        for entry in std::fs::read_dir(&self.dir)
            .with_context(|| format!("Failed to read runbook dir: {}", self.dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                match load_runbook_file(&path) {
                    Ok(rb) => runbooks.push(rb),
                    Err(e) => {
                        tracing::warn!("Skipping invalid runbook {}: {e}", path.display());
                    }
                }
            }
        }
        Ok(runbooks)
    }

    pub fn load(&self, id: &str) -> Result<Runbook> {
        let path = self.dir.join(format!("{id}.json"));
        load_runbook_file(&path)
    }

    pub fn save(&self, runbook: &Runbook) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("Failed to create runbook dir: {}", self.dir.display()))?;
        let path = self.dir.join(format!("{}.json", runbook.id));
        let json = serde_json::to_string_pretty(runbook)?;
        std::fs::write(&path, json)
            .with_context(|| format!("Failed to write runbook: {}", path.display()))?;
        Ok(())
    }

    pub fn delete(&self, id: &str) -> Result<bool> {
        let path = self.dir.join(format!("{id}.json"));
        if path.exists() {
            std::fs::remove_file(&path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn match_alerts(&self, alerts: &[Alert], target_name: &str) -> Result<Vec<Runbook>> {
        let all = self.load_all()?;
        Ok(all
            .into_iter()
            .filter(|rb| trigger_matches(&rb.trigger, alerts, target_name))
            .collect())
    }
}

fn load_runbook_file(path: &Path) -> Result<Runbook> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read runbook: {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse runbook: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Execution engine
// ---------------------------------------------------------------------------

pub async fn execute_runbook(
    runner: &dyn crate::tools::discovery::CommandRunner,
    runbook: &Runbook,
    target_name: &str,
    alerts: &[Alert],
) -> Result<RunbookExecution> {
    let context = PlaceholderContext::from_alerts(alerts, target_name);
    let mut execution = RunbookExecution {
        runbook_id: runbook.id.clone(),
        target_name: target_name.to_string(),
        started_at: Utc::now(),
        steps_completed: Vec::new(),
        status: ExecutionStatus::Running,
    };

    for (i, step) in runbook.steps.iter().enumerate() {
        let start = std::time::Instant::now();

        let result = match &step.command {
            Some(cmd) => {
                let resolved = resolve_placeholders(cmd, &context);
                execute_step(runner, &resolved, step).await
            }
            None => {
                // Manual step — record as success (no command to run).
                Ok(StepResult {
                    step_index: i,
                    description: step.description.clone(),
                    command: None,
                    output: None,
                    success: true,
                    duration_ms: 0,
                })
            }
        };

        let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        match result {
            Ok(mut sr) => {
                sr.step_index = i;
                sr.description = step.description.clone();
                sr.duration_ms = elapsed;
                let success = sr.success;
                execution.steps_completed.push(sr);

                if !success {
                    match &step.on_failure {
                        StepFailureAction::Abort => {
                            execution.status = ExecutionStatus::Failed {
                                step: i,
                                error: format!("Step {} failed: {}", i, step.description),
                            };
                            return Ok(execution);
                        }
                        StepFailureAction::Continue => {
                            // proceed
                        }
                        StepFailureAction::Retry {
                            max_attempts,
                            delay_secs,
                        } => {
                            let mut retried = false;
                            for _attempt in 1..=*max_attempts {
                                tokio::time::sleep(tokio::time::Duration::from_secs(*delay_secs))
                                    .await;
                                if let Some(cmd) = &step.command {
                                    let resolved = resolve_placeholders(cmd, &context);
                                    if let Ok(retry_result) =
                                        execute_step(runner, &resolved, step).await
                                    {
                                        if retry_result.success {
                                            let Some(last) =
                                                execution.steps_completed.last_mut()
                                            else {
                                                break;
                                            };
                                            *last = StepResult {
                                                step_index: i,
                                                description: step.description.clone(),
                                                command: Some(resolved),
                                                output: retry_result.output,
                                                success: true,
                                                duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                                            };
                                            retried = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            if !retried {
                                execution.status = ExecutionStatus::Failed {
                                    step: i,
                                    error: format!(
                                        "Step {} failed after retries: {}",
                                        i, step.description
                                    ),
                                };
                                return Ok(execution);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                execution.steps_completed.push(StepResult {
                    step_index: i,
                    description: step.description.clone(),
                    command: step.command.clone(),
                    output: None,
                    success: false,
                    duration_ms: elapsed,
                });
                execution.status = ExecutionStatus::Failed {
                    step: i,
                    error: e.to_string(),
                };
                return Ok(execution);
            }
        }
    }

    execution.status = ExecutionStatus::Completed;
    Ok(execution)
}

async fn execute_step(
    runner: &dyn crate::tools::discovery::CommandRunner,
    command: &str,
    step: &RunbookStep,
) -> Result<StepResult> {
    let output = runner.run(command).await?;
    let expected = step.expect_exit_code.unwrap_or(0);
    let success = output.exit_code == expected;

    Ok(StepResult {
        step_index: 0,
        description: String::new(),
        command: Some(command.to_string()),
        output: Some(output),
        success,
        duration_ms: 0,
    })
}

// ---------------------------------------------------------------------------
// Execution formatting
// ---------------------------------------------------------------------------

pub fn execution_to_markdown(exec: &RunbookExecution, runbook_name: &str) -> String {
    use std::fmt::Write;
    let mut md = String::new();
    let status_label = match &exec.status {
        ExecutionStatus::Running => "RUNNING",
        ExecutionStatus::Completed => "COMPLETED",
        ExecutionStatus::Failed { .. } => "FAILED",
        ExecutionStatus::Aborted => "ABORTED",
    };
    let _ = writeln!(md, "## Runbook: {} — {}\n", runbook_name, status_label);
    let _ = writeln!(
        md,
        "Target: {} | Started: {}\n",
        exec.target_name,
        exec.started_at.format("%H:%M:%S UTC")
    );

    for sr in &exec.steps_completed {
        let icon = if sr.success { "OK" } else { "FAIL" };
        let _ = writeln!(md, "- [{}] {} ({}ms)", icon, sr.description, sr.duration_ms);
        if let Some(ref cmd) = sr.command {
            let _ = writeln!(md, "  Command: `{}`", cmd);
        }
        if let Some(ref out) = sr.output {
            if !out.stdout.trim().is_empty() {
                let _ = writeln!(md, "  stdout: {}", out.stdout.trim());
            }
            if !out.stderr.trim().is_empty() {
                let _ = writeln!(md, "  stderr: {}", out.stderr.trim());
            }
        }
    }

    if let ExecutionStatus::Failed { step, ref error } = exec.status {
        let _ = writeln!(md, "\nFailed at step {}: {}", step, error);
    }

    md
}

// ---------------------------------------------------------------------------
// Default runbooks
// ---------------------------------------------------------------------------

pub fn default_runbooks() -> Vec<Runbook> {
    let now = Utc::now();
    vec![
        Runbook {
            id: "restart-container".to_string(),
            name: "Restart Container".to_string(),
            description: "Restart a stopped Docker container and verify it comes back up."
                .to_string(),
            trigger: RunbookTrigger {
                alert_categories: vec!["ContainerDown".to_string()],
                keywords: vec![],
                target_pattern: None,
            },
            steps: vec![
                RunbookStep {
                    description: "Restart the container".to_string(),
                    command: Some("docker restart {container}".to_string()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 30,
                },
                RunbookStep {
                    description: "Verify container is running".to_string(),
                    command: Some(
                        "docker ps --filter name={container} --format '{{{{.Status}}}}'"
                            .to_string(),
                    ),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 10,
                },
            ],
            created_at: now,
            updated_at: now,
            last_executed: None,
            execution_count: 0,
            success_rate: 0.0,
        },
        Runbook {
            id: "restart-service".to_string(),
            name: "Restart Service".to_string(),
            description: "Restart a stopped systemd service and verify it is active.".to_string(),
            trigger: RunbookTrigger {
                alert_categories: vec!["ServiceStopped".to_string()],
                keywords: vec![],
                target_pattern: None,
            },
            steps: vec![
                RunbookStep {
                    description: "Restart the service".to_string(),
                    command: Some("systemctl restart {service}".to_string()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 30,
                },
                RunbookStep {
                    description: "Verify service is active".to_string(),
                    command: Some("systemctl is-active {service}".to_string()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 10,
                },
            ],
            created_at: now,
            updated_at: now,
            last_executed: None,
            execution_count: 0,
            success_rate: 0.0,
        },
        Runbook {
            id: "clear-disk-space".to_string(),
            name: "Clear Disk Space".to_string(),
            description: "Reclaim disk space by pruning Docker and rotating journal logs."
                .to_string(),
            trigger: RunbookTrigger {
                alert_categories: vec!["DiskSpaceLow".to_string()],
                keywords: vec![],
                target_pattern: None,
            },
            steps: vec![
                RunbookStep {
                    description: "Prune unused Docker resources".to_string(),
                    command: Some("docker system prune -f".to_string()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Continue,
                    timeout_secs: 60,
                },
                RunbookStep {
                    description: "Rotate journal logs".to_string(),
                    command: Some("journalctl --vacuum-size=100M".to_string()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Continue,
                    timeout_secs: 30,
                },
                RunbookStep {
                    description: "Check disk usage again".to_string(),
                    command: Some("df -h".to_string()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 10,
                },
            ],
            created_at: now,
            updated_at: now,
            last_executed: None,
            execution_count: 0,
            success_rate: 0.0,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::discovery::CommandOutput;
    use crate::tools::monitoring::{Alert, AlertCategory, AlertSeverity};

    // -- Trigger matching --

    #[test]
    fn trigger_matches_alert_category() {
        let trigger = RunbookTrigger {
            alert_categories: vec!["ContainerDown".to_string()],
            keywords: vec![],
            target_pattern: None,
        };
        let alerts = vec![Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "Container 'api' is down".into(),
        }];
        assert!(trigger_matches(&trigger, &alerts, "prod-web-1"));
    }

    #[test]
    fn trigger_no_match_wrong_category() {
        let trigger = RunbookTrigger {
            alert_categories: vec!["ServiceStopped".to_string()],
            keywords: vec![],
            target_pattern: None,
        };
        let alerts = vec![Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "Container 'api' is down".into(),
        }];
        assert!(!trigger_matches(&trigger, &alerts, "prod-web-1"));
    }

    #[test]
    fn trigger_matches_keyword() {
        let trigger = RunbookTrigger {
            alert_categories: vec![],
            keywords: vec!["OOM".to_string(), "out of memory".to_string()],
            target_pattern: None,
        };
        let alerts = vec![Alert {
            severity: AlertSeverity::Warning,
            category: AlertCategory::HighMemory,
            message: "Process killed: OOM".into(),
        }];
        assert!(trigger_matches(&trigger, &alerts, "prod"));
    }

    #[test]
    fn trigger_matches_target_pattern() {
        let trigger = RunbookTrigger {
            alert_categories: vec!["DiskSpaceLow".to_string()],
            keywords: vec![],
            target_pattern: Some("prod-*".to_string()),
        };
        let alerts = vec![Alert {
            severity: AlertSeverity::Warning,
            category: AlertCategory::DiskSpaceLow,
            message: "Disk at 92%".into(),
        }];
        assert!(trigger_matches(&trigger, &alerts, "prod-web-1"));
        assert!(!trigger_matches(&trigger, &alerts, "staging-web-1"));
    }

    // -- Placeholder resolution --

    #[test]
    fn resolve_placeholders_basic() {
        let mut ctx = PlaceholderContext {
            values: HashMap::new(),
        };
        ctx.values
            .insert("container".to_string(), "api".to_string());
        ctx.values
            .insert("target".to_string(), "prod-1".to_string());

        let result = resolve_placeholders("docker restart {container}", &ctx);
        assert_eq!(result, "docker restart api");

        let result2 = resolve_placeholders("echo {target} {container}", &ctx);
        assert_eq!(result2, "echo prod-1 api");
    }

    #[test]
    fn placeholder_context_from_alerts() {
        let alerts = vec![Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "Container 'nginx' was running but is now missing".into(),
        }];
        let ctx = PlaceholderContext::from_alerts(&alerts, "prod-web");
        assert_eq!(ctx.values.get("container"), Some(&"nginx".to_string()));
        assert_eq!(ctx.values.get("target"), Some(&"prod-web".to_string()));
    }

    #[test]
    fn placeholder_context_service_extraction() {
        let alerts = vec![Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ServiceStopped,
            message: "Service 'nginx.service' was running but is no longer listed".into(),
        }];
        let ctx = PlaceholderContext::from_alerts(&alerts, "prod");
        assert_eq!(
            ctx.values.get("service"),
            Some(&"nginx.service".to_string())
        );
    }

    // -- Execution --

    struct MockRunner {
        responses: std::sync::Mutex<Vec<CommandOutput>>,
    }

    impl MockRunner {
        fn new(responses: Vec<CommandOutput>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::tools::discovery::CommandRunner for MockRunner {
        async fn run(&self, _command: &str) -> Result<CommandOutput> {
            let mut resps = self.responses.lock().unwrap();
            if resps.is_empty() {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                })
            } else {
                Ok(resps.remove(0))
            }
        }
    }

    #[tokio::test]
    async fn execute_runbook_all_steps_succeed() {
        let runner = MockRunner::new(vec![
            CommandOutput {
                stdout: "api\n".into(),
                stderr: String::new(),
                exit_code: 0,
            },
            CommandOutput {
                stdout: "Up 2 seconds\n".into(),
                stderr: String::new(),
                exit_code: 0,
            },
        ]);

        let rb = Runbook {
            id: "test-rb".into(),
            name: "Test".into(),
            description: "Test runbook".into(),
            trigger: RunbookTrigger {
                alert_categories: vec![],
                keywords: vec![],
                target_pattern: None,
            },
            steps: vec![
                RunbookStep {
                    description: "Restart".into(),
                    command: Some("docker restart {container}".into()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 10,
                },
                RunbookStep {
                    description: "Verify".into(),
                    command: Some("docker ps".into()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 10,
                },
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_executed: None,
            execution_count: 0,
            success_rate: 0.0,
        };

        let alerts = vec![Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "Container 'api' is down".into(),
        }];

        let exec = execute_runbook(&runner, &rb, "prod", &alerts)
            .await
            .unwrap();
        assert!(matches!(exec.status, ExecutionStatus::Completed));
        assert_eq!(exec.steps_completed.len(), 2);
        assert!(exec.steps_completed.iter().all(|s| s.success));
    }

    #[tokio::test]
    async fn execute_runbook_abort_on_failure() {
        let runner = MockRunner::new(vec![CommandOutput {
            stdout: String::new(),
            stderr: "Error: No such container".into(),
            exit_code: 1,
        }]);

        let rb = Runbook {
            id: "test-fail".into(),
            name: "Test Fail".into(),
            description: "Fails on first step".into(),
            trigger: RunbookTrigger {
                alert_categories: vec![],
                keywords: vec![],
                target_pattern: None,
            },
            steps: vec![
                RunbookStep {
                    description: "Will fail".into(),
                    command: Some("docker restart bad".into()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 10,
                },
                RunbookStep {
                    description: "Should not run".into(),
                    command: Some("echo done".into()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 10,
                },
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_executed: None,
            execution_count: 0,
            success_rate: 0.0,
        };

        let exec = execute_runbook(&runner, &rb, "prod", &[]).await.unwrap();
        assert!(matches!(
            exec.status,
            ExecutionStatus::Failed { step: 0, .. }
        ));
        assert_eq!(exec.steps_completed.len(), 1);
    }

    #[tokio::test]
    async fn execute_runbook_continue_on_failure() {
        let runner = MockRunner::new(vec![
            CommandOutput {
                stdout: String::new(),
                stderr: "not found".into(),
                exit_code: 1,
            },
            CommandOutput {
                stdout: "ok\n".into(),
                stderr: String::new(),
                exit_code: 0,
            },
        ]);

        let rb = Runbook {
            id: "test-continue".into(),
            name: "Test Continue".into(),
            description: "Continues past failure".into(),
            trigger: RunbookTrigger {
                alert_categories: vec![],
                keywords: vec![],
                target_pattern: None,
            },
            steps: vec![
                RunbookStep {
                    description: "May fail".into(),
                    command: Some("docker system prune -f".into()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Continue,
                    timeout_secs: 10,
                },
                RunbookStep {
                    description: "Should still run".into(),
                    command: Some("df -h".into()),
                    expect_exit_code: Some(0),
                    on_failure: StepFailureAction::Abort,
                    timeout_secs: 10,
                },
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_executed: None,
            execution_count: 0,
            success_rate: 0.0,
        };

        let exec = execute_runbook(&runner, &rb, "prod", &[]).await.unwrap();
        assert!(matches!(exec.status, ExecutionStatus::Completed));
        assert_eq!(exec.steps_completed.len(), 2);
        assert!(!exec.steps_completed[0].success);
        assert!(exec.steps_completed[1].success);
    }

    // -- Store --

    #[test]
    fn store_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = RunbookStore::new(dir.path().to_path_buf());

        let rb = default_runbooks().into_iter().next().unwrap();
        store.save(&rb).unwrap();

        let loaded = store.load(&rb.id).unwrap();
        assert_eq!(loaded.id, rb.id);
        assert_eq!(loaded.name, rb.name);
        assert_eq!(loaded.steps.len(), rb.steps.len());
    }

    #[test]
    fn store_load_all() {
        let dir = tempfile::tempdir().unwrap();
        let store = RunbookStore::new(dir.path().to_path_buf());

        for rb in default_runbooks() {
            store.save(&rb).unwrap();
        }

        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn store_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = RunbookStore::new(dir.path().to_path_buf());

        let rb = default_runbooks().into_iter().next().unwrap();
        store.save(&rb).unwrap();
        assert!(store.delete(&rb.id).unwrap());
        assert!(!store.delete(&rb.id).unwrap());
    }

    #[test]
    fn store_match_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let store = RunbookStore::new(dir.path().to_path_buf());

        for rb in default_runbooks() {
            store.save(&rb).unwrap();
        }

        let alerts = vec![Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "Container 'api' is down".into(),
        }];

        let matched = store.match_alerts(&alerts, "prod-web").unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id, "restart-container");
    }

    // -- Default runbooks --

    #[test]
    fn default_runbooks_are_valid() {
        let defaults = default_runbooks();
        assert_eq!(defaults.len(), 3);
        for rb in &defaults {
            assert!(!rb.id.is_empty());
            assert!(!rb.name.is_empty());
            assert!(!rb.steps.is_empty());
            assert!(!rb.trigger.alert_categories.is_empty());
            // Verify serialization round-trip
            let json = serde_json::to_string(rb).unwrap();
            let _: Runbook = serde_json::from_str(&json).unwrap();
        }
    }

    // -- Glob matching --

    #[test]
    fn glob_match_patterns() {
        assert!(glob_match("prod-*", "prod-web-1"));
        assert!(glob_match("prod-*", "prod-"));
        assert!(!glob_match("prod-*", "staging-web"));
        assert!(glob_match("*-web-*", "prod-web-1"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "not-exact"));
    }

    // -- extract_quoted_name --

    #[test]
    fn extract_quoted_name_works() {
        assert_eq!(
            extract_quoted_name("Container 'api' is down"),
            Some("api".to_string())
        );
        assert_eq!(extract_quoted_name("No quotes here"), None);
    }
}
