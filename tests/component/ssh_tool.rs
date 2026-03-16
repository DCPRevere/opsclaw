use serde_json::json;
use std::time::Duration;
use zeroclaw::tools::ssh_tool::{
    is_read_only_command, write_audit_entry, OpsClawAutonomy, SshExecutor, SshOutput, SshTool,
    SshToolConfig, TargetEntry,
};
use zeroclaw::tools::traits::Tool;

// ── Mock executor ───────────────────────────────────────

struct MockSshExecutor {
    /// Canned output returned by every call.
    output: SshOutput,
    /// Artificial delay to exercise timeout logic.
    delay: Option<Duration>,
}

impl MockSshExecutor {
    fn ok(stdout: &str) -> Self {
        Self {
            output: SshOutput {
                stdout: stdout.into(),
                stderr: String::new(),
                exit_code: 0,
            },
            delay: None,
        }
    }

    fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

#[async_trait::async_trait]
impl SshExecutor for MockSshExecutor {
    async fn run(
        &self,
        _target: &TargetEntry,
        _command: &str,
        _timeout: Duration,
        _pty: bool,
    ) -> anyhow::Result<SshOutput> {
        if let Some(d) = self.delay {
            tokio::time::sleep(d).await;
        }
        Ok(self.output.clone())
    }
}

// ── Helpers ─────────────────────────────────────────────

fn target(autonomy: OpsClawAutonomy) -> TargetEntry {
    TargetEntry {
        name: "web-1".into(),
        host: "10.0.0.1".into(),
        port: 22,
        user: "deploy".into(),
        private_key_pem: "fake-pem".into(),
        autonomy,
    }
}

fn config(targets: Vec<TargetEntry>) -> SshToolConfig {
    SshToolConfig { targets }
}

// ── Observe-mode filtering ──────────────────────────────

#[test]
fn observe_rejects_rm() {
    assert!(is_read_only_command("rm -rf /tmp").is_err());
}

#[test]
fn observe_rejects_mv() {
    assert!(is_read_only_command("mv a b").is_err());
}

#[test]
fn observe_rejects_docker_restart() {
    assert!(is_read_only_command("docker restart nginx").is_err());
}

#[test]
fn observe_allows_ps_aux() {
    assert!(is_read_only_command("ps aux").is_ok());
}

#[test]
fn observe_allows_docker_ps() {
    assert!(is_read_only_command("docker ps").is_ok());
}

#[test]
fn observe_allows_df_h() {
    assert!(is_read_only_command("df -h").is_ok());
}

// ── Observe-mode enforcement through execute ────────────

#[tokio::test]
async fn execute_observe_blocks_write() {
    let tool = SshTool::with_executor(
        config(vec![target(OpsClawAutonomy::Observe)]),
        Box::new(MockSshExecutor::ok("")),
    );
    let result = tool
        .execute(json!({"target": "web-1", "command": "rm -rf /data"}))
        .await
        .unwrap();
    assert!(!result.success);
    assert!(result.error.as_deref().unwrap().contains("observe mode"));
}

#[tokio::test]
async fn execute_observe_passes_read() {
    let tmp = tempfile::tempdir().unwrap();
    let tool = SshTool::with_executor(
        config(vec![target(OpsClawAutonomy::Observe)]),
        Box::new(MockSshExecutor::ok("load average: 0.1")),
    )
    .with_audit_dir(tmp.path().to_path_buf());
    let result = tool
        .execute(json!({"target": "web-1", "command": "uptime"}))
        .await
        .unwrap();
    assert!(result.success);
    assert!(result.output.contains("load average"));
}

#[tokio::test]
async fn execute_fullauto_allows_write() {
    let tmp = tempfile::tempdir().unwrap();
    let tool = SshTool::with_executor(
        config(vec![target(OpsClawAutonomy::FullAuto)]),
        Box::new(MockSshExecutor::ok("deleted")),
    )
    .with_audit_dir(tmp.path().to_path_buf());
    let result = tool
        .execute(json!({"target": "web-1", "command": "rm -rf /tmp/cache"}))
        .await
        .unwrap();
    assert!(result.success);
}

// ── Audit log format ────────────────────────────────────

#[test]
fn audit_log_contains_expected_fields() {
    let dir = tempfile::tempdir().unwrap();
    write_audit_entry("prod-db", "SELECT 1", 0, 7, Some(&dir.path().to_path_buf())).unwrap();

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let log = std::fs::read_to_string(dir.path().join(format!("{date}.log"))).unwrap();

    assert!(log.contains("TARGET=prod-db"), "missing TARGET");
    assert!(log.contains("CMD=SELECT 1"), "missing CMD");
    assert!(log.contains("EXIT=0"), "missing EXIT");
    assert!(log.contains("DURATION=7ms"), "missing DURATION");
    // ISO 8601 timestamp bracket.
    assert!(log.starts_with('['));
}

#[test]
fn audit_log_is_append_only() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().to_path_buf();
    write_audit_entry("a", "c1", 0, 1, Some(&base)).unwrap();
    write_audit_entry("b", "c2", 1, 2, Some(&base)).unwrap();

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let log = std::fs::read_to_string(dir.path().join(format!("{date}.log"))).unwrap();
    assert_eq!(log.lines().count(), 2);
}

// ── Timeout enforcement ─────────────────────────────────

#[tokio::test]
async fn timeout_triggers_error() {
    let tmp = tempfile::tempdir().unwrap();
    let executor = MockSshExecutor::ok("").with_delay(Duration::from_secs(5));
    let tool = SshTool::with_executor(
        config(vec![target(OpsClawAutonomy::FullAuto)]),
        Box::new(executor),
    )
    .with_timeout(Duration::from_millis(50))
    .with_audit_dir(tmp.path().to_path_buf());

    let result = tool
        .execute(json!({"target": "web-1", "command": "sleep 999"}))
        .await
        .unwrap();
    assert!(!result.success);
    assert!(result.error.as_deref().unwrap().contains("timed out"));
}

// ── Unknown target ──────────────────────────────────────

#[tokio::test]
async fn unknown_target_errors() {
    let tool = SshTool::with_executor(
        config(vec![target(OpsClawAutonomy::FullAuto)]),
        Box::new(MockSshExecutor::ok("")),
    );
    let result = tool
        .execute(json!({"target": "nonexistent", "command": "ls"}))
        .await
        .unwrap();
    assert!(!result.success);
    assert!(result
        .error
        .as_deref()
        .unwrap()
        .contains("unknown SSH target"));
}

// ── Audit log written on successful SSH call ────────────

#[tokio::test]
async fn audit_written_after_execution() {
    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().to_path_buf();
    let tool = SshTool::with_executor(
        config(vec![target(OpsClawAutonomy::FullAuto)]),
        Box::new(MockSshExecutor::ok("ok")),
    )
    .with_audit_dir(audit_path.clone());

    tool.execute(json!({"target": "web-1", "command": "echo hello"}))
        .await
        .unwrap();

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let log_path = audit_path.join(format!("{date}.log"));
    assert!(log_path.exists(), "audit log should exist after execution");
    let log = std::fs::read_to_string(log_path).unwrap();
    assert!(log.contains("CMD=echo hello"));
}
