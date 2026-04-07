//! [`CommandRunner`] implementations backed by SSH and local shell execution.
//!
//! - [`SshCommandRunner`] connects to a remote host via the [`SshExecutor`]
//!   abstraction (same one used by [`SshTool`]).
//! - [`LocalCommandRunner`] runs commands on the local machine via
//!   `tokio::process::Command` (sidecar mode).
//!
//! Both enforce the dry-run-mode read-only allowlist and write to the
//! append-only audit log.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use async_trait::async_trait;

use super::discovery::{CommandOutput, CommandRunner};
use crate::ops_config::OpsClawAutonomy;
use super::ssh_tool::{
    is_read_only_command, write_audit_entry, SshExecutor, ProjectEntry,
};

// ---------------------------------------------------------------------------
// SshCommandRunner
// ---------------------------------------------------------------------------

/// Executes commands on a remote host via SSH, implementing [`CommandRunner`].
pub struct SshCommandRunner {
    project: ProjectEntry,
    executor: Box<dyn SshExecutor>,
    timeout: Duration,
    audit_dir: Option<PathBuf>,
}

impl SshCommandRunner {
    pub fn new(project: ProjectEntry, executor: Box<dyn SshExecutor>) -> Self {
        Self {
            timeout: Duration::from_secs(30),
            project,
            executor,
            audit_dir: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_audit_dir(mut self, dir: PathBuf) -> Self {
        self.audit_dir = Some(dir);
        self
    }
}

#[async_trait]
impl CommandRunner for SshCommandRunner {
    async fn run(&self, command: &str) -> Result<CommandOutput> {
        // Autonomy enforcement — DryRun is normally intercepted by the
        // DryRunCommandRunner wrapper, but guard here as a safety net.
        if self.project.autonomy == OpsClawAutonomy::DryRun {
            if let Err(reason) = is_read_only_command(command) {
                bail!("dry-run mode: {reason}");
            }
        }

        let start = std::time::Instant::now();

        let result = tokio::time::timeout(
            self.timeout,
            self.executor
                .run(&self.project, command, self.timeout, false),
        )
        .await;

        let elapsed_ms = start.elapsed().as_millis();

        match result {
            Ok(Ok(output)) => {
                let _ = write_audit_entry(
                    &self.project.name,
                    command,
                    output.exit_code,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );
                Ok(CommandOutput {
                    stdout: output.stdout,
                    stderr: output.stderr,
                    exit_code: output.exit_code,
                })
            }
            Ok(Err(e)) => {
                let _ = write_audit_entry(
                    &self.project.name,
                    command,
                    -1,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );
                bail!("SSH execution failed: {e}");
            }
            Err(_) => {
                let _ = write_audit_entry(
                    &self.project.name,
                    command,
                    -1,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );
                bail!("command timed out after {}s", self.timeout.as_secs());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LocalCommandRunner
// ---------------------------------------------------------------------------

/// Executes commands on the local machine (sidecar mode), implementing
/// [`CommandRunner`].
pub struct LocalCommandRunner {
    pub autonomy: OpsClawAutonomy,
    pub project_name: String,
    pub timeout_secs: u64,
    audit_dir: Option<PathBuf>,
}

impl LocalCommandRunner {
    pub fn new(autonomy: OpsClawAutonomy, project_name: String) -> Self {
        Self {
            autonomy,
            project_name,
            timeout_secs: 30,
            audit_dir: None,
        }
    }

    pub fn with_timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_audit_dir(mut self, dir: PathBuf) -> Self {
        self.audit_dir = Some(dir);
        self
    }
}

#[async_trait]
impl CommandRunner for LocalCommandRunner {
    async fn run(&self, command: &str) -> Result<CommandOutput> {
        // Autonomy enforcement — DryRun is normally intercepted by the
        // DryRunCommandRunner wrapper, but guard here as a safety net.
        if self.autonomy == OpsClawAutonomy::DryRun {
            if let Err(reason) = is_read_only_command(command) {
                bail!("dry-run mode: {reason}");
            }
        }

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(self.timeout_secs);

        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let result = tokio::time::timeout(timeout, child.wait_with_output()).await;
        let elapsed_ms = start.elapsed().as_millis();

        match result {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                let _ = write_audit_entry(
                    &self.project_name,
                    command,
                    exit_code,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );
                Ok(CommandOutput {
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    exit_code,
                })
            }
            Ok(Err(e)) => {
                let _ = write_audit_entry(
                    &self.project_name,
                    command,
                    -1,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );
                bail!("local execution failed: {e}");
            }
            Err(_) => {
                let _ = write_audit_entry(
                    &self.project_name,
                    command,
                    -1,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );
                bail!("command timed out after {}s", self.timeout_secs);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DryRunCommandRunner
// ---------------------------------------------------------------------------

/// Wraps any [`CommandRunner`] to intercept write commands in dry-run mode.
///
/// Read-only commands are forwarded to the inner runner; write commands are
/// logged to an append-only audit file and a synthetic `[DRY RUN]` response is
/// returned without executing anything.
pub struct DryRunCommandRunner {
    inner: Box<dyn CommandRunner>,
    audit_log: PathBuf,
}

impl DryRunCommandRunner {
    pub fn new(inner: Box<dyn CommandRunner>, audit_log: PathBuf) -> Self {
        Self { inner, audit_log }
    }
}

#[async_trait]
impl CommandRunner for DryRunCommandRunner {
    async fn run(&self, command: &str) -> Result<CommandOutput> {
        if is_read_only_command(command).is_ok() {
            // Read-only: execute normally.
            self.inner.run(command).await
        } else {
            // Write command: log but don't execute.
            let entry = format!(
                "[{}] WOULD_HAVE: {}\n",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                command,
            );
            if let Some(parent) = self.audit_log.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.audit_log)?;
            std::io::Write::write_all(&mut file, entry.as_bytes())?;

            Ok(CommandOutput {
                stdout: format!("[DRY RUN] Would execute: {command}"),
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ssh_tool::SshOutput;

    fn test_project(autonomy: OpsClawAutonomy) -> ProjectEntry {
        ProjectEntry {
            name: "test-host".into(),
            host: "127.0.0.1".into(),
            port: 22,
            user: "root".into(),
            private_key_pem: "fake".into(),
            autonomy,
        }
    }

    struct StubExecutor {
        output: SshOutput,
        delay: Option<Duration>,
    }

    impl StubExecutor {
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

        fn with_delay(mut self, d: Duration) -> Self {
            self.delay = Some(d);
            self
        }
    }

    #[async_trait]
    impl SshExecutor for StubExecutor {
        async fn run(
            &self,
            _project: &ProjectEntry,
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

    // ── SshCommandRunner ─────────────────────────────────

    #[tokio::test]
    async fn ssh_runner_observe_rejects_write() {
        let runner = SshCommandRunner::new(
            test_project(OpsClawAutonomy::DryRun),
            Box::new(StubExecutor::ok("")),
        );
        let err = runner.run("rm -rf /tmp").await.unwrap_err();
        assert!(err.to_string().contains("dry-run mode"));
    }

    #[tokio::test]
    async fn ssh_runner_observe_allows_read() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = SshCommandRunner::new(
            test_project(OpsClawAutonomy::DryRun),
            Box::new(StubExecutor::ok("hello")),
        )
        .with_audit_dir(tmp.path().to_path_buf());

        let out = runner.run("echo hello").await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, "hello");
    }

    #[tokio::test]
    async fn ssh_runner_timeout() {
        let runner = SshCommandRunner::new(
            test_project(OpsClawAutonomy::Auto),
            Box::new(StubExecutor::ok("").with_delay(Duration::from_secs(5))),
        )
        .with_timeout(Duration::from_millis(50));

        let err = runner.run("sleep 999").await.unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }

    // ── LocalCommandRunner ───────────────────────────────

    #[tokio::test]
    async fn local_runner_observe_rejects_write() {
        let runner = LocalCommandRunner::new(OpsClawAutonomy::DryRun, "local".into());
        let err = runner.run("rm -rf /tmp").await.unwrap_err();
        assert!(err.to_string().contains("dry-run mode"));
    }

    #[tokio::test]
    async fn local_runner_runs_echo() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = LocalCommandRunner::new(OpsClawAutonomy::Auto, "local".into())
            .with_audit_dir(tmp.path().to_path_buf());

        let out = runner.run("echo hello").await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[tokio::test]
    async fn local_runner_captures_stderr() {
        let runner = LocalCommandRunner::new(OpsClawAutonomy::Auto, "local".into());
        let out = runner.run("echo err >&2").await.unwrap();
        assert!(out.stderr.contains("err"));
    }

    #[tokio::test]
    async fn local_runner_captures_exit_code() {
        let runner = LocalCommandRunner::new(OpsClawAutonomy::Auto, "local".into());
        let out = runner.run("exit 42").await.unwrap();
        assert_eq!(out.exit_code, 42);
    }

    // ── DryRunCommandRunner ─────────────────────────────

    #[tokio::test]
    async fn dry_run_passes_read_through() {
        let inner = LocalCommandRunner::new(OpsClawAutonomy::Auto, "local".into());
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("dry-run.log");
        let runner = DryRunCommandRunner::new(Box::new(inner), log_path.clone());

        let out = runner.run("echo hello").await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout.trim(), "hello");
        // No dry-run log written for read-only commands.
        assert!(!log_path.exists());
    }

    #[tokio::test]
    async fn dry_run_intercepts_write() {
        let inner = LocalCommandRunner::new(OpsClawAutonomy::Auto, "local".into());
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("dry-run.log");
        let runner = DryRunCommandRunner::new(Box::new(inner), log_path.clone());

        let out = runner.run("rm -rf /tmp/data").await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("[DRY RUN]"));
        assert!(out.stdout.contains("rm -rf /tmp/data"));
    }

    #[tokio::test]
    async fn dry_run_appends_to_log() {
        let inner = LocalCommandRunner::new(OpsClawAutonomy::Auto, "local".into());
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("dry-run.log");
        let runner = DryRunCommandRunner::new(Box::new(inner), log_path.clone());

        runner.run("rm -rf /tmp/a").await.unwrap();
        runner.run("systemctl restart nginx").await.unwrap();

        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(log.contains("WOULD_HAVE: rm -rf /tmp/a"));
        assert!(log.contains("WOULD_HAVE: systemctl restart nginx"));
    }
}
