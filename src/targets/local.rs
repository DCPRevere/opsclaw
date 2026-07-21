//! `LocalExecutor` — runs commands on the daemon host itself (the `local`
//! target). Transport only: a thin wrapper over `tokio::process::Command`
//! with a timeout. No policy, no audit — that's `policy::execute`'s job; this
//! type is only ever constructed behind it.

use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::process::Command as TokioCommand;

use crate::Result;
use crate::error::Error;
use crate::targets::{Command, ExecOutput, ProbeReport, TargetExecutor};

/// Runs commands via `/bin/sh -c <line>` on the daemon host. There is no
/// credential to resolve — the daemon's own process identity is the
/// authorization boundary, same as any local shell.
pub struct LocalExecutor {
    /// Shell used to interpret `Command::line` (default `/bin/sh`), so tests
    /// can swap in a stub without touching PATH.
    shell: String,
}

impl LocalExecutor {
    pub fn new() -> Self {
        LocalExecutor { shell: "/bin/sh".to_string() }
    }

    /// Construct with an explicit shell binary (tests only, in principle —
    /// production always wants the default `/bin/sh`).
    pub fn with_shell(shell: impl Into<String>) -> Self {
        LocalExecutor { shell: shell.into() }
    }
}

impl Default for LocalExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TargetExecutor for LocalExecutor {
    async fn run(&self, cmd: &Command, timeout: Duration) -> Result<ExecOutput> {
        let start = Instant::now();
        let child = TokioCommand::new(&self.shell)
            .arg("-c")
            .arg(&cmd.line)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::other(format!("local exec spawn failed: {e}")))?;

        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| Error::other(format!("local exec timed out after {timeout:?}")))?
            .map_err(|e| Error::other(format!("local exec failed: {e}")))?;

        Ok(ExecOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn probe(&self) -> Result<ProbeReport> {
        let cmd = Command {
            target: crate::domain::FqTarget::new("local", "local", "local"),
            line: "true".to_string(),
        };
        match self.run(&cmd, Duration::from_secs(5)).await {
            Ok(out) if out.success() => {
                Ok(ProbeReport { reachable: true, detail: "local shell ok".to_string() })
            }
            Ok(out) => Ok(ProbeReport {
                reachable: false,
                detail: format!("local shell exited {}: {}", out.exit_code, out.stderr.trim()),
            }),
            Err(e) => Ok(ProbeReport { reachable: false, detail: e.to_string() }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(line: &str) -> Command {
        Command { target: crate::domain::FqTarget::new("p", "e", "local"), line: line.to_string() }
    }

    #[tokio::test]
    async fn runs_and_captures_output() {
        let exec = LocalExecutor::new();
        let out = exec.run(&cmd("echo hello"), Duration::from_secs(5)).await.unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[tokio::test]
    async fn captures_nonzero_exit_and_stderr() {
        let exec = LocalExecutor::new();
        let out = exec.run(&cmd("echo oops 1>&2; exit 3"), Duration::from_secs(5)).await.unwrap();
        assert_eq!(out.exit_code, 3);
        assert_eq!(out.stderr.trim(), "oops");
    }

    #[tokio::test]
    async fn timeout_is_enforced() {
        let exec = LocalExecutor::new();
        let res = exec.run(&cmd("sleep 5"), Duration::from_millis(50)).await;
        assert!(res.is_err(), "expected a timeout error");
    }

    #[tokio::test]
    async fn probe_reports_reachable() {
        let exec = LocalExecutor::new();
        let report = exec.probe().await.unwrap();
        assert!(report.reachable);
    }

    #[tokio::test]
    async fn bad_shell_probe_reports_unreachable() {
        let exec = LocalExecutor::with_shell("/no/such/shell");
        let report = exec.probe().await.unwrap();
        assert!(!report.reachable);
    }
}
