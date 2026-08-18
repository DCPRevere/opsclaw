//! `SshExecutor` — shells out to the system `ssh` binary. Deliberately not a
//! pure-Rust SSH client (`docs/plans/IMPLEMENTATION.md` §5 decision point):
//! the system binary gets ProxyJump/bastion support, agent auth, and
//! known_hosts handling for free, which matters for example's jumpbox
//! topology (`docs/REFERENCE.md`).
//!
//! Constructed from resolved connection params, never a `SecretRef` —
//! resolution (reading the key material, registering it with the output
//! scrubber) happens once at wiring time in the target registry, not per
//! command.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::process::Command as TokioCommand;

use crate::Result;
use crate::error::Error;
use crate::targets::{Command, ExecOutput, ProbeReport, TargetExecutor};

/// Resolved SSH connection parameters. No [`crate::config::SecretRef`] here —
/// by the time this struct exists, the identity file path has already been
/// resolved and registered with the output scrubber; this type only ever
/// holds paths/strings needed to build an `ssh` argv.
#[derive(Debug, Clone)]
pub struct SshParams {
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    /// Private key file path (resolved). `None` relies on ssh-agent.
    pub identity_file: Option<PathBuf>,
    /// Optional bastion/jump host, `[user@]host[:port]` form, ssh's own
    /// `-J` syntax.
    pub jump_host: Option<String>,
    /// Configurable known_hosts path (brief: per-target, not the operator's
    /// personal `~/.ssh/known_hosts`).
    pub known_hosts_path: Option<PathBuf>,
    /// `StrictHostKeyChecking` value; defaults to `"yes"` when unset — never
    /// silently `"no"` (that would defeat known_hosts pinning).
    pub strict_host_key_checking: Option<String>,
}

pub struct SshExecutor {
    params: SshParams,
    /// Path to the `ssh` binary (default `"ssh"`, resolved via PATH); tests
    /// substitute a stub script.
    ssh_bin: String,
}

impl SshExecutor {
    pub fn new(params: SshParams) -> Self {
        SshExecutor { params, ssh_bin: "ssh".to_string() }
    }

    pub fn with_ssh_bin(params: SshParams, ssh_bin: impl Into<String>) -> Self {
        SshExecutor { params, ssh_bin: ssh_bin.into() }
    }

    /// Build the argv (minus the trailing remote command) common to `run`
    /// and `probe`.
    fn base_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.push("-o".to_string());
        args.push("BatchMode=yes".to_string()); // never block on an interactive prompt
        args.push("-o".to_string());
        args.push(format!(
            "StrictHostKeyChecking={}",
            self.params.strict_host_key_checking.as_deref().unwrap_or("yes")
        ));
        if let Some(kh) = &self.params.known_hosts_path {
            args.push("-o".to_string());
            args.push(format!("UserKnownHostsFile={}", kh.display()));
        }
        if let Some(identity) = &self.params.identity_file {
            args.push("-i".to_string());
            args.push(identity.display().to_string());
        }
        if let Some(jump) = &self.params.jump_host {
            args.push("-J".to_string());
            args.push(jump.clone());
        }
        if let Some(port) = self.params.port {
            args.push("-p".to_string());
            args.push(port.to_string());
        }
        let target = match &self.params.user {
            Some(user) => format!("{user}@{}", self.params.host),
            None => self.params.host.clone(),
        };
        args.push(target);
        args
    }

    async fn run_remote(&self, line: &str, timeout: Duration) -> Result<ExecOutput> {
        let start = Instant::now();
        let mut args = self.base_args();
        args.push(line.to_string());

        let child = TokioCommand::new(&self.ssh_bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::other(format!("ssh spawn failed: {e}")))?;

        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| Error::other(format!("ssh exec timed out after {timeout:?}")))?
            .map_err(|e| Error::other(format!("ssh exec failed: {e}")))?;

        Ok(ExecOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

#[async_trait]
impl TargetExecutor for SshExecutor {
    async fn run(&self, cmd: &Command, timeout: Duration) -> Result<ExecOutput> {
        self.run_remote(&cmd.line, timeout).await
    }

    async fn probe(&self) -> Result<ProbeReport> {
        match self.run_remote("echo ok", Duration::from_secs(10)).await {
            Ok(out) if out.success() && out.stdout.trim() == "ok" => {
                Ok(ProbeReport { reachable: true, detail: format!("ssh ok: {}", self.params.host) })
            }
            Ok(out) => Ok(ProbeReport {
                reachable: false,
                detail: format!(
                    "ssh to {} exited {}: {}",
                    self.params.host,
                    out.exit_code,
                    out.stderr.trim()
                ),
            }),
            Err(e) => Ok(ProbeReport {
                reachable: false,
                detail: format!("ssh to {} failed: {e}", self.params.host),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SshParams {
        SshParams {
            host: "web-1.internal".to_string(),
            port: Some(2222),
            user: Some("opsclaw".to_string()),
            identity_file: Some(PathBuf::from("/etc/opsclaw/keys/web-1")),
            jump_host: Some("bastion@jump.internal".to_string()),
            known_hosts_path: Some(PathBuf::from("/etc/opsclaw/known_hosts")),
            strict_host_key_checking: None,
        }
    }

    #[test]
    fn base_args_include_jump_host_and_identity() {
        let exec = SshExecutor::new(params());
        let args = exec.base_args();
        assert!(args.iter().any(|a| a == "-J"));
        assert!(args.contains(&"bastion@jump.internal".to_string()));
        assert!(args.contains(&"-i".to_string()));
        assert!(args.iter().any(|a| a.contains("web-1")));
        assert!(args.contains(&"opsclaw@web-1.internal".to_string()));
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"2222".to_string()));
    }

    #[test]
    fn strict_host_key_checking_defaults_yes_never_silently_off() {
        let exec = SshExecutor::new(params());
        let args = exec.base_args();
        assert!(args.contains(&"StrictHostKeyChecking=yes".to_string()));
    }

    #[test]
    fn known_hosts_path_is_configurable_not_the_operators_personal_file() {
        let exec = SshExecutor::new(params());
        let args = exec.base_args();
        assert!(args.iter().any(|a| a.starts_with("UserKnownHostsFile=") && a.contains("opsclaw")));
    }

    #[test]
    fn no_jump_host_omits_dash_j() {
        let mut p = params();
        p.jump_host = None;
        let exec = SshExecutor::new(p);
        assert!(!exec.base_args().iter().any(|a| a == "-J"));
    }

    #[tokio::test]
    async fn bad_binary_probe_reports_unreachable_not_a_panic() {
        let exec = SshExecutor::with_ssh_bin(params(), "/no/such/ssh-binary");
        let report = exec.probe().await.unwrap();
        assert!(!report.reachable);
    }
}
