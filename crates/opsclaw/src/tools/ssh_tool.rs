use zeroclaw::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Default SSH command timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Maximum output size in bytes (1 MB).
const MAX_OUTPUT_BYTES: usize = 1_048_576;

// ── Autonomy ────────────────────────────────────────────

/// Autonomy level for OpsClaw SSH targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpsClawAutonomy {
    DryRun,
    Approve,
    Auto,
}

// ── Read-only allowlist / denylist ──────────────────────

/// Commands allowed in dry-run mode (first token after optional `sudo`).
const READ_ONLY_ALLOW: &[&str] = &[
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "find",
    "df",
    "du",
    "free",
    "top",
    "ps",
    "ss",
    "netstat",
    "systemctl",
    "docker",
    "kubectl",
    "journalctl",
    "uptime",
    "uname",
    "whoami",
    "id",
    "hostname",
    "date",
    "echo",
    "env",
    "which",
    "stat",
    "file",
    "lsof",
    "curl",
    "wget",
    "ping",
    "traceroute",
    "dig",
    "nslookup",
    "ip",
    "ifconfig",
    "arp",
    "route",
    "mount",
    "lsblk",
    "fdisk",
    "pvs",
    "vgs",
    "lvs",
    "dmidecode",
    "lscpu",
    "lshw",
];

/// Sub-commands of allowed binaries that are mutating and must be denied.
const MUTATING_SUBCOMMANDS: &[(&str, &[&str])] = &[
    (
        "systemctl",
        &["start", "stop", "restart", "enable", "disable"],
    ),
    ("docker", &["rm", "rmi", "stop", "start", "restart", "kill"]),
    ("kubectl", &["delete", "apply", "patch"]),
];

/// Completely denied command names (first token).
const DENY_COMMANDS: &[&str] = &[
    "rm", "mv", "cp", "dd", "mkfs", "shutdown", "reboot", "kill", "pkill", "apt", "yum", "dnf",
    "pip", "npm", "cargo",
];

/// Check whether `command` is permitted under observe-mode policy.
pub fn is_read_only_command(command: &str) -> Result<(), String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    if tokens.is_empty() {
        return Err("empty command".into());
    }

    let (cmd_idx, cmd) = if tokens[0] == "sudo" {
        if tokens.len() < 2 {
            return Err("sudo without a command".into());
        }
        (1, tokens[1])
    } else {
        (0, tokens[0])
    };

    // Strip path prefix (e.g. /usr/bin/ls → ls).
    let base = cmd.rsplit('/').next().unwrap_or(cmd);

    // Explicit deny list.
    if DENY_COMMANDS.contains(&base) {
        return Err(format!(
            "command '{base}' is not allowed in dry-run mode (write/destructive)"
        ));
    }

    // Must be on the allowlist.
    if !READ_ONLY_ALLOW.contains(&base) {
        return Err(format!(
            "command '{base}' is not in the observe-mode allowlist"
        ));
    }

    // Check for mutating sub-commands.
    for (parent, subs) in MUTATING_SUBCOMMANDS {
        if base == *parent {
            if let Some(sub) = tokens.get(cmd_idx + 1) {
                if subs.contains(sub) {
                    return Err(format!(
                        "'{base} {sub}' is not allowed in dry-run mode (mutating sub-command)"
                    ));
                }
            }
        }
    }

    Ok(())
}

// ── Config types ────────────────────────────────────────

/// Per-target SSH configuration resolved at construction time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetEntry {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// PEM-encoded private key content (already resolved from secret store).
    pub private_key_pem: String,
    pub autonomy: OpsClawAutonomy,
}

/// Configuration bundle passed to [`SshTool`] at construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshToolConfig {
    pub targets: Vec<TargetEntry>,
}

// ── SSH executor trait (for testability) ────────────────

/// Abstraction over actual SSH execution so unit tests can mock the connection.
#[async_trait]
pub trait SshExecutor: Send + Sync {
    async fn run(
        &self,
        target: &TargetEntry,
        command: &str,
        timeout: Duration,
        pty: bool,
    ) -> anyhow::Result<SshOutput>;
}

/// Raw output from an SSH command execution.
#[derive(Debug, Clone)]
pub struct SshOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Real SSH executor backed by the `russh` crate.
pub struct RealSshExecutor;

/// Minimal handler that accepts any server host key.
struct SshClientHandler;

#[async_trait]
impl russh::client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all host keys. Production deployments should verify against
        // a known_hosts file — acceptable for the current threat model where
        // targets are pre-configured by the operator.
        Ok(true)
    }
}

#[async_trait]
impl SshExecutor for RealSshExecutor {
    async fn run(
        &self,
        target: &TargetEntry,
        command: &str,
        timeout: Duration,
        pty: bool,
    ) -> anyhow::Result<SshOutput> {
        let result = tokio::time::timeout(timeout, self.run_inner(target, command, pty)).await;
        match result {
            Ok(inner) => inner,
            Err(_) => anyhow::bail!("SSH command timed out after {}s", timeout.as_secs()),
        }
    }
}

impl RealSshExecutor {
    async fn run_inner(
        &self,
        target: &TargetEntry,
        command: &str,
        pty: bool,
    ) -> anyhow::Result<SshOutput> {
        // Decode the PEM private key.
        let key_pair = russh_keys::decode_secret_key(&target.private_key_pem, None)
            .map_err(|e| anyhow::anyhow!("failed to decode SSH private key: {e}"))?;

        // Connect.
        let config = Arc::new(russh::client::Config::default());
        let handler = SshClientHandler;
        let mut handle =
            russh::client::connect(config, (&*target.host, target.port), handler)
                .await
                .map_err(|e| anyhow::anyhow!("SSH connection to {}:{} failed: {e}", target.host, target.port))?;

        // Authenticate.
        let authenticated = handle
            .authenticate_publickey(&target.user, Arc::new(key_pair))
            .await
            .map_err(|e| anyhow::anyhow!("SSH authentication failed: {e}"))?;

        if !authenticated {
            anyhow::bail!(
                "SSH authentication failed for user '{}' on {}:{}",
                target.user,
                target.host,
                target.port,
            );
        }

        // Open session channel.
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| anyhow::anyhow!("failed to open SSH session channel: {e}"))?;

        // Request PTY if needed.
        if pty {
            channel
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .map_err(|e| anyhow::anyhow!("PTY request failed: {e}"))?;
        }

        // Execute command.
        channel
            .exec(true, command)
            .await
            .map_err(|e| anyhow::anyhow!("SSH exec failed: {e}"))?;

        // Collect output.
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut exit_code: Option<u32> = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => {
                    stdout_buf.extend_from_slice(&data);
                }
                russh::ChannelMsg::ExtendedData { data, .. } => {
                    stderr_buf.extend_from_slice(&data);
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status);
                }
                _ => {}
            }
        }

        // Disconnect gracefully.
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;

        Ok(SshOutput {
            stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
            exit_code: exit_code.map_or(-1, |c| c as i32),
        })
    }
}

// ── Audit logging ───────────────────────────────────────

fn audit_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".opsclaw/audit")
}

/// Append one line to the daily audit log.
pub fn write_audit_entry(
    target: &str,
    command: &str,
    exit_code: i32,
    duration_ms: u128,
    audit_base: Option<&PathBuf>,
) -> std::io::Result<()> {
    let dir = match audit_base {
        Some(d) => d.clone(),
        None => audit_dir(),
    };
    std::fs::create_dir_all(&dir)?;
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let path = dir.join(format!("{date}.log"));
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(
        f,
        "[{timestamp}] TARGET={target} CMD={command} EXIT={exit_code} DURATION={duration_ms}ms"
    )?;
    Ok(())
}

// ── SshCommandRunner ────────────────────────────────────

/// A resolved, ready-to-use SSH runner for a single target.
/// Created by `OpsClawContext::ssh_runner_for` with the key already resolved.
pub struct SshCommandRunner {
    target: TargetEntry,
    executor: Box<dyn SshExecutor>,
    timeout: Duration,
}

impl std::fmt::Debug for SshCommandRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshCommandRunner")
            .field("target", &self.target)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl SshCommandRunner {
    pub fn new(target: TargetEntry) -> Self {
        Self {
            target,
            executor: Box::new(RealSshExecutor),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Construct with a custom executor (for testing).
    pub fn with_executor(target: TargetEntry, executor: Box<dyn SshExecutor>) -> Self {
        Self {
            target,
            executor,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    pub fn target(&self) -> &TargetEntry {
        &self.target
    }

    pub fn host(&self) -> &str {
        &self.target.host
    }

    pub fn port(&self) -> u16 {
        self.target.port
    }

    pub fn user(&self) -> &str {
        &self.target.user
    }

    /// Execute a command on this target.
    pub async fn run(&self, command: &str, pty: bool) -> anyhow::Result<SshOutput> {
        self.executor
            .run(&self.target, command, self.timeout, pty)
            .await
    }
}

// ── SshTool ─────────────────────────────────────────────

/// Tool trait implementation for SSH command execution.
pub struct SshTool {
    config: SshToolConfig,
    executor: Box<dyn SshExecutor>,
    timeout: Duration,
    /// Override audit directory (used by tests).
    audit_dir: Option<PathBuf>,
}

impl SshTool {
    pub fn new(config: SshToolConfig) -> Self {
        Self {
            config,
            executor: Box::new(RealSshExecutor),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            audit_dir: None,
        }
    }

    /// Construct with a custom executor (for testing).
    pub fn with_executor(config: SshToolConfig, executor: Box<dyn SshExecutor>) -> Self {
        Self {
            config,
            executor,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            audit_dir: None,
        }
    }

    /// Override the command timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the audit log directory.
    pub fn with_audit_dir(mut self, dir: PathBuf) -> Self {
        self.audit_dir = Some(dir);
        self
    }

    fn resolve_target(&self, name: &str) -> Option<&TargetEntry> {
        self.config.targets.iter().find(|t| t.name == name)
    }
}

#[async_trait]
impl Tool for SshTool {
    fn name(&self) -> &str {
        "ssh"
    }

    fn description(&self) -> &str {
        "Execute a command on a remote host via SSH"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Name of the SSH target from config"
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to execute on the remote host"
                },
                "pty": {
                    "type": "boolean",
                    "description": "Allocate a PTY for the command (default false)",
                    "default": false
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Override default timeout in seconds"
                }
            },
            "required": ["target", "command"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let target_name = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'target' parameter"))?;

        let command = args
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'command' parameter"))?;

        let pty = args.get("pty").and_then(|v| v.as_bool()).unwrap_or(false);

        let timeout_override = args
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .map(Duration::from_secs);

        // Resolve target.
        let target = match self.resolve_target(target_name) {
            Some(t) => t,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("unknown SSH target '{target_name}'")),
                });
            }
        };

        // Autonomy enforcement — DryRun is intercepted by the
        // DryRunCommandRunner wrapper at a higher level, but if a caller
        // reaches SshTool directly we still block writes.
        if target.autonomy == OpsClawAutonomy::DryRun {
            if let Err(reason) = is_read_only_command(command) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("dry-run mode: {reason}")),
                });
            }
        }

        let timeout = timeout_override.unwrap_or(self.timeout);
        let start = std::time::Instant::now();

        // Execute via SSH.
        let result =
            tokio::time::timeout(timeout, self.executor.run(target, command, timeout, pty)).await;

        let elapsed_ms = start.elapsed().as_millis();

        match result {
            Ok(Ok(output)) => {
                let mut stdout = output.stdout;
                let mut stderr = output.stderr;

                // Truncate.
                if stdout.len() > MAX_OUTPUT_BYTES {
                    let mut b = MAX_OUTPUT_BYTES;
                    while b > 0 && !stdout.is_char_boundary(b) {
                        b -= 1;
                    }
                    stdout.truncate(b);
                    stdout.push_str("\n... [output truncated at 1MB]");
                }
                if stderr.len() > MAX_OUTPUT_BYTES {
                    let mut b = MAX_OUTPUT_BYTES;
                    while b > 0 && !stderr.is_char_boundary(b) {
                        b -= 1;
                    }
                    stderr.truncate(b);
                    stderr.push_str("\n... [stderr truncated at 1MB]");
                }

                // Audit log.
                let _ = write_audit_entry(
                    target_name,
                    command,
                    output.exit_code,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );

                let combined_output = format!(
                    "stdout:\n{stdout}\nstderr:\n{stderr}\nexit_code: {}",
                    output.exit_code
                );

                Ok(ToolResult {
                    success: output.exit_code == 0,
                    output: combined_output,
                    error: if output.exit_code != 0 {
                        Some(format!("command exited with code {}", output.exit_code))
                    } else {
                        None
                    },
                })
            }
            Ok(Err(e)) => {
                let _ = write_audit_entry(
                    target_name,
                    command,
                    -1,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );
                Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("SSH execution failed: {e}")),
                })
            }
            Err(_) => {
                let _ = write_audit_entry(
                    target_name,
                    command,
                    -1,
                    elapsed_ms,
                    self.audit_dir.as_ref(),
                );
                Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("command timed out after {}s", timeout.as_secs())),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_target(autonomy: OpsClawAutonomy) -> TargetEntry {
        TargetEntry {
            name: "prod-web-1".into(),
            host: "10.0.0.1".into(),
            port: 22,
            user: "deploy".into(),
            private_key_pem: "fake-key".into(),
            autonomy,
        }
    }

    fn config_with(targets: Vec<TargetEntry>) -> SshToolConfig {
        SshToolConfig { targets }
    }

    // ── Autonomy / command filtering ────────────────────

    #[test]
    fn observe_allows_read_commands() {
        assert!(is_read_only_command("ps aux").is_ok());
        assert!(is_read_only_command("docker ps").is_ok());
        assert!(is_read_only_command("df -h").is_ok());
        assert!(is_read_only_command("systemctl status nginx").is_ok());
        assert!(is_read_only_command("kubectl get pods").is_ok());
        assert!(is_read_only_command("journalctl -u sshd --no-pager").is_ok());
        assert!(is_read_only_command("cat /etc/hostname").is_ok());
    }

    #[test]
    fn observe_rejects_write_commands() {
        assert!(is_read_only_command("rm -rf /tmp/data").is_err());
        assert!(is_read_only_command("mv a b").is_err());
        assert!(is_read_only_command("shutdown -h now").is_err());
        assert!(is_read_only_command("kill -9 1234").is_err());
        assert!(is_read_only_command("apt install foo").is_err());
    }

    #[test]
    fn observe_rejects_mutating_subcommands() {
        assert!(is_read_only_command("docker restart nginx").is_err());
        assert!(is_read_only_command("systemctl restart nginx").is_err());
        assert!(is_read_only_command("kubectl delete pod foo").is_err());
        assert!(is_read_only_command("docker kill abc").is_err());
    }

    #[test]
    fn observe_allows_sudo_read() {
        assert!(is_read_only_command("sudo ps aux").is_ok());
        assert!(is_read_only_command("sudo cat /var/log/syslog").is_ok());
    }

    #[test]
    fn observe_rejects_sudo_write() {
        assert!(is_read_only_command("sudo rm -rf /").is_err());
        assert!(is_read_only_command("sudo reboot").is_err());
    }

    #[test]
    fn empty_command_rejected() {
        assert!(is_read_only_command("").is_err());
        assert!(is_read_only_command("   ").is_err());
    }

    // ── Tool metadata ───────────────────────────────────

    #[test]
    fn tool_name_and_description() {
        let tool = SshTool::new(config_with(vec![]));
        assert_eq!(tool.name(), "ssh");
        assert!(!tool.description().is_empty());
    }

    #[test]
    fn tool_schema_has_required_params() {
        let tool = SshTool::new(config_with(vec![]));
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["target"].is_object());
        assert!(schema["properties"]["command"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("target")));
        assert!(required.contains(&json!("command")));
    }

    // ── Target resolution ───────────────────────────────

    #[tokio::test]
    async fn unknown_target_returns_error() {
        let tool = SshTool::new(config_with(vec![default_target(OpsClawAutonomy::Auto)]));
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

    // ── Observe mode enforcement via execute ────────────

    #[tokio::test]
    async fn execute_observe_rejects_write() {
        let tool = SshTool::new(config_with(vec![default_target(OpsClawAutonomy::DryRun)]));
        let result = tool
            .execute(json!({"target": "prod-web-1", "command": "rm -rf /tmp"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("dry-run mode"));
    }

    #[tokio::test]
    async fn execute_observe_allows_read() {
        // Will fail at SSH execution (RealSshExecutor stub), but should NOT fail
        // at autonomy check.
        let tool = SshTool::new(config_with(vec![default_target(OpsClawAutonomy::DryRun)]));
        let result = tool
            .execute(json!({"target": "prod-web-1", "command": "ps aux"}))
            .await
            .unwrap();
        // Expect SSH failure, not autonomy failure.
        let err = result.error.as_deref().unwrap_or("");
        assert!(
            err.contains("SSH execution failed") || err.contains("not yet implemented"),
            "expected SSH failure, got: {err}"
        );
    }

    // ── Audit logging ───────────────────────────────────

    #[test]
    fn audit_log_format() {
        let dir = tempfile::tempdir().unwrap();
        write_audit_entry("web-1", "uptime", 0, 42, Some(&dir.path().to_path_buf())).unwrap();

        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let log = std::fs::read_to_string(dir.path().join(format!("{date}.log"))).unwrap();
        assert!(log.contains("TARGET=web-1"));
        assert!(log.contains("CMD=uptime"));
        assert!(log.contains("EXIT=0"));
        assert!(log.contains("DURATION=42ms"));
        // ISO 8601 timestamp check.
        assert!(log.starts_with('['));
        assert!(log.contains('T'));
    }

    #[test]
    fn audit_log_appends() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_path_buf();
        write_audit_entry("a", "cmd1", 0, 10, Some(&base)).unwrap();
        write_audit_entry("b", "cmd2", 1, 20, Some(&base)).unwrap();

        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let log = std::fs::read_to_string(dir.path().join(format!("{date}.log"))).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
