//! Systemd / journalctl tool. Runs typed systemctl and journalctl commands
//! over SSH, reusing the SSH executor from `ssh_tool`. Writes are gated
//! by autonomy: DryRun allows reads but rejects start/stop/restart/reload.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsClawAutonomy;
use crate::tools::ssh_tool::{write_audit_entry, TargetEntry, RealSshExecutor, SshExecutor};

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_OUTPUT_BYTES: usize = 32 * 1024;

pub struct SystemdToolConfig {
    pub targets: Vec<TargetEntry>,
}

pub struct SystemdTool {
    config: SystemdToolConfig,
    executor: Box<dyn SshExecutor>,
    timeout: Duration,
    audit_dir: Option<PathBuf>,
}

impl SystemdTool {
    pub fn new(config: SystemdToolConfig) -> Self {
        Self {
            config,
            executor: Box::new(RealSshExecutor),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            audit_dir: None,
        }
    }

    pub fn with_executor(config: SystemdToolConfig, executor: Box<dyn SshExecutor>) -> Self {
        Self {
            config,
            executor,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            audit_dir: None,
        }
    }

    pub fn with_audit_dir(mut self, dir: PathBuf) -> Self {
        self.audit_dir = Some(dir);
        self
    }

    fn resolve<'a>(&'a self, name: &str) -> Option<&'a TargetEntry> {
        self.config.targets.iter().find(|p| p.name == name)
    }
}

/// Validate a systemd unit name — reject anything with shell metacharacters.
/// Allowed: letters, digits, and `@ . _ - : \` (the usual systemd set).
pub fn is_valid_unit(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | ':' | '\\')
        })
}

fn is_safe_grep(pattern: &str) -> bool {
    // Allow a broad set of regex chars but reject shell metacharacters
    // that enable command injection.
    !pattern.is_empty()
        && pattern.len() <= 512
        && !pattern.chars().any(|c| matches!(c, '`' | '$' | ';' | '|' | '&' | '>' | '<' | '\n'))
}

fn shell_quote_double(s: &str) -> String {
    // For use inside double quotes in the generated command. Escape the
    // special-in-double-quote chars: `\` `"` `$` `` ` ``.
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' | '"' | '$' | '`' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

#[derive(Debug)]
enum Build {
    Ok { command: String, is_write: bool },
    Err(String),
}

fn build_command(args: &Value) -> Build {
    let action = match args.get("action").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Build::Err("missing 'action'".into()),
    };

    let unit = args.get("unit").and_then(|v| v.as_str());
    let must_validate_unit = |u: Option<&str>| -> Result<String, String> {
        let u = u.ok_or_else(|| format!("action '{action}' requires 'unit'"))?;
        if !is_valid_unit(u) {
            return Err(format!("invalid unit name '{u}'"));
        }
        Ok(u.to_string())
    };

    match action {
        "status" => match must_validate_unit(unit) {
            Ok(u) => Build::Ok {
                command: format!("systemctl status {u} --no-pager"),
                is_write: false,
            },
            Err(e) => Build::Err(e),
        },
        "is_active" => match must_validate_unit(unit) {
            Ok(u) => Build::Ok {
                command: format!("systemctl is-active {u}"),
                is_write: false,
            },
            Err(e) => Build::Err(e),
        },
        "is_failed" => match must_validate_unit(unit) {
            Ok(u) => Build::Ok {
                command: format!("systemctl is-failed {u}"),
                is_write: false,
            },
            Err(e) => Build::Err(e),
        },
        "list_failed" => Build::Ok {
            command: "systemctl list-units --state=failed --no-pager".into(),
            is_write: false,
        },
        "show" => {
            let u = match must_validate_unit(unit) {
                Ok(u) => u,
                Err(e) => return Build::Err(e),
            };
            let props = args.get("properties").and_then(|v| v.as_str());
            let suffix = match props {
                Some(p) => {
                    if p.split(',').any(|part| !part.chars().all(|c| c.is_ascii_alphanumeric())) {
                        return Build::Err(format!("invalid properties list '{p}'"));
                    }
                    format!(" -p {p}")
                }
                None => String::new(),
            };
            Build::Ok {
                command: format!("systemctl show {u}{suffix}"),
                is_write: false,
            }
        }
        "journal" => {
            let since = args
                .get("since")
                .and_then(|v| v.as_str())
                .unwrap_or("1 hour ago");
            let lines = args.get("lines").and_then(|v| v.as_u64()).unwrap_or(200);
            let mut cmd = String::from("journalctl --no-pager");
            if let Some(u) = unit {
                if !is_valid_unit(u) {
                    return Build::Err(format!("invalid unit name '{u}'"));
                }
                cmd.push_str(&format!(" -u {u}"));
            }
            cmd.push_str(&format!(" --since \"{}\"", shell_quote_double(since)));
            if let Some(until) = args.get("until").and_then(|v| v.as_str()) {
                cmd.push_str(&format!(" --until \"{}\"", shell_quote_double(until)));
            }
            cmd.push_str(&format!(" -n {lines} -o short-iso"));

            if let Some(pattern) = args.get("grep").and_then(|v| v.as_str()) {
                if !is_safe_grep(pattern) {
                    return Build::Err(format!("unsafe grep pattern '{pattern}'"));
                }
                cmd.push_str(&format!(" | grep -E \"{}\"", shell_quote_double(pattern)));
            }
            Build::Ok {
                command: cmd,
                is_write: false,
            }
        }
        "restart" | "reload" | "start" | "stop" => {
            let u = match must_validate_unit(unit) {
                Ok(u) => u,
                Err(e) => return Build::Err(e),
            };
            Build::Ok {
                command: format!("sudo systemctl {action} {u}"),
                is_write: true,
            }
        }
        other => Build::Err(format!("unknown action '{other}'")),
    }
}

#[async_trait]
impl Tool for SystemdTool {
    fn name(&self) -> &str {
        "systemd"
    }

    fn description(&self) -> &str {
        "Systemd / journalctl over SSH. Read actions: status, is_active, \
         is_failed, list_failed, show, journal. Write actions: restart, \
         reload, start, stop (gated by autonomy — DryRun rejects writes). \
         Every action is audit-logged. Unit names are regex-validated to \
         reject shell metacharacters."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "project name"},
                "action": {
                    "type": "string",
                    "enum": ["status", "is_active", "is_failed", "list_failed",
                             "show", "journal", "restart", "reload", "start", "stop"]
                },
                "unit": {"type": "string"},
                "properties": {"type": "string", "description": "show: comma-sep property list"},
                "since": {"type": "string", "default": "1 hour ago"},
                "until": {"type": "string"},
                "lines": {"type": "integer", "default": 200},
                "grep": {"type": "string", "description": "journal: regex filter"}
            },
            "required": ["target", "action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let target_name = match args.get("target").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("missing 'target'".into()),
                });
            }
        };

        let target = match self.resolve(target_name) {
            Some(t) => t,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("unknown target '{target_name}'")),
                });
            }
        };

        let (command, is_write) = match build_command(&args) {
            Build::Ok { command, is_write } => (command, is_write),
            Build::Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(e),
                });
            }
        };

        if is_write && target.autonomy == OpsClawAutonomy::DryRun {
            let _ = write_audit_entry(
                target_name,
                &format!("[blocked dry-run] {command}"),
                -1,
                0,
                self.audit_dir.as_ref(),
            );
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("dry-run mode: write action rejected ({command})")),
            });
        }

        let start = std::time::Instant::now();
        let result = self.executor.run(target, &command, self.timeout, false).await;
        let elapsed = start.elapsed().as_millis();

        match result {
            Ok(output) => {
                let _ = write_audit_entry(
                    target_name,
                    &command,
                    output.exit_code,
                    elapsed,
                    self.audit_dir.as_ref(),
                );

                let mut stdout = output.stdout;
                if stdout.len() > MAX_OUTPUT_BYTES {
                    let mut cut = MAX_OUTPUT_BYTES;
                    while cut > 0 && !stdout.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    stdout.truncate(cut);
                    stdout.push_str("\n... [truncated at 32KB]");
                }
                let combined = format!(
                    "command: {command}\nexit: {}\nstdout:\n{stdout}\nstderr:\n{}",
                    output.exit_code, output.stderr
                );
                Ok(ToolResult {
                    success: output.exit_code == 0,
                    output: combined,
                    error: if output.exit_code != 0 {
                        Some(format!("exited with code {}", output.exit_code))
                    } else {
                        None
                    },
                })
            }
            Err(e) => {
                let _ = write_audit_entry(
                    target_name,
                    &command,
                    -1,
                    elapsed,
                    self.audit_dir.as_ref(),
                );
                Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("SSH error: {e}")),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ssh_tool::SshOutput;
    use std::sync::{Arc, Mutex};

    struct RecordingExecutor {
        last: Arc<Mutex<Option<String>>>,
        output: SshOutput,
    }

    #[async_trait]
    impl SshExecutor for RecordingExecutor {
        async fn run(
            &self,
            _project: &TargetEntry,
            command: &str,
            _timeout: Duration,
            _pty: bool,
        ) -> anyhow::Result<SshOutput> {
            *self.last.lock().unwrap() = Some(command.to_string());
            Ok(self.output.clone())
        }
    }

    fn target(autonomy: OpsClawAutonomy) -> TargetEntry {
        TargetEntry {
            name: "prod".into(),
            host: "h".into(),
            port: 22,
            user: "u".into(),
            private_key_pem: "k".into(),
            autonomy,
        }
    }

    fn tool_with(
        autonomy: OpsClawAutonomy,
    ) -> (SystemdTool, Arc<Mutex<Option<String>>>) {
        let last = Arc::new(Mutex::new(None));
        let dir = tempfile::tempdir().unwrap();
        let exec = RecordingExecutor {
            last: last.clone(),
            output: SshOutput {
                stdout: "ok".into(),
                stderr: "".into(),
                exit_code: 0,
            },
        };
        let tool = SystemdTool::with_executor(
            SystemdToolConfig {
                targets: vec![target(autonomy)],
            },
            Box::new(exec),
        )
        .with_audit_dir(dir.keep());
        (tool, last)
    }

    #[test]
    fn valid_units() {
        assert!(is_valid_unit("nginx.service"));
        assert!(is_valid_unit("getty@tty1.service"));
        assert!(is_valid_unit("foo_bar-baz.service"));
    }

    #[test]
    fn invalid_units() {
        assert!(!is_valid_unit(""));
        assert!(!is_valid_unit("foo; rm -rf /"));
        assert!(!is_valid_unit("foo bar"));
        assert!(!is_valid_unit("$(echo)"));
        assert!(!is_valid_unit("foo|bar"));
    }

    #[tokio::test]
    async fn status_builds_expected_command() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "action": "status", "unit": "nginx.service"}))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(
            last.lock().unwrap().as_deref(),
            Some("systemctl status nginx.service --no-pager")
        );
    }

    #[tokio::test]
    async fn journal_with_grep_uses_pipe() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "action": "journal",
                "unit": "sshd.service", "grep": "Failed"
            }))
            .await
            .unwrap();
        assert!(r.success);
        let cmd = last.lock().unwrap().clone().unwrap();
        assert!(cmd.starts_with("journalctl --no-pager -u sshd.service"));
        assert!(cmd.contains("| grep -E \"Failed\""));
    }

    #[tokio::test]
    async fn restart_rejected_in_dry_run() {
        let (tool, last) = tool_with(OpsClawAutonomy::DryRun);
        let r = tool
            .execute(json!({"target": "prod", "action": "restart", "unit": "nginx.service"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("dry-run"));
        assert!(last.lock().unwrap().is_none(), "executor must not be called");
    }

    #[tokio::test]
    async fn read_allowed_in_dry_run() {
        let (tool, last) = tool_with(OpsClawAutonomy::DryRun);
        let r = tool
            .execute(json!({"target": "prod", "action": "status", "unit": "nginx.service"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(last.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn bad_unit_name_rejected() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "action": "status", "unit": "foo; rm -rf /"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("invalid unit"));
        assert!(last.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn unsafe_grep_rejected() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "action": "journal",
                "unit": "sshd.service", "grep": "foo | rm -rf /"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unsafe grep"));
        assert!(last.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn restart_builds_sudo_command() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "action": "restart", "unit": "nginx.service"}))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(
            last.lock().unwrap().as_deref(),
            Some("sudo systemctl restart nginx.service")
        );
    }
}
