//! Host-level firewall tool. Runs iptables/nftables/ufw commands over SSH,
//! reusing the SSH executor. Writes gated by autonomy; all commands
//! audit-logged.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsClawAutonomy;
use crate::tools::ssh_tool::{write_audit_entry, TargetEntry, RealSshExecutor, SshExecutor};

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_OUTPUT_BYTES: usize = 32 * 1024;

pub struct FirewallToolConfig {
    pub projects: Vec<TargetEntry>,
}

pub struct FirewallTool {
    config: FirewallToolConfig,
    executor: Box<dyn SshExecutor>,
    timeout: Duration,
    audit_dir: Option<PathBuf>,
}

impl FirewallTool {
    pub fn new(config: FirewallToolConfig) -> Self {
        Self {
            config,
            executor: Box::new(RealSshExecutor),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            audit_dir: None,
        }
    }

    pub fn with_executor(config: FirewallToolConfig, executor: Box<dyn SshExecutor>) -> Self {
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
        self.config.projects.iter().find(|p| p.name == name)
    }
}

/// Conservative rule-arg validator — rejects shell metacharacters and
/// control characters. Arguments are joined with spaces, so we accept
/// characters that appear in legitimate iptables/nftables/ufw args only.
pub fn is_safe_rule_arg(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s
            .chars()
            .any(|c| matches!(c, '`' | '$' | ';' | '|' | '&' | '>' | '<' | '\n' | '\r' | '"' | '\''))
}

#[derive(Debug)]
enum Build {
    Ok { command: String, is_write: bool },
    Err(String),
}

fn build_command(args: &Value) -> Build {
    let backend = args
        .get("backend")
        .and_then(|v| v.as_str())
        .unwrap_or("iptables");
    let action = match args.get("action").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Build::Err("missing 'action'".into()),
    };

    match backend {
        "iptables" => build_iptables(action, args),
        "nftables" => build_nftables(action, args),
        "ufw" => build_ufw(action, args),
        other => Build::Err(format!("unknown backend '{other}'")),
    }
}

fn build_iptables(action: &str, args: &Value) -> Build {
    let table = args
        .get("table")
        .and_then(|v| v.as_str())
        .unwrap_or("filter");
    if !table.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Build::Err(format!("invalid table '{table}'"));
    }
    let chain = args
        .get("chain")
        .and_then(|v| v.as_str())
        .unwrap_or("INPUT");
    if !chain.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Build::Err(format!("invalid chain '{chain}'"));
    }

    match action {
        "list" => Build::Ok {
            command: format!("sudo iptables -t {table} -L {chain} -n -v --line-numbers"),
            is_write: false,
        },
        "list_all" => Build::Ok {
            command: format!("sudo iptables -t {table} -S"),
            is_write: false,
        },
        "append" | "insert" | "delete" => {
            let flag = match action {
                "append" => "-A",
                "insert" => "-I",
                "delete" => "-D",
                _ => unreachable!(),
            };
            let rule = match args.get("rule").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s,
                _ => return Build::Err(format!("action '{action}' requires 'rule'")),
            };
            for tok in rule.split_whitespace() {
                if !is_safe_rule_arg(tok) {
                    return Build::Err(format!("unsafe token in rule: '{tok}'"));
                }
            }
            Build::Ok {
                command: format!("sudo iptables -t {table} {flag} {chain} {rule}"),
                is_write: true,
            }
        }
        "save" => Build::Ok {
            command: "sudo iptables-save".into(),
            is_write: false,
        },
        other => Build::Err(format!("iptables: unknown action '{other}'")),
    }
}

fn build_nftables(action: &str, args: &Value) -> Build {
    match action {
        "list_ruleset" => Build::Ok {
            command: "sudo nft list ruleset".into(),
            is_write: false,
        },
        "list_table" => {
            let family = args
                .get("family")
                .and_then(|v| v.as_str())
                .unwrap_or("inet");
            let table = match args.get("table").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return Build::Err("list_table requires 'table'".into()),
            };
            if !family.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Build::Err(format!("invalid family '{family}'"));
            }
            if !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                return Build::Err(format!("invalid table '{table}'"));
            }
            Build::Ok {
                command: format!("sudo nft list table {family} {table}"),
                is_write: false,
            }
        }
        "add_rule" | "delete_rule" => {
            let verb = if action == "add_rule" { "add rule" } else { "delete rule" };
            let rule = match args.get("rule").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s,
                _ => return Build::Err(format!("action '{action}' requires 'rule'")),
            };
            for tok in rule.split_whitespace() {
                if !is_safe_rule_arg(tok) {
                    return Build::Err(format!("unsafe token in rule: '{tok}'"));
                }
            }
            Build::Ok {
                command: format!("sudo nft {verb} {rule}"),
                is_write: true,
            }
        }
        other => Build::Err(format!("nftables: unknown action '{other}'")),
    }
}

fn build_ufw(action: &str, args: &Value) -> Build {
    match action {
        "status" => Build::Ok {
            command: "sudo ufw status verbose".into(),
            is_write: false,
        },
        "status_numbered" => Build::Ok {
            command: "sudo ufw status numbered".into(),
            is_write: false,
        },
        "allow" | "deny" | "reject" | "limit" => {
            let spec = match args.get("spec").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s,
                _ => return Build::Err(format!("action '{action}' requires 'spec'")),
            };
            for tok in spec.split_whitespace() {
                if !is_safe_rule_arg(tok) {
                    return Build::Err(format!("unsafe token in spec: '{tok}'"));
                }
            }
            Build::Ok {
                command: format!("sudo ufw {action} {spec}"),
                is_write: true,
            }
        }
        "delete" => {
            let number = match args.get("number").and_then(|v| v.as_u64()) {
                Some(n) => n,
                None => return Build::Err("delete requires numeric 'number'".into()),
            };
            Build::Ok {
                command: format!("sudo ufw --force delete {number}"),
                is_write: true,
            }
        }
        "enable" | "disable" => Build::Ok {
            command: format!("sudo ufw --force {action}"),
            is_write: true,
        },
        "reload" => Build::Ok {
            command: "sudo ufw reload".into(),
            is_write: true,
        },
        other => Build::Err(format!("ufw: unknown action '{other}'")),
    }
}

#[async_trait]
impl Tool for FirewallTool {
    fn name(&self) -> &str {
        "firewall"
    }

    fn description(&self) -> &str {
        "Host-level firewall via SSH. backend=iptables|nftables|ufw. \
         Reads: list, list_all (iptables), list_ruleset, list_table \
         (nftables), status, status_numbered (ufw). Writes: append/insert/ \
         delete (iptables), add_rule/delete_rule (nftables), \
         allow/deny/reject/limit/delete/enable/disable/reload (ufw). \
         Writes are gated by project autonomy — DryRun rejects them. \
         Rule arguments are validated to reject shell metacharacters."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "backend": {"type": "string", "enum": ["iptables", "nftables", "ufw"], "default": "iptables"},
                "action": {"type": "string"},
                "table": {"type": "string"},
                "chain": {"type": "string"},
                "family": {"type": "string"},
                "rule": {"type": "string"},
                "spec": {"type": "string"},
                "number": {"type": "integer"}
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
                error: Some(format!("dry-run mode: write rejected ({command})")),
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

    struct Recording {
        last: Arc<Mutex<Option<String>>>,
        output: SshOutput,
    }

    #[async_trait]
    impl SshExecutor for Recording {
        async fn run(
            &self,
            _p: &TargetEntry,
            command: &str,
            _t: Duration,
            _pty: bool,
        ) -> anyhow::Result<SshOutput> {
            *self.last.lock().unwrap() = Some(command.to_string());
            Ok(self.output.clone())
        }
    }

    fn project(autonomy: OpsClawAutonomy) -> TargetEntry {
        TargetEntry {
            name: "prod".into(),
            host: "h".into(),
            port: 22,
            user: "u".into(),
            private_key_pem: "k".into(),
            autonomy,
        }
    }

    fn tool_with(autonomy: OpsClawAutonomy) -> (FirewallTool, Arc<Mutex<Option<String>>>) {
        let last = Arc::new(Mutex::new(None));
        let dir = tempfile::tempdir().unwrap();
        let t = FirewallTool::with_executor(
            FirewallToolConfig {
                projects: vec![project(autonomy)],
            },
            Box::new(Recording {
                last: last.clone(),
                output: SshOutput {
                    stdout: "ok".into(),
                    stderr: "".into(),
                    exit_code: 0,
                },
            }),
        )
        .with_audit_dir(dir.keep());
        (t, last)
    }

    #[test]
    fn rejects_unsafe_rule_arg() {
        assert!(!is_safe_rule_arg("foo;bar"));
        assert!(!is_safe_rule_arg("`whoami`"));
        assert!(!is_safe_rule_arg("$(echo)"));
        assert!(is_safe_rule_arg("-p"));
        assert!(is_safe_rule_arg("10.0.0.1"));
        assert!(is_safe_rule_arg("ACCEPT"));
    }

    #[tokio::test]
    async fn iptables_list() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "backend": "iptables", "action": "list"}))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(
            last.lock().unwrap().as_deref(),
            Some("sudo iptables -t filter -L INPUT -n -v --line-numbers")
        );
    }

    #[tokio::test]
    async fn iptables_append_rule() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "backend": "iptables", "action": "append",
                "chain": "INPUT", "rule": "-p tcp --dport 22 -j ACCEPT"
            }))
            .await
            .unwrap();
        assert!(r.success);
        let cmd = last.lock().unwrap().clone().unwrap();
        assert!(cmd.contains("-A INPUT"));
        assert!(cmd.contains("--dport 22"));
    }

    #[tokio::test]
    async fn iptables_write_blocked_in_dry_run() {
        let (tool, last) = tool_with(OpsClawAutonomy::DryRun);
        let r = tool
            .execute(json!({
                "target": "prod", "backend": "iptables", "action": "append",
                "rule": "-p tcp --dport 22 -j ACCEPT"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("dry-run"));
        assert!(last.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn iptables_list_allowed_in_dry_run() {
        let (tool, last) = tool_with(OpsClawAutonomy::DryRun);
        let r = tool
            .execute(json!({"target": "prod", "backend": "iptables", "action": "list"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(last.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn nftables_add_rule_rejects_injection() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "backend": "nftables", "action": "add_rule",
                "rule": "inet filter input ; rm -rf /"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unsafe"));
        assert!(last.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn ufw_allow() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "backend": "ufw", "action": "allow",
                "spec": "22/tcp"
            }))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(last.lock().unwrap().as_deref(), Some("sudo ufw allow 22/tcp"));
    }

    #[tokio::test]
    async fn ufw_delete_requires_numeric() {
        let (tool, _last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "backend": "ufw", "action": "delete"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("number"));
    }

    #[tokio::test]
    async fn unknown_backend() {
        let (tool, _last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "backend": "pf", "action": "list"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unknown backend"));
    }
}
