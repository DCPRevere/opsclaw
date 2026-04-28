//! Docker tool. Runs `docker` CLI commands over SSH, reusing the SSH
//! executor. Reads: ps, inspect, logs, stats, images, version. Writes:
//! start, stop, restart, kill, rm, rmi, pull, exec. Writes gated by
//! autonomy; every command audit-logged. Container/image refs validated
//! to reject shell metacharacters.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsClawAutonomy;
use crate::tools::ssh_tool::{RealSshExecutor, SshExecutor, TargetEntry, write_audit_entry};

const DEFAULT_TIMEOUT_SECS: u64 = 60;
const MAX_OUTPUT_BYTES: usize = 32 * 1024;

pub struct DockerToolConfig {
    pub targets: Vec<TargetEntry>,
}

pub struct DockerTool {
    config: DockerToolConfig,
    executor: Box<dyn SshExecutor>,
    timeout: Duration,
    audit_dir: Option<PathBuf>,
}

impl DockerTool {
    pub fn new(config: DockerToolConfig) -> Self {
        Self {
            config,
            executor: Box::new(RealSshExecutor),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            audit_dir: None,
        }
    }

    pub fn with_executor(config: DockerToolConfig, executor: Box<dyn SshExecutor>) -> Self {
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
        self.config.targets.iter().find(|t| t.name == name)
    }
}

/// Accept container names, IDs (64-char hex or short), and `name/path` or
/// `registry/name:tag`. Reject shell metacharacters.
pub fn is_valid_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@' | '+')
        })
}

/// Stricter — rejects shell metacharacters AND whitespace. Used for `exec`
/// argv tokens because tokens are joined with single spaces, so a token
/// containing whitespace would break word boundaries on the remote side.
pub fn is_safe_arg(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && !s.chars().any(|c| {
            c.is_whitespace() || matches!(c, '`' | '$' | ';' | '|' | '&' | '>' | '<' | '"' | '\'')
        })
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

    let require_container = |args: &Value, action: &str| -> Result<String, String> {
        let c = args
            .get("container")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("action '{action}' requires 'container'"))?;
        if !is_valid_ref(c) {
            return Err(format!("invalid container ref '{c}'"));
        }
        Ok(c.to_string())
    };

    let require_image = |args: &Value, action: &str| -> Result<String, String> {
        let i = args
            .get("image")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("action '{action}' requires 'image'"))?;
        if !is_valid_ref(i) {
            return Err(format!("invalid image ref '{i}'"));
        }
        Ok(i.to_string())
    };

    match action {
        "ps" => {
            let all = args.get("all").and_then(|v| v.as_bool()).unwrap_or(false);
            let flag = if all { " -a" } else { "" };
            Build::Ok {
                command: format!("docker ps{flag} --format '{{{{json .}}}}'"),
                is_write: false,
            }
        }
        "inspect" => match require_container(args, action) {
            Ok(c) => Build::Ok {
                command: format!("docker inspect {c}"),
                is_write: false,
            },
            Err(e) => Build::Err(e),
        },
        "logs" => {
            let c = match require_container(args, action) {
                Ok(c) => c,
                Err(e) => return Build::Err(e),
            };
            let tail = args.get("tail").and_then(|v| v.as_u64()).unwrap_or(200);
            let since = args.get("since").and_then(|v| v.as_str()).unwrap_or("");
            let mut cmd = format!("docker logs --tail {tail} {c}");
            if !since.is_empty() {
                if !is_safe_arg(since) {
                    return Build::Err(format!("unsafe 'since' value '{since}'"));
                }
                cmd = format!("docker logs --tail {tail} --since \"{since}\" {c}");
            }
            Build::Ok {
                command: format!("{cmd} 2>&1"),
                is_write: false,
            }
        }
        "stats" => {
            let c = match args.get("container").and_then(|v| v.as_str()) {
                Some(s) if is_valid_ref(s) => format!(" {s}"),
                Some(bad) => return Build::Err(format!("invalid container ref '{bad}'")),
                None => String::new(),
            };
            Build::Ok {
                command: format!("docker stats --no-stream{c} --format '{{{{json .}}}}'"),
                is_write: false,
            }
        }
        "images" => Build::Ok {
            command: "docker images --format '{{json .}}'".into(),
            is_write: false,
        },
        "version" => Build::Ok {
            command: "docker version --format '{{json .}}'".into(),
            is_write: false,
        },
        "start" | "stop" | "restart" | "kill" => match require_container(args, action) {
            Ok(c) => Build::Ok {
                command: format!("docker {action} {c}"),
                is_write: true,
            },
            Err(e) => Build::Err(e),
        },
        "rm" => {
            let c = match require_container(args, action) {
                Ok(c) => c,
                Err(e) => return Build::Err(e),
            };
            let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            let flag = if force { " -f" } else { "" };
            Build::Ok {
                command: format!("docker rm{flag} {c}"),
                is_write: true,
            }
        }
        "rmi" => {
            let i = match require_image(args, action) {
                Ok(i) => i,
                Err(e) => return Build::Err(e),
            };
            let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            let flag = if force { " -f" } else { "" };
            Build::Ok {
                command: format!("docker rmi{flag} {i}"),
                is_write: true,
            }
        }
        "pull" => match require_image(args, action) {
            Ok(i) => Build::Ok {
                command: format!("docker pull {i}"),
                is_write: true,
            },
            Err(e) => Build::Err(e),
        },
        "exec" => {
            let c = match require_container(args, action) {
                Ok(c) => c,
                Err(e) => return Build::Err(e),
            };
            let argv = args.get("argv").and_then(|v| v.as_array());
            let argv = match argv {
                Some(a) if !a.is_empty() => a,
                _ => return Build::Err("exec requires non-empty 'argv' array".into()),
            };
            let mut rendered = Vec::with_capacity(argv.len());
            for v in argv {
                let s = match v.as_str() {
                    Some(s) => s,
                    None => return Build::Err("exec 'argv' entries must be strings".into()),
                };
                if !is_safe_arg(s) {
                    return Build::Err(format!("unsafe argv token '{s}'"));
                }
                rendered.push(s.to_string());
            }
            Build::Ok {
                command: format!("docker exec {c} {}", rendered.join(" ")),
                is_write: true,
            }
        }
        other => Build::Err(format!("unknown action '{other}'")),
    }
}

#[async_trait]
impl Tool for DockerTool {
    fn name(&self) -> &str {
        "docker"
    }

    fn description(&self) -> &str {
        "Docker CLI over SSH. Reads: ps, inspect, logs, stats, images, \
         version. Writes: start, stop, restart, kill, rm (force optional), \
         rmi, pull, exec (argv array). Writes are gated by target autonomy \
         — DryRun rejects them. Container and image refs are validated to \
         reject shell metacharacters. Every command is audit-logged."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["ps", "inspect", "logs", "stats", "images", "version",
                             "start", "stop", "restart", "kill", "rm", "rmi",
                             "pull", "exec"]
                },
                "container": {"type": "string"},
                "image": {"type": "string"},
                "all": {"type": "boolean", "description": "ps: include stopped"},
                "tail": {"type": "integer", "default": 200},
                "since": {"type": "string"},
                "force": {"type": "boolean"},
                "argv": {"type": "array", "items": {"type": "string"}, "description": "exec"}
            },
            "required": ["target", "action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let target_name = match args.get("target").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'target'")),
        };
        let target = match self.resolve(target_name) {
            Some(t) => t,
            None => return Ok(err(format!("unknown target '{target_name}'"))),
        };

        let (command, is_write) = match build_command(&args) {
            Build::Ok { command, is_write } => (command, is_write),
            Build::Err(e) => return Ok(err(e)),
        };

        if is_write && target.autonomy == OpsClawAutonomy::DryRun {
            let _ = write_audit_entry(
                target_name,
                &format!("[blocked dry-run] {command}"),
                -1,
                0,
                self.audit_dir.as_ref(),
            );
            return Ok(err(format!("dry-run mode: write rejected ({command})")));
        }

        let start = std::time::Instant::now();
        let result = self
            .executor
            .run(target, &command, self.timeout, false)
            .await;
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
                let _ =
                    write_audit_entry(target_name, &command, -1, elapsed, self.audit_dir.as_ref());
                Ok(err(format!("SSH error: {e}")))
            }
        }
    }
}

fn err<S: Into<String>>(msg: S) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(msg.into()),
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
            _t: &TargetEntry,
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

    fn tool_with(autonomy: OpsClawAutonomy) -> (DockerTool, Arc<Mutex<Option<String>>>) {
        let last = Arc::new(Mutex::new(None));
        let dir = tempfile::tempdir().unwrap();
        let tool = DockerTool::with_executor(
            DockerToolConfig {
                targets: vec![target(autonomy)],
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
        (tool, last)
    }

    #[test]
    fn valid_refs() {
        assert!(is_valid_ref("nginx"));
        assert!(is_valid_ref("registry.example.com/team/app:v1.2.3"));
        assert!(is_valid_ref("sha256:abc123"));
        assert!(is_valid_ref("my_container-1"));
    }

    #[test]
    fn invalid_refs() {
        assert!(!is_valid_ref(""));
        assert!(!is_valid_ref("foo; rm -rf /"));
        assert!(!is_valid_ref("$(whoami)"));
        assert!(!is_valid_ref("foo|bar"));
        assert!(!is_valid_ref("foo bar"));
    }

    #[tokio::test]
    async fn ps_builds_json_format() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "action": "ps"}))
            .await
            .unwrap();
        assert!(r.success);
        let cmd = last.lock().unwrap().clone().unwrap();
        assert!(cmd.starts_with("docker ps"));
        assert!(cmd.contains("--format '{{json .}}'"));
    }

    #[tokio::test]
    async fn ps_all_adds_flag() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let _ = tool
            .execute(json!({"target": "prod", "action": "ps", "all": true}))
            .await
            .unwrap();
        assert!(
            last.lock()
                .unwrap()
                .clone()
                .unwrap()
                .contains("docker ps -a")
        );
    }

    #[tokio::test]
    async fn logs_tail_default() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let _ = tool
            .execute(json!({"target": "prod", "action": "logs", "container": "web"}))
            .await
            .unwrap();
        let cmd = last.lock().unwrap().clone().unwrap();
        assert!(cmd.starts_with("docker logs --tail 200 web"));
    }

    #[tokio::test]
    async fn restart_is_write() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "action": "restart", "container": "web"}))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(last.lock().unwrap().as_deref(), Some("docker restart web"));
    }

    #[tokio::test]
    async fn write_blocked_in_dry_run() {
        let (tool, last) = tool_with(OpsClawAutonomy::DryRun);
        let r = tool
            .execute(json!({"target": "prod", "action": "restart", "container": "web"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("dry-run"));
        assert!(last.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn read_allowed_in_dry_run() {
        let (tool, last) = tool_with(OpsClawAutonomy::DryRun);
        let r = tool
            .execute(json!({"target": "prod", "action": "ps"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(last.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn bad_container_rejected() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "action": "restart", "container": "foo; rm -rf /"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("invalid container"));
        assert!(last.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn exec_requires_argv() {
        let (tool, _) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "action": "exec", "container": "web"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("argv"));
    }

    #[tokio::test]
    async fn exec_builds_command() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "action": "exec", "container": "web",
                "argv": ["ls", "-la", "/var/log"]
            }))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(
            last.lock().unwrap().as_deref(),
            Some("docker exec web ls -la /var/log")
        );
    }

    #[tokio::test]
    async fn exec_rejects_shell_injection_in_argv() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "action": "exec", "container": "web",
                "argv": ["sh", "-c", "rm -rf /"]
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unsafe argv"));
        assert!(last.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn rm_force_flag() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let _ = tool
            .execute(json!({
                "target": "prod", "action": "rm", "container": "web", "force": true
            }))
            .await
            .unwrap();
        assert_eq!(last.lock().unwrap().as_deref(), Some("docker rm -f web"));
    }

    #[tokio::test]
    async fn pull_validates_image() {
        let (tool, last) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({
                "target": "prod", "action": "pull",
                "image": "nginx:1.27-alpine"
            }))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(
            last.lock().unwrap().as_deref(),
            Some("docker pull nginx:1.27-alpine")
        );
    }

    #[tokio::test]
    async fn unknown_action() {
        let (tool, _) = tool_with(OpsClawAutonomy::Auto);
        let r = tool
            .execute(json!({"target": "prod", "action": "nuke"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unknown action"));
    }
}
