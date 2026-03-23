//! Real-time event streaming from Docker and systemd.
//!
//! Provides [`DockerEventSource`] and [`SystemdEventSource`] which spawn
//! long-running child processes (`docker events`, `journalctl -f`) and parse
//! their JSON output into [`StreamEvent`] values sent over a tokio channel.

use async_trait::async_trait;
use tracing::{debug, error, warn};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamEvent {
    Docker(DockerEvent),
    Systemd(SystemdEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerEvent {
    pub timestamp: DateTime<Utc>,
    /// "container", "network", "volume", etc.
    pub event_type: String,
    /// "start", "stop", "die", "kill", "oom", etc.
    pub action: String,
    /// Container/resource name.
    pub actor_name: String,
    /// Container ID (short, first 12 chars).
    pub actor_id: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdEvent {
    pub timestamp: DateTime<Utc>,
    /// e.g. "nginx.service"
    pub unit: String,
    /// syslog priority (0=emerg … 7=debug)
    pub priority: i32,
    pub message: String,
}

// ---------------------------------------------------------------------------
// EventSource trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait EventSource: Send + Sync {
    /// Stream events until the sender is dropped or an error occurs.
    async fn stream(&self, tx: mpsc::Sender<StreamEvent>) -> anyhow::Result<()>;
}

// ---------------------------------------------------------------------------
// Docker event source
// ---------------------------------------------------------------------------

pub struct DockerEventSource;

#[async_trait]
impl EventSource for DockerEventSource {
    async fn stream(&self, tx: mpsc::Sender<StreamEvent>) -> anyhow::Result<()> {
        debug!("Starting local docker event stream");
        let mut child = Command::new("docker")
            .args(["events", "--format", "{{json .}}"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture docker events stdout"))?;

        let mut lines = BufReader::new(stdout).lines();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            match parse_docker_event(&line) {
                Ok(ev) => {
                    if tx.send(StreamEvent::Docker(ev)).await.is_err() {
                        break; // receiver dropped
                    }
                }
                Err(e) => {
                    warn!(error = %e, raw = %line, "Skipping unparseable docker event");
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Systemd event source
// ---------------------------------------------------------------------------

pub struct SystemdEventSource;

#[async_trait]
impl EventSource for SystemdEventSource {
    async fn stream(&self, tx: mpsc::Sender<StreamEvent>) -> anyhow::Result<()> {
        debug!("Starting local systemd journal stream");
        let mut child = Command::new("journalctl")
            .args(["-f", "-n", "0", "-o", "json"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture journalctl stdout"))?;

        let mut lines = BufReader::new(stdout).lines();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            match parse_systemd_event(&line) {
                Ok(ev) => {
                    // Only forward errors and warnings (priority ≤ 4).
                    if ev.priority > 4 {
                        continue;
                    }
                    if tx.send(StreamEvent::Systemd(ev)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!(error = %e, raw = %line, "Skipping unparseable journalctl event");
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SSH event source
// ---------------------------------------------------------------------------

/// Streams Docker events and systemd journal entries from a remote host over SSH.
///
/// Spawns two child processes:
///   - `ssh … docker events --format json`
///   - `ssh … journalctl -f -n 0 -o json`
///
/// Each line of stdout is parsed and forwarded as a [`StreamEvent`].
pub struct SshEventSource {
    host: String,
    user: String,
    key_path: String,
    port: u16,
    name: String,
}

impl SshEventSource {
    pub fn new(host: String, user: String, key_path: String, port: u16, name: String) -> Self {
        Self {
            host,
            user,
            key_path,
            port,
            name,
        }
    }

    /// Build the base SSH command with common flags.
    fn ssh_command(&self, remote_cmd: &str) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "BatchMode=yes",
            "-i",
            &self.key_path,
            "-p",
            &self.port.to_string(),
            &format!("{}@{}", self.user, self.host),
        ])
        .args(remote_cmd.split_whitespace())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
        cmd
    }
}

#[async_trait]
impl EventSource for SshEventSource {
    async fn stream(&self, tx: mpsc::Sender<StreamEvent>) -> anyhow::Result<()> {
        debug!(target = %self.name, host = %self.host, user = %self.user, port = self.port, "Starting SSH event stream");
        // Spawn both Docker events and journalctl streams concurrently.
        let docker_tx = tx.clone();
        let name = self.name.clone();

        let mut docker_child = self
            .ssh_command("docker events --format {{json .}}")
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!("failed to spawn SSH docker-events for '{}': {e}", name)
            })?;

        let docker_stdout = docker_child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture SSH docker stdout"))?;

        let docker_handle = tokio::spawn(async move {
            let mut lines = BufReader::new(docker_stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                match parse_docker_event(&line) {
                    Ok(ev) => {
                        if docker_tx.send(StreamEvent::Docker(ev)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, raw = %line, target = %name, "Skipping unparseable SSH docker event");
                    }
                }
            }
        });

        let journal_tx = tx;
        let name2 = self.name.clone();

        let mut journal_child = self
            .ssh_command("journalctl -f -n 0 -o json")
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn SSH journalctl for '{}': {e}", name2))?;

        let journal_stdout = journal_child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture SSH journalctl stdout"))?;

        let journal_handle = tokio::spawn(async move {
            let mut lines = BufReader::new(journal_stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                match parse_systemd_event(&line) {
                    Ok(ev) => {
                        if ev.priority > 4 {
                            continue;
                        }
                        if journal_tx.send(StreamEvent::Systemd(ev)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, raw = %line, target = %name2, "Skipping unparseable SSH journalctl event");
                    }
                }
            }
        });

        // Wait for both to finish (they run until the SSH connection drops or
        // the receiver is closed).
        let _ = tokio::join!(docker_handle, journal_handle);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EventStreamManager
// ---------------------------------------------------------------------------

pub struct EventStreamManager {
    sources: Vec<Box<dyn EventSource>>,
}

impl EventStreamManager {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    pub fn add_docker_source(&mut self) {
        self.sources.push(Box::new(DockerEventSource));
    }

    pub fn add_systemd_source(&mut self) {
        self.sources.push(Box::new(SystemdEventSource));
    }

    pub fn add_ssh_source(
        &mut self,
        host: String,
        user: String,
        key_path: String,
        port: u16,
        name: String,
    ) {
        self.sources.push(Box::new(SshEventSource::new(
            host, user, key_path, port, name,
        )));
    }

    /// Start all sources, multiplexing events onto a single channel.
    pub async fn run(&self, tx: mpsc::Sender<StreamEvent>) -> anyhow::Result<()> {
        let mut handles = Vec::new();

        for (i, source) in self.sources.iter().enumerate() {
            // Each source gets its own clone of the sender.
            let tx = tx.clone();
            // SAFETY: We need 'static futures for tokio::spawn. The sources
            // live for the duration of `run` which awaits all handles, but we
            // cannot express that to the borrow-checker. Instead we use an
            // unsafe transmute to extend the lifetime. The caller must ensure
            // `self` outlives the spawned tasks (guaranteed because we join
            // all handles before returning).
            let source_ref: &dyn EventSource = source.as_ref();
            let source_static: &'static dyn EventSource =
                unsafe { std::mem::transmute(source_ref) };
            let handle = tokio::spawn(async move {
                if let Err(e) = source_static.stream(tx).await {
                    error!(source_index = i, error = %e, "Event source failed");
                }
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Alert mapping
// ---------------------------------------------------------------------------

/// Map a [`StreamEvent`] to an alert message string for notification.
/// Returns `None` for events that do not warrant an alert.
pub fn event_to_alert(event: &StreamEvent) -> Option<String> {
    match event {
        StreamEvent::Docker(ev) => {
            let action = ev.action.as_str();
            match action {
                "die" | "stop" | "kill" | "oom" => {
                    let exit = ev
                        .exit_code
                        .map(|c| format!(" (exit {c})"))
                        .unwrap_or_default();
                    Some(format!("Container {} {action}{exit}", ev.actor_name))
                }
                _ => None,
            }
        }
        StreamEvent::Systemd(ev) => {
            // priority 0–3 → alert (emerg/alert/crit/err)
            if ev.priority <= 3 {
                Some(format!("Service {}: {}", ev.unit, ev.message))
            } else {
                None // priority 4 (warning) is info-only
            }
        }
    }
}

/// Format a stream event for terminal display.
pub fn format_event(event: &StreamEvent) -> String {
    match event {
        StreamEvent::Docker(ev) => {
            let icon = match ev.action.as_str() {
                "die" | "stop" | "kill" | "oom" => "\u{1f534}",
                "start" => "\u{1f7e2}",
                _ => "\u{26aa}",
            };
            let exit = ev
                .exit_code
                .map(|c| format!(" (exit {c})"))
                .unwrap_or_default();
            format!(
                "[{}] {icon} Container {} {}{exit}",
                ev.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
                ev.actor_name,
                ev.action,
            )
        }
        StreamEvent::Systemd(ev) => {
            let icon = if ev.priority <= 3 {
                "\u{1f534}"
            } else {
                "\u{1f7e1}"
            };
            format!(
                "[{}] {icon} Service {}: {}",
                ev.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
                ev.unit,
                ev.message,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// JSON parsing
// ---------------------------------------------------------------------------

/// Parse a single line of `docker events --format '{{json .}}'` output.
pub fn parse_docker_event(json: &str) -> anyhow::Result<DockerEvent> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;

    let time_secs = v.get("time").and_then(|t| t.as_i64()).unwrap_or_default();

    let timestamp = Utc
        .timestamp_opt(time_secs, 0)
        .single()
        .unwrap_or_else(Utc::now);

    let event_type = v
        .get("Type")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let action = v
        .get("Action")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let actor = v.get("Actor");

    let actor_attrs = actor.and_then(|a| a.get("Attributes"));

    let actor_name = actor_attrs
        .and_then(|a| a.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let raw_id = v.get("id").and_then(|v| v.as_str()).unwrap_or_default();
    let actor_id = raw_id.chars().take(12).collect();

    let exit_code = actor_attrs
        .and_then(|a| a.get("exitCode"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i32>().ok());

    Ok(DockerEvent {
        timestamp,
        event_type,
        action,
        actor_name,
        actor_id,
        exit_code,
    })
}

/// Parse a single line of `journalctl -o json` output.
pub fn parse_systemd_event(json: &str) -> anyhow::Result<SystemdEvent> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;

    // __REALTIME_TIMESTAMP is microseconds since epoch (as a string).
    let usec: i64 = v
        .get("__REALTIME_TIMESTAMP")
        .and_then(|t| t.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or_default();

    let secs = usec / 1_000_000;
    let nsecs = u32::try_from((usec % 1_000_000) * 1_000).unwrap_or(0);
    let timestamp = Utc
        .timestamp_opt(secs, nsecs)
        .single()
        .unwrap_or_else(Utc::now);

    let unit = v
        .get("_SYSTEMD_UNIT")
        .or_else(|| v.get("UNIT"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let priority: i32 = v
        .get("PRIORITY")
        .and_then(|p| p.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    let message = v
        .get("MESSAGE")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    Ok(SystemdEvent {
        timestamp,
        unit,
        priority,
        message,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_docker_die_event() {
        let json = r#"{"status":"die","id":"abc123def456789","from":"nginx:latest","Type":"container","Action":"die","Actor":{"ID":"abc123def456789","Attributes":{"exitCode":"137","name":"my-container"}},"time":1710000000,"timeNano":1710000000000000000}"#;

        let ev = parse_docker_event(json).unwrap();
        assert_eq!(ev.event_type, "container");
        assert_eq!(ev.action, "die");
        assert_eq!(ev.actor_name, "my-container");
        assert_eq!(ev.actor_id, "abc123def456");
        assert_eq!(ev.exit_code, Some(137));
        assert_eq!(ev.timestamp.timestamp(), 1_710_000_000);
    }

    #[test]
    fn parse_docker_start_event() {
        let json = r#"{"status":"start","id":"deadbeef1234","from":"redis:7","Type":"container","Action":"start","Actor":{"ID":"deadbeef1234","Attributes":{"name":"redis-cache"}},"time":1710000100,"timeNano":1710000100000000000}"#;

        let ev = parse_docker_event(json).unwrap();
        assert_eq!(ev.action, "start");
        assert_eq!(ev.actor_name, "redis-cache");
        assert_eq!(ev.exit_code, None);
    }

    #[test]
    fn parse_docker_oom_event() {
        let json = r#"{"status":"oom","id":"oom123456789ab","Type":"container","Action":"oom","Actor":{"ID":"oom123456789ab","Attributes":{"name":"hungry-app"}},"time":1710000200}"#;

        let ev = parse_docker_event(json).unwrap();
        assert_eq!(ev.action, "oom");
        assert_eq!(ev.actor_name, "hungry-app");
    }

    #[test]
    fn parse_docker_invalid_json() {
        assert!(parse_docker_event("not json").is_err());
    }

    #[test]
    fn parse_systemd_error_event() {
        let json = r#"{"__REALTIME_TIMESTAMP":"1710000000123456","_SYSTEMD_UNIT":"nginx.service","PRIORITY":"3","MESSAGE":"Failed with result 'exit-code'"}"#;

        let ev = parse_systemd_event(json).unwrap();
        assert_eq!(ev.unit, "nginx.service");
        assert_eq!(ev.priority, 3);
        assert_eq!(ev.message, "Failed with result 'exit-code'");
        assert_eq!(ev.timestamp.timestamp(), 1_710_000_000);
    }

    #[test]
    fn parse_systemd_warning_event() {
        let json = r#"{"__REALTIME_TIMESTAMP":"1710000001000000","_SYSTEMD_UNIT":"postgres.service","PRIORITY":"4","MESSAGE":"Connection pool nearing limit"}"#;

        let ev = parse_systemd_event(json).unwrap();
        assert_eq!(ev.priority, 4);
        assert_eq!(ev.unit, "postgres.service");
    }

    #[test]
    fn parse_systemd_uses_unit_fallback() {
        let json = r#"{"__REALTIME_TIMESTAMP":"1710000002000000","UNIT":"sshd.service","PRIORITY":"3","MESSAGE":"Auth failure"}"#;

        let ev = parse_systemd_event(json).unwrap();
        assert_eq!(ev.unit, "sshd.service");
    }

    #[test]
    fn parse_systemd_invalid_json() {
        assert!(parse_systemd_event("{bad").is_err());
    }

    #[test]
    fn alert_docker_die() {
        let ev = StreamEvent::Docker(DockerEvent {
            timestamp: Utc::now(),
            event_type: "container".into(),
            action: "die".into(),
            actor_name: "sacra-api".into(),
            actor_id: "abc123".into(),
            exit_code: Some(137),
        });
        let alert = event_to_alert(&ev);
        assert_eq!(alert, Some("Container sacra-api die (exit 137)".into()));
    }

    #[test]
    fn alert_docker_oom() {
        let ev = StreamEvent::Docker(DockerEvent {
            timestamp: Utc::now(),
            event_type: "container".into(),
            action: "oom".into(),
            actor_name: "hungry".into(),
            actor_id: "xyz".into(),
            exit_code: None,
        });
        let alert = event_to_alert(&ev);
        assert_eq!(alert, Some("Container hungry oom".into()));
    }

    #[test]
    fn alert_docker_start_is_none() {
        let ev = StreamEvent::Docker(DockerEvent {
            timestamp: Utc::now(),
            event_type: "container".into(),
            action: "start".into(),
            actor_name: "app".into(),
            actor_id: "id".into(),
            exit_code: None,
        });
        assert!(event_to_alert(&ev).is_none());
    }

    #[test]
    fn alert_systemd_error() {
        let ev = StreamEvent::Systemd(SystemdEvent {
            timestamp: Utc::now(),
            unit: "nginx.service".into(),
            priority: 3,
            message: "Failed with result 'exit-code'".into(),
        });
        let alert = event_to_alert(&ev);
        assert_eq!(
            alert,
            Some("Service nginx.service: Failed with result 'exit-code'".into())
        );
    }

    #[test]
    fn alert_systemd_warning_is_none() {
        let ev = StreamEvent::Systemd(SystemdEvent {
            timestamp: Utc::now(),
            unit: "postgres.service".into(),
            priority: 4,
            message: "something".into(),
        });
        assert!(event_to_alert(&ev).is_none());
    }

    #[test]
    fn format_docker_die_event() {
        let ev = StreamEvent::Docker(DockerEvent {
            timestamp: Utc.with_ymd_and_hms(2026, 3, 17, 6, 0, 1).unwrap(),
            event_type: "container".into(),
            action: "die".into(),
            actor_name: "sacra-api".into(),
            actor_id: "abc123".into(),
            exit_code: Some(137),
        });
        let formatted = format_event(&ev);
        assert!(formatted.contains("sacra-api"));
        assert!(formatted.contains("die"));
        assert!(formatted.contains("exit 137"));
    }

    #[test]
    fn format_systemd_error_event() {
        let ev = StreamEvent::Systemd(SystemdEvent {
            timestamp: Utc.with_ymd_and_hms(2026, 3, 17, 6, 0, 2).unwrap(),
            unit: "nginx.service".into(),
            priority: 3,
            message: "Failed with result 'exit-code'".into(),
        });
        let formatted = format_event(&ev);
        assert!(formatted.contains("nginx.service"));
        assert!(formatted.contains("Failed"));
    }

    #[test]
    fn ssh_event_source_constructs() {
        let source = SshEventSource::new(
            "10.0.0.1".into(),
            "deploy".into(),
            "/tmp/test-key".into(),
            2222,
            "prod-web".into(),
        );
        assert_eq!(source.host, "10.0.0.1");
        assert_eq!(source.user, "deploy");
        assert_eq!(source.key_path, "/tmp/test-key");
        assert_eq!(source.port, 2222);
        assert_eq!(source.name, "prod-web");
    }

    #[test]
    fn ssh_event_source_ssh_command_args() {
        let source = SshEventSource::new(
            "10.0.0.1".into(),
            "deploy".into(),
            "/tmp/test-key".into(),
            2222,
            "prod-web".into(),
        );
        let cmd = source.ssh_command("docker events --format json");
        let prog = cmd.as_std().get_program();
        assert_eq!(prog, "ssh");
        let args: Vec<_> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy())
            .collect();
        assert!(args.contains(&"-i".into()));
        assert!(args.contains(&"/tmp/test-key".into()));
        assert!(args.contains(&"-p".into()));
        assert!(args.contains(&"2222".into()));
        assert!(args.contains(&"deploy@10.0.0.1".into()));
        assert!(args.contains(&"docker".into()));
        assert!(args.contains(&"events".into()));
    }

    #[test]
    fn manager_add_ssh_source() {
        let mut manager = EventStreamManager::new();
        assert_eq!(manager.sources.len(), 0);
        manager.add_ssh_source(
            "host".into(),
            "user".into(),
            "/key".into(),
            22,
            "test".into(),
        );
        assert_eq!(manager.sources.len(), 1);
    }
}
