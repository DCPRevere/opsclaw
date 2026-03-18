//! Log source discovery, collection, and level detection.
//!
//! Provides [`LogSourceType`] variants for Docker containers, systemd units,
//! and plain log files. Collection functions execute commands via
//! [`CommandRunner`] and parse output into [`LogEntry`] values with optional
//! severity detection.

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::tools::discovery::{CommandRunner, TargetSnapshot};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogSourceType {
    DockerContainer { container_name: String },
    SystemdUnit { unit_name: String },
    File { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: Option<DateTime<Utc>>,
    pub source: String,
    pub level: Option<LogLevel>,
    pub message: String,
    pub raw: String,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Fatal => write!(f, "FATAL"),
        }
    }
}

impl std::fmt::Display for LogSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogSourceType::DockerContainer { container_name } => {
                write!(f, "docker:{container_name}")
            }
            LogSourceType::SystemdUnit { unit_name } => write!(f, "systemd:{unit_name}"),
            LogSourceType::File { path } => write!(f, "file:{path}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Log level detection
// ---------------------------------------------------------------------------

/// Detect log level from a raw log line.
pub fn detect_log_level(line: &str) -> Option<LogLevel> {
    // Try JSON structured logs first.
    if line.trim_start().starts_with('{') {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(level_str) = val
                .get("level")
                .or_else(|| val.get("severity"))
                .and_then(|v| v.as_str())
            {
                return parse_level_keyword(level_str);
            }
        }
    }

    let upper = line.to_uppercase();

    // Python tracebacks / Java-Go stack traces.
    if upper.starts_with("TRACEBACK") || upper.contains("EXCEPTION") || upper.contains("PANIC:") {
        return Some(LogLevel::Error);
    }

    // Syslog-style `<N>` priority prefix.
    if let Some(rest) = line.strip_prefix('<') {
        if let Some(end) = rest.find('>') {
            if let Ok(pri) = rest[..end].parse::<u8>() {
                let severity = pri & 0x07; // low 3 bits = severity
                return match severity {
                    0 | 1 => Some(LogLevel::Fatal),  // emerg, alert
                    2 | 3 => Some(LogLevel::Error),  // crit, err
                    4 => Some(LogLevel::Warn),        // warning
                    5 | 6 => Some(LogLevel::Info),    // notice, info
                    _ => Some(LogLevel::Debug),       // debug
                };
            }
        }
    }

    // Keyword scan — match whole-ish tokens to reduce false positives.
    for token in ["FATAL", "CRITICAL"] {
        if upper.contains(token) {
            return Some(LogLevel::Fatal);
        }
    }
    for token in ["ERROR", "ERR "] {
        if upper.contains(token) {
            return Some(LogLevel::Error);
        }
    }
    for token in ["WARNING", "WARN "] {
        if upper.contains(token) {
            return Some(LogLevel::Warn);
        }
    }
    if upper.contains("INFO") {
        return Some(LogLevel::Info);
    }
    if upper.contains("DEBUG") {
        return Some(LogLevel::Debug);
    }

    None
}

fn parse_level_keyword(s: &str) -> Option<LogLevel> {
    match s.to_uppercase().as_str() {
        "FATAL" | "CRITICAL" | "EMERG" | "ALERT" => Some(LogLevel::Fatal),
        "ERROR" | "ERR" => Some(LogLevel::Error),
        "WARNING" | "WARN" => Some(LogLevel::Warn),
        "INFO" | "NOTICE" => Some(LogLevel::Info),
        "DEBUG" | "TRACE" => Some(LogLevel::Debug),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Docker log timestamp parsing
// ---------------------------------------------------------------------------

/// Parse a Docker `--timestamps` log line: `2024-03-17T12:00:00.123456789Z message`.
fn parse_docker_log_line(line: &str, container: &str) -> LogEntry {
    let (timestamp, message) = if line.len() > 30 && line.as_bytes().get(4) == Some(&b'-') {
        // Try to split on first space after the timestamp.
        if let Some(idx) = line.find(' ') {
            let ts_str = &line[..idx];
            // Docker timestamps: 2024-03-17T12:00:00.123456789Z
            // chrono can't parse 9-digit nanoseconds, truncate to micros.
            let ts_trimmed = if ts_str.contains('.') {
                // Truncate fractional seconds to 6 digits for chrono.
                let dot = ts_str.find('.').unwrap();
                let after_dot = &ts_str[dot + 1..];
                let z_pos = after_dot.find('Z').unwrap_or(after_dot.len());
                let frac = &after_dot[..z_pos];
                let frac_6 = if frac.len() > 6 { &frac[..6] } else { frac };
                format!("{}.{frac_6}Z", &ts_str[..dot])
            } else {
                ts_str.to_string()
            };

            let ts = DateTime::parse_from_rfc3339(&ts_trimmed)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
            (ts, line[idx + 1..].to_string())
        } else {
            (None, line.to_string())
        }
    } else {
        (None, line.to_string())
    };

    let level = detect_log_level(&message);

    LogEntry {
        timestamp,
        source: format!("docker:{container}"),
        level,
        message: message.clone(),
        raw: line.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Journalctl output parsing
// ---------------------------------------------------------------------------

/// Parse a `journalctl -o short-iso` line: `2024-03-17T12:00:00+0000 host unit[pid]: message`.
fn parse_journalctl_log_line(line: &str, unit: &str) -> LogEntry {
    let (timestamp, message) = if line.len() > 24 && line.as_bytes().get(4) == Some(&b'-') {
        if let Some(idx) = line.find(' ') {
            let ts_str = &line[..idx];
            let ts = NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S%z")
                .map(|ndt| ndt.and_utc())
                .ok()
                .or_else(|| {
                    DateTime::parse_from_rfc3339(ts_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                });

            // The message is typically after "host unit[pid]: " — find the colon.
            let msg = if let Some(colon_idx) = line[idx..].find(": ") {
                line[idx + colon_idx + 2..].to_string()
            } else {
                line[idx + 1..].to_string()
            };
            (ts, msg)
        } else {
            (None, line.to_string())
        }
    } else {
        (None, line.to_string())
    };

    let level = detect_log_level(&message);

    LogEntry {
        timestamp,
        source: format!("systemd:{unit}"),
        level,
        message: message.clone(),
        raw: line.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Collection functions
// ---------------------------------------------------------------------------

/// Collect recent logs from a Docker container.
pub async fn collect_docker_logs(
    runner: &dyn CommandRunner,
    container: &str,
    lines: usize,
    since: Option<&str>,
) -> Result<Vec<LogEntry>> {
    let mut cmd = format!("docker logs --tail {lines} --timestamps {container}");
    if let Some(since_val) = since {
        cmd = format!("docker logs --tail {lines} --timestamps --since {since_val} {container}");
    }

    let output = runner.run(&cmd).await?;
    // Docker logs may go to stdout or stderr; combine both.
    let combined = if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    };

    Ok(combined
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| parse_docker_log_line(l, container))
        .collect())
}

/// Collect recent logs from a systemd unit via journalctl.
pub async fn collect_journalctl_logs(
    runner: &dyn CommandRunner,
    unit: &str,
    lines: usize,
    since: Option<&str>,
) -> Result<Vec<LogEntry>> {
    let cmd = if let Some(since_val) = since {
        format!("journalctl -u {unit} -n {lines} --no-pager -o short-iso --since \"{since_val}\"")
    } else {
        format!("journalctl -u {unit} -n {lines} --no-pager -o short-iso")
    };

    let output = runner.run(&cmd).await?;

    Ok(output
        .stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        // journalctl -o short-iso has a header line starting with "-- "
        .filter(|l| !l.starts_with("-- "))
        .map(|l| parse_journalctl_log_line(l, unit))
        .collect())
}

/// Collect recent lines from a log file via `tail`.
pub async fn collect_file_logs(
    runner: &dyn CommandRunner,
    path: &str,
    lines: usize,
) -> Result<Vec<LogEntry>> {
    let cmd = format!("tail -n {lines} {path}");
    let output = runner.run(&cmd).await?;

    Ok(output
        .stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let level = detect_log_level(l);
            LogEntry {
                timestamp: None,
                source: format!("file:{path}"),
                level,
                message: l.to_string(),
                raw: l.to_string(),
            }
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Auto-discover log sources from a snapshot
// ---------------------------------------------------------------------------

/// Well-known log file paths to check.
const WELL_KNOWN_LOG_FILES: &[&str] = &[
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/nginx/error.log",
    "/var/log/nginx/access.log",
    "/var/log/apache2/error.log",
    "/var/log/mysql/error.log",
    "/var/log/postgresql/postgresql-main.log",
];

/// Derive log sources from an existing discovery snapshot.
pub fn discover_log_sources(snapshot: &TargetSnapshot) -> Vec<LogSourceType> {
    let mut sources = Vec::new();

    for c in &snapshot.containers {
        sources.push(LogSourceType::DockerContainer {
            container_name: c.name.clone(),
        });
    }

    for s in &snapshot.services {
        if s.active_state == "active" {
            sources.push(LogSourceType::SystemdUnit {
                unit_name: s.unit.clone(),
            });
        }
    }

    for &path in WELL_KNOWN_LOG_FILES {
        sources.push(LogSourceType::File {
            path: path.to_string(),
        });
    }

    sources
}

/// Collect logs from a single source.
pub async fn collect_logs(
    runner: &dyn CommandRunner,
    source: &LogSourceType,
    lines: usize,
    since: Option<&str>,
) -> Result<Vec<LogEntry>> {
    match source {
        LogSourceType::DockerContainer { container_name } => {
            collect_docker_logs(runner, container_name, lines, since).await
        }
        LogSourceType::SystemdUnit { unit_name } => {
            collect_journalctl_logs(runner, unit_name, lines, since).await
        }
        LogSourceType::File { path } => collect_file_logs(runner, path, lines).await,
    }
}

/// Format a log entry for terminal display.
pub fn format_log_entry(entry: &LogEntry) -> String {
    let ts = entry
        .timestamp
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "----".to_string());

    let level_tag = entry
        .level
        .as_ref()
        .map(|l| format!("[{l}]"))
        .unwrap_or_default();

    format!("{ts} {level_tag} ({}) {}", entry.source, entry.message)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::discovery::{
        CommandOutput, ContainerInfo, DiskInfo, LoadInfo, MemoryInfo, OsInfo, PortInfo,
        ServiceInfo, TargetSnapshot,
    };
    use async_trait::async_trait;

    struct MockRunner {
        responses: std::collections::HashMap<String, CommandOutput>,
    }

    impl MockRunner {
        fn new() -> Self {
            Self {
                responses: std::collections::HashMap::new(),
            }
        }

        fn add_response(&mut self, cmd_prefix: &str, stdout: &str) {
            self.responses.insert(
                cmd_prefix.to_string(),
                CommandOutput {
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            );
        }

        fn add_stderr_response(&mut self, cmd_prefix: &str, stderr: &str) {
            self.responses.insert(
                cmd_prefix.to_string(),
                CommandOutput {
                    stdout: String::new(),
                    stderr: stderr.to_string(),
                    exit_code: 0,
                },
            );
        }
    }

    #[async_trait]
    impl CommandRunner for MockRunner {
        async fn run(&self, command: &str) -> Result<CommandOutput> {
            for (prefix, output) in &self.responses {
                if command.starts_with(prefix) {
                    return Ok(output.clone());
                }
            }
            anyhow::bail!("unexpected command: {command}")
        }
    }

    fn make_snapshot(containers: Vec<&str>, services: Vec<(&str, &str)>) -> TargetSnapshot {
        TargetSnapshot {
            scanned_at: Utc::now(),
            os: OsInfo {
                uname: "Linux".into(),
                distro_name: "Ubuntu".into(),
                distro_version: "22.04".into(),
            },
            containers: containers
                .into_iter()
                .map(|name| ContainerInfo {
                    id: "abc123".into(),
                    name: name.to_string(),
                    image: "img".into(),
                    status: "Up".into(),
                    ports: String::new(),
                    running_for: "1h".into(),
                })
                .collect(),
            services: services
                .into_iter()
                .map(|(unit, state)| ServiceInfo {
                    unit: unit.to_string(),
                    load_state: "loaded".into(),
                    active_state: state.to_string(),
                    sub_state: "running".into(),
                    description: String::new(),
                })
                .collect(),
            listening_ports: vec![PortInfo {
                protocol: "tcp".into(),
                address: "*".into(),
                port: 80,
                process: "nginx".into(),
            }],
            disk: vec![DiskInfo {
                filesystem: "/dev/sda1".into(),
                size: "50G".into(),
                used: "20G".into(),
                available: "30G".into(),
                use_percent: 40,
                mount_point: "/".into(),
            }],
            memory: MemoryInfo {
                total_mb: 8000,
                used_mb: 4000,
                free_mb: 2000,
                available_mb: 4000,
            },
            load: LoadInfo {
                load_1: 0.5,
                load_5: 0.3,
                load_15: 0.2,
                uptime: "up 10 days".into(),
            },
            kubernetes: None,
        }
    }

    // ----- Log level detection tests -----

    #[test]
    fn detect_level_error_keyword() {
        assert_eq!(
            detect_log_level("2024-03-17 ERROR something failed"),
            Some(LogLevel::Error)
        );
    }

    #[test]
    fn detect_level_warn_keyword() {
        assert_eq!(
            detect_log_level("2024-03-17 WARNING disk space low"),
            Some(LogLevel::Warn)
        );
        assert_eq!(
            detect_log_level("WARN connection pool nearing limit"),
            Some(LogLevel::Warn)
        );
    }

    #[test]
    fn detect_level_fatal_keyword() {
        assert_eq!(
            detect_log_level("FATAL: unable to start"),
            Some(LogLevel::Fatal)
        );
        assert_eq!(
            detect_log_level("CRITICAL database corrupted"),
            Some(LogLevel::Fatal)
        );
    }

    #[test]
    fn detect_level_info_keyword() {
        assert_eq!(
            detect_log_level("INFO server started on :8080"),
            Some(LogLevel::Info)
        );
    }

    #[test]
    fn detect_level_debug_keyword() {
        assert_eq!(
            detect_log_level("DEBUG processing request id=42"),
            Some(LogLevel::Debug)
        );
    }

    #[test]
    fn detect_level_json_structured() {
        let line = r#"{"level":"error","message":"connection refused","timestamp":"2024-03-17T12:00:00Z"}"#;
        assert_eq!(detect_log_level(line), Some(LogLevel::Error));
    }

    #[test]
    fn detect_level_json_severity_field() {
        let line = r#"{"severity":"WARNING","msg":"slow query"}"#;
        assert_eq!(detect_log_level(line), Some(LogLevel::Warn));
    }

    #[test]
    fn detect_level_syslog_priority() {
        // priority 11 = facility 1, severity 3 (err)
        assert_eq!(detect_log_level("<11>some error message"), Some(LogLevel::Error));
        // priority 4 = severity 4 (warning)
        assert_eq!(detect_log_level("<4>warning message"), Some(LogLevel::Warn));
    }

    #[test]
    fn detect_level_python_traceback() {
        assert_eq!(
            detect_log_level("Traceback (most recent call last):"),
            Some(LogLevel::Error)
        );
    }

    #[test]
    fn detect_level_go_panic() {
        assert_eq!(
            detect_log_level("goroutine 1 [running]: panic: runtime error"),
            Some(LogLevel::Error)
        );
    }

    #[test]
    fn detect_level_none_for_plain_text() {
        assert_eq!(detect_log_level("just some normal log output"), None);
    }

    // ----- Docker log timestamp parsing -----

    #[test]
    fn parse_docker_log_with_timestamp() {
        let line = "2024-03-17T12:00:00.123456789Z ERROR something went wrong";
        let entry = parse_docker_log_line(line, "my-app");
        assert!(entry.timestamp.is_some());
        assert_eq!(entry.source, "docker:my-app");
        assert_eq!(entry.level, Some(LogLevel::Error));
        assert_eq!(entry.message, "ERROR something went wrong");
    }

    #[test]
    fn parse_docker_log_without_timestamp() {
        let line = "just a plain message";
        let entry = parse_docker_log_line(line, "my-app");
        assert!(entry.timestamp.is_none());
        assert_eq!(entry.message, "just a plain message");
    }

    // ----- Journalctl output parsing -----

    #[test]
    fn parse_journalctl_line() {
        let line = "2024-03-17T12:00:00+0000 myhost nginx[1234]: ERROR connection refused";
        let entry = parse_journalctl_log_line(line, "nginx.service");
        assert_eq!(entry.source, "systemd:nginx.service");
        assert_eq!(entry.level, Some(LogLevel::Error));
        assert!(entry.message.contains("connection refused"));
    }

    // ----- Collection via MockRunner -----

    #[tokio::test]
    async fn collect_docker_logs_parses_output() {
        let mut runner = MockRunner::new();
        runner.add_response(
            "docker logs",
            "2024-03-17T12:00:00.000000Z INFO started\n2024-03-17T12:00:01.000000Z ERROR crash\n",
        );

        let entries = collect_docker_logs(&runner, "app", 50, None).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].level, Some(LogLevel::Info));
        assert_eq!(entries[1].level, Some(LogLevel::Error));
    }

    #[tokio::test]
    async fn collect_docker_logs_from_stderr() {
        let mut runner = MockRunner::new();
        runner.add_stderr_response(
            "docker logs",
            "2024-03-17T12:00:00.000000Z ERROR panic\n",
        );

        let entries = collect_docker_logs(&runner, "app", 10, None).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].level, Some(LogLevel::Error));
    }

    #[tokio::test]
    async fn collect_journalctl_logs_parses_output() {
        let mut runner = MockRunner::new();
        runner.add_response(
            "journalctl",
            "2024-03-17T12:00:00+0000 host nginx[1]: INFO request served\n",
        );

        let entries = collect_journalctl_logs(&runner, "nginx.service", 50, None)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, "systemd:nginx.service");
    }

    #[tokio::test]
    async fn collect_file_logs_parses_output() {
        let mut runner = MockRunner::new();
        runner.add_response("tail", "ERROR disk full\nINFO recovered\n");

        let entries = collect_file_logs(&runner, "/var/log/syslog", 50)
            .await
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].level, Some(LogLevel::Error));
        assert_eq!(entries[1].level, Some(LogLevel::Info));
    }

    // ----- Auto-discovery -----

    #[test]
    fn discover_sources_from_snapshot() {
        let snap = make_snapshot(
            vec!["nginx", "redis"],
            vec![("nginx.service", "active"), ("cron.service", "inactive")],
        );

        let sources = discover_log_sources(&snap);

        // 2 containers + 1 active service + well-known files
        let docker_sources: Vec<_> = sources
            .iter()
            .filter(|s| matches!(s, LogSourceType::DockerContainer { .. }))
            .collect();
        assert_eq!(docker_sources.len(), 2);

        let systemd_sources: Vec<_> = sources
            .iter()
            .filter(|s| matches!(s, LogSourceType::SystemdUnit { .. }))
            .collect();
        assert_eq!(systemd_sources.len(), 1); // only active ones

        let file_sources: Vec<_> = sources
            .iter()
            .filter(|s| matches!(s, LogSourceType::File { .. }))
            .collect();
        assert_eq!(file_sources.len(), WELL_KNOWN_LOG_FILES.len());
    }

    #[test]
    fn discover_sources_empty_snapshot() {
        let snap = make_snapshot(vec![], vec![]);
        let sources = discover_log_sources(&snap);
        // Only well-known log files.
        assert_eq!(sources.len(), WELL_KNOWN_LOG_FILES.len());
    }
}
