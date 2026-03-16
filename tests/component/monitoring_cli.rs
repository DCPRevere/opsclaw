use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use zeroclaw::ops::{monitor_log, snapshots};
use zeroclaw::tools::discovery::*;
use zeroclaw::tools::monitoring::*;

// ---------------------------------------------------------------------------
// Mock runner (shared with discovery_scan tests)
// ---------------------------------------------------------------------------

struct MockRunner {
    responses: std::collections::HashMap<String, CommandOutput>,
}

impl MockRunner {
    fn new() -> Self {
        Self {
            responses: std::collections::HashMap::new(),
        }
    }

    fn add(&mut self, cmd: &str, stdout: &str) {
        self.responses.insert(
            cmd.to_string(),
            CommandOutput {
                stdout: stdout.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    }
}

#[async_trait]
impl CommandRunner for MockRunner {
    async fn run(&self, command: &str) -> Result<CommandOutput> {
        self.responses
            .get(command)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unexpected command: {command}"))
    }
}

// ---------------------------------------------------------------------------
// Sample outputs (same as discovery_scan tests)
// ---------------------------------------------------------------------------

const UNAME_OUTPUT: &str = "Linux sacra-vps 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux";
const OS_RELEASE_OUTPUT: &str = "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n";
const SS_OUTPUT: &str = "State Recv-Q Send-Q Local\\ Address:Port Peer\\ Address:Port Process
LISTEN 0 4096 0.0.0.0:33000 0.0.0.0:* users:((\"docker-proxy\",pid=1234,fd=4))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=800,fd=3))
";
const DOCKER_PS_OUTPUT: &str = r#"{"ID":"abc123","Names":"sacra-api","Image":"sacra/api:latest","Status":"Up 5 hours","Ports":"0.0.0.0:33000->8080/tcp","RunningFor":"5 hours"}
{"ID":"def456","Names":"postgres","Image":"postgres:15","Status":"Up 5 hours","Ports":"5432/tcp","RunningFor":"5 hours"}
"#;
const SYSTEMCTL_OUTPUT: &str = "  UNIT LOAD ACTIVE SUB DESCRIPTION
  ssh.service loaded active running OpenBSD Secure Shell server
  docker.service loaded active running Docker Application Container Engine
";
const DF_OUTPUT: &str = "Filesystem Size Used Avail Use% Mounted\\ on
/dev/sda1 40G 22G 16G 58% /
";
const FREE_OUTPUT: &str =
    "              total        used        free      shared  buff/cache   available
Mem:           7951        3042         512         123        4396        4558
Swap:          2047         100        1947
";
const UPTIME_OUTPUT: &str =
    " 14:23:05 up 42 days,  3:15,  2 users,  load average: 0.45, 0.30, 0.25";

fn mock_runner() -> MockRunner {
    let mut runner = MockRunner::new();
    runner.add("uname -a", UNAME_OUTPUT);
    runner.add("cat /etc/os-release", OS_RELEASE_OUTPUT);
    runner.add("ss -tlnp", SS_OUTPUT);
    runner.add("docker ps --format json", DOCKER_PS_OUTPUT);
    runner.add(
        "systemctl list-units --type=service --state=running --no-pager",
        SYSTEMCTL_OUTPUT,
    );
    runner.add("df -h", DF_OUTPUT);
    runner.add("free -m", FREE_OUTPUT);
    runner.add("uptime", UPTIME_OUTPUT);
    runner
}

// ---------------------------------------------------------------------------
// Snapshot save/load roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snapshot_save_load_roundtrip() {
    let runner = mock_runner();
    let snap = run_discovery_scan(&runner).await.unwrap();

    // Use a unique name to avoid clashing with concurrent test runs
    let target_name = format!("test-roundtrip-{}", std::process::id());

    snapshots::save_snapshot(&target_name, &snap).unwrap();
    let loaded = snapshots::load_snapshot(&target_name).unwrap().unwrap();

    assert_eq!(loaded.os.distro_name, snap.os.distro_name);
    assert_eq!(loaded.containers.len(), snap.containers.len());
    assert_eq!(loaded.services.len(), snap.services.len());
    assert_eq!(loaded.memory.total_mb, snap.memory.total_mb);

    // Cleanup
    let path = snapshots::snapshot_path(&target_name).unwrap();
    let _ = std::fs::remove_file(path);
}

#[test]
fn load_nonexistent_snapshot_returns_none() {
    let result = snapshots::load_snapshot("nonexistent-target-12345").unwrap();
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Monitor log format
// ---------------------------------------------------------------------------

#[test]
fn monitor_log_healthy_format() {
    let hc = HealthCheck {
        target_name: "sacra".into(),
        checked_at: Utc::now(),
        status: HealthStatus::Healthy,
        alerts: vec![],
    };
    let line = monitor_log::format_log_line(&hc);
    assert!(line.starts_with('['));
    assert!(line.contains("sacra HEALTHY"));
}

#[test]
fn monitor_log_critical_format() {
    let hc = HealthCheck {
        target_name: "sacra".into(),
        checked_at: Utc::now(),
        status: HealthStatus::Critical,
        alerts: vec![
            Alert {
                severity: AlertSeverity::Critical,
                category: AlertCategory::ContainerDown,
                message: "Container 'sacra-api' DOWN".into(),
            },
            Alert {
                severity: AlertSeverity::Warning,
                category: AlertCategory::DiskSpaceLow,
                message: "Disk '/' at 85% usage".into(),
            },
        ],
    };
    let line = monitor_log::format_log_line(&hc);
    assert!(line.contains("sacra CRITICAL"));
    assert!(line.contains("sacra-api"));
    assert!(line.contains("85%"));
}

#[test]
fn monitor_log_warning_format() {
    let hc = HealthCheck {
        target_name: "sacra".into(),
        checked_at: Utc::now(),
        status: HealthStatus::Warning,
        alerts: vec![Alert {
            severity: AlertSeverity::Warning,
            category: AlertCategory::DiskSpaceLow,
            message: "Disk '/' at 82% usage".into(),
        }],
    };
    let line = monitor_log::format_log_line(&hc);
    assert!(line.contains("sacra WARNING"));
    assert!(line.contains("82%"));
}

// ---------------------------------------------------------------------------
// Scan produces a valid snapshot from mock runner
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_produces_snapshot_from_mock_runner() {
    let runner = mock_runner();
    let snap = run_discovery_scan(&runner).await.unwrap();

    assert_eq!(snap.os.distro_name, "Ubuntu");
    assert_eq!(snap.os.distro_version, "22.04");
    assert_eq!(snap.containers.len(), 2);
    assert_eq!(snap.containers[0].name, "sacra-api");
    assert_eq!(snap.containers[1].name, "postgres");
    assert_eq!(snap.services.len(), 2);
    assert_eq!(snap.memory.total_mb, 7951);

    // Verify it serializes to JSON and back
    let json = serde_json::to_string(&snap).unwrap();
    let parsed: TargetSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.containers.len(), 2);
}

// ---------------------------------------------------------------------------
// Health check + log integration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_check_diff_produces_alerts_and_log_line() {
    let runner = mock_runner();
    let baseline = run_discovery_scan(&runner).await.unwrap();

    // Simulate a current state where sacra-api is missing
    let mut current = baseline.clone();
    current.containers.retain(|c| c.name != "sacra-api");

    let hc = check_health("sacra-vps", &baseline, &current);
    assert_eq!(hc.status, HealthStatus::Critical);

    let line = monitor_log::format_log_line(&hc);
    assert!(line.contains("sacra-vps CRITICAL"));
    assert!(line.contains("sacra-api"));
}
