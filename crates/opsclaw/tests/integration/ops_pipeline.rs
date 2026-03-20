//! Integration tests for the OpsClaw monitoring pipeline.
//!
//! Exercises: discovery scan → health-check diff → notifier wiring → full pipeline.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;

use opsclaw::ops::notifier::AlertNotifier;
use opsclaw::tools::discovery::{
    CommandOutput, CommandRunner, ContainerInfo, DiskInfo, LoadInfo, MemoryInfo, OsInfo, PortInfo,
    ServiceInfo, TargetSnapshot,
};
use opsclaw::tools::monitoring::{check_health, Alert, HealthCheck, HealthStatus};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// A mock command runner that returns canned output keyed by command substring.
struct MockCommandRunner {
    responses: Vec<(&'static str, CommandOutput)>,
}

impl MockCommandRunner {
    fn new(responses: Vec<(&'static str, CommandOutput)>) -> Self {
        Self { responses }
    }

    fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
        }
    }
}

#[async_trait]
impl CommandRunner for MockCommandRunner {
    async fn run(&self, command: &str) -> Result<CommandOutput> {
        for (pattern, output) in &self.responses {
            if command.contains(pattern) {
                return Ok(output.clone());
            }
        }
        Ok(CommandOutput {
            stdout: String::new(),
            stderr: format!("mock: unrecognised command: {command}"),
            exit_code: 1,
        })
    }
}

/// A mock notifier that captures all messages into shared vecs.
struct MockNotifier {
    alerts: Arc<Mutex<Vec<String>>>,
    texts: Arc<Mutex<Vec<String>>>,
    health_checks: Arc<Mutex<Vec<String>>>,
}

impl MockNotifier {
    #[allow(clippy::type_complexity)]
    fn new() -> (
        Self,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Vec<String>>>,
    ) {
        let alerts = Arc::new(Mutex::new(Vec::new()));
        let texts = Arc::new(Mutex::new(Vec::new()));
        let health_checks = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                alerts: Arc::clone(&alerts),
                texts: Arc::clone(&texts),
                health_checks: Arc::clone(&health_checks),
            },
            alerts,
            texts,
            health_checks,
        )
    }
}

#[async_trait]
impl AlertNotifier for MockNotifier {
    async fn notify_alert(&self, target_name: &str, alert: &Alert) -> anyhow::Result<()> {
        self.alerts
            .lock()
            .unwrap()
            .push(format!("[{target_name}] {}", alert.message));
        Ok(())
    }

    async fn notify(&self, target_name: &str, health: &HealthCheck) -> anyhow::Result<()> {
        self.health_checks.lock().unwrap().push(format!(
            "[{target_name}] {:?} ({} alerts)",
            health.status,
            health.alerts.len()
        ));
        Ok(())
    }

    async fn notify_text(&self, target_name: &str, message: &str) -> anyhow::Result<()> {
        self.texts
            .lock()
            .unwrap()
            .push(format!("[{target_name}] {message}"));
        Ok(())
    }
}

fn make_snapshot(containers: Vec<ContainerInfo>) -> TargetSnapshot {
    TargetSnapshot {
        scanned_at: Utc::now(),
        os: OsInfo {
            uname: "Linux test 6.1.0".to_string(),
            distro_name: "Ubuntu".to_string(),
            distro_version: "22.04".to_string(),
        },
        containers,
        services: vec![ServiceInfo {
            unit: "nginx.service".to_string(),
            load_state: "loaded".to_string(),
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
            description: "NGINX web server".to_string(),
        }],
        listening_ports: vec![PortInfo {
            protocol: "tcp".to_string(),
            address: "0.0.0.0".to_string(),
            port: 80,
            process: "nginx".to_string(),
        }],
        disk: vec![DiskInfo {
            filesystem: "/dev/sda1".to_string(),
            size: "50G".to_string(),
            used: "20G".to_string(),
            available: "28G".to_string(),
            use_percent: 42,
            mount_point: "/".to_string(),
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
            uptime: "up 10 days".to_string(),
        },
        kubernetes: None,
    }
}

fn three_containers() -> Vec<ContainerInfo> {
    vec![
        ContainerInfo {
            id: "aaa".into(),
            name: "web".into(),
            image: "nginx:latest".into(),
            status: "Up 2 hours".into(),
            ports: "80/tcp".into(),
            running_for: "2 hours".into(),
        },
        ContainerInfo {
            id: "bbb".into(),
            name: "api".into(),
            image: "myapp:1.0".into(),
            status: "Up 2 hours".into(),
            ports: "8080/tcp".into(),
            running_for: "2 hours".into(),
        },
        ContainerInfo {
            id: "ccc".into(),
            name: "db".into(),
            image: "postgres:16".into(),
            status: "Up 2 hours".into(),
            ports: "5432/tcp".into(),
            running_for: "2 hours".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Canned command outputs for MockCommandRunner
// ---------------------------------------------------------------------------

const UNAME_OUTPUT: &str = "Linux testhost 6.1.0-generic #1 SMP x86_64 GNU/Linux";

const OS_RELEASE_OUTPUT: &str = r#"NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu
PRETTY_NAME="Ubuntu 22.04.3 LTS"
"#;

const SS_OUTPUT: &str = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      511    0.0.0.0:80           0.0.0.0:*     users:((\"nginx\",pid=1234))
LISTEN 0      128    0.0.0.0:22           0.0.0.0:*     users:((\"sshd\",pid=567))
";

const SYSTEMCTL_OUTPUT: &str = "UNIT                 LOAD   ACTIVE SUB     DESCRIPTION
nginx.service        loaded active running NGINX web server
sshd.service         loaded active running OpenSSH server
";

const DF_OUTPUT: &str = "Filesystem     Size  Used Avail Use% Mounted on
/dev/sda1       50G   20G   28G  42% /
tmpfs          4.0G  100M  3.9G   3% /tmp
";

const FREE_OUTPUT: &str =
    "              total        used        free      shared  buff/cache   available
Mem:           8000        4000        2000         100        2000        4000
Swap:          2000         200        1800
";

const UPTIME_OUTPUT: &str =
    " 14:00:00 up 10 days,  5:30,  2 users,  load average: 0.50, 0.30, 0.20";

fn docker_ps_json(containers: &[(&str, &str, &str, &str, &str)]) -> String {
    containers
        .iter()
        .map(|(id, name, image, status, ports)| {
            serde_json::json!({
                "ID": id,
                "Names": name,
                "Image": image,
                "Status": status,
                "Ports": ports,
                "RunningFor": "2 hours"
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn baseline_runner() -> MockCommandRunner {
    let docker = docker_ps_json(&[
        ("aaa", "web", "nginx:latest", "Up 2 hours", "80/tcp"),
        ("bbb", "api", "myapp:1.0", "Up 2 hours", "8080/tcp"),
        ("ccc", "db", "postgres:16", "Up 2 hours", "5432/tcp"),
    ]);

    MockCommandRunner::new(vec![
        ("uname", MockCommandRunner::ok(UNAME_OUTPUT)),
        ("os-release", MockCommandRunner::ok(OS_RELEASE_OUTPUT)),
        ("ss ", MockCommandRunner::ok(SS_OUTPUT)),
        ("systemctl", MockCommandRunner::ok(SYSTEMCTL_OUTPUT)),
        ("df ", MockCommandRunner::ok(DF_OUTPUT)),
        ("free ", MockCommandRunner::ok(FREE_OUTPUT)),
        ("uptime", MockCommandRunner::ok(UPTIME_OUTPUT)),
        ("docker ps", MockCommandRunner::ok(&docker)),
    ])
}

fn degraded_runner() -> MockCommandRunner {
    // Only 2 containers — "db" is gone.
    let docker = docker_ps_json(&[
        ("aaa", "web", "nginx:latest", "Up 2 hours", "80/tcp"),
        ("bbb", "api", "myapp:1.0", "Up 2 hours", "8080/tcp"),
    ]);

    MockCommandRunner::new(vec![
        ("uname", MockCommandRunner::ok(UNAME_OUTPUT)),
        ("os-release", MockCommandRunner::ok(OS_RELEASE_OUTPUT)),
        ("ss ", MockCommandRunner::ok(SS_OUTPUT)),
        ("systemctl", MockCommandRunner::ok(SYSTEMCTL_OUTPUT)),
        ("df ", MockCommandRunner::ok(DF_OUTPUT)),
        ("free ", MockCommandRunner::ok(FREE_OUTPUT)),
        ("uptime", MockCommandRunner::ok(UPTIME_OUTPUT)),
        ("docker ps", MockCommandRunner::ok(&docker)),
    ])
}

// ===========================================================================
// Test 1: Mock CommandRunner → discovery scan → snapshot
// ===========================================================================

#[tokio::test]
async fn discovery_scan_produces_expected_snapshot() {
    use opsclaw::tools::discovery::run_discovery_scan;

    let runner = baseline_runner();
    let snap = run_discovery_scan(&runner)
        .await
        .expect("scan should succeed");

    // OS
    assert!(snap.os.uname.contains("Linux testhost"));
    assert_eq!(snap.os.distro_name, "Ubuntu");
    assert_eq!(snap.os.distro_version, "22.04");

    // Containers
    assert_eq!(snap.containers.len(), 3);
    let names: Vec<&str> = snap.containers.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"web"));
    assert!(names.contains(&"api"));
    assert!(names.contains(&"db"));

    // Services
    assert!(snap.services.len() >= 2);
    assert!(snap.services.iter().any(|s| s.unit == "nginx.service"));
    assert!(snap.services.iter().any(|s| s.unit == "sshd.service"));

    // Ports
    assert!(snap.listening_ports.iter().any(|p| p.port == 80));
    assert!(snap.listening_ports.iter().any(|p| p.port == 22));

    // Disk
    assert!(!snap.disk.is_empty());
    assert!(snap.disk.iter().any(|d| d.mount_point == "/"));
    let root = snap.disk.iter().find(|d| d.mount_point == "/").unwrap();
    assert_eq!(root.use_percent, 42);

    // Memory
    assert_eq!(snap.memory.total_mb, 8000);
    assert_eq!(snap.memory.used_mb, 4000);
    assert_eq!(snap.memory.available_mb, 4000);

    // Load
    assert!((snap.load.load_1 - 0.50).abs() < 0.01);
    assert!((snap.load.load_5 - 0.30).abs() < 0.01);
}

// ===========================================================================
// Test 2: Health check diff detection
// ===========================================================================

#[tokio::test]
async fn health_check_detects_missing_container() {
    let baseline = make_snapshot(three_containers());

    // Current: only 2 containers — "db" is stopped/missing.
    let current = make_snapshot(vec![
        ContainerInfo {
            id: "aaa".into(),
            name: "web".into(),
            image: "nginx:latest".into(),
            status: "Up 2 hours".into(),
            ports: "80/tcp".into(),
            running_for: "2 hours".into(),
        },
        ContainerInfo {
            id: "bbb".into(),
            name: "api".into(),
            image: "myapp:1.0".into(),
            status: "Up 2 hours".into(),
            ports: "8080/tcp".into(),
            running_for: "2 hours".into(),
        },
    ]);

    let hc = check_health("prod-server", &baseline, &current);

    assert_ne!(hc.status, HealthStatus::Healthy);
    assert!(!hc.alerts.is_empty());

    // There should be a ContainerDown alert for "db".
    let container_down_alerts: Vec<&Alert> = hc
        .alerts
        .iter()
        .filter(|a| a.message.contains("db"))
        .collect();
    assert!(
        !container_down_alerts.is_empty(),
        "expected an alert about the missing 'db' container"
    );
    assert!(container_down_alerts[0].message.contains("missing"));
}

// ===========================================================================
// Test 3: Notifier wiring (mock notifier)
// ===========================================================================

#[tokio::test]
async fn mock_notifier_captures_messages() {
    let (notifier, _alerts, texts, _hc) = MockNotifier::new();

    notifier
        .notify_text("staging", "disk is almost full")
        .await
        .unwrap();
    notifier
        .notify_text("staging", "container restarted")
        .await
        .unwrap();

    let captured = texts.lock().unwrap();
    assert_eq!(captured.len(), 2);
    assert!(captured[0].contains("staging"));
    assert!(captured[0].contains("disk is almost full"));
    assert!(captured[1].contains("container restarted"));
}

#[tokio::test]
async fn mock_notifier_captures_health_check() {
    let (notifier, _alerts, _texts, hc_log) = MockNotifier::new();

    let baseline = make_snapshot(three_containers());
    let current = make_snapshot(vec![three_containers()[0].clone()]);
    let hc = check_health("myhost", &baseline, &current);

    notifier.notify("myhost", &hc).await.unwrap();

    let captured = hc_log.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(captured[0].contains("myhost"));
}

#[tokio::test]
async fn mock_notifier_captures_individual_alerts() {
    let (notifier, alert_log, _texts, _hc) = MockNotifier::new();

    let alert = Alert {
        severity: opsclaw::tools::monitoring::AlertSeverity::Critical,
        category: opsclaw::tools::monitoring::AlertCategory::ContainerDown,
        message: "Container 'db' is gone".into(),
    };

    notifier.notify_alert("prod", &alert).await.unwrap();

    let captured = alert_log.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(captured[0].contains("prod"));
    assert!(captured[0].contains("db"));
}

// ===========================================================================
// Test 4: Full pipeline — scan → diff → health check → notify
// ===========================================================================

#[tokio::test]
async fn full_pipeline_scan_diff_notify() {
    use opsclaw::tools::discovery::run_discovery_scan;

    // First iteration: establish baseline.
    let baseline_runner = baseline_runner();
    let baseline = run_discovery_scan(&baseline_runner)
        .await
        .expect("baseline scan");
    assert_eq!(baseline.containers.len(), 3);

    // Second iteration: degraded state (missing container).
    let degraded = degraded_runner();
    let current = run_discovery_scan(&degraded).await.expect("current scan");
    assert_eq!(current.containers.len(), 2);

    // Health check detects the diff.
    let hc = check_health("prod", &baseline, &current);
    assert_ne!(hc.status, HealthStatus::Healthy);
    assert!(!hc.alerts.is_empty());

    // Wire through notifier.
    let (notifier, alert_log, _texts, hc_log) = MockNotifier::new();

    notifier.notify("prod", &hc).await.unwrap();
    for alert in &hc.alerts {
        notifier.notify_alert("prod", alert).await.unwrap();
    }

    // Notifier received the health-check summary.
    let hc_captured = hc_log.lock().unwrap();
    assert_eq!(hc_captured.len(), 1);
    assert!(hc_captured[0].contains("prod"));

    // Notifier received individual alerts, at least one about "db".
    let alerts_captured = alert_log.lock().unwrap();
    assert!(!alerts_captured.is_empty());
    assert!(
        alerts_captured.iter().any(|a| a.contains("db")),
        "expected alert about missing 'db' container, got: {alerts_captured:?}"
    );
}
