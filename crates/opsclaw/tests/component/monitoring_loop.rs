use chrono::Utc;
use zeroclaw::tools::discovery::*;
use zeroclaw::tools::monitoring::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn base_snapshot() -> TargetSnapshot {
    TargetSnapshot {
        scanned_at: Utc::now(),
        os: OsInfo {
            uname: "Linux test 5.15.0".to_string(),
            distro_name: "Ubuntu".to_string(),
            distro_version: "22.04".to_string(),
        },
        containers: vec![
            ContainerInfo {
                id: "abc123".into(),
                name: "sacra-api".into(),
                image: "sacra/api:latest".into(),
                status: "Up 5 hours".into(),
                ports: "0.0.0.0:33000->8080/tcp".into(),
                running_for: "5 hours".into(),
            },
            ContainerInfo {
                id: "def456".into(),
                name: "postgres".into(),
                image: "postgres:15".into(),
                status: "Up 5 hours".into(),
                ports: "5432/tcp".into(),
                running_for: "5 hours".into(),
            },
        ],
        services: vec![
            ServiceInfo {
                unit: "ssh.service".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                description: "OpenBSD Secure Shell server".into(),
            },
            ServiceInfo {
                unit: "docker.service".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                description: "Docker Application Container Engine".into(),
            },
        ],
        listening_ports: vec![
            PortInfo {
                protocol: "tcp".into(),
                address: "0.0.0.0".into(),
                port: 33000,
                process: "docker-proxy".into(),
            },
            PortInfo {
                protocol: "tcp".into(),
                address: "0.0.0.0".into(),
                port: 22,
                process: "sshd".into(),
            },
        ],
        disk: vec![DiskInfo {
            filesystem: "/dev/sda1".into(),
            size: "40G".into(),
            used: "22G".into(),
            available: "16G".into(),
            use_percent: 58,
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
            uptime: "up 42 days".into(),
        },
        kubernetes: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn no_changes_is_healthy() {
    let baseline = base_snapshot();
    let current = base_snapshot();
    let hc = check_health("sacra-vps", &baseline, &current);
    assert_eq!(hc.status, HealthStatus::Healthy);
    assert!(hc.alerts.is_empty());
    assert_eq!(hc.target_name, "sacra-vps");
}

#[test]
fn container_down_triggers_critical() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    // Remove sacra-api container
    current.containers.retain(|c| c.name != "sacra-api");

    let hc = check_health("sacra-vps", &baseline, &current);
    assert_eq!(hc.status, HealthStatus::Critical);
    let down_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::ContainerDown)
        .collect();
    assert_eq!(down_alerts.len(), 1);
    assert!(down_alerts[0].message.contains("sacra-api"));
    assert_eq!(down_alerts[0].severity, AlertSeverity::Critical);
}

#[test]
fn new_container_triggers_info() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    current.containers.push(ContainerInfo {
        id: "new123".into(),
        name: "redis".into(),
        image: "redis:7".into(),
        status: "Up 2 minutes".into(),
        ports: "6379/tcp".into(),
        running_for: "2 minutes".into(),
    });

    let hc = check_health("sacra-vps", &baseline, &current);
    let new_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::NewContainer)
        .collect();
    assert_eq!(new_alerts.len(), 1);
    assert!(new_alerts[0].message.contains("redis"));
    assert_eq!(new_alerts[0].severity, AlertSeverity::Info);
}

#[test]
fn container_restart_triggers_warning() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    // Simulate restart: running_for is much shorter than baseline
    current.containers[0].running_for = "2 minutes".to_string();

    let hc = check_health("sacra-vps", &baseline, &current);
    let restart_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::ContainerRestarted)
        .collect();
    assert_eq!(restart_alerts.len(), 1);
    assert_eq!(restart_alerts[0].severity, AlertSeverity::Warning);
}

#[test]
fn service_stopped_triggers_critical() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    // Remove docker.service from current
    current.services.retain(|s| s.unit != "docker.service");

    let hc = check_health("sacra-vps", &baseline, &current);
    assert_eq!(hc.status, HealthStatus::Critical);
    let svc_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::ServiceStopped)
        .collect();
    assert_eq!(svc_alerts.len(), 1);
    assert!(svc_alerts[0].message.contains("docker.service"));
}

#[test]
fn disk_space_warning_at_85_percent() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    current.disk[0].use_percent = 85;

    let hc = check_health("sacra-vps", &baseline, &current);
    assert_eq!(hc.status, HealthStatus::Warning);
    let disk_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::DiskSpaceLow)
        .collect();
    assert_eq!(disk_alerts.len(), 1);
    assert_eq!(disk_alerts[0].severity, AlertSeverity::Warning);
}

#[test]
fn disk_space_critical_at_95_percent() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    current.disk[0].use_percent = 95;

    let hc = check_health("sacra-vps", &baseline, &current);
    assert_eq!(hc.status, HealthStatus::Critical);
    let disk_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::DiskSpaceLow)
        .collect();
    assert_eq!(disk_alerts.len(), 1);
    assert_eq!(disk_alerts[0].severity, AlertSeverity::Critical);
}

#[test]
fn high_memory_triggers_warning() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    current.memory.used_mb = 7500; // 93.75% of 8000

    let hc = check_health("sacra-vps", &baseline, &current);
    let mem_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::HighMemory)
        .collect();
    assert_eq!(mem_alerts.len(), 1);
    assert_eq!(mem_alerts[0].severity, AlertSeverity::Warning);
}

#[test]
fn port_gone_triggers_warning() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    // Remove port 33000
    current.listening_ports.retain(|p| p.port != 33000);

    let hc = check_health("sacra-vps", &baseline, &current);
    let port_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::PortGone)
        .collect();
    assert_eq!(port_alerts.len(), 1);
    assert!(port_alerts[0].message.contains("33000"));
    assert_eq!(port_alerts[0].severity, AlertSeverity::Warning);
}

#[test]
fn new_port_triggers_info() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    current.listening_ports.push(PortInfo {
        protocol: "tcp".into(),
        address: "0.0.0.0".into(),
        port: 9090,
        process: "prometheus".into(),
    });

    let hc = check_health("sacra-vps", &baseline, &current);
    let port_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::NewPort)
        .collect();
    assert_eq!(port_alerts.len(), 1);
    assert!(port_alerts[0].message.contains("9090"));
    assert_eq!(port_alerts[0].severity, AlertSeverity::Info);
}

#[test]
fn multiple_alerts_picks_worst_status() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    // Container down (critical) + new port (info)
    current.containers.retain(|c| c.name != "sacra-api");
    current.listening_ports.push(PortInfo {
        protocol: "tcp".into(),
        address: "0.0.0.0".into(),
        port: 9090,
        process: "prometheus".into(),
    });

    let hc = check_health("sacra-vps", &baseline, &current);
    assert_eq!(hc.status, HealthStatus::Critical);
    assert!(hc.alerts.len() >= 2);
}

#[test]
fn health_check_markdown_output() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    current.containers.retain(|c| c.name != "sacra-api");
    current.disk[0].use_percent = 85;

    let hc = check_health("sacra-vps", &baseline, &current);
    let md = health_check_to_markdown(&hc);

    assert!(md.contains("sacra-vps"));
    assert!(md.contains("CRITICAL"));
    assert!(md.contains("[CRIT]"));
    assert!(md.contains("[WARN]"));
    assert!(md.contains("sacra-api"));
}

#[test]
fn high_load_triggers_warning() {
    let baseline = base_snapshot();
    let mut current = base_snapshot();
    current.load.load_1 = 12.0;

    let hc = check_health("sacra-vps", &baseline, &current);
    let load_alerts: Vec<_> = hc
        .alerts
        .iter()
        .filter(|a| a.category == AlertCategory::HighLoad)
        .collect();
    assert_eq!(load_alerts.len(), 1);
    assert_eq!(load_alerts[0].severity, AlertSeverity::Warning);
}
