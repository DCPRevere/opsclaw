//! Monitoring loop — compares a current scan against a baseline snapshot
//! and produces alerts when things change or thresholds are breached.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::discovery::TargetSnapshot;

// ---------------------------------------------------------------------------
// Health-check data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub target_name: String,
    pub checked_at: DateTime<Utc>,
    pub status: HealthStatus,
    pub alerts: Vec<Alert>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub message: String,
}

/// Re-export from zeroclaw config (canonical definition lives there for schema generation).
pub use crate::ops_config::AlertSeverity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertCategory {
    ContainerDown,
    ContainerRestarted,
    ServiceStopped,
    DiskSpaceLow,
    HighMemory,
    HighLoad,
    PortGone,
    NewPort,
    NewContainer,
    PodCrashLoop,
    PodNotReady,
    PodPending,
    DeploymentDegraded,
    NodeNotReady,
    PodHighRestarts,
    ProbeFailure,
    TlsCertExpiring,
    DnsResolutionFailed,
    MetricAnomaly,
}

// ---------------------------------------------------------------------------
// Diff engine
// ---------------------------------------------------------------------------

/// Compare a `current` snapshot against a `baseline` and return a [`HealthCheck`].
pub fn check_health(
    target_name: &str,
    baseline: &TargetSnapshot,
    current: &TargetSnapshot,
) -> HealthCheck {
    let mut alerts = Vec::new();

    diff_containers(baseline, current, &mut alerts);
    diff_services(baseline, current, &mut alerts);
    diff_disk(current, &mut alerts);
    diff_memory(current, &mut alerts);
    diff_load(current, &mut alerts);
    diff_ports(baseline, current, &mut alerts);
    diff_kubernetes(baseline, current, &mut alerts);

    let status = overall_status(&alerts);

    HealthCheck {
        target_name: target_name.to_string(),
        checked_at: Utc::now(),
        status,
        alerts,
    }
}

pub fn overall_status(alerts: &[Alert]) -> HealthStatus {
    if alerts.iter().any(|a| a.severity == AlertSeverity::Critical) {
        HealthStatus::Critical
    } else if alerts.iter().any(|a| a.severity == AlertSeverity::Warning) {
        HealthStatus::Warning
    } else {
        HealthStatus::Healthy
    }
}

fn diff_containers(baseline: &TargetSnapshot, current: &TargetSnapshot, alerts: &mut Vec<Alert>) {
    // Container in baseline but missing now → ContainerDown (Critical)
    for bc in &baseline.containers {
        let found = current.containers.iter().any(|cc| cc.name == bc.name);
        if !found {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: AlertCategory::ContainerDown,
                message: format!(
                    "Container '{}' (image: {}) was running but is now missing",
                    bc.name, bc.image
                ),
            });
        }
    }

    // New container not in baseline → NewContainer (Info)
    for cc in &current.containers {
        let found = baseline.containers.iter().any(|bc| bc.name == cc.name);
        if !found {
            alerts.push(Alert {
                severity: AlertSeverity::Info,
                category: AlertCategory::NewContainer,
                message: format!("New container '{}' (image: {}) detected", cc.name, cc.image),
            });
        }
    }

    // Container restart count increased → ContainerRestarted (Warning)
    // Docker status typically shows "Up X hours" or "Restarting" — we detect
    // if the running_for has reset (shorter uptime than baseline) as a proxy
    // for restart, or if the status contains "Restarting".
    for cc in &current.containers {
        if let Some(bc) = baseline.containers.iter().find(|b| b.name == cc.name) {
            let restarted = cc.status.contains("Restarting")
                || (is_shorter_uptime(&cc.running_for, &bc.running_for));
            if restarted {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: AlertCategory::ContainerRestarted,
                    message: format!(
                        "Container '{}' appears to have restarted (was: '{}', now: '{}')",
                        cc.name, bc.running_for, cc.running_for
                    ),
                });
            }
        }
    }
}

/// Rough heuristic: if the current running_for looks shorter than baseline,
/// the container likely restarted. Parses simple docker durations like
/// "2 hours", "3 days", "45 minutes", "5 seconds".
fn is_shorter_uptime(current: &str, baseline: &str) -> bool {
    let cur = duration_to_seconds(current);
    let base = duration_to_seconds(baseline);
    // Only flag if we could parse both and current is substantially shorter
    if cur > 0 && base > 0 {
        cur < base / 2
    } else {
        false
    }
}

fn duration_to_seconds(s: &str) -> u64 {
    let s = s.to_lowercase();
    let mut total = 0u64;
    for part in s.split_whitespace().collect::<Vec<_>>().chunks(2) {
        if part.len() == 2 {
            let num: u64 = part[0].parse().unwrap_or(0);
            let unit = part[1];
            let multiplier = if unit.starts_with("second") {
                1
            } else if unit.starts_with("minute") {
                60
            } else if unit.starts_with("hour") {
                3600
            } else if unit.starts_with("day") {
                86400
            } else if unit.starts_with("week") {
                604_800
            } else if unit.starts_with("month") {
                2_592_000
            } else {
                0
            };
            total += num * multiplier;
        }
    }
    total
}

fn diff_services(baseline: &TargetSnapshot, current: &TargetSnapshot, alerts: &mut Vec<Alert>) {
    for bs in &baseline.services {
        let found = current.services.iter().find(|cs| cs.unit == bs.unit);
        if found.is_none() {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: AlertCategory::ServiceStopped,
                message: format!("Service '{}' was running but is no longer listed", bs.unit),
            });
        }
    }
}

fn diff_disk(current: &TargetSnapshot, alerts: &mut Vec<Alert>) {
    for d in &current.disk {
        if d.use_percent > 90 {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: AlertCategory::DiskSpaceLow,
                message: format!(
                    "Disk '{}' at {}% usage (mount: {})",
                    d.filesystem, d.use_percent, d.mount_point
                ),
            });
        } else if d.use_percent > 80 {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: AlertCategory::DiskSpaceLow,
                message: format!(
                    "Disk '{}' at {}% usage (mount: {})",
                    d.filesystem, d.use_percent, d.mount_point
                ),
            });
        }
    }
}

fn diff_memory(current: &TargetSnapshot, alerts: &mut Vec<Alert>) {
    if current.memory.total_mb > 0 {
        let used_pct = (current.memory.used_mb as f64 / current.memory.total_mb as f64) * 100.0;
        if used_pct > 90.0 {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: AlertCategory::HighMemory,
                message: format!(
                    "Memory usage at {:.0}% ({}/{} MB)",
                    used_pct, current.memory.used_mb, current.memory.total_mb
                ),
            });
        }
    }
}

fn diff_load(current: &TargetSnapshot, alerts: &mut Vec<Alert>) {
    // We don't have CPU count from the snapshot, so we use a reasonable
    // default heuristic: load > 4.0 (≈ 2× a 2-core machine).
    // The caller can refine with cpu_count if available.
    // For now: flag if load_1 > 8.0 (high for most VPS).
    if current.load.load_1 > 8.0 {
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: AlertCategory::HighLoad,
            message: format!(
                "Load average {:.2} is high (1m: {:.2}, 5m: {:.2}, 15m: {:.2})",
                current.load.load_1, current.load.load_1, current.load.load_5, current.load.load_15
            ),
        });
    }
}

fn diff_ports(baseline: &TargetSnapshot, current: &TargetSnapshot, alerts: &mut Vec<Alert>) {
    // Port in baseline but gone now → PortGone (Warning)
    for bp in &baseline.listening_ports {
        let found = current
            .listening_ports
            .iter()
            .any(|cp| cp.port == bp.port && cp.protocol == bp.protocol);
        if !found {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: AlertCategory::PortGone,
                message: format!(
                    "Port {}/{} (process: '{}') was listening but is now gone",
                    bp.port, bp.protocol, bp.process
                ),
            });
        }
    }

    // New port not in baseline → NewPort (Info)
    for cp in &current.listening_ports {
        let found = baseline
            .listening_ports
            .iter()
            .any(|bp| bp.port == cp.port && bp.protocol == cp.protocol);
        if !found {
            alerts.push(Alert {
                severity: AlertSeverity::Info,
                category: AlertCategory::NewPort,
                message: format!(
                    "New port {}/{} (process: '{}') detected",
                    cp.port, cp.protocol, cp.process
                ),
            });
        }
    }
}

fn diff_kubernetes(baseline: &TargetSnapshot, current: &TargetSnapshot, alerts: &mut Vec<Alert>) {
    let current_k8s = match &current.kubernetes {
        Some(k) => k,
        None => return,
    };

    // CrashLoopBackOff pods → Critical
    for pod in &current_k8s.pods {
        if pod.status.contains("CrashLoopBackOff") {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: AlertCategory::PodCrashLoop,
                message: format!(
                    "Pod '{}/{}' is in CrashLoopBackOff (restarts: {})",
                    pod.namespace, pod.name, pod.restarts
                ),
            });
        }
    }

    // Pods not ready (ready count < total) → Warning
    for pod in &current_k8s.pods {
        if pod.status.contains("CrashLoopBackOff") {
            continue; // already reported above
        }
        if let Some((ready, total)) = parse_ready_fraction(&pod.ready) {
            if ready < total && pod.status != "Pending" {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: AlertCategory::PodNotReady,
                    message: format!(
                        "Pod '{}/{}' not fully ready ({} ready, {} expected)",
                        pod.namespace, pod.name, ready, total
                    ),
                });
            }
        }
    }

    // Pending pods that existed in baseline → Warning
    if let Some(baseline_k8s) = &baseline.kubernetes {
        for pod in &current_k8s.pods {
            if pod.status == "Pending" {
                let was_in_baseline = baseline_k8s
                    .pods
                    .iter()
                    .any(|bp| bp.name == pod.name && bp.namespace == pod.namespace);
                if was_in_baseline {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: AlertCategory::PodPending,
                        message: format!(
                            "Pod '{}/{}' is still Pending since last scan",
                            pod.namespace, pod.name
                        ),
                    });
                }
            }
        }

        // High restart count: restarts increased significantly
        for pod in &current_k8s.pods {
            if let Some(bp) = baseline_k8s
                .pods
                .iter()
                .find(|bp| bp.name == pod.name && bp.namespace == pod.namespace)
            {
                if pod.restarts > bp.restarts + 5 {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: AlertCategory::PodHighRestarts,
                        message: format!(
                            "Pod '{}/{}' restart count jumped from {} to {}",
                            pod.namespace, pod.name, bp.restarts, pod.restarts
                        ),
                    });
                }
            }
        }
    }

    // Deployment degraded: available < desired
    for dep in &current_k8s.deployments {
        if let Some((ready, desired)) = parse_ready_fraction(&dep.ready) {
            if ready < desired {
                let severity = if dep.available == 0 {
                    AlertSeverity::Critical
                } else {
                    AlertSeverity::Warning
                };
                alerts.push(Alert {
                    severity,
                    category: AlertCategory::DeploymentDegraded,
                    message: format!(
                        "Deployment '{}/{}' degraded: {} ready of {} desired ({} available)",
                        dep.namespace, dep.name, ready, desired, dep.available
                    ),
                });
            }
        }
    }

    // Node NotReady → Critical
    for node in &current_k8s.nodes {
        if node.status != "Ready" {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: AlertCategory::NodeNotReady,
                message: format!(
                    "Node '{}' is {} (roles: {}, version: {})",
                    node.name, node.status, node.roles, node.version
                ),
            });
        }
    }
}

/// Parse a "ready/total" string like "2/3" into (2, 3).
fn parse_ready_fraction(s: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() == 2 {
        let ready = parts[0].parse::<u32>().ok()?;
        let total = parts[1].parse::<u32>().ok()?;
        Some((ready, total))
    } else {
        None
    }
}

/// Render a health check as a human-readable markdown summary.
pub fn health_check_to_markdown(hc: &HealthCheck) -> String {
    use std::fmt::Write;

    let mut md = String::new();
    let status_label = match hc.status {
        HealthStatus::Healthy => "HEALTHY",
        HealthStatus::Warning => "WARNING",
        HealthStatus::Critical => "CRITICAL",
    };
    let _ = writeln!(
        md,
        "# Health Check: {} — {}\n",
        hc.target_name, status_label
    );
    let _ = writeln!(
        md,
        "Checked at: {}\n",
        hc.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    if hc.alerts.is_empty() {
        md.push_str("No alerts. All systems nominal.\n");
    } else {
        let _ = writeln!(md, "**{} alert(s):**\n", hc.alerts.len());
        for a in &hc.alerts {
            let sev = match a.severity {
                AlertSeverity::Info => "INFO",
                AlertSeverity::Warning => "WARN",
                AlertSeverity::Critical => "CRIT",
            };
            let _ = writeln!(md, "- **[{}]** {}", sev, a.message);
        }
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::discovery::*;

    fn empty_snapshot() -> TargetSnapshot {
        TargetSnapshot {
            scanned_at: Utc::now(),
            os: OsInfo {
                uname: String::new(),
                distro_name: String::new(),
                distro_version: String::new(),
            },
            containers: vec![],
            services: vec![],
            listening_ports: vec![],
            disk: vec![],
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
                uptime: String::new(),
            },
            kubernetes: None,
        }
    }

    #[test]
    fn healthy_when_no_changes() {
        let baseline = empty_snapshot();
        let current = empty_snapshot();
        let hc = check_health("test", &baseline, &current);
        assert_eq!(hc.status, HealthStatus::Healthy);
        assert!(hc.alerts.is_empty());
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(duration_to_seconds("2 hours"), 7200);
        assert_eq!(duration_to_seconds("3 days"), 259_200);
        assert_eq!(duration_to_seconds("45 minutes"), 2700);
    }

    #[test]
    fn overall_status_picks_worst() {
        let alerts = vec![
            Alert {
                severity: AlertSeverity::Info,
                category: AlertCategory::NewPort,
                message: String::new(),
            },
            Alert {
                severity: AlertSeverity::Warning,
                category: AlertCategory::HighLoad,
                message: String::new(),
            },
        ];
        assert_eq!(overall_status(&alerts), HealthStatus::Warning);
    }

    fn k8s_snapshot_with(k8s: KubernetesInfo) -> TargetSnapshot {
        let mut snap = empty_snapshot();
        snap.kubernetes = Some(k8s);
        snap
    }

    fn healthy_k8s() -> KubernetesInfo {
        KubernetesInfo {
            cluster_info: "Kubernetes control plane running".to_string(),
            namespaces: vec!["default".to_string()],
            pods: vec![K8sPod {
                name: "web-abc12".to_string(),
                namespace: "default".to_string(),
                status: "Running".to_string(),
                ready: "1/1".to_string(),
                restarts: 0,
                age: "2026-01-01T00:00:00Z".to_string(),
                node: "node-1".to_string(),
            }],
            deployments: vec![K8sDeployment {
                name: "web".to_string(),
                namespace: "default".to_string(),
                ready: "3/3".to_string(),
                up_to_date: 3,
                available: 3,
                age: "2026-01-01T00:00:00Z".to_string(),
            }],
            services: vec![],
            nodes: vec![K8sNode {
                name: "node-1".to_string(),
                status: "Ready".to_string(),
                roles: "control-plane".to_string(),
                age: "2026-01-01T00:00:00Z".to_string(),
                version: "v1.29.1".to_string(),
            }],
        }
    }

    #[test]
    fn k8s_crashloopbackoff_triggers_critical() {
        let baseline = k8s_snapshot_with(healthy_k8s());
        let mut bad_k8s = healthy_k8s();
        bad_k8s.pods[0].status = "CrashLoopBackOff".to_string();
        bad_k8s.pods[0].ready = "0/1".to_string();
        bad_k8s.pods[0].restarts = 42;
        let current = k8s_snapshot_with(bad_k8s);

        let hc = check_health("test", &baseline, &current);
        assert_eq!(hc.status, HealthStatus::Critical);
        assert!(hc
            .alerts
            .iter()
            .any(|a| a.category == AlertCategory::PodCrashLoop));
    }

    #[test]
    fn k8s_deployment_degraded_warning() {
        let baseline = k8s_snapshot_with(healthy_k8s());
        let mut bad_k8s = healthy_k8s();
        bad_k8s.deployments[0].ready = "2/3".to_string();
        bad_k8s.deployments[0].available = 2;
        let current = k8s_snapshot_with(bad_k8s);

        let hc = check_health("test", &baseline, &current);
        assert_eq!(hc.status, HealthStatus::Warning);
        assert!(hc
            .alerts
            .iter()
            .any(|a| a.category == AlertCategory::DeploymentDegraded));
    }

    #[test]
    fn k8s_deployment_zero_available_critical() {
        let baseline = k8s_snapshot_with(healthy_k8s());
        let mut bad_k8s = healthy_k8s();
        bad_k8s.deployments[0].ready = "0/3".to_string();
        bad_k8s.deployments[0].available = 0;
        let current = k8s_snapshot_with(bad_k8s);

        let hc = check_health("test", &baseline, &current);
        assert_eq!(hc.status, HealthStatus::Critical);
        assert!(hc.alerts.iter().any(|a| {
            a.category == AlertCategory::DeploymentDegraded && a.severity == AlertSeverity::Critical
        }));
    }

    #[test]
    fn k8s_node_not_ready_critical() {
        let baseline = k8s_snapshot_with(healthy_k8s());
        let mut bad_k8s = healthy_k8s();
        bad_k8s.nodes[0].status = "NotReady".to_string();
        let current = k8s_snapshot_with(bad_k8s);

        let hc = check_health("test", &baseline, &current);
        assert_eq!(hc.status, HealthStatus::Critical);
        assert!(hc
            .alerts
            .iter()
            .any(|a| a.category == AlertCategory::NodeNotReady));
    }

    #[test]
    fn k8s_no_alerts_when_kubernetes_absent() {
        let baseline = empty_snapshot();
        let current = empty_snapshot();
        let hc = check_health("test", &baseline, &current);
        assert_eq!(hc.status, HealthStatus::Healthy);
    }
}
