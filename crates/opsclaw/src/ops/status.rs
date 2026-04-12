//! Human-readable `opsclaw status` output formatter.

use std::fmt::Write;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::tools::discovery::TargetSnapshot;
use crate::ops_config::ProjectConfig;

/// Collected data for a single project's status display.
#[derive(Debug, Serialize)]
pub struct ProjectStatus {
    pub name: String,
    pub host: String,
    pub snapshot: Option<TargetSnapshot>,
    pub autonomy: String,
}

/// Format a human-readable duration from a `DateTime` to now.
fn time_ago(dt: DateTime<Utc>) -> String {
    let delta = Utc::now().signed_duration_since(dt);
    let secs = delta.num_seconds();
    if secs < 60 {
        return format!("{secs} sec ago");
    }
    let mins = delta.num_minutes();
    if mins < 60 {
        return format!("{mins} min ago");
    }
    let hours = delta.num_hours();
    if hours < 24 {
        return format!("{hours} hours ago");
    }
    let days = delta.num_days();
    format!("{days} days ago")
}

fn format_mb(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.1} GB", mb as f64 / 1024.0)
    } else {
        format!("{mb} MB")
    }
}

fn parse_uptime(raw: &str) -> String {
    // The raw uptime string from discovery looks like "up 42 days" or similar.
    // Strip the leading "up " if present.
    raw.trim_start_matches("up ").to_string()
}

/// Build a `ProjectStatus` from config.
pub fn gather_project_status(target: &ProjectConfig) -> Result<ProjectStatus> {
    let host = target.host.as_deref().unwrap_or("localhost").to_string();

    Ok(ProjectStatus {
        name: target.name.clone(),
        host,
        snapshot: None,
        autonomy: format!("{:?}", target.autonomy).to_lowercase(),
    })
}

/// Render a human-readable status report for a single project.
pub fn render_project_status(status: &ProjectStatus) -> String {
    let mut out = String::new();

    let header = format!("OpsClaw Status \u{2014} {} ({})", status.name, status.host);
    let _ = writeln!(out, "{header}");
    let _ = writeln!(out, "{}", "\u{2500}".repeat(header.len()));

    let snap = match &status.snapshot {
        Some(s) => s,
        None => {
            let _ = writeln!(out, "No snapshot found \u{2014} run `opsclaw scan` first.");
            return out;
        }
    };

    // Last scan
    let scanned = snap.scanned_at.format("%Y-%m-%d %H:%M UTC");
    let ago = time_ago(snap.scanned_at);
    let _ = writeln!(out, "Last scan:     {scanned} ({ago})");
    let _ = writeln!(out);

    // System
    let _ = writeln!(out, "System");
    let os_label = if snap.os.distro_name.is_empty() {
        snap.os.uname.clone()
    } else {
        format!("{} {}", snap.os.distro_name, snap.os.distro_version)
    };
    let _ = writeln!(out, "  OS:          {os_label}");
    let _ = writeln!(out, "  Uptime:      {}", parse_uptime(&snap.load.uptime));
    let total = format_mb(snap.memory.total_mb);
    let used = format_mb(snap.memory.used_mb);
    let pct = if snap.memory.total_mb > 0 {
        snap.memory.used_mb * 100 / snap.memory.total_mb
    } else {
        0
    };
    let _ = writeln!(out, "  Memory:      {used} / {total} ({pct}%)");

    // Disk — show root or first entry
    if let Some(d) = snap
        .disk
        .iter()
        .find(|d| d.mount_point == "/")
        .or(snap.disk.first())
    {
        let _ = writeln!(
            out,
            "  Disk {}:  {} / {} ({}%)",
            d.mount_point, d.used, d.size, d.use_percent
        );
    }
    let _ = writeln!(out);

    // Containers
    if !snap.containers.is_empty() {
        let running = snap
            .containers
            .iter()
            .filter(|c| c.status.starts_with("Up"))
            .count();
        let _ = writeln!(out, "Containers     {running} running");
        for c in &snap.containers {
            let icon = if c.status.starts_with("Up") {
                "\u{2713}"
            } else {
                "\u{2717}"
            };
            let healthy = if c.status.contains("healthy") {
                " (healthy)"
            } else {
                ""
            };
            let _ = writeln!(out, "  {icon} {:<16} {}{healthy}", c.name, c.status);
        }
        let _ = writeln!(out);
    }

    // Services
    if !snap.services.is_empty() {
        let _ = writeln!(out, "Services       systemd");
        for s in &snap.services {
            let icon = if s.active_state == "active" {
                "\u{2713}"
            } else {
                "\u{2717}"
            };
            let _ = writeln!(out, "  {icon} {:<16} {}", s.unit, s.active_state);
        }
        let _ = writeln!(out);
    }

    // Kubernetes
    if let Some(k8s) = &snap.kubernetes {
        let _ = writeln!(out, "Kubernetes");
        let running = k8s.pods.iter().filter(|p| p.status == "Running").count();
        let _ = writeln!(out, "  Pods:        {running}/{} running", k8s.pods.len());
        for pod in &k8s.pods {
            let icon = if pod.status == "Running" {
                "\u{2713}"
            } else {
                "\u{2717}"
            };
            let _ = writeln!(out, "  {icon} {:<24} {}", pod.name, pod.status);
        }
        let _ = writeln!(out);
    }

    // Autonomy
    let _ = writeln!(out, "Autonomy mode: {}", status.autonomy);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::discovery::*;
    use chrono::Utc;

    fn sample_status() -> ProjectStatus {
        ProjectStatus {
            name: "sacra".into(),
            host: "159.69.92.65".into(),
            snapshot: Some(TargetSnapshot {
                scanned_at: Utc::now() - chrono::Duration::minutes(3),
                os: OsInfo {
                    uname: "Linux sacra 6.1.0".into(),
                    distro_name: "Debian GNU/Linux".into(),
                    distro_version: "12".into(),
                },
                containers: vec![
                    ContainerInfo {
                        id: "a1".into(),
                        name: "sacra-api".into(),
                        image: "sacra/api:latest".into(),
                        status: "Up 7 hours (healthy)".into(),
                        ports: "0.0.0.0:33000->8080/tcp".into(),
                        running_for: "7 hours".into(),
                    },
                    ContainerInfo {
                        id: "a2".into(),
                        name: "postgres".into(),
                        image: "postgres:16".into(),
                        status: "Up 5 days (healthy)".into(),
                        ports: "5432/tcp".into(),
                        running_for: "5 days".into(),
                    },
                ],
                services: vec![ServiceInfo {
                    unit: "nginx".into(),
                    load_state: "loaded".into(),
                    active_state: "active".into(),
                    sub_state: "running".into(),
                    description: "nginx web server".into(),
                }],
                listening_ports: vec![],
                disk: vec![DiskInfo {
                    filesystem: "/dev/sda1".into(),
                    size: "40.0 GB".into(),
                    used: "12.4 GB".into(),
                    available: "27.6 GB".into(),
                    use_percent: 31,
                    mount_point: "/".into(),
                }],
                memory: MemoryInfo {
                    total_mb: 8192,
                    used_mb: 2150,
                    free_mb: 3000,
                    available_mb: 6042,
                },
                load: LoadInfo {
                    load_1: 0.5,
                    load_5: 0.3,
                    load_15: 0.2,
                    uptime: "up 4 days 7 hours".into(),
                },
                kubernetes: None,
            }),
            autonomy: "approve".into(),
        }
    }

    #[test]
    fn renders_header_and_system_section() {
        let status = sample_status();
        let output = render_project_status(&status);
        assert!(output.contains("OpsClaw Status \u{2014} sacra (159.69.92.65)"));
        assert!(output.contains("Debian GNU/Linux 12"));
        assert!(output.contains("4 days 7 hours"));
    }

    #[test]
    fn renders_containers() {
        let status = sample_status();
        let output = render_project_status(&status);
        assert!(output.contains("Containers     2 running"));
        assert!(output.contains("sacra-api"));
        assert!(output.contains("postgres"));
        assert!(output.contains("(healthy)"));
    }

    #[test]
    fn renders_services() {
        let status = sample_status();
        let output = render_project_status(&status);
        assert!(output.contains("Services       systemd"));
        assert!(output.contains("nginx"));
        assert!(output.contains("active"));
    }

    #[test]
    fn renders_disk() {
        let status = sample_status();
        let output = render_project_status(&status);
        assert!(output.contains("Disk /"));
        assert!(output.contains("31%"));
    }

    #[test]
    fn renders_memory() {
        let status = sample_status();
        let output = render_project_status(&status);
        assert!(output.contains("Memory:"));
        assert!(output.contains("8.0 GB"));
    }

    #[test]
    fn no_snapshot_shows_message() {
        let status = ProjectStatus {
            name: "missing".into(),
            host: "localhost".into(),
            snapshot: None,
            autonomy: "approve".into(),
        };
        let output = render_project_status(&status);
        assert!(output.contains("No snapshot found"));
        assert!(output.contains("opsclaw scan"));
    }

    #[test]
    fn time_ago_minutes() {
        let dt = Utc::now() - chrono::Duration::minutes(5);
        assert_eq!(time_ago(dt), "5 min ago");
    }

    #[test]
    fn time_ago_hours() {
        let dt = Utc::now() - chrono::Duration::hours(3);
        assert_eq!(time_ago(dt), "3 hours ago");
    }

    #[test]
    fn time_ago_days() {
        let dt = Utc::now() - chrono::Duration::days(2);
        assert_eq!(time_ago(dt), "2 days ago");
    }

    #[test]
    fn format_mb_gigabytes() {
        assert_eq!(format_mb(2048), "2.0 GB");
    }

    #[test]
    fn format_mb_megabytes() {
        assert_eq!(format_mb(512), "512 MB");
    }

    #[test]
    fn autonomy_shown() {
        let status = sample_status();
        let output = render_project_status(&status);
        assert!(output.contains("Autonomy mode: approve"));
    }
}
