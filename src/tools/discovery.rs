//! Discovery scan engine for mapping what is running on a target host.
//!
//! Runs a set of standard commands via a [`CommandRunner`] and parses their
//! output into a [`TargetSnapshot`] that captures OS info, containers,
//! services, listening ports, disk, memory, and load.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CommandRunner abstraction
// ---------------------------------------------------------------------------

/// Output of a single command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Abstraction over how commands are executed (SSH, local shell, mock, …).
#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, command: &str) -> Result<CommandOutput>;
}

// ---------------------------------------------------------------------------
// Snapshot data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSnapshot {
    pub scanned_at: DateTime<Utc>,
    pub os: OsInfo,
    pub containers: Vec<ContainerInfo>,
    pub services: Vec<ServiceInfo>,
    pub listening_ports: Vec<PortInfo>,
    pub disk: Vec<DiskInfo>,
    pub memory: MemoryInfo,
    pub load: LoadInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub uname: String,
    pub distro_name: String,
    pub distro_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: String,
    pub running_for: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub unit: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub process: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub filesystem: String,
    pub size: String,
    pub used: String,
    pub available: String,
    pub use_percent: u8,
    pub mount_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
    pub available_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadInfo {
    pub load_1: f64,
    pub load_5: f64,
    pub load_15: f64,
    pub uptime: String,
}

// ---------------------------------------------------------------------------
// Parsers — each takes raw stdout and returns a parsed struct
// ---------------------------------------------------------------------------

pub fn parse_uname(raw: &str) -> String {
    raw.trim().to_string()
}

pub fn parse_os_release(raw: &str) -> (String, String) {
    let mut name = String::new();
    let mut version = String::new();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("NAME=") {
            name = val.trim_matches('"').to_string();
        } else if let Some(val) = line.strip_prefix("VERSION_ID=") {
            version = val.trim_matches('"').to_string();
        }
    }
    (name, version)
}

pub fn parse_ps_aux(raw: &str) -> Vec<String> {
    raw.lines()
        .skip(1) // header
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

pub fn parse_ss(raw: &str) -> Vec<PortInfo> {
    let mut ports = Vec::new();
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 {
            continue;
        }
        let protocol = cols[0].to_string();
        let local_addr = cols[3];
        // Parse address:port — handle IPv6 brackets and *:port
        let (address, port) = split_addr_port(local_addr);
        let process = if cols.len() >= 6 {
            cols[5..].join(" ")
        } else {
            String::new()
        };
        ports.push(PortInfo {
            protocol,
            address,
            port,
            process,
        });
    }
    ports
}

fn split_addr_port(s: &str) -> (String, u16) {
    if let Some(idx) = s.rfind(':') {
        let addr = &s[..idx];
        let port_str = &s[idx + 1..];
        let port = port_str.parse::<u16>().unwrap_or(0);
        (addr.to_string(), port)
    } else {
        (s.to_string(), 0)
    }
}

pub fn parse_docker_ps_json(raw: &str) -> Vec<ContainerInfo> {
    let mut containers = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            containers.push(ContainerInfo {
                id: val["ID"].as_str().unwrap_or("").to_string(),
                name: val["Names"].as_str().unwrap_or("").to_string(),
                image: val["Image"].as_str().unwrap_or("").to_string(),
                status: val["Status"].as_str().unwrap_or("").to_string(),
                ports: val["Ports"].as_str().unwrap_or("").to_string(),
                running_for: val["RunningFor"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    containers
}

pub fn parse_systemctl(raw: &str) -> Vec<ServiceInfo> {
    let mut services = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        // Skip header, empty lines, and legend lines
        if trimmed.is_empty()
            || trimmed.starts_with("UNIT")
            || trimmed.starts_with("LOAD")
            || trimmed.contains("loaded units listed")
        {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        services.push(ServiceInfo {
            unit: cols[0].to_string(),
            load_state: cols[1].to_string(),
            active_state: cols[2].to_string(),
            sub_state: cols[3].to_string(),
            description: if cols.len() > 4 {
                cols[4..].join(" ")
            } else {
                String::new()
            },
        });
    }
    services
}

pub fn parse_df(raw: &str) -> Vec<DiskInfo> {
    let mut disks = Vec::new();
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let pct_str = cols[4].trim_end_matches('%');
        let use_percent = pct_str.parse::<u8>().unwrap_or(0);
        disks.push(DiskInfo {
            filesystem: cols[0].to_string(),
            size: cols[1].to_string(),
            used: cols[2].to_string(),
            available: cols[3].to_string(),
            use_percent,
            mount_point: cols[5].to_string(),
        });
    }
    disks
}

pub fn parse_free(raw: &str) -> MemoryInfo {
    for line in raw.lines() {
        if line.starts_with("Mem:") {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 7 {
                return MemoryInfo {
                    total_mb: cols[1].parse().unwrap_or(0),
                    used_mb: cols[2].parse().unwrap_or(0),
                    free_mb: cols[3].parse().unwrap_or(0),
                    available_mb: cols[6].parse().unwrap_or(0),
                };
            }
        }
    }
    MemoryInfo {
        total_mb: 0,
        used_mb: 0,
        free_mb: 0,
        available_mb: 0,
    }
}

pub fn parse_uptime(raw: &str) -> LoadInfo {
    let raw = raw.trim();
    let (load_1, load_5, load_15) = if let Some(idx) = raw.find("load average:") {
        let loads_str = &raw[idx + "load average:".len()..];
        let parts: Vec<&str> = loads_str.split(',').collect();
        let l1 = parts
            .first()
            .map_or(0.0, |s| s.trim().parse().unwrap_or(0.0));
        let l5 = parts
            .get(1)
            .map_or(0.0, |s| s.trim().parse().unwrap_or(0.0));
        let l15 = parts
            .get(2)
            .map_or(0.0, |s| s.trim().parse().unwrap_or(0.0));
        (l1, l5, l15)
    } else {
        (0.0, 0.0, 0.0)
    };
    LoadInfo {
        load_1,
        load_5,
        load_15,
        uptime: raw.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Full scan orchestration
// ---------------------------------------------------------------------------

pub async fn run_discovery_scan(runner: &dyn CommandRunner) -> Result<TargetSnapshot> {
    let uname_out = runner.run("uname -a").await?;
    let os_release_out = runner.run("cat /etc/os-release").await?;
    let ss_out = runner.run("ss -tlnp").await?;
    let systemctl_out = runner
        .run("systemctl list-units --type=service --state=running --no-pager")
        .await?;
    let df_out = runner.run("df -h").await?;
    let free_out = runner.run("free -m").await?;
    let uptime_out = runner.run("uptime").await?;

    // Docker is optional — if the command fails, treat as no containers.
    let docker_out = runner
        .run("docker ps --format json")
        .await
        .unwrap_or(CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
        });

    let uname = parse_uname(&uname_out.stdout);
    let (distro_name, distro_version) = parse_os_release(&os_release_out.stdout);

    Ok(TargetSnapshot {
        scanned_at: Utc::now(),
        os: OsInfo {
            uname,
            distro_name,
            distro_version,
        },
        containers: parse_docker_ps_json(&docker_out.stdout),
        services: parse_systemctl(&systemctl_out.stdout),
        listening_ports: parse_ss(&ss_out.stdout),
        disk: parse_df(&df_out.stdout),
        memory: parse_free(&free_out.stdout),
        load: parse_uptime(&uptime_out.stdout),
    })
}

// ---------------------------------------------------------------------------
// Markdown summary
// ---------------------------------------------------------------------------

pub fn snapshot_to_markdown(snap: &TargetSnapshot) -> String {
    use std::fmt::Write;

    let mut md = String::new();
    let _ = writeln!(
        md,
        "# Discovery Scan — {}\n",
        snap.scanned_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    md.push_str("## OS\n\n");
    let _ = writeln!(
        md,
        "- **Distro:** {} {}",
        snap.os.distro_name, snap.os.distro_version
    );
    let _ = writeln!(md, "- **Kernel:** {}\n", snap.os.uname);

    md.push_str("## Load\n\n");
    let _ = writeln!(
        md,
        "- **Load averages:** {:.2}, {:.2}, {:.2}",
        snap.load.load_1, snap.load.load_5, snap.load.load_15
    );
    let _ = writeln!(md, "- **Uptime:** {}\n", snap.load.uptime);

    md.push_str("## Memory\n\n");
    let _ = writeln!(
        md,
        "- **Total:** {} MB | **Used:** {} MB | **Available:** {} MB\n",
        snap.memory.total_mb, snap.memory.used_mb, snap.memory.available_mb
    );

    md.push_str("## Disk\n\n");
    md.push_str("| Filesystem | Size | Used | Avail | Use% | Mount |\n");
    md.push_str("|---|---|---|---|---|---|\n");
    for d in &snap.disk {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {}% | {} |",
            d.filesystem, d.size, d.used, d.available, d.use_percent, d.mount_point
        );
    }
    md.push('\n');

    if !snap.containers.is_empty() {
        md.push_str("## Containers\n\n");
        md.push_str("| Name | Image | Status | Ports |\n");
        md.push_str("|---|---|---|---|\n");
        for c in &snap.containers {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} |",
                c.name, c.image, c.status, c.ports
            );
        }
        md.push('\n');
    }

    if !snap.services.is_empty() {
        md.push_str("## Services\n\n");
        md.push_str("| Unit | State | Description |\n");
        md.push_str("|---|---|---|\n");
        for s in &snap.services {
            let _ = writeln!(
                md,
                "| {} | {} | {} |",
                s.unit, s.active_state, s.description
            );
        }
        md.push('\n');
    }

    if !snap.listening_ports.is_empty() {
        md.push_str("## Listening Ports\n\n");
        md.push_str("| Proto | Address | Port | Process |\n");
        md.push_str("|---|---|---|---|\n");
        for p in &snap.listening_ports {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} |",
                p.protocol, p.address, p.port, p.process
            );
        }
        md.push('\n');
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_os_release() {
        let raw = r#"NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu
PRETTY_NAME="Ubuntu 22.04.3 LTS"
"#;
        let (name, ver) = parse_os_release(raw);
        assert_eq!(name, "Ubuntu");
        assert_eq!(ver, "22.04");
    }

    #[test]
    fn test_parse_free() {
        let raw = "              total        used        free      shared  buff/cache   available
Mem:           7951        3042         512         123        4396        4558
Swap:          2047         100        1947
";
        let mem = parse_free(raw);
        assert_eq!(mem.total_mb, 7951);
        assert_eq!(mem.used_mb, 3042);
        assert_eq!(mem.free_mb, 512);
        assert_eq!(mem.available_mb, 4558);
    }

    #[test]
    fn test_parse_uptime() {
        let raw = " 14:23:05 up 42 days,  3:15,  2 users,  load average: 0.45, 0.30, 0.25";
        let load = parse_uptime(raw);
        assert!((load.load_1 - 0.45).abs() < 0.001);
        assert!((load.load_5 - 0.30).abs() < 0.001);
        assert!((load.load_15 - 0.25).abs() < 0.001);
    }
}
