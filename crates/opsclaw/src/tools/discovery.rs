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
    pub kubernetes: Option<KubernetesInfo>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesInfo {
    pub cluster_info: String,
    pub namespaces: Vec<String>,
    pub pods: Vec<K8sPod>,
    pub deployments: Vec<K8sDeployment>,
    pub services: Vec<K8sService>,
    pub nodes: Vec<K8sNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sPod {
    pub name: String,
    pub namespace: String,
    pub status: String,
    pub ready: String,
    pub restarts: u32,
    pub age: String,
    pub node: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sDeployment {
    pub name: String,
    pub namespace: String,
    pub ready: String,
    pub up_to_date: u32,
    pub available: u32,
    pub age: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sService {
    pub name: String,
    pub namespace: String,
    pub svc_type: String,
    pub cluster_ip: String,
    pub external_ip: String,
    pub ports: String,
    pub age: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sNode {
    pub name: String,
    pub status: String,
    pub roles: String,
    pub age: String,
    pub version: String,
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
// Kubernetes JSON parsers
// ---------------------------------------------------------------------------

pub fn parse_k8s_pods_json(raw: &str) -> Vec<K8sPod> {
    let val: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items = match val["items"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    items
        .iter()
        .map(|item| {
            let metadata = &item["metadata"];
            let status = &item["status"];
            let phase = status["phase"].as_str().unwrap_or("");
            // Check container statuses for more specific state (e.g. CrashLoopBackOff)
            let container_statuses = status["containerStatuses"].as_array();
            let (ready_str, restarts, detailed_status) =
                if let Some(cs) = container_statuses {
                    let total = cs.len();
                    let ready_count = cs
                        .iter()
                        .filter(|c| c["ready"].as_bool().unwrap_or(false))
                        .count();
                    let restarts: u32 = cs
                        .iter()
                        .map(|c| c["restartCount"].as_u64().unwrap_or(0) as u32)
                        .sum();
                    // Detect waiting reason like CrashLoopBackOff
                    let waiting_reason = cs.iter().find_map(|c| {
                        c["state"]["waiting"]["reason"].as_str().map(|s| s.to_string())
                    });
                    let st = waiting_reason.unwrap_or_else(|| phase.to_string());
                    (format!("{}/{}", ready_count, total), restarts, st)
                } else {
                    (String::from("0/0"), 0, phase.to_string())
                };
            let node = item["spec"]["nodeName"].as_str().unwrap_or("");
            K8sPod {
                name: metadata["name"].as_str().unwrap_or("").to_string(),
                namespace: metadata["namespace"].as_str().unwrap_or("").to_string(),
                status: detailed_status,
                ready: ready_str,
                restarts,
                age: metadata["creationTimestamp"].as_str().unwrap_or("").to_string(),
                node: node.to_string(),
            }
        })
        .collect()
}

pub fn parse_k8s_deployments_json(raw: &str) -> Vec<K8sDeployment> {
    let val: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items = match val["items"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    items
        .iter()
        .map(|item| {
            let metadata = &item["metadata"];
            let status = &item["status"];
            let spec = &item["spec"];
            let desired = spec["replicas"].as_u64().unwrap_or(0) as u32;
            let available = status["availableReplicas"].as_u64().unwrap_or(0) as u32;
            let up_to_date = status["updatedReplicas"].as_u64().unwrap_or(0) as u32;
            let ready_replicas = status["readyReplicas"].as_u64().unwrap_or(0) as u32;
            K8sDeployment {
                name: metadata["name"].as_str().unwrap_or("").to_string(),
                namespace: metadata["namespace"].as_str().unwrap_or("").to_string(),
                ready: format!("{}/{}", ready_replicas, desired),
                up_to_date,
                available,
                age: metadata["creationTimestamp"].as_str().unwrap_or("").to_string(),
            }
        })
        .collect()
}

pub fn parse_k8s_services_json(raw: &str) -> Vec<K8sService> {
    let val: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items = match val["items"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    items
        .iter()
        .map(|item| {
            let metadata = &item["metadata"];
            let spec = &item["spec"];
            let svc_type = spec["type"].as_str().unwrap_or("ClusterIP");
            let cluster_ip = spec["clusterIP"].as_str().unwrap_or("");
            let external_ip = if let Some(ingress) = item["status"]["loadBalancer"]["ingress"].as_array() {
                ingress
                    .iter()
                    .filter_map(|i| i["ip"].as_str().or_else(|| i["hostname"].as_str()))
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                String::from("<none>")
            };
            let ports = if let Some(ports_arr) = spec["ports"].as_array() {
                ports_arr
                    .iter()
                    .map(|p| {
                        let port = p["port"].as_u64().unwrap_or(0);
                        let protocol = p["protocol"].as_str().unwrap_or("TCP");
                        format!("{}/{}", port, protocol)
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                String::new()
            };
            K8sService {
                name: metadata["name"].as_str().unwrap_or("").to_string(),
                namespace: metadata["namespace"].as_str().unwrap_or("").to_string(),
                svc_type: svc_type.to_string(),
                cluster_ip: cluster_ip.to_string(),
                external_ip,
                ports,
                age: metadata["creationTimestamp"].as_str().unwrap_or("").to_string(),
            }
        })
        .collect()
}

pub fn parse_k8s_nodes_json(raw: &str) -> Vec<K8sNode> {
    let val: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items = match val["items"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    items
        .iter()
        .map(|item| {
            let metadata = &item["metadata"];
            let status = &item["status"];
            let node_status = status["conditions"]
                .as_array()
                .and_then(|conds| {
                    conds
                        .iter()
                        .find(|c| c["type"].as_str() == Some("Ready"))
                        .map(|c| {
                            if c["status"].as_str() == Some("True") {
                                "Ready"
                            } else {
                                "NotReady"
                            }
                        })
                })
                .unwrap_or("Unknown");
            let labels = metadata["labels"].as_object();
            let roles = labels
                .map(|l| {
                    l.keys()
                        .filter_map(|k| {
                            k.strip_prefix("node-role.kubernetes.io/")
                                .map(|r| r.to_string())
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            let version = status["nodeInfo"]["kubeletVersion"]
                .as_str()
                .unwrap_or("");
            K8sNode {
                name: metadata["name"].as_str().unwrap_or("").to_string(),
                status: node_status.to_string(),
                roles: if roles.is_empty() {
                    "<none>".to_string()
                } else {
                    roles
                },
                age: metadata["creationTimestamp"].as_str().unwrap_or("").to_string(),
                version: version.to_string(),
            }
        })
        .collect()
}

pub async fn discover_kubernetes(runner: &dyn CommandRunner) -> Option<KubernetesInfo> {
    // Check if kubectl is available
    let version_check = runner.run("kubectl version --client --short").await;
    if version_check.is_err() {
        return None;
    }
    let version_out = version_check.unwrap();
    if version_out.exit_code != 0 {
        return None;
    }

    let cluster_info = runner
        .run("kubectl cluster-info 2>/dev/null")
        .await
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();

    let namespaces = runner
        .run("kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'")
        .await
        .map(|o| {
            o.stdout
                .trim()
                .trim_matches('\'')
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let pods = runner
        .run("kubectl get pods --all-namespaces -o json")
        .await
        .map(|o| parse_k8s_pods_json(&o.stdout))
        .unwrap_or_default();

    let deployments = runner
        .run("kubectl get deployments --all-namespaces -o json")
        .await
        .map(|o| parse_k8s_deployments_json(&o.stdout))
        .unwrap_or_default();

    let services = runner
        .run("kubectl get services --all-namespaces -o json")
        .await
        .map(|o| parse_k8s_services_json(&o.stdout))
        .unwrap_or_default();

    let nodes = runner
        .run("kubectl get nodes -o json")
        .await
        .map(|o| parse_k8s_nodes_json(&o.stdout))
        .unwrap_or_default();

    Some(KubernetesInfo {
        cluster_info,
        namespaces,
        pods,
        deployments,
        services,
        nodes,
    })
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

    // Kubernetes is optional — if kubectl isn't available, skip.
    let kubernetes = discover_kubernetes(runner).await;

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
        kubernetes,
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

    if let Some(k8s) = &snap.kubernetes {
        md.push_str("## Kubernetes\n\n");
        if !k8s.cluster_info.is_empty() {
            let _ = writeln!(md, "**Cluster:** {}\n", k8s.cluster_info);
        }

        if !k8s.pods.is_empty() {
            md.push_str("### Pods\n\n");
            md.push_str("| Name | Namespace | Status | Ready | Restarts |\n");
            md.push_str("|---|---|---|---|---|\n");
            for p in &k8s.pods {
                let highlight = if p.status.contains("CrashLoopBackOff")
                    || p.status == "Error"
                    || p.status == "NotReady"
                {
                    " **UNHEALTHY**"
                } else {
                    ""
                };
                let _ = writeln!(
                    md,
                    "| {} | {} | {}{} | {} | {} |",
                    p.name, p.namespace, p.status, highlight, p.ready, p.restarts
                );
            }
            md.push('\n');
        }

        if !k8s.deployments.is_empty() {
            md.push_str("### Deployments\n\n");
            md.push_str("| Name | Namespace | Ready |\n");
            md.push_str("|---|---|---|\n");
            for d in &k8s.deployments {
                let _ = writeln!(md, "| {} | {} | {} |", d.name, d.namespace, d.ready);
            }
            md.push('\n');
        }

        if !k8s.nodes.is_empty() {
            md.push_str("### Nodes\n\n");
            md.push_str("| Name | Status | Roles | Version |\n");
            md.push_str("|---|---|---|---|\n");
            for n in &k8s.nodes {
                let highlight = if n.status != "Ready" {
                    " **UNHEALTHY**"
                } else {
                    ""
                };
                let _ = writeln!(
                    md,
                    "| {} | {}{} | {} | {} |",
                    n.name, n.status, highlight, n.roles, n.version
                );
            }
            md.push('\n');
        }
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

    #[test]
    fn test_parse_k8s_pods_json() {
        let raw = r#"{
            "items": [
                {
                    "metadata": {"name": "web-abc12", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
                    "spec": {"nodeName": "node-1"},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"ready": true, "restartCount": 2, "state": {"running": {}}}
                        ]
                    }
                },
                {
                    "metadata": {"name": "crash-pod", "namespace": "prod", "creationTimestamp": "2026-01-02T00:00:00Z"},
                    "spec": {"nodeName": "node-2"},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"ready": false, "restartCount": 42, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}
                        ]
                    }
                }
            ]
        }"#;
        let pods = parse_k8s_pods_json(raw);
        assert_eq!(pods.len(), 2);
        assert_eq!(pods[0].name, "web-abc12");
        assert_eq!(pods[0].namespace, "default");
        assert_eq!(pods[0].status, "Running");
        assert_eq!(pods[0].ready, "1/1");
        assert_eq!(pods[0].restarts, 2);
        assert_eq!(pods[0].node, "node-1");
        assert_eq!(pods[1].name, "crash-pod");
        assert_eq!(pods[1].status, "CrashLoopBackOff");
        assert_eq!(pods[1].ready, "0/1");
        assert_eq!(pods[1].restarts, 42);
    }

    #[test]
    fn test_parse_k8s_deployments_json() {
        let raw = r#"{
            "items": [
                {
                    "metadata": {"name": "web", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
                    "spec": {"replicas": 3},
                    "status": {"readyReplicas": 3, "availableReplicas": 3, "updatedReplicas": 3}
                },
                {
                    "metadata": {"name": "api", "namespace": "prod", "creationTimestamp": "2026-01-01T00:00:00Z"},
                    "spec": {"replicas": 3},
                    "status": {"readyReplicas": 2, "availableReplicas": 2, "updatedReplicas": 3}
                }
            ]
        }"#;
        let deps = parse_k8s_deployments_json(raw);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "web");
        assert_eq!(deps[0].ready, "3/3");
        assert_eq!(deps[0].available, 3);
        assert_eq!(deps[1].name, "api");
        assert_eq!(deps[1].ready, "2/3");
        assert_eq!(deps[1].available, 2);
    }

    #[test]
    fn test_parse_k8s_services_json() {
        let raw = r#"{
            "items": [
                {
                    "metadata": {"name": "web-svc", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
                    "spec": {"type": "ClusterIP", "clusterIP": "10.0.0.1", "ports": [{"port": 80, "protocol": "TCP"}]},
                    "status": {"loadBalancer": {}}
                }
            ]
        }"#;
        let svcs = parse_k8s_services_json(raw);
        assert_eq!(svcs.len(), 1);
        assert_eq!(svcs[0].name, "web-svc");
        assert_eq!(svcs[0].svc_type, "ClusterIP");
        assert_eq!(svcs[0].cluster_ip, "10.0.0.1");
        assert_eq!(svcs[0].ports, "80/TCP");
    }

    #[test]
    fn test_parse_k8s_nodes_json() {
        let raw = r#"{
            "items": [
                {
                    "metadata": {
                        "name": "node-1",
                        "creationTimestamp": "2026-01-01T00:00:00Z",
                        "labels": {"node-role.kubernetes.io/control-plane": ""}
                    },
                    "status": {
                        "conditions": [
                            {"type": "Ready", "status": "True"}
                        ],
                        "nodeInfo": {"kubeletVersion": "v1.29.1"}
                    }
                },
                {
                    "metadata": {
                        "name": "node-2",
                        "creationTimestamp": "2026-01-01T00:00:00Z",
                        "labels": {}
                    },
                    "status": {
                        "conditions": [
                            {"type": "Ready", "status": "False"}
                        ],
                        "nodeInfo": {"kubeletVersion": "v1.29.1"}
                    }
                }
            ]
        }"#;
        let nodes = parse_k8s_nodes_json(raw);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "node-1");
        assert_eq!(nodes[0].status, "Ready");
        assert_eq!(nodes[0].roles, "control-plane");
        assert_eq!(nodes[0].version, "v1.29.1");
        assert_eq!(nodes[1].name, "node-2");
        assert_eq!(nodes[1].status, "NotReady");
        assert_eq!(nodes[1].roles, "<none>");
    }

    #[tokio::test]
    async fn test_discover_kubernetes_returns_none_when_kubectl_unavailable() {
        struct NoKubectl;
        #[async_trait]
        impl CommandRunner for NoKubectl {
            async fn run(&self, _command: &str) -> Result<CommandOutput> {
                anyhow::bail!("command not found: kubectl")
            }
        }

        let runner = NoKubectl;
        let result = discover_kubernetes(&runner).await;
        assert!(result.is_none());
    }
}
