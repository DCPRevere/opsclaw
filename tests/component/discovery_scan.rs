//! Discovery scan component tests (Phase 1d).
//!
//! Tests the discovery scan routine that builds a target snapshot from
//! read-only commands. These tests validate the snapshot data model and
//! the scan's ability to parse command output into structured data.
//! They do NOT require a real SSH connection — they test the parsing layer.

use serde_json::Value;

// Import once implemented.
use zeroclaw::tools::ssh::discovery::{DiscoveryScan, TargetSnapshot};

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot structure
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn snapshot_has_required_sections() {
    let snapshot = TargetSnapshot::empty("prod-web-1");
    assert_eq!(snapshot.target_name(), "prod-web-1");
    assert!(snapshot.processes().is_empty());
    assert!(snapshot.listening_ports().is_empty());
    assert!(snapshot.containers().is_empty());
    assert!(snapshot.systemd_services().is_empty());
    assert!(snapshot.disks().is_empty());
    assert!(snapshot.os_info().is_none());
    assert!(snapshot.scanned_at().is_some(), "should record scan time");
}

#[test]
fn snapshot_serializes_to_json() {
    let snapshot = TargetSnapshot::empty("test");
    let json = serde_json::to_value(&snapshot).expect("should serialize to JSON");
    assert!(json.is_object());
    assert_eq!(json["target_name"], "test");
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing: ps aux
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_ps_aux_extracts_processes() {
    let ps_output = "\
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  16956  3456 ?        Ss   Mar15   0:03 /sbin/init
postgres   512  0.1  2.3 214788 47616 ?        Ss   Mar15   1:22 /usr/lib/postgresql/15/bin/postgres
www-data  1024  0.5  1.1  65432 22016 ?        S    Mar15   3:45 nginx: worker process
";
    let processes = DiscoveryScan::parse_ps_aux(ps_output);
    assert_eq!(processes.len(), 3);
    assert!(processes.iter().any(|p| p.command.contains("postgres")));
    assert!(processes.iter().any(|p| p.command.contains("nginx")));
    assert!(processes.iter().any(|p| p.user == "root"));
}

#[test]
fn parse_ps_aux_handles_empty_output() {
    let processes = DiscoveryScan::parse_ps_aux("");
    assert!(processes.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing: ss -tlnp
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_ss_extracts_listening_ports() {
    let ss_output = "\
State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process
LISTEN  0       128            0.0.0.0:22           0.0.0.0:*      users:((\"sshd\",pid=456,fd=3))
LISTEN  0       244          127.0.0.1:5432         0.0.0.0:*      users:((\"postgres\",pid=512,fd=6))
LISTEN  0       511            0.0.0.0:80           0.0.0.0:*      users:((\"nginx\",pid=1024,fd=8))
";
    let ports = DiscoveryScan::parse_ss(ss_output);
    assert_eq!(ports.len(), 3);
    assert!(ports.iter().any(|p| p.port == 22 && p.process == "sshd"));
    assert!(ports
        .iter()
        .any(|p| p.port == 5432 && p.process == "postgres"));
    assert!(ports.iter().any(|p| p.port == 80 && p.process == "nginx"));
}

#[test]
fn parse_ss_handles_ipv6() {
    let ss_output = "\
State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process
LISTEN  0       128               [::]:22              [::]:*      users:((\"sshd\",pid=456,fd=4))
";
    let ports = DiscoveryScan::parse_ss(ss_output);
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].port, 22);
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing: docker ps
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_docker_ps_extracts_containers() {
    let docker_output = "\
CONTAINER ID   IMAGE          COMMAND                  CREATED        STATUS        PORTS                  NAMES
abc123def456   postgres:15    \"docker-entrypoint.s…\"   2 days ago     Up 2 days     0.0.0.0:5432->5432/tcp db
fed654cba321   nginx:latest   \"/docker-entrypoint.…\"   2 days ago     Up 2 days     0.0.0.0:80->80/tcp     web
";
    let containers = DiscoveryScan::parse_docker_ps(docker_output);
    assert_eq!(containers.len(), 2);
    assert!(containers.iter().any(|c| c.name == "db" && c.image.contains("postgres")));
    assert!(containers.iter().any(|c| c.name == "web" && c.image.contains("nginx")));
    assert!(containers.iter().all(|c| c.status.contains("Up")));
}

#[test]
fn parse_docker_ps_handles_no_containers() {
    let docker_output = "\
CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES
";
    let containers = DiscoveryScan::parse_docker_ps(docker_output);
    assert!(containers.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing: df -h
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_df_extracts_disk_usage() {
    let df_output = "\
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   32G   16G  67% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sdb1       200G  180G   10G  95% /data
";
    let disks = DiscoveryScan::parse_df(df_output);
    assert!(disks.len() >= 2); // Might filter tmpfs
    assert!(disks.iter().any(|d| d.mount_point == "/" && d.use_percent == 67));
    assert!(disks.iter().any(|d| d.mount_point == "/data" && d.use_percent == 95));
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing: /etc/os-release
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_os_release() {
    let content = r#"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
"#;
    let info = DiscoveryScan::parse_os_release(content);
    assert_eq!(info.name, "Debian GNU/Linux");
    assert_eq!(info.version_id, "12");
    assert_eq!(info.id, "debian");
}

// ─────────────────────────────────────────────────────────────────────────────
// Database detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detect_databases_from_ports_and_processes() {
    let ss_output = "\
State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process
LISTEN  0       244          127.0.0.1:5432         0.0.0.0:*      users:((\"postgres\",pid=512,fd=6))
LISTEN  0       128          127.0.0.1:6379         0.0.0.0:*      users:((\"redis-server\",pid=800,fd=7))
LISTEN  0       80           127.0.0.1:3306         0.0.0.0:*      users:((\"mysqld\",pid=900,fd=5))
";
    let ports = DiscoveryScan::parse_ss(ss_output);
    let databases = DiscoveryScan::detect_databases(&ports);
    assert_eq!(databases.len(), 3);
    assert!(databases.iter().any(|d| d.db_type == "postgres" && d.port == 5432));
    assert!(databases.iter().any(|d| d.db_type == "redis" && d.port == 6379));
    assert!(databases.iter().any(|d| d.db_type == "mysql" && d.port == 3306));
}

#[test]
fn detect_postgres_on_non_standard_port() {
    let ss_output = "\
State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process
LISTEN  0       244          127.0.0.1:5433         0.0.0.0:*      users:((\"postgres\",pid=512,fd=6))
";
    let ports = DiscoveryScan::parse_ss(ss_output);
    let databases = DiscoveryScan::detect_databases(&ports);
    assert_eq!(databases.len(), 1);
    assert_eq!(databases[0].db_type, "postgres");
    assert_eq!(databases[0].port, 5433);
}

// ─────────────────────────────────────────────────────────────────────────────
// Drift detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn snapshot_diff_detects_new_container() {
    let mut old = TargetSnapshot::empty("test");
    old.add_container("web", "nginx:latest", "Up");

    let mut new = TargetSnapshot::empty("test");
    new.add_container("web", "nginx:latest", "Up");
    new.add_container("api", "myapp:v2", "Up");

    let diff = new.diff(&old);
    assert!(!diff.is_empty(), "should detect drift");
    assert!(
        diff.iter()
            .any(|d| d.contains("api") && d.contains("added")),
        "should report new container"
    );
}

#[test]
fn snapshot_diff_detects_stopped_container() {
    let mut old = TargetSnapshot::empty("test");
    old.add_container("web", "nginx:latest", "Up");
    old.add_container("worker", "myapp:v1", "Up");

    let mut new = TargetSnapshot::empty("test");
    new.add_container("web", "nginx:latest", "Up");

    let diff = new.diff(&old);
    assert!(
        diff.iter()
            .any(|d| d.contains("worker") && d.contains("removed")),
        "should report missing container"
    );
}

#[test]
fn snapshot_diff_empty_when_identical() {
    let mut s1 = TargetSnapshot::empty("test");
    s1.add_container("web", "nginx:latest", "Up");

    let mut s2 = TargetSnapshot::empty("test");
    s2.add_container("web", "nginx:latest", "Up");

    let diff = s1.diff(&s2);
    assert!(diff.is_empty(), "identical snapshots should have no diff");
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan is read-only
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn scan_commands_are_all_read_only() {
    let commands = DiscoveryScan::commands();
    let write_prefixes = [
        "rm ", "mv ", "cp ", "dd ", "mkfs", "kill", "reboot", "shutdown", "systemctl start",
        "systemctl stop", "systemctl restart", "docker stop", "docker rm", "docker kill",
        "apt", "yum", "dnf", "pip", "npm", "chmod", "chown",
    ];
    for cmd in &commands {
        for prefix in &write_prefixes {
            assert!(
                !cmd.starts_with(prefix),
                "scan command '{cmd}' looks like a write operation (starts with '{prefix}')"
            );
        }
    }
}
