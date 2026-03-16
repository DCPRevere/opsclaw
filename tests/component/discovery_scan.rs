use anyhow::Result;
use async_trait::async_trait;
use zeroclaw::tools::discovery::*;

// ---------------------------------------------------------------------------
// Mock runner
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
// Realistic sample outputs
// ---------------------------------------------------------------------------

const UNAME_OUTPUT: &str =
    "Linux sacra-vps 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux";

const OS_RELEASE_OUTPUT: &str = r#"PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"#;

const SS_OUTPUT: &str = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      4096       0.0.0.0:33000      0.0.0.0:*     users:((\"docker-proxy\",pid=1234,fd=4))
LISTEN 0      4096       0.0.0.0:33100      0.0.0.0:*     users:((\"docker-proxy\",pid=1235,fd=4))
LISTEN 0      4096       0.0.0.0:33200      0.0.0.0:*     users:((\"docker-proxy\",pid=1236,fd=4))
LISTEN 0      4096       0.0.0.0:33300      0.0.0.0:*     users:((\"docker-proxy\",pid=1237,fd=4))
LISTEN 0      4096       127.0.0.1:5432     0.0.0.0:*     users:((\"docker-proxy\",pid=1238,fd=4))
LISTEN 0      128        0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=800,fd=3))
";

const DOCKER_PS_OUTPUT: &str = r#"{"ID":"abc123","Names":"sacra-api","Image":"sacra/api:latest","Status":"Up 5 hours","Ports":"0.0.0.0:33000->8080/tcp","RunningFor":"5 hours"}
{"ID":"def456","Names":"sacra-server","Image":"sacra/server:latest","Status":"Up 5 hours","Ports":"0.0.0.0:33100->8080/tcp","RunningFor":"5 hours"}
{"ID":"ghi789","Names":"postgres","Image":"postgres:15","Status":"Up 5 hours","Ports":"5432/tcp","RunningFor":"5 hours"}
{"ID":"jkl012","Names":"seq","Image":"datalust/seq:latest","Status":"Up 5 hours","Ports":"0.0.0.0:33200->80/tcp","RunningFor":"5 hours"}
{"ID":"mno345","Names":"jaeger","Image":"jaegertracing/all-in-one:1.51","Status":"Up 5 hours","Ports":"0.0.0.0:33300->16686/tcp","RunningFor":"5 hours"}
"#;

const SYSTEMCTL_OUTPUT: &str = "  UNIT                       LOAD   ACTIVE SUB     DESCRIPTION
  ssh.service                loaded active running OpenBSD Secure Shell server
  docker.service             loaded active running Docker Application Container Engine
  systemd-journald.service   loaded active running Journal Service

3 loaded units listed.
";

const DF_OUTPUT: &str = "Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        40G   22G   16G  58% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
/dev/sda15      105M  6.1M   99M   6% /boot/efi
";

const FREE_OUTPUT: &str =
    "              total        used        free      shared  buff/cache   available
Mem:           7951        3042         512         123        4396        4558
Swap:          2047         100        1947
";

const UPTIME_OUTPUT: &str =
    " 14:23:05 up 42 days,  3:15,  2 users,  load average: 0.45, 0.30, 0.25";

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

#[test]
fn parse_uname_extracts_kernel() {
    let result = parse_uname(UNAME_OUTPUT);
    assert!(result.contains("5.15.0-91-generic"));
    assert!(result.contains("x86_64"));
}

#[test]
fn parse_os_release_extracts_distro() {
    let (name, ver) = parse_os_release(OS_RELEASE_OUTPUT);
    assert_eq!(name, "Ubuntu");
    assert_eq!(ver, "22.04");
}

#[test]
fn parse_ss_finds_all_ports() {
    let ports = parse_ss(SS_OUTPUT);
    assert_eq!(ports.len(), 6);
    let port_nums: Vec<u16> = ports.iter().map(|p| p.port).collect();
    assert!(port_nums.contains(&33000));
    assert!(port_nums.contains(&33100));
    assert!(port_nums.contains(&33200));
    assert!(port_nums.contains(&33300));
    assert!(port_nums.contains(&5432));
    assert!(port_nums.contains(&22));
}

#[test]
fn parse_ss_extracts_process_info() {
    let ports = parse_ss(SS_OUTPUT);
    let ssh_port = ports.iter().find(|p| p.port == 22).unwrap();
    assert!(ssh_port.process.contains("sshd"));
}

#[test]
fn parse_docker_ps_json_sacra_containers() {
    let containers = parse_docker_ps_json(DOCKER_PS_OUTPUT);
    assert_eq!(containers.len(), 5);
    let names: Vec<&str> = containers.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"sacra-api"));
    assert!(names.contains(&"sacra-server"));
    assert!(names.contains(&"postgres"));
    assert!(names.contains(&"seq"));
    assert!(names.contains(&"jaeger"));
}

#[test]
fn parse_docker_ps_json_extracts_fields() {
    let containers = parse_docker_ps_json(DOCKER_PS_OUTPUT);
    let api = containers.iter().find(|c| c.name == "sacra-api").unwrap();
    assert_eq!(api.image, "sacra/api:latest");
    assert_eq!(api.status, "Up 5 hours");
    assert!(api.ports.contains("33000"));
}

#[test]
fn parse_systemctl_services() {
    let services = parse_systemctl(SYSTEMCTL_OUTPUT);
    assert_eq!(services.len(), 3);
    let units: Vec<&str> = services.iter().map(|s| s.unit.as_str()).collect();
    assert!(units.contains(&"ssh.service"));
    assert!(units.contains(&"docker.service"));
}

#[test]
fn parse_df_disk_usage() {
    let disks = parse_df(DF_OUTPUT);
    assert_eq!(disks.len(), 3);
    let root = disks.iter().find(|d| d.mount_point == "/").unwrap();
    assert_eq!(root.use_percent, 58);
    assert_eq!(root.size, "40G");
}

#[test]
fn parse_free_memory() {
    let mem = parse_free(FREE_OUTPUT);
    assert_eq!(mem.total_mb, 7951);
    assert_eq!(mem.used_mb, 3042);
    assert_eq!(mem.available_mb, 4558);
}

#[test]
fn parse_uptime_load() {
    let load = parse_uptime(UPTIME_OUTPUT);
    assert!((load.load_1 - 0.45).abs() < 0.001);
    assert!((load.load_5 - 0.30).abs() < 0.001);
    assert!((load.load_15 - 0.25).abs() < 0.001);
}

// ---------------------------------------------------------------------------
// Full scan integration test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_scan_produces_snapshot() {
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

    let snap = run_discovery_scan(&runner).await.unwrap();

    assert_eq!(snap.os.distro_name, "Ubuntu");
    assert_eq!(snap.os.distro_version, "22.04");
    assert_eq!(snap.containers.len(), 5);
    assert_eq!(snap.services.len(), 3);
    assert_eq!(snap.listening_ports.len(), 6);
    assert_eq!(snap.disk.len(), 3);
    assert_eq!(snap.memory.total_mb, 7951);
    assert!((snap.load.load_1 - 0.45).abs() < 0.001);
}

// ---------------------------------------------------------------------------
// Markdown summary test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn markdown_summary_contains_key_sections() {
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

    let snap = run_discovery_scan(&runner).await.unwrap();
    let md = snapshot_to_markdown(&snap);

    assert!(md.contains("# Discovery Scan"));
    assert!(md.contains("## OS"));
    assert!(md.contains("Ubuntu"));
    assert!(md.contains("## Containers"));
    assert!(md.contains("sacra-api"));
    assert!(md.contains("## Listening Ports"));
    assert!(md.contains("33000"));
    assert!(md.contains("## Disk"));
    assert!(md.contains("58%"));
    assert!(md.contains("## Memory"));
    assert!(md.contains("7951"));
}
