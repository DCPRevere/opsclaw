//! External probes — HTTP, TCP, DNS, and TLS certificate checks.
//!
//! All probes execute commands via [`CommandRunner`] so they run from the
//! target host's perspective (over SSH or locally).

use anyhow::Result;

use zeroclaw::config::schema::{ProbeConfig, ProbeType};
use crate::tools::discovery::{CommandRunner, TargetSnapshot};
use crate::tools::monitoring::{Alert, AlertCategory, AlertSeverity};

// ---------------------------------------------------------------------------
// Probe result
// ---------------------------------------------------------------------------

/// Outcome of a single probe execution.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub probe_name: String,
    pub probe_type: String,
    pub success: bool,
    pub latency_ms: u64,
    pub message: String,
    pub details: Option<String>,
}

// ---------------------------------------------------------------------------
// Probe execution
// ---------------------------------------------------------------------------

/// Run a single probe via the given [`CommandRunner`].
pub async fn run_probe(
    runner: &dyn CommandRunner,
    probe: &ProbeConfig,
) -> Result<ProbeResult> {
    match &probe.probe_type {
        ProbeType::Http {
            url,
            expected_status,
            timeout_secs,
        } => run_http_probe(runner, &probe.name, url, *expected_status, *timeout_secs).await,
        ProbeType::Tcp {
            host,
            port,
            timeout_secs,
        } => run_tcp_probe(runner, &probe.name, host, *port, *timeout_secs).await,
        ProbeType::Dns {
            hostname,
            expected_ip,
        } => run_dns_probe(runner, &probe.name, hostname, expected_ip.as_deref()).await,
        ProbeType::TlsCert {
            hostname,
            port,
            warn_days,
        } => run_tls_probe(runner, &probe.name, hostname, *port, *warn_days).await,
    }
}

async fn run_http_probe(
    runner: &dyn CommandRunner,
    name: &str,
    url: &str,
    expected_status: Option<u16>,
    timeout_secs: u64,
) -> Result<ProbeResult> {
    let cmd = format!(
        "curl -sS -o /dev/null -w '%{{http_code}} %{{time_total}}' --max-time {timeout_secs} '{url}'"
    );
    let output = runner.run(&cmd).await?;
    let (success, latency_ms, message, details) =
        parse_curl_output(&output.stdout, output.exit_code, expected_status);
    Ok(ProbeResult {
        probe_name: name.to_string(),
        probe_type: "http".to_string(),
        success,
        latency_ms,
        message,
        details: Some(details),
    })
}

async fn run_tcp_probe(
    runner: &dyn CommandRunner,
    name: &str,
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<ProbeResult> {
    let cmd = format!("nc -z -w{timeout_secs} {host} {port} 2>&1 && echo OK || echo FAIL");
    let output = runner.run(&cmd).await?;
    let stdout = output.stdout.trim();
    let success = stdout.ends_with("OK");
    Ok(ProbeResult {
        probe_name: name.to_string(),
        probe_type: "tcp".to_string(),
        success,
        latency_ms: 0,
        message: if success {
            format!("TCP connection to {host}:{port} succeeded")
        } else {
            format!("TCP connection to {host}:{port} failed")
        },
        details: Some(stdout.to_string()),
    })
}

async fn run_dns_probe(
    runner: &dyn CommandRunner,
    name: &str,
    hostname: &str,
    expected_ip: Option<&str>,
) -> Result<ProbeResult> {
    let cmd = format!("dig +short {hostname}");
    let output = runner.run(&cmd).await?;
    let (success, message, details) =
        parse_dig_output(&output.stdout, expected_ip);
    Ok(ProbeResult {
        probe_name: name.to_string(),
        probe_type: "dns".to_string(),
        success,
        latency_ms: 0,
        message,
        details: Some(details),
    })
}

async fn run_tls_probe(
    runner: &dyn CommandRunner,
    name: &str,
    hostname: &str,
    port: u16,
    warn_days: u32,
) -> Result<ProbeResult> {
    let check_secs = u64::from(warn_days) * 86400;
    let cmd = format!(
        "echo | openssl s_client -servername {hostname} -connect {hostname}:{port} 2>/dev/null \
         | openssl x509 -noout -enddate -checkend {check_secs}"
    );
    let output = runner.run(&cmd).await?;
    let (success, message, details) =
        parse_openssl_output(&output.stdout, output.exit_code, hostname, warn_days);
    Ok(ProbeResult {
        probe_name: name.to_string(),
        probe_type: "tls_cert".to_string(),
        success,
        latency_ms: 0,
        message,
        details: Some(details),
    })
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Parse curl `-w '%{http_code} %{time_total}'` output.
///
/// Returns `(success, latency_ms, message, details)`.
pub fn parse_curl_output(
    stdout: &str,
    exit_code: i32,
    expected_status: Option<u16>,
) -> (bool, u64, String, String) {
    let trimmed = stdout.trim();
    let parts: Vec<&str> = trimmed.split_whitespace().collect();

    if exit_code != 0 || parts.len() < 2 {
        return (
            false,
            0,
            format!("HTTP probe failed (exit code {exit_code})"),
            trimmed.to_string(),
        );
    }

    let status_code: u16 = parts[0].parse().unwrap_or(0);
    let time_total: f64 = parts[1].parse().unwrap_or(0.0);
    let latency_ms = (time_total * 1000.0) as u64;

    let expected = expected_status.unwrap_or(200);
    let success = status_code == expected;

    let message = if success {
        format!("HTTP {status_code} in {latency_ms}ms")
    } else {
        format!("HTTP {status_code} (expected {expected}) in {latency_ms}ms")
    };

    (success, latency_ms, message, trimmed.to_string())
}

/// Parse `dig +short` output. Returns `(success, message, details)`.
pub fn parse_dig_output(stdout: &str, expected_ip: Option<&str>) -> (bool, String, String) {
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return (
            false,
            "DNS resolution returned no results".to_string(),
            stdout.to_string(),
        );
    }

    match expected_ip {
        Some(ip) => {
            let found = lines.iter().any(|l| *l == ip);
            if found {
                (
                    true,
                    format!("DNS resolved to expected IP {ip}"),
                    lines.join(", "),
                )
            } else {
                (
                    false,
                    format!("DNS resolved to [{}], expected {ip}", lines.join(", ")),
                    lines.join(", "),
                )
            }
        }
        None => (
            true,
            format!("DNS resolved to {}", lines.join(", ")),
            lines.join(", "),
        ),
    }
}

/// Parse openssl cert check output. Returns `(success, message, details)`.
pub fn parse_openssl_output(
    stdout: &str,
    exit_code: i32,
    hostname: &str,
    warn_days: u32,
) -> (bool, String, String) {
    let trimmed = stdout.trim();
    // openssl x509 -checkend returns 0 if cert is still valid, 1 if it will expire
    if exit_code == 0 {
        let expiry = extract_expiry_date(trimmed);
        (
            true,
            format!("TLS cert for {hostname} valid for >{warn_days} days{expiry}"),
            trimmed.to_string(),
        )
    } else {
        let expiry = extract_expiry_date(trimmed);
        (
            false,
            format!("TLS cert for {hostname} expires within {warn_days} days{expiry}"),
            trimmed.to_string(),
        )
    }
}

fn extract_expiry_date(output: &str) -> String {
    // Look for "notAfter=..." line
    for line in output.lines() {
        if let Some(date) = line.strip_prefix("notAfter=") {
            return format!(" (expires: {date})");
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Auto-discover probes from snapshot
// ---------------------------------------------------------------------------

/// Generate probe configs from a target snapshot's listening ports and containers.
///
/// When `host` is provided (e.g. for SSH targets), auto-discovered probes use
/// that address instead of `localhost`, so they hit the remote machine.
pub fn discover_probes(snapshot: &TargetSnapshot, host: Option<&str>) -> Vec<ProbeConfig> {
    let probe_host = host.unwrap_or("localhost");
    let mut probes = Vec::new();

    // From containers: any container exposing port 80/443 → HTTP probe
    for c in &snapshot.containers {
        if c.ports.contains("80") || c.ports.contains("443") {
            let port_num = if c.ports.contains("443") { 443 } else { 80 };
            let scheme = if port_num == 443 { "https" } else { "http" };
            probes.push(ProbeConfig {
                name: format!("auto-http-{}", c.name),
                probe_type: ProbeType::Http {
                    url: format!("{scheme}://{probe_host}:{port_num}/"),
                    expected_status: Some(200),
                    timeout_secs: 5,
                },
            });
        }
    }

    // From listening ports
    for p in &snapshot.listening_ports {
        let proc_lower = p.process.to_lowercase();
        // Any listening port with "http" or "api" in process name → HTTP probe
        if proc_lower.contains("http") || proc_lower.contains("api") {
            let name = format!("auto-http-{}-{}", p.process.replace('/', "-"), p.port);
            // Avoid duplicates with container probes
            if !probes.iter().any(|existing| existing.name == name) {
                probes.push(ProbeConfig {
                    name,
                    probe_type: ProbeType::Http {
                        url: format!("http://{probe_host}:{}/", p.port),
                        expected_status: None,
                        timeout_secs: 5,
                    },
                });
            }
        }

        // Any 443 listener → TLS cert check
        if p.port == 443 {
            probes.push(ProbeConfig {
                name: format!("auto-tls-{}", p.port),
                probe_type: ProbeType::TlsCert {
                    hostname: probe_host.to_string(),
                    port: 443,
                    warn_days: 30,
                },
            });
        }
    }

    probes
}

// ---------------------------------------------------------------------------
// Convert probe results to alerts
// ---------------------------------------------------------------------------

/// Convert a failed probe result into an [`Alert`].
pub fn probe_result_to_alert(result: &ProbeResult) -> Option<Alert> {
    if result.success {
        return None;
    }

    let (severity, category) = match result.probe_type.as_str() {
        "tls_cert" => (AlertSeverity::Warning, AlertCategory::TlsCertExpiring),
        "dns" => (AlertSeverity::Warning, AlertCategory::DnsResolutionFailed),
        _ => (AlertSeverity::Critical, AlertCategory::ProbeFailure),
    };

    Some(Alert {
        severity,
        category,
        message: format!("[{}] {}", result.probe_name, result.message),
    })
}

/// Format probe results as a markdown summary for LLM context.
pub fn probe_results_to_markdown(results: &[ProbeResult]) -> String {
    use std::fmt::Write;
    let mut md = String::new();
    let _ = writeln!(md, "## External Probe Results\n");
    for r in results {
        let icon = if r.success { "OK" } else { "FAIL" };
        let _ = writeln!(
            md,
            "- **[{icon}]** {name} ({ptype}): {msg}",
            name = r.probe_name,
            ptype = r.probe_type,
            msg = r.message
        );
        if let Some(ref d) = r.details {
            if !d.is_empty() {
                let _ = writeln!(md, "  - Details: {d}");
            }
        }
    }
    md
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::discovery::*;
    use chrono::Utc;

    #[test]
    fn parse_curl_success() {
        let (ok, latency, msg, _) = parse_curl_output("200 0.042", 0, Some(200));
        assert!(ok);
        assert_eq!(latency, 42);
        assert!(msg.contains("200"));
    }

    #[test]
    fn parse_curl_wrong_status() {
        let (ok, _, msg, _) = parse_curl_output("503 0.100", 0, Some(200));
        assert!(!ok);
        assert!(msg.contains("503"));
        assert!(msg.contains("expected 200"));
    }

    #[test]
    fn parse_curl_timeout() {
        let (ok, _, msg, _) = parse_curl_output("", 28, None);
        assert!(!ok);
        assert!(msg.contains("exit code 28"));
    }

    #[test]
    fn parse_curl_default_expects_200() {
        let (ok, _, _, _) = parse_curl_output("200 0.010", 0, None);
        assert!(ok);
    }

    #[test]
    fn parse_dig_with_expected_ip() {
        let (ok, msg, _) = parse_dig_output("93.184.216.34\n", Some("93.184.216.34"));
        assert!(ok);
        assert!(msg.contains("expected IP"));
    }

    #[test]
    fn parse_dig_wrong_ip() {
        let (ok, msg, _) = parse_dig_output("1.2.3.4\n", Some("5.6.7.8"));
        assert!(!ok);
        assert!(msg.contains("expected 5.6.7.8"));
    }

    #[test]
    fn parse_dig_no_result() {
        let (ok, msg, _) = parse_dig_output("", None);
        assert!(!ok);
        assert!(msg.contains("no results"));
    }

    #[test]
    fn parse_dig_no_expected() {
        let (ok, msg, _) = parse_dig_output("10.0.0.1\n", None);
        assert!(ok);
        assert!(msg.contains("10.0.0.1"));
    }

    #[test]
    fn parse_openssl_cert_valid() {
        let output = "notAfter=Dec 31 23:59:59 2026 GMT\nCertificate will not expire";
        let (ok, msg, _) = parse_openssl_output(output, 0, "example.com", 30);
        assert!(ok);
        assert!(msg.contains("valid"));
        assert!(msg.contains("example.com"));
    }

    #[test]
    fn parse_openssl_cert_expiring() {
        let output = "notAfter=Jan  1 00:00:00 2025 GMT\nCertificate will expire";
        let (ok, msg, _) = parse_openssl_output(output, 1, "example.com", 30);
        assert!(!ok);
        assert!(msg.contains("expires within"));
    }

    #[test]
    fn probe_failure_creates_alert() {
        let result = ProbeResult {
            probe_name: "api-health".to_string(),
            probe_type: "http".to_string(),
            success: false,
            latency_ms: 100,
            message: "HTTP 503".to_string(),
            details: None,
        };
        let alert = probe_result_to_alert(&result).expect("should create alert");
        assert_eq!(alert.category, AlertCategory::ProbeFailure);
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }

    #[test]
    fn probe_success_no_alert() {
        let result = ProbeResult {
            probe_name: "api-health".to_string(),
            probe_type: "http".to_string(),
            success: true,
            latency_ms: 42,
            message: "HTTP 200".to_string(),
            details: None,
        };
        assert!(probe_result_to_alert(&result).is_none());
    }

    #[test]
    fn tls_failure_alert_category() {
        let result = ProbeResult {
            probe_name: "tls-check".to_string(),
            probe_type: "tls_cert".to_string(),
            success: false,
            latency_ms: 0,
            message: "cert expiring".to_string(),
            details: None,
        };
        let alert = probe_result_to_alert(&result).unwrap();
        assert_eq!(alert.category, AlertCategory::TlsCertExpiring);
    }

    #[test]
    fn dns_failure_alert_category() {
        let result = ProbeResult {
            probe_name: "dns-check".to_string(),
            probe_type: "dns".to_string(),
            success: false,
            latency_ms: 0,
            message: "no results".to_string(),
            details: None,
        };
        let alert = probe_result_to_alert(&result).unwrap();
        assert_eq!(alert.category, AlertCategory::DnsResolutionFailed);
    }

    #[test]
    fn discover_probes_from_web_containers() {
        let snapshot = TargetSnapshot {
            scanned_at: Utc::now(),
            os: OsInfo {
                uname: String::new(),
                distro_name: String::new(),
                distro_version: String::new(),
            },
            containers: vec![ContainerInfo {
                id: "abc123".to_string(),
                name: "nginx".to_string(),
                image: "nginx:latest".to_string(),
                status: "Up 2 hours".to_string(),
                ports: "0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp".to_string(),
                running_for: "2 hours".to_string(),
            }],
            services: vec![],
            listening_ports: vec![PortInfo {
                protocol: "tcp".to_string(),
                address: "0.0.0.0".to_string(),
                port: 443,
                process: "nginx".to_string(),
            }],
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
        };

        let probes = discover_probes(&snapshot, None);
        assert!(!probes.is_empty());
        // Should have at least an HTTP probe from the container and a TLS probe from port 443
        let has_http = probes.iter().any(|p| matches!(p.probe_type, ProbeType::Http { .. }));
        let has_tls = probes.iter().any(|p| matches!(p.probe_type, ProbeType::TlsCert { .. }));
        assert!(has_http, "expected HTTP probe from container");
        assert!(has_tls, "expected TLS probe from port 443");
    }
}
