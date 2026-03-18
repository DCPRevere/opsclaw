//! Append-only monitor log at `~/.opsclaw/monitor.log`.

use crate::tools::monitoring::{AlertSeverity, HealthCheck, HealthStatus};
use anyhow::{Context, Result};
use chrono::Utc;
use std::io::Write;
use std::path::PathBuf;

/// Return the path to the monitor log file.
fn log_path() -> Result<PathBuf> {
    let user_dirs = directories::UserDirs::new().context("Cannot determine home directory")?;
    Ok(user_dirs.home_dir().join(".opsclaw").join("monitor.log"))
}

/// Format a single health-check result as a log line.
pub fn format_log_line(hc: &HealthCheck) -> String {
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    match hc.status {
        HealthStatus::Healthy => {
            format!("[{ts}] {} HEALTHY", hc.target_name)
        }
        HealthStatus::Warning | HealthStatus::Critical => {
            let warnings = hc
                .alerts
                .iter()
                .filter(|a| a.severity == AlertSeverity::Warning)
                .count();
            let criticals = hc
                .alerts
                .iter()
                .filter(|a| a.severity == AlertSeverity::Critical)
                .count();

            let mut parts = Vec::new();
            if criticals > 0 {
                parts.push(format!("{criticals} critical"));
            }
            if warnings > 0 {
                parts.push(format!("{warnings} warning"));
            }

            let status_label = match hc.status {
                HealthStatus::Critical => "CRITICAL",
                HealthStatus::Warning => "WARNING",
                HealthStatus::Healthy => unreachable!(),
            };
            let alert_details: Vec<String> = hc
                .alerts
                .iter()
                .filter(|a| a.severity != AlertSeverity::Info)
                .map(|a| {
                    let sev = match a.severity {
                        AlertSeverity::Warning => "WARNING",
                        AlertSeverity::Critical => "CRITICAL",
                        AlertSeverity::Info => "INFO",
                    };
                    format!("{sev}: {}", a.message)
                })
                .collect();
            format!(
                "[{ts}] {} {status_label}: {}",
                hc.target_name,
                alert_details.join("; ")
            )
        }
    }
}

/// Append a health-check result to the monitor log file.
pub fn append_log(hc: &HealthCheck) -> Result<()> {
    let path = log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let line = format_log_line(hc);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Failed to open monitor log at {}", path.display()))?;
    writeln!(file, "{line}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::monitoring::*;
    use chrono::Utc;

    #[test]
    fn healthy_log_line_format() {
        let hc = HealthCheck {
            target_name: "sacra".into(),
            checked_at: Utc::now(),
            status: HealthStatus::Healthy,
            alerts: vec![],
        };
        let line = format_log_line(&hc);
        assert!(line.contains("sacra HEALTHY"));
        assert!(line.starts_with('['));
    }

    #[test]
    fn critical_log_line_format() {
        let hc = HealthCheck {
            target_name: "sacra".into(),
            checked_at: Utc::now(),
            status: HealthStatus::Critical,
            alerts: vec![Alert {
                severity: AlertSeverity::Critical,
                category: AlertCategory::ContainerDown,
                message: "Container 'sacra-api' DOWN".into(),
            }],
        };
        let line = format_log_line(&hc);
        assert!(line.contains("sacra CRITICAL"));
        assert!(line.contains("sacra-api"));
    }
}
