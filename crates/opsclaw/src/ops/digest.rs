//! Daily digest generator — summarises monitoring activity over a rolling window.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ops::baseline::AnomalyAlert;
use crate::ops::incident_search::IncidentRecord;
use crate::tools::monitoring::HealthStatus;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Per-target summary within a digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetDigest {
    pub name: String,
    pub health_status: HealthStatus,
    pub incidents: Vec<IncidentRecord>,
    pub alerts: Vec<String>,
    pub baseline_anomalies: Vec<AnomalyAlert>,
    pub probe_failures: u32,
}

/// Full digest report covering a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestReport {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub targets: Vec<TargetDigest>,
    pub total_incidents: u32,
    pub auto_resolved: u32,
    pub pending: u32,
    pub highlights: Vec<String>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Input data for a single target when generating a digest.
pub struct TargetInput {
    pub name: String,
    pub health_status: HealthStatus,
    pub incidents: Vec<IncidentRecord>,
    pub alerts: Vec<String>,
    pub baseline_anomalies: Vec<AnomalyAlert>,
    pub probe_failures: u32,
}

impl DigestReport {
    /// Build a digest from pre-collected per-target data for the given period.
    pub fn generate(targets: Vec<TargetInput>, period_hours: u32) -> Self {
        let period_end = Utc::now();
        let period_start = period_end - chrono::Duration::hours(i64::from(period_hours));

        let mut total_incidents: u32 = 0;
        let mut auto_resolved: u32 = 0;
        let mut pending: u32 = 0;
        let mut highlights: Vec<String> = Vec::new();

        let target_digests: Vec<TargetDigest> = targets
            .into_iter()
            .map(|input| {
                let count = input.incidents.len() as u32;
                total_incidents += count;

                let resolved = input
                    .incidents
                    .iter()
                    .filter(|i| i.resolution.is_some())
                    .count() as u32;
                auto_resolved += resolved;
                pending += count - resolved;

                if matches!(input.health_status, HealthStatus::Critical) {
                    highlights.push(format!("{}: CRITICAL", input.name));
                }

                if !input.baseline_anomalies.is_empty() {
                    highlights.push(format!(
                        "{}: {} baseline anomalies",
                        input.name,
                        input.baseline_anomalies.len()
                    ));
                }

                TargetDigest {
                    name: input.name,
                    health_status: input.health_status,
                    incidents: input.incidents,
                    alerts: input.alerts,
                    baseline_anomalies: input.baseline_anomalies,
                    probe_failures: input.probe_failures,
                }
            })
            .collect();

        Self {
            period_start,
            period_end,
            targets: target_digests,
            total_incidents,
            auto_resolved,
            pending,
            highlights,
        }
    }

    /// Render the digest as a full markdown report.
    pub fn to_markdown(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        let _ = writeln!(out, "# OpsClaw Daily Digest");
        let _ = writeln!(
            out,
            "Period: {} — {}",
            self.period_start.format("%Y-%m-%d %H:%M UTC"),
            self.period_end.format("%Y-%m-%d %H:%M UTC"),
        );
        let _ = writeln!(out);

        let _ = writeln!(out, "## Summary");
        let _ = writeln!(
            out,
            "- **Incidents**: {} total, {} auto-resolved, {} pending",
            self.total_incidents, self.auto_resolved, self.pending,
        );
        let _ = writeln!(out, "- **Targets monitored**: {}", self.targets.len());
        let _ = writeln!(out);

        if self.targets.is_empty() && self.total_incidents == 0 {
            let _ = writeln!(out, "All quiet — no incidents or anomalies detected.");
            return out;
        }

        if !self.highlights.is_empty() {
            let _ = writeln!(out, "## Highlights");
            for h in &self.highlights {
                let _ = writeln!(out, "- {h}");
            }
            let _ = writeln!(out);
        }

        for t in &self.targets {
            let _ = writeln!(out, "## {}", t.name);
            let _ = writeln!(out, "- Health: {:?}", t.health_status);
            let _ = writeln!(out, "- Incidents: {}", t.incidents.len());
            if t.probe_failures > 0 {
                let _ = writeln!(out, "- Probe failures: {}", t.probe_failures);
            }

            if !t.alerts.is_empty() {
                let _ = writeln!(out, "### Alerts");
                for a in &t.alerts {
                    let _ = writeln!(out, "- {a}");
                }
            }

            if !t.baseline_anomalies.is_empty() {
                let _ = writeln!(out, "### Baseline Anomalies");
                for a in &t.baseline_anomalies {
                    let _ = writeln!(out, "- {}", a.message);
                }
            }

            if !t.incidents.is_empty() {
                let _ = writeln!(out, "### Incidents");
                for inc in &t.incidents {
                    let status = if inc.resolution.is_some() {
                        "resolved"
                    } else {
                        "pending"
                    };
                    let _ = writeln!(
                        out,
                        "- [{}] {} — {} ({})",
                        inc.severity, inc.incident_id, inc.symptoms, status,
                    );
                }
            }

            let _ = writeln!(out);
        }

        // Action items
        let unresolved: Vec<_> = self
            .targets
            .iter()
            .flat_map(|t| t.incidents.iter().filter(|i| i.resolution.is_none()))
            .collect();

        if !unresolved.is_empty() {
            let _ = writeln!(out, "## Action Items");
            for inc in &unresolved {
                let _ = writeln!(
                    out,
                    "- [ ] Resolve {} on {} ({})",
                    inc.incident_id, inc.target_name, inc.severity,
                );
            }
            let _ = writeln!(out);
        }

        out
    }

    /// Render a short summary suitable for Telegram (< 4096 chars).
    pub fn to_short_summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        let _ = writeln!(out, "OpsClaw Digest");
        let _ = writeln!(
            out,
            "{} — {}",
            self.period_start.format("%m/%d %H:%M"),
            self.period_end.format("%m/%d %H:%M"),
        );
        let _ = writeln!(out);

        if self.total_incidents == 0 && self.highlights.is_empty() {
            let _ = writeln!(out, "All quiet.");
            return out;
        }

        let _ = writeln!(
            out,
            "Incidents: {} total, {} resolved, {} pending",
            self.total_incidents, self.auto_resolved, self.pending,
        );

        for t in &self.targets {
            let _ = writeln!(
                out,
                "  {:?} {} — {} incidents, {} anomalies",
                t.health_status,
                t.name,
                t.incidents.len(),
                t.baseline_anomalies.len(),
            );
        }

        if !self.highlights.is_empty() {
            let _ = writeln!(out);
            for h in &self.highlights {
                let _ = writeln!(out, "! {h}");
            }
        }

        // Truncate to Telegram limit.
        if out.len() > 4096 {
            out.truncate(4090);
            out.push_str("\n...");
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::baseline::{AnomalyAlert, Trend};

    fn make_incident(id: &str, target: &str, resolved: bool) -> IncidentRecord {
        IncidentRecord {
            incident_id: id.to_string(),
            timestamp: Utc::now(),
            target_name: target.to_string(),
            severity: "Act".to_string(),
            llm_assessment: "Something broke".to_string(),
            suggested_actions: vec!["restart".to_string()],
            symptoms: "service down".to_string(),
            resolution: if resolved {
                Some("restarted".to_string())
            } else {
                None
            },
        }
    }

    fn make_anomaly(metric: &str) -> AnomalyAlert {
        AnomalyAlert {
            metric: metric.to_string(),
            current: 95.0,
            mean: 50.0,
            stddev: 5.0,
            sigma: 9.0,
            trend: Trend::Rising,
            message: format!("{metric} is 95.0 (normally 50.0)"),
        }
    }

    #[test]
    fn digest_from_mock_data() {
        let inputs = vec![TargetInput {
            name: "prod-1".to_string(),
            health_status: HealthStatus::Critical,
            incidents: vec![
                make_incident("inc-1", "prod-1", true),
                make_incident("inc-2", "prod-1", false),
            ],
            alerts: vec!["CPU high".to_string()],
            baseline_anomalies: vec![make_anomaly("cpu.load_1")],
            probe_failures: 1,
        }];

        let report = DigestReport::generate(inputs, 24);

        assert_eq!(report.total_incidents, 2);
        assert_eq!(report.auto_resolved, 1);
        assert_eq!(report.pending, 1);
        assert_eq!(report.targets.len(), 1);

        let md = report.to_markdown();
        assert!(md.contains("# OpsClaw Daily Digest"));
        assert!(md.contains("prod-1"));
        assert!(md.contains("Action Items"));
        assert!(md.contains("inc-2"));
    }

    #[test]
    fn short_summary_within_telegram_limit() {
        let mut incidents = Vec::new();
        for i in 0..50 {
            incidents.push(make_incident(&format!("inc-{i}"), "prod", i % 2 == 0));
        }

        let inputs = vec![TargetInput {
            name: "prod".to_string(),
            health_status: HealthStatus::Warning,
            incidents,
            alerts: vec!["alert".to_string()],
            baseline_anomalies: vec![make_anomaly("mem")],
            probe_failures: 0,
        }];

        let report = DigestReport::generate(inputs, 24);
        let summary = report.to_short_summary();
        assert!(summary.len() <= 4096);
        assert!(summary.contains("Incidents:"));
    }

    #[test]
    fn empty_period_all_quiet() {
        let report = DigestReport::generate(vec![], 24);

        assert_eq!(report.total_incidents, 0);

        let md = report.to_markdown();
        assert!(md.contains("All quiet"));

        let summary = report.to_short_summary();
        assert!(summary.contains("All quiet"));
    }
}
