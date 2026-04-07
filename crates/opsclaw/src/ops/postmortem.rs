//! Post-mortem generator — structured incident reports from recorded data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ops::incident_search::IncidentRecord;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// A single event in the incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event: String,
}

/// A structured post-mortem report for a single incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMortem {
    pub incident_id: String,
    pub title: String,
    pub severity: String,
    pub target: String,
    pub timeline: Vec<TimelineEntry>,
    pub root_cause: String,
    pub impact: String,
    pub actions_taken: Vec<String>,
    pub resolution: String,
    pub recommendations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

impl PostMortem {
    /// Generate a post-mortem from an incident record and optional health-check context.
    ///
    /// `health_checks` supplies additional timeline context (e.g. probe results
    /// recorded before and after the incident).
    pub fn generate(incident: &IncidentRecord, health_checks: &[TimelineEntry]) -> Self {
        let mut timeline = Vec::new();

        // Detection event.
        timeline.push(TimelineEntry {
            timestamp: incident.timestamp,
            event: format!("Incident detected: {}", incident.symptoms),
        });

        // Interleave health-check entries.
        for entry in health_checks {
            timeline.push(entry.clone());
        }

        // Diagnosis event.
        timeline.push(TimelineEntry {
            timestamp: incident.timestamp,
            event: format!("Diagnosis: {}", incident.llm_assessment),
        });

        // Actions taken.
        for action in &incident.suggested_actions {
            timeline.push(TimelineEntry {
                timestamp: incident.timestamp,
                event: format!("Action: {action}"),
            });
        }

        // Resolution event.
        let resolution = incident
            .resolution
            .clone()
            .unwrap_or_else(|| "Unresolved".to_string());

        if incident.resolution.is_some() {
            timeline.push(TimelineEntry {
                timestamp: incident.timestamp,
                event: format!("Resolved: {resolution}"),
            });
        }

        // Sort chronologically.
        timeline.sort_by_key(|e| e.timestamp);

        let title = format!("{} incident on {}", incident.severity, incident.target_name,);

        let impact = if incident.severity == "Act" {
            format!(
                "Service disruption on {} requiring immediate action",
                incident.target_name,
            )
        } else {
            format!("Degraded performance on {}", incident.target_name)
        };

        Self {
            incident_id: incident.incident_id.clone(),
            title,
            severity: incident.severity.clone(),
            target: incident.target_name.clone(),
            timeline,
            root_cause: incident.llm_assessment.clone(),
            impact,
            actions_taken: incident.suggested_actions.clone(),
            resolution,
            recommendations: derive_recommendations(incident),
        }
    }

    /// Render the post-mortem as markdown.
    pub fn to_markdown(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        let _ = writeln!(out, "# Post-Mortem: {}", self.title);
        let _ = writeln!(out);
        let _ = writeln!(out, "- **Incident ID**: {}", self.incident_id);
        let _ = writeln!(out, "- **Severity**: {}", self.severity);
        let _ = writeln!(out, "- **Target**: {}", self.target);
        let _ = writeln!(out);

        let _ = writeln!(out, "## Timeline");
        for entry in &self.timeline {
            let _ = writeln!(
                out,
                "- `{}` {}",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                entry.event,
            );
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "## Root Cause");
        let _ = writeln!(out, "{}", self.root_cause);
        let _ = writeln!(out);

        let _ = writeln!(out, "## Impact");
        let _ = writeln!(out, "{}", self.impact);
        let _ = writeln!(out);

        let _ = writeln!(out, "## Actions Taken");
        for action in &self.actions_taken {
            let _ = writeln!(out, "- {action}");
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "## Resolution");
        let _ = writeln!(out, "{}", self.resolution);
        let _ = writeln!(out);

        if !self.recommendations.is_empty() {
            let _ = writeln!(out, "## Recommendations");
            for rec in &self.recommendations {
                let _ = writeln!(out, "- {rec}");
            }
            let _ = writeln!(out);
        }

        out
    }
}

/// Derive simple recommendations based on incident data.
fn derive_recommendations(incident: &IncidentRecord) -> Vec<String> {
    let mut recs = Vec::new();

    let symptoms_lower = incident.symptoms.to_lowercase();

    if symptoms_lower.contains("oom") || symptoms_lower.contains("memory") {
        recs.push("Review memory limits and consider increasing allocation".to_string());
    }
    if symptoms_lower.contains("disk") {
        recs.push("Set up disk usage alerting with lower thresholds".to_string());
    }
    if symptoms_lower.contains("down") || symptoms_lower.contains("crashed") {
        recs.push("Add health-check probes and automatic restart policies".to_string());
    }

    if incident.resolution.is_none() {
        recs.push("Investigate and resolve this incident".to_string());
    }

    if recs.is_empty() {
        recs.push("Review monitoring thresholds for this target".to_string());
    }

    recs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_incident(resolved: bool) -> IncidentRecord {
        IncidentRecord {
            incident_id: "inc-42".to_string(),
            timestamp: Utc::now(),
            target_name: "prod-web".to_string(),
            severity: "Act".to_string(),
            llm_assessment: "Container crashed due to OOM".to_string(),
            suggested_actions: vec!["restart container".to_string()],
            symptoms: "container down, OOM detected".to_string(),
            resolution: if resolved {
                Some("Container restarted with higher memory limit".to_string())
            } else {
                None
            },
        }
    }

    #[test]
    fn postmortem_generate_and_render() {
        let incident = make_incident(true);
        let pm = PostMortem::generate(&incident, &[]);

        assert_eq!(pm.incident_id, "inc-42");
        assert_eq!(pm.target, "prod-web");
        assert!(!pm.timeline.is_empty());

        let md = pm.to_markdown();
        assert!(md.contains("# Post-Mortem:"));
        assert!(md.contains("inc-42"));
        assert!(md.contains("## Timeline"));
        assert!(md.contains("## Root Cause"));
        assert!(md.contains("## Resolution"));
    }

    #[test]
    fn timeline_is_chronological() {
        let incident = make_incident(true);
        let earlier = Utc::now() - Duration::hours(1);
        let later = Utc::now() + Duration::hours(1);

        let health_checks = vec![
            TimelineEntry {
                timestamp: later,
                event: "Recovery probe passed".to_string(),
            },
            TimelineEntry {
                timestamp: earlier,
                event: "Last healthy check".to_string(),
            },
        ];

        let pm = PostMortem::generate(&incident, &health_checks);

        for pair in pm.timeline.windows(2) {
            assert!(pair[0].timestamp <= pair[1].timestamp);
        }
    }

    #[test]
    fn unresolved_incident_has_recommendation() {
        let incident = make_incident(false);
        let pm = PostMortem::generate(&incident, &[]);

        assert_eq!(pm.resolution, "Unresolved");
        assert!(pm.recommendations.iter().any(|r| r.contains("Investigate")));
    }

    #[test]
    fn recommendations_include_memory_advice() {
        let incident = make_incident(true);
        let pm = PostMortem::generate(&incident, &[]);

        assert!(pm.recommendations.iter().any(|r| r.contains("memory")));
    }
}
