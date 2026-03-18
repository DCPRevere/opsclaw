//! Search past incidents for similar issues to provide context for LLM diagnosis.
//!
//! Loads incidents from JSONL files written by [`super::diagnosis::MonitoringAgent::record_incident`],
//! scores them by symptom overlap with current alerts, and formats matching incidents
//! as context for the LLM.

#[allow(unused_imports)]
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::tools::monitoring::Alert;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub incident_id: String,
    pub timestamp: DateTime<Utc>,
    pub target_name: String,
    pub severity: String,
    pub llm_assessment: String,
    pub suggested_actions: Vec<String>,
    pub symptoms: String,
    pub resolution: Option<String>,
}

/// A resolution record appended to the JSONL file to mark an incident as resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolutionRecord {
    incident_id: String,
    resolution: String,
    resolved_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// IncidentIndex
// ---------------------------------------------------------------------------

pub struct IncidentIndex {
    incidents: Vec<IncidentRecord>,
}

impl IncidentIndex {
    /// Load all incidents for a target from JSONL files under `~/.opsclaw/incidents/<target>/`.
    pub fn load(target_name: &str) -> Result<Self> {
        let dir = default_incident_dir().join(target_name);
        Self::load_from_dir(&dir)
    }

    /// Load incidents from a specific directory (useful for testing).
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let mut incidents = Vec::new();
        let mut resolutions: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        if !dir.exists() {
            return Ok(Self { incidents });
        }

        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read incident dir: {}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map_or(false, |ext| ext == "jsonl")
            })
            .collect();

        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let content = std::fs::read_to_string(entry.path())?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Try parsing as a resolution record first.
                if let Ok(res) = serde_json::from_str::<ResolutionRecord>(line) {
                    if res.resolution.is_empty() {
                        continue;
                    }
                    resolutions.insert(res.incident_id, res.resolution);
                    continue;
                }

                // Try parsing as a Diagnosis (the format written by record_incident).
                if let Ok(diag) = serde_json::from_str::<super::diagnosis::Diagnosis>(line) {
                    incidents.push(IncidentRecord {
                        incident_id: diag.incident_id,
                        timestamp: diag.timestamp,
                        target_name: diag.target_name,
                        severity: diag.severity.to_string(),
                        llm_assessment: diag.llm_assessment,
                        suggested_actions: diag.suggested_actions,
                        symptoms: diag.alerts_summary,
                        resolution: None,
                    });
                }
            }
        }

        // Apply resolutions.
        for incident in &mut incidents {
            if let Some(resolution) = resolutions.get(&incident.incident_id) {
                incident.resolution = Some(resolution.clone());
            }
        }

        Ok(Self { incidents })
    }

    /// Search for similar past incidents based on symptom/keyword matching with current alerts.
    pub fn search_similar(&self, current_alerts: &[Alert], max_results: usize) -> Vec<&IncidentRecord> {
        if self.incidents.is_empty() || current_alerts.is_empty() {
            return Vec::new();
        }

        let current_keywords = extract_keywords_from_alerts(current_alerts);
        let current_categories: HashSet<String> = current_alerts
            .iter()
            .map(|a| format!("{:?}", a.category))
            .collect();

        let mut scored: Vec<(&IncidentRecord, f64)> = self
            .incidents
            .iter()
            .map(|inc| {
                let score = score_incident(inc, &current_keywords, &current_categories);
                (inc, score)
            })
            .filter(|(_, score)| *score > 0.0)
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(max_results);
        scored.into_iter().map(|(inc, _)| inc).collect()
    }

    /// Format matching incidents as context for the LLM prompt.
    pub fn format_context(matches: &[&IncidentRecord]) -> String {
        if matches.is_empty() {
            return String::new();
        }

        let mut out = String::from("## Similar Past Incidents\n");

        for inc in matches {
            let date = inc.timestamp.format("%Y-%m-%d");
            out.push_str(&format!(
                "\n### {} (severity: {})\n",
                date,
                inc.severity.to_lowercase()
            ));
            out.push_str(&format!("Symptoms: {}\n", inc.symptoms));
            out.push_str(&format!("Diagnosis: {}\n", inc.llm_assessment));
            if !inc.suggested_actions.is_empty() {
                out.push_str(&format!("Actions taken: {}\n", inc.suggested_actions.join(", ")));
            }
            if let Some(ref resolution) = inc.resolution {
                out.push_str(&format!("Resolution: {}\n", resolution));
            }
        }

        out
    }

    /// Return a reference to all loaded incidents.
    pub fn incidents(&self) -> &[IncidentRecord] {
        &self.incidents
    }

    /// Search incidents by a free-text keyword query.
    pub fn search_by_keyword(&self, query: &str, max_results: usize) -> Vec<&IncidentRecord> {
        let keywords = extract_keywords(query);
        if keywords.is_empty() {
            return Vec::new();
        }

        let mut scored: Vec<(&IncidentRecord, f64)> = self
            .incidents
            .iter()
            .map(|inc| {
                let text = format!(
                    "{} {} {}",
                    inc.symptoms, inc.llm_assessment, inc.suggested_actions.join(" ")
                );
                let text_lower = text.to_lowercase();
                let score: f64 = keywords
                    .iter()
                    .filter(|kw| text_lower.contains(kw.as_str()))
                    .count() as f64;
                (inc, score)
            })
            .filter(|(_, score)| *score > 0.0)
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(max_results);
        scored.into_iter().map(|(inc, _)| inc).collect()
    }
}

// ---------------------------------------------------------------------------
// Resolution tracking
// ---------------------------------------------------------------------------

/// Mark an incident as resolved by appending a resolution record to the JSONL file.
pub fn mark_resolved(target_name: &str, incident_id: &str, resolution: &str) -> Result<()> {
    mark_resolved_in_dir(&default_incident_dir(), target_name, incident_id, resolution)
}

fn mark_resolved_in_dir(
    base_dir: &Path,
    target_name: &str,
    incident_id: &str,
    resolution: &str,
) -> Result<()> {
    let dir = base_dir.join(target_name);
    if !dir.exists() {
        anyhow::bail!("No incidents directory for target '{target_name}'");
    }

    // Verify the incident exists in some file.
    let found = find_incident_file(&dir, incident_id)?;
    if found.is_none() {
        anyhow::bail!("Incident '{incident_id}' not found for target '{target_name}'");
    }

    let record = ResolutionRecord {
        incident_id: incident_id.to_string(),
        resolution: resolution.to_string(),
        resolved_at: Utc::now(),
    };

    let line = serde_json::to_string(&record)?;
    let path = found.unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .with_context(|| format!("Failed to open {}", path.display()))?;
    use std::io::Write;
    writeln!(file, "{line}")?;

    Ok(())
}

fn find_incident_file(dir: &Path, incident_id: &str) -> Result<Option<PathBuf>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().map_or(true, |e| e != "jsonl") {
            continue;
        }
        let content = std::fs::read_to_string(entry.path())?;
        for line in content.lines() {
            if line.contains(incident_id) {
                return Ok(Some(entry.path()));
            }
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

fn extract_keywords_from_alerts(alerts: &[Alert]) -> HashSet<String> {
    let mut keywords = HashSet::new();
    for alert in alerts {
        keywords.extend(extract_keywords(&alert.message));
        keywords.insert(format!("{:?}", alert.category).to_lowercase());
    }
    keywords
}

fn extract_keywords(text: &str) -> HashSet<String> {
    let stop_words: HashSet<&str> = [
        "a", "an", "the", "is", "was", "are", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "shall", "can", "need", "dare", "ought",
        "used", "to", "of", "in", "for", "on", "with", "at", "by", "from",
        "as", "into", "through", "during", "before", "after", "above",
        "below", "between", "out", "off", "over", "under", "again",
        "further", "then", "once", "not", "no", "nor", "and", "but", "or",
        "so", "if", "it", "its", "that", "this", "than", "too", "very",
    ]
    .iter()
    .copied()
    .collect();

    text.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .map(|w| w.to_lowercase())
        .filter(|w| w.len() > 2 && !stop_words.contains(w.as_str()))
        .collect()
}

fn score_incident(
    incident: &IncidentRecord,
    current_keywords: &HashSet<String>,
    current_categories: &HashSet<String>,
) -> f64 {
    let incident_text = format!(
        "{} {} {}",
        incident.symptoms, incident.llm_assessment, incident.suggested_actions.join(" ")
    );
    let incident_keywords = extract_keywords(&incident_text);

    // Keyword overlap score.
    let overlap = current_keywords.intersection(&incident_keywords).count() as f64;
    if overlap == 0.0 {
        return 0.0;
    }

    let mut score = overlap;

    // Category match boost: check if incident symptoms mention a current category.
    let symptoms_lower = incident.symptoms.to_lowercase();
    for cat in current_categories {
        if symptoms_lower.contains(&cat.to_lowercase()) {
            score += 2.0;
        }
    }

    // Recency boost: incidents from the last 7 days get a small boost.
    let age_days = (Utc::now() - incident.timestamp).num_days();
    if age_days <= 7 {
        score += 1.0;
    }

    // Resolved incidents are slightly more valuable (known fix).
    if incident.resolution.is_some() {
        score += 1.5;
    }

    score
}

fn default_incident_dir() -> PathBuf {
    directories::UserDirs::new()
        .map(|u| u.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".opsclaw")
        .join("incidents")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivial_test() {
        assert_eq!(2 + 2, 4);
    }

    use crate::ops::diagnosis::{Diagnosis, DiagnosisSeverity};
    use crate::tools::monitoring::{AlertCategory, AlertSeverity, HealthStatus};

    fn make_test_diagnosis(id: &str, target: &str, summary: &str, assessment: &str) -> Diagnosis {
        Diagnosis {
            incident_id: id.to_string(),
            target_name: target.to_string(),
            timestamp: Utc::now(),
            health_status: HealthStatus::Critical,
            alerts_summary: summary.to_string(),
            llm_assessment: assessment.to_string(),
            suggested_actions: vec!["restart service".to_string()],
            severity: DiagnosisSeverity::Act,
        }
    }

    fn write_diagnosis_to_dir(dir: &Path, diag: &Diagnosis) {
        let path = dir.join(format!("{}.jsonl", diag.timestamp.format("%Y-%m-%d")));
        let line = serde_json::to_string(diag).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        use std::io::Write;
        writeln!(file, "{line}").unwrap();
    }

    #[test]
    fn load_incidents_from_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let target_dir = tmp.path().join("prod");
        std::fs::create_dir_all(&target_dir).unwrap();

        let diag = make_test_diagnosis(
            "inc-1",
            "prod",
            "- [CRIT] Container 'api' is down",
            "Container crashed due to OOM",
        );
        write_diagnosis_to_dir(&target_dir, &diag);

        let index = IncidentIndex::load_from_dir(&target_dir).unwrap();
        assert_eq!(index.incidents.len(), 1);
        assert_eq!(index.incidents[0].incident_id, "inc-1");
        assert_eq!(index.incidents[0].severity, "Act");
    }

    #[test]
    fn keyword_matching_similar_alerts_score_higher() {
        let tmp = tempfile::tempdir().unwrap();
        let target_dir = tmp.path().join("prod");
        std::fs::create_dir_all(&target_dir).unwrap();

        let similar = make_test_diagnosis(
            "inc-similar",
            "prod",
            "- [CRIT] Container 'api' is down",
            "Container api crashed due to OOM. Memory limit exceeded.",
        );
        let unrelated = make_test_diagnosis(
            "inc-unrelated",
            "prod",
            "- [WARN] Disk space low on /var",
            "Disk usage at 95%. Old logs consuming space.",
        );
        write_diagnosis_to_dir(&target_dir, &similar);
        write_diagnosis_to_dir(&target_dir, &unrelated);

        let index = IncidentIndex::load_from_dir(&target_dir).unwrap();

        let alerts = vec![Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "Container 'api' is down".to_string(),
        }];

        let results = index.search_similar(&alerts, 3);
        assert!(!results.is_empty());
        assert_eq!(results[0].incident_id, "inc-similar");
    }

    #[test]
    fn category_matching_boosts_score() {
        let tmp = tempfile::tempdir().unwrap();
        let target_dir = tmp.path().join("prod");
        std::fs::create_dir_all(&target_dir).unwrap();

        let with_category = make_test_diagnosis(
            "inc-cat",
            "prod",
            "- [CRIT] ContainerDown: service gone",
            "containerdown event detected for service",
        );
        let without_category = make_test_diagnosis(
            "inc-nocat",
            "prod",
            "- [WARN] service gone from list",
            "Service disappeared from the process list",
        );
        write_diagnosis_to_dir(&target_dir, &with_category);
        write_diagnosis_to_dir(&target_dir, &without_category);

        let index = IncidentIndex::load_from_dir(&target_dir).unwrap();

        let alerts = vec![Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "service gone".to_string(),
        }];

        let results = index.search_similar(&alerts, 3);
        assert!(results.len() >= 1);
        // The one with matching category text should rank first.
        assert_eq!(results[0].incident_id, "inc-cat");
    }

    #[test]
    fn format_context_produces_readable_output() {
        let record = IncidentRecord {
            incident_id: "inc-1".to_string(),
            timestamp: Utc::now(),
            target_name: "prod".to_string(),
            severity: "Warning".to_string(),
            llm_assessment: "Container crashed due to OOM".to_string(),
            suggested_actions: vec!["docker restart api".to_string(), "increase memory".to_string()],
            symptoms: "Container 'api' was missing, port 8080 gone".to_string(),
            resolution: Some("Resolved after restart".to_string()),
        };

        let context = IncidentIndex::format_context(&[&record]);
        assert!(context.contains("## Similar Past Incidents"));
        assert!(context.contains("severity: warning"));
        assert!(context.contains("Container crashed due to OOM"));
        assert!(context.contains("docker restart api"));
        assert!(context.contains("Resolved after restart"));
    }

    #[test]
    fn empty_index_returns_no_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let target_dir = tmp.path().join("empty");
        // Don't create the directory — simulates no incidents.

        let index = IncidentIndex::load_from_dir(&target_dir).unwrap();
        let alerts = vec![Alert {
            severity: AlertSeverity::Warning,
            category: AlertCategory::HighLoad,
            message: "Load is high".to_string(),
        }];
        let results = index.search_similar(&alerts, 3);
        assert!(results.is_empty());
    }

    #[test]
    fn mark_resolved_and_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let target_dir = tmp.path().join("prod");
        std::fs::create_dir_all(&target_dir).unwrap();

        let diag = make_test_diagnosis(
            "inc-resolve",
            "prod",
            "- [CRIT] down",
            "It broke",
        );
        write_diagnosis_to_dir(&target_dir, &diag);

        mark_resolved_in_dir(tmp.path(), "prod", "inc-resolve", "Fixed by restarting").unwrap();

        let index = IncidentIndex::load_from_dir(&target_dir).unwrap();
        assert_eq!(index.incidents.len(), 1);
        assert_eq!(
            index.incidents[0].resolution.as_deref(),
            Some("Fixed by restarting")
        );
    }

    #[test]
    fn search_by_keyword_finds_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let target_dir = tmp.path().join("prod");
        std::fs::create_dir_all(&target_dir).unwrap();

        let diag = make_test_diagnosis(
            "inc-kw",
            "prod",
            "- [CRIT] Container 'api' crashed",
            "OOM kill detected in container api",
        );
        write_diagnosis_to_dir(&target_dir, &diag);

        let index = IncidentIndex::load_from_dir(&target_dir).unwrap();
        let results = index.search_by_keyword("container crashed", 3);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].incident_id, "inc-kw");
    }

    #[test]
    fn search_by_keyword_no_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let target_dir = tmp.path().join("prod");
        std::fs::create_dir_all(&target_dir).unwrap();

        let diag = make_test_diagnosis("inc-1", "prod", "- [WARN] disk low", "Disk at 95%");
        write_diagnosis_to_dir(&target_dir, &diag);

        let index = IncidentIndex::load_from_dir(&target_dir).unwrap();
        let results = index.search_by_keyword("completely unrelated zebra", 3);
        assert!(results.is_empty());
    }
}
