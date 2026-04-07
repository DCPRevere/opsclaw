//! LLM-driven diagnosis agent — takes a non-healthy [`HealthCheck`] and calls
//! an LLM to produce a structured [`Diagnosis`] with assessment, actions, and
//! severity. Incidents are persisted as JSONL files under `~/.opsclaw/incidents/`.

use crate::tools::monitoring::{AlertSeverity, HealthCheck, HealthStatus};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnosis {
    pub incident_id: String,
    pub target_name: String,
    pub timestamp: DateTime<Utc>,
    pub health_status: HealthStatus,
    pub alerts_summary: String,
    pub llm_assessment: String,
    pub suggested_actions: Vec<String>,
    pub severity: DiagnosisSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosisSeverity {
    Monitor,
    Investigate,
    Act,
}

impl std::fmt::Display for DiagnosisSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor => write!(f, "Monitor"),
            Self::Investigate => write!(f, "Investigate"),
            Self::Act => write!(f, "Act"),
        }
    }
}

// ---------------------------------------------------------------------------
// MonitoringAgent
// ---------------------------------------------------------------------------

pub struct MonitoringAgent {
    pub model: String,
    pub api_key: String,
    pub incident_log_dir: PathBuf,
    client: reqwest::Client,
}

impl MonitoringAgent {
    pub fn new(model: impl Into<String>, api_key: impl Into<String>) -> Self {
        let home = directories::UserDirs::new()
            .map(|u| u.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            model: model.into(),
            api_key: api_key.into(),
            incident_log_dir: home.join(".opsclaw").join("incidents"),
            client: reqwest::Client::new(),
        }
    }

    /// If health is Warning/Critical, call LLM to diagnose and return a [`Diagnosis`].
    /// Returns `None` when health is `Healthy`.
    pub async fn diagnose(
        &self,
        health: &HealthCheck,
        target_context: Option<&str>,
    ) -> Result<Option<Diagnosis>> {
        if health.status == HealthStatus::Healthy {
            return Ok(None);
        }

        let prompt = build_prompt(health, target_context);
        let llm_response = self.call_llm(&prompt).await?;
        let (assessment, actions, severity) = parse_llm_response(&llm_response);

        let diagnosis = Diagnosis {
            incident_id: uuid::Uuid::new_v4().to_string(),
            target_name: health.target_name.clone(),
            timestamp: Utc::now(),
            health_status: health.status.clone(),
            alerts_summary: alerts_to_bullets(health),
            llm_assessment: assessment,
            suggested_actions: actions,
            severity,
        };

        Ok(Some(diagnosis))
    }

    /// Append a [`Diagnosis`] to the incident log (JSONL file per target per day).
    pub fn record_incident(&self, diagnosis: &Diagnosis) -> Result<()> {
        let dir = self.incident_log_dir.join(&diagnosis.target_name);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create incident dir: {}", dir.display()))?;

        let date = diagnosis.timestamp.format("%Y-%m-%d");
        let path = dir.join(format!("{date}.jsonl"));

        let line = serde_json::to_string(diagnosis)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Failed to open incident log: {}", path.display()))?;
        writeln!(file, "{line}")?;

        Ok(())
    }

    /// Return the path where incident logs are stored for a given target + date.
    pub fn incident_log_path(&self, target_name: &str, date: &str) -> PathBuf {
        self.incident_log_dir
            .join(target_name)
            .join(format!("{date}.jsonl"))
    }

    // -----------------------------------------------------------------------
    // Private: LLM API call
    // -----------------------------------------------------------------------

    async fn call_llm(&self, prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 512,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        });

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to send request to Anthropic API")?;

        let status = resp.status();
        let resp_body: serde_json::Value = resp
            .json()
            .await
            .context("Failed to parse Anthropic API response")?;

        if !status.is_success() {
            let err_msg = resp_body["error"]["message"]
                .as_str()
                .unwrap_or("unknown error");
            anyhow::bail!("Anthropic API error ({}): {}", status, err_msg);
        }

        // Extract text from the first content block.
        let text = resp_body["content"]
            .as_array()
            .and_then(|blocks| blocks.first())
            .and_then(|block| block["text"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(text)
    }
}

// ---------------------------------------------------------------------------
// Prompt building
// ---------------------------------------------------------------------------

fn build_prompt(health: &HealthCheck, target_context: Option<&str>) -> String {
    let status_label = match health.status {
        HealthStatus::Healthy => "Healthy",
        HealthStatus::Warning => "Warning",
        HealthStatus::Critical => "Critical",
    };

    let bullets = alerts_to_bullets(health);

    let context_section = match target_context {
        Some(ctx) if !ctx.is_empty() => format!("\nAdditional context:\n{ctx}\n"),
        _ => String::new(),
    };

    format!(
        "You are OpsClaw, an AI SRE monitoring agent.\n\
         \n\
         Target: {}\n\
         Status: {} — {} alerts\n\
         \n\
         Alerts:\n\
         {}\n\
         {}\n\
         Diagnose this situation concisely:\n\
         1. What is likely wrong?\n\
         2. What should be checked or done?\n\
         3. Severity: Monitor / Investigate / Act\n\
         \n\
         Reply in this format:\n\
         ASSESSMENT: <one-paragraph assessment>\n\
         ACTIONS:\n\
         - <action 1>\n\
         - <action 2>\n\
         SEVERITY: <Monitor|Investigate|Act>",
        health.target_name,
        status_label,
        health.alerts.len(),
        bullets,
        context_section,
    )
}

fn alerts_to_bullets(health: &HealthCheck) -> String {
    health
        .alerts
        .iter()
        .map(|a| {
            let sev = match a.severity {
                AlertSeverity::Info => "INFO",
                AlertSeverity::Warning => "WARN",
                AlertSeverity::Critical => "CRIT",
            };
            format!("- [{sev}] {}", a.message)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

fn parse_llm_response(text: &str) -> (String, Vec<String>, DiagnosisSeverity) {
    let assessment = extract_after(text, "ASSESSMENT:").unwrap_or_else(|| text.to_string());

    let actions = extract_actions(text);

    let severity = extract_after(text, "SEVERITY:")
        .map(|s| match s.trim() {
            "Act" => DiagnosisSeverity::Act,
            "Investigate" => DiagnosisSeverity::Investigate,
            _ => DiagnosisSeverity::Monitor,
        })
        .unwrap_or(DiagnosisSeverity::Investigate);

    (assessment, actions, severity)
}

/// Extract text after a label up to the next known label or end of string.
fn extract_after(text: &str, label: &str) -> Option<String> {
    let start = text.find(label)?;
    let after = &text[start + label.len()..];

    // Stop at the next known section header.
    let end = ["ASSESSMENT:", "ACTIONS:", "SEVERITY:"]
        .iter()
        .filter(|&&l| l != label)
        .filter_map(|l| after.find(l))
        .min()
        .unwrap_or(after.len());

    let value = after[..end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Parse action lines (lines starting with `- `) from the ACTIONS section.
fn extract_actions(text: &str) -> Vec<String> {
    let Some(start) = text.find("ACTIONS:") else {
        return vec![];
    };
    let after = &text[start + "ACTIONS:".len()..];

    // Stop at SEVERITY: if present.
    let end = after.find("SEVERITY:").unwrap_or(after.len());
    let section = &after[..end];

    section
        .lines()
        .map(|l| l.trim())
        .filter(|l| l.starts_with("- "))
        .map(|l| l[2..].trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::monitoring::{
        Alert, AlertCategory, AlertSeverity, HealthCheck, HealthStatus,
    };

    #[test]
    fn parse_well_formed_response() {
        let text = "\
ASSESSMENT: The container sacra-api has restarted multiple times, likely due to OOM.
ACTIONS:
- Check container logs for OOM kills
- Inspect memory limits in docker-compose
- Review recent deployments for memory regression
SEVERITY: Act";

        let (assessment, actions, severity) = parse_llm_response(text);
        assert!(assessment.contains("sacra-api"));
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0], "Check container logs for OOM kills");
        assert_eq!(severity, DiagnosisSeverity::Act);
    }

    #[test]
    fn parse_missing_sections_falls_back() {
        let text = "Something went wrong, not sure what.";
        let (assessment, actions, severity) = parse_llm_response(text);
        assert_eq!(assessment, text);
        assert!(actions.is_empty());
        assert_eq!(severity, DiagnosisSeverity::Investigate);
    }

    #[test]
    fn parse_severity_monitor() {
        let text = "ASSESSMENT: Minor issue.\nACTIONS:\n- Watch it\nSEVERITY: Monitor";
        let (_, _, severity) = parse_llm_response(text);
        assert_eq!(severity, DiagnosisSeverity::Monitor);
    }

    #[test]
    fn alerts_to_bullets_format() {
        let hc = HealthCheck {
            target_name: "test".into(),
            checked_at: Utc::now(),
            status: HealthStatus::Warning,
            alerts: vec![Alert {
                severity: AlertSeverity::Warning,
                category: AlertCategory::HighLoad,
                message: "Load is high".into(),
            }],
        };
        let bullets = alerts_to_bullets(&hc);
        assert_eq!(bullets, "- [WARN] Load is high");
    }

    #[test]
    fn build_prompt_includes_target_and_alerts() {
        let hc = HealthCheck {
            target_name: "prod-web-1".into(),
            checked_at: Utc::now(),
            status: HealthStatus::Critical,
            alerts: vec![Alert {
                severity: AlertSeverity::Critical,
                category: AlertCategory::ContainerDown,
                message: "Container 'api' is down".into(),
            }],
        };
        let prompt = build_prompt(&hc, Some("Custom context info"));
        assert!(prompt.contains("prod-web-1"));
        assert!(prompt.contains("Critical"));
        assert!(prompt.contains("Container 'api' is down"));
        assert!(prompt.contains("Custom context info"));
    }

    #[test]
    fn build_prompt_no_context() {
        let hc = HealthCheck {
            target_name: "t1".into(),
            checked_at: Utc::now(),
            status: HealthStatus::Warning,
            alerts: vec![],
        };
        let prompt = build_prompt(&hc, None);
        assert!(!prompt.contains("Additional context"));
    }

    #[test]
    fn record_incident_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let agent = MonitoringAgent {
            model: "test".into(),
            api_key: "test".into(),
            incident_log_dir: dir.path().to_path_buf(),
            client: reqwest::Client::new(),
        };

        let diag = Diagnosis {
            incident_id: "abc-123".into(),
            target_name: "prod".into(),
            timestamp: Utc::now(),
            health_status: HealthStatus::Critical,
            alerts_summary: "- [CRIT] down".into(),
            llm_assessment: "It's broken".into(),
            suggested_actions: vec!["fix it".into()],
            severity: DiagnosisSeverity::Act,
        };

        agent.record_incident(&diag).unwrap();

        let date = diag.timestamp.format("%Y-%m-%d").to_string();
        let path = agent.incident_log_path("prod", &date);
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: Diagnosis = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.incident_id, "abc-123");
        assert_eq!(parsed.severity, DiagnosisSeverity::Act);
    }

    #[test]
    fn healthy_check_returns_none() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let agent = MonitoringAgent::new("test", "test");
        let hc = HealthCheck {
            target_name: "t".into(),
            checked_at: Utc::now(),
            status: HealthStatus::Healthy,
            alerts: vec![],
        };
        let result = rt.block_on(agent.diagnose(&hc, None)).unwrap();
        assert!(result.is_none());
    }
}
