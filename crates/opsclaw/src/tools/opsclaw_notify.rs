//! `opsclaw_notify` — the opsclaw-owned notification tool.
//!
//! The agent calls this when it confirms a problem worth alerting on.
//! It POSTs a structured payload to `[notifications].webhook_url`, so
//! an SRE receiving webhook on the other end can route/page as normal.
//!
//! Why this exists alongside zeroclaw's `escalate_to_human`: the
//! upstream tool routes via the channels orchestrator's channel-map
//! handle, which is not populated for heartbeat-worker agent runs
//! today (see CLAUDE.md → autonomous loop). Rather than patch the
//! runtime, we ship an opsclaw-owned tool that talks to the webhook
//! directly. If upstream later fixes the escalate path, both tools
//! can coexist — this one remains useful for SRE flows that don't
//! want to conflate operator chat with paging.

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsConfig;

pub struct OpsClawNotifyTool {
    webhook_url: Option<String>,
    bearer_token: Option<String>,
}

impl OpsClawNotifyTool {
    pub fn new(config: &OpsConfig) -> Self {
        let (webhook_url, bearer_token) = match config.notifications.as_ref() {
            Some(n) => (n.webhook_url.clone(), n.webhook_bearer_token.clone()),
            None => (None, None),
        };
        Self {
            webhook_url,
            bearer_token,
        }
    }
}

#[async_trait]
impl Tool for OpsClawNotifyTool {
    fn name(&self) -> &str {
        "opsclaw_notify"
    }

    fn description(&self) -> &str {
        "Send a structured alert about a confirmed problem. Call this when you \
         have investigated a suspected issue and are confident it warrants \
         human attention. Do NOT call this for speculation or for healthy \
         findings. Every call produces an outbound alert. Required fields: \
         summary (one-line), severity (info|warning|critical), category \
         (e.g. HighMemory, DiskFull, ServiceStopped, PortClosed, \
         ContainerDown, Unreachable). Optional: details (multi-line \
         context), target (which project the alert is about)."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "One-line summary of the problem (e.g. 'Memory on sim-target at 87%')"
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "warning", "critical"],
                    "description": "Severity; warning for degraded, critical for outages"
                },
                "category": {
                    "type": "string",
                    "description": "Short category like HighMemory, DiskFull, ServiceStopped"
                },
                "details": {
                    "type": "string",
                    "description": "Multi-line context: what you observed, which tools confirmed it"
                },
                "target": {
                    "type": "string",
                    "description": "Project name the alert is about"
                }
            },
            "required": ["summary", "severity", "category"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let Some(webhook_url) = self.webhook_url.as_deref() else {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    "opsclaw_notify: no [notifications].webhook_url configured; \
                     cannot send alert. Add one to your config."
                        .to_string(),
                ),
            });
        };

        let summary = match args.get("summary").and_then(|v| v.as_str()) {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing or empty 'summary'".into()),
                });
            }
        };

        let severity = args
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("warning")
            .to_lowercase();
        if !["info", "warning", "critical"].contains(&severity.as_str()) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Invalid 'severity' value: {severity}; expected info|warning|critical"
                )),
            });
        }

        let category = match args.get("category").and_then(|v| v.as_str()) {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing or empty 'category'".into()),
                });
            }
        };

        let details = args
            .get("details")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let payload = json!({
            "type": "opsclaw.alert",
            "summary": summary,
            "severity": severity,
            "category": category,
            "details": details,
            "target": target,
            // Cheap client-side timestamp; the sink also records its own.
            "sent_at": chrono::Utc::now().to_rfc3339(),
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let mut req = client.post(webhook_url).json(&payload);
        if let Some(token) = self.bearer_token.as_deref() {
            req = req.bearer_auth(token);
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    Ok(ToolResult {
                        success: true,
                        output: format!(
                            "Alert sent to {webhook_url} (status={status}, \
                             severity={severity}, category={category})"
                        ),
                        error: None,
                    })
                } else {
                    let body = resp.text().await.unwrap_or_default();
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Webhook rejected alert: {status} {body}")),
                    })
                }
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Webhook POST failed: {e}")),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_stable() {
        let tool = OpsClawNotifyTool {
            webhook_url: None,
            bearer_token: None,
        };
        assert_eq!(tool.name(), "opsclaw_notify");
    }

    #[test]
    fn schema_requires_summary_severity_category() {
        let tool = OpsClawNotifyTool {
            webhook_url: None,
            bearer_token: None,
        };
        let schema = tool.parameters_schema();
        let required = schema["required"].as_array().unwrap();
        let required: Vec<_> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required.contains(&"summary"));
        assert!(required.contains(&"severity"));
        assert!(required.contains(&"category"));
    }

    #[tokio::test]
    async fn missing_webhook_url_returns_structured_error() {
        let tool = OpsClawNotifyTool {
            webhook_url: None,
            bearer_token: None,
        };
        let r = tool
            .execute(json!({
                "summary": "test", "severity": "warning", "category": "Test"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("webhook_url"));
    }

    #[tokio::test]
    async fn missing_summary_returns_structured_error() {
        let tool = OpsClawNotifyTool {
            webhook_url: Some("http://example".into()),
            bearer_token: None,
        };
        let r = tool
            .execute(json!({"severity": "warning", "category": "Test"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().to_lowercase().contains("summary"));
    }

    #[tokio::test]
    async fn bad_severity_rejected() {
        let tool = OpsClawNotifyTool {
            webhook_url: Some("http://example".into()),
            bearer_token: None,
        };
        let r = tool
            .execute(json!({
                "summary": "x", "severity": "panic", "category": "X"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("severity"));
    }
}
