//! PagerDuty tool. Read + write (acknowledge, resolve, add_note).
//!
//! Writes are gated by the configured autonomy level: DryRun returns a
//! "would do X" message without hitting the API. All actions — read and
//! write — pass through the OpsClaw audit log.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsClawAutonomy;
use crate::tools::ssh_tool::write_audit_entry;

const MAX_OUTPUT_BYTES: usize = 8 * 1024;
const PD_ACCEPT: &str = "application/vnd.pagerduty+json;version=2";

#[derive(Debug, Clone)]
pub struct PagerDutyToolConfig {
    pub api_key: String,
    pub default_service_id: Option<String>,
    pub default_from: Option<String>,
    pub autonomy: OpsClawAutonomy,
    pub api_base: String,
}

impl PagerDutyToolConfig {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            default_service_id: None,
            default_from: None,
            autonomy: OpsClawAutonomy::default(),
            api_base: "https://api.pagerduty.com".into(),
        }
    }
}

pub struct PagerDutyTool {
    config: PagerDutyToolConfig,
    client: reqwest::Client,
    audit_dir: Option<PathBuf>,
}

impl PagerDutyTool {
    pub fn new(config: PagerDutyToolConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            audit_dir: None,
        }
    }

    pub fn with_audit_dir(mut self, dir: PathBuf) -> Self {
        self.audit_dir = Some(dir);
        self
    }

    fn auth_header(&self) -> String {
        format!("Token token={}", self.config.api_key)
    }

    async fn get(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> reqwest::Result<reqwest::Response> {
        let url = format!("{}/{}", self.config.api_base.trim_end_matches('/'), path);
        self.client
            .get(&url)
            .header("Authorization", self.auth_header())
            .header("Accept", PD_ACCEPT)
            .query(params)
            .send()
            .await
    }

    async fn put(&self, path: &str, from: &str, body: Value) -> reqwest::Result<reqwest::Response> {
        let url = format!("{}/{}", self.config.api_base.trim_end_matches('/'), path);
        self.client
            .put(&url)
            .header("Authorization", self.auth_header())
            .header("Accept", PD_ACCEPT)
            .header("Content-Type", "application/json")
            .header("From", from)
            .json(&body)
            .send()
            .await
    }

    async fn post(
        &self,
        path: &str,
        from: &str,
        body: Value,
    ) -> reqwest::Result<reqwest::Response> {
        let url = format!("{}/{}", self.config.api_base.trim_end_matches('/'), path);
        self.client
            .post(&url)
            .header("Authorization", self.auth_header())
            .header("Accept", PD_ACCEPT)
            .header("Content-Type", "application/json")
            .header("From", from)
            .json(&body)
            .send()
            .await
    }

    fn audit(&self, action: &str, duration_ms: u128, exit: i32) {
        let _ = write_audit_entry(
            "pagerduty",
            action,
            exit,
            duration_ms,
            self.audit_dir.as_ref(),
        );
    }
}

#[async_trait]
impl Tool for PagerDutyTool {
    fn name(&self) -> &str {
        "pagerduty"
    }

    fn description(&self) -> &str {
        "PagerDuty tool. Actions: list_incidents, get_incident, on_call, \
         acknowledge, resolve, add_note. Writes respect the configured \
         autonomy — DryRun returns a 'would do X' message without calling \
         the API. Every action is audit-logged."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list_incidents", "get_incident", "on_call",
                             "acknowledge", "resolve", "add_note"]
                },
                "status": {"type": "string"},
                "service_id": {"type": "string"},
                "urgency": {"type": "string", "enum": ["high", "low"]},
                "limit": {"type": "integer", "default": 25},
                "incident_id": {"type": "string"},
                "incident_ids": {"type": "array", "items": {"type": "string"}},
                "schedule_id": {"type": "string"},
                "escalation_policy_id": {"type": "string"},
                "from": {"type": "string"},
                "content": {"type": "string"}
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("missing 'action'".into()),
                });
            }
        };

        let start = std::time::Instant::now();
        let result = match action {
            "list_incidents" => self.list_incidents(&args).await,
            "get_incident" => self.get_incident(&args).await,
            "on_call" => self.on_call(&args).await,
            "acknowledge" => self.incident_status_write(&args, "acknowledged").await,
            "resolve" => self.incident_status_write(&args, "resolved").await,
            "add_note" => self.add_note(&args).await,
            other => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("unknown action '{other}'")),
            }),
        };
        let elapsed = start.elapsed().as_millis();
        let exit = match &result {
            Ok(r) if r.success => 0,
            _ => 1,
        };
        self.audit(action, elapsed, exit);
        result
    }
}

impl PagerDutyTool {
    fn resolve_from<'a>(&'a self, args: &'a Value) -> Option<&'a str> {
        args.get("from")
            .and_then(|v| v.as_str())
            .or(self.config.default_from.as_deref())
    }

    async fn list_incidents(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let mut params: Vec<(&str, String)> = Vec::new();
        let default_status = "triggered,acknowledged".to_string();
        let status = args
            .get("status")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or(default_status);
        for s in status.split(',') {
            params.push(("statuses[]", s.trim().to_string()));
        }
        if let Some(sid) = args
            .get("service_id")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| self.config.default_service_id.clone())
        {
            params.push(("service_ids[]", sid));
        }
        if let Some(u) = args.get("urgency").and_then(|v| v.as_str()) {
            params.push(("urgencies[]", u.to_string()));
        }
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(25);
        params.push(("limit", limit.to_string()));

        let resp = match self.get("incidents", &params).await {
            Ok(r) => r,
            Err(e) => return http_err(format!("{e}")),
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return http_err(format!("{status}: {}", snippet(&text)));
        }
        let body: Value = serde_json::from_str(&text)?;
        let mut out = String::new();
        if let Some(arr) = body.get("incidents").and_then(|v| v.as_array()) {
            writeln!(out, "count: {}", arr.len()).ok();
            for inc in arr {
                let id = inc.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let st = inc.get("status").and_then(|v| v.as_str()).unwrap_or("");
                let urg = inc.get("urgency").and_then(|v| v.as_str()).unwrap_or("");
                let svc = inc
                    .get("service")
                    .and_then(|v| v.get("summary"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let title = inc.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let created = inc.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
                writeln!(out, "  {id} [{st}/{urg}] {svc} {created} — {title}").ok();
            }
        }
        Ok(ToolResult {
            success: true,
            output: truncate(out),
            error: None,
        })
    }

    async fn get_incident(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let id = match args.get("incident_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(param_err("missing 'incident_id'")),
        };
        let resp = match self.get(&format!("incidents/{id}"), &[]).await {
            Ok(r) => r,
            Err(e) => return http_err(format!("{e}")),
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return http_err(format!("{status}: {}", snippet(&text)));
        }
        let body: Value = serde_json::from_str(&text)?;
        let inc = body
            .get("incident")
            .cloned()
            .unwrap_or_else(|| body.clone());
        let mut out = String::new();
        let get = |k: &str| {
            inc.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        writeln!(out, "id: {}", get("id")).ok();
        writeln!(out, "status: {}", get("status")).ok();
        writeln!(out, "urgency: {}", get("urgency")).ok();
        writeln!(out, "title: {}", get("title")).ok();
        writeln!(out, "created_at: {}", get("created_at")).ok();
        if let Some(desc) = inc.get("description").and_then(|v| v.as_str()) {
            writeln!(out, "description: {desc}").ok();
        }
        Ok(ToolResult {
            success: true,
            output: truncate(out),
            error: None,
        })
    }

    async fn on_call(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(s) = args.get("schedule_id").and_then(|v| v.as_str()) {
            params.push(("schedule_ids[]", s.to_string()));
        }
        if let Some(p) = args.get("escalation_policy_id").and_then(|v| v.as_str()) {
            params.push(("escalation_policy_ids[]", p.to_string()));
        }
        if params.is_empty() {
            return Ok(param_err(
                "on_call requires 'schedule_id' or 'escalation_policy_id'",
            ));
        }
        let resp = match self.get("oncalls", &params).await {
            Ok(r) => r,
            Err(e) => return http_err(format!("{e}")),
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return http_err(format!("{status}: {}", snippet(&text)));
        }
        let body: Value = serde_json::from_str(&text)?;
        let mut out = String::new();
        if let Some(arr) = body.get("oncalls").and_then(|v| v.as_array()) {
            for item in arr {
                let name = item
                    .get("user")
                    .and_then(|v| v.get("summary"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let level = item
                    .get("escalation_level")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                writeln!(out, "  level={level} user={name}").ok();
            }
        }
        Ok(ToolResult {
            success: true,
            output: truncate(out),
            error: None,
        })
    }

    async fn incident_status_write(
        &self,
        args: &Value,
        new_status: &str,
    ) -> anyhow::Result<ToolResult> {
        let ids: Vec<String> =
            if let Some(arr) = args.get("incident_ids").and_then(|v| v.as_array()) {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            } else if let Some(id) = args.get("incident_id").and_then(|v| v.as_str()) {
                vec![id.to_string()]
            } else {
                return Ok(param_err("requires 'incident_id' or 'incident_ids'"));
            };

        let from = match self.resolve_from(args) {
            Some(s) => s.to_string(),
            None => return Ok(param_err("requires 'from' email (or default_from)")),
        };

        if self.config.autonomy == OpsClawAutonomy::DryRun {
            return Ok(ToolResult {
                success: true,
                output: format!(
                    "[dry-run] would set {} incidents to '{new_status}' (from={from}): {:?}",
                    ids.len(),
                    ids
                ),
                error: None,
            });
        }

        let body = json!({
            "incidents": ids.iter().map(|id| json!({
                "id": id,
                "type": "incident_reference",
                "status": new_status,
            })).collect::<Vec<_>>()
        });

        let resp = match self.put("incidents", &from, body).await {
            Ok(r) => r,
            Err(e) => return http_err(format!("{e}")),
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return http_err(format!("{status}: {}", snippet(&text)));
        }
        Ok(ToolResult {
            success: true,
            output: format!("set {} incidents to '{new_status}'", ids.len()),
            error: None,
        })
    }

    async fn add_note(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let id = match args.get("incident_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(param_err("missing 'incident_id'")),
        };
        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(param_err("missing 'content'")),
        };
        let from = match self.resolve_from(args) {
            Some(s) => s.to_string(),
            None => return Ok(param_err("requires 'from' email")),
        };
        if self.config.autonomy == OpsClawAutonomy::DryRun {
            return Ok(ToolResult {
                success: true,
                output: format!("[dry-run] would add note to {id}: {content}"),
                error: None,
            });
        }
        let body = json!({"note": {"content": content}});
        let resp = match self
            .post(&format!("incidents/{id}/notes"), &from, body)
            .await
        {
            Ok(r) => r,
            Err(e) => return http_err(format!("{e}")),
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return http_err(format!("{status}: {}", snippet(&text)));
        }
        Ok(ToolResult {
            success: true,
            output: format!("note added to {id}"),
            error: None,
        })
    }
}

fn snippet(s: &str) -> &str {
    &s[..s.len().min(500)]
}

fn http_err(msg: String) -> anyhow::Result<ToolResult> {
    Ok(ToolResult {
        success: false,
        output: String::new(),
        error: Some(msg),
    })
}

fn param_err(msg: &str) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(msg.into()),
    }
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_OUTPUT_BYTES {
        let mut cut = MAX_OUTPUT_BYTES;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n... [truncated]");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_tool(server: &MockServer, autonomy: OpsClawAutonomy) -> PagerDutyTool {
        let dir = tempfile::tempdir().unwrap();
        PagerDutyTool::new(PagerDutyToolConfig {
            api_key: "secret".into(),
            default_service_id: None,
            default_from: Some("me@example.com".into()),
            autonomy,
            api_base: server.uri(),
        })
        .with_audit_dir(dir.keep())
    }

    #[tokio::test]
    async fn list_incidents_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/incidents"))
            .and(header("authorization", "Token token=secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "incidents": [
                    {"id": "P1", "status": "triggered", "urgency": "high",
                     "service": {"summary": "web"}, "title": "500s",
                     "created_at": "2025-01-01T00:00:00Z"}
                ]
            })))
            .mount(&server)
            .await;
        let t = make_tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "list_incidents"}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("P1"));
        assert!(r.output.contains("500s"));
    }

    #[tokio::test]
    async fn get_incident_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/incidents/P1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "incident": {"id": "P1", "status": "triggered", "urgency": "high",
                             "title": "t", "created_at": "c"}
            })))
            .mount(&server)
            .await;
        let t = make_tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "get_incident", "incident_id": "P1"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.contains("id: P1"));
    }

    #[tokio::test]
    async fn acknowledge_success() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/incidents"))
            .and(header("from", "me@example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"incidents": []})))
            .mount(&server)
            .await;
        let t = make_tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "acknowledge", "incident_id": "P1"}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("acknowledged"));
    }

    #[tokio::test]
    async fn acknowledge_dry_run_skips_http() {
        let server = MockServer::start().await;
        let t = make_tool(&server, OpsClawAutonomy::DryRun);
        let r = t
            .execute(json!({"action": "acknowledge", "incident_id": "P1"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.starts_with("[dry-run]"));
        assert!(r.output.contains("acknowledged"));
    }

    #[tokio::test]
    async fn auth_failure_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/incidents"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "nope"})))
            .mount(&server)
            .await;
        let t = make_tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "list_incidents"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("401"));
    }

    #[tokio::test]
    async fn server_500_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/incidents"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let t = make_tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "list_incidents"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("500"));
    }

    #[tokio::test]
    async fn unknown_action_rejected() {
        let server = MockServer::start().await;
        let t = make_tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "rm_rf"})).await.unwrap();
        assert!(!r.success);
    }

    #[tokio::test]
    async fn acknowledge_requires_incident_id() {
        let server = MockServer::start().await;
        let t = make_tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "acknowledge"})).await.unwrap();
        assert!(!r.success);
    }
}
