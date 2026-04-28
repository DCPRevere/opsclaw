//! Cloudflare tool. Narrow SRE scope: zones, DNS records, firewall rules,
//! cache purge, rate-limit/WAF rule toggle, basic analytics.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsClawAutonomy;
use crate::tools::ssh_tool::write_audit_entry;

const MAX_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct CloudflareToolConfig {
    pub api_token: String,
    pub default_zone_id: Option<String>,
    pub default_account_id: Option<String>,
    pub autonomy: OpsClawAutonomy,
    pub api_base: String,
}

impl CloudflareToolConfig {
    pub fn new(api_token: String) -> Self {
        Self {
            api_token,
            default_zone_id: None,
            default_account_id: None,
            autonomy: OpsClawAutonomy::default(),
            api_base: "https://api.cloudflare.com".into(),
        }
    }
}

pub struct CloudflareTool {
    config: CloudflareToolConfig,
    client: reqwest::Client,
    audit_dir: Option<PathBuf>,
}

impl CloudflareTool {
    pub fn new(config: CloudflareToolConfig) -> Self {
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

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!(
            "{}/client/v4/{}",
            self.config.api_base.trim_end_matches('/'),
            path
        );
        self.client
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
    }

    fn resolve_zone(&self, args: &Value) -> Result<String, String> {
        args.get("zone_id")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| self.config.default_zone_id.clone())
            .ok_or_else(|| "missing 'zone_id' (no default_zone_id)".into())
    }

    fn is_dry_run(&self) -> bool {
        self.config.autonomy == OpsClawAutonomy::DryRun
    }

    fn audit(&self, action: &str, detail: &str, duration_ms: u128, exit: i32) {
        let _ = write_audit_entry(
            "cloudflare",
            &format!("{action} {detail}"),
            exit,
            duration_ms,
            self.audit_dir.as_ref(),
        );
    }
}

#[async_trait]
impl Tool for CloudflareTool {
    fn name(&self) -> &str {
        "cloudflare"
    }

    fn description(&self) -> &str {
        "Cloudflare tool. Reads: list_zones, list_dns, get_dns, \
         list_firewall_rules, list_rate_limits, zone_analytics. Writes: \
         create_dns, update_dns, delete_dns, purge_cache, \
         toggle_firewall_rule, toggle_rate_limit. Writes respect autonomy; \
         all actions audit-logged."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "zone_id": {"type": "string"},
                "record_id": {"type": "string"},
                "rule_id": {"type": "string"},
                "name": {"type": "string"},
                "type": {"type": "string"},
                "content": {"type": "string"},
                "ttl": {"type": "integer"},
                "proxied": {"type": "boolean"},
                "files": {"type": "array", "items": {"type": "string"}},
                "purge_everything": {"type": "boolean"},
                "enabled": {"type": "boolean"},
                "per_page": {"type": "integer", "default": 50}
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                return Ok(err("missing 'action'"));
            }
        };
        let start = std::time::Instant::now();
        let result = self.dispatch(&action, &args).await;
        let elapsed = start.elapsed().as_millis();
        let exit = match &result {
            Ok(r) if r.success => 0,
            _ => 1,
        };
        let detail = args
            .get("zone_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        self.audit(&action, &detail, elapsed, exit);
        result
    }
}

impl CloudflareTool {
    async fn dispatch(&self, action: &str, args: &Value) -> anyhow::Result<ToolResult> {
        match action {
            "list_zones" => self.list_zones(args).await,
            "list_dns" => self.list_dns(args).await,
            "get_dns" => self.get_dns(args).await,
            "list_firewall_rules" => self.list_firewall_rules(args).await,
            "list_rate_limits" => self.list_rate_limits(args).await,
            "zone_analytics" => self.zone_analytics(args).await,
            "create_dns" => self.create_dns(args).await,
            "update_dns" => self.update_dns(args).await,
            "delete_dns" => self.delete_dns(args).await,
            "purge_cache" => self.purge_cache(args).await,
            "toggle_firewall_rule" => self.toggle_rule(args, "firewall").await,
            "toggle_rate_limit" => self.toggle_rule(args, "rate_limit").await,
            other => Ok(err(format!("unknown action '{other}'"))),
        }
    }

    async fn list_zones(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let per_page = args
            .get("per_page")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .min(1000);
        let resp = self
            .req(reqwest::Method::GET, "zones")
            .query(&[("per_page", per_page.to_string())])
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(arr) = v.get("result").and_then(|v| v.as_array()) {
            writeln!(out, "count: {}", arr.len()).ok();
            for z in arr {
                let id = z.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let name = z.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let st = z.get("status").and_then(|v| v.as_str()).unwrap_or("");
                writeln!(out, "  {id} [{st}] {name}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn list_dns(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let per_page = args
            .get("per_page")
            .and_then(|v| v.as_u64())
            .unwrap_or(100)
            .min(5000);
        let mut q: Vec<(&str, String)> = vec![("per_page", per_page.to_string())];
        if let Some(t) = args.get("type").and_then(|v| v.as_str()) {
            q.push(("type", t.to_string()));
        }
        if let Some(n) = args.get("name").and_then(|v| v.as_str()) {
            q.push(("name", n.to_string()));
        }
        let path = format!("zones/{zone}/dns_records");
        let resp = self
            .req(reqwest::Method::GET, &path)
            .query(&q)
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(arr) = v.get("result").and_then(|v| v.as_array()) {
            writeln!(out, "count: {}", arr.len()).ok();
            for r in arr {
                let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let t = r.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let content = r.get("content").and_then(|v| v.as_str()).unwrap_or("");
                let proxied = r.get("proxied").and_then(|v| v.as_bool()).unwrap_or(false);
                writeln!(out, "  {id} {t} {name} → {content} proxied={proxied}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn get_dns(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let id = match args.get("record_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'record_id'")),
        };
        let path = format!("zones/{zone}/dns_records/{id}");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let r = v.get("result").cloned().unwrap_or(v);
        let mut out = String::new();
        for k in ["id", "type", "name", "content", "ttl", "proxied"] {
            if let Some(val) = r.get(k) {
                writeln!(out, "{k}: {val}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn list_firewall_rules(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        // Cloudflare's "rulesets" API replaces the older firewall_rules endpoint.
        let path = format!("zones/{zone}/rulesets/phases/http_request_firewall_custom/entrypoint");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(rules) = v
            .get("result")
            .and_then(|r| r.get("rules"))
            .and_then(|r| r.as_array())
        {
            writeln!(out, "count: {}", rules.len()).ok();
            for r in rules {
                let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let desc = r.get("description").and_then(|v| v.as_str()).unwrap_or("");
                let action = r.get("action").and_then(|v| v.as_str()).unwrap_or("");
                let enabled = r.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                writeln!(out, "  {id} [{action}] enabled={enabled} — {desc}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn list_rate_limits(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let path = format!("zones/{zone}/rulesets/phases/http_ratelimit/entrypoint");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(rules) = v
            .get("result")
            .and_then(|r| r.get("rules"))
            .and_then(|r| r.as_array())
        {
            writeln!(out, "count: {}", rules.len()).ok();
            for r in rules {
                let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let desc = r.get("description").and_then(|v| v.as_str()).unwrap_or("");
                let enabled = r.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                writeln!(out, "  {id} enabled={enabled} — {desc}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn zone_analytics(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let path = format!("zones/{zone}/analytics/dashboard");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let totals = v
            .get("result")
            .and_then(|r| r.get("totals"))
            .cloned()
            .unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(req) = totals.get("requests").and_then(|v| v.get("all")) {
            writeln!(out, "requests_all: {req}").ok();
        }
        if let Some(bw) = totals.get("bandwidth").and_then(|v| v.get("all")) {
            writeln!(out, "bandwidth_all: {bw}").ok();
        }
        if let Some(threats) = totals.get("threats").and_then(|v| v.get("all")) {
            writeln!(out, "threats_all: {threats}").ok();
        }
        if out.is_empty() {
            out = serde_json::to_string_pretty(&totals).unwrap_or_default();
        }
        Ok(ok_res(out))
    }

    async fn create_dns(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let type_ = match args.get("type").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'type'")),
        };
        let name = match args.get("name").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'name'")),
        };
        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'content'")),
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would create DNS {type_} {name} → {content} in zone {zone}"
            )));
        }
        let mut body = json!({"type": type_, "name": name, "content": content});
        if let Some(ttl) = args.get("ttl").and_then(|v| v.as_u64()) {
            body["ttl"] = json!(ttl);
        }
        if let Some(proxied) = args.get("proxied").and_then(|v| v.as_bool()) {
            body["proxied"] = json!(proxied);
        }
        let path = format!("zones/{zone}/dns_records");
        let resp = self
            .req(reqwest::Method::POST, &path)
            .json(&body)
            .send()
            .await?;
        let (ok, status, resp_body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&resp_body))));
        }
        Ok(ok_res(format!("created {type_} {name}")))
    }

    async fn update_dns(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let id = match args.get("record_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'record_id'")),
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would update DNS {id} in zone {zone}"
            )));
        }
        let mut body = serde_json::Map::new();
        for k in ["type", "name", "content"] {
            if let Some(v) = args.get(k).and_then(|v| v.as_str()) {
                body.insert(k.into(), json!(v));
            }
        }
        if let Some(ttl) = args.get("ttl").and_then(|v| v.as_u64()) {
            body.insert("ttl".into(), json!(ttl));
        }
        if let Some(pr) = args.get("proxied").and_then(|v| v.as_bool()) {
            body.insert("proxied".into(), json!(pr));
        }
        let path = format!("zones/{zone}/dns_records/{id}");
        let resp = self
            .req(reqwest::Method::PATCH, &path)
            .json(&Value::Object(body))
            .send()
            .await?;
        let (ok, status, resp_body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&resp_body))));
        }
        Ok(ok_res(format!("updated {id}")))
    }

    async fn delete_dns(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let id = match args.get("record_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'record_id'")),
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would delete DNS {id} in zone {zone}"
            )));
        }
        let path = format!("zones/{zone}/dns_records/{id}");
        let resp = self.req(reqwest::Method::DELETE, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        Ok(ok_res(format!("deleted {id}")))
    }

    async fn purge_cache(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let purge_everything = args
            .get("purge_everything")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let files: Vec<String> = args
            .get("files")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !purge_everything && files.is_empty() {
            return Ok(err(
                "purge_cache requires 'purge_everything' or non-empty 'files'",
            ));
        }
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would purge zone {zone} (everything={purge_everything}, {} files)",
                files.len()
            )));
        }
        let body = if purge_everything {
            json!({"purge_everything": true})
        } else {
            json!({"files": files})
        };
        let path = format!("zones/{zone}/purge_cache");
        let resp = self
            .req(reqwest::Method::POST, &path)
            .json(&body)
            .send()
            .await?;
        let (ok, status, resp_body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&resp_body))));
        }
        Ok(ok_res(format!("cache purged for zone {zone}")))
    }

    async fn toggle_rule(&self, args: &Value, kind: &str) -> anyhow::Result<ToolResult> {
        let zone = match self.resolve_zone(args) {
            Ok(z) => z,
            Err(e) => return Ok(err(e)),
        };
        let rule_id = match args.get("rule_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'rule_id'")),
        };
        let enabled = match args.get("enabled").and_then(|v| v.as_bool()) {
            Some(b) => b,
            None => return Ok(err("missing 'enabled' (bool)")),
        };
        let phase = if kind == "firewall" {
            "http_request_firewall_custom"
        } else {
            "http_ratelimit"
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would set {kind} rule {rule_id} enabled={enabled} in zone {zone}"
            )));
        }
        // PATCH the ruleset's rule.
        let path = format!("zones/{zone}/rulesets/phases/{phase}/entrypoint/rules/{rule_id}");
        let resp = self
            .req(reqwest::Method::PATCH, &path)
            .json(&json!({"enabled": enabled}))
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        Ok(ok_res(format!("{kind} rule {rule_id} enabled={enabled}")))
    }
}

async fn consume(resp: reqwest::Response) -> (bool, reqwest::StatusCode, String) {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (status.is_success(), status, text)
}

fn snippet(s: &str) -> &str {
    &s[..s.len().min(500)]
}

fn err<S: Into<String>>(msg: S) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(msg.into()),
    }
}

fn ok_res(mut s: String) -> ToolResult {
    if s.len() > MAX_OUTPUT_BYTES {
        let mut cut = MAX_OUTPUT_BYTES;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n... [truncated]");
    }
    ToolResult {
        success: true,
        output: s,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tool(server: &MockServer, autonomy: OpsClawAutonomy) -> CloudflareTool {
        let dir = tempfile::tempdir().unwrap();
        CloudflareTool::new(CloudflareToolConfig {
            api_token: "TOK".into(),
            default_zone_id: Some("Z1".into()),
            default_account_id: None,
            autonomy,
            api_base: server.uri(),
        })
        .with_audit_dir(dir.keep())
    }

    #[tokio::test]
    async fn list_dns_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/Z1/dns_records"))
            .and(header("authorization", "Bearer TOK"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [
                    {"id": "r1", "type": "A", "name": "foo.example.com",
                     "content": "1.2.3.4", "proxied": true}
                ]
            })))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "list_dns"})).await.unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("r1"));
        assert!(r.output.contains("1.2.3.4"));
    }

    #[tokio::test]
    async fn purge_everything() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/client/v4/zones/Z1/purge_cache"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "purge_cache", "purge_everything": true}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("purged"));
    }

    #[tokio::test]
    async fn purge_dry_run_skips_http() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::DryRun);
        let r = t
            .execute(json!({"action": "purge_cache", "purge_everything": true}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.starts_with("[dry-run]"));
    }

    #[tokio::test]
    async fn create_dns_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/client/v4/zones/Z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({
                "action": "create_dns", "type": "A",
                "name": "x.example.com", "content": "1.2.3.4"
            }))
            .await
            .unwrap();
        assert!(r.success);
    }

    #[tokio::test]
    async fn toggle_firewall_rule_requires_enabled() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "toggle_firewall_rule", "rule_id": "R1"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("enabled"));
    }

    #[tokio::test]
    async fn purge_requires_files_or_all() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "purge_cache"})).await.unwrap();
        assert!(!r.success);
    }

    #[tokio::test]
    async fn server_500_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "list_zones"})).await.unwrap();
        assert!(!r.success);
    }

    #[tokio::test]
    async fn unknown_action_rejected() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "nuke_internet"})).await.unwrap();
        assert!(!r.success);
    }

    #[tokio::test]
    async fn missing_action_rejected() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({})).await.unwrap();
        assert!(!r.success);
    }
}
