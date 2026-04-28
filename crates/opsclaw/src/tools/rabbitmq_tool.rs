//! RabbitMQ management API tool (not AMQP).
//!
//! Read-write: list overviews, queues, bindings; get queue; peek messages
//! non-destructively (ack_requeue_true); publish; purge; delete queues;
//! create/delete bindings. Writes gated by autonomy + audit-logged.

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
pub struct RabbitMqToolConfig {
    /// Management API base, e.g. http://rabbit.example.com:15672
    pub api_base: String,
    pub username: String,
    pub password: String,
    pub autonomy: OpsClawAutonomy,
    pub default_vhost: String,
}

impl RabbitMqToolConfig {
    pub fn new(api_base: String, username: String, password: String) -> Self {
        Self {
            api_base,
            username,
            password,
            autonomy: OpsClawAutonomy::default(),
            default_vhost: "/".into(),
        }
    }
}

pub struct RabbitMqTool {
    config: RabbitMqToolConfig,
    client: reqwest::Client,
    audit_dir: Option<PathBuf>,
}

impl RabbitMqTool {
    pub fn new(config: RabbitMqToolConfig) -> Self {
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
            "{}/api/{}",
            self.config.api_base.trim_end_matches('/'),
            path
        );
        self.client
            .request(method, &url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .header("Content-Type", "application/json")
    }

    fn resolve_vhost<'a>(&'a self, args: &'a Value) -> String {
        args.get("vhost")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| self.config.default_vhost.clone())
    }

    fn is_dry_run(&self) -> bool {
        self.config.autonomy == OpsClawAutonomy::DryRun
    }

    fn audit(&self, action: &str, detail: &str, duration_ms: u128, exit: i32) {
        let _ = write_audit_entry(
            "rabbitmq",
            &format!("{action} {detail}"),
            exit,
            duration_ms,
            self.audit_dir.as_ref(),
        );
    }
}

#[async_trait]
impl Tool for RabbitMqTool {
    fn name(&self) -> &str {
        "rabbitmq"
    }

    fn description(&self) -> &str {
        "RabbitMQ management API. Reads: overview, list_queues, get_queue, \
         list_bindings, list_exchanges, peek (non-destructive get). Writes: \
         publish, purge_queue, delete_queue, create_binding, delete_binding. \
         Writes respect autonomy and are audit-logged."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "vhost": {"type": "string"},
                "queue": {"type": "string"},
                "exchange": {"type": "string"},
                "routing_key": {"type": "string"},
                "destination": {"type": "string"},
                "destination_type": {"type": "string", "enum": ["queue", "exchange"]},
                "count": {"type": "integer", "default": 10},
                "payload": {"type": "string"}
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(err("missing 'action'")),
        };
        let start = std::time::Instant::now();
        let result = self.dispatch(&action, &args).await;
        let elapsed = start.elapsed().as_millis();
        let exit = match &result {
            Ok(r) if r.success => 0,
            _ => 1,
        };
        let detail = args
            .get("queue")
            .or_else(|| args.get("exchange"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        self.audit(&action, &detail, elapsed, exit);
        result
    }
}

impl RabbitMqTool {
    async fn dispatch(&self, action: &str, args: &Value) -> anyhow::Result<ToolResult> {
        match action {
            "overview" => self.overview().await,
            "list_queues" => self.list_queues(args).await,
            "get_queue" => self.get_queue(args).await,
            "list_bindings" => self.list_bindings(args).await,
            "list_exchanges" => self.list_exchanges(args).await,
            "peek" => self.peek(args).await,
            "publish" => self.publish(args).await,
            "purge_queue" => self.purge_queue(args).await,
            "delete_queue" => self.delete_queue(args).await,
            "create_binding" => self.create_binding(args).await,
            "delete_binding" => self.delete_binding(args).await,
            other => Ok(err(format!("unknown action '{other}'"))),
        }
    }

    async fn overview(&self) -> anyhow::Result<ToolResult> {
        let resp = self.req(reqwest::Method::GET, "overview").send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(n) = v.get("rabbitmq_version").and_then(|v| v.as_str()) {
            writeln!(out, "rabbitmq_version: {n}").ok();
        }
        if let Some(cluster) = v.get("cluster_name").and_then(|v| v.as_str()) {
            writeln!(out, "cluster: {cluster}").ok();
        }
        for key in ["queue_totals", "message_stats", "object_totals"] {
            if let Some(sub) = v.get(key) {
                writeln!(out, "{key}: {sub}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn list_queues(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let path = format!("queues/{vhost}");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(qs) = arr.as_array() {
            writeln!(out, "count: {}", qs.len()).ok();
            writeln!(out, "NAME\tREADY\tUNACKED\tCONSUMERS\tSTATE").ok();
            for q in qs {
                let name = q.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let ready = q
                    .get("messages_ready")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let unacked = q
                    .get("messages_unacknowledged")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let consumers = q.get("consumers").and_then(|v| v.as_u64()).unwrap_or(0);
                let state = q.get("state").and_then(|v| v.as_str()).unwrap_or("");
                writeln!(out, "{name}\t{ready}\t{unacked}\t{consumers}\t{state}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn get_queue(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let queue = match args.get("queue").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'queue'")),
        };
        let path = format!("queues/{vhost}/{}", urlencode(queue));
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        for k in [
            "name",
            "state",
            "messages",
            "messages_ready",
            "messages_unacknowledged",
            "consumers",
            "memory",
        ] {
            if let Some(val) = v.get(k) {
                writeln!(out, "{k}: {val}").ok();
            }
        }
        if let Some(rates) = v.get("message_stats") {
            writeln!(out, "message_stats: {rates}").ok();
        }
        Ok(ok_res(out))
    }

    async fn list_bindings(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let path = if let Some(q) = args.get("queue").and_then(|v| v.as_str()) {
            format!("queues/{vhost}/{}/bindings", urlencode(q))
        } else if let Some(e) = args.get("exchange").and_then(|v| v.as_str()) {
            format!("exchanges/{vhost}/{}/bindings/source", urlencode(e))
        } else {
            format!("bindings/{vhost}")
        };
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(bs) = arr.as_array() {
            writeln!(out, "count: {}", bs.len()).ok();
            for b in bs {
                let src = b.get("source").and_then(|v| v.as_str()).unwrap_or("");
                let dest = b.get("destination").and_then(|v| v.as_str()).unwrap_or("");
                let dtype = b
                    .get("destination_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let rk = b.get("routing_key").and_then(|v| v.as_str()).unwrap_or("");
                writeln!(out, "  {src} → {dest}({dtype}) rk={rk}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn list_exchanges(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let path = format!("exchanges/{vhost}");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(es) = arr.as_array() {
            writeln!(out, "count: {}", es.len()).ok();
            for e in es {
                let name = e
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(default)");
                let t = e.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let durable = e.get("durable").and_then(|v| v.as_bool()).unwrap_or(false);
                writeln!(out, "  {name} [{t}] durable={durable}").ok();
            }
        }
        Ok(ok_res(out))
    }

    /// Non-destructive peek via `ackmode=ack_requeue_true`.
    async fn peek(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let queue = match args.get("queue").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'queue'")),
        };
        let count = args.get("count").and_then(|v| v.as_u64()).unwrap_or(10);
        let path = format!("queues/{vhost}/{}/get", urlencode(queue));
        let body = json!({
            "count": count,
            "ackmode": "ack_requeue_true",
            "encoding": "auto",
            "truncate": 50000
        });
        let resp = self
            .req(reqwest::Method::POST, &path)
            .json(&body)
            .send()
            .await?;
        let (ok, status, resp_body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&resp_body))));
        }
        let arr: Value = serde_json::from_str(&resp_body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(msgs) = arr.as_array() {
            writeln!(out, "peeked: {}", msgs.len()).ok();
            for m in msgs {
                let rk = m.get("routing_key").and_then(|v| v.as_str()).unwrap_or("");
                let redelivered = m
                    .get("redelivered")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let payload = m.get("payload").and_then(|v| v.as_str()).unwrap_or("");
                let pl_short: String = payload.chars().take(200).collect();
                writeln!(
                    out,
                    "  rk={rk} redelivered={redelivered} payload={pl_short}"
                )
                .ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn publish(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let exchange = args.get("exchange").and_then(|v| v.as_str()).unwrap_or(""); // "" = default exchange
        let routing_key = match args.get("routing_key").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(err("missing 'routing_key'")),
        };
        let payload = match args.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(err("missing 'payload'")),
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would publish to exchange='{exchange}' rk='{routing_key}' ({} bytes)",
                payload.len()
            )));
        }
        let path = format!("exchanges/{vhost}/{}/publish", urlencode(exchange));
        let body = json!({
            "properties": {},
            "routing_key": routing_key,
            "payload": payload,
            "payload_encoding": "string"
        });
        let resp = self
            .req(reqwest::Method::POST, &path)
            .json(&body)
            .send()
            .await?;
        let (ok, status, resp_body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&resp_body))));
        }
        let v: Value = serde_json::from_str(&resp_body).unwrap_or(Value::Null);
        let routed = v.get("routed").and_then(|v| v.as_bool()).unwrap_or(false);
        Ok(ok_res(format!("published; routed={routed}")))
    }

    async fn purge_queue(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let queue = match args.get("queue").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(err("missing 'queue'")),
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!("[dry-run] would purge queue '{queue}'")));
        }
        let path = format!("queues/{vhost}/{}/contents", urlencode(&queue));
        let resp = self.req(reqwest::Method::DELETE, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        Ok(ok_res(format!("queue '{queue}' purged")))
    }

    async fn delete_queue(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let queue = match args.get("queue").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(err("missing 'queue'")),
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!("[dry-run] would delete queue '{queue}'")));
        }
        let path = format!("queues/{vhost}/{}", urlencode(&queue));
        let resp = self.req(reqwest::Method::DELETE, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        Ok(ok_res(format!("queue '{queue}' deleted")))
    }

    async fn create_binding(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let exchange = match args.get("exchange").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(err("missing 'exchange'")),
        };
        let destination = match args.get("destination").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(err("missing 'destination'")),
        };
        let dtype = args
            .get("destination_type")
            .and_then(|v| v.as_str())
            .unwrap_or("queue");
        if dtype != "queue" && dtype != "exchange" {
            return Ok(err("destination_type must be 'queue' or 'exchange'"));
        }
        let routing_key = args
            .get("routing_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would bind {exchange} → {destination}({dtype}) rk='{routing_key}'"
            )));
        }
        let seg = if dtype == "queue" { "q" } else { "e" };
        let path = format!(
            "bindings/{vhost}/e/{}/{seg}/{}",
            urlencode(&exchange),
            urlencode(&destination)
        );
        let body = json!({"routing_key": routing_key, "arguments": {}});
        let resp = self
            .req(reqwest::Method::POST, &path)
            .json(&body)
            .send()
            .await?;
        let (ok, status, resp_body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&resp_body))));
        }
        Ok(ok_res(format!("bound {exchange} → {destination}({dtype})")))
    }

    async fn delete_binding(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let vhost = encode_vhost(&self.resolve_vhost(args));
        let exchange = match args.get("exchange").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(err("missing 'exchange'")),
        };
        let destination = match args.get("destination").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(err("missing 'destination'")),
        };
        let dtype = args
            .get("destination_type")
            .and_then(|v| v.as_str())
            .unwrap_or("queue");
        let routing_key = args
            .get("routing_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would delete binding {exchange} → {destination}({dtype}) rk='{routing_key}'"
            )));
        }
        let seg = if dtype == "queue" { "q" } else { "e" };
        // The binding's `props_key` segment — RabbitMQ encodes the routing
        // key as `<rk>` when unambiguous, or `~` for empty. We use the
        // routing key as-is; if you need exact matching for complex keys,
        // fetch the binding first.
        let prop = if routing_key.is_empty() {
            "~"
        } else {
            routing_key
        };
        let path = format!(
            "bindings/{vhost}/e/{}/{seg}/{}/{}",
            urlencode(&exchange),
            urlencode(&destination),
            urlencode(prop)
        );
        let resp = self.req(reqwest::Method::DELETE, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        Ok(ok_res("binding deleted".into()))
    }
}

/// RabbitMQ encodes the default vhost `/` as `%2F` in URLs. Everything else
/// passes through URL encoding.
fn encode_vhost(v: &str) -> String {
    urlencode(v)
}

fn urlencode(s: &str) -> String {
    // Minimal encoder — covers `/`, space, and reserved chars that appear
    // in queue/exchange names.
    let mut out = String::with_capacity(s.len());
    for c in s.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            }
            _ => {
                write!(out, "%{:02X}", c).ok();
            }
        }
    }
    out
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

    fn tool(server: &MockServer, autonomy: OpsClawAutonomy) -> RabbitMqTool {
        let dir = tempfile::tempdir().unwrap();
        RabbitMqTool::new(RabbitMqToolConfig {
            api_base: server.uri(),
            username: "guest".into(),
            password: "guest".into(),
            autonomy,
            default_vhost: "/".into(),
        })
        .with_audit_dir(dir.keep())
    }

    #[test]
    fn encode_default_vhost() {
        assert_eq!(encode_vhost("/"), "%2F");
        assert_eq!(encode_vhost("test"), "test");
    }

    #[tokio::test]
    async fn list_queues_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/queues/%2F"))
            .and(header("authorization", "Basic Z3Vlc3Q6Z3Vlc3Q="))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"name": "q1", "messages_ready": 5, "messages_unacknowledged": 0,
                 "consumers": 1, "state": "running"}
            ])))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "list_queues"})).await.unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("q1"));
        assert!(r.output.contains("running"));
    }

    #[tokio::test]
    async fn peek_is_non_destructive() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/queues/%2F/q1/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"routing_key": "rk", "redelivered": false, "payload": "hello"}
            ])))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "peek", "queue": "q1"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.contains("peeked: 1"));
        assert!(r.output.contains("payload=hello"));
    }

    #[tokio::test]
    async fn publish_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/exchanges/%2F//publish"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"routed": true})))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({
                "action": "publish", "routing_key": "task.q",
                "payload": "hi"
            }))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("routed=true"));
    }

    #[tokio::test]
    async fn purge_dry_run_skips_http() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::DryRun);
        let r = t
            .execute(json!({"action": "purge_queue", "queue": "q1"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.starts_with("[dry-run]"));
    }

    #[tokio::test]
    async fn overview_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/overview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rabbitmq_version": "3.13.0",
                "cluster_name": "c1"
            })))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "overview"})).await.unwrap();
        assert!(r.success);
        assert!(r.output.contains("3.13.0"));
        assert!(r.output.contains("cluster: c1"));
    }

    #[tokio::test]
    async fn auth_failure_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/queues/%2F"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "list_queues"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("401"));
    }

    #[tokio::test]
    async fn server_500_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/queues/%2F"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "list_queues"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("500"));
    }

    #[tokio::test]
    async fn unknown_action_rejected() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "nuke"})).await.unwrap();
        assert!(!r.success);
    }

    #[tokio::test]
    async fn publish_dry_run_skips_http() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::DryRun);
        let r = t
            .execute(json!({
                "action": "publish", "exchange": "ex", "routing_key": "rk",
                "payload": "hello"
            }))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.starts_with("[dry-run]"));
    }
}
