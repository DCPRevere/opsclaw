//! PostHog tool. Read-only v1.
//!
//! Surfaces product-analytics signal that closes the loop between an
//! infra-side alert and what users are actually experiencing:
//!
//! - did the error event spike around the time the alert fired?
//! - which feature flag was just rolled out?
//! - what was *this specific user* doing when they reported the bug?
//!
//! Six actions, all GET/POST against the public PostHog API:
//!
//! - `query_events`         — count + sample for one event in a time window.
//! - `recent_flag_changes`  — flags modified in the last N hours.
//! - `flag_status`          — one flag: rollout %, recent metadata.
//! - `events_for_user`      — last N events for a `distinct_id`.
//! - `session_replay_url`   — most recent replay URL for a `distinct_id`.
//! - `hogql`                — escape hatch for HogQL/ClickHouse queries.
//!
//! All actions are read-only; no write surface in v1.
//! See `docs/tools/posthog.md` for the user-facing summary.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsClawAutonomy;
use crate::tools::ssh_tool::write_audit_entry;

const MAX_OUTPUT_BYTES: usize = 16 * 1024;
/// Default cap on number of events surfaced per query. Without this, a
/// careless agent can pull millions of rows on a wide HogQL query and spend
/// real money on PostHog egress.
const DEFAULT_LIMIT: u64 = 200;
/// Hard ceiling — the agent can ask for up to this many; anything higher is
/// silently clamped.
const MAX_LIMIT: u64 = 5_000;
/// Default time window when the agent doesn't specify one. SRE questions are
/// almost always "since the alert fired" which is rarely longer than an hour.
const DEFAULT_SINCE: &str = "-1h";

#[derive(Debug, Clone)]
pub struct PostHogToolConfig {
    pub api_key: String,
    pub project_id: String,
    pub host: String,
    /// Reserved for v2 (write actions). v1 is read-only.
    pub autonomy: OpsClawAutonomy,
}

impl PostHogToolConfig {
    pub fn new(api_key: String, project_id: String, host: String) -> Self {
        Self {
            api_key,
            project_id,
            host,
            autonomy: OpsClawAutonomy::default(),
        }
    }
}

pub struct PostHogTool {
    config: PostHogToolConfig,
    client: reqwest::Client,
    audit_dir: Option<PathBuf>,
}

impl PostHogTool {
    pub fn new(config: PostHogToolConfig) -> Self {
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
            "{}/api/projects/{}/{}",
            self.config.host.trim_end_matches('/'),
            self.config.project_id,
            path.trim_start_matches('/')
        );
        self.client
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
    }

    fn audit(&self, action: &str, detail: &str, duration_ms: u128, exit: i32) {
        let _ = write_audit_entry(
            "posthog",
            &format!("{action} {detail}"),
            exit,
            duration_ms,
            self.audit_dir.as_ref(),
        );
    }
}

#[async_trait]
impl Tool for PostHogTool {
    fn name(&self) -> &str {
        "posthog"
    }

    fn description(&self) -> &str {
        "PostHog tool. Read-only product-analytics queries to enrich an SRE \
         alert with user-facing signal: event spikes, recent feature-flag \
         rollouts, per-user activity, session replays. Actions: \
         query_events, recent_flag_changes, flag_status, events_for_user, \
         session_replay_url, hogql. Use when an alert points at user-facing \
         behaviour and the infra-side tools (logs/traces) don't explain it."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "query_events", "recent_flag_changes", "flag_status",
                        "events_for_user", "session_replay_url", "hogql"
                    ]
                },
                "event_name":   {"type": "string", "description": "for query_events"},
                "since":        {"type": "string", "description": "ISO-8601 or relative like '-1h', '-30m'. Default '-1h'."},
                "until":        {"type": "string", "description": "ISO-8601 or 'now'. Default 'now'."},
                "filters":      {"type": "object", "description": "for query_events; equality filters on event properties"},
                "flag_key":     {"type": "string", "description": "for flag_status"},
                "active_only":  {"type": "boolean", "description": "for recent_flag_changes; default true"},
                "hours":        {"type": "integer", "description": "for recent_flag_changes; default 24"},
                "distinct_id":  {"type": "string", "description": "for events_for_user, session_replay_url"},
                "limit":        {"type": "integer", "description": "max rows; default 200, clamped to 5000"},
                "query":        {"type": "string", "description": "for hogql; raw HogQL query"}
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
        let detail = action_detail(&action, &args);
        self.audit(&action, &detail, elapsed, exit);
        result
    }
}

impl PostHogTool {
    async fn dispatch(&self, action: &str, args: &Value) -> anyhow::Result<ToolResult> {
        match action {
            "query_events" => self.query_events(args).await,
            "recent_flag_changes" => self.recent_flag_changes(args).await,
            "flag_status" => self.flag_status(args).await,
            "events_for_user" => self.events_for_user(args).await,
            "session_replay_url" => self.session_replay_url(args).await,
            "hogql" => self.hogql_query(args).await,
            other => Ok(err(format!("unknown action '{other}'"))),
        }
    }

    /// Count + sample for one event over a time window. Property filters
    /// are AND-ed with equality.
    async fn query_events(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let event = match args.get("event_name").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(err("missing 'event_name'")),
        };
        let since = since_or_default(args);
        let until = until_or_default(args);
        let limit = clamp_limit(args);

        // Build a HogQL query: count + small sample. Property filters land in
        // the WHERE via parameterised equality; we don't accept raw SQL there
        // to keep the agent's surface narrow.
        let mut where_clauses: Vec<String> = vec![
            format!("event = '{}'", escape_sql(&event)),
            format!("timestamp >= toDateTime('{since}')"),
            format!("timestamp <= toDateTime('{until}')"),
        ];
        if let Some(filters) = args.get("filters").and_then(|v| v.as_object()) {
            for (k, v) in filters {
                if let Some(val) = v.as_str() {
                    where_clauses.push(format!(
                        "properties['{}'] = '{}'",
                        escape_sql(k),
                        escape_sql(val)
                    ));
                }
            }
        }
        let where_sql = where_clauses.join(" AND ");

        // Two queries: total count, plus a small sample so the agent has
        // something concrete to reason about.
        let count_sql = format!("SELECT count() FROM events WHERE {where_sql}");
        let sample_sql = format!(
            "SELECT timestamp, distinct_id, properties FROM events \
             WHERE {where_sql} ORDER BY timestamp DESC LIMIT {limit}"
        );

        let count = self.run_hogql(&count_sql).await?;
        let sample = self.run_hogql(&sample_sql).await?;

        let total = count
            .get("results")
            .and_then(|r| r.as_array())
            .and_then(|rows| rows.first())
            .and_then(|row| row.as_array())
            .and_then(|cols| cols.first())
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        let mut out = String::new();
        writeln!(out, "event: {event}").ok();
        writeln!(out, "window: {since} → {until}").ok();
        writeln!(out, "total: {total}").ok();
        writeln!(out, "sample (up to {limit}):").ok();
        if let Some(rows) = sample.get("results").and_then(|r| r.as_array()) {
            for row in rows.iter().take(limit as usize) {
                if let Some(cols) = row.as_array() {
                    let ts = cols.first().and_then(|v| v.as_str()).unwrap_or("?");
                    let did = cols.get(1).and_then(|v| v.as_str()).unwrap_or("?");
                    let props = cols
                        .get(2)
                        .map(|v| serde_json::to_string(v).unwrap_or_default())
                        .unwrap_or_default();
                    let props_short = &props[..props.len().min(200)];
                    writeln!(out, "  {ts} {did} {props_short}").ok();
                }
            }
        }
        Ok(ok_res(out))
    }

    /// Flags modified in the last N hours, optionally limited to active.
    async fn recent_flag_changes(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let hours = args.get("hours").and_then(|v| v.as_u64()).unwrap_or(24);
        let active_only = args
            .get("active_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // PostHog's feature_flags endpoint returns all flags; we filter
        // client-side by `updated_at` against the cutoff.
        let resp = self
            .req(reqwest::Method::GET, "feature_flags")
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let flags = match v.get("results").and_then(|r| r.as_array()) {
            Some(arr) => arr,
            None => return Ok(ok_res("no flags returned\n".into())),
        };

        let cutoff = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let mut out = String::new();
        writeln!(out, "flags modified since {cutoff_str}:").ok();
        let mut shown = 0usize;
        for f in flags {
            let updated = f.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
            if updated.is_empty() || updated < cutoff_str.as_str() {
                continue;
            }
            let active = f.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
            if active_only && !active {
                continue;
            }
            let key = f.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let rollout = f
                .get("rollout_percentage")
                .and_then(|v| v.as_u64())
                .map(|p| format!("{p}%"))
                .unwrap_or_else(|| "—".into());
            writeln!(
                out,
                "  {key} active={active} rollout={rollout} updated={updated}"
            )
            .ok();
            shown += 1;
        }
        if shown == 0 {
            writeln!(out, "  (none)").ok();
        }
        Ok(ok_res(out))
    }

    /// One flag's full metadata: rollout %, filters, active state.
    async fn flag_status(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let key = match args.get("flag_key").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(err("missing 'flag_key'")),
        };
        // PostHog's feature_flags endpoint supports ?key=, but only some
        // versions; safer to GET all and filter.
        let resp = self
            .req(reqwest::Method::GET, "feature_flags")
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let flag = v.get("results").and_then(|r| r.as_array()).and_then(|arr| {
            arr.iter()
                .find(|f| f.get("key").and_then(|k| k.as_str()) == Some(key.as_str()))
        });
        let Some(flag) = flag else {
            return Ok(err(format!("flag '{key}' not found")));
        };

        let mut out = String::new();
        writeln!(out, "flag: {key}").ok();
        writeln!(
            out,
            "  active: {}",
            flag.get("active")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        )
        .ok();
        if let Some(p) = flag.get("rollout_percentage").and_then(|v| v.as_u64()) {
            writeln!(out, "  rollout: {p}%").ok();
        }
        if let Some(updated) = flag.get("updated_at").and_then(|v| v.as_str()) {
            writeln!(out, "  updated_at: {updated}").ok();
        }
        if let Some(created) = flag.get("created_at").and_then(|v| v.as_str()) {
            writeln!(out, "  created_at: {created}").ok();
        }
        if let Some(name) = flag.get("name").and_then(|v| v.as_str()) {
            if !name.is_empty() {
                writeln!(out, "  name: {name}").ok();
            }
        }
        if let Some(filters) = flag.get("filters") {
            let pretty = serde_json::to_string_pretty(filters).unwrap_or_default();
            writeln!(out, "  filters:\n{}", indent(&pretty, 4)).ok();
        }
        Ok(ok_res(out))
    }

    /// Last N events for a single `distinct_id`. The classic "user reported
    /// a bug — what were they doing" query.
    async fn events_for_user(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let did = match args.get("distinct_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(err("missing 'distinct_id'")),
        };
        let limit = clamp_limit(args);
        let since = since_or_default(args);

        let sql = format!(
            "SELECT timestamp, event, properties FROM events \
             WHERE distinct_id = '{}' AND timestamp >= toDateTime('{since}') \
             ORDER BY timestamp DESC LIMIT {limit}",
            escape_sql(&did)
        );
        let result = self.run_hogql(&sql).await?;
        let mut out = String::new();
        writeln!(out, "distinct_id: {did}").ok();
        writeln!(out, "since: {since}").ok();
        if let Some(rows) = result.get("results").and_then(|r| r.as_array()) {
            writeln!(out, "events ({}):", rows.len()).ok();
            for row in rows {
                if let Some(cols) = row.as_array() {
                    let ts = cols.first().and_then(|v| v.as_str()).unwrap_or("?");
                    let event = cols.get(1).and_then(|v| v.as_str()).unwrap_or("?");
                    let props = cols
                        .get(2)
                        .map(|v| serde_json::to_string(v).unwrap_or_default())
                        .unwrap_or_default();
                    let props_short = &props[..props.len().min(150)];
                    writeln!(out, "  {ts} {event} {props_short}").ok();
                }
            }
        }
        Ok(ok_res(out))
    }

    /// Most recent session replay for a `distinct_id`. Returns the URL the
    /// human can paste into a browser; replays themselves are too big to
    /// inline.
    async fn session_replay_url(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let did = match args.get("distinct_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(err("missing 'distinct_id'")),
        };
        let resp = self
            .req(reqwest::Method::GET, "session_recordings")
            .query(&[("distinct_id", did.as_str()), ("limit", "1")])
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let recording = v
            .get("results")
            .and_then(|r| r.as_array())
            .and_then(|arr| arr.first());
        let Some(rec) = recording else {
            return Ok(ok_res(format!("no replays found for distinct_id={did}\n")));
        };

        let id = rec.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let start = rec
            .get("start_time")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let duration = rec
            .get("recording_duration")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let url = format!(
            "{}/project/{}/replay/{}",
            self.config.host.trim_end_matches('/'),
            self.config.project_id,
            id
        );
        let mut out = String::new();
        writeln!(out, "distinct_id: {did}").ok();
        writeln!(out, "replay: {url}").ok();
        writeln!(out, "  start: {start}").ok();
        writeln!(out, "  duration_s: {duration}").ok();
        Ok(ok_res(out))
    }

    /// Run a raw HogQL query. Power-user escape hatch; the agent should
    /// reach for the structured actions first.
    async fn hogql_query(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let query = match args.get("query").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(err("missing 'query'")),
        };
        let result = self.run_hogql(&query).await?;
        let pretty = serde_json::to_string_pretty(&result).unwrap_or_default();
        Ok(ok_res(pretty))
    }

    /// Internal: POST to /query with a HogQL body. Single API entry point
    /// for everything that needs ClickHouse-flavoured access.
    async fn run_hogql(&self, query: &str) -> anyhow::Result<Value> {
        let body = json!({
            "query": {
                "kind": "HogQLQuery",
                "query": query,
            }
        });
        let resp = self
            .req(reqwest::Method::POST, "query")
            .json(&body)
            .send()
            .await?;
        let (ok, status, raw) = consume(resp).await;
        if !ok {
            anyhow::bail!("hogql {status}: {}", snippet(&raw));
        }
        Ok(serde_json::from_str(&raw).unwrap_or(Value::Null))
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/// Build the audit detail string from the action and args. Keeps audit
/// entries human-readable without dumping full JSON.
fn action_detail(action: &str, args: &Value) -> String {
    match action {
        "query_events" => args
            .get("event_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "flag_status" => args
            .get("flag_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "events_for_user" | "session_replay_url" => args
            .get("distinct_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

fn since_or_default(args: &Value) -> String {
    args.get("since")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SINCE)
        .to_string()
}

fn until_or_default(args: &Value) -> String {
    args.get("until")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("now")
        .to_string()
}

fn clamp_limit(args: &Value) -> u64 {
    let raw = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_LIMIT);
    raw.clamp(1, MAX_LIMIT)
}

/// Minimal SQL-string escape for HogQL string literals. Doubles single
/// quotes; rejects nothing — HogQL will surface its own parser errors for
/// anything truly malformed. Works because we only build literal-equality
/// `=` clauses; we don't accept raw SQL fragments from the agent for the
/// structured actions.
fn escape_sql(s: &str) -> String {
    s.replace('\'', "''")
}

fn indent(s: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    s.lines()
        .map(|l| format!("{pad}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tool_for(server: &MockServer) -> PostHogTool {
        PostHogTool::new(PostHogToolConfig::new(
            "phx_test".into(),
            "12345".into(),
            server.uri(),
        ))
    }

    #[tokio::test]
    async fn query_events_returns_total_and_sample() {
        let server = MockServer::start().await;
        // The tool issues two HogQL POSTs — count, then sample. Both hit the
        // same /api/projects/12345/query path; we mock with a count-then-rows
        // sequence by responding to either body the same way.
        Mock::given(method("POST"))
            .and(path("/api/projects/12345/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [["2026-04-28T17:00:00Z", "user-1", {"plan": "pro"}]]
            })))
            .mount(&server)
            .await;

        let tool = tool_for(&server);
        let out = tool
            .execute(json!({
                "action": "query_events",
                "event_name": "checkout_failed"
            }))
            .await
            .unwrap();
        assert!(out.success, "expected success, got {out:?}");
        assert!(out.output.contains("event: checkout_failed"));
        assert!(out.output.contains("user-1"));
    }

    #[tokio::test]
    async fn recent_flag_changes_filters_by_cutoff() {
        let server = MockServer::start().await;
        let recent = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::hours(1))
            .unwrap()
            .to_rfc3339();
        let stale = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::days(30))
            .unwrap()
            .to_rfc3339();

        Mock::given(method("GET"))
            .and(path("/api/projects/12345/feature_flags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"key": "fresh", "active": true,  "rollout_percentage": 50, "updated_at": recent},
                    {"key": "old",   "active": true,  "rollout_percentage": 100, "updated_at": stale},
                ]
            })))
            .mount(&server)
            .await;

        let tool = tool_for(&server);
        let out = tool
            .execute(json!({
                "action": "recent_flag_changes",
                "hours": 24
            }))
            .await
            .unwrap();
        assert!(out.success);
        assert!(out.output.contains("fresh"));
        assert!(!out.output.contains(" old "));
    }

    #[tokio::test]
    async fn flag_status_finds_named_flag() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/projects/12345/feature_flags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"key": "wanted", "active": true, "rollout_percentage": 25,
                     "name": "Wanted Flag", "updated_at": "2026-04-28T00:00:00Z"},
                ]
            })))
            .mount(&server)
            .await;

        let tool = tool_for(&server);
        let out = tool
            .execute(json!({
                "action": "flag_status",
                "flag_key": "wanted"
            }))
            .await
            .unwrap();
        assert!(out.success);
        assert!(out.output.contains("flag: wanted"));
        assert!(out.output.contains("rollout: 25%"));
    }

    #[tokio::test]
    async fn flag_status_missing_flag_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/projects/12345/feature_flags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
            .mount(&server)
            .await;

        let tool = tool_for(&server);
        let out = tool
            .execute(json!({
                "action": "flag_status",
                "flag_key": "missing"
            }))
            .await
            .unwrap();
        assert!(!out.success);
        assert!(out.error.unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn session_replay_url_returns_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/projects/12345/session_recordings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "id": "rec-abc",
                    "start_time": "2026-04-28T16:00:00Z",
                    "recording_duration": 240
                }]
            })))
            .mount(&server)
            .await;

        let tool = tool_for(&server);
        let out = tool
            .execute(json!({
                "action": "session_replay_url",
                "distinct_id": "user-99"
            }))
            .await
            .unwrap();
        assert!(out.success);
        assert!(out.output.contains("/project/12345/replay/rec-abc"));
        assert!(out.output.contains("duration_s: 240"));
    }

    #[tokio::test]
    async fn unknown_action_errors() {
        let server = MockServer::start().await;
        let tool = tool_for(&server);
        let out = tool.execute(json!({"action": "nope"})).await.unwrap();
        assert!(!out.success);
        assert!(out.error.unwrap().contains("unknown action"));
    }

    #[tokio::test]
    async fn missing_action_errors() {
        let server = MockServer::start().await;
        let tool = tool_for(&server);
        let out = tool.execute(json!({})).await.unwrap();
        assert!(!out.success);
        assert!(out.error.unwrap().contains("missing 'action'"));
    }

    #[test]
    fn escape_sql_doubles_single_quotes() {
        assert_eq!(escape_sql("o'brien"), "o''brien");
        assert_eq!(escape_sql("plain"), "plain");
    }

    #[test]
    fn clamp_limit_respects_default_and_ceiling() {
        assert_eq!(clamp_limit(&json!({})), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(&json!({"limit": 50})), 50);
        assert_eq!(clamp_limit(&json!({"limit": 99999})), MAX_LIMIT);
        assert_eq!(clamp_limit(&json!({"limit": 0})), 1);
    }
}
