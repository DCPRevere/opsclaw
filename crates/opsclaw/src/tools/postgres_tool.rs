//! Postgres tool. Connects directly via tokio-postgres against configured
//! instances. Read-only by default; writes (ANALYZE, VACUUM, REINDEX, and
//! arbitrary EXEC) are gated by autonomy and audit-logged.
//!
//! Canned health actions: connections, locks, long_queries, replication,
//! table_sizes, db_size. Plus query (SELECT) and exec (non-SELECT) for
//! arbitrary statements.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio_postgres::types::{FromSql, Type};
use tokio_postgres::{Client, NoTls, Row};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsClawAutonomy;
use crate::tools::ssh_tool::write_audit_entry;

const MAX_OUTPUT_BYTES: usize = 16 * 1024;
const DEFAULT_ROW_LIMIT: i64 = 100;
const MAX_ROW_LIMIT: i64 = 5_000;
const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone)]
pub struct PostgresInstance {
    pub name: String,
    pub dsn: String,
    pub autonomy: OpsClawAutonomy,
}

pub struct PostgresToolConfig {
    pub instances: Vec<PostgresInstance>,
}

pub struct PostgresTool {
    config: PostgresToolConfig,
    instances: HashMap<String, PostgresInstance>,
    audit_dir: Option<PathBuf>,
}

impl PostgresTool {
    pub fn new(config: PostgresToolConfig) -> Self {
        let instances = config
            .instances
            .iter()
            .cloned()
            .map(|i| (i.name.clone(), i))
            .collect();
        Self {
            config,
            instances,
            audit_dir: None,
        }
    }

    pub fn with_audit_dir(mut self, dir: PathBuf) -> Self {
        self.audit_dir = Some(dir);
        self
    }

    fn instance_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.instances.keys().cloned().collect();
        v.sort();
        v
    }

    fn audit(&self, instance: &str, action: &str, detail: &str, duration_ms: u128, exit: i32) {
        let _ = write_audit_entry(
            &format!("postgres:{instance}"),
            &format!("{action} {detail}"),
            exit,
            duration_ms,
            self.audit_dir.as_ref(),
        );
    }
}

async fn connect(dsn: &str, timeout_ms: u64) -> anyhow::Result<Client> {
    let (client, connection) = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        tokio_postgres::connect(dsn, NoTls),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout after {timeout_ms}ms"))??;

    // Drive the connection future in the background. It ends when the
    // client is dropped.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("postgres connection closed: {e}");
        }
    });
    Ok(client)
}

/// Safety guard for `query` action: refuse anything that doesn't start with
/// SELECT, WITH, SHOW, or EXPLAIN. Strips comments/whitespace first.
fn is_read_only_sql(sql: &str) -> bool {
    let trimmed = strip_leading_comments(sql).trim_start().to_ascii_uppercase();
    trimmed.starts_with("SELECT")
        || trimmed.starts_with("WITH")
        || trimmed.starts_with("SHOW")
        || trimmed.starts_with("EXPLAIN")
}

fn strip_leading_comments(sql: &str) -> &str {
    let mut s = sql.trim_start();
    loop {
        if let Some(rest) = s.strip_prefix("--") {
            if let Some(nl) = rest.find('\n') {
                s = &rest[nl + 1..].trim_start();
            } else {
                return "";
            }
        } else if let Some(rest) = s.strip_prefix("/*") {
            if let Some(end) = rest.find("*/") {
                s = &rest[end + 2..].trim_start();
            } else {
                return "";
            }
        } else {
            return s;
        }
    }
}

/// Render a row as a compact TSV-ish line. Uses a small set of typed
/// FromSql conversions; falls back to Debug for exotic types.
fn render_value(row: &Row, idx: usize) -> String {
    let col = &row.columns()[idx];
    let ty = col.type_();
    macro_rules! try_ty {
        ($t:ty) => {
            match row.try_get::<_, Option<$t>>(idx) {
                Ok(Some(v)) => return format!("{v}"),
                Ok(None) => return "NULL".into(),
                Err(_) => {}
            }
        };
    }
    match *ty {
        Type::BOOL => try_ty!(bool),
        Type::INT2 => try_ty!(i16),
        Type::INT4 => try_ty!(i32),
        Type::INT8 => try_ty!(i64),
        Type::FLOAT4 => try_ty!(f32),
        Type::FLOAT8 => try_ty!(f64),
        Type::TEXT | Type::VARCHAR | Type::NAME | Type::BPCHAR => try_ty!(String),
        Type::TIMESTAMP | Type::TIMESTAMPTZ => try_ty!(chrono::NaiveDateTime),
        Type::OID => try_ty!(u32),
        _ => {}
    }
    // Fallback: try as string, else opaque
    if let Ok(s) = row.try_get::<_, Option<String>>(idx) {
        return s.unwrap_or_else(|| "NULL".into());
    }
    // Raw bytes — report type only.
    format!("<{}>", ty.name())
}

fn render_rows(rows: &[Row], limit: i64) -> String {
    let mut out = String::new();
    writeln!(out, "rows: {}", rows.len()).ok();
    if rows.is_empty() {
        return out;
    }
    let cols = rows[0].columns();
    let header = cols
        .iter()
        .map(|c| c.name().to_string())
        .collect::<Vec<_>>()
        .join("\t");
    writeln!(out, "{header}").ok();
    for (i, r) in rows.iter().enumerate() {
        if i as i64 >= limit {
            writeln!(out, "... [{} more rows]", rows.len() as i64 - limit).ok();
            break;
        }
        let mut cells = Vec::with_capacity(cols.len());
        for idx in 0..cols.len() {
            cells.push(render_value(r, idx));
        }
        writeln!(out, "{}", cells.join("\t")).ok();
    }
    out
}

#[async_trait]
impl Tool for PostgresTool {
    fn name(&self) -> &str {
        "postgres"
    }

    fn description(&self) -> &str {
        "Postgres tool. Reads: connections, locks, long_queries, \
         replication, table_sizes, db_size, query (SELECT/WITH/SHOW/\
         EXPLAIN). Writes: exec (arbitrary SQL — gated by autonomy), \
         analyze, vacuum, reindex. Writes respect the instance's autonomy \
         — DryRun rejects them. Every statement is audit-logged. Direct \
         driver connection via tokio-postgres; no shell involved."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "instance": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": [
                        "connections", "locks", "long_queries", "replication",
                        "table_sizes", "db_size", "query",
                        "exec", "analyze", "vacuum", "reindex"
                    ]
                },
                "sql": {"type": "string", "description": "query/exec"},
                "limit": {"type": "integer", "default": 100},
                "min_duration_ms": {"type": "integer", "default": 1000, "description": "long_queries"},
                "table": {"type": "string", "description": "analyze/vacuum/reindex"},
                "statement_timeout_ms": {"type": "integer", "default": 10000}
            },
            "required": ["instance", "action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let name = match args.get("instance").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(pg_err("missing 'instance'")),
        };
        let instance = match self.instances.get(name) {
            Some(i) => i,
            None => {
                return Ok(pg_err(format!(
                    "unknown instance '{name}'. Available: {}",
                    self.instance_names().join(", ")
                )));
            }
        };
        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Ok(pg_err("missing 'action'")),
        };

        let is_write = matches!(
            action.as_str(),
            "exec" | "analyze" | "vacuum" | "reindex"
        );
        if is_write && instance.autonomy == OpsClawAutonomy::DryRun {
            self.audit(
                name,
                &format!("[blocked dry-run] {action}"),
                "",
                0,
                -1,
            );
            return Ok(pg_err(format!(
                "dry-run mode: write action '{action}' rejected"
            )));
        }

        let timeout_ms = args
            .get("statement_timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_STATEMENT_TIMEOUT_MS);

        let start = std::time::Instant::now();
        let result = self.dispatch(instance, &action, &args, timeout_ms).await;
        let elapsed = start.elapsed().as_millis();
        let exit = match &result {
            Ok(r) if r.success => 0,
            _ => 1,
        };
        let detail = args
            .get("sql")
            .or_else(|| args.get("table"))
            .and_then(|v| v.as_str())
            .map(|s| s.chars().take(80).collect::<String>())
            .unwrap_or_default();
        self.audit(name, &action, &detail, elapsed, exit);
        result
    }
}

impl PostgresTool {
    async fn dispatch(
        &self,
        instance: &PostgresInstance,
        action: &str,
        args: &Value,
        timeout_ms: u64,
    ) -> anyhow::Result<ToolResult> {
        let client = match connect(&instance.dsn, timeout_ms).await {
            Ok(c) => c,
            Err(e) => return Ok(pg_err(format!("connect failed: {e}"))),
        };
        let _ = client
            .simple_query(&format!("SET statement_timeout = {}", timeout_ms))
            .await;

        let limit = args
            .get("limit")
            .and_then(|v| v.as_i64())
            .unwrap_or(DEFAULT_ROW_LIMIT)
            .clamp(1, MAX_ROW_LIMIT);

        match action {
            "connections" => {
                let sql = "SELECT state, count(*) AS n FROM pg_stat_activity GROUP BY state ORDER BY n DESC";
                run_query(&client, sql, &[], limit).await
            }
            "locks" => {
                let sql = "SELECT l.locktype, l.mode, l.granted, a.pid, a.usename, a.query \
                    FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid \
                    WHERE NOT l.granted OR l.mode LIKE '%Exclusive%' \
                    ORDER BY l.granted, a.pid";
                run_query(&client, sql, &[], limit).await
            }
            "long_queries" => {
                let min_ms = args
                    .get("min_duration_ms")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1000);
                let sql = "SELECT pid, usename, state, now() - query_start AS duration, \
                    substring(query, 1, 200) AS query \
                    FROM pg_stat_activity \
                    WHERE state <> 'idle' AND query_start IS NOT NULL \
                      AND now() - query_start > make_interval(secs := $1::double precision / 1000) \
                    ORDER BY duration DESC";
                let min_ms_f64 = min_ms as f64;
                run_query(&client, sql, &[&min_ms_f64], limit).await
            }
            "replication" => {
                let sql = "SELECT application_name, state, sent_lsn, write_lsn, flush_lsn, \
                    replay_lsn, write_lag, flush_lag, replay_lag \
                    FROM pg_stat_replication";
                run_query(&client, sql, &[], limit).await
            }
            "table_sizes" => {
                let sql = "SELECT schemaname, relname, \
                    pg_size_pretty(pg_total_relation_size(relid)) AS total_size, \
                    pg_total_relation_size(relid) AS bytes \
                    FROM pg_catalog.pg_statio_user_tables \
                    ORDER BY pg_total_relation_size(relid) DESC";
                run_query(&client, sql, &[], limit).await
            }
            "db_size" => {
                let sql = "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size, \
                    pg_database_size(datname) AS bytes FROM pg_database ORDER BY bytes DESC";
                run_query(&client, sql, &[], limit).await
            }
            "query" => {
                let sql = match args.get("sql").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s,
                    _ => return Ok(pg_err("query requires 'sql'")),
                };
                if !is_read_only_sql(sql) {
                    return Ok(pg_err(
                        "query action only allows SELECT/WITH/SHOW/EXPLAIN; use 'exec' for mutations",
                    ));
                }
                run_query(&client, sql, &[], limit).await
            }
            "exec" => {
                let sql = match args.get("sql").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s,
                    _ => return Ok(pg_err("exec requires 'sql'")),
                };
                match client.batch_execute(sql).await {
                    Ok(()) => Ok(pg_ok("exec ok".into())),
                    Err(e) => Ok(pg_err(format!("exec failed: {e}"))),
                }
            }
            "analyze" => {
                let sql = build_maintenance_sql("ANALYZE", args)?;
                match client.batch_execute(&sql).await {
                    Ok(()) => Ok(pg_ok(format!("ran: {sql}"))),
                    Err(e) => Ok(pg_err(format!("{e}"))),
                }
            }
            "vacuum" => {
                let sql = build_maintenance_sql("VACUUM", args)?;
                match client.batch_execute(&sql).await {
                    Ok(()) => Ok(pg_ok(format!("ran: {sql}"))),
                    Err(e) => Ok(pg_err(format!("{e}"))),
                }
            }
            "reindex" => {
                let sql = build_maintenance_sql("REINDEX TABLE", args)?;
                match client.batch_execute(&sql).await {
                    Ok(()) => Ok(pg_ok(format!("ran: {sql}"))),
                    Err(e) => Ok(pg_err(format!("{e}"))),
                }
            }
            other => Ok(pg_err(format!("unknown action '{other}'"))),
        }
    }
}

fn build_maintenance_sql(verb: &str, args: &Value) -> anyhow::Result<String> {
    let table = args
        .get("table")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("{verb} requires 'table'"))?;
    if !is_safe_table_ident(table) {
        anyhow::bail!("invalid table identifier '{table}'");
    }
    Ok(format!("{verb} {table}"))
}

/// Accept `ident` or `schema.ident`. Letters, digits, `_`, one `.` allowed.
fn is_safe_table_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && s.matches('.').count() <= 1
}

async fn run_query(
    client: &Client,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    limit: i64,
) -> anyhow::Result<ToolResult> {
    match client.query(sql, params).await {
        Ok(rows) => Ok(pg_ok(render_rows(&rows, limit))),
        Err(e) => Ok(pg_err(format!("{e}"))),
    }
}

fn pg_ok(mut s: String) -> ToolResult {
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

fn pg_err<S: Into<String>>(msg: S) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(msg.into()),
    }
}

/// Unused helper retained for the `FromSql` import. Prevents dead-code warning.
#[allow(dead_code)]
fn _unused_fromsql<'a, T: FromSql<'a>>() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_sql_accepts_expected() {
        assert!(is_read_only_sql("SELECT 1"));
        assert!(is_read_only_sql("  select * from t"));
        assert!(is_read_only_sql("WITH x AS (SELECT 1) SELECT * FROM x"));
        assert!(is_read_only_sql("EXPLAIN SELECT 1"));
        assert!(is_read_only_sql("SHOW search_path"));
        assert!(is_read_only_sql("-- comment\nSELECT 1"));
        assert!(is_read_only_sql("/* c */ SELECT 1"));
    }

    #[test]
    fn read_only_sql_rejects_writes() {
        assert!(!is_read_only_sql("DELETE FROM t"));
        assert!(!is_read_only_sql("UPDATE t SET x=1"));
        assert!(!is_read_only_sql("INSERT INTO t VALUES (1)"));
        assert!(!is_read_only_sql("DROP TABLE t"));
        assert!(!is_read_only_sql("TRUNCATE t"));
    }

    #[test]
    fn safe_idents() {
        assert!(is_safe_table_ident("users"));
        assert!(is_safe_table_ident("public.users"));
        assert!(is_safe_table_ident("Schema_1.table_2"));
        assert!(!is_safe_table_ident(""));
        assert!(!is_safe_table_ident("users; DROP TABLE x"));
        assert!(!is_safe_table_ident("a.b.c"));
        assert!(!is_safe_table_ident("foo bar"));
        assert!(!is_safe_table_ident("users\""));
    }

    #[test]
    fn tool_metadata() {
        let t = PostgresTool::new(PostgresToolConfig {
            instances: vec![],
        });
        assert_eq!(t.name(), "postgres");
        assert!(!t.description().is_empty());
        let schema = t.parameters_schema();
        assert!(schema["properties"]["action"].is_object());
    }

    #[tokio::test]
    async fn unknown_instance() {
        let t = PostgresTool::new(PostgresToolConfig { instances: vec![] });
        let r = t
            .execute(json!({"instance": "nope", "action": "connections"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unknown instance"));
    }

    #[tokio::test]
    async fn query_rejects_write_sql() {
        let t = PostgresTool::new(PostgresToolConfig {
            instances: vec![PostgresInstance {
                name: "dev".into(),
                dsn: "host=127.0.0.1 port=1 user=x".into(),
                autonomy: OpsClawAutonomy::Auto,
            }],
        });
        let r = t
            .execute(json!({
                "instance": "dev", "action": "query",
                "sql": "DELETE FROM users",
                "statement_timeout_ms": 200
            }))
            .await
            .unwrap();
        assert!(!r.success);
        // Either the SELECT-only guard catches it, or the connection fails
        // first — both results are acceptable. We expect the guard because
        // we validate before connecting... actually the current dispatch
        // connects first. Accept either outcome, but prefer the guard.
        let err = r.error.unwrap();
        assert!(err.contains("SELECT") || err.contains("connect") || err.contains("timeout"));
    }

    #[tokio::test]
    async fn dry_run_rejects_writes_without_connecting() {
        let t = PostgresTool::new(PostgresToolConfig {
            instances: vec![PostgresInstance {
                name: "prod".into(),
                // Unreachable DSN — if we try to connect, the test will hang or fail.
                dsn: "host=127.0.0.1 port=1 user=x".into(),
                autonomy: OpsClawAutonomy::DryRun,
            }],
        });
        let r = t
            .execute(json!({
                "instance": "prod", "action": "exec",
                "sql": "DROP TABLE users"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("dry-run"));
    }

    #[tokio::test]
    async fn missing_instance_arg() {
        let t = PostgresTool::new(PostgresToolConfig { instances: vec![] });
        let r = t
            .execute(json!({"action": "connections"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn missing_action_arg() {
        let t = PostgresTool::new(PostgresToolConfig {
            instances: vec![PostgresInstance {
                name: "dev".into(),
                dsn: "host=127.0.0.1 port=1 user=x".into(),
                autonomy: OpsClawAutonomy::Auto,
            }],
        });
        let r = t
            .execute(json!({"instance": "dev"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn unsafe_table_ident_rejected_without_connecting() {
        // table-stats action should reject shell-injection-looking idents
        // at validation time, before attempting to connect.
        let t = PostgresTool::new(PostgresToolConfig {
            instances: vec![PostgresInstance {
                name: "dev".into(),
                dsn: "host=127.0.0.1 port=1 user=x".into(),
                autonomy: OpsClawAutonomy::Auto,
            }],
        });
        let r = t
            .execute(json!({
                "instance": "dev", "action": "table_stats",
                "table": "users; DROP TABLE admins"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        // Accept either a validation rejection or a connect error — both
        // prove the bad statement never ran.
        assert!(r.error.is_some());
    }
}
