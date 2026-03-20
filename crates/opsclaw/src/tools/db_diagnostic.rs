//! Database diagnostic tool for read-only Postgres and Redis health queries.
//!
//! Runs queries via the existing SSH [`CommandRunner`] abstraction —
//! no direct database driver dependencies are needed.

use std::fmt::Write;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::tools::discovery::CommandRunner;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Type of database to diagnose.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    Postgres,
    Redis,
}

/// Per-database configuration entry (lives under `[[targets.databases]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Human-readable name for this database instance.
    pub name: String,
    /// Type of database.
    #[serde(rename = "type")]
    pub db_type: DatabaseType,
    /// DSN / connection string stored as a secret reference, **or** inline
    /// for non-secret local dev setups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsn: Option<String>,
    /// Alternative: plain host (used with `port`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Alternative: plain port (default 5432 / 6379).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

/// Aggregated diagnostic snapshot for one database instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbDiagnosticSnapshot {
    pub name: String,
    pub db_type: DatabaseType,
    pub metrics: DbMetrics,
}

/// Parsed health metrics — variant per database type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum DbMetrics {
    Postgres(PostgresMetrics),
    Redis(RedisMetrics),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostgresMetrics {
    pub connection_count: Option<i64>,
    pub active_queries: Vec<ActiveQuery>,
    pub replication_lag_lsn: Option<String>,
    pub database_size_bytes: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveQuery {
    pub pid: String,
    pub state: String,
    pub query_start: String,
    pub query: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedisMetrics {
    pub connected_clients: Option<i64>,
    pub used_memory_bytes: Option<i64>,
    pub used_memory_human: Option<String>,
    pub keyspace_hits: Option<i64>,
    pub keyspace_misses: Option<i64>,
    pub hit_rate_pct: Option<f64>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run read-only diagnostic queries for all configured databases on a target.
pub async fn fetch_db_diagnostics(
    runner: &dyn CommandRunner,
    databases: &[DatabaseConfig],
) -> Vec<DbDiagnosticSnapshot> {
    let mut results = Vec::new();
    for db in databases {
        match &db.db_type {
            DatabaseType::Postgres => match run_postgres_diagnostics(runner, db).await {
                Ok(metrics) => results.push(DbDiagnosticSnapshot {
                    name: db.name.clone(),
                    db_type: DatabaseType::Postgres,
                    metrics: DbMetrics::Postgres(metrics),
                }),
                Err(e) => tracing::warn!("postgres diagnostic failed for {}: {e:#}", db.name),
            },
            DatabaseType::Redis => match run_redis_diagnostics(runner, db).await {
                Ok(metrics) => results.push(DbDiagnosticSnapshot {
                    name: db.name.clone(),
                    db_type: DatabaseType::Redis,
                    metrics: DbMetrics::Redis(metrics),
                }),
                Err(e) => tracing::warn!("redis diagnostic failed for {}: {e:#}", db.name),
            },
        }
    }
    results
}

/// Render diagnostic snapshots as markdown suitable for LLM context.
pub fn diagnostics_to_markdown(snapshots: &[DbDiagnosticSnapshot]) -> String {
    if snapshots.is_empty() {
        return String::new();
    }
    let mut md = String::from("## Database Diagnostics\n\n");
    for snap in snapshots {
        let _ = writeln!(
            md,
            "### {} ({})\n",
            snap.name,
            type_label(&snap.db_type)
        );
        match &snap.metrics {
            DbMetrics::Postgres(pg) => {
                if let Some(count) = pg.connection_count {
                    let _ = writeln!(md, "- **Connections**: {count}");
                }
                if let Some(size) = pg.database_size_bytes {
                    let _ = writeln!(md, "- **Database size**: {} bytes", size);
                }
                if let Some(lsn) = &pg.replication_lag_lsn {
                    let _ = writeln!(md, "- **Replication LSN**: {lsn}");
                }
                if !pg.active_queries.is_empty() {
                    let _ = writeln!(
                        md,
                        "- **Active queries**: {}\n",
                        pg.active_queries.len()
                    );
                    md.push_str("| PID | State | Started | Query |\n");
                    md.push_str("|-----|-------|---------|-------|\n");
                    for q in &pg.active_queries {
                        let short_query = truncate(&q.query, 80);
                        let _ = writeln!(
                            md,
                            "| {} | {} | {} | {} |",
                            q.pid, q.state, q.query_start, short_query
                        );
                    }
                    md.push('\n');
                }
            }
            DbMetrics::Redis(r) => {
                if let Some(clients) = r.connected_clients {
                    let _ = writeln!(md, "- **Connected clients**: {clients}");
                }
                if let Some(mem) = &r.used_memory_human {
                    let _ = writeln!(md, "- **Used memory**: {mem}");
                }
                if let Some(hits) = r.keyspace_hits {
                    let misses = r.keyspace_misses.unwrap_or(0);
                    let _ = write!(md, "- **Keyspace hits/misses**: {hits}/{misses}");
                    if let Some(rate) = r.hit_rate_pct {
                        let _ = write!(md, " ({rate:.1}% hit rate)");
                    }
                    md.push('\n');
                }
            }
        }
        md.push('\n');
    }
    md
}

// ---------------------------------------------------------------------------
// Postgres internals
// ---------------------------------------------------------------------------

fn psql_cmd(db: &DatabaseConfig, sql: &str) -> String {
    let conn = build_pg_conn_args(db);
    format!("psql {conn} -t -A -c {}", shell_quote(sql))
}

fn build_pg_conn_args(db: &DatabaseConfig) -> String {
    if let Some(dsn) = &db.dsn {
        shell_quote(dsn)
    } else {
        let host = db.host.as_deref().unwrap_or("localhost");
        let port = db.port.unwrap_or(5432);
        format!("-h {host} -p {port}")
    }
}

async fn run_postgres_diagnostics(
    runner: &dyn CommandRunner,
    db: &DatabaseConfig,
) -> Result<PostgresMetrics> {
    let mut metrics = PostgresMetrics::default();

    // Connection count
    let cmd = psql_cmd(db, "SELECT count(*) FROM pg_stat_activity;");
    if let Ok(out) = runner.run(&cmd).await {
        if out.exit_code == 0 {
            metrics.connection_count = out.stdout.trim().parse().ok();
        }
    }

    // Active queries
    let cmd = psql_cmd(
        db,
        "SELECT pid, state, query_start, query FROM pg_stat_activity WHERE state = 'active';",
    );
    if let Ok(out) = runner.run(&cmd).await {
        if out.exit_code == 0 {
            metrics.active_queries = parse_pg_active_queries(&out.stdout);
        }
    }

    // Replication lag LSN
    let cmd = psql_cmd(db, "SELECT pg_last_wal_replay_lsn();");
    if let Ok(out) = runner.run(&cmd).await {
        if out.exit_code == 0 {
            let val = out.stdout.trim();
            if !val.is_empty() {
                metrics.replication_lag_lsn = Some(val.to_string());
            }
        }
    }

    // Database size
    let cmd = psql_cmd(db, "SELECT pg_database_size(current_database());");
    if let Ok(out) = runner.run(&cmd).await {
        if out.exit_code == 0 {
            metrics.database_size_bytes = out.stdout.trim().parse().ok();
        }
    }

    Ok(metrics)
}

fn parse_pg_active_queries(output: &str) -> Vec<ActiveQuery> {
    // psql -t -A output: pipe-delimited columns, one row per line
    output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(4, '|').collect();
            if parts.len() == 4 {
                Some(ActiveQuery {
                    pid: parts[0].trim().to_string(),
                    state: parts[1].trim().to_string(),
                    query_start: parts[2].trim().to_string(),
                    query: parts[3].trim().to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Redis internals
// ---------------------------------------------------------------------------

fn redis_cli_cmd(db: &DatabaseConfig) -> String {
    if let Some(dsn) = &db.dsn {
        format!("redis-cli -u {} info", shell_quote(dsn))
    } else {
        let host = db.host.as_deref().unwrap_or("localhost");
        let port = db.port.unwrap_or(6379);
        format!("redis-cli -h {host} -p {port} info")
    }
}

async fn run_redis_diagnostics(
    runner: &dyn CommandRunner,
    db: &DatabaseConfig,
) -> Result<RedisMetrics> {
    let cmd = redis_cli_cmd(db);
    let out = runner.run(&cmd).await?;
    anyhow::ensure!(
        out.exit_code == 0,
        "redis-cli exited with {}",
        out.exit_code
    );
    Ok(parse_redis_info(&out.stdout))
}

fn parse_redis_info(output: &str) -> RedisMetrics {
    let mut m = RedisMetrics::default();
    for line in output.lines() {
        let line = line.trim();
        if let Some((key, val)) = line.split_once(':') {
            match key {
                "connected_clients" => m.connected_clients = val.trim().parse().ok(),
                "used_memory" => m.used_memory_bytes = val.trim().parse().ok(),
                "used_memory_human" => m.used_memory_human = Some(val.trim().to_string()),
                "keyspace_hits" => m.keyspace_hits = val.trim().parse().ok(),
                "keyspace_misses" => m.keyspace_misses = val.trim().parse().ok(),
                _ => {}
            }
        }
    }
    // Compute hit rate
    if let (Some(hits), Some(misses)) = (m.keyspace_hits, m.keyspace_misses) {
        let total = hits + misses;
        if total > 0 {
            m.hit_rate_pct = Some((hits as f64 / total as f64) * 100.0);
        }
    }
    m
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn shell_quote(s: &str) -> String {
    // Single-quote the value, escaping embedded single quotes.
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn type_label(t: &DatabaseType) -> &'static str {
    match t {
        DatabaseType::Postgres => "postgres",
        DatabaseType::Redis => "redis",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::discovery::{CommandOutput, CommandRunner};
    use anyhow::Result;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockRunner {
        responses: Mutex<HashMap<String, CommandOutput>>,
    }

    impl MockRunner {
        fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
            }
        }

        fn add(&self, cmd_contains: &str, stdout: &str) {
            self.responses.lock().unwrap().insert(
                cmd_contains.to_string(),
                CommandOutput {
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            );
        }
    }

    #[async_trait]
    impl CommandRunner for MockRunner {
        async fn run(&self, command: &str) -> Result<CommandOutput> {
            let map = self.responses.lock().unwrap();
            for (pattern, output) in map.iter() {
                if command.contains(pattern) {
                    return Ok(output.clone());
                }
            }
            Ok(CommandOutput {
                stdout: String::new(),
                stderr: "command not found".to_string(),
                exit_code: 127,
            })
        }
    }

    #[test]
    fn test_parse_pg_active_queries() {
        let output = "123|active|2026-03-19 10:00:00|SELECT 1\n456|active|2026-03-19 10:01:00|SELECT * FROM users\n";
        let queries = parse_pg_active_queries(output);
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].pid, "123");
        assert_eq!(queries[0].state, "active");
        assert_eq!(queries[1].query, "SELECT * FROM users");
    }

    #[test]
    fn test_parse_redis_info() {
        let output = "\
# Clients\r
connected_clients:42\r
# Memory\r
used_memory:1048576\r
used_memory_human:1.00M\r
# Stats\r
keyspace_hits:9000\r
keyspace_misses:1000\r
";
        let m = parse_redis_info(output);
        assert_eq!(m.connected_clients, Some(42));
        assert_eq!(m.used_memory_bytes, Some(1_048_576));
        assert_eq!(m.used_memory_human.as_deref(), Some("1.00M"));
        assert_eq!(m.keyspace_hits, Some(9000));
        assert_eq!(m.keyspace_misses, Some(1000));
        let rate = m.hit_rate_pct.unwrap();
        assert!((rate - 90.0).abs() < 0.01);
    }

    #[test]
    fn test_diagnostics_to_markdown_empty() {
        assert_eq!(diagnostics_to_markdown(&[]), "");
    }

    #[test]
    fn test_diagnostics_to_markdown_postgres() {
        let snap = DbDiagnosticSnapshot {
            name: "main-db".to_string(),
            db_type: DatabaseType::Postgres,
            metrics: DbMetrics::Postgres(PostgresMetrics {
                connection_count: Some(25),
                active_queries: vec![],
                replication_lag_lsn: None,
                database_size_bytes: Some(1_000_000),
            }),
        };
        let md = diagnostics_to_markdown(&[snap]);
        assert!(md.contains("main-db"));
        assert!(md.contains("**Connections**: 25"));
        assert!(md.contains("1000000 bytes"));
    }

    #[tokio::test]
    async fn test_fetch_postgres_diagnostics() {
        let runner = MockRunner::new();
        runner.add("pg_stat_activity;", "42\n");
        runner.add("WHERE state =", "1|active|2026-03-19|SELECT 1\n");
        runner.add("pg_last_wal_replay_lsn", "0/1234ABCD\n");
        runner.add("pg_database_size", "5000000\n");

        let dbs = vec![DatabaseConfig {
            name: "test-pg".to_string(),
            db_type: DatabaseType::Postgres,
            dsn: Some("postgresql://localhost/test".to_string()),
            host: None,
            port: None,
        }];
        let results = fetch_db_diagnostics(&runner, &dbs).await;
        assert_eq!(results.len(), 1);
        if let DbMetrics::Postgres(pg) = &results[0].metrics {
            assert_eq!(pg.connection_count, Some(42));
            assert_eq!(pg.active_queries.len(), 1);
            assert_eq!(pg.replication_lag_lsn.as_deref(), Some("0/1234ABCD"));
            assert_eq!(pg.database_size_bytes, Some(5_000_000));
        } else {
            panic!("expected postgres metrics");
        }
    }

    #[tokio::test]
    async fn test_fetch_redis_diagnostics() {
        let runner = MockRunner::new();
        runner.add(
            "redis-cli",
            "connected_clients:10\nused_memory:2048\nused_memory_human:2K\nkeyspace_hits:100\nkeyspace_misses:50\n",
        );

        let dbs = vec![DatabaseConfig {
            name: "cache".to_string(),
            db_type: DatabaseType::Redis,
            dsn: None,
            host: Some("redis.local".to_string()),
            port: Some(6379),
        }];
        let results = fetch_db_diagnostics(&runner, &dbs).await;
        assert_eq!(results.len(), 1);
        if let DbMetrics::Redis(r) = &results[0].metrics {
            assert_eq!(r.connected_clients, Some(10));
            assert_eq!(r.used_memory_bytes, Some(2048));
            let rate = r.hit_rate_pct.unwrap();
            assert!((rate - 66.66).abs() < 0.1);
        } else {
            panic!("expected redis metrics");
        }
    }

    #[test]
    fn test_shell_quote() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_build_pg_conn_args_dsn() {
        let db = DatabaseConfig {
            name: "x".into(),
            db_type: DatabaseType::Postgres,
            dsn: Some("postgresql://u:p@host/db".into()),
            host: None,
            port: None,
        };
        let args = build_pg_conn_args(&db);
        assert!(args.contains("postgresql://"));
    }

    #[test]
    fn test_build_pg_conn_args_host_port() {
        let db = DatabaseConfig {
            name: "x".into(),
            db_type: DatabaseType::Postgres,
            dsn: None,
            host: Some("db.internal".into()),
            port: Some(5433),
        };
        let args = build_pg_conn_args(&db);
        assert!(args.contains("-h db.internal"));
        assert!(args.contains("-p 5433"));
    }
}
