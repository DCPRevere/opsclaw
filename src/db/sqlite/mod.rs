//! SQLite repository implementations (the live/only backend — DESIGN.md
//! §7.2: one daemon, one SQLite store; no Postgres in v1).
//!
//! Uses runtime-checked `sqlx::query` (never the compile-time `query!`
//! macros) so the crate builds and tests with no DB present. The schema
//! lives in `migrations/`, applied automatically at connect time.
//!
//! Validated against the in-memory fake by the shared parity suite in
//! `tests/repo_parity.rs`, run unconditionally (SQLite needs no server, so
//! unlike gianna's Postgres-gated `pg` tests, there is no env var to set —
//! see that file's module doc).

mod access;
mod accounts;
mod approvals;
mod audit;
mod channel_state;
mod chat;
mod control;
mod incidents;
mod invites;
mod jobs;
mod push;
mod runbook_runs;
mod tokens;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Executor, SqlitePool};
use std::str::FromStr;

use crate::{Error, Result};

#[derive(Clone)]
pub struct SqliteDb {
    pool: SqlitePool,
}

impl SqliteDb {
    /// Connect (creating the file if absent), set WAL mode + busy_timeout on
    /// every pooled connection, and run migrations.
    pub async fn connect(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(path)
            .map_err(|e| Error::Other(format!("sqlite connect options: {e}")))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    // WAL mode: readers don't block the writer (the scheduler
                    // ticks concurrently with HTTP reads). busy_timeout backs
                    // off internally instead of the caller seeing SQLITE_BUSY
                    // immediately under the brief write contention WAL still
                    // has (two writers racing a single-writer DB).
                    conn.execute("PRAGMA journal_mode = WAL;").await?;
                    conn.execute("PRAGMA busy_timeout = 5000;").await?;
                    conn.execute("PRAGMA foreign_keys = ON;").await?;
                    Ok(())
                })
            })
            .connect_with(opts)
            .await
            .map_err(|e| {
                tracing::error!("sqlite connect failed: {e}");
                Error::Other(format!("sqlite connect: {e}"))
            })?;

        tracing::info!("sqlite connected; running migrations");
        sqlx::migrate!("./migrations").run(&pool).await.map_err(|e| {
            tracing::error!("sqlite migration failed: {e}");
            Error::Other(format!("sqlite migrate: {e}"))
        })?;
        tracing::info!("sqlite migrations up to date");

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[async_trait::async_trait]
impl crate::db::HealthRepo for SqliteDb {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}
