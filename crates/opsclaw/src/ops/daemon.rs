//! OpsClaw daemon mode — runs monitor, watch, and digest as long-lived tasks
//! alongside the ZeroClaw runtime (gateway, heartbeat, scheduler).

use anyhow::Result;
use tokio::task::JoinSet;
use tracing::{error, info};
use zeroclaw::config::Config;

use crate::ops_cli;

/// Start the OpsClaw daemon: spawns monitor loops, event watchers, periodic
/// digest generation, and the full ZeroClaw runtime (gateway, channels,
/// heartbeat, scheduler).
pub async fn start_daemon(config: &Config, host: String, port: u16) -> Result<()> {
    let targets = config.targets.as_deref().unwrap_or_default();
    if targets.is_empty() {
        info!("No targets configured — running ZeroClaw runtime only");
    } else {
        info!(
            "Starting OpsClaw daemon with {} target(s): {}",
            targets.len(),
            targets
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let mut tasks = JoinSet::new();

    // --- Monitor loop per target ---
    // Each target gets its own monitor task running at the default 300s interval.
    for t in targets {
        let target_name = t.name.clone();
        let cfg = config.clone();
        tasks.spawn(async move {
            info!("Starting monitor loop for target '{target_name}'");
            if let Err(e) =
                ops_cli::handle_monitor(&cfg, Some(target_name.clone()), 300, false).await
            {
                error!("Monitor task for '{target_name}' exited with error: {e:#}");
            }
        });
    }

    // --- Watch (event streaming) for all targets ---
    {
        let cfg = config.clone();
        tasks.spawn(async move {
            info!("Starting event watch for all targets");
            if let Err(e) = ops_cli::handle_watch(&cfg, None).await {
                error!("Watch task exited with error: {e:#}");
            }
        });
    }

    // --- Periodic digest ---
    {
        let cfg = config.clone();
        tasks.spawn(async move {
            info!("Starting periodic digest (every 24h)");
            loop {
                // Wait 24 hours between digests.
                tokio::time::sleep(tokio::time::Duration::from_secs(24 * 60 * 60)).await;

                info!("Generating scheduled digest");
                if let Err(e) = ops_cli::handle_digest(&cfg, None, 24, true).await {
                    error!("Digest generation failed: {e:#}");
                }
            }
        });
    }

    // --- ZeroClaw runtime (gateway, channels, heartbeat, scheduler) ---
    // This blocks until shutdown signal is received.
    let runtime_result = Box::pin(zeroclaw::daemon::run(config.clone(), host, port)).await;

    // ZeroClaw runtime exited (shutdown signal received) — abort all OpsClaw tasks.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}

    runtime_result
}
