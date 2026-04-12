//! OpsClaw daemon mode — runs monitor, watch, and digest as long-lived tasks
//! alongside the ZeroClaw runtime (gateway, heartbeat, scheduler).

use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::ops_cli;
use crate::ops_config::OpsConfig;

/// Start the OpsClaw daemon: spawns monitor loops, event watchers, periodic
/// digest generation, and the full ZeroClaw runtime (gateway, channels,
/// heartbeat, scheduler).
pub async fn start_daemon(
    config: &OpsConfig,
    host: String,
    port: u16,
    openshell_ctx: &crate::openshell::OpenShellContext,
) -> Result<()> {
    let projects = config.projects.as_deref().unwrap_or_default();
    if projects.is_empty() {
        info!("No projects configured — running ZeroClaw runtime only");
    } else {
        info!(
            "Starting OpsClaw daemon with {} project(s): {}",
            projects.len(),
            projects
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let mut tasks = JoinSet::new();

    // --- Monitor loop per project ---
    // Each project gets its own monitor task running at the default 300s interval.
    for t in projects {
        let target_name = t.name.clone();
        let cfg = config.clone();
        let os_ctx = openshell_ctx.clone();
        tasks.spawn(run_monitor_with_backoff(target_name, cfg, os_ctx));
    }

    // --- Watch (event streaming) for all projects ---
    {
        let cfg = config.clone();
        tasks.spawn(async move {
            info!("Starting event watch for all projects");
            if let Err(e) = ops_cli::handle_watch(&cfg, None).await {
                error!("Watch task exited with error: {e:#}");
            }
        });
    }

    // --- A2A server ---
    if let Some(a2a_config) = &config.a2a {
        if a2a_config.server.enabled {
            let server_config = a2a_config.server.clone();
            info!(
                "Starting A2A server on {}:{}",
                server_config.bind, server_config.port
            );
            tasks.spawn(async move {
                if let Err(e) = crate::tools::a2a_server::run_a2a_server(server_config).await {
                    error!("A2A server exited with error: {e:#}");
                }
            });
        }
    }

    // --- ZeroClaw runtime (gateway, channels, heartbeat, scheduler) ---
    // This blocks until shutdown signal is received.
    let runtime_result = Box::pin(zeroclaw::daemon::run(config.inner.clone(), host, port)).await;

    // ZeroClaw runtime exited (shutdown signal received) — abort all OpsClaw tasks.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}

    runtime_result
}

const MAX_FAILURES: u32 = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);

fn backoff_delay(attempt: u32) -> Duration {
    match attempt {
        1 => Duration::ZERO,
        2 => Duration::from_secs(10),
        3 => Duration::from_secs(30),
        _ => Duration::from_secs(60),
    }
}

async fn run_monitor_with_backoff(
    target: String,
    config: OpsConfig,
    openshell_ctx: crate::openshell::OpenShellContext,
) {
    let mut consecutive_failures: u32 = 0;
    let mut window_start = Instant::now();

    loop {
        info!("Starting monitor loop for project '{target}'");
        if let Err(e) =
            ops_cli::handle_monitor(&config, Some(target.clone()), 300, false, &openshell_ctx).await
        {
            error!("Monitor task for '{target}' exited with error: {e:#}");
        }

        consecutive_failures += 1;

        // Reset the failure window if enough time has passed.
        if window_start.elapsed() >= FAILURE_WINDOW {
            consecutive_failures = 1;
            window_start = Instant::now();
        }

        if consecutive_failures >= MAX_FAILURES {
            warn!("[{target}] monitor task failed {consecutive_failures} times, giving up");
            return;
        }

        let delay = backoff_delay(consecutive_failures);
        info!(
            "[{target}] monitor task exited, restarting (attempt {})...",
            consecutive_failures + 1
        );
        tokio::time::sleep(delay).await;
    }
}
