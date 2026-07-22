//! The Axum server: full router (auth, incidents, approvals, status, e-stop,
//! audit, invites, remote-CLI, webhooks), the scheduler loop, and graceful
//! shutdown. Ported from gianna's `src/http/server.rs`: HTTP drains first
//! (axum's own graceful shutdown), THEN background work gets a bounded
//! (~20s, DESIGN §3) window to settle — an in-flight scheduler tick's
//! claimed-but-not-sent job must not be abandoned mid-write.

use super::routes::router;
use super::state::AppState;
use crate::Result;

/// Bind and serve until SIGINT/SIGTERM. Spawns the scheduler loop alongside
/// HTTP; both share ONE `CancellationToken`/`TaskTracker` shutdown pair so
/// a deploy drains real work rather than killing it mid-flight.
pub async fn run(state: AppState) -> Result<()> {
    let listen = state.config.daemon.listen.clone();

    // The token lives on `state` (created at boot) so boot-time wiring can
    // hand it to components that take it at construction (Telegram's
    // long-poll) — this function is still the ONLY place it gets cancelled.
    let shutdown = state.shutdown.clone();
    let tracker = tokio_util::task::TaskTracker::new();

    crate::scheduler::spawn(
        scheduler_deps(&state),
        state.scheduler.clone(),
        shutdown.clone(),
        &tracker,
    );

    // Inbound chat: listeners + consumer over every listening channel
    // (no-op when the list is empty — fakes mode, or no Telegram token).
    crate::channels::inbound::spawn(
        state.listen_channels.clone(),
        state.chat.clone(),
        shutdown.clone(),
        &tracker,
    );

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| crate::Error::Config(format!("cannot bind {listen}: {e}")))?;
    tracing::info!(%listen, version = crate::version(), "opsclaw listening");

    let bg_shutdown = shutdown.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            // HTTP is draining; tell background work to stop starting new
            // work too.
            bg_shutdown.cancel();
        })
        .await
        .map_err(|e| crate::Error::other(e.to_string()))?;

    // HTTP has drained. Give background work (the scheduler's in-flight
    // tick) a BOUNDED window to settle — past the budget we log the
    // shortfall and exit anyway, so a wedged task can never hold a deploy
    // open forever. DESIGN.md §3: "~20s"; document that the systemd/docker
    // stop timeout must exceed this.
    const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
    tracker.close();
    let drained = tokio::time::timeout(DRAIN_BUDGET, tracker.wait()).await.is_ok();
    if drained {
        tracing::info!("opsclaw shut down cleanly (background work drained)");
    } else {
        tracing::warn!(
            "shutdown drain hit the {}s budget; exiting with work still in flight",
            DRAIN_BUDGET.as_secs()
        );
    }
    Ok(())
}

/// Build the scheduler's dependency bundle from `AppState` — a narrower
/// view (`scheduler::SchedulerDeps` needs only `JobRepo`/`ControlRepo`, a
/// channel, a composer, and config), not the whole `AllRepos` surface.
/// `composer` is `scheduler::NoopComposer` until the agent-loop integration
/// wires a real one (same "seam, not a hard dependency" reasoning as
/// `http::webhook::IngestAlert` — see that module's doc comment).
pub(crate) fn scheduler_deps(state: &AppState) -> crate::scheduler::SchedulerDeps {
    crate::scheduler::SchedulerDeps {
        jobs: state.repos.clone(),
        control: state.repos.clone(),
        incidents: state.repos.clone(),
        approvals: state.repos.clone(),
        channel: state.channel.clone(),
        named_channels: state.named_channels.clone(),
        composer: state.composer.clone(),
        config: state.config.clone(),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received; draining");
}
