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

    // Kept out of `router(state)`'s move so the post-HTTP drain below can
    // still reach the chat seam — `ChatHandler::drain` is how the daemon
    // waits for memory's detached retains (see `drain_background_work`).
    let chat = state.chat.clone();

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
    // tick, and memory's in-flight detached retains) a BOUNDED window to
    // settle — past the budget we log the shortfall and exit anyway, so a
    // wedged task can never hold a deploy open forever. DESIGN.md §3:
    // "~20s"; document that the systemd/docker stop timeout must exceed
    // this.
    const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
    tracker.close();
    let (tasks_drained, retains_drained) =
        drain_background_work(&tracker, chat.as_ref(), DRAIN_BUDGET).await;
    if tasks_drained && retains_drained {
        tracing::info!("opsclaw shut down cleanly (background work drained)");
    } else {
        tracing::warn!(
            tasks_drained,
            retains_drained,
            "shutdown drain hit the {}s budget; exiting with work still in flight",
            DRAIN_BUDGET.as_secs()
        );
    }
    Ok(())
}

/// The post-HTTP shutdown drain, in one place so it is testable without a
/// bound socket: waits for the tracker's long-lived background tasks (the
/// scheduler loop, channel inbound), THEN for the chat seam's detached
/// work — memory's fire-and-forget retains (`Memory::retain_detached`
/// spawns onto Memory's own TaskTracker, which every dispatch path shares
/// through `DispatchDeps.memory`; `ChatHandler::drain` is the seam that
/// waits on it, DESIGN §3 memory: "a `TaskTracker` drains in-flight retains
/// on SIGTERM so a deploy doesn't drop a just-learned fact"). Both phases
/// share ONE wall-clock `budget` (the second gets whatever the first left
/// over) so the documented ~20s bound stays truthful — two full budgets in
/// sequence would quietly double the stop window a deploy must allow.
/// Returns (tasks_drained, retains_drained); the caller logs, never blocks
/// past the budget.
async fn drain_background_work(
    tracker: &tokio_util::task::TaskTracker,
    chat: &dyn crate::channels::ChatHandler,
    budget: std::time::Duration,
) -> (bool, bool) {
    let started = std::time::Instant::now();
    let tasks_drained = tokio::time::timeout(budget, tracker.wait()).await.is_ok();
    // `drain` with a zero budget still reports honestly (true iff nothing
    // was in flight), so an exhausted first phase can't hang the second.
    let retains_drained = chat.drain(budget.saturating_sub(started.elapsed())).await;
    (tasks_drained, retains_drained)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::ChatHandler;
    use crate::domain::Principal;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Records the budget `drain` was handed and returns a scripted result —
    /// the direct observable of the shutdown path's memory-drain contract
    /// without booting a daemon.
    struct ProbeChat {
        drained_ok: bool,
        seen_budget: Mutex<Option<std::time::Duration>>,
    }

    #[async_trait]
    impl ChatHandler for ProbeChat {
        async fn chat(
            &self,
            _principal: Principal,
            _speaker: &str,
            _message: &str,
        ) -> crate::Result<String> {
            unreachable!("drain tests never chat")
        }
        async fn drain(&self, timeout: std::time::Duration) -> bool {
            *self.seen_budget.lock().unwrap() = Some(timeout);
            self.drained_ok
        }
    }

    #[tokio::test]
    async fn drain_waits_for_tasks_then_hands_chat_the_remaining_budget() {
        let tracker = tokio_util::task::TaskTracker::new();
        tracker.spawn(tokio::time::sleep(std::time::Duration::from_millis(50)));
        tracker.close();
        let chat = ProbeChat { drained_ok: true, seen_budget: Mutex::new(None) };

        let (tasks, retains) =
            drain_background_work(&tracker, &chat, std::time::Duration::from_secs(5)).await;

        assert!(tasks && retains);
        // The chat/memory drain gets the REMAINDER of the one shared budget,
        // never a fresh window — two full budgets in sequence would quietly
        // double the stop timeout a deploy must allow.
        let seen = chat.seen_budget.lock().unwrap().expect("chat drain must be called");
        assert!(seen < std::time::Duration::from_secs(5), "not a fresh budget: {seen:?}");
        assert!(seen > std::time::Duration::from_secs(3), "not starved either: {seen:?}");
    }

    #[tokio::test]
    async fn drain_reports_an_undrained_retain_not_masking_it() {
        let tracker = tokio_util::task::TaskTracker::new();
        tracker.close();
        let chat = ProbeChat { drained_ok: false, seen_budget: Mutex::new(None) };

        let (tasks, retains) =
            drain_background_work(&tracker, &chat, std::time::Duration::from_millis(100)).await;

        assert!(tasks);
        assert!(!retains, "a retain that missed the budget must surface in the shutdown log");
    }

    #[tokio::test]
    async fn drain_is_bounded_even_when_a_task_hangs_and_still_asks_the_chat_seam() {
        let tracker = tokio_util::task::TaskTracker::new();
        tracker.spawn(std::future::pending::<()>());
        tracker.close();
        let chat = ProbeChat { drained_ok: true, seen_budget: Mutex::new(None) };

        let before = std::time::Instant::now();
        let (tasks, _retains) =
            drain_background_work(&tracker, &chat, std::time::Duration::from_millis(100)).await;

        assert!(!tasks, "a wedged task must time out, not hold the deploy open");
        assert!(before.elapsed() < std::time::Duration::from_secs(2));
        // The exhausted budget leaves ~nothing for the memory drain, but it
        // is still ASKED (zero-budget drain reports honestly) — skipping it
        // would silently drop the retains_drained signal from the log.
        assert!(chat.seen_budget.lock().unwrap().is_some());
    }
}
