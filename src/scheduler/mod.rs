//! The heartbeat (Wave 3). Ported from gianna's scheduler
//! (`src/scheduler/mod.rs`, `src/scheduler/jobs.rs`,
//! `src/db/{postgres,memory}/control.rs`):
//!
//! - Supervised loops with panic-catch-respawn ([`supervise`]) — one bad tick
//!   or a wedged phase must not silently kill proactive behaviour until the
//!   next deploy. The fast (jobs) loop and the external dead-man loop run
//!   independently so a slow scan job can never delay the dead-man ping, and
//!   `tick`'s phases are each wrapped so one failing phase never starves the
//!   others (gianna's v0.6.4 starvation regression).
//! - Watchdog ([`heartbeat_status`], [`tick_lag`]): an atomic bumped at tick
//!   START (liveness, not success), with separate lag ("alive but slow") and
//!   stall ("dead") alerts, each rate-limited via `ControlRepo::claim`.
//!   Thresholds derive from the CURRENT tick interval ([`SchedulerHandle`]),
//!   not a constant — gianna hardcoded 60s/5min/10min; opsclaw's tick interval
//!   is itself adaptive, so the thresholds must scale with it.
//! - Adaptive tick interval ([`SchedulerHandle::tighten`]/[`SchedulerHandle::relax`]):
//!   a relaxed base cadence, tightened while an incident is active or a
//!   hypothesis is unconfirmed. A simple nudge-counter policy, not gianna's
//!   fixed 60s — other modules (incidents, Wave 3) hold the handle and call
//!   `tighten`/`relax` as incidents open/resolve.
//! - Claim-before-send exactly-once ([`jobs::fire_one_job`]): gianna's
//!   `digest_sends` claim generalized to `ControlRepo::claim(kind, key, at)`,
//!   keyed per (job, occurrence) — atomically claimed BEFORE compose/send,
//!   crash-safe, dedup across ticks.
//! - `Job::advance` (in `domain::job`, already ported) fast-forwards past
//!   missed occurrences; exhausted one-shots retire themselves.
//! - Bounded compose concurrency (a semaphore) + retry/backoff/dead-letter
//!   with a 24h give-up window (`JobRepo::record_job_failure` /
//!   `job_failure_state` / `clear_job_failure`, already ported) — gianna once
//!   re-ran a failed compose every 60s forever.
//! - Seeded scan jobs ([`jobs::seed_default_scan_jobs`]): prompt-from-const-
//!   at-fire-time via `Payload::ScanRoutine` (already frozen in
//!   `domain::job`) — see `AGENTS.md`: unlike gianna's `SystemPrompt`, opsclaw
//!   has no per-job override, so a const edit reaches every seeded job on its
//!   very next tick, always.
//! - External dead-man heartbeat ([`ping_deadman`]): every tick, a
//!   fire-and-forget POST to `config.daemon.deadman_url`, non-fatal on
//!   failure, rate-limited failure logging.
//!
//! ## What's new (no gianna analog)
//!
//! `agent/`, `incidents/`, and the `policy` engine are later-wave stubs
//! (fail-closed) at the time this module lands, so "compose a job's prompt"
//! is seamed behind [`jobs::JobComposer`] rather than a hard dependency on
//! the (not yet built) agent loop — mirrors how `policy::PolicyExecute` was
//! seamed for the same reason (see that module's doc comment). `SchedulerDeps`
//! wires a `JobComposer` impl the same way `ToolCtx` wires a `PolicyExecute`
//! impl; the real agent-backed composer swaps in when Wave 3's agent loop
//! lands, with no change to this module's shape.

pub mod jobs;
#[cfg(test)]
mod tests;

pub use jobs::{
    JobComposer, NoopComposer, RECORD_SCAN_PROMPT, resolved_prompt, seed_default_scan_jobs,
};

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use chrono::{DateTime, Utc};

use crate::Result;
use crate::channels::Channel;
use crate::config::Config;
use crate::db::{ControlRepo, JobRepo};

/// Everything a scheduler tick needs. Analogous to gianna's `AppState`, but
/// scoped to exactly what this module touches — `db` and `channel` are
/// trait objects so tests wire fakes (`db::memory::InMemoryDb`,
/// `channels::RecordingChannel`) with no real backend.
#[derive(Clone)]
pub struct SchedulerDeps {
    pub jobs: Arc<dyn JobRepo>,
    pub control: Arc<dyn ControlRepo>,
    pub channel: Arc<dyn Channel>,
    pub composer: Arc<dyn JobComposer>,
    pub config: Arc<Config>,
}

/// Bumped at tick START (liveness, not success) — the dead-man's switch the
/// watchdog reads. A module-level default lives on [`SchedulerHandle`] rather
/// than a bare static (gianna's `LAST_TICK_DURATION_MS`/`last_scheduler_tick`
/// were `AppState` fields for the same reason: a static can't be reset
/// between tests, a handle can be constructed fresh per test).
#[derive(Clone)]
pub struct SchedulerHandle {
    last_tick_ms: Arc<AtomicI64>,
    last_tick_duration_ms: Arc<AtomicI64>,
    /// Current tick interval in milliseconds — the base the watchdog derives
    /// lag/stall thresholds from. Adaptive: `tighten`/`relax` move it: see
    /// module doc "Adaptive tick interval".
    interval_ms: Arc<AtomicU64>,
    base_interval_ms: u64,
    /// How many open callers currently want a tightened cadence (incidents,
    /// unconfirmed hypotheses). >0 => tightened; back to 0 => relaxed. A
    /// counter rather than a bool so two independent callers (e.g. two open
    /// incidents) don't have the second's `relax()` prematurely widen the
    /// interval while the first is still active.
    tighten_count: Arc<AtomicU64>,
}

/// A tick slower than `interval * LAG_MULTIPLE` pages the lag watchdog —
/// "alive but slow" (a loop whose every tick takes minutes stays live, since
/// the heartbeat keeps bumping, yet proactive work runs persistently late).
/// 5x mirrors gianna's ratio (5min lag threshold over a 60s cadence).
const LAG_MULTIPLE: i64 = 5;
/// A heartbeat older than `interval * STALL_MULTIPLE` pages the stall
/// watchdog — "dead" (deadlock, wedged await, dead task). 10x mirrors
/// gianna's ratio (10min stall threshold over a 60s cadence).
const STALL_MULTIPLE: i64 = 10;

impl SchedulerHandle {
    /// `base_interval_ms` is the relaxed cadence — the interval in force with
    /// no tighten calls outstanding.
    pub fn new(base_interval_ms: u64) -> Self {
        SchedulerHandle {
            last_tick_ms: Arc::new(AtomicI64::new(0)),
            last_tick_duration_ms: Arc::new(AtomicI64::new(0)),
            interval_ms: Arc::new(AtomicU64::new(base_interval_ms.max(1))),
            base_interval_ms: base_interval_ms.max(1),
            tighten_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The tick interval currently in force.
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms.load(Ordering::Relaxed)
    }

    pub fn interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.interval_ms())
    }

    /// Request a tightened cadence (an incident opened, a hypothesis is
    /// unconfirmed): halves the interval, floored at 1s so a caller can never
    /// drive the loop into a busy-spin. Reference-counted — call `relax` once
    /// per `tighten` when the reason clears; the interval only widens back
    /// once every tightener has relaxed.
    pub fn tighten(&self) {
        self.tighten_count.fetch_add(1, Ordering::Relaxed);
        self.recompute_interval();
    }

    /// Release one prior `tighten` call. A `relax` with no matching prior
    /// `tighten` is a no-op (the counter is saturating, never goes negative).
    pub fn relax(&self) {
        let _ = self
            .tighten_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| Some(c.saturating_sub(1)));
        self.recompute_interval();
    }

    fn recompute_interval(&self) {
        let tightened = self.tighten_count.load(Ordering::Relaxed) > 0;
        let new_interval =
            if tightened { (self.base_interval_ms / 2).max(1000) } else { self.base_interval_ms };
        self.interval_ms.store(new_interval, Ordering::Relaxed);
    }

    /// Record tick START — call before any phase work, so a slow phase reads
    /// as lag, not a stall (gianna's ordering lesson).
    pub fn mark_tick_start(&self, now: DateTime<Utc>) {
        self.last_tick_ms.store(now.timestamp_millis(), Ordering::Relaxed);
    }

    /// Record how long the just-completed tick took, whether it errored or
    /// not — a tick that ran long AND errored is still lag worth surfacing.
    pub fn mark_tick_duration(&self, duration: std::time::Duration) {
        self.last_tick_duration_ms.store(duration.as_millis() as i64, Ordering::Relaxed);
    }

    /// Pure lag check: `Some(duration_ms)` when the last completed tick took
    /// longer than `interval * LAG_MULTIPLE`, else `None` (including before
    /// the first tick, duration 0).
    pub fn lag(&self) -> Option<i64> {
        let dur = self.last_tick_duration_ms.load(Ordering::Relaxed);
        let threshold = self.interval_ms() as i64 * LAG_MULTIPLE;
        (dur > threshold).then_some(dur)
    }

    /// Pure stall check against `now_ms`: `Some((last_tick_ms, age_ms))` when
    /// the loop has ticked at least once AND the heartbeat is older than
    /// `interval * STALL_MULTIPLE`, else `None`.
    pub fn stall(&self, now_ms: i64) -> Option<(i64, i64)> {
        let last = self.last_tick_ms.load(Ordering::Relaxed);
        if last == 0 {
            return None; // never ticked (fresh boot): not a stall yet
        }
        let age = now_ms - last;
        let threshold = self.interval_ms() as i64 * STALL_MULTIPLE;
        (age > threshold).then_some((last, age))
    }

    /// The heartbeat health an operator sees — reads the SAME cell `stall`
    /// does, so an admin view can never disagree with the alert.
    pub fn heartbeat_status(&self, now_ms: i64) -> HeartbeatStatus {
        let last = self.last_tick_ms.load(Ordering::Relaxed);
        if last == 0 {
            return HeartbeatStatus::Booting;
        }
        if self.stall(now_ms).is_some() {
            HeartbeatStatus::Stalled
        } else {
            HeartbeatStatus::Healthy
        }
    }

    /// True iff at least `interval_ms()` has elapsed since tick start was
    /// last recorded (or the loop has never ticked). The fast loop's
    /// supervisor wakes on a short fixed grain (`SUPERVISE_GRANULARITY`) so a
    /// `tighten()` takes effect promptly, but must not fire `tick()` on
    /// every one of those wakes — this is the gate that turns "wake often"
    /// into "tick on the ADAPTIVE cadence".
    fn due(&self, now_ms: i64) -> bool {
        let last = self.last_tick_ms.load(Ordering::Relaxed);
        last == 0 || now_ms - last >= self.interval_ms() as i64
    }
}

/// The heartbeat health an operator sees (gianna's `HeartbeatStatus`
/// verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatStatus {
    /// The loop has never ticked (fresh boot); not yet a stall.
    Booting,
    /// Last tick is within the stall threshold.
    Healthy,
    /// Last tick is older than the stall threshold — proactive delivery is down.
    Stalled,
}

impl HeartbeatStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HeartbeatStatus::Booting => "booting",
            HeartbeatStatus::Healthy => "healthy",
            HeartbeatStatus::Stalled => "stalled",
        }
    }
}

/// Claim kind for the watchdog's own rate-limited alerts, so a lasting
/// stall/lag pages once per window rather than every tick — reuses
/// `ControlRepo::claim` (crash-safe, already exercised by the parity suite)
/// instead of inventing a second in-memory rate limiter.
const CLAIM_KIND_STALL_ALERT: &str = "scheduler_stall_alert";
const CLAIM_KIND_LAG_ALERT: &str = "scheduler_lag_alert";
const CLAIM_KIND_DEADMAN_FAILURE: &str = "scheduler_deadman_failure";
/// How often a lasting condition may re-page: the claim key folds in a
/// coarse time bucket (see `rate_limit_bucket`) so the SAME condition, still
/// true `WINDOW` later, claims a fresh key and pages again.
const ALERT_RATE_LIMIT_WINDOW: chrono::Duration = chrono::Duration::hours(6);

/// Bucket `at` into a stable window-sized string so `ControlRepo::claim`
/// naturally rate-limits repeated alerts of the same kind: the first call in
/// a window claims and pages, every subsequent call in the SAME window loses
/// the claim and stays silent, and the next window's call claims fresh.
fn rate_limit_bucket(at: DateTime<Utc>, window: chrono::Duration) -> String {
    let window_secs = window.num_seconds().max(1);
    (at.timestamp() / window_secs).to_string()
}

/// Run one scheduler pass: fire any due jobs, ping the external dead-man
/// receiver, and run hourly housekeeping. Pure of timing (the caller supplies
/// `now_utc`) so it is testable without a real clock.
pub async fn tick(
    deps: &SchedulerDeps,
    handle: &SchedulerHandle,
    now_utc: DateTime<Utc>,
) -> Result<()> {
    // Heartbeat: record liveness BEFORE any phase work (see SchedulerHandle
    // doc) — a slow phase must read as lag, not a stall.
    handle.mark_tick_start(now_utc);

    // Each phase is independent: a failure in one must NOT skip the others,
    // or one bad subsystem starves every other proactive behaviour. `phase!`
    // awaits and logs (never propagates) a phase error.
    macro_rules! phase {
        ($name:literal, $fut:expr) => {
            if let Err(e) = $fut.await {
                tracing::error!(concat!("scheduler phase ", $name, " failed: {}"), e);
            }
        };
    }

    phase!("run_due_jobs", jobs::run_due_jobs(deps, now_utc));
    phase!("ping_deadman", ping_deadman(deps, now_utc));

    if now_utc.timestamp() % 3600 < deps.config.daemon.tick_seconds as i64
        && let Err(e) = deps.control.prune_housekeeping(now_utc).await
    {
        tracing::warn!("housekeeping prune failed: {e}");
    }

    Ok(())
}

/// Fire-and-forget POST to the configured external dead-man receiver
/// (DESIGN.md §4: "external dead-man heartbeat"). Non-fatal: a failure never
/// fails the tick, and failures are logged at a rate limit (via
/// `ControlRepo::claim`) rather than every tick, so an outage at the receiver
/// doesn't flood logs. A no-op (`Ok`) when no URL is configured — plain,
/// unauthenticated HTTP, matching every widely-used dead-man-switch receiver
/// (healthchecks.io and workalikes accept a bare GET/POST to a per-check
/// URL).
async fn ping_deadman(deps: &SchedulerDeps, now_utc: DateTime<Utc>) -> Result<()> {
    let Some(url) = &deps.config.daemon.deadman_url else {
        return Ok(());
    };
    // A short client timeout so a wedged receiver can never hold up the tick
    // (dead-man pings are best-effort liveness, not a phase worth blocking
    // other work on) — bounded well under any sane tick interval.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| crate::Error::other(format!("deadman client build: {e}")))?;
    if let Err(e) = client.post(url).send().await {
        let bucket = rate_limit_bucket(now_utc, ALERT_RATE_LIMIT_WINDOW);
        if deps.control.claim(CLAIM_KIND_DEADMAN_FAILURE, &bucket, now_utc).await.unwrap_or(true) {
            tracing::warn!(url, error = %e, "dead-man heartbeat ping failed");
        }
    }
    Ok(())
}

/// Spawn the always-on scheduler: the fast (jobs + dead-man) loop under a
/// panic supervisor, plus the stall/lag watchdog spawned alongside it so it
/// survives the fast loop's own respawns.
///
/// `shutdown` is cancelled on SIGTERM (deploy). The loop observes it: an
/// in-flight tick RUNS TO COMPLETION (a job claimed-but-not-sent must not be
/// abandoned mid-tick — claim-before-send would lose it), but no NEW tick
/// starts after cancellation. `tracker` lets the server's shutdown drain wait
/// (bounded) for the loop to settle before the process exits.
pub fn spawn(
    deps: SchedulerDeps,
    handle: SchedulerHandle,
    shutdown: tokio_util::sync::CancellationToken,
    tracker: &tokio_util::task::TaskTracker,
) {
    spawn_watchdog(deps.clone(), handle.clone(), shutdown.clone(), tracker);
    supervise(
        "scheduler",
        (deps, handle.clone()),
        shutdown,
        tracker,
        |(deps, handle)| async move {
            // The supervisor wakes every SUPERVISE_GRANULARITY so a `tighten()`
            // is observed promptly, but only actually ticks once the ADAPTIVE
            // interval has elapsed — otherwise a tightened (sub-base) interval
            // would still only fire at the stale base cadence, and an untightened
            // base interval would fire far too often.
            if !handle.due(Utc::now().timestamp_millis()) {
                return;
            }
            let started = std::time::Instant::now();
            let res = tick(&deps, &handle, Utc::now()).await;
            handle.mark_tick_duration(started.elapsed());
            if let Err(e) = res {
                tracing::warn!("scheduler tick error: {e}");
            }
        },
    );
}

/// Spawn the stall/lag watchdog on its own supervised loop — checked every
/// second so a short adaptive (tightened) interval still gets timely alerts,
/// independent of the fast loop's own cadence.
fn spawn_watchdog(
    deps: SchedulerDeps,
    handle: SchedulerHandle,
    shutdown: tokio_util::sync::CancellationToken,
    tracker: &tokio_util::task::TaskTracker,
) {
    supervise(
        "scheduler-watchdog",
        (deps, handle),
        shutdown,
        tracker,
        |(deps, handle)| async move {
            let now = Utc::now();
            if let Some((last, age)) = handle.stall(now.timestamp_millis()) {
                let bucket = rate_limit_bucket(now, ALERT_RATE_LIMIT_WINDOW);
                if deps.control.claim(CLAIM_KIND_STALL_ALERT, &bucket, now).await.unwrap_or(true) {
                    tracing::error!(
                        last_tick_ms = last,
                        stalled_for_ms = age,
                        "scheduler STALL: the fast loop has not ticked within its watchdog threshold"
                    );
                    deps.channel
                        .send(crate::channels::OutboundMessage {
                            operator: None,
                            body: format!(
                                "Scheduler stalled: the fast loop has not ticked in {}s. \
                             Scan jobs and the dead-man heartbeat are NOT running. \
                             Check the app logs for a wedged phase or a dead task.",
                                age / 1000
                            ),
                        })
                        .await
                        .ok();
                }
            }
            if let Some(dur) = handle.lag() {
                let bucket = rate_limit_bucket(now, ALERT_RATE_LIMIT_WINDOW);
                if deps.control.claim(CLAIM_KIND_LAG_ALERT, &bucket, now).await.unwrap_or(true) {
                    tracing::warn!(
                        tick_ms = dur,
                        "scheduler LAG: last tick took far longer than the current interval"
                    );
                    deps.channel
                        .send(crate::channels::OutboundMessage {
                            operator: None,
                            body: format!(
                                "Scheduler running late: the last tick took {}s against a {}s \
                             cadence. The loop is alive but proactive delivery is persistently \
                             late — check per-phase timings in the app logs.",
                                dur / 1000,
                                handle.interval().as_secs()
                            ),
                        })
                        .await
                        .ok();
                }
            }
        },
    );
    // NB: the watchdog's own supervise() loop runs on a fixed 1s cadence
    // (SUPERVISE_WATCHDOG_INTERVAL below), independent of the scheduler's
    // adaptive interval — the watchdog must sample often enough to catch a
    // tightened (sub-base) cadence's own stall/lag promptly.
}

/// Run `body` every [`SUPERVISE_GRANULARITY`] for the life of the process,
/// under a panic supervisor: a panic inside the inner loop is caught and the
/// loop respawned after 5s, so a single bad iteration can't silently end
/// this schedule until the next deploy. `name` tags the log line that
/// announces a respawn.
///
/// Ported from gianna's `scheduler::supervise` (`src/scheduler/mod.rs`),
/// generalized from gianna's fixed 60s wake to a short fixed grain: the fast
/// loop's `body` closure self-gates on [`SchedulerHandle::due`] (the
/// ADAPTIVE interval) so a `tighten()` takes effect within one grain rather
/// than only after a respawn, and the watchdog (which has no adaptive
/// interval of its own) samples on the same short grain so it catches a
/// tightened cadence's stall/lag promptly too.
fn supervise<S, F, Fut>(
    name: &'static str,
    state: S,
    shutdown: tokio_util::sync::CancellationToken,
    tracker: &tokio_util::task::TaskTracker,
    body: F,
) where
    S: Clone + Send + 'static,
    F: Fn(S) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    tracker.spawn(async move {
        loop {
            if shutdown.is_cancelled() {
                tracing::info!("{name} loop stopping (shutdown)");
                return;
            }
            let st = state.clone();
            let body = body.clone();
            let loop_shutdown = shutdown.clone();
            let run = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = loop_shutdown.cancelled() => break,
                        _ = tokio::time::sleep(SUPERVISE_GRANULARITY) => {}
                    }
                    body(st.clone()).await;
                }
            });
            match run.await {
                Ok(()) => {
                    tracing::info!("{name} loop drained and stopped (shutdown)");
                    return;
                }
                Err(_) if shutdown.is_cancelled() => return,
                Err(e) => {
                    tracing::error!("{name} loop died ({e}); respawning in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });
}

/// The supervisor's own wake granularity — NOT the scheduler's tick interval.
/// [`SchedulerHandle::due`] gates the fast loop's actual `tick()` firing
/// against the adaptive interval, so this constant only bounds how quickly a
/// `tighten()` takes effect and how often the watchdog samples — both want
/// to be short, not the multi-minute base cadence.
const SUPERVISE_GRANULARITY: std::time::Duration = std::time::Duration::from_secs(1);
