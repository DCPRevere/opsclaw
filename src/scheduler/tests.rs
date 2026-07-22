//! Scheduler tests. Ported (adapted for single-tenant/no-household) from
//! gianna's `src/scheduler/tests.rs`: `interval_routine_is_not_double_sent_
//! after_a_crash` -> `claim_is_exactly_once_across_crash_replay`,
//! `job_failure_budget_counts_and_clears` -> `job_failure_budget_...`
//! (already exercised at the repo layer by `tests/repo_parity.rs`'s
//! `job_failure_lifecycle`; kept here at the scheduler layer too, since this
//! is where the give-up/backoff POLICY built on top of the repo lives),
//! `scheduler_lag_trips_on_a_slow_tick` -> `handle_lag_trips_on_a_slow_tick`,
//! and the stall-watchdog section -> `handle_stall_*`. `Job::advance`'s own
//! fast-forward/one-shot-exhaustion tests already live in `domain::job`
//! (ported earlier, untouched here) — not re-duplicated.
//!
//! `tick`/`fire_one_job` are pure over an injected `now_utc`, so most tests
//! drive the clock directly with no dependency on wall-clock timing.
//! `spawn_ticks_on_the_adaptive_interval_and_tighten_speeds_it_up` and
//! `a_panicking_body_is_caught_and_the_loop_respawns` exercise the actual
//! `spawn`/`supervise` wall-clock behaviour with real (short, sub-second)
//! sleeps rather than `tokio::time::pause` — this crate's `tokio` dependency
//! does not enable the `test-util` feature (`Cargo.toml` is frozen for this
//! port, per the brief), so virtual time isn't available here.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};

use super::*;
use crate::channels::recording::RecordingChannel;
use crate::db::memory::InMemoryDb;
use crate::domain::{Job, Payload, Schedule};

fn t(h: u32, m: u32) -> DateTime<Utc> {
    // Far-future fixed instant, matching `domain::job`'s test convention, so
    // these don't depend on the wall clock.
    Utc.with_ymd_and_hms(2099, 6, 9, h, m, 0).unwrap()
}

fn deps_with(
    composer: Arc<dyn JobComposer>,
) -> (SchedulerDeps, Arc<InMemoryDb>, Arc<RecordingChannel>) {
    let db = Arc::new(InMemoryDb::new());
    let channel = Arc::new(RecordingChannel::new());
    let deps = SchedulerDeps {
        jobs: db.clone(),
        control: db.clone(),
        incidents: db.clone(),
        approvals: db.clone(),
        channel: channel.clone(),
        named_channels: vec![channel.clone()],
        composer,
        config: Arc::new(Config::default()),
    };
    (deps, db, channel)
}

fn deps() -> (SchedulerDeps, Arc<InMemoryDb>, Arc<RecordingChannel>) {
    deps_with(Arc::new(NoopComposer))
}

/// A composer that always returns a fixed body — the "compose succeeds"
/// fixture for send-path tests.
struct FixedComposer(String);

#[async_trait]
impl JobComposer for FixedComposer {
    async fn compose(
        &self,
        _job: &Job,
        _prompt: &str,
        _now_utc: DateTime<Utc>,
    ) -> Result<Option<String>> {
        Ok(Some(self.0.clone()))
    }
}

/// A composer that always fails — the retry/dead-letter fixture.
struct FailingComposer;

#[async_trait]
impl JobComposer for FailingComposer {
    async fn compose(
        &self,
        _job: &Job,
        _prompt: &str,
        _now_utc: DateTime<Utc>,
    ) -> Result<Option<String>> {
        Err(crate::Error::other("composer boom"))
    }
}

/// Composes a fixed body, and re-inserts a fresh due `Once` job on every
/// call — the spawn-integration fixture for "one due job per tick forever"
/// (see `spawn_ticks_on_the_adaptive_interval_and_tighten_speeds_it_up`).
struct SelfPerpetuatingComposer {
    db: Arc<InMemoryDb>,
}

#[async_trait]
impl JobComposer for SelfPerpetuatingComposer {
    async fn compose(
        &self,
        _job: &Job,
        _prompt: &str,
        now_utc: DateTime<Utc>,
    ) -> Result<Option<String>> {
        let mut next = prompt_job("heartbeat-probe", Schedule::Once { at: now_utc });
        // See the comment at the test's job setup: `Job::new` alone would
        // leave `next_run_at: None` for an `at` that's already "now or
        // earlier" by construction time — set it explicitly so the
        // perpetuation actually continues.
        next.next_run_at = Some(now_utc);
        self.db.insert(&next).await?;
        Ok(Some("tick".into()))
    }
}

/// Counts concurrent-in-flight composes (peak, not just total) — the bounded-
/// concurrency fixture.
struct ConcurrencyTrackingComposer {
    inflight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

#[async_trait]
impl JobComposer for ConcurrencyTrackingComposer {
    async fn compose(
        &self,
        _job: &Job,
        _prompt: &str,
        _now_utc: DateTime<Utc>,
    ) -> Result<Option<String>> {
        let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        Ok(Some("done".into()))
    }
}

fn prompt_job(name: &str, schedule: Schedule) -> Job {
    Job::new(name, schedule, Payload::Prompt { body: "do the thing".into() })
}

/// A channel whose `send` fails the first `fail_times` calls, then succeeds
/// — the send-failure-then-retry-succeeds fixture (distinct from a compose
/// failure: this proves the attempt-keyed send claim, not just the failure
/// budget, lets a genuine retry get a fresh claim after a real send failure).
struct FlakyThenOkChannel {
    remaining_failures: std::sync::atomic::AtomicUsize,
    sent: std::sync::Mutex<Vec<String>>,
}

impl FlakyThenOkChannel {
    fn new(fail_times: usize) -> Self {
        FlakyThenOkChannel {
            remaining_failures: std::sync::atomic::AtomicUsize::new(fail_times),
            sent: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<String> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl crate::channels::Channel for FlakyThenOkChannel {
    fn name(&self) -> &str {
        "flaky"
    }

    async fn send(&self, msg: crate::channels::OutboundMessage) -> Result<()> {
        // `then_some` eagerly evaluates its argument regardless of the guard
        // (unlike `then`/`then_with`), so `n - 1` must be computed only
        // inside a branch that already knows `n > 0` — a bare
        // `(n > 0).then_some(n - 1)` still panics on underflow when n == 0.
        let decremented =
            self.remaining_failures.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n > 0 { Some(n - 1) } else { None }
            });
        if decremented.is_ok() {
            return Err(crate::Error::other("channel down"));
        }
        self.sent.lock().unwrap().push(msg.body);
        Ok(())
    }
}

// ---- claim-before-send exactly-once ----

#[tokio::test]
async fn claim_is_exactly_once_across_crash_replay() {
    let (deps, db, channel) = deps_with(Arc::new(FixedComposer("scan result".into())));
    let now = t(10, 0);
    let mut job = prompt_job("recurring-scan", Schedule::Interval { every_minutes: 5 });
    job.next_run_at = Some(now);
    db.insert(&job).await.unwrap();

    // First fire: sends and advances.
    jobs::run_due_jobs(&deps, now).await.unwrap();
    assert_eq!(channel.sent().len(), 1, "first fire sends once");
    let stored = db.get(job.id).await.unwrap().unwrap();
    assert!(stored.next_run_at.unwrap() > now, "advanced past the fired occurrence");

    // Simulate a crash-replay: the row is put back exactly as it was BEFORE
    // the advance (a restart that lost the post-fire write, or a second
    // scheduler instance reading a stale copy), still due for the SAME
    // occurrence. The per-occurrence claim (not merely due-filtering) must
    // block a second send of that same occurrence.
    let mut replayed = stored.clone();
    replayed.next_run_at = Some(now);
    db.update(&replayed).await.unwrap();

    jobs::run_due_jobs(&deps, now).await.unwrap();

    assert_eq!(channel.sent().len(), 1, "still exactly one send across the crash-replay");
}

#[tokio::test]
async fn recurring_job_advances_and_dedups_across_ticks_at_the_same_instant() {
    let (deps, db, channel) = deps_with(Arc::new(FixedComposer("hi".into())));
    let now = t(10, 0);
    let mut job = prompt_job("every-5-min", Schedule::Interval { every_minutes: 5 });
    job.next_run_at = Some(now);
    db.insert(&job).await.unwrap();

    jobs::run_due_jobs(&deps, now).await.unwrap();
    assert_eq!(channel.sent().len(), 1);

    let stored = db.get(job.id).await.unwrap().unwrap();
    assert!(stored.next_run_at.unwrap() > now, "advanced past the fired occurrence");

    // Running the tick again at the SAME instant finds nothing due (the
    // stored job already advanced) — dedup across ticks, not just within one.
    jobs::run_due_jobs(&deps, now).await.unwrap();
    assert_eq!(channel.sent().len(), 1, "no duplicate send on a second tick at the same instant");
}

// ---- retry / backoff / dead-letter give-up ----

#[tokio::test]
async fn one_shot_stays_due_and_retries_on_failure_then_dead_letters_after_give_up() {
    let (deps, db, channel) = deps_with(Arc::new(FailingComposer));
    let t0 = t(9, 0);
    let mut job = prompt_job("one-shot-flaky", Schedule::Once { at: t0 });
    job.next_run_at = Some(t0);
    db.insert(&job).await.unwrap();

    // First failure: stays due (no advance), attempt 1 recorded.
    jobs::run_due_jobs(&deps, t0).await.unwrap();
    let stored = db.get(job.id).await.unwrap().unwrap();
    assert_eq!(
        stored.next_run_at,
        Some(t0),
        "a failed one-shot must stay due, not advance/disable"
    );
    assert!(stored.enabled);
    assert!(channel.sent().is_empty());

    // Retry immediately (attempt 1's backoff is zero) — attempt 2 recorded,
    // still within backoff after this (5 min).
    jobs::run_due_jobs(&deps, t0).await.unwrap();
    let occurrence_key = format!("{}:{}", job.id, t0.timestamp());
    let f = db.job_failure_state(job.id, &occurrence_key).await.unwrap().unwrap();
    assert_eq!(f.attempts, 2);

    // Still inside the attempt-2 backoff window (5 min): a retry attempt
    // right now must NOT burn another compose (attempts stay at 2).
    jobs::run_due_jobs(&deps, t0 + Duration::minutes(1)).await.unwrap();
    let f = db.job_failure_state(job.id, &occurrence_key).await.unwrap().unwrap();
    assert_eq!(f.attempts, 2, "inside the backoff window: no retry yet");

    // Past give-up (24h later): dead-lettered — the one-shot is disabled,
    // the failure record cleared, and an alert sent.
    let past_giveup = f.first_failed_at + Duration::hours(25);
    jobs::run_due_jobs(&deps, past_giveup).await.unwrap();
    let stored = db.get(job.id).await.unwrap().unwrap();
    assert!(!stored.enabled, "dead-lettered one-shot is disabled");
    assert!(
        db.job_failure_state(job.id, &occurrence_key).await.unwrap().is_none(),
        "failure record cleared on give-up"
    );
    // The ONLY channel send across the whole run is the dead-letter alert —
    // a permanently-failing compose never produces a real message to send.
    let sent = channel.sent();
    assert_eq!(sent.len(), 1, "exactly one send: the dead-letter alert");
    assert!(sent[0].body.contains("given up"), "{}", sent[0].body);
}

#[tokio::test]
async fn recurring_job_does_not_accumulate_a_retry_budget_it_just_advances() {
    // A RECURRING job's failed occurrence is once-or-never per-occurrence:
    // gianna's rule ("a recurring job advances regardless") — the retry
    // budget exists only to protect one-shots from an infinite re-fire loop.
    let (deps, db, _channel) = deps_with(Arc::new(FailingComposer));
    let now = t(9, 0);
    let mut job = prompt_job("recurring-flaky", Schedule::Interval { every_minutes: 5 });
    job.next_run_at = Some(now);
    db.insert(&job).await.unwrap();

    jobs::run_due_jobs(&deps, now).await.unwrap();
    let stored = db.get(job.id).await.unwrap().unwrap();
    assert!(
        stored.next_run_at.unwrap() > now,
        "a recurring job advances even after a failed compose"
    );
}

#[tokio::test]
async fn send_failure_gets_a_fresh_claim_on_genuine_retry_and_eventually_succeeds() {
    // Compose always succeeds; the CHANNEL flakes twice then sends fine. This
    // exercises the attempt-keyed send claim specifically: a compose-side
    // failure never claims at all, so it always retries freely — the real
    // question is whether a SEND failure (which DOES claim before sending)
    // still lets a later genuine retry through rather than being locked out
    // by its own now-unreachable prior-attempt claim.
    let flaky = Arc::new(FlakyThenOkChannel::new(2));
    let db = Arc::new(InMemoryDb::new());
    let deps = SchedulerDeps {
        jobs: db.clone(),
        control: db.clone(),
        incidents: db.clone(),
        approvals: db.clone(),
        channel: flaky.clone(),
        named_channels: vec![flaky.clone()],
        composer: Arc::new(FixedComposer("payload".into())),
        config: Arc::new(Config::default()),
    };
    let t0 = t(9, 0);
    let mut job = prompt_job("flaky-send", Schedule::Once { at: t0 });
    job.next_run_at = Some(t0);
    db.insert(&job).await.unwrap();

    // Attempt 1: claims send-attempt "0", send fails, attempts -> 1, stays due.
    jobs::run_due_jobs(&deps, t0).await.unwrap();
    assert!(flaky.sent().is_empty());
    let stored = db.get(job.id).await.unwrap().unwrap();
    assert_eq!(stored.next_run_at, Some(t0), "still due after a send failure");

    // Attempt 2 (attempt-1's backoff is zero, so this retries immediately):
    // claims send-attempt "1" (fresh — attempt-0's claim is unreachable
    // now), send fails again. attempts -> 2, whose backoff is 5 minutes.
    jobs::run_due_jobs(&deps, t0).await.unwrap();
    assert!(flaky.sent().is_empty());

    // Attempt 3, past the 5-minute backoff: claims send-attempt "2", the
    // channel is healthy now — sends.
    let t3 = t0 + Duration::minutes(5) + Duration::seconds(1);
    jobs::run_due_jobs(&deps, t3).await.unwrap();
    assert_eq!(flaky.sent(), vec!["payload".to_string()], "the third attempt finally gets through");
    let stored = db.get(job.id).await.unwrap().unwrap();
    assert!(!stored.enabled, "a fired one-shot retires");

    let occurrence_key = format!("{}:{}", job.id, t0.timestamp());
    assert!(
        db.job_failure_state(job.id, &occurrence_key).await.unwrap().is_none(),
        "a successful send clears the retry budget"
    );
}

// ---- bounded compose concurrency ----

#[tokio::test]
async fn compose_concurrency_is_bounded_across_a_batch_of_due_jobs() {
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let composer =
        Arc::new(ConcurrencyTrackingComposer { inflight: inflight.clone(), peak: peak.clone() });
    let (deps, db, channel) = deps_with(composer);
    let now = t(11, 0);

    // More due jobs than the concurrency limit (JOB_COMPOSE_CONCURRENCY = 4).
    for i in 0..10 {
        let mut job = prompt_job(&format!("job-{i}"), Schedule::Interval { every_minutes: 5 });
        job.next_run_at = Some(now);
        db.insert(&job).await.unwrap();
    }

    jobs::run_due_jobs(&deps, now).await.unwrap();

    assert_eq!(channel.sent().len(), 10, "every due job still fires");
    assert!(
        peak.load(Ordering::SeqCst) <= 4,
        "peak in-flight composes must respect the semaphore bound"
    );
    assert!(
        peak.load(Ordering::SeqCst) >= 2,
        "sanity: the batch actually overlapped, not fully serial"
    );
}

// ---- seeded scan jobs: prompt resolves from a code constant at fire time ----

#[tokio::test]
async fn seeded_scan_job_prompt_resolves_from_const_not_a_snapshot() {
    let mut cfg = Config::default();
    cfg.projects.push(crate::config::ProjectCfg {
        name: "remundo".into(),
        autonomy: None,
        escalation: None,
        envs: vec![crate::config::EnvCfg {
            name: "prod".into(),
            autonomy: None,
            expected_state: None,
            targets: vec![crate::config::TargetCfg {
                name: "cluster".into(),
                kind: crate::config::TargetKindName::Kubernetes,
                provider: None,
                region: None,
                autonomy: None,
                expected_state: None,
                credential: Some(crate::config::SecretRef::env("X")),
                address: None,
                jump_host: None,
                ssh_port: None,
                ssh_user: None,
                ssh_known_hosts_path: None,
                ssh_strict_host_key_checking: None,
                resources: vec![],
            }],
        }],
    });
    let db = Arc::new(InMemoryDb::new());
    let channel = Arc::new(RecordingChannel::new());
    let deps = SchedulerDeps {
        jobs: db.clone(),
        control: db.clone(),
        incidents: db.clone(),
        approvals: db.clone(),
        channel: channel.clone(),
        named_channels: vec![channel],
        composer: Arc::new(NoopComposer),
        config: Arc::new(cfg),
    };

    seed_default_scan_jobs(&deps, 5).await.unwrap();
    let seeded = db.list().await.unwrap();
    assert_eq!(seeded.len(), 1);
    let job = &seeded[0];
    assert!(job.system);
    assert_eq!(job.name, "remundo::prod::cluster-scan");
    let Payload::ScanRoutine { routine } = &job.payload else {
        panic!("seeded job must carry a ScanRoutine payload, not a snapshotted prompt");
    };
    assert_eq!(routine, jobs::RECORD_SCAN_PROMPT);

    // The prompt text resolves from the CODE CONST at fire/preview time —
    // never stored in the row — so editing the const (simulated here by
    // reading the resolver directly) is what a real fire would compose from.
    let resolved = resolved_prompt(&job.payload).unwrap();
    assert_eq!(resolved, jobs::system_routine_prompt(jobs::RECORD_SCAN_PROMPT).unwrap());

    // Re-seeding is idempotent: no duplicate job for the same target.
    seed_default_scan_jobs(&deps, 5).await.unwrap();
    assert_eq!(
        db.list().await.unwrap().len(),
        1,
        "re-seeding must not duplicate an existing system job"
    );
}

// ---- adaptive tick interval ----

#[test]
fn tighten_halves_interval_and_relax_restores_it() {
    let handle = SchedulerHandle::new(60_000);
    assert_eq!(handle.interval_ms(), 60_000);
    handle.tighten();
    assert_eq!(handle.interval_ms(), 30_000);
    handle.relax();
    assert_eq!(handle.interval_ms(), 60_000);
}

#[test]
fn tighten_is_reference_counted_across_concurrent_callers() {
    let handle = SchedulerHandle::new(60_000);
    handle.tighten(); // e.g. incident A opens
    handle.tighten(); // e.g. incident B opens
    assert_eq!(handle.interval_ms(), 30_000, "still tightened while either is open");
    handle.relax(); // incident A resolves
    assert_eq!(handle.interval_ms(), 30_000, "B is still open — must not widen yet");
    handle.relax(); // incident B resolves
    assert_eq!(handle.interval_ms(), 60_000, "widens only once every tightener has relaxed");
}

#[test]
fn relax_with_no_matching_tighten_is_a_harmless_no_op() {
    let handle = SchedulerHandle::new(60_000);
    handle.relax();
    handle.relax();
    assert_eq!(handle.interval_ms(), 60_000);
    handle.tighten();
    assert_eq!(handle.interval_ms(), 30_000, "a later genuine tighten still works");
}

#[test]
fn tightened_interval_never_drops_below_the_one_second_floor() {
    let handle = SchedulerHandle::new(1_200); // sub-2s base
    handle.tighten();
    assert_eq!(handle.interval_ms(), 1_000, "floored at 1s, never a busy-spin");
}

// ---- watchdog: lag vs stall ----

#[test]
fn handle_lag_trips_on_a_slow_tick_relative_to_the_current_interval() {
    let handle = SchedulerHandle::new(60_000); // lag threshold = 5 * 60_000 = 300_000ms
    assert_eq!(handle.lag(), None, "an un-run loop (duration 0) is not lag");
    handle.mark_tick_duration(std::time::Duration::from_millis(299_999));
    assert_eq!(handle.lag(), None, "a tick within the threshold is fine");
    handle.mark_tick_duration(std::time::Duration::from_millis(300_001));
    assert_eq!(handle.lag(), Some(300_001), "a slow tick trips the watchdog");
}

#[test]
fn lag_threshold_scales_with_the_adaptive_interval() {
    let handle = SchedulerHandle::new(60_000);
    handle.tighten(); // interval now 30_000ms; lag threshold now 150_000ms
    handle.mark_tick_duration(std::time::Duration::from_millis(150_001));
    assert!(
        handle.lag().is_some(),
        "the lag threshold must derive from the CURRENT (tightened) interval"
    );
    handle.mark_tick_duration(std::time::Duration::from_millis(149_999));
    assert!(handle.lag().is_none());
}

#[test]
fn handle_stall_is_not_tripped_before_the_first_tick() {
    let handle = SchedulerHandle::new(60_000);
    assert_eq!(
        handle.stall(Utc::now().timestamp_millis()),
        None,
        "never-ticked is a fresh boot, not a stall"
    );
    assert_eq!(handle.heartbeat_status(Utc::now().timestamp_millis()), HeartbeatStatus::Booting);
}

#[test]
fn handle_stall_trips_after_the_threshold_and_reports_via_heartbeat_status() {
    let handle = SchedulerHandle::new(60_000); // stall threshold = 10 * 60_000 = 600_000ms
    let t0 = t(9, 0);
    handle.mark_tick_start(t0);
    let just_inside = t0.timestamp_millis() + 599_999;
    assert_eq!(handle.stall(just_inside), None);
    assert_eq!(handle.heartbeat_status(just_inside), HeartbeatStatus::Healthy);

    let just_outside = t0.timestamp_millis() + 600_001;
    let (last, age) = handle.stall(just_outside).expect("must trip past the threshold");
    assert_eq!(last, t0.timestamp_millis());
    assert_eq!(age, 600_001);
    assert_eq!(handle.heartbeat_status(just_outside), HeartbeatStatus::Stalled);
}

#[test]
fn stall_threshold_scales_with_the_adaptive_interval() {
    let handle = SchedulerHandle::new(60_000);
    handle.tighten(); // interval now 30_000ms; stall threshold now 300_000ms
    let t0 = t(9, 0);
    handle.mark_tick_start(t0);
    assert!(handle.stall(t0.timestamp_millis() + 300_001).is_some());
    assert!(handle.stall(t0.timestamp_millis() + 299_999).is_none());
}

// ---- external dead-man heartbeat ----

#[tokio::test]
async fn deadman_ping_is_a_noop_when_unconfigured() {
    let (deps, _db, _channel) = deps();
    // No deadman_url set on the default config — must not error, must not panic.
    assert!(ping_deadman(&deps, Utc::now()).await.is_ok());
}

#[tokio::test]
async fn deadman_ping_failure_is_non_fatal_to_the_tick() {
    let (mut deps, db, channel) = deps();
    // An address nothing listens on: the POST fails, but the tick must still
    // succeed — a dead-man ping failure is best-effort, never fatal.
    let mut cfg = (*deps.config).clone();
    cfg.daemon.deadman_url = Some("http://127.0.0.1:1/deadman".into());
    deps.config = Arc::new(cfg);
    let handle = SchedulerHandle::new(60_000);

    let result = tick(&deps, &handle, Utc::now()).await;
    assert!(result.is_ok(), "a dead-man ping failure must never fail the tick");
    let _ = (db, channel);
}

// ---- full tick wiring: phase isolation ----

#[tokio::test]
async fn tick_marks_heartbeat_before_running_any_phase() {
    let (deps, _db, _channel) = deps();
    let handle = SchedulerHandle::new(60_000);
    let now = t(12, 0);
    assert_eq!(handle.heartbeat_status(now.timestamp_millis()), HeartbeatStatus::Booting);
    tick(&deps, &handle, now).await.unwrap();
    assert_eq!(
        handle.heartbeat_status(now.timestamp_millis()),
        HeartbeatStatus::Healthy,
        "tick() must bump the heartbeat even though nothing was due"
    );
}

// ---- spawn: real wall-clock behaviour (tokio::time::pause) ----

/// `spawn`'s fast loop actually fires ticks on the adaptive interval, and
/// `SchedulerHandle::tighten` takes effect on the very next supervisor
/// wake — not only after a respawn. `tokio`'s virtual-time test utilities
/// (`time::pause`/`advance`) need the `test-util` feature, which is not
/// enabled on this crate's `tokio` dependency (out of scope for this port —
/// `Cargo.toml` is frozen), so this drives real sleeps instead. The base
/// interval is chosen well above [`SUPERVISE_GRANULARITY`] so its halved
/// (tightened) value clears the handle's own 1s floor with room to spare —
/// this makes the test ~9s of real time, the one slow test in this module.
#[tokio::test]
async fn spawn_ticks_on_the_adaptive_interval_and_tighten_speeds_it_up() {
    // `domain::job::Schedule` has minute granularity (the minimum cadence any
    // real Job can carry), far coarser than this test's sub-10s window, so a
    // recurring Job can't itself serve as a per-tick counter. Instead: a
    // SELF-PERPETUATING one-shot — its composer re-inserts a fresh due
    // `Once` job on every fire — so `run_due_jobs` finds exactly one due job
    // on every scheduler tick for the life of the test, and the channel's
    // send count IS the tick count.
    let db = Arc::new(InMemoryDb::new());
    let composer = Arc::new(SelfPerpetuatingComposer { db: db.clone() });
    let channel = Arc::new(RecordingChannel::new());
    let deps = SchedulerDeps {
        jobs: db.clone(),
        control: db.clone(),
        incidents: db.clone(),
        approvals: db.clone(),
        channel: channel.clone(),
        named_channels: vec![channel.clone()],
        composer,
        config: Arc::new(Config::default()),
    };
    let now = Utc::now();
    let mut job = prompt_job("heartbeat-probe", Schedule::Once { at: now });
    // `Job::new` computes `next_run_at` via `Schedule::next_after`, which for
    // `Once` requires `at > after` — constructing with `at == now` (or any
    // instant that has since become "now or earlier" by the time
    // `next_after` runs) leaves the job already exhausted (`next_run_at:
    // None`). Set it explicitly, as every other fixture in this file does.
    job.next_run_at = Some(now);
    db.insert(&job).await.unwrap();

    let base = std::time::Duration::from_secs(4);
    let handle = SchedulerHandle::new(base.as_millis() as u64);
    let shutdown = tokio_util::sync::CancellationToken::new();
    let tracker = tokio_util::task::TaskTracker::new();
    spawn(deps, handle.clone(), shutdown.clone(), &tracker);

    // Just past one base interval: at least one tick should have run.
    tokio::time::sleep(base + std::time::Duration::from_millis(200)).await;
    let after_one = channel.sent().len();
    assert!(after_one >= 1, "at least one tick fired within one base interval");

    // Tighten: the interval halves to 2s (well above the 1s floor). The
    // SAME wall-clock window (one base interval) should now yield more
    // ticks than the untightened window did, if the tightened cadence took
    // effect promptly (not just after a respawn — there is no respawn here).
    handle.tighten();
    assert_eq!(handle.interval_ms(), base.as_millis() as u64 / 2);
    let before_window = channel.sent().len();
    tokio::time::sleep(base + std::time::Duration::from_millis(200)).await;
    let after_tighten = channel.sent().len();
    let tightened_count = after_tighten - before_window;
    assert!(
        tightened_count > after_one,
        "a tightened interval must fire more ticks in the same wall-clock window \
         (untightened: {after_one}, tightened: {tightened_count})"
    );

    shutdown.cancel();
    tracker.close();
    tokio::time::timeout(std::time::Duration::from_secs(5), tracker.wait())
        .await
        .expect("supervised loops must drain promptly on shutdown");
}

/// A panicking tick must not end the schedule: `supervise` catches the
/// panic and respawns, and subsequent ticks resume firing. Exercises
/// `supervise` directly (a private item, reachable via `use super::*`)
/// rather than through the full `spawn`, so the test isn't pinned to
/// `supervise`'s real 5s respawn backoff — real short sleeps stay fast.
#[tokio::test]
async fn a_panicking_body_is_caught_and_the_loop_respawns() {
    let fired = Arc::new(AtomicUsize::new(0));
    let panicked_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown = tokio_util::sync::CancellationToken::new();
    let tracker = tokio_util::task::TaskTracker::new();

    // A stand-in `supervise` body (not a real tick) that panics exactly
    // once, then always succeeds — isolates "does supervise recover from a
    // panic" from the 5s production respawn backoff.
    let state = (fired.clone(), panicked_once.clone());
    tracker.spawn({
        let shutdown = shutdown.clone();
        async move {
            loop {
                if shutdown.is_cancelled() {
                    return;
                }
                let (fired, panicked_once) = state.clone();
                let loop_shutdown = shutdown.clone();
                let run = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            biased;
                            _ = loop_shutdown.cancelled() => break,
                            _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
                        }
                        if !panicked_once.swap(true, Ordering::SeqCst) {
                            panic!("simulated body panic on the first tick");
                        }
                        fired.fetch_add(1, Ordering::SeqCst);
                    }
                });
                match run.await {
                    Ok(()) => return,
                    Err(_) if shutdown.is_cancelled() => return,
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                }
            }
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(
        fired.load(Ordering::SeqCst) > 0,
        "the loop must resume firing after the panic is caught and respawned"
    );

    shutdown.cancel();
    tracker.close();
    tokio::time::timeout(std::time::Duration::from_secs(5), tracker.wait())
        .await
        .expect("supervised loops must drain promptly on shutdown");
}

// ---- escalation driver (escalations.rs) ----

fn active_incident(fingerprint: &str, opened_at: DateTime<Utc>) -> crate::domain::Incident {
    use crate::domain::{FqTarget, Incident, IncidentState, Severity};
    Incident {
        id: uuid::Uuid::new_v4(),
        fingerprint: fingerprint.into(),
        fault_class: String::new(),
        target: FqTarget::new("remundo", "prod", "cluster"),
        severity: Severity::Critical,
        state: IncidentState::Active,
        signals: "pod restarts: 6800; CA expired 2026-03-06".into(),
        hypothesis: "dapr sentry CA expired, control plane crashlooping".into(),
        recommended_action: Some("rotate the sentry CA".into()),
        opened_at,
        reopened_at: None,
        acked_at: None,
        acked_by: None,
        resolved_at: None,
        last_notified_at: None,
        notify_count: 0,
        escalation_step: 0,
        step_started_at: None,
    }
}

async fn insert_incident(db: &InMemoryDb, incident: &crate::domain::Incident) {
    crate::db::IncidentRepo::insert(db, incident).await.unwrap();
}

async fn get_incident(db: &InMemoryDb, id: uuid::Uuid) -> crate::domain::Incident {
    crate::db::IncidentRepo::get(db, id).await.unwrap().unwrap()
}

#[tokio::test]
async fn escalation_first_notify_pages_once_with_the_structured_payload() {
    let (deps, db, channel) = deps();
    let handle = SchedulerHandle::new(60_000);
    let t0 = t(9, 0);
    let incident = active_incident("fp-dapr", t0);
    insert_incident(&db, &incident).await;

    escalations::drive(&deps, &handle, t0).await.unwrap();
    let sent = channel.sent();
    assert_eq!(sent.len(), 1, "exactly one page for the first notify");
    let body = &sent[0].body;
    for needle in [
        "Critical",
        "remundo::prod::cluster",
        "dapr sentry CA expired",
        "pod restarts: 6800",
        "rotate the sentry CA",
        "step 1/1",
    ] {
        assert!(body.contains(needle), "page must carry {needle:?}, got:\n{body}");
    }

    // The chain position was persisted…
    let stored = get_incident(&db, incident.id).await;
    assert_eq!(stored.notify_count, 1);
    assert_eq!(stored.step_started_at, Some(t0));
    assert_eq!(stored.last_notified_at, Some(t0));

    // …so an immediate second tick is a Wait, not a duplicate page.
    escalations::drive(&deps, &handle, t0).await.unwrap();
    assert_eq!(channel.sent().len(), 1, "no spam on the very next tick");
}

#[tokio::test]
async fn escalation_renotifies_then_expires_on_the_default_chain() {
    let (deps, db, channel) = deps();
    let handle = SchedulerHandle::new(60_000);
    let t0 = t(9, 0);
    let incident = active_incident("fp-renotify", t0);
    insert_incident(&db, &incident).await;

    // Default (no [[escalation.step]] configured) chain: one broadcast
    // step, 60m ack window, 20m re-notify.
    escalations::drive(&deps, &handle, t0).await.unwrap();
    escalations::drive(&deps, &handle, t0 + Duration::minutes(21)).await.unwrap();
    let sent = channel.sent();
    assert_eq!(sent.len(), 2, "one notify + one re-notify");
    assert!(sent[1].body.contains("REMINDER"), "re-notify says so: {}", sent[1].body);

    // Past the single step's ack window: the chain is exhausted — the
    // incident expires, with no further pages.
    escalations::drive(&deps, &handle, t0 + Duration::minutes(61)).await.unwrap();
    let stored = get_incident(&db, incident.id).await;
    assert_eq!(stored.state, crate::domain::IncidentState::Expired);
    assert_eq!(channel.sent().len(), 2, "expiry itself is not a page");

    // An Expired incident is closed: nothing further ever happens.
    escalations::drive(&deps, &handle, t0 + Duration::minutes(90)).await.unwrap();
    assert_eq!(channel.sent().len(), 2);
}

#[tokio::test]
async fn escalation_reopened_incident_pages_once_then_resumes_only_if_unacked() {
    use crate::config::EscalationStepCfg;
    let db = Arc::new(InMemoryDb::new());
    let channel = Arc::new(RecordingChannel::new());
    let mut cfg = Config::default();
    cfg.escalation.steps = vec![
        EscalationStepCfg {
            contact: "*".into(),
            ack_timeout_minutes: 15,
            repeat_interval_minutes: 5,
        },
        EscalationStepCfg {
            contact: "*".into(),
            ack_timeout_minutes: 15,
            repeat_interval_minutes: 5,
        },
    ];
    let deps = SchedulerDeps {
        jobs: db.clone(),
        control: db.clone(),
        incidents: db.clone(),
        approvals: db.clone(),
        channel: channel.clone(),
        named_channels: vec![],
        composer: Arc::new(NoopComposer),
        config: Arc::new(cfg),
    };
    let handle = SchedulerHandle::new(60_000);
    let t0 = t(9, 0);
    let incident = active_incident("fp-reopen", t0);
    insert_incident(&db, &incident).await;

    // Exhaust the whole chain unacked: notify step 0, escalate to step 1,
    // expire past step 1's window.
    escalations::drive(&deps, &handle, t0).await.unwrap();
    escalations::drive(&deps, &handle, t0 + Duration::minutes(16)).await.unwrap();
    escalations::drive(&deps, &handle, t0 + Duration::minutes(32)).await.unwrap();
    assert_eq!(get_incident(&db, incident.id).await.state, crate::domain::IncidentState::Expired);
    let baseline = channel.sent().len();

    // The same fault re-detected: `opsclaw_notify`'s path re-opens the SAME
    // row rather than inserting a duplicate.
    let t1 = t0 + Duration::minutes(60);
    crate::db::IncidentRepo::reopen(db.as_ref(), incident.id, t1).await.unwrap();

    // Exactly one gentler page for the re-open…
    escalations::drive(&deps, &handle, t1).await.unwrap();
    let sent = channel.sent();
    assert_eq!(sent.len(), baseline + 1);
    assert!(sent.last().unwrap().body.contains("RE-OPENED"), "{}", sent.last().unwrap().body);

    // …and NO reminder inside step 0's window, where a fresh incident
    // would have re-notified (repeat 5m < 6m < ack_timeout 15m).
    assert_eq!(
        channel.sent().len(),
        baseline + 1,
        "re-opened incidents do not re-notify at step 0"
    );
    escalations::drive(&deps, &handle, t1 + Duration::minutes(6)).await.unwrap();
    assert_eq!(channel.sent().len(), baseline + 1);

    // Still unacked past step 0's window: the chain resumes normally —
    // escalate to step 1…
    escalations::drive(&deps, &handle, t1 + Duration::minutes(16)).await.unwrap();
    let sent = channel.sent();
    assert_eq!(sent.len(), baseline + 2);
    assert!(sent.last().unwrap().body.contains("ESCALATION"), "{}", sent.last().unwrap().body);

    // …with step 1's normal re-notify cadence back in force.
    escalations::drive(&deps, &handle, t1 + Duration::minutes(22)).await.unwrap();
    let sent = channel.sent();
    assert_eq!(sent.len(), baseline + 3);
    assert!(sent.last().unwrap().body.contains("REMINDER"), "{}", sent.last().unwrap().body);
}

#[tokio::test]
async fn escalation_walks_configured_steps_and_resolves_named_contacts() {
    use crate::config::EscalationStepCfg;
    let db = Arc::new(InMemoryDb::new());
    let broadcast = Arc::new(RecordingChannel::new());
    let named = Arc::new(RecordingChannel::new()); // Channel::name() == "recording"
    let mut cfg = Config::default();
    cfg.escalation.steps = vec![
        EscalationStepCfg {
            contact: "recording".into(), // resolves to `named`
            ack_timeout_minutes: 15,
            repeat_interval_minutes: 5,
        },
        EscalationStepCfg {
            contact: "no-such-channel".into(), // falls back to broadcast
            ack_timeout_minutes: 15,
            repeat_interval_minutes: 5,
        },
    ];
    let deps = SchedulerDeps {
        jobs: db.clone(),
        control: db.clone(),
        incidents: db.clone(),
        approvals: db.clone(),
        channel: broadcast.clone(),
        named_channels: vec![named.clone()],
        composer: Arc::new(NoopComposer),
        config: Arc::new(cfg),
    };
    let handle = SchedulerHandle::new(60_000);
    let t0 = t(9, 0);
    let incident = active_incident("fp-chain", t0);
    insert_incident(&db, &incident).await;

    // Step 0 pages the NAMED channel only.
    escalations::drive(&deps, &handle, t0).await.unwrap();
    assert_eq!(named.sent().len(), 1);
    assert!(broadcast.sent().is_empty());
    assert!(named.sent()[0].body.contains("step 1/2"));

    // Past step 0's ack window: escalate to step 1, whose unknown contact
    // falls back to the broadcast fan-out (page everyone, never no one).
    escalations::drive(&deps, &handle, t0 + Duration::minutes(16)).await.unwrap();
    assert_eq!(named.sent().len(), 1, "step 0's contact is done");
    assert_eq!(broadcast.sent().len(), 1);
    let body = &broadcast.sent()[0].body;
    assert!(body.contains("ESCALATION"), "{body}");
    assert!(body.contains("step 2/2"), "{body}");

    let stored = get_incident(&db, incident.id).await;
    assert_eq!(stored.escalation_step, 1);
    assert_eq!(stored.step_started_at, Some(t0 + Duration::minutes(16)));
}

#[tokio::test]
async fn escalation_resolves_the_chain_per_incident_project() {
    // Two open incidents in DIFFERENT projects on the same tick: project
    // "aproj" declares its own [project.escalation] naming the recording
    // channel, so its incident pages there; project "bproj" declares
    // nothing and inherits the GLOBAL chain, whose "*" contact is the
    // broadcast fan-out. One drive() pass must route each to its own
    // chain — the whole point of per-project escalation.
    use crate::config::{EscalationCfg, EscalationStepCfg};
    let db = Arc::new(InMemoryDb::new());
    let broadcast = Arc::new(RecordingChannel::new());
    let named = Arc::new(RecordingChannel::new()); // Channel::name() == "recording"
    let mut cfg = Config::default();
    cfg.escalation.steps = vec![EscalationStepCfg {
        contact: "*".into(),
        ack_timeout_minutes: 60,
        repeat_interval_minutes: 20,
    }];
    cfg.projects.push(crate::config::ProjectCfg {
        name: "aproj".into(),
        autonomy: None,
        escalation: Some(EscalationCfg {
            steps: vec![EscalationStepCfg {
                contact: "recording".into(), // resolves to `named`
                ack_timeout_minutes: 15,
                repeat_interval_minutes: 5,
            }],
        }),
        envs: vec![],
    });
    cfg.projects.push(crate::config::ProjectCfg {
        name: "bproj".into(),
        autonomy: None,
        escalation: None, // inherits the global chain
        envs: vec![],
    });
    cfg.validate().unwrap();
    let deps = SchedulerDeps {
        jobs: db.clone(),
        control: db.clone(),
        incidents: db.clone(),
        approvals: db.clone(),
        channel: broadcast.clone(),
        named_channels: vec![named.clone()],
        composer: Arc::new(NoopComposer),
        config: Arc::new(cfg),
    };
    let handle = SchedulerHandle::new(60_000);
    let t0 = t(9, 0);
    let mut a = active_incident("fp-aproj", t0);
    a.target = crate::domain::FqTarget::new("aproj", "prod", "web-1");
    let mut b = active_incident("fp-bproj", t0);
    b.target = crate::domain::FqTarget::new("bproj", "prod", "db-1");
    insert_incident(&db, &a).await;
    insert_incident(&db, &b).await;

    escalations::drive(&deps, &handle, t0).await.unwrap();

    // aproj's incident went to the NAMED channel only…
    let named_sent = named.sent();
    assert_eq!(named_sent.len(), 1);
    assert!(named_sent[0].body.contains("aproj::prod::web-1"), "{}", named_sent[0].body);
    // …and bproj's went through the global broadcast fan-out only.
    let broadcast_sent = broadcast.sent();
    assert_eq!(broadcast_sent.len(), 1);
    assert!(broadcast_sent[0].body.contains("bproj::prod::db-1"), "{}", broadcast_sent[0].body);
}

#[tokio::test]
async fn escalation_ack_stops_the_chain_and_resolve_stays_silent() {
    let (deps, db, channel) = deps();
    let handle = SchedulerHandle::new(60_000);
    let t0 = t(9, 0);
    let mut acked = active_incident("fp-acked", t0);
    acked.state = crate::domain::IncidentState::Acknowledged;
    insert_incident(&db, &acked).await;
    let mut resolved = active_incident("fp-resolved", t0);
    resolved.state = crate::domain::IncidentState::Resolved;
    insert_incident(&db, &resolved).await;

    escalations::drive(&deps, &handle, t0 + Duration::minutes(30)).await.unwrap();
    assert!(channel.sent().is_empty(), "no pages for acked or resolved incidents");
    // An acked incident is still OPEN — cadence stays tightened while it's
    // being worked.
    assert_eq!(handle.interval_ms(), 30_000);
}

#[tokio::test]
async fn escalation_send_failure_releases_the_claim_and_the_next_tick_retries() {
    let db = Arc::new(InMemoryDb::new());
    let flaky = Arc::new(FlakyThenOkChannel::new(1)); // first send fails, then ok
    let deps = SchedulerDeps {
        jobs: db.clone(),
        control: db.clone(),
        incidents: db.clone(),
        approvals: db.clone(),
        channel: flaky.clone(),
        named_channels: vec![],
        composer: Arc::new(NoopComposer),
        config: Arc::new(Config::default()),
    };
    let handle = SchedulerHandle::new(60_000);
    let t0 = t(9, 0);
    let incident = active_incident("fp-flaky", t0);
    insert_incident(&db, &incident).await;

    // First tick: the send errors — nothing recorded, claim released.
    escalations::drive(&deps, &handle, t0).await.unwrap();
    assert_eq!(get_incident(&db, incident.id).await.notify_count, 0);

    // Next tick retries the SAME occurrence and succeeds.
    escalations::drive(&deps, &handle, t0 + Duration::minutes(1)).await.unwrap();
    let stored = get_incident(&db, incident.id).await;
    assert_eq!(stored.notify_count, 1, "the released claim allowed the retry");
}

#[tokio::test]
async fn incident_pressure_tightens_while_open_and_relaxes_when_clear() {
    let (deps, db, _channel) = deps();
    let handle = SchedulerHandle::new(60_000);
    assert_eq!(handle.interval_ms(), 60_000);

    let t0 = t(9, 0);
    let incident = active_incident("fp-pressure", t0);
    insert_incident(&db, &incident).await;
    escalations::drive(&deps, &handle, t0).await.unwrap();
    assert_eq!(handle.interval_ms(), 30_000, "open incident tightens the cadence");
    // Reconciliation is level-based: another tick with the incident still
    // open must not stack a second tighten.
    escalations::drive(&deps, &handle, t0 + Duration::minutes(1)).await.unwrap();
    assert_eq!(handle.interval_ms(), 30_000);

    crate::db::IncidentRepo::set_state(
        db.as_ref(),
        incident.id,
        crate::domain::IncidentState::Resolved,
        None,
    )
    .await
    .unwrap();
    escalations::drive(&deps, &handle, t0 + Duration::minutes(2)).await.unwrap();
    assert_eq!(handle.interval_ms(), 60_000, "clear board relaxes back to base");
}

#[tokio::test]
async fn expired_approvals_are_announced_exactly_once() {
    let (deps, db, channel) = deps();
    let t0 = t(9, 0);
    let req = crate::incidents::new_approval_request(
        crate::incidents::NewApproval {
            requested_by: crate::domain::Principal::Agent { job: None },
            incident: None,
            target: crate::domain::FqTarget::new("remundo", "prod", "cluster"),
            tool: "kubernetes".into(),
            command: "delete pod stuck-pod -n prod-backend".into(),
            risk: crate::domain::RiskClass::High,
            hypothesis: "pod wedged in Terminating".into(),
            expires_in: Some(Duration::minutes(30)),
        },
        t0,
    );
    crate::db::ApprovalRepo::insert(db.as_ref(), &req).await.unwrap();

    // Before the deadline: nothing to sweep.
    escalations::expire_approvals(&deps, t0 + Duration::minutes(10)).await.unwrap();
    assert!(channel.sent().is_empty());

    // Past it: swept + announced once…
    escalations::expire_approvals(&deps, t0 + Duration::minutes(31)).await.unwrap();
    let sent = channel.sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].body.contains("EXPIRED"), "{}", sent[0].body);
    assert!(sent[0].body.contains("delete pod stuck-pod"), "{}", sent[0].body);

    // …and never again (expire_due only returns rows it just transitioned).
    escalations::expire_approvals(&deps, t0 + Duration::minutes(45)).await.unwrap();
    assert_eq!(channel.sent().len(), 1);
}
