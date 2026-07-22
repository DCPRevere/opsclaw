//! Fire due jobs. Ported from gianna's `src/scheduler/jobs.rs`
//! (`run_due_jobs`, `fire_one_job`, `job_retry_backoff`,
//! `record_and_triage_failure`, `payload_compose_prompt`,
//! `seed_default_jobs_in`) — the generic per-household digest engine
//! generalized to opsclaw's single-tenant scan-job engine: no household
//! scoping, no quiet-hours/daily-cap persona gating (opsclaw is an SRE
//! agent, not a companion app), and `Payload::ScanRoutine` (already frozen
//! in `domain::job`) replaces gianna's `Payload::SystemPrompt` — see
//! `AGENTS.md` on why a const edit here reaches every seeded job immediately
//! (opsclaw has no per-job hand-edit fallback to preserve).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::SchedulerDeps;
use crate::Result;
use crate::channels::OutboundMessage;
use crate::domain::{Job, Payload, Schedule};

/// Seams "compose a job's prompt into a result string" behind a trait —
/// gianna's `run_due_jobs` called straight into the agent loop
/// (`state.agent.for_job_run()`), but opsclaw's agent loop is a later-wave
/// stub (see `agent/mod.rs`) at the time this module lands. Mirrors how
/// `policy::PolicyExecute` was seamed for the same "not built yet" reason
/// (see that module's doc comment) — the real agent-backed composer swaps in
/// with no change to `fire_one_job`'s shape.
#[async_trait]
pub trait JobComposer: Send + Sync {
    /// Compose the body to send for a `Prompt`/`ScanRoutine` job. `Ok(None)`
    /// means "ran fine but produced nothing to send" (treated like gianna's
    /// empty-reply case: logged, not an error, not a failure to retry).
    async fn compose(
        &self,
        job: &Job,
        prompt: &str,
        now_utc: DateTime<Utc>,
    ) -> Result<Option<String>>;
}

/// The fail-closed default: every compose "succeeds" with nothing to send.
/// Never a failure — the point is to prove the claim/advance/dead-letter
/// scaffolding works with no agent wired in, not to fabricate output when
/// there is nothing behind this seam.
pub struct NoopComposer;

#[async_trait]
impl JobComposer for NoopComposer {
    async fn compose(
        &self,
        _job: &Job,
        _prompt: &str,
        _now_utc: DateTime<Utc>,
    ) -> Result<Option<String>> {
        Ok(None)
    }
}

/// How many due jobs compose concurrently within one tick. Bounds compose
/// work so jobs clustered at the same tick don't stack serially and delay
/// the dead-man ping (the v0.6.4 starvation shape gianna's module doc
/// describes). A small pool — enough to hide provider latency, not so wide
/// it floods the LLM.
const JOB_COMPOSE_CONCURRENCY: usize = 4;

/// Hard ceiling on a single job's compose. One wedged job (a provider stall,
/// a pathological tool loop) must not hold its concurrency slot open
/// indefinitely — past this the compose is abandoned and the occurrence is
/// treated as "produced nothing" (released, retried with backoff). Sized for
/// the agent-backed composer: a scan is a full diagnose cycle (up to
/// MAX_STEPS_HEARTBEAT tool calls against a live cluster), which routinely
/// needs several minutes — 90s aborted every real scan. The jobs lane is
/// separate from the alerts lane, so a long compose no longer delays the
/// dead-man ping; this only bounds true wedges.
const COMPOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Give up on a failing one-shot job occurrence after this long. Past this
/// the occurrence is dead-lettered (the one-shot disabled) and the operator
/// alerted, so a permanently failing job neither bleeds compose work forever
/// nor dies invisibly.
const JOB_GIVE_UP: chrono::Duration = chrono::Duration::hours(24);

/// Backoff before the next retry of a failed job occurrence, by attempt
/// count: 1 -> next tick (retry soon), 2 -> +5min, 3+ -> +30min. Bounds the
/// ~1440 full compose turns/day a deterministically-failing one-shot used to
/// burn down to a handful, while still retrying promptly for a transient
/// blip.
fn job_retry_backoff(attempts: i64) -> chrono::Duration {
    match attempts {
        ..=1 => chrono::Duration::zero(),
        2 => chrono::Duration::minutes(5),
        _ => chrono::Duration::minutes(30),
    }
}

/// Claim kind for the per-occurrence exactly-once claim (`ControlRepo::claim`).
const CLAIM_KIND_JOB_FIRE: &str = "job_fire";
/// Claim kind for the dead-letter alert (rate-limited separately from the
/// stall/lag watchdog alerts).
const CLAIM_KIND_JOB_DEADLETTER: &str = "job_deadletter";
/// Claim kind for the sustained-failure alert (fires once at the 3rd
/// attempt, before the 24h give-up).
const CLAIM_KIND_JOB_FAILING: &str = "job_failing";

/// Fire every due job, with BOUNDED CONCURRENCY (a semaphore + `join_all`) so
/// jobs clustered at the same tick don't stack their composes one-behind-
/// another inside the tick — see `JOB_COMPOSE_CONCURRENCY`. Each job's full
/// lifecycle (claim, compose, send, advance) lives in `fire_one_job`; a
/// per-job error is logged, not propagated — one bad job must not starve the
/// rest of the batch.
pub(super) async fn run_due_jobs(deps: &SchedulerDeps, now_utc: DateTime<Utc>) -> Result<()> {
    let due = deps.jobs.due_jobs(now_utc).await?;
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(JOB_COMPOSE_CONCURRENCY));
    let runs = due.into_iter().map(|mut job| {
        let sem = sem.clone();
        async move {
            let _permit = sem.acquire_owned().await.expect("semaphore not closed");
            if let Err(e) = fire_one_job(deps, &mut job, now_utc).await {
                tracing::error!(job = %job.id, name = %job.name, "job fire errored: {e}");
            }
        }
    });
    futures::future::join_all(runs).await;
    Ok(())
}

/// One job's full firing lifecycle: the crash-safe per-occurrence claim,
/// compose, send, and advance. Returns `true` iff a message was actually
/// sent. Ported from gianna's `fire_one_job`; the household/access/spend/
/// quiet-hours gates gianna ran before the claim have no opsclaw analog
/// (single-tenant, no persona budget) — everything downstream of those
/// (claim, retry budget, compose timeout, dead-letter) is preserved.
async fn fire_one_job(deps: &SchedulerDeps, job: &mut Job, now_utc: DateTime<Utc>) -> Result<bool> {
    let mut sent = false;

    // Per-occurrence identity — NOT per calendar day — so a sub-daily
    // interval job isn't collapsed to one fire a day. The CLAIM itself
    // (crash-safe exactly-once) is taken further down, right before the
    // actual send, keyed by THIS `claim_key` plus the current attempt number
    // (see that call site): `ControlRepo::claim` has no matching `unclaim`
    // in the frozen contract (gianna's `digest_sends` claim had a natural
    // composite-key DELETE for `clear_digest_sent`; opsclaw's claim table is
    // a flat (kind, key) set with no delete method), so claiming on the bare
    // occurrence key BEFORE compose (gianna's exact ordering) would
    // permanently lock out every retry after a real failure, not just guard
    // against a crash-replay of one attempt. Composing is side-effect-free
    // and safe to repeat regardless; folding the attempt number into the
    // SEND claim gives exactly-once per attempt (a crash mid-send can't
    // re-send) while still letting a genuinely failed attempt be retried as
    // a fresh attempt. Flagged as a deliberate divergence from gianna's
    // claim-before-compose ordering in the port report.
    let occurrence = job.next_run_at.unwrap_or(now_utc);
    let claim_key = format!("{}:{}", job.id, occurrence.timestamp());

    // Retry budget (one-shots only — a recurring job advances regardless, so
    // a failed occurrence is once-or-never, not a re-run loop). BEFORE the
    // expensive compose, consult this occurrence's failure record: hold off
    // during the backoff window, or dead-letter once it's failed for >24h.
    if !job.schedule.is_recurring()
        && let Ok(Some(f)) = deps.jobs.job_failure_state(job.id, &claim_key).await
    {
        if now_utc >= f.first_failed_at + JOB_GIVE_UP {
            tracing::error!(
                job = %job.id, name = %job.name, attempts = f.attempts,
                "job occurrence failed for over 24h — dead-lettering (disabling one-shot)"
            );
            alert_deadletter(deps, job, f.attempts, &f.last_error, now_utc).await;
            let _ = deps.jobs.clear_job_failure(job.id, &claim_key).await;
            advance_and_save(deps, job, now_utc).await;
            return Ok(false);
        }
        if now_utc < f.last_failed_at + job_retry_backoff(f.attempts) {
            // Still inside the backoff window: don't burn another compose.
            // Stay due (no advance) — a later tick past the window retries.
            return Ok(false);
        }
    }

    let body = match &job.payload {
        Payload::Text(t) => Some(t.clone()),
        other => {
            let Some(prompt) = payload_compose_prompt(other) else {
                advance_and_save(deps, job, now_utc).await;
                return Ok(false);
            };
            // Per-compose deadline: one wedged job can't hold its
            // concurrency slot (or the tick) open forever. A timeout is
            // treated like "produced nothing" — released and retried with
            // backoff — so it flows through the same failure path below.
            match tokio::time::timeout(COMPOSE_TIMEOUT, deps.composer.compose(job, prompt, now_utc))
                .await
            {
                Ok(Ok(body)) => body,
                Ok(Err(e)) => {
                    return handle_fire_failure(
                        deps,
                        job,
                        &claim_key,
                        occurrence,
                        &format!("compose: {e}"),
                        now_utc,
                    )
                    .await;
                }
                Err(_) => {
                    tracing::warn!(
                        job = %job.id, name = %job.name, timeout_s = COMPOSE_TIMEOUT.as_secs(),
                        "job compose exceeded the per-compose timeout — abandoning this occurrence"
                    );
                    return handle_fire_failure(
                        deps,
                        job,
                        &claim_key,
                        occurrence,
                        "compose exceeded the per-compose timeout",
                        now_utc,
                    )
                    .await;
                }
            }
        }
    };

    if let Some(body) = body.filter(|b| !b.trim().is_empty()) {
        // Crash-safe exactly-once claim, taken right before the one
        // side-effecting step (the send) — see the comment above `claim_key`
        // on why the claim sits here rather than before compose. The key
        // folds in the current attempt number (from the failure-budget
        // record, 0 if this occurrence never failed before): exactly-once
        // guards a CRASH-REPLAY of this same attempt (a restart mid-send
        // must not re-send), while a GENUINE retry after a real send
        // failure — a new attempt number — gets a fresh claim rather than
        // being permanently locked out (there is no `unclaim` to release
        // the prior attempt's claim; see the comment on `claim_key`).
        let attempt = deps
            .jobs
            .job_failure_state(job.id, &claim_key)
            .await
            .ok()
            .flatten()
            .map(|f| f.attempts)
            .unwrap_or(0);
        let send_claim_key = format!("{claim_key}:{attempt}");
        match deps.control.claim(CLAIM_KIND_JOB_FIRE, &send_claim_key, now_utc).await {
            Ok(true) => {} // first claim for THIS attempt — proceed to send
            Ok(false) => {
                // Already sent this exact attempt (crash-replay or a second
                // scheduler instance racing this one).
                advance_and_save(deps, job, now_utc).await;
                return Ok(false);
            }
            Err(e) => {
                tracing::error!(job = %job.id, "fire claim failed (proceeding; duplicate possible): {e}");
            }
        }
        match deps
            .channel
            .send(OutboundMessage { operator: None, body: body.clone(), meta: None })
            .await
        {
            Ok(()) => {
                sent = true;
                tracing::info!(job = %job.id, name = %job.name, body_len = body.len(), "job fired");
                // A successful send resets the retry budget for this
                // occurrence (no-op if it never failed).
                let _ = deps.jobs.clear_job_failure(job.id, &claim_key).await;
            }
            Err(e) => {
                return handle_fire_failure(
                    deps,
                    job,
                    &claim_key,
                    occurrence,
                    &format!("send: {e}"),
                    now_utc,
                )
                .await;
            }
        }
    } else {
        tracing::info!(job = %job.id, name = %job.name, "job fired but produced nothing");
        // A ONE-SHOT prompt job that produced nothing (a transient compose
        // error, or a legitimately empty result) must NOT advance — advance()
        // disables a Once job, losing it forever with its per-occurrence
        // claim already burned. Release the claim and stay due so it retries
        // with backoff, exactly like the failure path; a give-up
        // dead-letters it. Recurring jobs just wait for the next run.
        if !job.schedule.is_recurring() {
            return handle_fire_failure(
                deps,
                job,
                &claim_key,
                occurrence,
                "compose produced nothing",
                now_utc,
            )
            .await;
        }
    }

    advance_and_save(deps, job, now_utc).await;
    Ok(sent)
}

/// Shared failure path for a fire that composed nothing usable or whose send
/// failed: record the failure against the retry budget (bumping `attempts`)
/// and triage (backoff vs give-up). A give-up lets the one-shot fall through
/// to advance (disabling it — dead-letter); a retry keeps a one-shot due
/// (returns without advancing). Recurring jobs always advance regardless.
///
/// No claim to release here: a COMPOSE failure (or a produced-nothing
/// result) never claimed at all — the claim is taken only immediately
/// before the send, keyed by attempt number (see that call site), so the
/// NEXT attempt (this call bumps `attempts`, which changes the send claim
/// key) gets a fresh claim automatically with nothing to release. A SEND
/// failure's claim (for the attempt that just failed) is likewise left in
/// place — it's now a stale, unreachable key (the next attempt claims under
/// a different key), not a lock blocking the retry.
async fn handle_fire_failure(
    deps: &SchedulerDeps,
    job: &mut Job,
    claim_key: &str,
    _occurrence: DateTime<Utc>,
    error: &str,
    now_utc: DateTime<Utc>,
) -> Result<bool> {
    let gave_up = record_and_triage_failure(deps, job, claim_key, error, now_utc).await;
    if !job.schedule.is_recurring() && !gave_up {
        return Ok(false);
    }
    advance_and_save(deps, job, now_utc).await;
    Ok(false)
}

/// Record a failed job occurrence and decide its fate: give up (dead-letter)
/// once the failure is older than [`JOB_GIVE_UP`], else keep it for a
/// backed-off retry. Returns true if this occurrence was GIVEN UP. Alerts on
/// give-up and on the first crossing into repeated failure.
async fn record_and_triage_failure(
    deps: &SchedulerDeps,
    job: &Job,
    occurrence_key: &str,
    error: &str,
    now_utc: DateTime<Utc>,
) -> bool {
    let f = match deps.jobs.record_job_failure(job.id, occurrence_key, error, now_utc).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(job = %job.id, "job failure record write failed (retry budget unavailable): {e}");
            return false;
        }
    };
    let give_up = now_utc >= f.first_failed_at + JOB_GIVE_UP;
    if give_up {
        tracing::error!(
            job = %job.id, name = %job.name, attempts = f.attempts,
            "job occurrence failed for over 24h — giving up (dead-lettered)"
        );
        alert_deadletter(deps, job, f.attempts, error, now_utc).await;
        let _ = deps.jobs.clear_job_failure(job.id, occurrence_key).await;
        return true;
    }
    if f.attempts >= 3 {
        alert_failing(deps, job, f.attempts, error, now_utc).await;
    }
    tracing::warn!(job = %job.id, name = %job.name, attempts = f.attempts, "job occurrence failed (retrying with backoff): {error}");
    false
}

async fn alert_deadletter(
    deps: &SchedulerDeps,
    job: &Job,
    attempts: i64,
    error: &str,
    now_utc: DateTime<Utc>,
) {
    let key = job.id.to_string();
    if !deps.control.claim(CLAIM_KIND_JOB_DEADLETTER, &key, now_utc).await.unwrap_or(true) {
        return; // already alerted this job's dead-letter (a job id fires this once, ever)
    }
    deps.channel
        .send(OutboundMessage {
            operator: None,
            meta: None,
            body: format!(
                "Scheduled job '{}' failed to compose or send for over 24h ({attempts} attempts) \
                 and has been given up on. Last error: {error}.",
                job.name
            ),
        })
        .await
        .ok();
}

async fn alert_failing(
    deps: &SchedulerDeps,
    job: &Job,
    attempts: i64,
    error: &str,
    now_utc: DateTime<Utc>,
) {
    // Bucketed by job + coarse time window so a job stuck failing every
    // backoff interval pages again after the window rather than once ever.
    let bucket = super::rate_limit_bucket(now_utc, chrono::Duration::hours(6));
    let key = format!("{}:{bucket}", job.id);
    if !deps.control.claim(CLAIM_KIND_JOB_FAILING, &key, now_utc).await.unwrap_or(true) {
        return;
    }
    deps.channel
        .send(OutboundMessage {
            operator: None,
            meta: None,
            body: format!(
                "Scheduled job '{}' has failed {attempts} times and is retrying with backoff. \
                 Last error: {error}.",
                job.name
            ),
        })
        .await
        .ok();
}

async fn advance_and_save(deps: &SchedulerDeps, job: &mut Job, now: DateTime<Utc>) {
    job.advance(now);
    match deps.jobs.update(job).await {
        Ok(updated) => *job = updated,
        // A version Conflict is EXPECTED, not a fault: a concurrent operator
        // edit moved the row, so the edit wins and this advance is skipped.
        // The job is re-read fresh on the next tick.
        Err(crate::error::Error::Conflict(_)) => {
            tracing::debug!(job = %job.id, "job advance skipped — concurrent edit won (re-read next tick)");
        }
        // Any other failure re-fires the job every tick until the DB
        // recovers — loud, so the re-fire loop is visible rather than
        // mystery duplicates.
        Err(e) => {
            tracing::error!(job = %job.id, "job advance failed: {e}");
        }
    }
}

/// Seeded per-project/environment scan routine prompts. `AGENTS.md`: read
/// FRESH each tick from `resolved_prompt`/`payload_compose_prompt` — never
/// snapshotted into a `jobs` row — so editing a const here reaches every
/// unedited seeded job on its very next tick, no migration.
pub const RECORD_SCAN_PROMPT: &str = "record_scan";
// The checklist below is MANDATORY, not advisory, because a real scan
// (2026-07-22) declared a cluster healthy while six pods in one namespace
// were crash-looping at ~7,000 restarts: the model that run sampled one
// namespace and leaned on aggregate metrics (Prometheus `up`) and log
// search, neither of which surfaces a crashloop. A scan whose coverage
// depends on the model's per-run whims is not a scan.
const DEFAULT_SCAN_PROMPT: &str = "Run a full health scan of this target. The following checks are MANDATORY every scan, in \
     this order, before any deeper digging:\n\
     1. WORKLOAD SWEEP — enumerate workload state across the WHOLE target (for kubernetes: \
     pods across ALL namespaces), and flag anything crash-looping, restarting excessively, \
     failing to pull images, stuck initializing/terminating, or not ready. Aggregate metrics \
     and log searches do NOT substitute for this sweep — a crash-looping pod can look healthy \
     in both.\n\
     2. RESOURCE PRESSURE — CPU, memory, and disk headroom, flagging anything saturated or \
     trending toward exhaustion.\n\
     3. FAULT SIGNALS — elevated error rates and log lines indicating a fault, using the \
     target's configured metrics/log resources.\n\
     Corroborate any single weak signal before treating it as a finding (an app health \
     endpoint proves only that its own process loop is alive) — never open an incident on one \
     weak signal alone. A LONG-STANDING fault is still a fault: report it with its age; do not \
     dismiss it as pre-existing. End the report by stating what was checked (namespaces/areas \
     covered), so a reader can see coverage, not just conclusions.";

/// Resolve a routine key to its prompt TEXT from the code const. Unknown keys
/// (a stale seeded row referencing a routine that no longer exists) resolve
/// to `None` rather than panicking — the job simply produces nothing that
/// tick, logged, not a crash.
pub fn system_routine_prompt(routine: &str) -> Option<&'static str> {
    match routine {
        RECORD_SCAN_PROMPT => Some(DEFAULT_SCAN_PROMPT),
        _ => None,
    }
}

/// Resolve a job payload to the prompt it composes from — `None` for a
/// verbatim `Text` (the caller sends it directly, no compose step) or an
/// unknown `ScanRoutine` key.
pub(super) fn payload_compose_prompt(payload: &Payload) -> Option<&str> {
    match payload {
        Payload::Text(_) => None,
        Payload::Prompt { body } => Some(body.as_str()),
        Payload::ScanRoutine { routine } => system_routine_prompt(routine),
    }
}

/// Public alias mirroring gianna's `scheduler::resolved_prompt` — resolve a
/// job's payload to the prompt text it would compose from right now (used by
/// a later CLI/API wave to preview a seeded job's current wording).
pub fn resolved_prompt(payload: &Payload) -> Option<&str> {
    payload_compose_prompt(payload)
}

/// Seed (idempotently) the built-in per-project/environment scan job from
/// opsclaw's config, one job per (project, env, target) triple that has no
/// existing seeded job with that name yet. Ported from gianna's
/// `seed_default_jobs_in`: re-seeding REPLACES stale system jobs by name so
/// a config edit (a target renamed/added) re-times cleanly, but a job an
/// operator has since edited (no longer `system`) is left alone.
pub async fn seed_default_scan_jobs(deps: &SchedulerDeps, every_minutes: i64) -> Result<()> {
    let existing = deps.jobs.list().await?;
    let existing_system_names: std::collections::HashSet<&str> =
        existing.iter().filter(|j| j.system).map(|j| j.name.as_str()).collect();

    for project in &deps.config.projects {
        for env in &project.envs {
            for target in &env.targets {
                let name = format!("{}::{}::{}-scan", project.name, env.name, target.name);
                if existing_system_names.contains(name.as_str()) {
                    continue; // already seeded; an operator edit converts it away from `system`
                }
                let job = Job::new(
                    name,
                    Schedule::Interval { every_minutes: every_minutes.max(1) },
                    Payload::ScanRoutine { routine: RECORD_SCAN_PROMPT.to_string() },
                )
                .system();
                deps.jobs.insert(&job).await?;
            }
        }
    }
    Ok(())
}

/// The analytics-style `kind` label for a fired job's payload shape,
/// mirroring gianna's `analytics_kind` — never dumps the payload BODY.
pub fn analytics_kind(payload: &Payload) -> &'static str {
    match payload {
        Payload::Text(_) => "text",
        Payload::Prompt { .. } => "prompt",
        Payload::ScanRoutine { .. } => "scan_routine",
    }
}
