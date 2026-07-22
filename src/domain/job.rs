//! Scheduled jobs — the generic recurring-prompt engine.
//!
//! A `Job` is a system-defined recurring action: a schedule plus a payload.
//! The payload is usually a natural-language PROMPT that the agent
//! re-interprets fresh each run (so "scan remundo prod every 5 minutes" is a
//! row, not code). The built-in per-project scan jobs are just seeded jobs
//! of this same machinery.
//!
//! Design follows the validated prior art (Hermes / OpenClaw / gianna):
//! schedules reduce to {once, interval, cron}; cron is the normal form; the
//! dispatcher is a polling tick that fires due jobs and advances
//! `next_run_at`; missed runs after downtime are fast-forwarded, not
//! replayed in a burst.

use chrono::{DateTime, Duration, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How often a job runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Schedule {
    /// One-shot at a specific instant.
    Once { at: DateTime<Utc> },
    /// Every `every_minutes` minutes.
    Interval { every_minutes: i64 },
    /// A standard 5-field cron expression, evaluated in `timezone` (so "0 8 * * *"
    /// means 8am local wall-clock, DST-aware). `timezone` is a typed
    /// `chrono_tz::Tz` rather than a raw String: serde round-trips it as the
    /// IANA name (e.g. "Europe/London"), so stored JSON rows are byte-identical
    /// and deserialize unchanged — but a malformed zone now fails loudly at
    /// parse time instead of silently collapsing to UTC.
    Cron { expr: String, timezone: Tz },
}

impl Schedule {
    /// True for a repeating schedule (Interval/Cron), false for a one-shot
    /// (Once). A one-shot that fails to fire must NOT be advanced past its
    /// occurrence — `advance` would return None and disable it, losing the
    /// action — so the scheduler uses this to leave it due for a retry.
    pub fn is_recurring(&self) -> bool {
        !matches!(self, Schedule::Once { .. })
    }

    /// The next run strictly after `after`. None if a one-shot is already past.
    pub fn next_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Schedule::Once { at } => (*at > after).then_some(*at),
            Schedule::Interval { every_minutes } => {
                // Duration::minutes PANICS on overflow (a ~15-digit interval), which
                // would take down any caller computing the next run. try_minutes
                // returns None instead; a value that large is never a real cadence,
                // so a missing next-run (treated as "no upcoming occurrence") is the
                // safe outcome. Clamp to >=1 as before.
                Duration::try_minutes((*every_minutes).max(1)).map(|d| after + d)
            }
            Schedule::Cron { expr, timezone } => {
                use croner::Cron;
                use std::str::FromStr;
                // `timezone` is already a typed `Tz` (validated at construction /
                // deserialization) — no fallible string parse, so a stored cron
                // job can never silently mis-fire in UTC.
                let tz: Tz = *timezone;
                let cron = Cron::from_str(expr).ok()?;
                let local_after = after.with_timezone(&tz);
                cron.find_next_occurrence(&local_after, false).ok().map(|dt| dt.with_timezone(&Utc))
            }
        }
    }

    /// True if EVERY adjacent occurrence over the next dozen fires is at least
    /// `min_minutes` apart — the job cadence floor. Walking several
    /// occurrences (not just the first gap) catches crafted multi-value crons
    /// like "0,30,35 * * * *" whose tight gap isn't the leading one. Returns
    /// false for a schedule that yields no upcoming occurrence at all.
    pub fn respects_min_gap(&self, min_minutes: i64) -> bool {
        let now = Utc::now();
        let Some(mut prev) = self.next_after(now) else { return false };
        for _ in 0..12 {
            let Some(next) = self.next_after(prev) else { break };
            if (next - prev).num_minutes() < min_minutes {
                return false;
            }
            prev = next;
        }
        true
    }
}

/// A job must not run more often than this — a cost/abuse floor for job
/// creation paths (HTTP + chat + config seeding).
pub const JOB_GAP_MINUTES_MIN: i64 = 1;
/// Ceiling on the number of jobs (single-tenant daemon, so this is a global
/// cap rather than per-household as in gianna).
pub const JOBS_MAX: usize = 500;
/// Upper bound on an interval job (~1 year in minutes). Anything larger is
/// never a real cadence; capping keeps the value well clear of the arithmetic
/// overflow that would otherwise occur when computing the next run.
pub const JOB_INTERVAL_MINUTES_MAX: i64 = 366 * 24 * 60;

impl Payload {
    /// A one-word operator-facing kind for the scheduler-health job listing:
    /// `text` | `prompt` | `scan_routine`. Never dumps the payload BODY (a
    /// prompt can be long) — just the shape.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Payload::Text(_) => "text",
            Payload::Prompt { .. } => "prompt",
            Payload::ScanRoutine { .. } => "scan_routine",
        }
    }
}

/// What a job does when it fires.
///
/// Deliberately does NOT snapshot a scan routine's prompt into the row (see
/// `AGENTS.md` — "Seeded scan-job prompts resolve from code constants at
/// fire time"): `ScanRoutine` resolves its prompt text from a code constant
/// keyed by `routine` at fire time, so editing the constant reaches every
/// unedited seeded job on its very next tick, no migration required. The
/// hand-edited variant is gianna's, verbatim: `opsclaw-cli jobs edit
/// --prompt` converts a `ScanRoutine` job to `Prompt { body }` — free text
/// the operator owns forever, never re-resolved from the const — while
/// re-seeding keeps skipping the row by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "body")]
pub enum Payload {
    /// A fixed message sent verbatim (e.g. a simple reminder).
    Text(String),
    /// A natural-language instruction the agent interprets fresh each run.
    /// An operator-authored job carries its text here.
    Prompt { body: String },
    /// A built-in per-project/environment scan routine whose prompt text
    /// lives in code (a `*_ROUTINE_PROMPT` const in the scheduler), resolved
    /// from `routine` at fire time — never snapshotted into the row.
    /// Serializes as `{"kind":"scan_routine","body":{"routine":"..."}}`; the
    /// wire string is what the seeding path writes, so keep routine keys
    /// stable — renaming one is a stored-row break.
    ScanRoutine { routine: String },
}

/// A scheduled recurring job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    /// Human name, used for "pause the remundo scan" (never an id to the operator).
    pub name: String,
    pub schedule: Schedule,
    pub payload: Payload,
    pub enabled: bool,
    /// True for a seeded per-project scan job (so re-seeding doesn't duplicate it).
    #[serde(default)]
    pub system: bool,
    pub next_run_at: Option<DateTime<Utc>>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Optimistic-concurrency token. Every persisted write bumps it; a writer
    /// updates `WHERE version = <the value it read>` so the scheduler's advance
    /// and a concurrent operator edit can't silently clobber each other (the
    /// loser of the race sees 0 rows affected and re-reads instead of
    /// overwriting).
    #[serde(default)]
    pub version: i64,
}

impl Job {
    pub fn new(name: impl Into<String>, schedule: Schedule, payload: Payload) -> Self {
        let now = Utc::now();
        let next_run_at = schedule.next_after(now);
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            schedule,
            payload,
            enabled: true,
            system: false,
            next_run_at,
            last_run_at: None,
            created_at: now,
            version: 0,
        }
    }

    pub fn system(mut self) -> Self {
        self.system = true;
        self
    }

    /// Is this job due to run at `now` (enabled and its next-run has arrived)?
    pub fn is_due(&self, now: DateTime<Utc>) -> bool {
        self.enabled && self.next_run_at.is_some_and(|n| n <= now)
    }

    /// Advance `next_run_at` past `now`, fast-forwarding over any missed runs so
    /// downtime doesn't fire a burst. Returns the new next-run (None when a
    /// one-shot is exhausted — caller should disable it).
    pub fn advance(&mut self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.last_run_at = Some(now);
        let mut next = self.schedule.next_after(now);
        // For recurring jobs, skip any occurrences already in the past (missed
        // while down) so we land on a future time, not a backlog.
        let mut guard = 0;
        while let Some(n) = next {
            if n > now || guard > 100_000 {
                break;
            }
            next = self.schedule.next_after(n);
            guard += 1;
        }
        // The step loop can exit with `next` still in the past: either the guard
        // tripped after a long downtime (an Interval is unbounded — stepping one
        // bucket at a time from a last run long ago would need millions of
        // iterations) or `next_after` returned a non-increasing value. A stale
        // past next_run_at keeps is_due() true forever → a hot loop / burst, so
        // collapse straight to the first occurrence strictly after `now`.
        if matches!(next, Some(n) if n <= now) {
            next = self.schedule.next_after(now);
        }
        self.next_run_at = next;
        if next.is_none() {
            self.enabled = false; // exhausted one-shot
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(h: u32, m: u32) -> DateTime<Utc> {
        // A far-future fixed instant so these tests don't depend on the wall clock
        // (Job::new computes next_run_at from Utc::now(); a one-shot dated in the
        // past relative to real-now would resolve to None).
        Utc.with_ymd_and_hms(2099, 6, 9, h, m, 0).unwrap()
    }

    #[test]
    fn interval_schedule_advances() {
        let s = Schedule::Interval { every_minutes: 30 };
        assert_eq!(s.next_after(t(8, 0)), Some(t(8, 30)));
    }

    #[test]
    fn once_schedule_fires_then_exhausts() {
        let s = Schedule::Once { at: t(9, 0) };
        assert_eq!(s.next_after(t(8, 0)), Some(t(9, 0)));
        assert_eq!(s.next_after(t(9, 1)), None); // already past
    }

    #[test]
    fn cron_resolves_local_wall_clock() {
        // 8am London. On 9 Jun 2026 (BST, UTC+1) -> 07:00 UTC next day.
        let s = Schedule::Cron { expr: "0 8 * * *".into(), timezone: chrono_tz::Europe::London };
        let next = s.next_after(t(10, 0)).unwrap();
        assert_eq!(next.format("%H:%M").to_string(), "07:00");
    }

    #[test]
    fn advance_fast_forwards_over_missed_runs() {
        // A daily 8am-London job that hasn't run for days: advancing from "now"
        // should land on the NEXT future 8am, not replay the backlog.
        let mut job = Job::new(
            "remundo-prod-morning-scan",
            Schedule::Cron { expr: "0 8 * * *".into(), timezone: chrono_tz::Europe::London },
            Payload::Prompt { body: "scan remundo prod".into() },
        );
        let now = t(10, 0); // mid-morning, today's 8am already passed
        let next = job.advance(now).unwrap();
        assert!(next > now);
        assert_eq!(next.format("%H:%M").to_string(), "07:00"); // tomorrow 8am London
    }

    #[test]
    fn interval_advance_lands_in_future_after_long_downtime() {
        // An Interval whose last run was long ago (here ~5 years before `now`):
        // stepping one bucket at a time from then would trip the 100k guard, and
        // leaving the guard's stale value in the PAST would keep is_due() true
        // forever (a hot loop / burst). One advance must settle on a FUTURE time.
        let mut job = Job::new(
            "ping",
            Schedule::Interval { every_minutes: 5 },
            Payload::Prompt { body: "status".into() },
        );
        // Backdate so the first next_after(last_run) is ~5 years before `now`:
        // 5 years / 5 min ≈ 525k steps, well past the 100k guard.
        job.next_run_at = Some(t(8, 0) - Duration::days(365 * 5));
        let now = t(8, 0);
        let next = job.advance(now).expect("interval never exhausts");
        assert!(next > now, "advance must not leave next_run_at in the past: {next} <= {now}");
        assert!(!job.is_due(now), "a just-advanced interval job must not still be due");
        // And it's the FIRST occurrence strictly after now, not a stale backlog point.
        assert_eq!(next, now + Duration::minutes(5));
    }

    #[test]
    fn one_shot_disables_after_firing() {
        let mut job = Job::new(
            "reminder",
            Schedule::Once { at: t(9, 0) },
            Payload::Text("disk usage check".into()),
        );
        assert!(job.is_due(t(9, 1)));
        assert!(job.advance(t(9, 1)).is_none());
        assert!(!job.enabled);
    }

    #[test]
    fn cron_timezone_serde_round_trips_as_iana_name() {
        // The typed `Tz` field must serialize to (and deserialize from) the bare
        // IANA name string — the exact shape already stored in `jobs.schedule`
        // rows — so migrating String -> Tz leaves persisted JSON byte-compatible.
        let s = Schedule::Cron { expr: "0 8 * * *".into(), timezone: chrono_tz::Europe::London };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "cron", "expr": "0 8 * * *", "timezone": "Europe/London" }),
            "serialized shape must match the existing stored-row shape"
        );

        // An EXISTING-shape payload (as written by the old String field) must
        // still deserialize — this is the stored-row compatibility guarantee.
        let stored: Schedule = serde_json::from_value(serde_json::json!({
            "kind": "cron",
            "expr": "30 7 * * *",
            "timezone": "America/New_York"
        }))
        .expect("existing-shape cron JSON must deserialize into the typed Tz field");
        assert_eq!(
            stored,
            Schedule::Cron { expr: "30 7 * * *".into(), timezone: chrono_tz::America::New_York }
        );

        // A malformed zone now fails loudly rather than silently becoming UTC.
        let bad: std::result::Result<Schedule, _> = serde_json::from_value(serde_json::json!({
            "kind": "cron",
            "expr": "0 8 * * *",
            "timezone": "Not/AZone"
        }));
        assert!(bad.is_err(), "a bad IANA name must fail deserialization, not default to UTC");
    }

    #[test]
    fn scan_routine_payload_does_not_snapshot_prompt() {
        // ScanRoutine carries only the routine key, never prompt text — the
        // resolve-from-code-constant-at-fire-time invariant (AGENTS.md).
        let p = Payload::ScanRoutine { routine: "remundo_default_scan".into() };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "scan_routine", "body": { "routine": "remundo_default_scan" } })
        );
        assert_eq!(p.kind_label(), "scan_routine");
    }

    #[test]
    fn payload_kind_label_never_leaks_prompt_body() {
        let p = Payload::Prompt { body: "a very long and possibly sensitive instruction".into() };
        assert_eq!(p.kind_label(), "prompt");
        let t = Payload::Text("also sensitive".into());
        assert_eq!(t.kind_label(), "text");
    }
}
