//! Execution history types — data only. Persistence (a `RunbookRunRepo`) is
//! a later wave's job (see `db::mod`'s note); this module owns the shapes and
//! the success-rate math that both the DB layer and the CLI/policy will want.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{FqTarget, Principal};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ok,
    Failed,
    Skipped,
    Retried,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepOutcome {
    pub step_index: usize,
    pub status: StepStatus,
    /// Captured command output (stdout/stderr), scrubbed of secrets before
    /// it ever reaches this struct — scrubbing happens at the policy choke
    /// point, not here (this module has no IO).
    pub output: String,
}

/// One execution of a runbook against a target. This is the single canonical
/// type — the persistence layer (`db::RunbookRunRepo`) stores and returns
/// exactly this, rather than a parallel row struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookRun {
    pub id: Uuid,
    /// The runbook's title (stable identity for grouping/success-rate; the
    /// file path can move, the title is what an operator recognizes).
    pub runbook: String,
    pub target: FqTarget,
    /// Who ran it (audit/attribution). `None` on a run constructed purely for
    /// in-memory success-rate math before persistence assigns one.
    pub principal: Option<Principal>,
    pub started_at: DateTime<Utc>,
    /// Set once the run completes; `None` while in flight.
    pub finished_at: Option<DateTime<Utc>>,
    pub steps: Vec<StepOutcome>,
}

impl RunbookRun {
    /// A run "succeeded" if it has at least one step outcome and none of them
    /// failed. An empty `steps` list (nothing ran yet) counts as not
    /// successful — an in-flight or aborted-before-any-step run must not
    /// inflate the success rate.
    pub fn succeeded(&self) -> bool {
        !self.steps.is_empty() && self.steps.iter().all(|s| s.status != StepStatus::Failed)
    }
}

/// Fraction of `runs` that succeeded, in `[0.0, 1.0]`. `0.0` on an empty
/// slice (no data yet is treated as "no evidence of success", not "perfect"
/// or "NaN") — callers surfacing this in the UI should distinguish "0 runs"
/// from "0% success" using `runs.is_empty()` themselves if that matters.
pub fn success_rate(runs: &[RunbookRun]) -> f64 {
    if runs.is_empty() {
        return 0.0;
    }
    let succeeded = runs.iter().filter(|r| r.succeeded()).count();
    succeeded as f64 / runs.len() as f64
}

/// Minimum recorded runs before success-rate signals mean anything — one
/// unlucky run must not flag a runbook nobody has exercised yet.
pub const MIN_RUNS_FOR_SIGNAL: usize = 3;

/// Rate at or below which a runbook is surfaced for review (brief §7:
/// "low scorers surfaced for review").
pub const LOW_SUCCESS_THRESHOLD: f64 = 0.5;

/// True when a runbook has enough runs to be meaningful AND its success rate
/// is at or below `threshold` — the surfacing rule for "needs review". Fewer
/// than [`MIN_RUNS_FOR_SIGNAL`] runs never trips this.
pub fn low_success(runs: &[RunbookRun], threshold: f64) -> bool {
    if runs.len() < MIN_RUNS_FOR_SIGNAL {
        return false;
    }
    success_rate(runs) <= threshold
}

/// The same rule as [`low_success`], but over an already-aggregated
/// `(total, rate)` pair — the shape `db::RunbookRunRepo::success_rate`
/// returns — with the canonical [`LOW_SUCCESS_THRESHOLD`] baked in, so the
/// two surfacing sites (`opsclaw-cli runbook list` and the `runbook_list`
/// tool) share one rule instead of each re-deriving threshold and sample
/// size.
pub fn low_success_from_rate(total_runs: i64, rate: f64) -> bool {
    total_runs >= MIN_RUNS_FOR_SIGNAL as i64 && rate <= LOW_SUCCESS_THRESHOLD
}

/// The review marker both surfacing sites print, e.g.
/// `[low success: 40% over 5 runs]` — one definition so the CLI listing and
/// the `runbook_list` tool output can't drift apart (the marker is what an
/// operator greps for and what the model pattern-matches on). `None` when
/// the runbook isn't a low scorer per [`low_success_from_rate`].
pub fn low_success_marker(total_runs: i64, rate: f64) -> Option<String> {
    low_success_from_rate(total_runs, rate)
        .then(|| format!("[low success: {:.0}% over {} runs]", rate * 100.0, total_runs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(statuses: &[StepStatus]) -> RunbookRun {
        RunbookRun {
            id: Uuid::new_v4(),
            runbook: "DLQ backlog triage".into(),
            target: FqTarget::new("remundo", "prod", "web-1"),
            principal: None,
            started_at: Utc::now(),
            finished_at: None,
            steps: statuses
                .iter()
                .enumerate()
                .map(|(i, s)| StepOutcome { step_index: i, status: *s, output: String::new() })
                .collect(),
        }
    }

    #[test]
    fn succeeded_true_when_all_ok() {
        let r = run(&[StepStatus::Ok, StepStatus::Ok]);
        assert!(r.succeeded());
    }

    #[test]
    fn succeeded_true_with_skipped_and_retried_but_no_failure() {
        let r = run(&[StepStatus::Ok, StepStatus::Retried, StepStatus::Skipped]);
        assert!(r.succeeded());
    }

    #[test]
    fn succeeded_false_on_any_failure() {
        let r = run(&[StepStatus::Ok, StepStatus::Failed]);
        assert!(!r.succeeded());
    }

    #[test]
    fn succeeded_false_when_no_steps_ran() {
        let r = run(&[]);
        assert!(!r.succeeded());
    }

    #[test]
    fn success_rate_empty_is_zero() {
        assert_eq!(success_rate(&[]), 0.0);
    }

    #[test]
    fn success_rate_math() {
        let runs = vec![
            run(&[StepStatus::Ok]),
            run(&[StepStatus::Ok]),
            run(&[StepStatus::Failed]),
            run(&[StepStatus::Ok]),
        ];
        assert!((success_rate(&runs) - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn success_rate_all_failed_is_zero() {
        let runs = vec![run(&[StepStatus::Failed]), run(&[StepStatus::Failed])];
        assert_eq!(success_rate(&runs), 0.0);
    }

    #[test]
    fn success_rate_all_succeeded_is_one() {
        let runs = vec![run(&[StepStatus::Ok]), run(&[StepStatus::Ok])];
        assert_eq!(success_rate(&runs), 1.0);
    }

    #[test]
    fn low_success_requires_minimum_sample_size() {
        // Two failing runs is a 0% rate but below the minimum sample —
        // must not flag yet.
        let runs = vec![run(&[StepStatus::Failed]), run(&[StepStatus::Failed])];
        assert!(!low_success(&runs, 0.5));
    }

    #[test]
    fn low_success_flags_once_threshold_and_sample_size_met() {
        let runs =
            vec![run(&[StepStatus::Failed]), run(&[StepStatus::Failed]), run(&[StepStatus::Ok])];
        // 1/3 = 0.333... <= 0.5 threshold, and sample size (3) meets minimum.
        assert!(low_success(&runs, 0.5));
    }

    #[test]
    fn low_success_false_above_threshold() {
        let runs = vec![run(&[StepStatus::Ok]), run(&[StepStatus::Ok]), run(&[StepStatus::Failed])];
        // 2/3 = 0.666... > 0.5 threshold.
        assert!(!low_success(&runs, 0.5));
    }

    #[test]
    fn low_success_boundary_is_inclusive() {
        let runs = vec![
            run(&[StepStatus::Ok]),
            run(&[StepStatus::Ok]),
            run(&[StepStatus::Failed]),
            run(&[StepStatus::Failed]),
        ];
        // Exactly 0.5 success rate, threshold 0.5 -> flagged (<=).
        assert!(low_success(&runs, 0.5));
    }

    #[test]
    fn low_success_from_rate_mirrors_the_slice_rule() {
        // Below the minimum sample: never flagged, however bad the rate.
        assert!(!low_success_from_rate(2, 0.0));
        // At the minimum sample with a low rate: flagged.
        assert!(low_success_from_rate(3, 0.4));
        // Inclusive boundary, same as `low_success`.
        assert!(low_success_from_rate(4, 0.5));
        // Healthy rate: not flagged.
        assert!(!low_success_from_rate(10, 0.9));
    }

    #[test]
    fn low_success_marker_formats_percent_and_run_count() {
        assert_eq!(low_success_marker(5, 0.4).as_deref(), Some("[low success: 40% over 5 runs]"));
        assert_eq!(low_success_marker(10, 0.9), None);
        assert_eq!(low_success_marker(2, 0.0), None, "below minimum sample: no marker");
    }
}
