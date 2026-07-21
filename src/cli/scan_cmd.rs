//! `opsclaw-cli scan <target>` — one-shot diagnose cycle against a
//! configured target, on demand. The day-one validation command: exactly
//! what a seeded scan job does every interval, but NOW, for ONE target,
//! with the report printed to the terminal instead of (only) fanned out.
//!
//! Reuses the daemon's own composer seam (`AppState.composer`, the
//! agent-backed `JobComposer`) so a manual scan and a scheduled scan are
//! the same code path — heartbeat mode, deny-by-default tool subset, every
//! command through policy. The synthetic `Job` here is a VALUE handed to
//! `compose`, never inserted into the job table: a manual scan leaves no
//! schedule behind.

use chrono::Utc;
use serde::Serialize;

use crate::Result;
use crate::domain::{FqTarget, Job, Payload, Schedule};
use crate::http::AppState;

#[derive(Debug, Serialize)]
pub struct ScanOutcome {
    pub target: String,
    /// The agent's scan report — `None` when the turn genuinely produced
    /// nothing to say (same contract as a scheduled scan's compose).
    pub report: Option<String>,
}

/// The per-target manual-scan prompt: the seeded scan wording
/// (`scheduler::jobs`' default routine), scoped to one named target so the
/// model doesn't wander across the whole estate when the operator asked
/// about one thing.
fn scan_prompt(target: &FqTarget) -> String {
    format!(
        "Scan {target} for anomalies: elevated error rates, resource pressure \
         (CPU/memory/disk), crash-looping or flapping processes, and any log lines indicating \
         a fault. Corroborate any single signal before treating it as a finding (an app health \
         endpoint proves only that its own process loop is alive) — never open an incident on \
         one weak signal alone. Finish with a short report of what you checked and found."
    )
}

/// Run one manual scan. `target` is the `project::env::target` path and must
/// be configured — an unknown path is refused with the valid choices listed,
/// same courtesy the tools' own resolve errors give the model.
pub async fn run(state: &AppState, target: &str) -> Result<ScanOutcome> {
    let fq = FqTarget::parse(target)?;
    let known: Vec<String> = state
        .config
        .projects
        .iter()
        .flat_map(|p| {
            p.envs.iter().flat_map(move |e| {
                e.targets.iter().map(move |t| format!("{}::{}::{}", p.name, e.name, t.name))
            })
        })
        .collect();
    if !known.iter().any(|k| *k == fq.to_string()) {
        return Err(crate::Error::validation(format!(
            "no configured target {target:?} — configured targets: {}",
            if known.is_empty() { "(none)".to_string() } else { known.join(", ") }
        )));
    }

    let prompt = scan_prompt(&fq);
    let job = Job::new(
        format!("{fq}-manual-scan"),
        Schedule::Interval { every_minutes: crate::domain::JOB_GAP_MINUTES_MIN },
        Payload::Prompt { body: prompt.clone() },
    )
    .system();

    let report = state.composer.compose(&job, &prompt, Utc::now()).await?;
    Ok(ScanOutcome { target: fq.to_string(), report })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_prompt_names_the_target_and_keeps_the_corroboration_rule() {
        let fq = FqTarget::new("remundo", "sandbox", "cluster");
        let p = scan_prompt(&fq);
        assert!(p.contains("remundo::sandbox::cluster"));
        assert!(p.contains("Corroborate"));
    }
}
