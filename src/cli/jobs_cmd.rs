//! `opsclaw-cli jobs list|edit` — the operator surface over the scheduler's
//! job table (DESIGN §3 Scheduler: "a persistent task list … user-editable").
//!
//! `edit` is where gianna's prompt-from-const contract completes: a SEEDED
//! scan job stores `Payload::ScanRoutine { routine }` and resolves its
//! prompt from a code constant at fire time (so improving the const
//! upgrades every unedited job). The moment an operator edits the prompt,
//! the job CONVERTS to `Payload::Prompt { body }` — free text, kept forever,
//! never re-resolved from the const — and re-seeding still skips it by name,
//! so the edit survives every reboot.

use chrono::Utc;
use serde::Serialize;

use crate::Result;
use crate::db::JobRepo;
use crate::domain::{Job, Payload, Schedule};

/// One row of `jobs list` — the operator-facing shape (`--json` emits it
/// verbatim; the text form renders from it so the two can't drift).
#[derive(Debug, Serialize)]
pub struct JobRow {
    pub name: String,
    pub enabled: bool,
    pub system: bool,
    pub schedule: String,
    pub payload: String,
    pub next_run_at: Option<String>,
    pub last_run_at: Option<String>,
}

fn describe_schedule(s: &Schedule) -> String {
    match s {
        Schedule::Interval { every_minutes } => format!("every {every_minutes}m"),
        Schedule::Once { at } => format!("once at {}", at.format("%Y-%m-%d %H:%M UTC")),
        other => format!("{other:?}"),
    }
}

fn describe_payload(p: &Payload) -> String {
    match p {
        Payload::Text(t) => format!("text: {}", preview(t)),
        Payload::Prompt { body } => format!("prompt: {}", preview(body)),
        Payload::ScanRoutine { routine, .. } => {
            format!("scan routine {routine:?} (prompt from code; edit converts to free text)")
        }
    }
}

fn preview(s: &str) -> String {
    let one_line = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > 60 {
        format!("{}…", one_line.chars().take(60).collect::<String>())
    } else {
        one_line
    }
}

pub async fn list(jobs: &dyn JobRepo) -> Result<Vec<JobRow>> {
    let mut all = jobs.list().await?;
    all.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(all
        .iter()
        .map(|j| JobRow {
            name: j.name.clone(),
            enabled: j.enabled,
            system: j.system,
            schedule: describe_schedule(&j.schedule),
            payload: describe_payload(&j.payload),
            next_run_at: j.next_run_at.map(|t| t.to_rfc3339()),
            last_run_at: j.last_run_at.map(|t| t.to_rfc3339()),
        })
        .collect())
}

/// Edit a job by NAME (the operator-facing identity — never an id). At
/// least one of `prompt`/`every_minutes`/`enabled` must be given. A prompt
/// edit on a `ScanRoutine` job performs the free-text conversion described
/// in the module doc; an interval edit recomputes `next_run_at` from now so
/// the new cadence takes effect immediately rather than after one stale
/// interval.
pub async fn edit(
    jobs: &dyn JobRepo,
    name: &str,
    prompt: Option<String>,
    every_minutes: Option<i64>,
    enabled: Option<bool>,
) -> Result<Job> {
    if prompt.is_none() && every_minutes.is_none() && enabled.is_none() {
        return Err(crate::Error::Config(
            "nothing to change — pass --prompt, --every-minutes, and/or --enabled".into(),
        ));
    }
    let all = jobs.list().await?;
    let Some(mut job) = all.into_iter().find(|j| j.name == name) else {
        let mut names: Vec<String> = jobs.list().await?.into_iter().map(|j| j.name).collect();
        names.sort();
        return Err(crate::Error::NotFound(format!(
            "no job named {name:?} — jobs: {}",
            names.join(", ")
        )));
    };

    if let Some(body) = prompt {
        if body.trim().is_empty() {
            return Err(crate::Error::Config("--prompt must not be empty".into()));
        }
        // THE conversion: from const-resolved ScanRoutine (or old free
        // text) to operator-owned free text, kept forever.
        job.payload = Payload::Prompt { body };
    }
    if let Some(mins) = every_minutes {
        if mins < 1 {
            return Err(crate::Error::Config("--every-minutes must be >= 1".into()));
        }
        job.schedule = Schedule::Interval { every_minutes: mins };
        job.next_run_at = job.schedule.next_after(Utc::now());
    }
    if let Some(e) = enabled {
        job.enabled = e;
    }
    jobs.update(&job).await
}

pub async fn delete(jobs: &dyn JobRepo, name: &str) -> Result<bool> {
    let Some(job) = jobs.list().await?.into_iter().find(|job| job.name == name) else {
        return Ok(false);
    };
    jobs.delete(job.id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory::InMemoryDb;
    use std::sync::Arc;

    fn seeded_scan_job(name: &str) -> Job {
        Job::new(
            name,
            Schedule::Interval { every_minutes: 30 },
            Payload::ScanRoutine {
                routine: "record_scan".into(),
                target: Some(crate::domain::FqTarget::new("remundo", "prod", "cluster")),
            },
        )
        .system()
    }

    #[tokio::test]
    async fn list_renders_scan_routine_jobs_with_the_conversion_hint() {
        let db = Arc::new(InMemoryDb::new());
        JobRepo::insert(db.as_ref(), &seeded_scan_job("remundo::prod::cluster-scan"))
            .await
            .unwrap();
        let rows = list(db.as_ref()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].system);
        assert!(rows[0].payload.contains("scan routine"), "{}", rows[0].payload);
        assert!(rows[0].schedule.contains("every 30m"), "{}", rows[0].schedule);
    }

    #[tokio::test]
    async fn prompt_edit_converts_a_seeded_job_to_free_text_and_reseeding_skips_it() {
        let db = Arc::new(InMemoryDb::new());
        JobRepo::insert(db.as_ref(), &seeded_scan_job("remundo::prod::cluster-scan"))
            .await
            .unwrap();

        let edited = edit(
            db.as_ref(),
            "remundo::prod::cluster-scan",
            Some("scan only the prod-backend namespace".into()),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            edited.payload,
            Payload::Prompt { body: "scan only the prod-backend namespace".into() },
            "ScanRoutine converts to operator-owned free text"
        );
        assert!(edited.system, "stays the seeded slot so re-seeding skips it by name");

        // The stored row really converted (not just the returned copy).
        let stored = JobRepo::get(db.as_ref(), edited.id).await.unwrap().unwrap();
        assert!(matches!(stored.payload, Payload::Prompt { .. }));
    }

    #[tokio::test]
    async fn interval_edit_recomputes_next_run() {
        let db = Arc::new(InMemoryDb::new());
        let mut job = seeded_scan_job("scan");
        job.next_run_at = Some(Utc::now() + chrono::Duration::minutes(30));
        JobRepo::insert(db.as_ref(), &job).await.unwrap();

        let edited = edit(db.as_ref(), "scan", None, Some(5), None).await.unwrap();
        assert_eq!(edited.schedule, Schedule::Interval { every_minutes: 5 });
        let next = edited.next_run_at.expect("recomputed");
        assert!(next <= Utc::now() + chrono::Duration::minutes(5));
    }

    #[tokio::test]
    async fn edit_refuses_no_op_and_unknown_names() {
        let db = Arc::new(InMemoryDb::new());
        JobRepo::insert(db.as_ref(), &seeded_scan_job("scan")).await.unwrap();
        let err = edit(db.as_ref(), "scan", None, None, None).await.unwrap_err();
        assert!(err.to_string().contains("nothing to change"), "{err}");
        let err = edit(db.as_ref(), "nope", Some("x".into()), None, None).await.unwrap_err();
        assert!(err.to_string().contains("no job named"), "{err}");
        assert!(err.to_string().contains("scan"), "names the valid jobs: {err}");
    }
}
