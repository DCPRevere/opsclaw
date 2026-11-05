//! `opsclaw-cli postmortem <id>` — renders `incidents::postmortem::render_postmortem`
//! for a stored incident (DESIGN.md §4: "`opsclaw postmortem <id>` renders a
//! structured postmortem from the incident's signals, hypothesis, audit
//! trail, and resolution").
//!
//! `render_postmortem` is pure and explicitly does not filter audit records
//! itself (`incidents/postmortem.rs`'s own doc comment) — this module does
//! the filtering: records whose `fq_target` matches the incident's target,
//! within `opened_at..resolved_at.unwrap_or(now)`.

use uuid::Uuid;

use crate::Result;
use crate::db::{Db, IncidentRepo};
use crate::incidents::postmortem::render_postmortem;

/// Render the postmortem markdown for `id`, or `None` if no such incident
/// exists. Pages the audit chain via `AuditRepo::range` rather than assuming
/// it fits in memory, same discipline as `audit_cmd::verify`.
pub async fn render(db: &Db, id: Uuid) -> Result<Option<String>> {
    // Fully-qualified: AllRepos unions several `get`-declaring traits.
    let Some(incident) = IncidentRepo::get(db.repos().as_ref(), id).await? else {
        return Ok(None);
    };

    let window_end = incident.resolved_at.unwrap_or_else(chrono::Utc::now);
    let target_str = incident.target.to_string();

    let mut matching = Vec::new();
    let mut cursor = 1i64;
    const PAGE_SIZE: i64 = 500;
    loop {
        let page = db.repos().range(cursor, PAGE_SIZE).await?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for record in page {
            if record.fq_target == target_str
                && record.ts >= incident.opened_at
                && record.ts <= window_end
            {
                matching.push(record);
            }
        }
        cursor += page_len as i64;
        if (page_len as i64) < PAGE_SIZE {
            break;
        }
    }
    // range() pages in seq order already; no separate sort needed.

    Ok(Some(render_postmortem(&incident, &matching)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain;
    use crate::audit::{AuditOutcome, AuditRecord};
    use crate::domain::{FqTarget, Incident, IncidentState, Principal, RiskClass, Severity};
    use chrono::Utc;

    fn sample_incident() -> Incident {
        Incident {
            id: Uuid::new_v4(),
            fingerprint: "fp-1".into(),
            fault_class: String::new(),
            target: FqTarget::new("p", "e", "t"),
            severity: Severity::Critical,
            state: IncidentState::Resolved,
            signals: "cpu_pct=97".into(),
            hypothesis: "runaway process".into(),
            recommended_action: Some("restart the service".into()),
            opened_at: Utc::now() - chrono::Duration::minutes(10),
            reopened_at: None,
            acked_at: None,
            acked_by: None,
            resolved_at: Some(Utc::now()),
            last_notified_at: None,
            notify_count: 1,
            escalation_step: 0,
            step_started_at: None,
            accepted_at: None,
            accepted_by: None,
        }
    }

    fn audit_record(
        seq: i64,
        fq_target: &str,
        ts: chrono::DateTime<Utc>,
        tail: Option<&AuditRecord>,
    ) -> AuditRecord {
        let r = AuditRecord {
            id: Uuid::new_v4(),
            seq,
            ts,
            principal: Principal::System,
            fq_target: fq_target.to_string(),
            tool: "ssh".into(),
            command: "systemctl restart app".into(),
            risk: RiskClass::Medium,
            outcome: AuditOutcome::Executed,
            exit_code: Some(0),
            prev_hash: String::new(),
            hash: String::new(),
        };
        chain::seal(r, tail).unwrap()
    }

    #[tokio::test]
    async fn unknown_incident_returns_none() {
        let db = Db::fake();
        assert!(render(&db, Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn renders_with_only_matching_records() {
        let db = Db::fake();
        let incident = sample_incident();
        IncidentRepo::insert(db.repos().as_ref(), &incident).await.unwrap();

        // A record for the same target inside the window.
        let r1 = audit_record(
            1,
            &incident.target.to_string(),
            incident.opened_at + chrono::Duration::minutes(1),
            None,
        );
        db.repos().append(&r1).await.unwrap();
        // A record for a DIFFERENT target — must be excluded.
        let r2 = audit_record(
            2,
            "p::e::unrelated",
            incident.opened_at + chrono::Duration::minutes(2),
            Some(&r1),
        );
        db.repos().append(&r2).await.unwrap();
        // A record for the same target but OUTSIDE the window (before opened_at).
        let r3 = audit_record(
            3,
            &incident.target.to_string(),
            incident.opened_at - chrono::Duration::hours(1),
            Some(&r2),
        );
        db.repos().append(&r3).await.unwrap();

        let md = render(&db, incident.id).await.unwrap().unwrap();
        assert!(
            md.contains("systemctl restart app"),
            "expected the in-window matching record to be rendered:\n{md}"
        );
        // Exactly one command line should be rendered (r1), not r2/r3.
        assert_eq!(md.matches("systemctl restart app").count(), 1);
    }
}
