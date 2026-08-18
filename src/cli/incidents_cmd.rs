//! `opsclaw-cli incidents` (list/show) — thin read wrapper over
//! `db::IncidentRepo`, the same repo the daemon's scheduler writes
//! (DESIGN.md §1: "the CLI drives the same orchestrator path"). No incident
//! lifecycle logic lives here — `incidents/` owns fingerprinting, dedup, and
//! state transitions; this module only reads and formats.

use uuid::Uuid;

use crate::Result;
use crate::cli::output::{print_json, print_table};
use crate::db::{Db, IncidentRepo};
use crate::domain::Incident;
use crate::domain::IncidentState;

pub async fn list(db: &Db, include_closed: bool, limit: i64, json: bool) -> Result<Vec<Incident>> {
    // Fully-qualified: `AllRepos` unions several repo traits that each
    // declare their own `list`/`get`, so plain method-call syntax is
    // ambiguous (E0034) even though only IncidentRepo's signature matches
    // the arguments here.
    let incidents = IncidentRepo::list(db.repos().as_ref(), include_closed, limit).await?;
    if json {
        print_json(&incidents);
    } else {
        let rows: Vec<Vec<String>> = incidents
            .iter()
            .map(|i| {
                vec![
                    i.id.to_string(),
                    i.target.to_string(),
                    format!("{:?}", i.severity),
                    format!("{:?}", i.state),
                    i.opened_at.to_rfc3339(),
                    i.hypothesis.chars().take(60).collect(),
                ]
            })
            .collect();
        print_table(&["id", "target", "severity", "state", "opened_at", "hypothesis"], &rows);
    }
    Ok(incidents)
}

pub async fn transition(db: &Db, id: Uuid, to: IncidentState) -> Result<Incident> {
    let current = IncidentRepo::get(db.repos().as_ref(), id)
        .await?
        .ok_or_else(|| crate::Error::NotFound("incident".into()))?;
    crate::incidents::lifecycle::validate_transition(current.state, to)?;
    IncidentRepo::set_state(db.repos().as_ref(), id, to, None).await?;
    IncidentRepo::get(db.repos().as_ref(), id)
        .await?
        .ok_or_else(|| crate::Error::NotFound("incident".into()))
}

pub async fn show(db: &Db, id: Uuid, json: bool) -> Result<Option<Incident>> {
    let incident = IncidentRepo::get(db.repos().as_ref(), id).await?;
    match &incident {
        Some(i) if json => print_json(i),
        Some(i) => {
            println!("id:            {}", i.id);
            println!("fingerprint:   {}", i.fingerprint);
            println!("target:        {}", i.target);
            println!("severity:      {:?}", i.severity);
            println!("state:         {:?}", i.state);
            println!("opened_at:     {}", i.opened_at.to_rfc3339());
            if let Some(acked) = i.acked_at {
                println!("acked_at:      {}", acked.to_rfc3339());
            }
            if let Some(resolved) = i.resolved_at {
                println!("resolved_at:   {}", resolved.to_rfc3339());
            }
            println!("notify_count:  {}", i.notify_count);
            println!("hypothesis:    {}", i.hypothesis);
            println!("signals:       {}", i.signals);
            if let Some(action) = &i.recommended_action {
                println!("recommended:   {action}");
            }
        }
        None if json => print_json(&serde_json::json!(null)),
        None => println!("no incident with id {id}"),
    }
    Ok(incident)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FqTarget, Incident, IncidentState, Severity};

    fn sample_incident(target: &str) -> Incident {
        Incident {
            id: Uuid::new_v4(),
            fingerprint: format!("fp-{target}"),
            fault_class: String::new(),
            target: FqTarget::new("p", "e", target),
            severity: Severity::Critical,
            state: IncidentState::Active,
            signals: "cpu_pct=97".into(),
            hypothesis: "runaway process".into(),
            recommended_action: None,
            opened_at: chrono::Utc::now(),
            reopened_at: None,
            acked_at: None,
            acked_by: None,
            resolved_at: None,
            last_notified_at: None,
            notify_count: 1,
            escalation_step: 0,
            step_started_at: None,
        }
    }

    #[tokio::test]
    async fn list_returns_inserted_incidents() {
        let db = Db::fake();
        let incident = sample_incident("web-1");
        IncidentRepo::insert(db.repos().as_ref(), &incident).await.unwrap();

        let listed = list(&db, true, 10, false).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, incident.id);
    }

    #[tokio::test]
    async fn show_returns_none_for_unknown_id() {
        let db = Db::fake();
        let found = show(&db, Uuid::new_v4(), false).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn show_returns_the_incident() {
        let db = Db::fake();
        let incident = sample_incident("web-1");
        IncidentRepo::insert(db.repos().as_ref(), &incident).await.unwrap();

        let found = show(&db, incident.id, false).await.unwrap().unwrap();
        assert_eq!(found.id, incident.id);
    }

    #[tokio::test]
    async fn acknowledge_and_resolve_follow_the_lifecycle() {
        let db = Db::fake();
        let incident = sample_incident("web-1");
        IncidentRepo::insert(db.repos().as_ref(), &incident).await.unwrap();

        let acked = transition(&db, incident.id, IncidentState::Acknowledged).await.unwrap();
        assert_eq!(acked.state, IncidentState::Acknowledged);
        assert!(acked.acked_at.is_some());

        let resolved = transition(&db, incident.id, IncidentState::Resolved).await.unwrap();
        assert_eq!(resolved.state, IncidentState::Resolved);
        assert!(resolved.resolved_at.is_some());
    }
}
