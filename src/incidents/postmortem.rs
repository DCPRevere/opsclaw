//! Postmortem rendering (brief §6/§13, DESIGN.md §4: `opsclaw postmortem
//! <id>` renders a structured postmortem from the incident's signals,
//! hypothesis, audit trail, and resolution).
//!
//! Pure function: no DB, no IO — the caller (CLI/HTTP handler) fetches the
//! `Incident` and its `AuditRecord`s and hands them here. Snapshot-style
//! tests pin the exact markdown shape.

use chrono::{DateTime, Utc};

use crate::audit::AuditRecord;
use crate::domain::{Incident, IncidentState};

/// Render a structured markdown postmortem for a (normally resolved or
/// expired, but any-state) incident, given the audit records that touched
/// its target during its lifetime.
///
/// `audit_records` should already be scoped by the caller to this incident's
/// `fq_target` and time window (`opened_at`..`resolved_at`/now) — this
/// function does not filter; it renders whatever it is given, in the order
/// given.
pub fn render_postmortem(incident: &Incident, audit_records: &[AuditRecord]) -> String {
    let mut out = String::new();

    out.push_str(&format!("# Postmortem: {}\n\n", incident.fingerprint));
    out.push_str(&format!("- **Incident ID:** {}\n", incident.id));
    out.push_str(&format!("- **Target:** {}\n", incident.target));
    out.push_str(&format!("- **Severity:** {:?}\n", incident.severity));
    out.push_str(&format!("- **Final state:** {:?}\n", incident.state));
    out.push_str(&format!("- **Opened:** {}\n", fmt_ts(incident.opened_at)));
    if let Some(acked) = incident.acked_at {
        out.push_str(&format!("- **Acknowledged:** {}\n", fmt_ts(acked)));
    }
    if let Some(resolved) = incident.resolved_at {
        out.push_str(&format!("- **Resolved:** {}\n", fmt_ts(resolved)));
        out.push_str(&format!(
            "- **Time to resolve:** {}\n",
            fmt_duration(resolved - incident.opened_at)
        ));
    }
    out.push_str(&format!("- **Notifications sent:** {}\n", incident.notify_count));
    out.push('\n');

    out.push_str("## Signals\n\n");
    out.push_str(&indent_as_blockquote(&incident.signals));
    out.push_str("\n\n");

    out.push_str("## Hypothesis\n\n");
    out.push_str(&indent_as_blockquote(&incident.hypothesis));
    out.push_str("\n\n");

    if let Some(action) = &incident.recommended_action {
        out.push_str("## Recommended action\n\n");
        out.push_str(&indent_as_blockquote(action));
        out.push_str("\n\n");
    }

    out.push_str("## Audit trail\n\n");
    if audit_records.is_empty() {
        out.push_str(
            "_No audited commands recorded against this target during the incident window._\n\n",
        );
    } else {
        out.push_str("| Time | Principal | Tool | Command | Risk | Outcome |\n");
        out.push_str("|---|---|---|---|---|---|\n");
        for r in audit_records {
            out.push_str(&format!(
                "| {} | {} | {} | `{}` | {:?} | {:?} |\n",
                fmt_ts(r.ts),
                r.principal,
                r.tool,
                escape_table_cell(&r.command),
                r.risk,
                r.outcome
            ));
        }
        out.push('\n');
    }

    out.push_str("## Resolution\n\n");
    out.push_str(&resolution_summary(incident));
    out.push('\n');

    out
}

fn fmt_ts(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339()
}

fn fmt_duration(d: chrono::Duration) -> String {
    let total_secs = d.num_seconds().max(0);
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Render free text as a markdown blockquote, one `> ` per line, so
/// multi-line signals/hypothesis text can't accidentally break out of its
/// section (e.g. a signal string containing `## `).
fn indent_as_blockquote(text: &str) -> String {
    if text.is_empty() {
        return "_none recorded_".to_string();
    }
    text.lines().map(|line| format!("> {line}")).collect::<Vec<_>>().join("\n")
}

/// Escape pipe characters so a command containing `|` can't break the
/// markdown table it renders into.
fn escape_table_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

fn resolution_summary(incident: &Incident) -> String {
    match incident.state {
        IncidentState::Resolved => "Resolved.".to_string(),
        IncidentState::Expired => {
            "**Expired** — the escalation chain was exhausted with no acknowledgement.".to_string()
        }
        IncidentState::Active => {
            "**Still active** — this postmortem was generated before resolution.".to_string()
        }
        IncidentState::Acknowledged => {
            "**Acknowledged, not yet resolved** — this postmortem was generated before resolution."
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditOutcome;
    use crate::domain::{FqTarget, Principal, RiskClass, Severity};
    use chrono::Duration;
    use uuid::Uuid;

    fn base_incident() -> Incident {
        let opened = DateTime::parse_from_rfc3339("2026-07-20T10:00:00Z").unwrap().into();
        Incident {
            id: Uuid::nil(),
            fingerprint: "abc123fingerprint".into(),
            fault_class: String::new(),
            target: FqTarget::new("remundo", "prod", "web-1"),
            severity: Severity::Critical,
            state: IncidentState::Resolved,
            signals: "CPU at 97% for 8m\nload average 12.4".into(),
            hypothesis: "Runaway worker process consuming a full core.".into(),
            recommended_action: Some("Restart the worker pool.".into()),
            opened_at: opened,
            acked_at: Some(opened + Duration::minutes(2)),
            acked_by: Some(Uuid::nil()),
            resolved_at: Some(opened + Duration::minutes(17)),
            last_notified_at: Some(opened),
            notify_count: 2,
            escalation_step: 0,
            step_started_at: Some(opened),
        }
    }

    fn audit_record(command: &str) -> AuditRecord {
        AuditRecord {
            id: Uuid::nil(),
            seq: 1,
            ts: DateTime::parse_from_rfc3339("2026-07-20T10:05:00Z").unwrap().into(),
            principal: Principal::Agent { job: None },
            fq_target: "remundo::prod::web-1".into(),
            tool: "systemd".into(),
            command: command.into(),
            risk: RiskClass::Medium,
            outcome: AuditOutcome::Executed,
            exit_code: Some(0),
            prev_hash: "0".repeat(68),
            hash: "1".repeat(64),
        }
    }

    #[test]
    fn renders_core_sections() {
        let md = render_postmortem(&base_incident(), &[]);
        assert!(md.starts_with("# Postmortem: abc123fingerprint\n"));
        assert!(md.contains("## Signals"));
        assert!(md.contains("## Hypothesis"));
        assert!(md.contains("## Recommended action"));
        assert!(md.contains("## Audit trail"));
        assert!(md.contains("## Resolution"));
    }

    #[test]
    fn signals_and_hypothesis_render_as_blockquote() {
        let md = render_postmortem(&base_incident(), &[]);
        assert!(md.contains("> CPU at 97% for 8m"));
        assert!(md.contains("> load average 12.4"));
        assert!(md.contains("> Runaway worker process consuming a full core."));
    }

    #[test]
    fn empty_audit_trail_says_so() {
        let md = render_postmortem(&base_incident(), &[]);
        assert!(md.contains("No audited commands recorded"));
    }

    #[test]
    fn audit_trail_renders_as_table_with_commands() {
        let records = vec![audit_record("systemctl restart worker"), audit_record("df -h")];
        let md = render_postmortem(&base_incident(), &records);
        assert!(md.contains("| Time | Principal | Tool | Command | Risk | Outcome |"));
        assert!(md.contains("`systemctl restart worker`"));
        assert!(md.contains("`df -h`"));
    }

    #[test]
    fn command_with_pipe_does_not_break_table() {
        let records = vec![audit_record("ps aux | grep worker")];
        let md = render_postmortem(&base_incident(), &records);
        assert!(md.contains("ps aux \\| grep worker"));
        // Still exactly one header separator row for the table.
        assert_eq!(md.matches("|---|---|---|---|---|---|").count(), 1);
    }

    #[test]
    fn resolved_state_shows_time_to_resolve() {
        let md = render_postmortem(&base_incident(), &[]);
        assert!(md.contains("Time to resolve:** 17m 0s"));
        assert!(md.contains("Resolution\n\nResolved."));
    }

    #[test]
    fn expired_state_notes_chain_exhaustion() {
        let mut incident = base_incident();
        incident.state = IncidentState::Expired;
        incident.resolved_at = None;
        let md = render_postmortem(&incident, &[]);
        assert!(md.contains("Expired** — the escalation chain was exhausted"));
        assert!(!md.contains("Time to resolve"));
    }

    #[test]
    fn active_state_notes_generated_before_resolution() {
        let mut incident = base_incident();
        incident.state = IncidentState::Active;
        incident.resolved_at = None;
        incident.acked_at = None;
        let md = render_postmortem(&incident, &[]);
        assert!(md.contains("Still active"));
    }

    #[test]
    fn missing_recommended_action_omits_that_section() {
        let mut incident = base_incident();
        incident.recommended_action = None;
        let md = render_postmortem(&incident, &[]);
        assert!(!md.contains("## Recommended action"));
    }

    #[test]
    fn no_signals_renders_none_recorded() {
        let mut incident = base_incident();
        incident.signals = String::new();
        let md = render_postmortem(&incident, &[]);
        assert!(md.contains("_none recorded_"));
    }

    #[test]
    fn snapshot_of_full_render_shape() {
        // Pins the exact rendered shape for a representative incident so an
        // accidental format change is caught explicitly, not just by the
        // more targeted tests above.
        let incident = base_incident();
        let records = vec![audit_record("systemctl restart worker")];
        let md = render_postmortem(&incident, &records);
        let expected = "\
# Postmortem: abc123fingerprint

- **Incident ID:** 00000000-0000-0000-0000-000000000000
- **Target:** remundo::prod::web-1
- **Severity:** Critical
- **Final state:** Resolved
- **Opened:** 2026-07-20T10:00:00+00:00
- **Acknowledged:** 2026-07-20T10:02:00+00:00
- **Resolved:** 2026-07-20T10:17:00+00:00
- **Time to resolve:** 17m 0s
- **Notifications sent:** 2

## Signals

> CPU at 97% for 8m
> load average 12.4

## Hypothesis

> Runaway worker process consuming a full core.

## Recommended action

> Restart the worker pool.

## Audit trail

| Time | Principal | Tool | Command | Risk | Outcome |
|---|---|---|---|---|---|
| 2026-07-20T10:05:00+00:00 | agent | systemd | `systemctl restart worker` | Medium | Executed |

## Resolution

Resolved.
";
        assert_eq!(md, expected);
    }
}
