//! The escalation-chain driver — the scheduler phase that turns persisted
//! incidents into actual pages (brief §6, DESIGN.md §4 "Incidents").
//!
//! `opsclaw_notify` (the agent's one escalation tool) only OPENS incidents;
//! this module is what delivers them: every tick it walks the open incident
//! set, asks the pure [`next_escalation`] what each Active incident needs
//! (first notify / re-notify / escalate to the next contact / expire), and
//! performs it — claim first (`ControlRepo::claim`, gianna's
//! claim-before-compose rule, so a crash mid-send skips rather than
//! double-pages), send through the step's contact channel, then persist the
//! chain position via `IncidentRepo::record_notification` so a restart
//! resumes where the chain left off instead of re-paging priority 0.
//!
//! Anti-spam properties (brief §6 "equal in weight to detection"):
//! - one send per (fingerprint, step, notify_count) occurrence, enforced by
//!   the claim table — crash-safe at-most-once;
//! - an Acknowledged incident is skipped entirely (the ack stops the chain;
//!   `next_escalation`'s contract), a Resolved/Expired one is not even
//!   listed — resolution produces silence, never trailing alerts;
//! - a chain exhausted unacknowledged transitions the incident to
//!   `Expired` exactly once (guarded by the same state filter).
//!
//! The driver also reconciles the adaptive cadence (DESIGN §3 scheduler):
//! any open incident ⇒ [`SchedulerHandle::set_incident_pressure`] tightens
//! the tick interval; all quiet ⇒ relaxes it.

use chrono::{DateTime, Utc};

use super::{SchedulerDeps, SchedulerHandle};
use crate::Result;
use crate::channels::{Channel, OutboundMessage};
use crate::config::ESCALATION_BROADCAST;
use crate::domain::{Incident, IncidentState};
use crate::incidents::{
    CLAIM_KIND_ESCALATION_NOTIFY, EscalationAction, EscalationChain, EscalationState, claim_key,
    next_escalation, validate_transition,
};

/// Upper bound on open incidents driven per tick — a runaway incident
/// storm must not turn the escalation phase into an unbounded loop that
/// starves the rest of the tick. 200 is far beyond any sane open-incident
/// count for one team; anything past it waits a tick (`list` returns
/// newest-bounded, and the claim table keeps the eventual sends
/// exactly-once regardless of which tick performs them).
const MAX_DRIVEN_PER_TICK: i64 = 200;

/// One scheduler pass over the open incident set. Never fails the tick for
/// a single incident's error — each incident is driven independently, same
/// isolation rule as the tick's phases themselves.
pub(super) async fn drive(
    deps: &SchedulerDeps,
    handle: &SchedulerHandle,
    now: DateTime<Utc>,
) -> Result<()> {
    let open = deps.incidents.list(false, MAX_DRIVEN_PER_TICK).await?;
    // Adaptive cadence: tightened while ANY incident is open (Active or
    // Acknowledged — an acked incident is still being worked), relaxed
    // when the board is clear.
    handle.set_incident_pressure(!open.is_empty());

    let chain = deps.config.escalation.chain();
    for incident in open.iter().filter(|i| i.state == IncidentState::Active) {
        if let Err(e) = drive_one(deps, &chain, incident, now).await {
            tracing::error!(
                incident = %incident.id,
                fingerprint = %incident.fingerprint,
                "escalation drive failed: {e}"
            );
        }
    }
    Ok(())
}

async fn drive_one(
    deps: &SchedulerDeps,
    chain: &EscalationChain,
    incident: &Incident,
    now: DateTime<Utc>,
) -> Result<()> {
    let action = next_escalation(chain, EscalationState::of(incident), now);
    let (kind, step) = match action {
        EscalationAction::Wait => return Ok(()),
        EscalationAction::ChainExhausted => {
            // Every contact's window elapsed unacknowledged — the chain is
            // done. `Expired` is a terminal, queryable verdict ("paging
            // failed to reach anyone"), never silent auto-resolution.
            validate_transition(incident.state, IncidentState::Expired)?;
            deps.incidents.set_state(incident.id, IncidentState::Expired, None).await?;
            tracing::warn!(
                incident = %incident.id,
                target = %incident.target,
                "escalation chain exhausted with no ack after {} notifications — incident expired",
                incident.notify_count
            );
            return Ok(());
        }
        EscalationAction::Notify { step } => ("INCIDENT", step),
        EscalationAction::Renotify { step } => ("REMINDER — unacknowledged incident", step),
        EscalationAction::Escalate { step } => ("ESCALATION — still unacknowledged", step),
    };

    // Claim BEFORE composing/sending: the occurrence is this exact send —
    // (step, notify_count) advances only when record_notification lands, so
    // a crash between claim and send loses at most this one send (the safe
    // direction for paging) and the chain still advances on ack_timeout.
    let occurrence = format!("s{step}-n{}", incident.notify_count);
    let key = claim_key(&incident.fingerprint, &occurrence);
    if !deps.control.claim(CLAIM_KIND_ESCALATION_NOTIFY, &key, now).await? {
        return Ok(());
    }

    let contact = &chain.steps[step.min(chain.steps.len() - 1)].contact;
    let body = render_page(incident, kind, step, chain.steps.len());
    // Structured twin for action-capable channels (web chat renders an
    // inline Acknowledge button from this); text-only channels ignore it.
    let meta = Some(serde_json::json!({
        "kind": "incident",
        "id": incident.id,
        "severity": incident.severity,
        "target": incident.target,
        "hypothesis": incident.hypothesis,
    }));
    match contact_channel(deps, contact).send(OutboundMessage { operator: None, body, meta }).await
    {
        Ok(()) => {
            // Renotify keeps the step's ack clock; a first Notify or an
            // Escalate starts (or restarts) it at this send.
            let step_started_at = match action {
                EscalationAction::Renotify { .. } => incident.step_started_at.unwrap_or(now),
                _ => now,
            };
            deps.incidents.record_notification(incident.id, now, step as i64, step_started_at).await
        }
        Err(e) => {
            // A FAILED send (an error return, not a crash) releases the
            // claim so the next tick retries this same occurrence instead
            // of the claim wedging the step silent for its whole window.
            if let Err(re) = deps.control.release(CLAIM_KIND_ESCALATION_NOTIFY, &key).await {
                tracing::error!(
                    incident = %incident.id,
                    "failed to release escalation claim after send error: {re}"
                );
            }
            Err(e)
        }
    }
}

/// Resolve an escalation step's contact to a channel: a `Channel::name()`
/// match against the individual configured channels, `"*"` (or an unknown
/// name, loudly) falling back to the broadcast fan-out — a typo'd contact
/// must page everyone rather than nobody.
fn contact_channel<'a>(deps: &'a SchedulerDeps, contact: &str) -> &'a std::sync::Arc<dyn Channel> {
    if contact != ESCALATION_BROADCAST {
        if let Some(ch) = deps.named_channels.iter().find(|c| c.name() == contact) {
            return ch;
        }
        tracing::warn!(
            "escalation contact {contact:?} matches no configured channel \
             ({:?}) — broadcasting on every channel instead",
            deps.named_channels.iter().map(|c| c.name()).collect::<Vec<_>>()
        );
    }
    &deps.channel
}

/// The page body — the product's most visible artifact (brief §6): severity,
/// fully-qualified target, the observed signals, the hypothesis, and the
/// recommended action, plus where the chain stands and how to stop it.
fn render_page(incident: &Incident, kind: &str, step: usize, total_steps: usize) -> String {
    let recommended = incident
        .recommended_action
        .as_deref()
        .unwrap_or("none recorded — diagnose from the signals above");
    format!(
        "{kind}\n\
         [{severity:?}] {target}\n\
         hypothesis: {hypothesis}\n\
         signals: {signals}\n\
         recommended action: {recommended}\n\
         incident {id} — step {step_no}/{total_steps}, notification #{n}. \
         Acknowledge it (web UI → incidents) to stop this chain.",
        severity = incident.severity,
        target = incident.target,
        hypothesis = incident.hypothesis,
        signals = incident.signals,
        id = incident.id,
        step_no = step + 1,
        n = incident.notify_count + 1,
    )
}

/// The approval-timeout sweep (DESIGN §4 Approvals: "Timeouts cancel via a
/// scheduler sweep"): expire every pending request past its deadline and
/// announce each lapse once — `ApprovalRepo::expire_due` only returns rows
/// it just transitioned, so the announcement is naturally exactly-once with
/// no claim needed.
pub(super) async fn expire_approvals(deps: &SchedulerDeps, now: DateTime<Utc>) -> Result<()> {
    let expired = crate::incidents::sweep_expired(&*deps.approvals, now).await?;
    for req in expired {
        tracing::warn!(approval = %req.id, command = %req.command, "approval expired unactioned");
        let body = format!(
            "approval request {id} EXPIRED unactioned: `{command}` ({tool}) on {target} \
             [{risk:?}] — nobody approved or denied it within its window, so it is \
             cancelled. Re-request from chat if the action is still needed.",
            id = req.id,
            command = req.command,
            tool = req.tool,
            target = req.target,
            risk = req.risk,
        );
        if let Err(e) =
            deps.channel.send(OutboundMessage { operator: None, body, meta: None }).await
        {
            tracing::warn!("could not announce expired approval {}: {e}", req.id);
        }
    }
    Ok(())
}
