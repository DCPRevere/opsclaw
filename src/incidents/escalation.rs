//! Escalation contact chain (brief §6, DESIGN.md §4 "Incidents"): an ordered
//! list of steps, each naming a contact/channel target, an `ack_timeout`
//! (how long to wait for an ack before moving to the next step) and a
//! `repeat_interval` (how often to re-notify the SAME step while waiting).
//!
//! This module is pure: no DB, no channel sends, no clock reads beyond the
//! `now` argument threaded in by the caller. [`next_escalation`] is the one
//! function the scheduler drives every tick — it decides WHAT should happen
//! next (notify step N / re-notify step N / advance to step N+1 / chain
//! exhausted), never performs it. The scheduler is responsible for actually
//! sending, claiming (`lifecycle::claim_key` / `ControlRepo::claim`) BEFORE
//! composing per DESIGN.md §3, and persisting the resulting `EscalationState`
//! for the next tick.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// One step in the chain: notify `contact`, wait up to `ack_timeout` for an
/// ack, and while waiting, re-notify the same contact every `repeat_interval`
/// (so a step doesn't go silent for the whole timeout window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationStep {
    /// Free-text contact/channel identity (e.g. a Telegram chat id, an
    /// operator account id as a string, a webhook name) — this module
    /// doesn't resolve or send to it, so it stays opaque here.
    pub contact: String,
    /// How long to wait for an ack before escalating to the next step.
    pub ack_timeout: Duration,
    /// How often to re-notify this same step while waiting (must be shorter
    /// than `ack_timeout` to have any effect — see `EscalationChain::validate`).
    pub repeat_interval: Duration,
}

/// An ordered escalation chain: priority 0 first, then 1, 2, ... Must have
/// at least one step to page anyone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationChain {
    pub steps: Vec<EscalationStep>,
}

impl EscalationChain {
    pub fn new(steps: Vec<EscalationStep>) -> Self {
        EscalationChain { steps }
    }

    /// Structural sanity check, called by config validation before boot
    /// (config's fail-fast `validate()`, DESIGN.md §3 Config): an empty
    /// chain, or a step whose `repeat_interval` is not strictly shorter than
    /// its `ack_timeout` (so it would never actually re-notify before
    /// escalating), or a non-positive duration, is a config error.
    pub fn validate(&self) -> crate::Result<()> {
        if self.steps.is_empty() {
            return Err(crate::Error::Config("escalation chain has no steps".into()));
        }
        for (i, step) in self.steps.iter().enumerate() {
            // An empty/whitespace contact is always a typo: the driver
            // would fall back to broadcast (safe direction), but the
            // operator plainly meant to name SOMEONE — refuse at boot like
            // every other silently-wrong config shape.
            if step.contact.trim().is_empty() {
                return Err(crate::Error::Config(format!(
                    "escalation step {i}: contact must not be empty (use \"*\" to broadcast)"
                )));
            }
            if step.ack_timeout <= Duration::zero() {
                return Err(crate::Error::Config(format!(
                    "escalation step {i} ({}): ack_timeout must be positive",
                    step.contact
                )));
            }
            if step.repeat_interval <= Duration::zero() {
                return Err(crate::Error::Config(format!(
                    "escalation step {i} ({}): repeat_interval must be positive",
                    step.contact
                )));
            }
            if step.repeat_interval >= step.ack_timeout {
                return Err(crate::Error::Config(format!(
                    "escalation step {i} ({}): repeat_interval must be shorter than ack_timeout",
                    step.contact
                )));
            }
        }
        Ok(())
    }
}

/// Where an incident is in its escalation chain, as of its last scheduler
/// tick. Persisted alongside the incident (or reconstructed from
/// `Incident.last_notified_at`/`notify_count` — see the note on
/// [`next_escalation`]) so `next_escalation` is a pure function of state, not
/// of tick history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscalationState {
    /// Index into `EscalationChain::steps` currently being notified.
    pub step: usize,
    /// When the CURRENT step was first notified (its clock for
    /// `ack_timeout`). `None` means the chain hasn't sent its first
    /// notification yet.
    pub step_started_at: Option<DateTime<Utc>>,
    /// When the current step was last (re-)notified — the clock
    /// `repeat_interval` is measured against. `None` before any send.
    pub last_notified_at: Option<DateTime<Utc>>,
}

impl EscalationState {
    /// The starting state for a freshly-opened incident: nothing notified
    /// yet, sitting at step 0.
    pub fn fresh() -> Self {
        EscalationState { step: 0, step_started_at: None, last_notified_at: None }
    }

    /// Rehydrate from the incident's durable fields (`escalation_step`,
    /// `step_started_at`, `last_notified_at`) — the scheduler reads this at
    /// tick time and persists advances via `IncidentRepo::record_notification`,
    /// so a restart resumes the chain where it left off instead of paging
    /// priority 0 again.
    pub fn of(incident: &crate::domain::Incident) -> Self {
        EscalationState {
            step: incident.escalation_step.max(0) as usize,
            step_started_at: incident.step_started_at,
            last_notified_at: incident.last_notified_at,
        }
    }
}

/// What the scheduler should do this tick, per DESIGN.md §3 ("notify
/// priority 0, wait ack_timeout, escalate, re-notify on repeat_interval").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationAction {
    /// Notify `step` (index into the chain) for the first time.
    Notify { step: usize },
    /// Re-notify `step` — the ack_timeout hasn't elapsed yet, but
    /// repeat_interval has since the last send.
    Renotify { step: usize },
    /// Move to `step` and notify it — the previous step's ack_timeout
    /// elapsed with no ack.
    Escalate { step: usize },
    /// Every step's ack_timeout elapsed with no ack — the chain is
    /// exhausted. The caller transitions the incident to `Expired`
    /// (`lifecycle::validate_transition(Active, Expired)`).
    ChainExhausted,
    /// Nothing to do this tick (already notified/re-notified recently and
    /// neither ack_timeout nor repeat_interval has elapsed).
    Wait,
}

/// Pure decision function, driven by the scheduler once per tick for every
/// open (Active, unacknowledged) incident. Does NOT read `Incident.state` —
/// the caller only calls this for incidents it has already confirmed are
/// still open and unacknowledged (an ack stops the chain entirely; there is
/// no `EscalationAction` for "acknowledged", by design — the scheduler simply
/// stops calling this once `IncidentState` leaves `Active`).
///
/// Contract: `state` reflects the outcome of the PREVIOUS call (the
/// scheduler updates `step`/`step_started_at`/`last_notified_at` after
/// acting on the returned `EscalationAction`, per the docs on each variant),
/// so this function is a pure fold over that persisted state plus `now` —
/// no hidden reliance on wall-clock history.
pub fn next_escalation(
    chain: &EscalationChain,
    state: EscalationState,
    now: DateTime<Utc>,
) -> EscalationAction {
    if chain.steps.is_empty() {
        // Config validation should have rejected this chain already; treat
        // defensively as immediately exhausted rather than panicking or
        // silently notifying nobody forever.
        return EscalationAction::ChainExhausted;
    }

    let Some(started_at) = state.step_started_at else {
        // Never notified yet: send the current step now.
        return EscalationAction::Notify { step: state.step };
    };

    let current = &chain.steps[state.step.min(chain.steps.len() - 1)];

    if now - started_at >= current.ack_timeout {
        // This step's window elapsed with no ack — escalate.
        let next_step = state.step + 1;
        return if next_step < chain.steps.len() {
            EscalationAction::Escalate { step: next_step }
        } else {
            EscalationAction::ChainExhausted
        };
    }

    // Still within this step's ack_timeout — check whether it's time to
    // re-notify. `last_notified_at` is always Some once `step_started_at`
    // is Some (the first Notify sets both), so this fallback to
    // `started_at` is defensive, not a real path.
    let last = state.last_notified_at.unwrap_or(started_at);
    if now - last >= current.repeat_interval {
        EscalationAction::Renotify { step: state.step }
    } else {
        EscalationAction::Wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(contact: &str, ack_timeout_mins: i64, repeat_mins: i64) -> EscalationStep {
        EscalationStep {
            contact: contact.into(),
            ack_timeout: Duration::minutes(ack_timeout_mins),
            repeat_interval: Duration::minutes(repeat_mins),
        }
    }

    fn chain() -> EscalationChain {
        EscalationChain::new(vec![
            step("primary-oncall", 15, 5),
            step("secondary-oncall", 15, 5),
            step("team-lead", 30, 10),
        ])
    }

    #[test]
    fn fresh_incident_notifies_step_zero() {
        let action = next_escalation(&chain(), EscalationState::fresh(), Utc::now());
        assert_eq!(action, EscalationAction::Notify { step: 0 });
    }

    #[test]
    fn no_action_immediately_after_notify() {
        let now = Utc::now();
        let state =
            EscalationState { step: 0, step_started_at: Some(now), last_notified_at: Some(now) };
        assert_eq!(next_escalation(&chain(), state, now), EscalationAction::Wait);
    }

    #[test]
    fn renotifies_after_repeat_interval_within_ack_timeout() {
        let started = Utc::now();
        let now = started + Duration::minutes(6); // past repeat(5), within ack_timeout(15)
        let state = EscalationState {
            step: 0,
            step_started_at: Some(started),
            last_notified_at: Some(started),
        };
        assert_eq!(next_escalation(&chain(), state, now), EscalationAction::Renotify { step: 0 });
    }

    #[test]
    fn escalates_after_ack_timeout() {
        let started = Utc::now();
        let now = started + Duration::minutes(16); // past ack_timeout(15)
        let state = EscalationState {
            step: 0,
            step_started_at: Some(started),
            last_notified_at: Some(started),
        };
        assert_eq!(next_escalation(&chain(), state, now), EscalationAction::Escalate { step: 1 });
    }

    #[test]
    fn escalation_takes_priority_over_repeat_when_both_elapsed() {
        // ack_timeout elapsed implies repeat_interval elapsed too (repeat <
        // ack by construction/validate) — escalate must win, never renotify
        // a step whose window is already blown.
        let started = Utc::now();
        let now = started + Duration::minutes(20);
        let state = EscalationState {
            step: 0,
            step_started_at: Some(started),
            last_notified_at: Some(started),
        };
        assert_eq!(next_escalation(&chain(), state, now), EscalationAction::Escalate { step: 1 });
    }

    #[test]
    fn chain_exhausted_after_last_step_ack_timeout() {
        let started = Utc::now();
        let now = started + Duration::minutes(31); // past last step's ack_timeout(30)
        let state = EscalationState {
            step: 2,
            step_started_at: Some(started),
            last_notified_at: Some(started),
        };
        assert_eq!(next_escalation(&chain(), state, now), EscalationAction::ChainExhausted);
    }

    #[test]
    fn empty_chain_is_immediately_exhausted() {
        let empty = EscalationChain::new(vec![]);
        assert_eq!(
            next_escalation(&empty, EscalationState::fresh(), Utc::now()),
            EscalationAction::ChainExhausted
        );
    }

    #[test]
    fn multiple_renotifies_before_escalation() {
        let started = Utc::now();
        let c = chain();
        // t+5: first renotify.
        let state1 = EscalationState {
            step: 0,
            step_started_at: Some(started),
            last_notified_at: Some(started),
        };
        let action1 = next_escalation(&c, state1, started + Duration::minutes(5));
        assert_eq!(action1, EscalationAction::Renotify { step: 0 });

        // Scheduler updates last_notified_at after acting; t+10: second renotify.
        let state2 = EscalationState {
            step: 0,
            step_started_at: Some(started),
            last_notified_at: Some(started + Duration::minutes(5)),
        };
        let action2 = next_escalation(&c, state2, started + Duration::minutes(10));
        assert_eq!(action2, EscalationAction::Renotify { step: 0 });
    }

    #[test]
    fn validate_rejects_empty_chain() {
        assert!(EscalationChain::new(vec![]).validate().is_err());
    }

    #[test]
    fn validate_rejects_repeat_not_shorter_than_ack_timeout() {
        let c = EscalationChain::new(vec![step("oncall", 10, 10)]);
        assert!(c.validate().is_err());
        let c2 = EscalationChain::new(vec![step("oncall", 10, 15)]);
        assert!(c2.validate().is_err());
    }

    #[test]
    fn validate_rejects_non_positive_durations() {
        let c = EscalationChain::new(vec![EscalationStep {
            contact: "oncall".into(),
            ack_timeout: Duration::zero(),
            repeat_interval: Duration::minutes(1),
        }]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_well_formed_chain() {
        assert!(chain().validate().is_ok());
    }

    #[test]
    fn validate_error_names_the_offending_step() {
        let c = EscalationChain::new(vec![step("good", 10, 5), step("bad-step", 10, 10)]);
        let err = c.validate().unwrap_err();
        assert!(format!("{err}").contains("bad-step"));
    }
}
