//! Incident lifecycle: coarse state machine (gianna's 3-state billing
//! lesson — coarse states + booleans beat mirroring an external vocabulary)
//! plus the claim-key convention that suppresses trailing alerts on
//! resolution.
//!
//! `IncidentState` itself lives in `domain` (frozen contract); this module
//! owns the transition RULES — which moves are valid — and errors loudly on
//! an invalid one rather than silently coercing it (DESIGN.md §4).

use crate::Error;
use crate::domain::IncidentState;

/// Attempt a state transition. `Ok(())` if `from -> to` is a valid move;
/// `Err` otherwise. Valid moves:
///
/// - `Active -> Acknowledged` (a human or the escalation chain acks it)
/// - `Active -> Resolved` (auto-resolved or force-resolved without an ack)
/// - `Active -> Expired` (escalation chain exhausted with no ack)
/// - `Acknowledged -> Resolved`
/// - `Acknowledged -> Active` (a re-occurrence after ack but before
///   resolution — the fault is still live)
/// - `Expired -> Active` (the SAME fault re-detected after the chain
///   exhausted — the incident re-opens rather than duplicating; see
///   `IncidentRepo::reopen`)
/// - `Expired -> Resolved` (someone fixed it after nobody acked it)
/// - `Expired -> Acknowledged` (accepted as known: `IncidentRepo::accept`)
///
/// `Resolved` is terminal: nothing transitions out of it. A fresh detection
/// matching a RESOLVED incident's fingerprint opens a NEW incident (a fault
/// that came back after being fixed is genuinely new), whereas one matching
/// an EXPIRED incident re-opens it (the fault never went away — nobody ever
/// acked it, so a new row would just churn a fresh notification cycle for
/// the same long-standing problem).
pub fn validate_transition(from: IncidentState, to: IncidentState) -> crate::Result<()> {
    use IncidentState::*;
    let valid = matches!(
        (from, to),
        (Active, Acknowledged)
            | (Active, Resolved)
            | (Active, Expired)
            | (Acknowledged, Resolved)
            | (Acknowledged, Active)
            | (Expired, Active)
            | (Expired, Resolved)
            | (Expired, Acknowledged)
    );
    if valid {
        Ok(())
    } else {
        Err(Error::Policy(format!("invalid incident transition: {from:?} -> {to:?}")))
    }
}

/// True once an incident is in a closed state (Resolved/Expired) — the
/// notification chain has stopped and per-occurrence claims for it should
/// stop being made. Expired is closed but not sealed: a re-detection of the
/// same fingerprint re-opens it (`Expired -> Active` above); Resolved never
/// re-opens.
pub fn is_terminal(state: IncidentState) -> bool {
    matches!(state, IncidentState::Resolved | IncidentState::Expired)
}

/// True when new detections matching this incident's fingerprint should
/// attach as an occurrence on THIS incident rather than opening a new one —
/// i.e. the incident is still open (Active or Acknowledged). Mirrors
/// `IncidentRepo::find_open_by_fingerprint`'s intended scope; kept here as
/// the single source of truth for "open" so callers don't redefine it.
pub fn is_open(state: IncidentState) -> bool {
    matches!(state, IncidentState::Active | IncidentState::Acknowledged)
}

/// Claim-table key convention for suppressing trailing alerts (DESIGN.md §3:
/// "Anti-spam = gianna's claim table generalized" — atomically claim before
/// composing/sending, keyed per (incident fingerprint, occurrence)).
///
/// Format: `"{fingerprint}:{occurrence}"`. `kind` passed separately to
/// `ControlRepo::claim` should be a stable constant per call site (e.g.
/// `"incident_notify"`, `"incident_escalate"`) so different notification
/// PURPOSES for the same occurrence don't collide with each other — only
/// repeats of the SAME purpose for the SAME occurrence should be suppressed.
///
/// `occurrence` disambiguates re-notifications of the same open incident
/// (e.g. a repeat_interval re-notify, or an escalation step) from the
/// original notify; a scheduler-side counter or escalation step index is a
/// typical value. Resolution suppresses trailing alerts simply by the
/// incident moving to a terminal state before scheduler code composes a new
/// occurrence — `is_terminal` is the check a caller makes BEFORE attempting
/// the claim, so a resolved incident never even reaches `ControlRepo::claim`
/// for a new occurrence.
pub fn claim_key(fingerprint: &str, occurrence: &str) -> String {
    format!("{fingerprint}:{occurrence}")
}

/// The `kind` passed to `ControlRepo::claim` for the escalation chain's
/// notify/re-notify calls (see `escalation::next_escalation`). A stable
/// constant so the scheduler and this module agree on it without a shared
/// enum crossing the module boundary.
pub const CLAIM_KIND_ESCALATION_NOTIFY: &str = "incident_escalation_notify";

#[cfg(test)]
mod tests {
    use super::*;
    use IncidentState::*;

    #[test]
    fn active_to_acknowledged_is_valid() {
        assert!(validate_transition(Active, Acknowledged).is_ok());
    }

    #[test]
    fn active_to_resolved_is_valid() {
        assert!(validate_transition(Active, Resolved).is_ok());
    }

    #[test]
    fn active_to_expired_is_valid() {
        assert!(validate_transition(Active, Expired).is_ok());
    }

    #[test]
    fn acknowledged_to_resolved_is_valid() {
        assert!(validate_transition(Acknowledged, Resolved).is_ok());
    }

    #[test]
    fn acknowledged_to_active_is_valid_reoccurrence() {
        assert!(validate_transition(Acknowledged, Active).is_ok());
    }

    #[test]
    fn resolved_is_terminal() {
        assert!(validate_transition(Resolved, Active).is_err());
        assert!(validate_transition(Resolved, Acknowledged).is_err());
        assert!(validate_transition(Resolved, Expired).is_err());
    }

    #[test]
    fn expired_can_reopen_be_acked_or_be_resolved() {
        // Re-detection re-opens to Active (the chain restarts from the top).
        // A person can also ack or resolve it directly: with alerts only in
        // the web UI, most incidents expire before anyone looks, and an
        // expired incident nobody could close was stuck forever.
        assert!(validate_transition(Expired, Active).is_ok());
        assert!(validate_transition(Expired, Acknowledged).is_ok());
        assert!(validate_transition(Expired, Resolved).is_ok());
    }

    #[test]
    fn acknowledged_to_expired_is_invalid() {
        // Expiry is specifically "escalation chain exhausted with no ack" —
        // once acked, the chain has succeeded, so this path is closed.
        assert!(validate_transition(Acknowledged, Expired).is_err());
    }

    #[test]
    fn self_transitions_are_invalid() {
        assert!(validate_transition(Active, Active).is_err());
        assert!(validate_transition(Acknowledged, Acknowledged).is_err());
    }

    #[test]
    fn invalid_transition_is_an_error_not_silent() {
        let err = validate_transition(Resolved, Active).unwrap_err();
        assert!(format!("{err}").contains("invalid incident transition"));
    }

    #[test]
    fn is_terminal_matches_resolved_and_expired_only() {
        assert!(!is_terminal(Active));
        assert!(!is_terminal(Acknowledged));
        assert!(is_terminal(Resolved));
        assert!(is_terminal(Expired));
    }

    #[test]
    fn is_open_matches_active_and_acknowledged_only() {
        assert!(is_open(Active));
        assert!(is_open(Acknowledged));
        assert!(!is_open(Resolved));
        assert!(!is_open(Expired));
    }

    #[test]
    fn claim_key_format_is_stable() {
        assert_eq!(claim_key("abc123", "0"), "abc123:0");
        assert_eq!(claim_key("abc123", "escalate-1"), "abc123:escalate-1");
    }

    #[test]
    fn claim_key_distinguishes_occurrences() {
        assert_ne!(claim_key("abc123", "0"), claim_key("abc123", "1"));
    }
}
