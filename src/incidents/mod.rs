//! Incident engine (Wave 3): fingerprinting, claim-based dedup (one incident
//! → one alert), lifecycle transitions, escalation contact chain, approvals,
//! postmortem rendering. Types live in `crate::domain`; persistence in
//! `db::repo`.
//!
//! ## Submodules
//!
//! - [`fingerprint`] — the anti-spam identity: `(fq target, fault class,
//!   resource) -> String`, deterministic and stable across restarts. A new
//!   detection matching an open incident's fingerprint
//!   (`IncidentRepo::find_open_by_fingerprint`) attaches as an occurrence on
//!   that incident, never a new row.
//! - [`lifecycle`] — the `Active -> Acknowledged -> Resolved | Expired`
//!   transition rules (invalid moves error, never silently coerce; `Expired
//!   -> Active` re-opens on re-detection) and the claim-key convention
//!   (`lifecycle::claim_key`) that suppresses trailing alerts once an
//!   incident is resolved.
//! - [`escalation`] — the ordered contact chain data model
//!   (`EscalationChain`/`EscalationStep`) and the pure
//!   [`escalation::next_escalation`] function the scheduler drives every
//!   tick: notify priority 0, wait `ack_timeout`, escalate, re-notify on
//!   `repeat_interval`.
//! - [`approvals`] — `approve`/`deny`/`sweep_expired`, composed over
//!   `db::ApprovalRepo` and `policy::PolicyExecute`. `approve` executes the
//!   STORED command verbatim, never a fresh LLM interpretation, audited
//!   under both the requesting agent's principal and the approving operator.
//! - [`postmortem`] — `render_postmortem`, a pure function from an
//!   `Incident` + its `AuditRecord`s to structured markdown.

pub mod approvals;
pub mod escalation;
pub mod fingerprint;
pub mod lifecycle;
pub mod postmortem;

pub use approvals::{
    DEFAULT_APPROVAL_TIMEOUT, DecisionOutcome, NewApproval, approve, deny, new_approval_request,
    sweep_expired,
};
pub use escalation::{
    EscalationAction, EscalationChain, EscalationState, EscalationStep, next_escalation,
};
pub use fingerprint::{FingerprintKey, fingerprint, fingerprint_for};
pub use lifecycle::{
    CLAIM_KIND_ESCALATION_NOTIFY, claim_key, is_open, is_terminal, validate_transition,
};
pub use postmortem::render_postmortem;
