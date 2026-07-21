//! Incident engine (Wave 3): fingerprinting, claim-based dedup (one incident
//! → one alert), lifecycle transitions, escalation contact chain, postmortem
//! rendering. Types live in `crate::domain`; persistence in `db::repo`.
