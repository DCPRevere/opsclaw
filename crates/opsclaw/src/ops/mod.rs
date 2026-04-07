//! OpsClaw operational modules: context, notifications, snapshot persistence and monitor logging.

pub mod approval;
pub mod baseline;
pub mod context;
pub mod daemon;
pub mod data_sources;
pub mod diagnosis;
pub mod digest;
pub mod doctor;
pub mod escalation;

pub mod event_stream;
pub mod incident_search;
pub mod log_sources;
pub mod monitor_log;
pub mod notifier;
pub mod postmortem;
pub mod probes;
pub mod runbooks;
pub mod setup;
pub mod snapshots;
pub mod status;
