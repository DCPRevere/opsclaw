//! OpsClaw — an autonomous SRE agent.
//!
//! `OPSCLAW_BRIEF.md` is the reference for intent, `docs/DESIGN.md` for
//! architecture, `docs/plans/IMPLEMENTATION.md` for the build plan. The
//! architecture is transplanted from gianna (a production agent by the same
//! author); module-level docs note what was ported and what is new.
//!
//! Safety invariant (enforced by structure, asserted in tests): nothing can
//! reach a [`targets::TargetExecutor`] except through [`policy`], which
//! classifies risk, checks the e-stop, applies autonomy gates, and writes the
//! audit chain around every remote command.

pub mod agent;
pub mod audit;
pub mod boot;
pub mod channels;
pub mod cli;
pub mod config;
pub mod db;
pub mod domain;
pub mod error;
pub mod http;
pub mod incidents;
pub mod llm;
pub mod memory;
pub mod policy;
pub mod runbooks;
pub mod scheduler;
pub mod targets;
pub mod tools;

pub use error::{Error, Result};

/// Build version, embedded at compile time.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
