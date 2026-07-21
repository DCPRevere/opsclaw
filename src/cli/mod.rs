//! Local-mode CLI logic (`opsclaw-cli`), Wave 4 — DESIGN.md §1 ("`opsclaw-cli`
//! — onboard, config wizards, chat REPL, estop, incidents, postmortem,
//! doctor, runbook, memory") and §5 (onboard → config project add → doctor →
//! daemon in under ten minutes is definition-of-done #1).
//!
//! **Local mode only.** Remote mode (talking to a daemon's gateway over the
//! token-auth API — DESIGN.md §4 "remote-CLI API") is a later wave; nothing
//! here opens an HTTP client. Everything is a thin wrapper that links the
//! library directly and drives the same paths a live daemon would use
//! (gianna pattern, DESIGN.md §1: "the CLI drives the same orchestrator path
//! as every channel, zero duplicated logic") — no logic is reimplemented
//! here that already lives in `config/`, `policy/`, `db/`, `audit/`,
//! `incidents/`, or `runbooks/`; this module is glue: parse args, call the
//! library, format output.
//!
//! Module split mirrors one command family per file, each exposing plain
//! functions the `opsclaw-cli` binary's clap dispatch calls directly — kept
//! free of clap types themselves so they're callable (and testable) without
//! going through argv parsing.

pub mod audit_cmd;
pub mod config_cmd;
pub mod doctor;
pub mod estop;
pub mod incidents_cmd;
pub mod legacy;
pub mod onboard;
pub mod output;
pub mod postmortem_cmd;
pub mod prompt;
pub mod runbook_cmd;
pub mod vapid;
