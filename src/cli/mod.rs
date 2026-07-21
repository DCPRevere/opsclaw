//! CLI logic (`opsclaw-cli`) — DESIGN.md §1 ("`opsclaw-cli` — onboard,
//! config wizards, chat REPL, estop, incidents, postmortem, doctor,
//! runbook, memory") and §5 (onboard → config project add → doctor →
//! daemon in under ten minutes is definition-of-done #1).
//!
//! **Both modes now.** LOCAL mode (the original, and still most of this
//! module) links the library directly and drives the same paths a live
//! daemon would use (gianna pattern, DESIGN.md §1: "the CLI drives the same
//! orchestrator path as every channel, zero duplicated logic") — no logic
//! is reimplemented here that already lives in `config/`, `policy/`, `db/`,
//! `audit/`, `incidents/`, or `runbooks/`; this module is glue: parse args,
//! call the library, format output. REMOTE mode (DESIGN.md §4 "remote-CLI
//! API", §7 decision 14) lives entirely under [`remote`] and opens an HTTP
//! client to a daemon's gateway instead — see that module's doc for the
//! session-storage/scope rationale. `bin/cli/main.rs`'s dispatch is the one
//! place that decides which mode a given invocation uses: `chat`/`estop`
//! default to local and take an explicit `--remote` flag to use the saved
//! gateway session instead; `status`/`approve`/`deny`/`whoami` are
//! remote-only (no local analogue — they act on a live daemon); `login`/
//! `logout` manage the remote session itself. This module never needs to
//! know which mode called it.
//!
//! Module split mirrors one command family per file, each exposing plain
//! functions the `opsclaw-cli` binary's clap dispatch calls directly — kept
//! free of clap types themselves so they're callable (and testable) without
//! going through argv parsing.

pub mod audit_cmd;
pub mod chat_repl;
pub mod config_cmd;
pub mod doctor;
pub mod estop;
pub mod incidents_cmd;
pub mod legacy;
pub mod memory_cmd;
pub mod onboard;
pub mod output;
pub mod postmortem_cmd;
pub mod prompt;
pub mod remote;
pub mod runbook_cmd;
pub mod scan_cmd;
pub mod secret_cmd;
pub mod ui_cmd;
pub mod vapid;
