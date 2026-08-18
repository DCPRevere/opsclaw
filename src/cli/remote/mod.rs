//! The REMOTE-mode CLI surface (DESIGN.md §1/§7 decision 14): `opsclaw-cli`
//! talking to a live daemon's gateway over its token-auth API, instead of
//! linking the library directly. Reached when `session::load()` finds a
//! saved session (`login` wrote it, or `OPSCLAW_TOKEN`/`OPSCLAW_SERVER` is
//! set) — `bin/cli/main.rs`'s dispatch is the one place that decides
//! local-vs-remote per invocation.
//!
//! Decision 14's "small set": `chat`, `incidents [list|show]`, `approve
//! <id>`/`deny <id>`, `estop engage|resume`, `status` — plus `login`/
//! `logout` (session lifecycle) and `whoami` (a natural, tiny addition next
//! to them). Everything else stays local-CLI-only or web-UI-only; this
//! module does not grow a remote twin of `runbook`/`memory`/`config`/
//! `onboard`/`doctor`/`audit`/`postmortem` — those need either local
//! filesystem access this process doesn't have when remote (config wizards,
//! runbook files) or simply aren't in decision 14's list, and growing the
//! remote surface past what DESIGN.md named is exactly the kind of
//! un-reviewed scope creep the decision was written to prevent.
//!
//! ## Session storage
//!
//! See [`session`] for the full rationale; short version: `~/.opsclaw/
//! cli.toml`, deliberately NOT `config.toml` (a personal bearer token must
//! never end up in a file meant to be shared/synced), 0600.
//!
//! ## Module split
//!
//! One file per command family, mirroring `cli::mod`'s own local-mode
//! split: [`auth`] (login/logout), [`chat`], [`incidents`], [`approvals`],
//! [`estop`], [`status`] (status + whoami). [`client`] is the shared HTTP
//! plumbing every one of them calls through. Every function here takes an
//! already-loaded [`session::Session`] (never loads one itself beyond
//! `client::require_session`, which the CLI's dispatch calls once) so each
//! is testable against a `wiremock::MockServer` in isolation.

pub mod approvals;
pub mod auth;
pub mod chat;
pub mod client;
pub mod estop;
pub mod history;
pub mod incidents;
pub mod invites;
pub mod session;
pub mod status;
