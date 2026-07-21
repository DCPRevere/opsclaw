//! Remote-CLI session storage: `~/.opsclaw/cli.toml` (or
//! `$OPSCLAW_CLI_HOME/cli.toml` — see [`session_dir`]), 0600. Deliberately a
//! SEPARATE file from `config.toml` — DESIGN.md's task brief for this wave
//! is explicit: "NEVER store the token in the shared config.toml". Two
//! reasons that split matters, not just one:
//!
//! - `config.toml` is meant to be committed/shared/synced between an
//!   operator's machines and even between teammates setting up a new
//!   deployment (`config_cmd::write_config`'s callers include the onboarding
//!   wizard); a personal bearer token living in it would leak the moment
//!   anyone copied that file, same failure shape `config::SecretStore`
//!   exists to prevent for target credentials.
//! - `config.toml` holds LOCAL-mode daemon config (which gateway THIS box
//!   runs); `cli.toml` holds REMOTE-mode session state (which gateway a
//!   human operator's `opsclaw-cli` is currently signed in to). They can
//!   legitimately differ — an operator's laptop has no local daemon at all,
//!   only a remote session — so conflating the files would conflate two
//!   independent axes.
//!
//! Named and shaped after gianna's `bin/cli/remote/mod.rs` session file
//! (`~/.config/gianna/session.json`) — same idea (server + token, file
//! perms 0600, env var override for CI/scripting), TOML instead of JSON
//! only because this crate's config story is already TOML end to end and
//! there's no reason to introduce a second serialization format for one
//! small file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    /// The gateway's base URL, no trailing slash (e.g.
    /// `https://opsclaw.example.com`).
    pub server: String,
    /// The `ops_`-prefixed bearer token `login` minted. Plaintext, ON DISK,
    /// 0600 — the same trust model as `~/.ssh/id_ed25519`: this file's
    /// permissions ARE the protection, not an additional layer.
    pub token: String,
}

/// Where the session file lives: `$OPSCLAW_CLI_HOME/cli.toml` if set (tests
/// use this to avoid touching a real `~/.opsclaw`), else
/// `<config::default_dir()>/cli.toml` — the same `~/.opsclaw` directory
/// `config.toml` and the secret store already live in, just a different
/// file within it (module doc: same directory, deliberately separate file).
pub fn session_dir() -> PathBuf {
    std::env::var_os("OPSCLAW_CLI_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(crate::config::default_dir)
}

pub fn session_path() -> PathBuf {
    session_dir().join("cli.toml")
}

/// The session to use: `OPSCLAW_TOKEN` (+ optional `OPSCLAW_SERVER`) wins
/// for CI/scripting (gianna's `GIANNA_TOKEN`/`GIANNA_SERVER` precedent),
/// else the file `login` wrote. `None` (not an error) when neither is
/// present — callers decide what "not logged in" means for their command
/// (`bin/cli/main.rs`'s dispatch uses this to choose local vs. remote mode
/// outright).
pub fn load() -> Option<Session> {
    if let Ok(token) = std::env::var("OPSCLAW_TOKEN") {
        let server = std::env::var("OPSCLAW_SERVER").unwrap_or_default();
        if !server.is_empty() {
            return Some(Session { server: server.trim_end_matches('/').to_string(), token });
        }
        // A token with no server is unusable — fall through to the file
        // rather than returning a session with an empty `server`, which
        // would build nonsense URLs like "/cli/v1/me".
    }
    load_from(&session_path())
}

fn load_from(path: &Path) -> Option<Session> {
    let raw = std::fs::read_to_string(path).ok()?;
    toml::from_str(&raw).ok()
}

/// Persist `session`, creating the directory if needed, permissions 0600
/// (0700 on the containing directory) on unix — a credential file gets the
/// same treatment `~/.ssh` does.
pub fn save(session: &Session) -> Result<PathBuf> {
    save_to(&session_dir(), session)
}

fn save_to(dir: &Path, session: &Session) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("cli.toml");
    let body = toml::to_string_pretty(session)
        .map_err(|e| crate::Error::Config(format!("serializing cli session: {e}")))?;
    // Temp file + rename, same crash-safety stance as
    // `cli::config_cmd::write_config`.
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

/// Delete the session file if present (idempotent — `logout` calls this
/// even when there's nothing to delete). Returns whether a file was
/// actually removed.
pub fn clear() -> Result<bool> {
    let path = session_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Serializes every test in this crate that touches `OPSCLAW_TOKEN`/
/// `OPSCLAW_SERVER`/`OPSCLAW_CLI_HOME` — env vars are process-global, so
/// `cargo test`'s default parallel threads can otherwise interleave two
/// tests' `set_var`/`remove_var` calls (same hazard, same fix as
/// `llm::chain::tests::ENV_LOCK`, which this mirrors in spirit). `tokio::
/// sync::Mutex`, not `std::sync::Mutex`: the tests sharing this lock are
/// `#[tokio::test]`s that hold the guard across `.await` points (a real
/// HTTP round-trip against a `wiremock` server needs to happen while the
/// env vars stay pinned), and `clippy::await_holding_lock` correctly
/// refuses that for a std mutex. `pub(crate)` so `cli::remote::auth`'s and
/// `cli::remote::client`'s test modules — the other two places that touch
/// these same env vars — share this ONE lock rather than each declaring
/// their own (which would defeat the point: two different locks don't
/// serialize against each other).
#[cfg(test)]
pub(crate) static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let session =
            Session { server: "https://gw.example.com".into(), token: "ops_abc123".into() };
        let path = save_to(dir.path(), &session).unwrap();
        assert!(path.exists());

        let loaded = load_from(&path).unwrap();
        assert_eq!(loaded, session);
    }

    #[test]
    fn load_from_missing_file_is_none_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_from(&dir.path().join("nope.toml")).is_none());
    }

    #[test]
    fn load_from_corrupt_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        std::fs::write(&path, "not valid toml {{{").unwrap();
        assert!(load_from(&path).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let session =
            Session { server: "https://gw.example.com".into(), token: "ops_abc123".into() };
        let path = save_to(dir.path(), &session).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn clear_reports_whether_a_file_existed() {
        // `#[test]`, not `#[tokio::test]` — see `client.rs`'s matching
        // comment for why `blocking_lock` is the right call here.
        let _g = ENV_LOCK.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("OPSCLAW_CLI_HOME", dir.path()) };

        assert!(!clear().unwrap(), "nothing to clear yet");
        save(&Session { server: "https://x".into(), token: "ops_x".into() }).unwrap();
        assert!(clear().unwrap());
        assert!(!session_path().exists());

        unsafe { std::env::remove_var("OPSCLAW_CLI_HOME") };
    }
}
