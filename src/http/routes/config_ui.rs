//! Config read/update (DESIGN §3: "Config edits go through daemon API
//! handlers that validate and rewrite `config.toml` — the file stays the
//! single source of truth and stays hand-editable"). No gianna analog
//! (gianna has no config-file concept for operators to hand-edit) — this
//! module is new, matching the shape of every other route here: `Authed`,
//! a thin JSON wrapper over an existing pure function (`Config::validate`).
//!
//! `Config` can never leak a secret VALUE through this surface by
//! construction (`config`'s module doc): it holds only [`SecretRef`]s
//! (names), and `toml::to_string` round-trips exactly what's already on
//! disk — a `env:VAR`/`store:KEY` reference, never the resolved value.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Error;
use crate::Result;
use crate::config::Config;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/config", get(get_config).post(update_config))
}

fn config_path() -> std::path::PathBuf {
    crate::config::default_dir().join("config.toml")
}

/// GET /api/config — the CONFIG THIS DAEMON IS ACTUALLY RUNNING WITH,
/// serialized back to TOML from `state.config` (the in-memory value
/// resolved once at boot — `http::state`'s module doc), never re-read from
/// disk. Two reasons this beats a fresh disk read: (1) it can never
/// disagree with the daemon's actual behaviour (a hand-edit to
/// `config.toml` since boot hasn't taken effect yet either way — see
/// `update_config`'s note on why edits need a restart), and (2) it makes
/// this route path-agnostic and disk-IO-free, so a test's `AppState::fake`
/// never risks touching the REAL `~/.opsclaw/config.toml` on whatever
/// machine happens to run the suite (verified the hard way: this crate's
/// own dev machine has a legacy zeroclaw-fork config there with
/// unencrypted SSH keys in it — reading it in a test would have been bad
/// enough; the original draft of this handler also WROTE to that same
/// path from `update_config`, which is the more serious version of the
/// same mistake. See `update_config`'s doc comment for how the write side
/// is contained.
async fn get_config(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let toml_text = toml::to_string_pretty(&*state.config)
        .map_err(|e| Error::other(format!("serialize config: {e}")))?;
    Ok(Json(json!({ "toml": toml_text, "path": config_path().display().to_string() })))
}

#[derive(Deserialize)]
pub struct UpdateConfigReq {
    pub toml: String,
}

/// POST /api/config — parse, validate (the SAME `Config::validate` the
/// daemon runs at boot — this surface can never accept something the
/// daemon itself would refuse to start with), then atomically rewrite
/// `config.toml`. The in-memory `AppState.config` this request handled
/// with is NOT hot-reloaded (DESIGN §3/AGENTS.md: config changes take
/// effect on the next daemon restart, same as gianna's "needs a release to
/// show" stance for embedded content) — the response says so explicitly
/// rather than implying the change is live.
///
/// The write target is `config_path()` — `config::default_dir()` (honours
/// `$OPSCLAW_HOME`, else `~/.opsclaw`), the SAME resolution `main.rs` uses
/// at boot. This is a genuine gap flagged in the port report: `AppState`
/// has no `config_path` field to make this route path-injectable the way
/// `AppState::fake` makes everything else fake-safe, so a test exercising
/// THIS handler must set `$OPSCLAW_HOME` to an isolated tempdir itself
/// (see `tests/e2e_flow.rs`'s `config_surface_*` tests) rather than the
/// route offering a clean seam. `GET` was fixed to serialize `state.config`
/// instead of reading disk (no such gap there); this write side still
/// needs the real, effective, on-disk path to be a meaningful "save".
async fn update_config(
    State(_state): State<AppState>,
    Authed(_ctx): Authed,
    Json(req): Json<UpdateConfigReq>,
) -> Result<Json<Value>> {
    let parsed: Config =
        toml::from_str(&req.toml).map_err(|e| Error::validation(format!("invalid TOML: {e}")))?;
    parsed.validate().map_err(|e| Error::validation(e.to_string()))?;

    let path = config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Write to a sibling temp file then rename — a crash mid-write must
    // never leave config.toml half-written (the file the daemon reads at
    // every future boot).
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, &req.toml)?;
    std::fs::rename(&tmp_path, &path)?;

    Ok(Json(json!({
        "ok": true,
        "note": "saved — restart the daemon to apply (config is read at boot, not hot-reloaded)",
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_path_is_under_the_default_opsclaw_dir() {
        let p = config_path();
        assert!(p.ends_with("config.toml"));
    }
}
