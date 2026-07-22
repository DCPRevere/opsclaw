//! Config read/update (DESIGN §3: "Config edits go through daemon API
//! handlers that validate and rewrite `config.toml` — the file stays the
//! single source of truth and stays hand-editable"). No gianna analog
//! (gianna has no config-file concept for operators to hand-edit) — this
//! module is new, matching the shape of every other route here: `Authed`,
//! a thin JSON wrapper over existing pure functions (`Config::validate`,
//! `config::persist_config_text`).
//!
//! `Config` can never leak a secret VALUE through this surface by
//! construction (`config`'s module doc): it holds only [`SecretRef`]s
//! (names), so both the TOML and JSON serializations carry exactly the
//! `env:VAR`/`store:KEY` reference strings that are already on disk —
//! never a resolved value. Route tests pin this property anyway
//! (`tests/e2e_flow.rs::config_read_never_contains_secret_values`) so a
//! future by-value field can't regress it silently.
//!
//! Surface (deliberately narrow):
//! - `GET  /api/config` — the full running config (TOML + JSON views);
//! - `POST /api/config` — replace the whole file (raw TOML, the settings
//!   textarea);
//! - `PUT  /api/config/escalation` — set the global or one project's
//!   escalation chain;
//! - `PUT  /api/config/policy` — replace `[policy]` bound lists;
//! - `PUT  /api/config/autonomy` — set/clear one project/env/target
//!   autonomy level (promotion to `auto` requires `confirm_auto: true`).
//!
//! There are NO create/delete endpoints for projects or targets — that
//! intake is wizard-only for now (`opsclaw-cli config project add`), on
//! purpose: a project declaration carries credentials-by-reference and
//! per-kind resource shapes that the wizard walks an operator through; a
//! bare JSON POST would make it too easy to declare a half-wired target.
//!
//! Every write goes through the same pipeline: load the ON-DISK config
//! (never the in-memory boot snapshot — a hand-edit since boot must not be
//! silently reverted by an API edit), apply the change, run the SAME
//! `Config::validate()` the daemon boots with (400 with the validation
//! message on refusal, file untouched), then persist via
//! [`crate::config::persist_config_text`] — atomic temp-file+rename with a
//! `.bak` of the previous contents (an earlier incident overwrote an
//! operator's config; the `.bak` is the one-`mv` recovery path).

use axum::extract::State;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Error;
use crate::Result;
use crate::config::{Config, EscalationCfg, EscalationStepCfg};
use crate::domain::Autonomy;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/config", get(get_config).post(update_config))
        .route("/api/config/escalation", put(put_escalation))
        .route("/api/config/policy", put(put_policy))
        .route("/api/config/autonomy", put(put_autonomy))
}

/// GET /api/config — the CONFIG THIS DAEMON IS ACTUALLY RUNNING WITH,
/// serialized from `state.config` (the in-memory value resolved once at
/// boot — `http::state`'s module doc), never re-read from disk: it can
/// never disagree with the daemon's actual behaviour (a hand-edit since
/// boot hasn't taken effect yet either way — see `update_config`'s note on
/// restarts), and the read path stays disk-IO-free so a test's
/// `AppState::fake` never touches a real machine's `~/.opsclaw`.
///
/// Returned in BOTH shapes the settings page needs: `toml` (the raw-file
/// editor textarea) and `config` (structured JSON, so the escalation/
/// policy/autonomy editors can seed themselves without a TOML parser in
/// the browser). Secrets appear as their reference strings only — see the
/// module doc.
async fn get_config(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let toml_text = toml::to_string_pretty(&*state.config)
        .map_err(|e| Error::other(format!("serialize config: {e}")))?;
    let structured = serde_json::to_value(&*state.config)
        .map_err(|e| Error::other(format!("serialize config: {e}")))?;
    Ok(Json(json!({
        "toml": toml_text,
        "config": structured,
        "path": state.config_path.display().to_string(),
    })))
}

#[derive(Deserialize)]
pub struct UpdateConfigReq {
    pub toml: String,
}

/// POST /api/config — parse, validate (the SAME `Config::validate` the
/// daemon runs at boot — this surface can never accept something the
/// daemon itself would refuse to start with), then atomically rewrite
/// `config.toml` (with a `.bak` of what it replaced). The in-memory
/// `AppState.config` this request handled with is NOT hot-reloaded
/// (DESIGN §3/AGENTS.md: config changes take effect on the next daemon
/// restart) — the response says so explicitly rather than implying the
/// change is live.
///
/// The write target is `state.config_path` — the EXACT path the daemon
/// loaded its config from, injected at boot. Never `config::default_dir()`
/// resolved here: an earlier version of this handler did that, and a test
/// run overwrote the developer's real `~/.opsclaw/config.toml` (the
/// incident documented on `AppState::config_path`). `AppState::fake`
/// points the field at a per-instance non-existent temp path, so a
/// fakes-mode write is physically incapable of reaching a real config.
///
/// The raw request text is written verbatim (not re-serialized through
/// `Config`) so an operator's comments and formatting survive the save —
/// the file "stays hand-editable" promise.
async fn update_config(
    State(state): State<AppState>,
    Authed(_ctx): Authed,
    Json(req): Json<UpdateConfigReq>,
) -> Result<Json<Value>> {
    let parsed: Config =
        toml::from_str(&req.toml).map_err(|e| Error::validation(format!("invalid TOML: {e}")))?;
    parsed.validate().map_err(|e| Error::validation(e.to_string()))?;
    crate::config::persist_config_text(&state.config_path, &req.toml)?;
    Ok(Json(json!({ "ok": true, "note": RESTART_NOTE })))
}

const RESTART_NOTE: &str =
    "saved — restart the daemon to apply (config is read at boot, not hot-reloaded)";

/// Load the ON-DISK config for a structured edit: file-or-default, WITHOUT
/// the env overlay — the same stance as `cli::config_cmd`'s wizard loads,
/// and for the same reason: re-applying `apply_env_overlay` before a
/// re-write would silently bake this daemon process's ambient environment
/// (e.g. `OPENROUTER_API_KEY` exported in its unit file) into the team's
/// shared `config.toml`.
fn load_for_edit(path: &std::path::Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let raw = std::fs::read_to_string(path)?;
    toml::from_str(&raw).map_err(|e| Error::validation(format!("existing {}: {e}", path.display())))
}

/// The shared back half of every structured edit: validate the WHOLE
/// mutated config with the boot-time `Config::validate()` (a 400 with the
/// validation message on refusal — the file is untouched), then persist
/// atomically with a `.bak` of the previous contents.
fn validate_and_persist(state: &AppState, cfg: &Config) -> Result<Json<Value>> {
    cfg.validate().map_err(|e| Error::validation(e.to_string()))?;
    let body =
        toml::to_string_pretty(cfg).map_err(|e| Error::other(format!("serialize config: {e}")))?;
    crate::config::persist_config_text(&state.config_path, &body)?;
    Ok(Json(json!({ "ok": true, "note": RESTART_NOTE })))
}

#[derive(Deserialize)]
pub struct EscalationEditReq {
    /// `None` edits the GLOBAL `[escalation]` chain; `Some(name)` edits
    /// that project's `[project.escalation]` override. The project must
    /// already exist — this surface never creates one (wizard-only).
    pub project: Option<String>,
    /// The full replacement chain, in order. For a project, `[]` REMOVES
    /// the override (back to inheriting the global chain) — the only
    /// sensible reading, since a declared-empty override is a validation
    /// error. For the global chain, `[]` resets to the built-in broadcast
    /// default.
    pub steps: Vec<EscalationStepCfg>,
}

/// PUT /api/config/escalation — set the global or one project's escalation
/// chain (Task A's `Config::escalation_chain_for` inheritance: project
/// override > global > built-in broadcast).
async fn put_escalation(
    State(state): State<AppState>,
    Authed(_ctx): Authed,
    Json(req): Json<EscalationEditReq>,
) -> Result<Json<Value>> {
    let mut cfg = load_for_edit(&state.config_path)?;
    match &req.project {
        None => cfg.escalation.steps = req.steps,
        Some(name) => {
            let project = cfg
                .projects
                .iter_mut()
                .find(|p| &p.name == name)
                .ok_or_else(|| Error::validation(format!("no project named {name:?}")))?;
            project.escalation = if req.steps.is_empty() {
                None // remove the override — inherit the global chain
            } else {
                Some(EscalationCfg { steps: req.steps })
            };
        }
    }
    validate_and_persist(&state, &cfg)
}

/// Each list is optional so a caller can edit one bound without restating
/// the others; a PROVIDED list replaces that bound wholesale (there is no
/// append form — the full list is what an operator reviews).
#[derive(Deserialize)]
pub struct PolicyEditReq {
    pub auto_approve: Option<Vec<String>>,
    pub always_ask: Option<Vec<String>>,
    pub command_allowlist: Option<Vec<String>>,
    pub forbidden_paths: Option<Vec<String>>,
}

/// PUT /api/config/policy — replace `[policy]` bound lists. The empty-entry
/// checks (`""` matches everything — a silent fail-open) run inside
/// `Config::validate()` like every other refusal.
async fn put_policy(
    State(state): State<AppState>,
    Authed(_ctx): Authed,
    Json(req): Json<PolicyEditReq>,
) -> Result<Json<Value>> {
    let mut cfg = load_for_edit(&state.config_path)?;
    if let Some(v) = req.auto_approve {
        cfg.policy.auto_approve = v;
    }
    if let Some(v) = req.always_ask {
        cfg.policy.always_ask = v;
    }
    if let Some(v) = req.command_allowlist {
        cfg.policy.command_allowlist = v;
    }
    if let Some(v) = req.forbidden_paths {
        cfg.policy.forbidden_paths = v;
    }
    validate_and_persist(&state, &cfg)
}

#[derive(Deserialize)]
pub struct AutonomyEditReq {
    pub project: String,
    /// With `env` (and optionally `target`) the edit lands on that node;
    /// project-only edits the project level. `target` without `env` is
    /// refused — the tree has no such address.
    pub env: Option<String>,
    pub target: Option<String>,
    /// The level to set; absent/`null` CLEARS the override at that node so
    /// it inherits from the level above (target > env > project >
    /// `suggest` — `Config::autonomy_for`).
    pub autonomy: Option<Autonomy>,
    /// Required `true` when `autonomy` is `"auto"` — a fat-finger guard:
    /// full autonomy is the one promotion that removes the human from the
    /// loop, so it must never happen from a mis-pasted request body.
    #[serde(default)]
    pub confirm_auto: bool,
}

/// PUT /api/config/autonomy — set or clear the autonomy override on an
/// EXISTING project/env/target (this surface never creates tree nodes —
/// wizard-only). "Never silently toward more autonomy": promoting to
/// `auto` demands an explicit `confirm_auto: true` in the same request.
async fn put_autonomy(
    State(state): State<AppState>,
    Authed(_ctx): Authed,
    Json(req): Json<AutonomyEditReq>,
) -> Result<Json<Value>> {
    if req.autonomy == Some(Autonomy::Auto) && !req.confirm_auto {
        return Err(Error::validation(
            "setting autonomy to \"auto\" removes the human from the loop — repeat the request \
             with confirm_auto: true to confirm",
        ));
    }
    if req.target.is_some() && req.env.is_none() {
        return Err(Error::validation("a target-level edit needs its env too"));
    }

    let mut cfg = load_for_edit(&state.config_path)?;
    let project = cfg
        .projects
        .iter_mut()
        .find(|p| p.name == req.project)
        .ok_or_else(|| Error::validation(format!("no project named {:?}", req.project)))?;
    let slot = match (&req.env, &req.target) {
        (None, None) => &mut project.autonomy,
        (Some(env), target) => {
            let env_cfg = project.envs.iter_mut().find(|e| &e.name == env).ok_or_else(|| {
                Error::validation(format!("project {:?} has no env {env:?}", req.project))
            })?;
            match target {
                None => &mut env_cfg.autonomy,
                Some(target) => {
                    &mut env_cfg
                        .targets
                        .iter_mut()
                        .find(|t| &t.name == target)
                        .ok_or_else(|| {
                            Error::validation(format!(
                                "env {:?}::{env:?} has no target {target:?}",
                                req.project
                            ))
                        })?
                        .autonomy
                }
            }
        }
        (None, Some(_)) => unreachable!("refused above"),
    };
    *slot = req.autonomy;
    validate_and_persist(&state, &cfg)
}

// HTTP-level coverage (real bound server + reqwest — this repo's e2e
// convention) lives in `tests/e2e_flow.rs`'s `config_surface_*` /
// `config_read_never_contains_secret_values` / `config_edit_*` tests: an
// auth round trip needs a seeded account + login, which that file's
// fixtures already provide.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autonomy_req_auto_without_confirm_is_shaped_for_refusal() {
        // The guard itself is exercised over HTTP in e2e; this pins the
        // serde shape — `confirm_auto` absent must default to false, never
        // to "confirmed".
        let req: AutonomyEditReq = serde_json::from_value(serde_json::json!({
            "project": "p", "autonomy": "auto"
        }))
        .unwrap();
        assert_eq!(req.autonomy, Some(Autonomy::Auto));
        assert!(!req.confirm_auto, "absent confirm_auto must never read as confirmed");
    }
}
