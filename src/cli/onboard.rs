//! `opsclaw-cli onboard` — the first-run wizard (DESIGN.md §5: "`opsclaw
//! onboard` → `config project add` (chaining wizards) → `doctor` → `daemon`
//! in under ten minutes is definition-of-done #1").
//!
//! Idempotent by design: re-running `onboard` against an already-onboarded
//! `~/.opsclaw` must not regenerate the VAPID keypair (gianna's lesson,
//! ported into `PushCfg`'s own half-set-pair check — DESIGN.md §4: "never
//! rotate [VAPID keys] (breaks every subscribed device)") or clobber an
//! existing `config.toml`'s projects. `SecretStore::open` is already
//! idempotent (creates the key file only if absent, `config/secrets.rs`);
//! this module mirrors that for everything else it touches.
//!
//! Two entry points: [`run`] (interactive, drives any [`Prompter`]) and
//! [`run_non_interactive`] (`--yes`, flag-driven, for CI/scripted installs —
//! DESIGN.md doesn't mandate a flag surface here, but a wizard with no
//! non-interactive escape hatch is untestable in CI by construction, so this
//! exists from day one rather than being bolted on later). Both read the
//! same [`NonInteractiveOptions`]: a flag that means something under `--yes`
//! means the same thing interactively, as the prompt's default.

use std::path::Path;

use base64::Engine;
use rand::Rng;
use serde::Serialize;

use crate::Result;
use crate::cli::config_cmd::write_config;
use crate::cli::prompt::Prompter;
use crate::cli::vapid;
use crate::config::{AuthProvider, Config, SecretRef, SecretStore};

#[derive(Debug, Serialize)]
pub struct OnboardOutcome {
    pub config_path: String,
    pub config_created: bool,
    pub secret_store_path: String,
    pub vapid_generated: bool,
    pub jwt_generated: bool,
    pub summary: Vec<String>,
}

/// The `onboard` flags. Named for the path they were built for, but read by
/// BOTH: under `--yes` these are the answers, and interactively they are the
/// prompt defaults ([`ask_defaulted`]). Wiring only the scripted path to them
/// is what made `--hindsight-url` a flag clap accepted and the wizard
/// ignored — including in the onboarding command `deploy/docker-compose.yml`
/// documents.
///
/// Every field is optional — an unset field is left at `Config::default()`
/// for that section, which is the fully-faked, self-validating boot
/// DESIGN.md §3 promises ("with zero config the whole daemon runs and
/// self-validates on fakes").
#[derive(Debug, Default, Clone)]
pub struct NonInteractiveOptions {
    pub openrouter_api_key_env: Option<String>,
    pub models: Vec<String>,
    pub hindsight_url: Option<String>,
    pub telegram_bot_token_env: Option<String>,
    pub deadman_url: Option<String>,
    /// Which identity provider fronts sign-in. Unset leaves the config's
    /// current value (`local` on a fresh install), so a scripted install
    /// that says nothing about auth keeps password sign-in.
    pub auth_provider: Option<AuthProvider>,
    pub hanko_api_url: Option<String>,
    pub hanko_audience: Vec<String>,
}

/// Shared setup: refuse on a legacy config, open (idempotently create) the
/// secret store, and load-or-default the config WITHOUT the env overlay
/// (same reasoning as `config_cmd::load_for_edit` — a wizard write must
/// round-trip through exactly what's on disk, not bake in this process's
/// ambient environment).
fn prepare(config_path: &Path, opsclaw_home: &Path) -> Result<(Config, bool, SecretStore)> {
    let config_existed = config_path.exists();
    if config_existed {
        let raw = std::fs::read_to_string(config_path)?;
        if crate::cli::legacy::looks_like_legacy_config(&raw) {
            return Err(crate::Error::Config(format!(
                "{}: {}",
                config_path.display(),
                crate::cli::legacy::LEGACY_CONFIG_MESSAGE
            )));
        }
    }
    let cfg = if config_existed {
        let raw = std::fs::read_to_string(config_path)?;
        toml::from_str(&raw)
            .map_err(|e| crate::Error::Config(format!("{}: {e}", config_path.display())))?
    } else {
        Config::default()
    };
    let store = SecretStore::open(opsclaw_home)?;
    Ok((cfg, config_existed, store))
}

/// Ask for one of a fixed set of options by exact string match, re-asking
/// (bounded) rather than silently defaulting — the same shape and the same
/// reasoning as `config_cmd`'s own fixed-option prompt: a mistyped auth
/// provider must never quietly become something else, because "local"
/// silently standing in for "hanko" is a deployment that accepts passwords
/// the operator believes are disabled.
fn ask_choice(
    p: &mut dyn Prompter,
    question: &str,
    options: &[&str],
    default: &str,
) -> Result<String> {
    debug_assert!(options.contains(&default), "default must be one of options");
    let hint = options.join("|");
    for _ in 0..5 {
        let answer = p.ask(&format!("{question} ({hint})"), Some(default))?;
        if options.contains(&answer.as_str()) {
            return Ok(answer);
        }
        p.say(&format!("  not one of: {hint}"));
    }
    Err(crate::Error::Config(format!("too many invalid answers to {question:?}")))
}

/// Ask for a value that has no meaningful blank answer, restating `why` on
/// an empty one. `default` (the current config value, on a rerun) is what a
/// blank answer means when there is one — pressing enter through the wizard
/// keeps what is already configured, never clears it. Bounded (like
/// [`ask_choice`]) rather than looping for ever: a non-interactive stdin at
/// EOF answers "" every time, and an unbounded re-ask would spin instead of
/// failing.
fn ask_required(
    p: &mut dyn Prompter,
    question: &str,
    default: Option<&str>,
    why: &str,
) -> Result<String> {
    for _ in 0..5 {
        let answer = p.ask(question, default)?;
        if !answer.trim().is_empty() {
            return Ok(answer.trim().to_string());
        }
        p.say(&format!("  {why}"));
    }
    Err(crate::Error::Config(format!("no answer given for {question:?}")))
}

/// The `[auth]` question. Asked BEFORE the config is validated and written —
/// an answer collected after that point would never reach `config.toml`.
///
/// The daemon signs its own session cookie either way (see [`ensure_jwt`]);
/// this chooses only who proves the operator's identity at the front door.
///
/// Every default here is the CURRENT value, so a rerun that presses enter
/// through changes nothing — the same never-clobber rule as [`ensure_vapid`]
/// and [`ensure_jwt`]. A hanko install silently answered back down to
/// passwords would leave every account (which under hanko holds no usable
/// password hash at all) unable to sign in.
fn ask_auth(p: &mut dyn Prompter, cfg: &mut Config, summary: &mut Vec<String>) -> Result<()> {
    p.say("[sign-in] who proves an operator is who they say they are when they open the web UI.");
    p.say("          \"local\" is this daemon's own email + password. \"hanko\" hands the front");
    p.say("          door to a Hanko project (passkeys, email codes) and links each account to");
    p.say("          a Hanko user id — no password is ever stored here.");
    let current = match cfg.auth.provider {
        AuthProvider::Local => "local",
        AuthProvider::Hanko => "hanko",
        AuthProvider::Oidc => {
            p.say("          SSO (oidc) is configured in [auth.oidc]; leaving it as it is.");
            summary.push("Sign-in: SSO (oidc), unchanged".into());
            return Ok(());
        }
    };
    let provider = ask_choice(p, "auth provider", &["local", "hanko"], current)?;
    if provider != "hanko" {
        cfg.auth.provider = AuthProvider::Local;
        // validate() refuses hanko fields under local, so switching back
        // clears them rather than writing a config that will not boot.
        cfg.auth.api_url = None;
        cfg.auth.audience.clear();
        summary.push("Sign-in: local email + password".to_string());
        return Ok(());
    }

    cfg.auth.provider = AuthProvider::Hanko;
    let api_url = ask_required(
        p,
        "Hanko API URL (Cloud: https://<tenant>.hanko.io; self-hosted: the PUBLIC port, 8000)",
        cfg.auth.api_base(),
        "required under hanko — the daemon validates every sign-in against it",
    )?;
    if !api_url.starts_with("https://") {
        // validate() refuses this outside fakes mode; say why here rather
        // than let the refusal arrive as a bare error after the whole
        // wizard.
        p.say("  warning: passkeys need a secure context — a http:// URL only works on a dev box");
    }
    cfg.auth.api_url = Some(api_url.clone());

    p.say("  the session audience is Hanko's webauthn.relying_party.id (the domain the web UI is");
    p.say("  served from). It cannot be inferred: without it, a token from ANY Hanko project this");
    p.say("  daemon can reach would be accepted.");
    let current_audience = cfg.auth.audience.join(", ");
    let audience = ask_required(
        p,
        "session audience (comma-separated)",
        Some(current_audience.as_str()).filter(|a| !a.is_empty()),
        "required under hanko — an unchecked audience accepts other projects' tokens",
    )?;
    cfg.auth.audience =
        audience.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    summary.push(format!("Sign-in: hanko at {api_url}, audience {}", cfg.auth.audience.join(", ")));
    Ok(())
}

/// Generate and persist a VAPID keypair into `cfg.push` UNLESS one is
/// already fully set (idempotent — never rotates an existing pair). Returns
/// true iff a new pair was generated. The private key is stored in the
/// secret store (never written to config.toml in the clear — `SecretRef`
/// keeps `Config`'s own `Debug` redaction and the audit-layer scrubber
/// meaningful for it exactly like every other secret); the public key is
/// not secret (it's shipped to every browser as `applicationServerKey`) and
/// is stored as a plain string, matching `PushCfg.vapid_public_key`'s type.
fn ensure_vapid(cfg: &mut Config, store: &SecretStore) -> Result<bool> {
    if cfg.push.vapid_private_key.is_some() && cfg.push.vapid_public_key.is_some() {
        return Ok(false);
    }
    if cfg.push.vapid_private_key.is_some() || cfg.push.vapid_public_key.is_some() {
        // Half-set already (e.g. hand-edited config.toml) — do not paper
        // over it by generating a fresh pair; that would silently discard
        // whichever half was set. validate() will refuse to boot on this;
        // surface the same refusal here rather than guessing.
        return Err(crate::Error::Config(
            "push: vapid_private_key/vapid_public_key are half-set — set both or clear both before \
             running onboard again (onboard never overwrites an existing key, generated or hand-set)"
                .into(),
        ));
    }
    let kp = vapid::generate();
    const SECRET_NAME: &str = "vapid_private_key";
    store.set(SECRET_NAME, &kp.private_key)?;
    cfg.push.vapid_private_key = Some(SecretRef::store(SECRET_NAME));
    cfg.push.vapid_public_key = Some(kp.public_key);
    Ok(true)
}

/// Wire the gateway JWT secret on first run. Live mode's `validate()`
/// refuses an unset `http.jwt_secret` (the dev-default fallback would let
/// anyone forge an operator session), and unlike a provider key there is
/// nothing to ask the operator for — a strong random value is the only
/// right answer, so both wizard paths supply one. An already-referenced
/// secret is kept, and a pre-seeded `store:jwt-secret` value is adopted
/// rather than overwritten: rotating this secret invalidates every
/// signed-in session and CLI token, so onboard must never do it implicitly
/// (the same never-rotate contract as [`ensure_vapid`]).
fn ensure_jwt(cfg: &mut Config, store: &SecretStore) -> Result<bool> {
    if cfg.http.jwt_secret.is_some() {
        return Ok(false);
    }
    const SECRET_NAME: &str = "jwt-secret";
    let generated = store.get(SECRET_NAME)?.is_none();
    if generated {
        let mut buf = [0u8; 48];
        rand::rng().fill_bytes(&mut buf);
        store.set(SECRET_NAME, &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))?;
    }
    cfg.http.jwt_secret = Some(SecretRef::store(SECRET_NAME));
    Ok(generated)
}

/// Chained operator-account creation for the interactive wizard. Opens the
/// same database file the daemon (and `account create`) would — explicit
/// `daemon.db_path` or the default `<home>/opsclaw.sqlite3` — so the account
/// is already there on first boot. The 12-character password rule is stated
/// BEFORE any input and enforced before the confirmation prompt: the old
/// flow's rejection only after typing the password twice is exactly the
/// friction this exists to remove. Returns the created account's email.
///
/// The credential asked for follows `auth.provider`: under hanko there is no
/// password to set (the account carries the `NO_PASSWORD` sentinel), so the
/// password loop is not run at all — prompting for a credential the daemon
/// will never check is worse than not asking.
async fn wizard_account(p: &mut dyn Prompter, cfg: &Config, opsclaw_home: &Path) -> Result<String> {
    let db_path = cfg
        .daemon
        .db_path
        .clone()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| opsclaw_home.join("opsclaw.sqlite3").display().to_string());
    let db = crate::db::Db::connect(&db_path).await?;

    let email = p.ask("operator email", None)?;
    let display_name = p.ask("display name", Some(&email))?;
    let out = match cfg.auth.provider {
        AuthProvider::Oidc => {
            return Err(crate::Error::validation(
                "this daemon signs in through SSO (oidc): set auth.oidc.auto_create = true so \
                 accounts are made at first sign-in, or run `opsclaw-cli account create <email> \
                 --oidc-subject <sub>`",
            ));
        }
        AuthProvider::Local => {
            p.say(
                "  the password must be at least 12 characters (it guards a daemon that can act on",
            );
            p.say("  production systems).");
            let password = loop {
                let first = p.ask_hidden("password (min 12 characters; hidden)")?;
                if first.len() < 12 {
                    p.say("  too short — at least 12 characters, try again");
                    continue;
                }
                let second = p.ask_hidden("confirm password")?;
                if first != second {
                    p.say("  passwords did not match — try again");
                    continue;
                }
                break first;
            };
            crate::cli::account_cmd::create(
                &db,
                &email,
                &display_name,
                crate::cli::account_cmd::Credential::Password(&password),
            )
            .await?
        }
        AuthProvider::Hanko => {
            p.say("  this daemon signs in through hanko, so no password is set here. The account");
            p.say("  links to a Hanko user id (claims.subject in the Hanko console); the operator");
            p.say("  must already exist there.");
            let subject = ask_required(
                p,
                "hanko user id (claims.subject)",
                None,
                "required — it is what the account links to, and sign-in fails without it",
            )?;
            crate::cli::account_cmd::create(
                &db,
                &email,
                &display_name,
                crate::cli::account_cmd::Credential::HankoSubject(&subject),
            )
            .await?
        }
    };
    p.say(&format!(
        "  created operator {} — sign in at the web UI once the daemon is running",
        out.email
    ));
    Ok(out.email)
}

/// Ask a question that may already have a discovered answer.
///
/// With no default this is `p.ask(q, None)` unchanged: blank means skip, and
/// no new vocabulary is introduced where there is nothing to suggest. With a
/// default, blank now means TAKE IT — so the operator who presses enter
/// through the wizard lands on the setup their environment already describes
/// instead of on fakes — and `none` is the explicit way to decline. The skip
/// token is spelled out in the prompt precisely because the meaning of blank
/// flips: an unannounced flip would silently configure things for operators
/// who were deliberately skipping.
fn ask_defaulted(p: &mut dyn Prompter, question: &str, default: Option<&str>) -> Result<String> {
    let Some(default) = default.filter(|d| !d.is_empty()) else {
        return p.ask(question, None);
    };
    let answer =
        p.ask(&format!("{question} (enter to accept, \"none\" to skip)"), Some(default))?;
    Ok(if answer.eq_ignore_ascii_case("none") { String::new() } else { answer })
}

/// The default for the LLM key prompt, best evidence first: an explicit
/// `--openrouter-api-key-env`, else the reference an earlier run already
/// wrote, else the conventional variable name IF it actually holds a value.
///
/// The last clause uses [`Config::env_configured`] rather than a bare
/// `var_os().is_some()` on purpose — `.env.example` ships blank optional
/// credentials, and suggesting a name backed by an empty value is how the
/// v0.1.1 crash-loop started.
fn default_llm_key_env(opts: &NonInteractiveOptions, cfg: &Config) -> Option<String> {
    if let Some(name) = opts.openrouter_api_key_env.as_ref().filter(|n| !n.is_empty()) {
        return Some(name.clone());
    }
    if let Some(SecretRef::Env(name)) = &cfg.llm.api_key {
        return Some(name.clone());
    }
    Config::env_configured(OPENROUTER_KEY_VAR).then(|| OPENROUTER_KEY_VAR.to_string())
}

/// Flag, else what config already holds, else the environment variable the
/// daemon itself reads for this setting.
fn default_from_flag_config_or_env(
    flag: Option<&str>,
    from_config: Option<&str>,
    env_var: &str,
) -> Option<String> {
    flag.filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| from_config.filter(|v| !v.is_empty()).map(str::to_string))
        .or_else(|| {
            Config::env_configured(env_var)
                .then(|| std::env::var(env_var).ok())
                .flatten()
                .map(|v| v.trim().to_string())
        })
}

const OPENROUTER_KEY_VAR: &str = "OPENROUTER_API_KEY";
const TELEGRAM_TOKEN_VAR: &str = "TELEGRAM_BOT_TOKEN";
const OPENROUTER_MODELS_URL: &str = "https://openrouter.ai/api/v1/models";

/// Warn about model ids OpenRouter's public catalogue does not list.
///
/// A mistyped id is accepted by every layer below this one: `validate()`
/// only checks that the list is non-empty when a key is set, and `doctor`
/// checks that the KEY resolves, not that the MODEL exists. So the first
/// symptom is a failed reasoning call during a real incident — the worst
/// possible moment to discover a typo made at install time.
///
/// Warns, never refuses, and treats every failure as silence. The catalogue
/// is a remote service reached over a network that may be air-gapped,
/// proxied, or simply down; an operator must never be blocked from
/// onboarding because a third-party endpoint is unreachable, and a
/// legitimately new model that this catalogue lags behind must not be
/// rejected either. The check is worth having only because it is advisory.
async fn warn_on_unknown_models(p: &mut dyn Prompter, models: &[String]) {
    if let Some(warning) = unknown_model_warning(models).await {
        p.say(&format!("  {warning}"));
    }
}

/// [`warn_on_unknown_models`]'s finding as a line, so `--yes` can carry the
/// same warning where it has no prompter to say it through: a scripted
/// install mistypes a model as readily as a human does.
///
/// Called from the CLI binary rather than from [`run_non_interactive`]
/// itself, deliberately. This reaches the network, and a library function
/// that unit tests drive must not — a test asserting on config-writing would
/// otherwise make a live third-party request as a side effect, going slow
/// when the network is slow and leaking test traffic off the machine. The
/// comparison itself is pure and tested; only the fetch is not.
pub async fn unknown_model_warning(models: &[String]) -> Option<String> {
    if models.is_empty() {
        return None;
    }
    // Offline, proxied, slow, or an unexpected payload: say nothing.
    let known = fetch_openrouter_model_ids().await?;
    let unknown = unknown_model_ids(models, &known);
    if unknown.is_empty() {
        return None;
    }
    Some(format!(
        "warning: OpenRouter does not list {} — check for a typo; an unknown model is accepted \
         here and fails at the first reasoning call, not at `doctor`",
        unknown.join(", ")
    ))
}

/// The ids in `models` that `known` does not contain. Split out from the
/// fetch so the decision is testable without a network.
fn unknown_model_ids<'a>(
    models: &'a [String],
    known: &std::collections::HashSet<String>,
) -> Vec<&'a str> {
    models.iter().map(String::as_str).filter(|m| !known.contains(*m)).collect()
}

/// The `id` of every model OpenRouter currently publishes, or `None` if the
/// catalogue could not be read for any reason. No API key: this endpoint is
/// public, and onboarding must be able to check a model list before any key
/// has been proven to work.
async fn fetch_openrouter_model_ids() -> Option<std::collections::HashSet<String>> {
    let client =
        reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().ok()?;
    let body: serde_json::Value =
        client.get(OPENROUTER_MODELS_URL).send().await.ok()?.json().await.ok()?;
    let ids: std::collections::HashSet<String> = body
        .get("data")?
        .as_array()?
        .iter()
        .filter_map(|m| m.get("id")?.as_str().map(str::to_string))
        .collect();
    // An empty catalogue means the shape changed under us, not that no model
    // exists — treat it as unreadable so every id is left unwarned.
    (!ids.is_empty()).then_some(ids)
}

/// Interactive path: ask, don't assume — but do not re-ask for what is
/// already known. Flags and the surrounding environment become prompt
/// DEFAULTS (see [`ask_defaulted`]), so `--hindsight-url` is honoured here
/// as well as under `--yes`, and a compose install whose `.env` already
/// names every credential can be walked through with the enter key. Where
/// nothing is discoverable the old rule stands: blank skips that
/// integration and lands on the fully-faked, self-validating daemon
/// `Config::default()` already is.
pub async fn run(
    p: &mut dyn Prompter,
    opts: &NonInteractiveOptions,
    config_path: &Path,
    opsclaw_home: &Path,
) -> Result<OnboardOutcome> {
    let (mut cfg, config_existed, store) = prepare(config_path, opsclaw_home)?;
    let mut summary = Vec::new();

    p.say("OpsClaw onboarding — this step creates two things:");
    p.say(&format!("  the config file:            {}", config_path.display()));
    p.say(&format!(
        "  the encrypted secret store: {} (AES-256-GCM, 0600 key file beside it)",
        opsclaw_home.join("secrets.enc").display()
    ));
    p.say("every question can be left blank to skip that integration — the daemon then runs it");
    p.say("in self-validating fakes mode, and you can rerun `opsclaw-cli onboard` any time.");

    p.say("[llm] OpsClaw reasons with an OpenRouter model. The API key is stored by REFERENCE");
    p.say("      (the env var's NAME) — the key's value never enters the config file.");
    let llm_key_env = ask_defaulted(
        p,
        "OpenRouter API key env var name (blank to skip; sets fakes-mode LLM)",
        default_llm_key_env(opts, &cfg).as_deref(),
    )?;
    if !llm_key_env.is_empty() {
        if std::env::var(&llm_key_env).is_err() {
            p.say(&format!(
                "  warning: ${llm_key_env} is not set in this shell — export it where the daemon \
                 runs or the LLM will fail to authenticate"
            ));
        }
        cfg.llm.api_key = Some(SecretRef::env(&llm_key_env));
        let models_default = default_from_flag_config_or_env(
            (!opts.models.is_empty()).then(|| opts.models.join(",")).as_deref(),
            (!cfg.llm.models.is_empty()).then(|| cfg.llm.models.join(",")).as_deref(),
            "OPSCLAW_MODELS",
        );
        let models_raw = ask_defaulted(
            p,
            "comma-separated OpenRouter model list (required if a key is set)",
            models_default.as_deref(),
        )?;
        cfg.llm.models =
            models_raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        warn_on_unknown_models(p, &cfg.llm.models).await;
        summary.push(format!("LLM: env:{llm_key_env}, {} model(s)", cfg.llm.models.len()));
    } else {
        summary.push("LLM: not configured (fakes mode)".to_string());
    }

    p.say("[memory] Hindsight is the optional long-term memory service; without it, memory");
    p.say("         features run as an honest no-op.");
    let hindsight_url = ask_defaulted(
        p,
        "Hindsight URL (blank to skip; memory runs as an honest no-op)",
        default_from_flag_config_or_env(
            opts.hindsight_url.as_deref(),
            cfg.memory.hindsight_url.as_deref(),
            "HINDSIGHT_URL",
        )
        .as_deref(),
    )?;
    if !hindsight_url.is_empty() {
        cfg.memory.hindsight_url = Some(hindsight_url.clone());
        summary.push(format!("Memory: {hindsight_url}"));
    } else {
        summary.push("Memory: not configured (honest no-op)".to_string());
    }

    p.say("[telegram] optional chat channel for alerts and approvals; the bot token is stored");
    p.say("           by env-var REFERENCE, like the LLM key.");
    let telegram_default = opts
        .telegram_bot_token_env
        .clone()
        .or_else(|| match &cfg.telegram.bot_token {
            Some(SecretRef::Env(name)) => Some(name.clone()),
            _ => None,
        })
        .or_else(|| {
            Config::env_configured(TELEGRAM_TOKEN_VAR).then(|| TELEGRAM_TOKEN_VAR.to_string())
        });
    let telegram_env = ask_defaulted(
        p,
        "Telegram bot token env var name (blank to skip)",
        telegram_default.as_deref(),
    )?;
    if !telegram_env.is_empty() {
        if std::env::var(&telegram_env).is_err() {
            p.say(&format!(
                "  warning: ${telegram_env} is not set in this shell — export it where the \
                 daemon runs"
            ));
        }
        cfg.telegram.bot_token = Some(SecretRef::env(&telegram_env));
        summary.push(format!("Telegram: env:{telegram_env}"));
    } else {
        summary.push("Telegram: not configured".to_string());
    }

    p.say("[dead-man] an external heartbeat URL (e.g. healthchecks.io) that alerts you when");
    p.say("           OpsClaw itself dies — essential if it runs inside a cluster it monitors.");
    let deadman_url = ask_defaulted(
        p,
        "external dead-man heartbeat URL (blank to skip; REQUIRED for in-cluster installs)",
        default_from_flag_config_or_env(
            opts.deadman_url.as_deref(),
            cfg.daemon.deadman_url.as_deref(),
            "OPSCLAW_DEADMAN_URL",
        )
        .as_deref(),
    )?;
    if !deadman_url.is_empty() {
        cfg.daemon.deadman_url = Some(deadman_url.clone());
        summary.push(format!("Dead-man heartbeat: {deadman_url}"));
    } else {
        summary.push("Dead-man heartbeat: not configured".to_string());
    }

    ask_auth(p, &mut cfg, &mut summary)?;

    let vapid_generated = ensure_vapid(&mut cfg, &store)?;
    summary.push(if vapid_generated {
        "Push: generated a new VAPID keypair".to_string()
    } else {
        "Push: existing VAPID keypair kept (never rotated)".to_string()
    });

    let jwt_generated = ensure_jwt(&mut cfg, &store)?;
    summary.push(if jwt_generated {
        "Gateway: generated http.jwt_secret (store:jwt-secret)".to_string()
    } else {
        "Gateway: existing JWT secret kept (never rotated)".to_string()
    });

    cfg.validate()?;
    write_config(config_path, &cfg)?;

    p.say(&format!("-- base setup done: wrote {} --", config_path.display()));
    for line in &summary {
        p.say(&format!("  {line}"));
    }

    // The remaining first-run steps (project wizard → operator account →
    // doctor) used to live only in the operator's head; offer each one
    // inline, and print the standalone command whenever a stage is skipped
    // or fails so nothing is lost by bailing out. A stage failure narrates
    // and continues rather than erroring the whole onboard — everything up
    // to here is already safely on disk.
    p.say("[projects] a project groups environments, which group targets — the machines and");
    p.say("           clusters OpsClaw watches. Nothing is monitored until one exists.");
    if p.confirm("add your first project now?", false)? {
        match crate::cli::config_cmd::add_project(p, config_path, &store) {
            Ok(project) => summary.push(format!("Project: added {:?}", project.name)),
            Err(e) => {
                p.say(&format!(
                    "  project wizard failed: {e} — run `opsclaw-cli config project add` when ready"
                ));
            }
        }
    } else {
        p.say("  skipped — run `opsclaw-cli config project add` when ready.");
    }

    // The standalone command differs by provider: `account create` under
    // hanko refuses without `--hanko-subject`, so printing the bare form
    // would send a skipping operator straight into an error.
    let account_cmd = match cfg.auth.provider {
        AuthProvider::Local => "`opsclaw-cli account create <email>`",
        AuthProvider::Hanko => "`opsclaw-cli account create <email> --hanko-subject <id>`",
        AuthProvider::Oidc => "`opsclaw-cli account create <email> --oidc-subject <sub>`",
    };
    p.say("[account] the web UI needs an operator account; the FIRST one can only be created");
    p.say("          from this CLI (it goes straight into the daemon's local database).");
    if cfg.auth.provider == AuthProvider::Hanko {
        p.say("          Under hanko this LINKS an existing Hanko user; it sets no password.");
    }
    if p.confirm("create your operator account now?", false)? {
        match wizard_account(p, &cfg, opsclaw_home).await {
            Ok(email) => summary.push(format!("Account: created {email}")),
            Err(e) => {
                p.say(&format!("  account creation failed: {e} — run {account_cmd} when ready"));
            }
        }
    } else {
        p.say(&format!("  skipped — run {account_cmd} when ready."));
    }

    p.say("[doctor] verifies the whole setup end to end: config validity, every secret");
    p.say("         reference, and reachability of each configured target.");
    if p.confirm("run doctor now?", true)? {
        match crate::cli::doctor::run(config_path, opsclaw_home).await {
            Ok(report) => {
                for check in &report.checks {
                    let mark = if check.ok { "OK  " } else { "FAIL" };
                    p.say(&format!("  [{mark}] {}: {}", check.name, check.detail));
                }
                if !report.ok() {
                    p.say("  fix the FAILs above and re-run `opsclaw-cli doctor` before starting.");
                }
            }
            Err(e) => p.say(&format!("  doctor failed to run: {e}")),
        }
    } else {
        p.say("  skipped — run `opsclaw-cli doctor` before starting the daemon.");
    }

    p.say("all set — start OpsClaw with: `opsclaw-cli daemon`");

    Ok(OnboardOutcome {
        config_path: config_path.display().to_string(),
        config_created: !config_existed,
        secret_store_path: opsclaw_home.display().to_string(),
        vapid_generated,
        jwt_generated,
        summary,
    })
}

/// `--yes` / non-interactive path: same effect as [`run`] with every prompt
/// answered from `opts`, for CI and scripted installs.
pub async fn run_non_interactive(
    opts: &NonInteractiveOptions,
    config_path: &Path,
    opsclaw_home: &Path,
) -> Result<OnboardOutcome> {
    let (mut cfg, config_existed, store) = prepare(config_path, opsclaw_home)?;
    let mut summary = Vec::new();

    if let Some(env_name) = &opts.openrouter_api_key_env {
        cfg.llm.api_key = Some(SecretRef::env(env_name));
        cfg.llm.models = opts.models.clone();
        summary.push(format!("LLM: env:{env_name}, {} model(s)", cfg.llm.models.len()));
    } else {
        summary.push("LLM: not configured (fakes mode)".to_string());
    }

    if let Some(url) = &opts.hindsight_url {
        cfg.memory.hindsight_url = Some(url.clone());
        summary.push(format!("Memory: {url}"));
    } else {
        summary.push("Memory: not configured (honest no-op)".to_string());
    }

    if let Some(env_name) = &opts.telegram_bot_token_env {
        cfg.telegram.bot_token = Some(SecretRef::env(env_name));
        summary.push(format!("Telegram: env:{env_name}"));
    } else {
        summary.push("Telegram: not configured".to_string());
    }

    if let Some(url) = &opts.deadman_url {
        cfg.daemon.deadman_url = Some(url.clone());
        summary.push(format!("Dead-man heartbeat: {url}"));
    } else {
        summary.push("Dead-man heartbeat: not configured".to_string());
    }

    // Auth: an unset --auth-provider leaves whatever is on disk alone, so a
    // rerun that says nothing about auth never downgrades a hanko install
    // back to passwords. Incoherent combinations (hanko with no api_url, a
    // stray api_url under local) are left to `validate()` below — which
    // refuses BEFORE anything is written, exactly like every other section.
    if let Some(provider) = opts.auth_provider {
        cfg.auth.provider = provider;
        // An explicit `--auth-provider local` reverts the SECTION, not just
        // the one field. Leaving a previous install's api_url/audience in
        // place would produce a config `validate()` rejects, so the
        // scripted rollback of a hanko deployment would exit nonzero having
        // written nothing — the interactive wizard already clears them.
        if provider == AuthProvider::Local {
            cfg.auth.api_url = None;
            cfg.auth.audience.clear();
        }
    }
    if let Some(url) = &opts.hanko_api_url {
        cfg.auth.api_url = Some(url.clone());
    }
    if !opts.hanko_audience.is_empty() {
        cfg.auth.audience = opts.hanko_audience.clone();
    }
    summary.push(match cfg.auth.provider {
        AuthProvider::Local => "Sign-in: local email + password".to_string(),
        AuthProvider::Hanko => format!(
            "Sign-in: hanko at {}, audience {}",
            cfg.auth.api_base().unwrap_or("(unset)"),
            cfg.auth.audience.join(", ")
        ),
        AuthProvider::Oidc => format!(
            "Sign-in: SSO (oidc) at {}",
            cfg.auth.oidc.as_ref().map(|o| o.issuer.as_str()).unwrap_or("(unset)")
        ),
    });

    let vapid_generated = ensure_vapid(&mut cfg, &store)?;
    summary.push(if vapid_generated {
        "Push: generated a new VAPID keypair".to_string()
    } else {
        "Push: existing VAPID keypair kept (never rotated)".to_string()
    });

    let jwt_generated = ensure_jwt(&mut cfg, &store)?;
    summary.push(if jwt_generated {
        "Gateway: generated http.jwt_secret (store:jwt-secret)".to_string()
    } else {
        "Gateway: existing JWT secret kept (never rotated)".to_string()
    });

    cfg.validate()?;
    write_config(config_path, &cfg)?;

    Ok(OnboardOutcome {
        config_path: config_path.display().to_string(),
        config_created: !config_existed,
        secret_store_path: opsclaw_home.display().to_string(),
        vapid_generated,
        jwt_generated,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::prompt::ScriptedPrompter;

    #[tokio::test]
    async fn non_interactive_yes_produces_a_validating_fully_faked_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions::default();

        let outcome = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();
        assert!(outcome.config_created);
        assert!(outcome.vapid_generated);

        let cfg = Config::load(Some(&config_path)).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.fully_faked());
        assert!(cfg.push.vapid_private_key.is_some());
        assert!(cfg.push.vapid_public_key.is_some());
    }

    #[tokio::test]
    async fn secret_store_key_file_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        run_non_interactive(&NonInteractiveOptions::default(), &config_path, dir.path())
            .await
            .unwrap();

        let key_path = dir.path().join("secret.key");
        assert!(key_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn rerun_does_not_rotate_vapid_keys() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions::default();

        let first = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();
        assert!(first.vapid_generated);
        let cfg1 = Config::load(Some(&config_path)).unwrap();

        let second = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();
        assert!(!second.vapid_generated);
        assert!(!second.config_created);
        let cfg2 = Config::load(Some(&config_path)).unwrap();

        assert_eq!(cfg1.push.vapid_public_key, cfg2.push.vapid_public_key);
    }

    #[tokio::test]
    async fn non_interactive_live_mode_succeeds_and_wires_a_generated_jwt_secret() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        unsafe { std::env::set_var("OPSCLAW_ONBOARD_JWT_TEST_KEY", "sk-test") };
        let opts = NonInteractiveOptions {
            openrouter_api_key_env: Some("OPSCLAW_ONBOARD_JWT_TEST_KEY".into()),
            models: vec!["some/model".into()],
            hindsight_url: Some("http://localhost:8888".into()),
            ..Default::default()
        };

        let outcome = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();
        assert!(outcome.jwt_generated);

        let cfg = Config::load(Some(&config_path)).unwrap();
        cfg.validate().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        let stored = store.get("jwt-secret").unwrap().expect("secret must be in the store");
        assert!(stored.len() >= 32, "must satisfy resolve_jwt_secret's minimum length");
        assert_eq!(cfg.resolve_jwt_secret(&store).unwrap(), stored);
        unsafe { std::env::remove_var("OPSCLAW_ONBOARD_JWT_TEST_KEY") };
    }

    #[tokio::test]
    async fn rerun_does_not_rotate_the_jwt_secret() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions::default();

        let first = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();
        assert!(first.jwt_generated);
        let store = SecretStore::open(dir.path()).unwrap();
        let v1 = store.get("jwt-secret").unwrap().unwrap();

        let second = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();
        assert!(!second.jwt_generated);
        assert_eq!(store.get("jwt-secret").unwrap().unwrap(), v1);
    }

    #[tokio::test]
    async fn preseeded_store_jwt_secret_is_adopted_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let store = SecretStore::open(dir.path()).unwrap();
        store.set("jwt-secret", "operator-chose-this-value-before-onboarding").unwrap();

        let outcome =
            run_non_interactive(&NonInteractiveOptions::default(), &config_path, dir.path())
                .await
                .unwrap();
        assert!(!outcome.jwt_generated, "a pre-seeded value is adopted, not regenerated");
        assert_eq!(
            store.get("jwt-secret").unwrap().unwrap(),
            "operator-chose-this-value-before-onboarding"
        );
        let cfg = Config::load(Some(&config_path)).unwrap();
        assert!(cfg.http.jwt_secret.is_some(), "config must reference the adopted secret");
    }

    #[tokio::test]
    async fn non_interactive_with_llm_key_but_no_models_fails_validate_not_a_silent_write() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        unsafe { std::env::set_var("OPSCLAW_ONBOARD_TEST_KEY", "sk-test") };
        let opts = NonInteractiveOptions {
            openrouter_api_key_env: Some("OPSCLAW_ONBOARD_TEST_KEY".into()),
            models: Vec::new(), // deliberately empty
            ..Default::default()
        };

        let err = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap_err();
        assert!(err.to_string().contains("llm.models"));
        assert!(!config_path.exists(), "must not write a config that fails validate()");
        unsafe { std::env::remove_var("OPSCLAW_ONBOARD_TEST_KEY") };
    }

    #[tokio::test]
    async fn refuses_a_legacy_config_with_a_clear_message() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "schema_version = 2\n[providers]\n").unwrap();

        let err = run_non_interactive(&NonInteractiveOptions::default(), &config_path, dir.path())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("different, unrelated opsclaw generation"));
    }

    #[tokio::test]
    async fn interactive_wizard_drives_scripted_answers() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut p = ScriptedPrompter::new([
            "",                      // llm key env: skip
            "",                      // hindsight url: skip
            "",                      // telegram env: skip
            "https://hc-ping.com/x", // deadman url
            "",                      // auth provider: default (local)
            "n",                     // chained project wizard: skip
            "n",                     // chained account creation: skip
            "n",                     // chained doctor run: skip
        ]);

        let outcome =
            run(&mut p, &NonInteractiveOptions::default(), &config_path, dir.path()).await.unwrap();
        assert!(outcome.config_created);
        let cfg = Config::load(Some(&config_path)).unwrap();
        assert_eq!(cfg.daemon.deadman_url.as_deref(), Some("https://hc-ping.com/x"));
        assert_eq!(cfg.auth.provider, AuthProvider::Local, "blank keeps password sign-in");
    }

    #[tokio::test]
    async fn chained_flow_runs_project_account_and_doctor_then_points_at_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut p = ScriptedPrompter::new([
            "", // llm key env: skip
            "", // hindsight url: skip
            "", // telegram env: skip
            "", // deadman url: skip
            "", // auth provider: default (local)
            // -- chained project wizard --
            "y",
            "demo",      // project name
            "",          // project autonomy: default
            "prod",      // env name
            "",          // env autonomy: inherit
            "running",   // env expected_state
            "y",         // add a target now? yes
            "this-host", // target name
            "local",     // target kind (no credential prompt)
            "",          // address
            "",          // target autonomy: inherit
            "running",   // target expected_state
            "n",         // another target? no
            "n",         // another env? no
            // -- chained account creation --
            "y",
            "ops@example.com", // email
            "",                // display name: default (the email)
            "short",           // too short: refused BEFORE any confirmation prompt
            "a-long-enough-password",
            "a-long-enough-password",
            // -- chained doctor --
            "y",
        ]);

        let outcome =
            run(&mut p, &NonInteractiveOptions::default(), &config_path, dir.path()).await.unwrap();
        assert!(outcome.config_created);

        let cfg = Config::load(Some(&config_path)).unwrap();
        assert_eq!(cfg.projects.len(), 1, "chained project wizard must have persisted");
        assert_eq!(cfg.projects[0].name, "demo");

        // The account landed in the same db file the daemon will open.
        let db = crate::db::Db::connect(&dir.path().join("opsclaw.sqlite3").display().to_string())
            .await
            .unwrap();
        let accounts = crate::cli::account_cmd::list(&db).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].email, "ops@example.com");

        // Rule stated upfront; the short attempt refused before confirmation.
        assert!(p.said.iter().any(|l| l.contains("at least 12 characters")), "{:?}", p.said);
        assert!(p.said.iter().any(|l| l.contains("too short")), "{:?}", p.said);

        // Doctor ran green on the fully-faked base + local target...
        assert!(p.said.iter().any(|l| l.contains("[OK  ] config")), "{:?}", p.said);
        // ...and the wizard ends by naming the exact next command.
        assert!(p.said.last().unwrap().contains("`opsclaw-cli daemon`"), "{:?}", p.said);
    }

    #[tokio::test]
    async fn the_hindsight_url_flag_reaches_the_interactive_prompt() {
        // The regression: `--hindsight-url` was read only under `--yes`, so
        // the onboarding command deploy/docker-compose.yml documents passed
        // it, the operator pressed enter, and memory was written as "not
        // configured" — while the compose file's own HINDSIGHT_URL env turned
        // memory ON at runtime. Config and behaviour disagreed.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions {
            hindsight_url: Some("http://opsclaw-hindsight:8888".into()),
            ..Default::default()
        };
        let mut p = ScriptedPrompter::new([
            "",  // llm key env: skip
            "",  // hindsight url: ENTER — must take the flag, not skip
            "",  // telegram env: skip
            "",  // deadman url: skip
            "",  // auth provider: default (local)
            "n", // project wizard: skip
            "n", // account: skip
            "n", // doctor: skip
        ]);

        run(&mut p, &opts, &config_path, dir.path()).await.unwrap();

        let cfg = Config::load(Some(&config_path)).unwrap();
        assert_eq!(cfg.memory.hindsight_url.as_deref(), Some("http://opsclaw-hindsight:8888"));
    }

    #[tokio::test]
    async fn none_is_how_you_decline_a_discovered_default() {
        // The counterpart to the test above: a default must not become a
        // value the operator cannot refuse, or the flip in what blank means
        // would take away the ability to skip.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions {
            hindsight_url: Some("http://opsclaw-hindsight:8888".into()),
            ..Default::default()
        };
        let mut p = ScriptedPrompter::new(["", "none", "", "", "", "n", "n", "n"]);

        run(&mut p, &opts, &config_path, dir.path()).await.unwrap();

        let cfg = Config::load(Some(&config_path)).unwrap();
        assert_eq!(cfg.memory.hindsight_url, None);
    }

    #[test]
    fn ask_defaulted_only_changes_the_meaning_of_blank_when_it_has_something_to_offer() {
        // No default: byte-for-byte the old behaviour, including the question
        // text — operators who skip must not be taught new vocabulary that
        // does not apply to them.
        let mut p = ScriptedPrompter::new([""]);
        assert_eq!(ask_defaulted(&mut p, "q", None).unwrap(), "");
        assert_eq!(p.asked, vec!["q".to_string()]);

        // An empty-string default is not a default.
        let mut p = ScriptedPrompter::new([""]);
        assert_eq!(ask_defaulted(&mut p, "q", Some("")).unwrap(), "");
        assert_eq!(p.asked, vec!["q".to_string()]);

        // With one, blank takes it and the skip token is spelled out.
        let mut p = ScriptedPrompter::new([""]);
        assert_eq!(ask_defaulted(&mut p, "q", Some("found")).unwrap(), "found");
        assert!(p.asked[0].contains("\"none\" to skip"), "{:?}", p.asked);

        // An explicit answer still wins over the default.
        let mut p = ScriptedPrompter::new(["typed"]);
        assert_eq!(ask_defaulted(&mut p, "q", Some("found")).unwrap(), "typed");

        // And "none" means skip, case-insensitively.
        let mut p = ScriptedPrompter::new(["NONE"]);
        assert_eq!(ask_defaulted(&mut p, "q", Some("found")).unwrap(), "");
    }

    #[test]
    fn unknown_model_ids_are_exactly_those_the_catalogue_omits() {
        let known: std::collections::HashSet<String> =
            ["deepseek/deepseek-v4-flash-0731", "openai/gpt-4o-mini"]
                .into_iter()
                .map(str::to_string)
                .collect();

        let all_good = vec!["openai/gpt-4o-mini".to_string()];
        assert!(unknown_model_ids(&all_good, &known).is_empty());

        // The failure this guards: a typo is accepted by validate() (which
        // only checks the list is non-empty) and by doctor (which checks the
        // KEY resolves, not the MODEL), so without this it first surfaces as
        // a failed reasoning call mid-incident.
        let typo = vec!["deepseek/deepseek-v4-flash-0713".to_string()];
        assert_eq!(unknown_model_ids(&typo, &known), vec!["deepseek/deepseek-v4-flash-0713"]);

        assert!(unknown_model_ids(&[], &known).is_empty());
    }

    #[test]
    fn the_llm_key_default_prefers_the_flag_then_the_existing_config() {
        // Deliberately no env-var mutation: OPENROUTER_API_KEY is
        // process-global and setting it corrupts every test running in
        // parallel. Flag and config precedence are testable without it.
        let mut cfg = Config::default();
        assert_eq!(default_llm_key_env(&NonInteractiveOptions::default(), &cfg), None);

        cfg.llm.api_key = Some(SecretRef::env("FROM_CONFIG"));
        assert_eq!(
            default_llm_key_env(&NonInteractiveOptions::default(), &cfg).as_deref(),
            Some("FROM_CONFIG"),
            "a rerun must offer back what the last run wrote"
        );

        let opts = NonInteractiveOptions {
            openrouter_api_key_env: Some("FROM_FLAG".into()),
            ..Default::default()
        };
        assert_eq!(
            default_llm_key_env(&opts, &cfg).as_deref(),
            Some("FROM_FLAG"),
            "an explicit flag outranks what is already on disk"
        );

        // A store: reference is not an env var NAME, so it cannot answer this
        // prompt — offering "vapid_private_key" here would be nonsense.
        cfg.llm.api_key = Some(SecretRef::store("some-key"));
        assert_eq!(default_llm_key_env(&NonInteractiveOptions::default(), &cfg), None);
    }

    #[tokio::test]
    async fn chained_flow_skips_print_the_standalone_commands() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        // llm, hindsight, telegram, deadman, auth provider, then three skips.
        let mut p = ScriptedPrompter::new(["", "", "", "", "", "n", "n", "n"]);

        run(&mut p, &NonInteractiveOptions::default(), &config_path, dir.path()).await.unwrap();

        let said = p.said.join("\n");
        assert!(said.contains("`opsclaw-cli config project add`"), "{said}");
        assert!(said.contains("`opsclaw-cli account create <email>`"), "{said}");
        assert!(said.contains("`opsclaw-cli doctor`"), "{said}");
        assert!(p.said.last().unwrap().contains("`opsclaw-cli daemon`"), "{said}");
    }

    #[tokio::test]
    async fn hanko_wizard_never_asks_for_a_password() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut p = ScriptedPrompter::new([
            "",                        // llm key env: skip
            "",                        // hindsight url: skip
            "",                        // telegram env: skip
            "",                        // deadman url: skip
            "hanko",                   // auth provider
            "https://tenant.hanko.io", // hanko api url
            "ops.example.com",         // session audience
            "n",                       // chained project wizard: skip
            // -- chained account creation: a LINK, not a password --
            "y",
            "ops@example.com",
            "",                                     // display name: default (the email)
            "6f1c0e64-0000-4000-8000-000000000001", // hanko user id
            "n", // chained doctor run: skip (it would call out to hanko)
        ]);

        run(&mut p, &NonInteractiveOptions::default(), &config_path, dir.path()).await.unwrap();

        let cfg = Config::load(Some(&config_path)).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.auth.provider, AuthProvider::Hanko);
        assert_eq!(cfg.auth.api_base(), Some("https://tenant.hanko.io"));
        assert_eq!(cfg.auth.audience, vec!["ops.example.com".to_string()]);

        // The password loop never ran: neither its rule nor its prompts.
        let said = p.said.join("\n");
        assert!(!said.contains("at least 12 characters"), "{said}");
        assert!(!said.contains("passwords did not match"), "{said}");

        // The account exists, linked by subject, with no usable password.
        let db = crate::db::Db::connect(&dir.path().join("opsclaw.sqlite3").display().to_string())
            .await
            .unwrap();
        let account = db
            .repos()
            .by_external_subject(
                crate::db::AUTH_PROVIDER_HANKO,
                "6f1c0e64-0000-4000-8000-000000000001",
            )
            .await
            .unwrap()
            .expect("the wizard must have linked the account to the hanko subject");
        assert_eq!(account.email, "ops@example.com");
        assert_eq!(account.password_hash, crate::http::auth::NO_PASSWORD);
        assert!(
            !crate::http::auth::verify_password("", &account.password_hash).unwrap(),
            "the sentinel must never verify"
        );

        // The gateway still signs its own cookie under hanko — ensure_jwt
        // runs for BOTH providers (rotating it would sign every operator
        // out).
        assert!(cfg.http.jwt_secret.is_some());
        let store = SecretStore::open(dir.path()).unwrap();
        assert!(cfg.resolve_jwt_secret(&store).unwrap().len() >= 32);
    }

    #[tokio::test]
    async fn a_rerun_pressing_enter_keeps_hanko_rather_than_downgrading_to_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions {
            auth_provider: Some(AuthProvider::Hanko),
            hanko_api_url: Some("https://tenant.hanko.io".into()),
            hanko_audience: vec!["ops.example.com".into()],
            ..Default::default()
        };
        run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();

        // Blank answers all the way through the rerun.
        let mut p = ScriptedPrompter::new(["", "", "", "", "", "", "", "n", "n", "n"]);
        run(&mut p, &NonInteractiveOptions::default(), &config_path, dir.path()).await.unwrap();

        let cfg = Config::load(Some(&config_path)).unwrap();
        assert_eq!(cfg.auth.provider, AuthProvider::Hanko, "{:?}", p.said);
        assert_eq!(cfg.auth.api_base(), Some("https://tenant.hanko.io"));
        assert_eq!(cfg.auth.audience, vec!["ops.example.com".to_string()]);
    }

    #[tokio::test]
    async fn non_interactive_hanko_writes_the_auth_section() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions {
            auth_provider: Some(AuthProvider::Hanko),
            hanko_api_url: Some("https://tenant.hanko.io/".into()),
            hanko_audience: vec!["ops.example.com".into()],
            ..Default::default()
        };

        let outcome = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();
        assert!(outcome.jwt_generated, "the daemon still signs its own cookie under hanko");

        let cfg = Config::load(Some(&config_path)).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.auth.provider, AuthProvider::Hanko);
        assert_eq!(cfg.auth.api_base(), Some("https://tenant.hanko.io"));
        assert_eq!(cfg.auth.audience, vec!["ops.example.com".to_string()]);
    }

    #[tokio::test]
    async fn non_interactive_hanko_without_an_api_url_fails_validate_not_a_silent_write() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions {
            auth_provider: Some(AuthProvider::Hanko),
            hanko_audience: vec!["ops.example.com".into()],
            ..Default::default()
        };

        let err = run_non_interactive(&opts, &config_path, dir.path()).await.unwrap_err();
        assert!(err.to_string().contains("auth.api_url"), "{err}");
        assert!(!config_path.exists(), "must not write a config that fails validate()");
    }

    #[tokio::test]
    async fn rerun_without_auth_flags_does_not_downgrade_hanko_to_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let opts = NonInteractiveOptions {
            auth_provider: Some(AuthProvider::Hanko),
            hanko_api_url: Some("https://tenant.hanko.io".into()),
            hanko_audience: vec!["ops.example.com".into()],
            ..Default::default()
        };
        run_non_interactive(&opts, &config_path, dir.path()).await.unwrap();

        run_non_interactive(&NonInteractiveOptions::default(), &config_path, dir.path())
            .await
            .unwrap();

        let cfg = Config::load(Some(&config_path)).unwrap();
        assert_eq!(cfg.auth.provider, AuthProvider::Hanko);
        assert_eq!(cfg.auth.api_base(), Some("https://tenant.hanko.io"));
    }
}
