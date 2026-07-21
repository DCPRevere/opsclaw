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
//! exists from day one rather than being bolted on later).

use std::path::Path;

use serde::Serialize;

use crate::Result;
use crate::cli::config_cmd::write_config;
use crate::cli::prompt::Prompter;
use crate::cli::vapid;
use crate::config::{Config, SecretRef, SecretStore};

#[derive(Debug, Serialize)]
pub struct OnboardOutcome {
    pub config_path: String,
    pub config_created: bool,
    pub secret_store_path: String,
    pub vapid_generated: bool,
    pub summary: Vec<String>,
}

/// Flags for the non-interactive path (`onboard --yes`). Every field is
/// optional — an unset field is left at `Config::default()` for that
/// section, which is the fully-faked, self-validating boot DESIGN.md §3
/// promises ("with zero config the whole daemon runs and self-validates on
/// fakes").
#[derive(Debug, Default, Clone)]
pub struct NonInteractiveOptions {
    pub openrouter_api_key_env: Option<String>,
    pub models: Vec<String>,
    pub hindsight_url: Option<String>,
    pub telegram_bot_token_env: Option<String>,
    pub deadman_url: Option<String>,
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
        toml::from_str(&raw).map_err(|e| crate::Error::Config(format!("{}: {e}", config_path.display())))?
    } else {
        Config::default()
    };
    let store = SecretStore::open(opsclaw_home)?;
    Ok((cfg, config_existed, store))
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

/// Interactive path: ask, don't assume. Every question has a sensible
/// default (empty = skip that integration, matching fakes mode) so an
/// operator can hit enter through the whole thing and land on a fully-faked,
/// self-validating daemon — exactly what `Config::default()` already is,
/// made discoverable through a guided walkthrough instead of silence.
pub async fn run(p: &mut dyn Prompter, config_path: &Path, opsclaw_home: &Path) -> Result<OnboardOutcome> {
    let (mut cfg, config_existed, store) = prepare(config_path, opsclaw_home)?;
    let mut summary = Vec::new();

    p.say("OpsClaw onboarding — every question can be left blank to skip that integration.");

    let llm_key_env = p.ask("OpenRouter API key env var name (blank to skip; sets fakes-mode LLM)", None)?;
    if !llm_key_env.is_empty() {
        cfg.llm.api_key = Some(SecretRef::env(&llm_key_env));
        let models_raw = p.ask("comma-separated OpenRouter model list (required if a key is set)", None)?;
        cfg.llm.models = models_raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        summary.push(format!("LLM: env:{llm_key_env}, {} model(s)", cfg.llm.models.len()));
    } else {
        summary.push("LLM: not configured (fakes mode)".to_string());
    }

    let hindsight_url = p.ask("Hindsight URL (blank to skip; memory runs as an honest no-op)", None)?;
    if !hindsight_url.is_empty() {
        cfg.memory.hindsight_url = Some(hindsight_url.clone());
        summary.push(format!("Memory: {hindsight_url}"));
    } else {
        summary.push("Memory: not configured (honest no-op)".to_string());
    }

    let telegram_env = p.ask("Telegram bot token env var name (blank to skip)", None)?;
    if !telegram_env.is_empty() {
        cfg.telegram.bot_token = Some(SecretRef::env(&telegram_env));
        summary.push(format!("Telegram: env:{telegram_env}"));
    } else {
        summary.push("Telegram: not configured".to_string());
    }

    let deadman_url = p.ask(
        "external dead-man heartbeat URL (blank to skip; REQUIRED for in-cluster installs)",
        None,
    )?;
    if !deadman_url.is_empty() {
        cfg.daemon.deadman_url = Some(deadman_url.clone());
        summary.push(format!("Dead-man heartbeat: {deadman_url}"));
    } else {
        summary.push("Dead-man heartbeat: not configured".to_string());
    }

    let vapid_generated = ensure_vapid(&mut cfg, &store)?;
    summary.push(if vapid_generated {
        "Push: generated a new VAPID keypair".to_string()
    } else {
        "Push: existing VAPID keypair kept (never rotated)".to_string()
    });

    cfg.validate()?;
    write_config(config_path, &cfg)?;

    p.say(&format!("wrote {}", config_path.display()));
    p.say("next: `opsclaw-cli config project add` to add a project, then `opsclaw-cli doctor`.");

    Ok(OnboardOutcome {
        config_path: config_path.display().to_string(),
        config_created: !config_existed,
        secret_store_path: opsclaw_home.display().to_string(),
        vapid_generated,
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

    let vapid_generated = ensure_vapid(&mut cfg, &store)?;
    summary.push(if vapid_generated {
        "Push: generated a new VAPID keypair".to_string()
    } else {
        "Push: existing VAPID keypair kept (never rotated)".to_string()
    });

    cfg.validate()?;
    write_config(config_path, &cfg)?;

    Ok(OnboardOutcome {
        config_path: config_path.display().to_string(),
        config_created: !config_existed,
        secret_store_path: opsclaw_home.display().to_string(),
        vapid_generated,
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
        run_non_interactive(&NonInteractiveOptions::default(), &config_path, dir.path()).await.unwrap();

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
            "",              // llm key env: skip
            "",              // hindsight url: skip
            "",              // telegram env: skip
            "https://hc-ping.com/x", // deadman url
        ]);

        let outcome = run(&mut p, &config_path, dir.path()).await.unwrap();
        assert!(outcome.config_created);
        let cfg = Config::load(Some(&config_path)).unwrap();
        assert_eq!(cfg.daemon.deadman_url.as_deref(), Some("https://hc-ping.com/x"));
    }
}
