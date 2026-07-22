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

use base64::Engine;
use rand::Rng;
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
    pub jwt_generated: bool,
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
        toml::from_str(&raw)
            .map_err(|e| crate::Error::Config(format!("{}: {e}", config_path.display())))?
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
    p.say("  the password must be at least 12 characters (it guards a daemon that can act on");
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
    let out = crate::cli::account_cmd::create(&db, &email, &display_name, &password).await?;
    p.say(&format!(
        "  created operator {} — sign in at the web UI once the daemon is running",
        out.email
    ));
    Ok(out.email)
}

/// Interactive path: ask, don't assume. Every question has a sensible
/// default (empty = skip that integration, matching fakes mode) so an
/// operator can hit enter through the whole thing and land on a fully-faked,
/// self-validating daemon — exactly what `Config::default()` already is,
/// made discoverable through a guided walkthrough instead of silence.
pub async fn run(
    p: &mut dyn Prompter,
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
    let llm_key_env =
        p.ask("OpenRouter API key env var name (blank to skip; sets fakes-mode LLM)", None)?;
    if !llm_key_env.is_empty() {
        if std::env::var(&llm_key_env).is_err() {
            p.say(&format!(
                "  warning: ${llm_key_env} is not set in this shell — export it where the daemon \
                 runs or the LLM will fail to authenticate"
            ));
        }
        cfg.llm.api_key = Some(SecretRef::env(&llm_key_env));
        let models_raw =
            p.ask("comma-separated OpenRouter model list (required if a key is set)", None)?;
        cfg.llm.models =
            models_raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        summary.push(format!("LLM: env:{llm_key_env}, {} model(s)", cfg.llm.models.len()));
    } else {
        summary.push("LLM: not configured (fakes mode)".to_string());
    }

    p.say("[memory] Hindsight is the optional long-term memory service; without it, memory");
    p.say("         features run as an honest no-op.");
    let hindsight_url =
        p.ask("Hindsight URL (blank to skip; memory runs as an honest no-op)", None)?;
    if !hindsight_url.is_empty() {
        cfg.memory.hindsight_url = Some(hindsight_url.clone());
        summary.push(format!("Memory: {hindsight_url}"));
    } else {
        summary.push("Memory: not configured (honest no-op)".to_string());
    }

    p.say("[telegram] optional chat channel for alerts and approvals; the bot token is stored");
    p.say("           by env-var REFERENCE, like the LLM key.");
    let telegram_env = p.ask("Telegram bot token env var name (blank to skip)", None)?;
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

    p.say("[account] the web UI needs an operator account; the FIRST one can only be created");
    p.say("          from this CLI (it goes straight into the daemon's local database).");
    if p.confirm("create your operator account now?", false)? {
        match wizard_account(p, &cfg, opsclaw_home).await {
            Ok(email) => summary.push(format!("Account: created {email}")),
            Err(e) => {
                p.say(&format!(
                    "  account creation failed: {e} — run `opsclaw-cli account create <email>` \
                     when ready"
                ));
            }
        }
    } else {
        p.say("  skipped — run `opsclaw-cli account create <email>` when ready.");
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
            "n",                     // chained project wizard: skip
            "n",                     // chained account creation: skip
            "n",                     // chained doctor run: skip
        ]);

        let outcome = run(&mut p, &config_path, dir.path()).await.unwrap();
        assert!(outcome.config_created);
        let cfg = Config::load(Some(&config_path)).unwrap();
        assert_eq!(cfg.daemon.deadman_url.as_deref(), Some("https://hc-ping.com/x"));
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
            // -- chained project wizard --
            "y",
            "demo",      // project name
            "",          // project autonomy: default
            "prod",      // env name
            "",          // env autonomy: inherit
            "running",   // env expected_state
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

        let outcome = run(&mut p, &config_path, dir.path()).await.unwrap();
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
    async fn chained_flow_skips_print_the_standalone_commands() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut p = ScriptedPrompter::new(["", "", "", "", "n", "n", "n"]);

        run(&mut p, &config_path, dir.path()).await.unwrap();

        let said = p.said.join("\n");
        assert!(said.contains("`opsclaw-cli config project add`"), "{said}");
        assert!(said.contains("`opsclaw-cli account create <email>`"), "{said}");
        assert!(said.contains("`opsclaw-cli doctor`"), "{said}");
        assert!(p.said.last().unwrap().contains("`opsclaw-cli daemon`"), "{said}");
    }
}
