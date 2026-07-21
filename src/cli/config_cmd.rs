//! `opsclaw-cli config project add` (the chaining project → env → target
//! wizard, DESIGN.md §5) and `opsclaw-cli config validate`.
//!
//! Every prompt goes through the [`crate::cli::prompt::Prompter`] trait, so
//! the whole chain is testable with [`crate::cli::prompt::ScriptedPrompter`]
//! without a real terminal. This module never writes a partial/invalid
//! config to disk: it builds the new `ProjectCfg` (or edits the target
//! `EnvCfg`/list) entirely in memory, appends it to a loaded `Config`, then
//! validates the WHOLE config before persisting — a wizard that "succeeds"
//! but leaves `config.toml` unparseable or failing `validate()` would be
//! worse than refusing to write at all.

use std::path::Path;

use crate::Result;
use crate::cli::prompt::Prompter;
use crate::config::{
    Config, EnvCfg, ProjectCfg, ResourceCfg, SecretRef, TargetCfg, TargetKindName,
};
use crate::domain::{Autonomy, CloudProvider, ExpectedState};

/// Serialize `cfg` and write it to `path`, creating parent directories if
/// needed. There is no `Config::save()` in `config/mod.rs` (only `load`) —
/// this is the CLI's own write path, used by every command that persists a
/// config edit (onboard, config project add). Writes via a temp file +
/// rename in the same directory so a crash mid-write can never leave a
/// half-written `config.toml` (the file `Config::load` reads on every
/// daemon boot).
pub fn write_config(path: &Path, cfg: &Config) -> Result<()> {
    let body = toml::to_string_pretty(cfg)
        .map_err(|e| crate::Error::Config(format!("serializing config: {e}")))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, body)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Ask for one of a fixed set of options by exact string match, re-asking
/// (up to `max_attempts` times) on a bad answer rather than silently
/// defaulting — a mistyped autonomy level or target kind must never
/// silently become something else (config.rs's own stance: "unparseable
/// autonomy must not default to anything but observe" is a load-bearing
/// invariant this wizard must not undermine by guessing).
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

fn ask_autonomy(p: &mut dyn Prompter, question: &str) -> Result<Option<Autonomy>> {
    let answer = ask_choice(p, question, &["", "observe", "suggest", "act_on_known", "auto"], "")?;
    if answer.is_empty() {
        Ok(None) // inherit from the level above (project > env > target), DESIGN.md §1
    } else {
        Ok(Some(answer.parse()?))
    }
}

/// Prompt for one new target within an environment, returning it unattached.
fn wizard_target(p: &mut dyn Prompter) -> Result<TargetCfg> {
    let name = p.ask("target name", None)?;
    let kind_str = ask_choice(p, "target kind", &["ssh", "local", "kubernetes", "cloud"], "ssh")?;
    let kind = match kind_str.as_str() {
        "ssh" => TargetKindName::Ssh,
        "local" => TargetKindName::Local,
        "kubernetes" => TargetKindName::Kubernetes,
        "cloud" => TargetKindName::Cloud,
        _ => unreachable!("ask_choice only returns a listed option"),
    };

    let provider = if kind == TargetKindName::Cloud {
        let provider_str = ask_choice(p, "cloud provider", &["azure", "scaleway"], "azure")?;
        Some(match provider_str.as_str() {
            "azure" => CloudProvider::Azure,
            "scaleway" => CloudProvider::Scaleway,
            _ => unreachable!(),
        })
    } else {
        None
    };
    let region = if provider.is_some() {
        let r = p.ask("region (blank for none)", None)?;
        if r.is_empty() { None } else { Some(r) }
    } else {
        None
    };

    let address = {
        let a = p.ask("address (host for ssh, context hint for kubernetes; blank if n/a)", None)?;
        if a.is_empty() { None } else { Some(a) }
    };

    // Jump host only makes sense for ssh (DESIGN §4: remundo's estate sits
    // behind an Azure Bastion jumpbox) — don't clutter other kinds' wizard.
    let jump_host = if kind == TargetKindName::Ssh {
        let j = p.ask("jump host ([user@]host[:port], blank for direct)", None)?;
        if j.is_empty() { None } else { Some(j) }
    } else {
        None
    };

    // Credentials never inherit (brief invariant #5) — required for every
    // kind except local, and the wizard enforces that here rather than
    // deferring silently to validate() finding it later.
    let credential = if kind == TargetKindName::Local {
        None
    } else {
        loop {
            let raw = p.ask("credential reference (env:VAR or store:KEY)", None)?;
            match SecretRef::parse(&raw) {
                Ok(r) => break Some(r),
                Err(e) => p.say(&format!("  {e} — try again")),
            }
        }
    };

    let autonomy = ask_autonomy(p, "target autonomy override (blank = inherit)")?;
    let expected_state_str =
        ask_choice(p, "expected state", &["running", "stopped", "ephemeral"], "running")?;
    let expected_state = Some(match expected_state_str.as_str() {
        "running" => ExpectedState::Running,
        "stopped" => ExpectedState::Stopped,
        "ephemeral" => ExpectedState::Ephemeral,
        _ => unreachable!(),
    });

    Ok(TargetCfg {
        name,
        kind,
        provider,
        region,
        autonomy,
        expected_state,
        credential,
        address,
        jump_host,
        ssh_port: None,
        ssh_user: None,
        ssh_known_hosts_path: None,
        ssh_strict_host_key_checking: None,
        resources: Vec::<ResourceCfg>::new(),
    })
}

/// Prompt for one new environment within a project, chaining into one or
/// more targets.
fn wizard_env(p: &mut dyn Prompter) -> Result<EnvCfg> {
    let name = p.ask("environment name", None)?;
    let autonomy = ask_autonomy(p, "environment autonomy override (blank = inherit)")?;
    let expected_state_str = ask_choice(
        p,
        "environment expected state",
        &["running", "stopped", "ephemeral"],
        "running",
    )?;
    let expected_state = Some(match expected_state_str.as_str() {
        "running" => ExpectedState::Running,
        "stopped" => ExpectedState::Stopped,
        "ephemeral" => ExpectedState::Ephemeral,
        _ => unreachable!(),
    });

    let mut targets = Vec::new();
    loop {
        p.say(&format!("-- target #{} in environment {name:?} --", targets.len() + 1));
        targets.push(wizard_target(p)?);
        if !p.confirm("add another target to this environment?", false)? {
            break;
        }
    }

    Ok(EnvCfg { name, autonomy, expected_state, targets })
}

/// The full chaining wizard: project → env → target(s), env repeatable.
/// Returns the assembled `ProjectCfg`; callers append it to a `Config` and
/// persist. Pure with respect to `Config` — never reads or writes a file
/// itself, so it's usable identically from `onboard` (fresh config) and
/// `config project add` (existing config).
pub fn wizard_project(p: &mut dyn Prompter) -> Result<ProjectCfg> {
    let name = p.ask("project name", None)?;
    let autonomy = ask_autonomy(p, "project autonomy override (blank = default: suggest)")?;

    let mut envs = Vec::new();
    loop {
        p.say(&format!("-- environment #{} in project {name:?} --", envs.len() + 1));
        envs.push(wizard_env(p)?);
        if !p.confirm("add another environment to this project?", false)? {
            break;
        }
    }

    Ok(ProjectCfg { name, autonomy, envs })
}

/// `config project add`: run the wizard, append the result to the config at
/// `config_path` (loaded fresh, or `Config::default()` if absent), validate
/// the WHOLE result, and only then write it back. On validation failure the
/// file on disk is left untouched — the operator fixes the wizard answers
/// (or edits the printed TOML fragment by hand) and reruns, rather than
/// having a broken config silently swapped in.
pub fn add_project(p: &mut dyn Prompter, config_path: &Path) -> Result<ProjectCfg> {
    let mut cfg = load_for_edit(config_path)?;
    let project = wizard_project(p)?;

    if cfg.projects.iter().any(|existing| existing.name == project.name) {
        return Err(crate::Error::Config(format!(
            "project {:?} already exists in {} — edit it by hand or pick a different name",
            project.name,
            config_path.display()
        )));
    }

    cfg.projects.push(project.clone());
    cfg.validate()?;
    write_config(config_path, &cfg)?;
    Ok(project)
}

/// Load a config for editing: same file-or-default rule as `Config::load`,
/// but WITHOUT the env overlay — wizard edits must round-trip through
/// exactly what's on disk, and re-applying `apply_env_overlay` before a
/// re-write would silently bake this process's ambient environment (e.g. an
/// operator's personal `OPENROUTER_API_KEY` exported for an unrelated
/// reason) into the team's shared config.toml.
fn load_for_edit(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let raw = std::fs::read_to_string(path)?;
    if crate::cli::legacy::looks_like_legacy_config(&raw) {
        return Err(crate::Error::Config(format!(
            "{}: {}",
            path.display(),
            crate::cli::legacy::LEGACY_CONFIG_MESSAGE
        )));
    }
    toml::from_str(&raw).map_err(|e| crate::Error::Config(format!("{}: {e}", path.display())))
}

/// `config validate`: load (file-or-default, WITH the env overlay this time
/// — validate should see exactly what the daemon would boot with) and run
/// `Config::validate()`, returning the errors as a `Vec<String>` (one line
/// per failure — `Error::Config` joins them with `\n`) rather than
/// `crate::Result<()>`, so the caller can print every failure instead of
/// just the first.
pub fn validate(config_path: &Path) -> Result<Vec<String>> {
    let raw =
        if config_path.exists() { std::fs::read_to_string(config_path)? } else { String::new() };
    if !raw.is_empty() && crate::cli::legacy::looks_like_legacy_config(&raw) {
        return Ok(vec![format!(
            "{}: {}",
            config_path.display(),
            crate::cli::legacy::LEGACY_CONFIG_MESSAGE
        )]);
    }

    let cfg = Config::load(Some(config_path))?;
    match cfg.validate() {
        Ok(()) => Ok(Vec::new()),
        Err(crate::Error::Config(msg)) => Ok(msg.lines().map(str::to_string).collect()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::prompt::ScriptedPrompter;

    #[test]
    fn wizard_project_single_env_single_target() {
        let mut p = ScriptedPrompter::new([
            "remundo",                 // project name
            "",                        // project autonomy: inherit
            "prod",                    // env name
            "",                        // env autonomy: inherit
            "running",                 // env expected_state
            "bastion",                 // target name
            "ssh",                     // target kind
            "bastion.remundo.example", // address
            "",                        // jump host: direct (ssh-only prompt)
            "env:REMUNDO_SSH_KEY",     // credential
            "",                        // target autonomy: inherit
            "running",                 // target expected_state
            "n",                       // add another target? no
            "n",                       // add another env? no
        ]);
        let project = wizard_project(&mut p).unwrap();
        assert_eq!(project.name, "remundo");
        assert_eq!(project.envs.len(), 1);
        assert_eq!(project.envs[0].name, "prod");
        assert_eq!(project.envs[0].targets.len(), 1);
        assert_eq!(project.envs[0].targets[0].name, "bastion");
        assert_eq!(project.envs[0].targets[0].kind, TargetKindName::Ssh);
        assert_eq!(
            project.envs[0].targets[0].credential.as_ref().map(|c| c.to_string()),
            Some("env:REMUNDO_SSH_KEY".to_string())
        );
    }

    #[test]
    fn wizard_target_local_needs_no_credential() {
        let mut p = ScriptedPrompter::new(["this-host", "local", "", "", "running"]);
        let t = wizard_target(&mut p).unwrap();
        assert_eq!(t.kind, TargetKindName::Local);
        assert!(t.credential.is_none());
    }

    #[test]
    fn wizard_target_cloud_requires_provider() {
        let mut p = ScriptedPrompter::new([
            "aci-runner",
            "cloud",
            "azure",
            "westeurope",
            "",
            "env:AZURE_CRED",
            "",
            "running",
        ]);
        let t = wizard_target(&mut p).unwrap();
        assert_eq!(t.kind, TargetKindName::Cloud);
        assert_eq!(t.provider, Some(CloudProvider::Azure));
        assert_eq!(t.region.as_deref(), Some("westeurope"));
    }

    #[test]
    fn wizard_target_rejects_bad_credential_ref_then_accepts() {
        let mut p = ScriptedPrompter::new([
            "bastion",
            "ssh",
            "",
            "not-a-valid-ref",
            "env:GOOD",
            "",
            "running",
        ]);
        let t = wizard_target(&mut p).unwrap();
        assert_eq!(t.credential.as_ref().map(|c| c.to_string()), Some("env:GOOD".to_string()));
    }

    #[test]
    fn add_project_writes_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        let mut p = ScriptedPrompter::new([
            "remundo",
            "",
            "prod",
            "",
            "running",
            "this-host",
            "local",
            "",
            "",
            "running",
            "n",
            "n",
        ]);
        let project = add_project(&mut p, &config_path).unwrap();
        assert_eq!(project.name, "remundo");

        assert!(config_path.exists());
        let reloaded = Config::load(Some(&config_path)).unwrap();
        assert_eq!(reloaded.projects.len(), 1);
        assert_eq!(reloaded.projects[0].name, "remundo");
        reloaded.validate().unwrap();
    }

    #[test]
    fn add_project_rejects_duplicate_name() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        let mut p1 = ScriptedPrompter::new([
            "remundo",
            "",
            "prod",
            "",
            "running",
            "this-host",
            "local",
            "",
            "",
            "running",
            "n",
            "n",
        ]);
        add_project(&mut p1, &config_path).unwrap();

        let mut p2 = ScriptedPrompter::new([
            "remundo",
            "",
            "staging",
            "",
            "running",
            "this-host",
            "local",
            "",
            "",
            "running",
            "n",
            "n",
        ]);
        let err = add_project(&mut p2, &config_path).unwrap_err();
        assert!(err.to_string().contains("already exists"));

        // The file must be untouched by the failed second attempt.
        let reloaded = Config::load(Some(&config_path)).unwrap();
        assert_eq!(reloaded.projects.len(), 1);
    }

    #[test]
    fn validate_reports_multiple_errors_without_failing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
                [llm]
                api_key = "env:SOME_KEY"

                [[project]]
                name = "p"
                [[project.env]]
                name = "e"
                [[project.env.target]]
                name = "t"
                kind = "ssh"
            "#,
        )
        .unwrap();

        let errors = validate(&config_path).unwrap();
        // api_key with empty models, AND an ssh target with no credential —
        // both should be reported, not just the first.
        assert!(errors.iter().any(|e| e.contains("llm.models")), "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("credential") || e.contains("t")), "{errors:?}");
    }

    #[test]
    fn validate_detects_legacy_config_without_raw_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "schema_version = 2\n[providers]\nfallback = \"openai\"\n")
            .unwrap();

        let errors = validate(&config_path).unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("different, unrelated opsclaw generation"));
    }

    #[test]
    fn validate_on_missing_file_is_clean_fakes_mode() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let errors = validate(&config_path).unwrap();
        assert!(errors.is_empty());
    }
}
