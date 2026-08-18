//! `opsclaw-cli config show|apply|edit|rm` — editing an existing config,
//! the counterpart to `config project add`'s create-only wizard.
//!
//! Until these existed the config CLI was append-only: `project add`,
//! `resource add`, `validate`. There was no way to add an environment to an
//! existing project, move a target between environments, or remove anything
//! — so any restructuring meant hand-editing `config.toml`, and inside a
//! container that meant copying the file out of a docker volume and back.
//!
//! LOCAL, not `--remote`. The gateway already exposes the same capability
//! (`POST /api/config`, `src/http/routes/config_ui.rs`), but reaching it
//! needs an authenticated session, which needs the web UI, which on a
//! locked-down host is exactly what an operator may not have yet. These
//! commands write the file directly, like `onboard` and `config project add`
//! already do, so they work over `docker compose exec` with no gateway, no
//! session, and no browser.
//!
//! Every write goes through the same two gates the HTTP surface uses, in the
//! same order: parse, then the SAME [`Config::validate`] the daemon boots
//! with, and only then [`crate::config::persist_config_text`] (atomic
//! temp-file+rename, `.bak` of the previous contents). A refused config is
//! never written. That ordering is the whole point of these commands rather
//! than a documented `$EDITOR` recipe: live mode refuses to boot on an
//! invalid config, and Docker will not `exec` into a restarting container,
//! so an unvalidated save is an install you cannot get back into.
//!
//! [`apply`] preserves the operator's text verbatim — comments and
//! formatting survive, matching `POST /api/config` and the "stays
//! hand-editable" promise. [`remove`] cannot: a structural edit is made
//! against the parsed `Config` and re-serialized, which drops comments, the
//! same trade-off the structured `PUT /api/config/*` routes already make.
//! It says so when it runs.

use std::path::Path;

use crate::Result;
use crate::config::{Config, persist_config_text};

/// The config as text, byte-for-byte as it sits on disk.
///
/// Safe to print, pipe, and paste into a ticket: `Config` holds
/// [`crate::config::SecretRef`]s (names) and never resolved values, so the
/// strongest thing in here is an `env:VAR`/`store:KEY` reference string —
/// the same property `GET /api/config` relies on.
///
/// On a host with no config file yet this prints the serialized default
/// rather than failing, so `show > f && $EDITOR f && apply < f` works as a
/// first-config workflow and not only as an edit one.
pub fn show(config_path: &Path) -> Result<String> {
    if config_path.exists() {
        return Ok(std::fs::read_to_string(config_path)?);
    }
    toml::to_string_pretty(&Config::default())
        .map_err(|e| crate::Error::Config(format!("serializing default config: {e}")))
}

/// Replace `config.toml` with `body`, but only once the daemon has been
/// proven willing to boot on it.
///
/// Parse failure and validation failure both return before anything is
/// written, so a rejected apply leaves the running config exactly as it was.
/// The bytes written are `body` verbatim, NOT a re-serialization of the
/// parsed `Config` — an operator's comments are part of their config.
pub fn apply(config_path: &Path, body: &str) -> Result<()> {
    let parsed: Config =
        toml::from_str(body).map_err(|e| crate::Error::Config(format!("invalid TOML: {e}")))?;
    parsed.validate()?;
    persist_config_text(config_path, body)?;
    Ok(())
}

/// What to say after a config write: that a restart is needed, AND the
/// command that does it here.
///
/// Config is read at boot, not hot-reloaded (DESIGN §3), so every write path
/// has to tell the operator to restart — but "restart the daemon" on its own
/// leaves them to work out how, and the answer differs by packaging. Inside
/// the standard image the daemon is PID 1 of a container that `systemctl`
/// cannot reach and the compose file is on a host this process cannot see;
/// under `deploy/opsclaw.service` it is a systemd unit and `docker` is not
/// involved at all. Printing the wrong one is worse than printing none.
///
/// The container command is deliberately unqualified — no `--env-file`, no
/// path. This process cannot know the operator's compose project directory
/// (it is on the host, outside the container's filesystem), so the hint says
/// where to run it rather than inventing arguments that may not match.
pub fn restart_hint() -> String {
    let in_container = std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists();
    if in_container {
        "restart to apply (config is read at boot, not hot-reloaded):\n  docker compose restart \
         opsclaw-daemon   — on the host, from the directory holding docker-compose.yml"
            .to_string()
    } else {
        "restart to apply (config is read at boot, not hot-reloaded):\n  systemctl restart \
         opsclaw   — or `systemctl --user restart opsclaw` for a user unit"
            .to_string()
    }
}

/// Where [`edit`] leaves your work when the result does not validate: beside
/// the real config, at a predictable path, rather than in a temp directory
/// the error message would have to explain.
pub fn edit_scratch_path(config_path: &Path) -> std::path::PathBuf {
    config_path.with_extension("toml.edit")
}

/// Outcome of an [`edit`] — distinguished so the caller can say "no changes"
/// instead of claiming a write that did not happen.
#[derive(Debug, PartialEq, Eq)]
pub enum EditOutcome {
    Applied,
    Unchanged,
}

/// Open `$VISUAL`/`$EDITOR` on the current config, then [`apply`] the result.
///
/// Deliberately fails with a pointer to `show`/`apply` when no editor is
/// configured, instead of guessing at `vi`: the runtime image
/// (`deploy/Dockerfile`) installs only `ca-certificates` and `curl`, so
/// inside the standard container there IS no editor, and a fallback that
/// spawns one would fail with `No such file or directory` — an error naming
/// neither the cause nor the way round it.
///
/// On a validation failure the edited text is kept at
/// [`edit_scratch_path`] and named in the error, so a long edit is never
/// lost to a typo.
pub fn edit(config_path: &Path) -> Result<EditOutcome> {
    edit_with(config_path, &resolve_editor()?)
}

/// `$VISUAL`, else `$EDITOR`, else an error that teaches the way round it.
///
/// Split from [`edit_with`] so the rest of editing is testable without
/// touching `VISUAL`/`EDITOR`: those are process-global, and mutating them
/// in a test corrupts every other test running in parallel — the same
/// hazard that keeps the config crate's own env tests to pure functions.
fn resolve_editor() -> Result<String> {
    std::env::var("VISUAL")
        .ok()
        .or_else(|| std::env::var("EDITOR").ok())
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .ok_or_else(|| {
            crate::Error::Config(
                "no $EDITOR or $VISUAL set. Inside the standard container there is no editor at \
                 all — use `opsclaw-cli config show > c.toml`, edit it wherever you like, then \
                 `opsclaw-cli config apply --file c.toml` (or pipe it in on stdin)"
                    .into(),
            )
        })
}

fn edit_with(config_path: &Path, editor: &str) -> Result<EditOutcome> {
    let before = show(config_path)?;
    let scratch = edit_scratch_path(config_path);
    std::fs::write(&scratch, &before)?;

    let status = std::process::Command::new("sh")
        .arg("-c")
        // $EDITOR legitimately carries flags ("code -w", "emacs -nw"), so it
        // goes through a shell rather than being treated as one executable
        // name. The path is ours, not operator input.
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(&scratch)
        .status()
        .map_err(|e| crate::Error::Config(format!("could not run editor {editor:?}: {e}")))?;
    if !status.success() {
        let _ = std::fs::remove_file(&scratch);
        return Err(crate::Error::Config(format!(
            "editor {editor:?} exited with {status} — config left unchanged"
        )));
    }

    let after = std::fs::read_to_string(&scratch)?;
    if after == before {
        let _ = std::fs::remove_file(&scratch);
        return Ok(EditOutcome::Unchanged);
    }
    match apply(config_path, &after) {
        Ok(()) => {
            let _ = std::fs::remove_file(&scratch);
            Ok(EditOutcome::Applied)
        }
        Err(e) => Err(crate::Error::Config(format!(
            "{e}\n\nconfig.toml is UNCHANGED. Your edit is kept at {} — fix it there and run \
             `opsclaw-cli config apply --file {}`",
            scratch.display(),
            scratch.display()
        ))),
    }
}

/// What [`remove`] would delete, for the confirmation preview.
///
/// Enumerates the whole subtree rather than counting it. `config rm
/// <project>` takes out every environment, target and resource beneath it,
/// and a count ("removes 4 things") does not let an operator notice that one
/// of the four is the production cluster.
pub fn describe_removal(config_path: &Path, path: &str) -> Result<String> {
    let raw = std::fs::read_to_string(config_path)?;
    let cfg: Config = toml::from_str(&raw)
        .map_err(|e| crate::Error::Config(format!("{}: {e}", config_path.display())))?;

    let parts: Vec<&str> = path.split("::").map(str::trim).collect();
    let mut lines = Vec::new();
    match parts.as_slice() {
        [project] => {
            let p = cfg
                .projects
                .iter()
                .find(|p| p.name == *project)
                .ok_or_else(|| unknown_path(&cfg, path))?;
            lines.push(format!("will remove PROJECT {project:?} and everything under it:"));
            for e in &p.envs {
                lines.push(format!("  env {}::{}", p.name, e.name));
                for t in &e.targets {
                    lines.push(format!("    target {}::{}::{}", p.name, e.name, t.name));
                    for r in &t.resources {
                        lines.push(format!("      resource {} [{:?}]", r.name(), r.rtype()));
                    }
                }
            }
        }
        [project, env] => {
            let e = cfg
                .projects
                .iter()
                .find(|p| p.name == *project)
                .and_then(|p| p.envs.iter().find(|e| e.name == *env))
                .ok_or_else(|| unknown_path(&cfg, path))?;
            lines.push(format!("will remove ENVIRONMENT {project}::{env} and its targets:"));
            for t in &e.targets {
                lines.push(format!("  target {}::{}::{}", project, env, t.name));
                for r in &t.resources {
                    lines.push(format!("    resource {} [{:?}]", r.name(), r.rtype()));
                }
            }
        }
        [project, env, target] => {
            let t = cfg
                .projects
                .iter()
                .find(|p| p.name == *project)
                .and_then(|p| p.envs.iter().find(|e| e.name == *env))
                .and_then(|e| e.targets.iter().find(|t| t.name == *target))
                .ok_or_else(|| unknown_path(&cfg, path))?;
            lines.push(format!("will remove TARGET {project}::{env}::{target} [{:?}]", t.kind));
            for r in &t.resources {
                lines.push(format!("  resource {} [{:?}]", r.name(), r.rtype()));
            }
        }
        _ => {
            return Err(crate::Error::Config(format!(
                "{path:?} is not a project, project::env, or project::env::target path"
            )));
        }
    }
    Ok(lines.join("\n"))
}

/// Remove the project, environment, or target named by `path`
/// (`project`, `project::env`, or `project::env::target`) — the same
/// `::`-separated form `scan` and `doctor` already print.
///
/// Refuses an unknown path rather than succeeding silently: "removed
/// nothing, exit 0" on a typo is how an operator concludes a target is gone
/// when it is still being scanned.
///
/// Re-serializes, so comments do not survive — see the module doc. The
/// caller is expected to say so.
pub fn remove(config_path: &Path, path: &str) -> Result<String> {
    let raw = if config_path.exists() {
        std::fs::read_to_string(config_path)?
    } else {
        return Err(crate::Error::Config(format!(
            "{} does not exist — nothing to remove",
            config_path.display()
        )));
    };
    let mut cfg: Config = toml::from_str(&raw)
        .map_err(|e| crate::Error::Config(format!("{}: {e}", config_path.display())))?;

    let parts: Vec<&str> = path.split("::").map(str::trim).collect();
    let removed = match parts.as_slice() {
        [project] => {
            let before = cfg.projects.len();
            cfg.projects.retain(|p| p.name != *project);
            if cfg.projects.len() == before {
                return Err(unknown_path(&cfg, path));
            }
            format!("project {project:?}")
        }
        [project, env] => {
            let p = cfg
                .projects
                .iter_mut()
                .find(|p| p.name == *project)
                .ok_or_else(|| crate::Error::Config(format!("no project named {project:?}")))?;
            let before = p.envs.len();
            p.envs.retain(|e| e.name != *env);
            if p.envs.len() == before {
                return Err(unknown_path(&cfg, path));
            }
            format!("environment {project}::{env}")
        }
        [project, env, target] => {
            let e = cfg
                .projects
                .iter_mut()
                .find(|p| p.name == *project)
                .and_then(|p| p.envs.iter_mut().find(|e| e.name == *env))
                .ok_or_else(|| {
                    crate::Error::Config(format!("no environment named {project}::{env}"))
                })?;
            let before = e.targets.len();
            e.targets.retain(|t| t.name != *target);
            if e.targets.len() == before {
                return Err(unknown_path(&cfg, path));
            }
            format!("target {project}::{env}::{target}")
        }
        _ => {
            return Err(crate::Error::Config(format!(
                "{path:?} is not a project, project::env, or project::env::target path"
            )));
        }
    };

    // Same order as `apply`: prove the daemon would still boot BEFORE
    // touching the file. Removing the last target of an environment is fine
    // (`validate()` has always allowed an empty one), but removing something
    // an escalation chain or resource still points at may not be.
    cfg.validate()?;
    let body = toml::to_string_pretty(&cfg)
        .map_err(|e| crate::Error::Config(format!("serializing config: {e}")))?;
    persist_config_text(config_path, &body)?;
    Ok(removed)
}

/// The "no such path" error, listing what DOES exist. A bare "not found" on
/// a `::` path is unhelpful when the mistake is usually one level or one
/// typo away.
fn unknown_path(cfg: &Config, path: &str) -> crate::Error {
    let mut known: Vec<String> = Vec::new();
    for p in &cfg.projects {
        known.push(p.name.clone());
        for e in &p.envs {
            known.push(format!("{}::{}", p.name, e.name));
            for t in &e.targets {
                known.push(format!("{}::{}::{}", p.name, e.name, t.name));
            }
        }
    }
    crate::Error::Config(format!(
        "nothing at {path:?}. Configured: {}",
        if known.is_empty() { "(nothing)".to_string() } else { known.join(", ") }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE_ENOUGH: &str = r#"
# a comment that must survive an apply
[[project]]
name = "example"

[[project.env]]
name = "dev"
expected_state = "running"

[[project.env.target]]
name = "jumpbox"
kind = "local"
expected_state = "running"
"#;

    fn write(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn the_restart_hint_names_a_command_that_exists_where_it_is_printed() {
        // "restart the daemon" alone leaves an operator to work out how, and
        // the answer differs by packaging: systemctl cannot reach a daemon
        // that is PID 1 of a container, and docker is not involved at all in
        // a systemd install. Whichever branch runs here, it must name exactly
        // one of them and say where to run it.
        let hint = restart_hint();
        assert!(hint.contains("not hot-reloaded"), "{hint}");
        let docker = hint.contains("docker compose restart");
        let systemd = hint.contains("systemctl restart");
        assert!(docker ^ systemd, "exactly one restart mechanism, never both: {hint}");
        if docker {
            assert!(
                hint.contains("on the host"),
                "the compose file is not in the container: {hint}"
            );
        }
    }

    #[test]
    fn show_round_trips_through_apply_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);

        let text = show(&path).unwrap();
        assert_eq!(text, LIVE_ENOUGH, "show must be the file, not a re-serialization");

        apply(&path, &text).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), LIVE_ENOUGH);
        assert!(
            std::fs::read_to_string(&path).unwrap().contains("# a comment that must survive"),
            "an operator's comments are part of their config"
        );
    }

    #[test]
    fn show_on_a_fresh_host_offers_the_default_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let text = show(&path).unwrap();
        assert!(!path.exists(), "show must not create the file it is reading");
        apply(&path, &text)
            .expect("the default config must be appliable — it is what onboard writes over");
    }

    #[test]
    fn a_refused_apply_leaves_the_running_config_untouched() {
        // The failure this prevents: live mode refuses to boot on an invalid
        // config, and docker will not exec into a restarting container — so
        // a save that writes first and validates second is an install you
        // cannot get back into.
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);

        let err = apply(&path, "this is not toml at all {{{").unwrap_err();
        assert!(err.to_string().contains("invalid TOML"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), LIVE_ENOUGH);

        // Parses, but the daemon would refuse it: a key with no models.
        let refused = "[llm]\napi_key = \"env:SOMETHING\"\n";
        let err = apply(&path, refused).unwrap_err();
        assert!(
            !err.to_string().contains("invalid TOML"),
            "must reach validate(), not stop at parse: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            LIVE_ENOUGH,
            "a config validate() rejects must never be written"
        );
    }

    #[test]
    fn apply_keeps_a_bak_of_what_it_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);
        apply(&path, "# replaced\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# replaced\n");
        assert_eq!(
            std::fs::read_to_string(path.with_extension("toml.bak")).unwrap(),
            LIVE_ENOUGH,
            "one `mv` back is the recovery path"
        );
    }

    #[test]
    fn remove_takes_a_target_an_env_or_a_project() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);

        assert_eq!(remove(&path, "example::dev::jumpbox").unwrap(), "target example::dev::jumpbox");
        let cfg = Config::load(Some(&path)).unwrap();
        assert!(cfg.projects[0].envs[0].targets.is_empty());
        assert_eq!(cfg.projects[0].envs.len(), 1, "removing a target must not remove its env");

        assert_eq!(remove(&path, "example::dev").unwrap(), "environment example::dev");
        let cfg = Config::load(Some(&path)).unwrap();
        assert!(cfg.projects[0].envs.is_empty());

        assert_eq!(remove(&path, "example").unwrap(), "project \"example\"");
        let cfg = Config::load(Some(&path)).unwrap();
        assert!(cfg.projects.is_empty());
    }

    #[test]
    fn removing_nothing_is_an_error_that_lists_what_exists() {
        // "removed nothing, exit 0" is how an operator concludes a target is
        // gone while it is still being scanned.
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);

        let err = remove(&path, "example::dev::typo").unwrap_err().to_string();
        assert!(err.contains("nothing at"), "{err}");
        assert!(err.contains("example::dev::jumpbox"), "must list the real path: {err}");

        let err = remove(&path, "example::nosuchenv::x").unwrap_err().to_string();
        assert!(err.contains("no environment named example::nosuchenv"), "{err}");

        let err = remove(&path, "a::b::c::d").unwrap_err().to_string();
        assert!(err.contains("is not a project"), "{err}");

        // Every failure above left the file alone.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), LIVE_ENOUGH);
    }

    #[test]
    fn an_editor_that_changes_nothing_reports_unchanged_and_leaves_no_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);
        // `true` ignores its argument and exits 0 — an editor the operator
        // opened and quit without saving.
        assert_eq!(edit_with(&path, "true").unwrap(), EditOutcome::Unchanged);
        assert!(!edit_scratch_path(&path).exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), LIVE_ENOUGH);
    }

    #[test]
    fn an_editor_carrying_flags_still_reaches_the_file() {
        // $EDITOR legitimately holds flags ("code -w", "emacs -nw"), which is
        // why the spawn goes through a shell rather than exec'ing one name.
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);
        assert_eq!(
            edit_with(&path, "sed -i -e '$a\\# appended by the editor'").unwrap(),
            EditOutcome::Applied
        );
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("# appended by the editor"), "{after}");
        assert!(after.contains("# a comment that must survive"), "verbatim write: {after}");
    }

    #[test]
    fn a_failed_edit_keeps_the_operators_work_and_says_where() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);
        // An "editor" that replaces the file with something validate() refuses.
        let err =
            edit_with(&path, "printf '[llm]\\napi_key = \"env:X\"\\n' >").unwrap_err().to_string();
        assert!(err.contains("UNCHANGED"), "{err}");
        assert!(err.contains("config.toml.edit"), "must name where the work is: {err}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            LIVE_ENOUGH,
            "the running config survives a bad edit"
        );
        assert!(edit_scratch_path(&path).exists(), "a long edit must not be lost to a typo");
    }

    #[test]
    fn an_editor_that_fails_leaves_everything_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, LIVE_ENOUGH);
        let err = edit_with(&path, "false").unwrap_err().to_string();
        assert!(err.contains("config left unchanged"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), LIVE_ENOUGH);
        assert!(!edit_scratch_path(&path).exists());
    }
}
