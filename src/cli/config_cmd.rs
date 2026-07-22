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

/// Prompt for one new resource, TYPE-AWARE: each resource kind asks only
/// the questions that make sense for it (an ECK Elasticsearch defaults to
/// basic auth as `elastic` behind a self-signed CA; ArgoCD/Prometheus/
/// Service Bus/EventStore take a bearer/SAS token), and each kind builds
/// its own `ResourceCfg` variant — the per-type connection shape lives in
/// the type; this wizard just fills it in at intake.
fn wizard_resource(p: &mut dyn Prompter) -> Result<ResourceCfg> {
    use crate::config::{
        ArgocdResourceCfg, AsbResourceCfg, EsResourceCfg, EventstoreResourceCfg, PromResourceCfg,
    };
    use crate::domain::ResourceType;

    let type_str = ask_choice(
        p,
        "resource type",
        &["elasticsearch", "prometheus", "argocd", "azure_service_bus", "eventstore"],
        "elasticsearch",
    )?;
    let rtype: ResourceType = type_str
        .parse()
        .map_err(|()| crate::Error::Config(format!("unknown resource type {type_str:?}")))?;
    let name = p.ask("resource name (e.g. logs, metrics, main)", None)?;
    // Every kind this wizard offers requires a url (the union type refuses
    // to parse without one) — insist here rather than fail at validate.
    let url_hint = match rtype {
        ResourceType::AzureServiceBus => "namespace endpoint (https://<ns>.servicebus.windows.net)",
        ResourceType::Prometheus => "base url (e.g. http://localhost:9090)",
        _ => "base url (e.g. https://localhost:9201)",
    };
    let url = loop {
        let u = p.ask(url_hint, None)?;
        if !u.is_empty() {
            break u;
        }
        p.say("  a url is required for this resource type");
    };

    // Auth scheme per type: Elasticsearch (ECK) and EventStore are
    // basic-auth by default; ArgoCD/Prometheus/Service Bus are bearer/SAS.
    // Blank username = bearer after all (an ES behind an API-key proxy
    // exists; a dev-mode EventStore has no auth).
    let username = match rtype {
        ResourceType::Elasticsearch => {
            let u = p.ask("basic-auth username (blank for bearer-token auth)", Some("elastic"))?;
            if u.is_empty() { None } else { Some(u) }
        }
        ResourceType::Eventstore => {
            let u = p.ask("basic-auth username (blank for no auth)", Some("admin"))?;
            if u.is_empty() { None } else { Some(u) }
        }
        _ => None,
    };
    // ArgoCD and Service Bus cannot function unauthenticated — their
    // variants make `credential` mandatory, so the wizard must too.
    let cred_required = username.is_some()
        || matches!(rtype, ResourceType::Argocd | ResourceType::AzureServiceBus);
    let cred_question = match (username.is_some(), cred_required) {
        (true, _) => "password reference (env:VAR or store:KEY)",
        (false, true) => "token reference (env:VAR or store:KEY)",
        (false, false) => "token reference (env:VAR or store:KEY; blank for no auth)",
    };
    let credential = loop {
        let raw = p.ask(cred_question, None)?;
        if raw.is_empty() {
            if cred_required {
                p.say("  this resource type needs a credential — enter a reference");
                continue;
            }
            break None;
        }
        match SecretRef::parse(&raw) {
            Ok(r) => break Some(r),
            Err(e) => p.say(&format!("  {e} — try again")),
        }
    };

    // TLS trust: worth asking whenever the endpoint is https — in-cluster
    // endpoints (ECK's self-signed CA) are the norm for ES, possible for
    // most of them. Skipped for plain http, and for Service Bus (always a
    // publicly-trusted Azure certificate; its variant has no TLS knobs).
    let ask_tls =
        url.starts_with("https://") && rtype != ResourceType::AzureServiceBus;
    let (ca_cert_path, insecure_tls) = if ask_tls {
        let ca = p.ask("custom CA certificate path (PEM; blank for system trust)", None)?;
        let ca_cert_path =
            if ca.is_empty() { None } else { Some(std::path::PathBuf::from(ca)) };
        let insecure_tls = if ca_cert_path.is_none() {
            p.confirm(
                "DISABLE certificate verification? (only for a localhost port-forward hop)",
                false,
            )?
        } else {
            false
        };
        (ca_cert_path, insecure_tls)
    } else {
        (None, false)
    };

    Ok(match rtype {
        ResourceType::Elasticsearch => ResourceCfg::Elasticsearch(EsResourceCfg {
            name,
            url,
            username,
            credential,
            ca_cert_path,
            insecure_tls,
        }),
        ResourceType::Prometheus => ResourceCfg::Prometheus(PromResourceCfg {
            name,
            url,
            username,
            credential,
            ca_cert_path,
            insecure_tls,
        }),
        ResourceType::Eventstore => ResourceCfg::Eventstore(EventstoreResourceCfg {
            name,
            url,
            username,
            credential,
            ca_cert_path,
            insecure_tls,
        }),
        ResourceType::Argocd => ResourceCfg::Argocd(ArgocdResourceCfg {
            name,
            url,
            credential: credential.expect("cred_required loop guarantees a value"),
            ca_cert_path,
            insecure_tls,
        }),
        ResourceType::AzureServiceBus => ResourceCfg::AzureServiceBus(AsbResourceCfg {
            name,
            url,
            credential: credential.expect("cred_required loop guarantees a value"),
        }),
        other => {
            return Err(crate::Error::Config(format!(
                "resource type {other} is not offered by this wizard"
            )));
        }
    })
}

/// `config resource add`: pick an existing `project::env::target`, run the
/// resource wizard, validate the WHOLE config, then write — same
/// never-persist-invalid rule as `add_project`. Returns the added resource
/// and the fully-qualified path it landed on.
pub fn add_resource(p: &mut dyn Prompter, config_path: &Path) -> Result<(String, ResourceCfg)> {
    let mut cfg = load_for_edit(config_path)?;
    let paths: Vec<String> = cfg
        .projects
        .iter()
        .flat_map(|pr| {
            pr.envs.iter().flat_map(move |e| {
                e.targets.iter().map(move |t| format!("{}::{}::{}", pr.name, e.name, t.name))
            })
        })
        .collect();
    if paths.is_empty() {
        return Err(crate::Error::Config(
            "no targets configured yet — run `opsclaw-cli config project add` first".into(),
        ));
    }
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let chosen = ask_choice(p, "attach to target", &path_refs, path_refs[0])?;
    let resource = wizard_resource(p)?;

    let (proj, rest) = chosen.split_once("::").expect("validated shape");
    let (env, tgt) = rest.split_once("::").expect("validated shape");
    let target = cfg
        .projects
        .iter_mut()
        .find(|pr| pr.name == proj)
        .and_then(|pr| pr.envs.iter_mut().find(|e| e.name == env))
        .and_then(|e| e.targets.iter_mut().find(|t| t.name == tgt))
        .expect("chosen from the listed paths");
    if target
        .resources
        .iter()
        .any(|r| r.rtype() == resource.rtype() && r.name() == resource.name())
    {
        return Err(crate::Error::Config(format!(
            "resource {}::{} already exists on {chosen} — edit it by hand or pick another name",
            resource.rtype(),
            resource.name()
        )));
    }
    target.resources.push(resource.clone());

    cfg.validate()?;
    write_config(config_path, &cfg)?;
    Ok((chosen, resource))
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

    fn seeded_config(dir: &Path) -> std::path::PathBuf {
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            r#"
            [[project]]
            name = "remundo"
            [[project.env]]
            name = "sandbox"
            [[project.env.target]]
            name = "cluster"
            kind = "kubernetes"
            credential = "store:sandbox-kubeconfig"
            "#,
        )
        .unwrap();
        config_path
    }

    #[test]
    fn add_resource_elasticsearch_asks_basic_auth_and_tls() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = seeded_config(dir.path());

        let mut p = ScriptedPrompter::new([
            "remundo::sandbox::cluster",  // attach to target
            "elasticsearch",              // type
            "logs",                       // name
            "https://localhost:9201",     // url
            "elastic",                    // basic-auth username
            "store:es-password",          // password reference
            "",                           // custom CA path: none
            "y",                          // disable cert verification (port-forward hop)
        ]);
        let (target, resource) = add_resource(&mut p, &config_path).unwrap();
        assert_eq!(target, "remundo::sandbox::cluster");
        let ResourceCfg::Elasticsearch(es) = &resource else {
            panic!("expected an Elasticsearch variant, got {resource:?}");
        };
        assert_eq!(es.username.as_deref(), Some("elastic"));
        assert!(es.insecure_tls);

        let reloaded = Config::load(Some(&config_path)).unwrap();
        let r = &reloaded.projects[0].envs[0].targets[0].resources[0];
        let ResourceCfg::Elasticsearch(es) = r else {
            panic!("expected an Elasticsearch variant after reload, got {r:?}");
        };
        assert_eq!(es.name, "logs");
        assert_eq!(es.username.as_deref(), Some("elastic"));
        assert_eq!(
            es.credential.as_ref().map(|c| c.to_string()),
            Some("store:es-password".into())
        );
        assert!(es.insecure_tls);
        reloaded.validate().unwrap();
    }

    #[test]
    fn add_resource_prometheus_skips_es_only_questions() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = seeded_config(dir.path());

        // http url → no TLS questions; prometheus → no username question.
        let mut p = ScriptedPrompter::new([
            "remundo::sandbox::cluster",
            "prometheus",
            "metrics",
            "http://localhost:9090",
            "", // token: none
        ]);
        let (_, resource) = add_resource(&mut p, &config_path).unwrap();
        assert_eq!(resource.rtype(), crate::domain::ResourceType::Prometheus);
        let ResourceCfg::Prometheus(prom) = &resource else {
            panic!("expected a Prometheus variant, got {resource:?}");
        };
        assert!(prom.username.is_none());
        assert!(prom.credential.is_none());
        assert!(!prom.insecure_tls);
    }

    #[test]
    fn add_resource_rejects_duplicate_and_leaves_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = seeded_config(dir.path());
        let answers = [
            "remundo::sandbox::cluster",
            "prometheus",
            "metrics",
            "http://localhost:9090",
            "",
        ];
        let mut p1 = ScriptedPrompter::new(answers);
        add_resource(&mut p1, &config_path).unwrap();
        let mut p2 = ScriptedPrompter::new(answers);
        let err = add_resource(&mut p2, &config_path).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        let reloaded = Config::load(Some(&config_path)).unwrap();
        assert_eq!(reloaded.projects[0].envs[0].targets[0].resources.len(), 1);
    }

    #[test]
    fn add_resource_with_no_targets_says_run_project_add_first() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut p = ScriptedPrompter::new(Vec::<String>::new());
        let err = add_resource(&mut p, &config_path).unwrap_err();
        assert!(err.to_string().contains("config project add"), "{err}");
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
