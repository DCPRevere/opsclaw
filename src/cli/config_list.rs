//! `opsclaw-cli config list` — the inventory an operator can actually read.
//!
//! `config show` prints the TOML, which is the source of truth but not an
//! answer to the question operators actually ask: *what is this target
//! allowed to do?* Autonomy and expected-state INHERIT down the tree
//! (target > env > project > default), so the effective value for a target
//! is frequently written nowhere in the file. Reading it off the TOML means
//! resolving the chain by eye, and getting that wrong in the permissive
//! direction is how an operator believes a target is in `observe` while the
//! daemon has it in `act_on_known`.
//!
//! So this resolves through [`Config::autonomy_for`] and
//! [`Config::expected_state_for`] — the SAME functions the daemon and the
//! policy layer use — and shows both the effective value and where it came
//! from. A second implementation of the inheritance rule here would be a
//! second opinion, and the one place a config viewer must never disagree
//! with the daemon is on what a target may do.
//!
//! Distinct from the agent's own `opsclaw_config` tool
//! (`src/tools/config_tool.rs`), which renders a narrower view for the LLM:
//! no expected-state, no credential references, and unresolved autonomy
//! ("inherits env"). That asymmetry is why this exists — the agent could
//! enumerate what it manages and the operator could not.
//!
//! Secret-safe by the same construction as everything else that touches
//! `Config`: credentials are [`crate::config::SecretRef`]s, which hold and
//! display NAMES (`env:VAR` / `store:KEY`), never resolved values.

use serde::Serialize;

use crate::Result;
use crate::config::Config;
#[cfg(test)]
use crate::domain::Autonomy;

/// One target, with inheritance already resolved. Serialized directly for
/// `--json`, so the machine-readable form carries the effective values too
/// rather than making every consumer re-implement the chain.
#[derive(Debug, Serialize)]
pub struct TargetView {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub address: Option<String>,
    pub kubernetes_context: Option<String>,
    pub kubernetes_scope: Option<String>,
    pub jump_host: Option<String>,
    pub provider: Option<String>,
    pub region: Option<String>,
    /// The reference NAME only (`env:VAR` / `store:KEY`) — never a value.
    pub credential: Option<String>,
    pub autonomy: String,
    /// Which level actually supplied the autonomy above.
    pub autonomy_from: String,
    pub expected_state: String,
    pub expected_state_from: String,
    pub resources: Vec<ResourceView>,
}

#[derive(Debug, Serialize)]
pub struct ResourceView {
    pub name: String,
    pub rtype: String,
    pub credential: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EnvView {
    pub name: String,
    pub autonomy_override: Option<String>,
    pub expected_state_override: Option<String>,
    pub targets: Vec<TargetView>,
}

#[derive(Debug, Serialize)]
pub struct ProjectView {
    pub name: String,
    pub autonomy_override: Option<String>,
    /// Whether this project declares its own escalation chain. The chain
    /// itself can carry channel addresses, so only its presence is reported.
    pub escalation_override: bool,
    pub envs: Vec<EnvView>,
}

/// Build the resolved inventory from a loaded config.
pub fn inventory(cfg: &Config) -> Vec<ProjectView> {
    cfg.projects
        .iter()
        .map(|p| ProjectView {
            name: p.name.clone(),
            autonomy_override: p.autonomy.map(|a| a.to_string()),
            escalation_override: p.escalation.is_some(),
            envs: p
                .envs
                .iter()
                .map(|e| EnvView {
                    name: e.name.clone(),
                    autonomy_override: e.autonomy.map(|a| a.to_string()),
                    expected_state_override: e
                        .expected_state
                        .map(|s| format!("{s:?}").to_lowercase()),
                    targets: e
                        .targets
                        .iter()
                        .map(|t| {
                            let autonomy = cfg.autonomy_for(&p.name, &e.name, &t.name);
                            let expected = cfg.expected_state_for(&p.name, &e.name, &t.name);
                            TargetView {
                                path: format!("{}::{}::{}", p.name, e.name, t.name),
                                name: t.name.clone(),
                                kind: format!("{:?}", t.kind).to_lowercase(),
                                address: t.address.clone(),
                                kubernetes_context: t
                                    .kubernetes
                                    .as_ref()
                                    .map(|kubernetes| kubernetes.context.clone()),
                                kubernetes_scope: t.kubernetes.as_ref().map(|kubernetes| {
                                    match &kubernetes.namespace {
                                        Some(namespace) => format!("namespace:{namespace}"),
                                        None => "cluster".to_string(),
                                    }
                                }),
                                jump_host: t.jump_host.clone(),
                                provider: t.provider.map(|pr| format!("{pr:?}").to_lowercase()),
                                region: t.region.clone(),
                                credential: t.credential.as_ref().map(|c| c.to_string()),
                                autonomy: autonomy.to_string(),
                                autonomy_from: source_of(
                                    t.autonomy.is_some(),
                                    e.autonomy.is_some(),
                                    p.autonomy.is_some(),
                                ),
                                expected_state: format!("{expected:?}").to_lowercase(),
                                expected_state_from: source_of(
                                    t.expected_state.is_some(),
                                    e.expected_state.is_some(),
                                    false,
                                ),
                                resources: t
                                    .resources
                                    .iter()
                                    .map(|r| ResourceView {
                                        name: r.name().to_string(),
                                        rtype: format!("{:?}", r.rtype()).to_lowercase(),
                                        credential: r.credential().map(|c| c.to_string()),
                                    })
                                    .collect(),
                            }
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect()
}

/// Which level supplied a resolved value. Named rather than inferred at the
/// call site so the text and JSON forms cannot drift apart.
fn source_of(on_target: bool, on_env: bool, on_project: bool) -> String {
    if on_target {
        "target".into()
    } else if on_env {
        "env".into()
    } else if on_project {
        "project".into()
    } else {
        "default".into()
    }
}

/// The human-readable tree.
///
/// Empty levels are called out rather than rendered as blank space: an
/// environment with no targets looks exactly like a completed setup until
/// you notice nothing is ever scanned, and that is a state the wizard could
/// produce for a whole release.
pub fn render(projects: &[ProjectView]) -> String {
    if projects.is_empty() {
        return "no projects configured — run `opsclaw-cli config project add`\n".to_string();
    }
    let mut out = String::new();
    for p in projects {
        out.push_str(&format!("project {}", p.name));
        if let Some(a) = &p.autonomy_override {
            out.push_str(&format!("   autonomy: {a}"));
        }
        if p.escalation_override {
            out.push_str("   [own escalation chain]");
        }
        out.push('\n');
        if p.envs.is_empty() {
            out.push_str("  (no environments)\n\n");
            continue;
        }
        for e in &p.envs {
            out.push_str(&format!("  env {}", e.name));
            if let Some(a) = &e.autonomy_override {
                out.push_str(&format!("   autonomy: {a}"));
            }
            if let Some(s) = &e.expected_state_override {
                out.push_str(&format!("   expected: {s}"));
            }
            out.push('\n');
            if e.targets.is_empty() {
                out.push_str("    (no targets — nothing here is watched)\n");
                continue;
            }
            for t in &e.targets {
                out.push_str(&format!("    target {}   [{}]\n", t.name, t.kind));
                let mut field = |label: &str, value: &str| {
                    out.push_str(&format!("      {label:<14}{value}\n"));
                };
                if let Some(a) = &t.address {
                    field("address", a);
                }
                if let Some(context) = &t.kubernetes_context {
                    field("context", context);
                }
                if let Some(scope) = &t.kubernetes_scope {
                    field("k8s scope", scope);
                }
                if let Some(j) = &t.jump_host {
                    field("jump host", j);
                }
                if let Some(pr) = &t.provider {
                    field("provider", pr);
                }
                if let Some(r) = &t.region {
                    field("region", r);
                }
                field("autonomy", &format!("{} (from {})", t.autonomy, t.autonomy_from));
                field(
                    "expected",
                    &format!("{} (from {})", t.expected_state, t.expected_state_from),
                );
                field("credential", t.credential.as_deref().unwrap_or("none"));
                if t.resources.is_empty() {
                    field("resources", "none");
                } else {
                    for r in &t.resources {
                        field(
                            "resource",
                            &format!(
                                "{} [{}]{}",
                                r.name,
                                r.rtype,
                                r.credential
                                    .as_deref()
                                    .map(|c| format!(" credential={c}"))
                                    .unwrap_or_default()
                            ),
                        );
                    }
                }
            }
        }
        out.push('\n');
    }
    // The legend earns its line: "from default" is the difference between a
    // level that chose `suggest` and one that never said anything, and those
    // are not the same fact when deciding whether to promote a target.
    out.push_str(
        "autonomy/expected show the EFFECTIVE value the daemon uses, resolved\n\
         target > env > project > default. \"from default\" means no level set it.\n",
    );
    out
}

/// A `project[::env[::target]]` selector — the same `::` path `scan`,
/// `config rm` and `doctor`'s own output already use, so filtering needs no
/// vocabulary an operator has not already met.
#[derive(Debug, PartialEq, Eq)]
struct Selector {
    project: String,
    env: Option<String>,
    target: Option<String>,
}

impl Selector {
    fn parse(raw: &str) -> Result<Self> {
        let parts: Vec<&str> = raw.split("::").map(str::trim).collect();
        match parts.as_slice() {
            [p] if !p.is_empty() => Ok(Selector { project: (*p).into(), env: None, target: None }),
            [p, e] if !p.is_empty() && !e.is_empty() => {
                Ok(Selector { project: (*p).into(), env: Some((*e).into()), target: None })
            }
            [p, e, t] if !p.is_empty() && !e.is_empty() && !t.is_empty() => Ok(Selector {
                project: (*p).into(),
                env: Some((*e).into()),
                target: Some((*t).into()),
            }),
            _ => Err(crate::Error::Config(format!(
                "{raw:?} is not a project, project::env, or project::env::target path"
            ))),
        }
    }
}

/// Narrow an inventory to the selected subtrees. Selectors UNION, so
/// `list a::dev b::prod` shows both.
///
/// Filtering happens on the resolved views, never on the `Config` — every
/// effective autonomy and expected-state has already been computed against
/// the WHOLE tree by then. Filtering the config first would drop the very
/// ancestors the inheritance chain reads, so a narrowed listing could report
/// a different autonomy than the daemon enforces, which is exactly the
/// disagreement this module exists to prevent.
///
/// An empty selector list means no filtering (show everything). A selector
/// list that matches nothing is an ERROR listing what does exist, not an
/// empty success: a filtered listing that silently shows nothing reads as
/// "this project has no targets" rather than "you typed the name wrong".
fn filter(projects: Vec<ProjectView>, selectors: &[Selector]) -> Vec<ProjectView> {
    if selectors.is_empty() {
        return projects;
    }
    projects
        .into_iter()
        .filter_map(|p| {
            let hits: Vec<&Selector> = selectors.iter().filter(|s| s.project == p.name).collect();
            if hits.is_empty() {
                return None;
            }
            // A bare `project` selector takes the whole subtree; otherwise
            // keep only the environments (and targets) named.
            if hits.iter().any(|s| s.env.is_none()) {
                return Some(p);
            }
            let envs: Vec<EnvView> = p
                .envs
                .into_iter()
                .filter_map(|e| {
                    let env_hits: Vec<&&Selector> =
                        hits.iter().filter(|s| s.env.as_deref() == Some(e.name.as_str())).collect();
                    if env_hits.is_empty() {
                        return None;
                    }
                    if env_hits.iter().any(|s| s.target.is_none()) {
                        return Some(e);
                    }
                    let targets: Vec<TargetView> = e
                        .targets
                        .into_iter()
                        .filter(|t| {
                            env_hits.iter().any(|s| s.target.as_deref() == Some(t.name.as_str()))
                        })
                        .collect();
                    if targets.is_empty() { None } else { Some(EnvView { targets, ..e }) }
                })
                .collect();
            if envs.is_empty() { None } else { Some(ProjectView { envs, ..p }) }
        })
        .collect()
}

/// Every selectable path in a config, for the "nothing matched" error.
fn known_paths(projects: &[ProjectView]) -> Vec<String> {
    let mut out = Vec::new();
    for p in projects {
        out.push(p.name.clone());
        for e in &p.envs {
            out.push(format!("{}::{}", p.name, e.name));
            for t in &e.targets {
                out.push(t.path.clone());
            }
        }
    }
    out
}

/// `config list` end to end: load, resolve, filter.
///
/// `paths` empty lists everything.
pub fn list(config_path: &std::path::Path, paths: &[String]) -> Result<Vec<ProjectView>> {
    let cfg = Config::load(Some(config_path))?;
    let all = inventory(&cfg);
    let selectors = paths.iter().map(|p| Selector::parse(p)).collect::<Result<Vec<_>>>()?;
    let known = known_paths(&all);
    let filtered = filter(all, &selectors);
    if filtered.is_empty() && !selectors.is_empty() {
        return Err(crate::Error::Config(format!(
            "nothing matched {}. Configured: {}",
            paths.iter().map(|p| format!("{p:?}")).collect::<Vec<_>>().join(", "),
            if known.is_empty() { "(nothing)".to_string() } else { known.join(", ") }
        )));
    }
    Ok(filtered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Config {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn effective_autonomy_is_resolved_and_attributed() {
        // The reason this module exists: none of these three targets says
        // anything about autonomy itself, and they land on three DIFFERENT
        // effective values. Reading that off the TOML means resolving the
        // chain by eye, and erring permissively is how an operator believes
        // a target is in observe while the daemon has it acting.
        let cfg = parse(
            r#"
            [[project]]
            name = "example"
            autonomy = "observe"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "inherits-project"
            kind = "local"
            [[project.env]]
            name = "staging"
            autonomy = "act_on_known"
            [[project.env.target]]
            name = "inherits-env"
            kind = "local"
            [[project.env.target]]
            name = "says-so-itself"
            kind = "local"
            autonomy = "suggest"
            "#,
        );
        let inv = inventory(&cfg);
        let t = |env: usize, idx: usize| -> &TargetView { &inv[0].envs[env].targets[idx] };

        assert_eq!(t(0, 0).autonomy, "observe");
        assert_eq!(t(0, 0).autonomy_from, "project");

        assert_eq!(t(1, 0).autonomy, "act_on_known");
        assert_eq!(t(1, 0).autonomy_from, "env");

        assert_eq!(t(1, 1).autonomy, "suggest");
        assert_eq!(t(1, 1).autonomy_from, "target");
    }

    #[test]
    fn a_config_that_sets_nothing_reports_the_daemons_default() {
        let cfg = parse(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "local"
            "#,
        );
        let inv = inventory(&cfg);
        let t = &inv[0].envs[0].targets[0];
        // Must agree with Config::autonomy_for's documented default, not
        // with a guess made here.
        assert_eq!(t.autonomy, Autonomy::Suggest.to_string());
        assert_eq!(t.autonomy_from, "default");
        assert_eq!(t.expected_state, "running");
        assert_eq!(t.expected_state_from, "default");
        assert_eq!(t.path, "p::e::t");
    }

    #[test]
    fn it_never_renders_a_secret_value() {
        const SECRET: &str = "s3cr3t-must-never-print-4c1d";
        // SAFETY: single-threaded test setup; the assertion is about the
        // rendered output, and the variable name is unique to this test.
        unsafe { std::env::set_var("OPSCLAW_CONFIG_LIST_TEST_SECRET", SECRET) };
        let cfg = parse(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "ssh"
            address = "10.0.0.5"
            credential = "env:OPSCLAW_CONFIG_LIST_TEST_SECRET"
            "#,
        );
        let inv = inventory(&cfg);
        let text = render(&inv);
        assert!(!text.contains(SECRET), "the VALUE must never appear: {text}");
        assert!(
            text.contains("env:OPSCLAW_CONFIG_LIST_TEST_SECRET"),
            "the reference NAME is what an operator needs to see: {text}"
        );
        let json = serde_json::to_string(&inv).unwrap();
        assert!(!json.contains(SECRET), "nor through --json: {json}");
    }

    #[test]
    fn an_env_with_no_targets_says_so_rather_than_rendering_blank() {
        // The wizard could produce exactly this for a whole release, and a
        // blank line under an env name reads as a finished setup.
        let cfg = parse(
            r#"
            [[project]]
            name = "example"
            [[project.env]]
            name = "dev"
            "#,
        );
        let text = render(&inventory(&cfg));
        assert!(text.contains("no targets — nothing here is watched"), "{text}");
    }

    #[test]
    fn an_empty_config_points_at_the_command_that_fixes_it() {
        let text = render(&inventory(&Config::default()));
        assert!(text.contains("config project add"), "{text}");
    }

    #[test]
    fn the_tree_carries_the_details_show_would_make_you_read_toml_for() {
        let cfg = parse(
            r#"
            [[project]]
            name = "example"
            [[project.env]]
            name = "prod"
            expected_state = "stopped"
            [[project.env.target]]
            name = "web-1"
            kind = "ssh"
            address = "10.0.0.5"
            jump_host = "bastion.example"
            credential = "store:web-1-key"
            [[project.env.target.resource]]
            type = "postgres"
            name = "primary"
            "#,
        );
        let text = render(&inventory(&cfg));
        for expected in [
            "target web-1   [ssh]",
            "10.0.0.5",
            "bastion.example",
            "store:web-1-key",
            "primary",
            "stopped (from env)",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    const TWO_PROJECTS: &str = r#"
        [[project]]
        name = "example"
        autonomy = "observe"
        [[project.env]]
        name = "dev"
        [[project.env.target]]
        name = "web-1"
        kind = "local"
        [[project.env.target]]
        name = "web-2"
        kind = "local"
        [[project.env]]
        name = "prod"
        [[project.env.target]]
        name = "db-1"
        kind = "local"
        [[project]]
        name = "other"
        [[project.env]]
        name = "dev"
        [[project.env.target]]
        name = "thing"
        kind = "local"
        "#;

    fn sel(s: &str) -> Selector {
        Selector::parse(s).unwrap()
    }

    fn paths_in(views: &[ProjectView]) -> Vec<String> {
        views
            .iter()
            .flat_map(|p| p.envs.iter().flat_map(|e| e.targets.iter().map(|t| t.path.clone())))
            .collect()
    }

    #[test]
    fn a_filter_selects_a_project_an_env_or_a_single_target() {
        let cfg = parse(TWO_PROJECTS);

        assert_eq!(
            paths_in(&filter(inventory(&cfg), &[sel("example")])),
            ["example::dev::web-1", "example::dev::web-2", "example::prod::db-1"]
        );
        assert_eq!(
            paths_in(&filter(inventory(&cfg), &[sel("example::dev")])),
            ["example::dev::web-1", "example::dev::web-2"]
        );
        assert_eq!(
            paths_in(&filter(inventory(&cfg), &[sel("example::dev::web-2")])),
            ["example::dev::web-2"]
        );
        assert_eq!(paths_in(&filter(inventory(&cfg), &[])), paths_in(&inventory(&cfg)));
    }

    #[test]
    fn filters_union_across_projects_and_envs() {
        // "limit them to only some projects or envs" — plural, so several
        // selectors have to combine rather than the last one winning.
        let cfg = parse(TWO_PROJECTS);
        assert_eq!(
            paths_in(&filter(inventory(&cfg), &[sel("example::prod"), sel("other::dev")])),
            ["example::prod::db-1", "other::dev::thing"]
        );
    }

    #[test]
    fn an_env_of_the_same_name_in_another_project_is_not_swept_in() {
        // Both projects have a "dev". Matching on the env name alone would
        // quietly widen the filter the operator asked for.
        let cfg = parse(TWO_PROJECTS);
        assert_eq!(paths_in(&filter(inventory(&cfg), &[sel("other::dev")])), ["other::dev::thing"]);
    }

    #[test]
    fn filtering_never_changes_a_resolved_value() {
        // The trap this guards: autonomy here comes from the PROJECT, so
        // filtering the Config down to one target before resolving would
        // drop the ancestor the chain reads and report `suggest` — a
        // narrowed listing disagreeing with the daemon about what a target
        // may do. Filtering the resolved views cannot do that.
        let cfg = parse(TWO_PROJECTS);
        let unfiltered = inventory(&cfg);
        let whole = &unfiltered[0].envs[0].targets[0];
        assert_eq!(whole.autonomy, "observe");
        assert_eq!(whole.autonomy_from, "project");

        let narrowed = filter(inventory(&cfg), &[sel("example::dev::web-1")]);
        let one = &narrowed[0].envs[0].targets[0];
        assert_eq!(one.autonomy, whole.autonomy);
        assert_eq!(one.autonomy_from, whole.autonomy_from);
    }

    #[test]
    fn a_filter_matching_nothing_is_an_error_that_lists_what_exists() {
        // An empty success reads as "this project has no targets" rather
        // than "you typed the name wrong".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, TWO_PROJECTS).unwrap();

        let err = list(&path, &["example::nope".to_string()]).unwrap_err().to_string();
        assert!(err.contains("nothing matched"), "{err}");
        assert!(err.contains("example::dev::web-1"), "must list real paths: {err}");

        assert!(list(&path, &["example::dev".to_string()]).is_ok());
    }

    #[test]
    fn a_malformed_selector_is_refused_rather_than_guessed_at() {
        assert!(Selector::parse("a::b::c::d").is_err());
        assert!(Selector::parse("").is_err());
        assert!(Selector::parse("a::").is_err());
        assert_eq!(
            sel(" example :: dev "),
            Selector { project: "example".into(), env: Some("dev".into()), target: None },
            "whitespace around the separator is an operator typing, not a different name"
        );
    }

    #[test]
    fn expected_state_never_attributes_to_project() {
        // expected_state inherits target > env only (Config::expected_state_for
        // has no project level), so claiming "from project" would be a lie
        // this module invented.
        let cfg = parse(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "local"
            "#,
        );
        let inv = inventory(&cfg);
        assert_ne!(inv[0].envs[0].targets[0].expected_state_from, "project");
    }
}
