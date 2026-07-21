//! `opsclaw-cli` — operator/developer CLI. Links the library crate and
//! drives the same orchestrator path as every channel (gianna pattern).
//!
//! **Two modes.** Most commands here either have no daemon counterpart
//! (onboard, config wizards) or open the same SQLite file the daemon would
//! (doctor, estop, incidents, audit, postmortem, runbook) — that's LOCAL
//! mode, and it never opens an HTTP client to a daemon. `login`/`logout`
//! and the `--remote`-flagged small set (`chat`, `incidents`, `approve`,
//! `deny`, `estop`, `status`, `whoami` — DESIGN §7 decision 14) instead
//! speak to a live daemon's gateway over its token-auth API
//! (`opsclaw::cli::remote::*`, resolved through [`remote_session`] below).
//! The rule is explicit, not auto-detected from whether a session happens
//! to be saved: `chat`/`incidents`/`estop` default to LOCAL and take a
//! literal `--remote` flag to use the saved gateway session instead (a
//! fresh install with no `login` ever run still gets a working `chat`);
//! `status`/`approve`/`deny`/`whoami` are remote-ONLY (no local analogue —
//! they act on a live daemon's own state, which a local invocation has no
//! way to ask about). Every remote arm calls `remote_session()`, which
//! errors clearly ("run `opsclaw-cli login` first") when nothing is saved,
//! rather than silently falling back to local behaviour.
//!
//! Argument parsing lives here (clap types); all actual logic is in
//! `opsclaw::cli::*`, kept free of clap so it's callable from tests without
//! going through argv (see `src/cli/mod.rs`'s doc comment).

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use opsclaw::cli::prompt::StdioPrompter;
use opsclaw::cli::remote::session::Session;
use opsclaw::config::Config;
use opsclaw::http::server;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "opsclaw-cli", version, about = "OpsClaw operator CLI")]
struct Cli {
    /// Override the config file path (default: $OPSCLAW_HOME/config.toml or
    /// ~/.opsclaw/config.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

/// Parse one `key=value` `--var` argument (runbook `run`'s `--var k=v`,
/// repeatable). A clap `value_parser` rather than post-hoc parsing so a
/// malformed `--var` is rejected at argv-parse time with clap's own
/// pointing-at-the-bad-arg error, not a generic runtime failure later.
fn parse_var(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected key=value, got {s:?}"))
}

#[derive(Subcommand)]
enum Command {
    /// First-run wizard: provider key, channels, memory, gateway.
    Onboard {
        /// Non-interactive: answer every prompt from flags, no stdin.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        openrouter_api_key_env: Option<String>,
        /// Comma-separated OpenRouter model list.
        #[arg(long, value_delimiter = ',')]
        models: Vec<String>,
        #[arg(long)]
        hindsight_url: Option<String>,
        #[arg(long)]
        telegram_bot_token_env: Option<String>,
        #[arg(long)]
        deadman_url: Option<String>,
    },
    /// Config + dependency health check.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Run the daemon (identical to the `opsclaw` binary).
    Daemon,
    /// Freeze all agent action across all targets instantly. LOCAL by
    /// default (writes the sentinel file directly — works even with the
    /// daemon wedged, see `cli::estop`'s doc); `--remote` instead calls a
    /// live daemon's gateway (DESIGN §7 decision 14) for the "away from the
    /// box" case.
    Estop {
        /// Resume normal operation.
        #[arg(long)]
        resume: bool,
        #[arg(long, default_value = "operator requested via CLI")]
        reason: String,
        #[arg(long)]
        remote: bool,
    },
    /// Config management: project/env/target wizards, validation.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// List/show incidents.
    Incidents {
        #[command(subcommand)]
        command: IncidentsCommand,
    },
    /// Audit chain inspection.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Render a structured postmortem for an incident.
    Postmortem { id: Uuid },
    /// Runbook authoring + execution.
    Runbook {
        #[command(subcommand)]
        command: RunbookCommand,
    },
    /// Team memory: recall/store/forget (local mode; honest no-op when
    /// memory.hindsight_url isn't configured).
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    /// Talk to the agent. One-shot with a message, else a REPL. LOCAL by
    /// default (drives the daemon's own library wiring, no HTTP); `--remote`
    /// forces the saved gateway session instead — see module doc.
    Chat {
        /// Send once and print the reply, instead of an interactive REPL.
        message: Option<String>,
        #[arg(long)]
        remote: bool,
    },
    /// Daemon status. LOCAL mode has no analogue for this (there is no
    /// running-daemon introspection without a daemon to ask) — this
    /// command is REMOTE-ONLY, over the saved gateway session.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Approve a pending approval (remote-only — DESIGN §7 decision 14;
    /// acts on a live daemon's approval queue over its gateway).
    Approve {
        id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// Deny a pending approval (remote-only; see `Approve`).
    Deny {
        id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// Sign in to a gateway's remote CLI surface (browser hand-off); saves
    /// a revocable token under ~/.opsclaw/cli.toml.
    Login {
        /// The gateway to sign in to.
        #[arg(long)]
        remote: String,
    },
    /// Revoke the saved remote session (server-side) and delete it locally.
    Logout,
    /// Show which account the saved remote session belongs to.
    Whoami {
        #[arg(long)]
        json: bool,
    },
    /// Encrypted secret store management. Values NEVER pass through argv
    /// (visible in ps/shell history) — `set` reads from a hidden prompt,
    /// piped stdin, --from-env, or --from-file.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Run one diagnose cycle against a configured target NOW and print
    /// the agent's report (same code path as a scheduled scan).
    Scan {
        /// `project::env::target` path.
        target: String,
        #[arg(long)]
        json: bool,
    },
    /// What the agent WOULD have run: mutations refused by observe-mode
    /// autonomy, from the audit chain. Read this before promoting a
    /// target's autonomy.
    DryRunLog {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Open the web UI in a browser ($BROWSER or the platform default);
    /// with --tunnel, first stand up an SSH port-forward to a remote
    /// daemon and open the local end.
    Ui {
        /// SSH to `user@host[:port]` and forward the daemon's port locally
        /// before opening the browser.
        #[arg(long)]
        tunnel: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Store a secret under NAME. Value source (in order): --from-env,
    /// --from-file, piped stdin, else a hidden interactive prompt.
    Set {
        name: String,
        /// Read the value from this environment variable.
        #[arg(long)]
        from_env: Option<String>,
        /// Read the value from this file (e.g. a kubeconfig path lives in
        /// config, but a CA bundle's CONTENTS could be stored this way).
        #[arg(long)]
        from_file: Option<PathBuf>,
    },
    /// List stored secret NAMES (never values).
    List {
        #[arg(long)]
        json: bool,
    },
    /// Remove one stored secret.
    Rm { name: String },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Chaining project → env → target wizard.
    Project {
        #[command(subcommand)]
        command: ConfigProjectCommand,
    },
    /// Type-aware resource wizard: attach an elasticsearch/prometheus/
    /// argocd/service-bus/eventstore endpoint to an existing target.
    Resource {
        #[command(subcommand)]
        command: ConfigResourceCommand,
    },
    /// Validate the config and print every failure.
    Validate {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ConfigProjectCommand {
    Add,
}

#[derive(Subcommand)]
enum ConfigResourceCommand {
    Add,
}

#[derive(Subcommand)]
enum IncidentsCommand {
    List {
        #[arg(long)]
        include_closed: bool,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        remote: bool,
    },
    Show {
        id: Uuid,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        remote: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Re-walk the whole hash chain and report the first tamper/break found, if any.
    Verify {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RunbookCommand {
    /// Write a starter runbook file.
    Init { name: String },
    /// List every runbook.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show one runbook's parsed shape.
    Show {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Execute a runbook's steps against a target, through policy.
    Run {
        /// The runbook's TITLE (its `title` front-matter field, not the
        /// file name — matches `RunbookStore`'s own title-keyed identity).
        title: String,
        #[arg(long)]
        target: String,
        /// `key=value`, repeatable — overrides the runbook's `[default_vars]`.
        #[arg(long = "var", value_parser = parse_var)]
        vars: Vec<(String, String)>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum MemoryCommand {
    /// Recall facts relevant to a query.
    Recall {
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Store an explicit note.
    Store {
        text: String,
        /// Attribution label. Defaults to the same "no authenticated local
        /// account" label the local chat REPL uses — see
        /// `cli::chat_repl::LOCAL_SPEAKER`'s doc for the reasoning; kept as
        /// a literal here (not a `const` reference) because clap's
        /// `default_value` wants a string literal, not an expression.
        #[arg(long, default_value = "local operator")]
        speaker: String,
        #[arg(long)]
        json: bool,
    },
    /// Forget one fact by id, or every fact matching a query.
    Forget {
        /// An opaque memory id (no spaces), or a free-text query.
        target: String,
        #[arg(long, default_value = "operator requested via CLI")]
        reason: String,
        #[arg(long)]
        json: bool,
    },
}

fn opsclaw_home() -> PathBuf {
    opsclaw::config::default_dir()
}

fn config_path(cli_override: &Option<PathBuf>) -> PathBuf {
    cli_override.clone().unwrap_or_else(|| opsclaw_home().join("config.toml"))
}

fn sentinel_path() -> PathBuf {
    opsclaw_home().join(opsclaw::policy::estop::SENTINEL_FILE)
}

/// The daemon's own db_path resolution, mirrored here: load config (if any)
/// and use `daemon.db_path` if set, else `None` — commands that need a DB
/// then skip cleanly or report why, never guess a path the daemon wouldn't
/// actually use.
fn resolve_db_path(config_path: &std::path::Path) -> Option<String> {
    opsclaw::config::Config::load(Some(config_path))
        .ok()
        .and_then(|c| c.daemon.db_path)
        .map(|p| p.display().to_string())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let cfg_path = config_path(&cli.config);
    let home = opsclaw_home();

    if let Err(e) = dispatch(cli.command, &cfg_path, &home).await {
        eprintln!("opsclaw-cli: {e}");
        std::process::exit(1);
    }
}

async fn dispatch(
    command: Command,
    cfg_path: &std::path::Path,
    home: &std::path::Path,
) -> opsclaw::Result<()> {
    match command {
        // `opsclaw-cli daemon` IS the `opsclaw` binary: both call
        // `boot::daemon_state` — one wiring path, drift impossible (the old
        // duplicated wiring here drifted within a day of being written).
        Command::Daemon => {
            let config = Config::load(Some(cfg_path))?;
            config.validate()?;
            let state = opsclaw::boot::daemon_state(config, cfg_path.to_path_buf(), home).await?;
            opsclaw::boot::seed_scan_jobs(&state).await?;
            server::run(state).await?;
        }

        Command::Onboard {
            yes,
            openrouter_api_key_env,
            models,
            hindsight_url,
            telegram_bot_token_env,
            deadman_url,
        } => {
            let outcome = if yes {
                let opts = opsclaw::cli::onboard::NonInteractiveOptions {
                    openrouter_api_key_env,
                    models,
                    hindsight_url,
                    telegram_bot_token_env,
                    deadman_url,
                };
                opsclaw::cli::onboard::run_non_interactive(&opts, cfg_path, home).await?
            } else {
                let mut prompter = StdioPrompter::new();
                opsclaw::cli::onboard::run(&mut prompter, cfg_path, home).await?
            };
            for line in &outcome.summary {
                println!("  {line}");
            }
            println!("config written to {}", outcome.config_path);
        }

        Command::Doctor { json } => {
            let report = opsclaw::cli::doctor::run(cfg_path, home).await?;
            if json {
                opsclaw::cli::output::print_json(&report);
            } else {
                for check in &report.checks {
                    let mark = if check.ok { "OK  " } else { "FAIL" };
                    println!("[{mark}] {}: {}", check.name, check.detail);
                }
            }
            if !report.ok() {
                std::process::exit(1);
            }
        }

        Command::Estop { resume, reason, remote } if remote => {
            let session = remote_session()?;
            let engaged = if resume {
                opsclaw::cli::remote::estop::resume(&session).await?
            } else {
                opsclaw::cli::remote::estop::engage(&session, &reason).await?
            };
            println!("estop_engaged: {engaged}");
        }

        Command::Estop { resume, reason, remote: _ } => {
            let sentinel = sentinel_path();
            let db_path = resolve_db_path(cfg_path);
            let outcome = if resume {
                opsclaw::cli::estop::resume(&sentinel, db_path.as_deref()).await?
            } else {
                opsclaw::cli::estop::engage(&sentinel, &reason, db_path.as_deref()).await?
            };
            if resume {
                println!("resumed — sentinel removed at {}", outcome.sentinel_path);
            } else {
                println!("ENGAGED — sentinel written at {}", outcome.sentinel_path);
            }
        }

        Command::Config { command } => match command {
            ConfigCommand::Project { command: ConfigProjectCommand::Add } => {
                let mut prompter = StdioPrompter::new();
                let project = opsclaw::cli::config_cmd::add_project(&mut prompter, cfg_path)?;
                println!("added project {:?} to {}", project.name, cfg_path.display());
            }
            ConfigCommand::Resource { command: ConfigResourceCommand::Add } => {
                let mut prompter = StdioPrompter::new();
                let (target, resource) =
                    opsclaw::cli::config_cmd::add_resource(&mut prompter, cfg_path)?;
                println!(
                    "added {}::{} to {target} in {} (restart the daemon to pick it up)",
                    resource.rtype,
                    resource.name,
                    cfg_path.display()
                );
            }
            ConfigCommand::Validate { json } => {
                let errors = opsclaw::cli::config_cmd::validate(cfg_path)?;
                if json {
                    opsclaw::cli::output::print_json(&errors);
                } else if errors.is_empty() {
                    println!("OK — {} is valid", cfg_path.display());
                } else {
                    for e in &errors {
                        println!("FAIL: {e}");
                    }
                }
                if !errors.is_empty() {
                    std::process::exit(1);
                }
            }
        },

        Command::Incidents { command } => match command {
            IncidentsCommand::List { include_closed, limit, json, remote: true } => {
                let session = remote_session()?;
                opsclaw::cli::remote::incidents::list(&session, include_closed, limit, json)
                    .await?;
            }
            IncidentsCommand::List { include_closed, limit, json, remote: false } => {
                let db = open_db(cfg_path).await?;
                opsclaw::cli::incidents_cmd::list(&db, include_closed, limit, json).await?;
            }
            IncidentsCommand::Show { id, json, remote: true } => {
                let session = remote_session()?;
                opsclaw::cli::remote::incidents::show(&session, id, json).await?;
            }
            IncidentsCommand::Show { id, json, remote: false } => {
                let db = open_db(cfg_path).await?;
                let found = opsclaw::cli::incidents_cmd::show(&db, id, json).await?;
                if found.is_none() && !json {
                    std::process::exit(1);
                }
            }
        },

        Command::Audit { command: AuditCommand::Verify { json } } => {
            let db = open_db(cfg_path).await?;
            let outcome = opsclaw::cli::audit_cmd::verify(&db, 1).await?;
            if json {
                opsclaw::cli::output::print_json(&outcome);
            } else if outcome.ok {
                println!("OK — {} record(s) verified", outcome.records_verified);
            } else {
                println!(
                    "FAIL after {} record(s): {}",
                    outcome.records_verified,
                    outcome.failure.as_deref().unwrap_or("unknown")
                );
            }
            if !outcome.ok {
                std::process::exit(1);
            }
        }

        Command::Postmortem { id } => {
            let db = open_db(cfg_path).await?;
            match opsclaw::cli::postmortem_cmd::render(&db, id).await? {
                Some(md) => println!("{md}"),
                None => {
                    eprintln!("no incident with id {id}");
                    std::process::exit(1);
                }
            }
        }

        Command::Runbook { command } => match command {
            RunbookCommand::Init { name } => {
                let path = opsclaw::cli::runbook_cmd::init(home, &name)?;
                println!("wrote {}", path.display());
            }
            RunbookCommand::List { json } => {
                let summaries = opsclaw::cli::runbook_cmd::list(home)?;
                if json {
                    opsclaw::cli::output::print_json(&summaries);
                } else if summaries.is_empty() {
                    println!(
                        "(no runbooks in {})",
                        opsclaw::cli::runbook_cmd::runbooks_dir(home).display()
                    );
                } else {
                    for s in &summaries {
                        match s {
                            Ok(s) => println!("{}: {:?} ({} step(s))", s.file, s.title, s.steps),
                            Err(e) => println!("ERROR: {e}"),
                        }
                    }
                }
            }
            RunbookCommand::Show { name, json } => {
                let rb = opsclaw::cli::runbook_cmd::show(home, &name)?;
                if json {
                    opsclaw::cli::output::print_json(&serde_json::json!({
                        "title": rb.front_matter.title,
                        "trigger": {
                            "alert_categories": rb.front_matter.trigger.alert_categories,
                            "keywords": rb.front_matter.trigger.keywords,
                            "target_glob": rb.front_matter.trigger.target_glob,
                        },
                        "steps": rb.steps.iter().map(|s| serde_json::json!({
                            "text": s.text,
                            "command": s.command,
                            "placeholders": s.placeholders,
                            "on_fail": format!("{:?}", s.on_fail),
                        })).collect::<Vec<_>>(),
                    }));
                } else {
                    println!("# {}", rb.front_matter.title);
                    println!("trigger: {:?}", rb.front_matter.trigger);
                    for (i, step) in rb.steps.iter().enumerate() {
                        println!("{}. {}", i + 1, step.text.trim());
                        if let Some(cmd) = &step.command {
                            println!("   $ {cmd}");
                        }
                    }
                }
            }
            RunbookCommand::Run { title, target, vars, json } => {
                let config = Config::load(Some(cfg_path))?;
                config.validate()?;
                let target = opsclaw::domain::FqTarget::parse(&target)?;
                let cli_vars: std::collections::BTreeMap<String, String> =
                    vars.into_iter().collect();

                // Full daemon wiring (no HTTP bind) — a real command needs
                // the policy engine, which needs executors/e-stop/audit
                // (same reasoning as `Chat`'s local arm below).
                let state =
                    opsclaw::boot::daemon_state(config, cfg_path.to_path_buf(), home).await?;
                let store = opsclaw::runbooks::RunbookStore::load(
                    opsclaw::cli::runbook_cmd::runbooks_dir(home),
                )?;
                let runs: std::sync::Arc<dyn opsclaw::db::RunbookRunRepo> = state.repos.clone();
                let outcome = opsclaw::cli::runbook_cmd::run(
                    &store,
                    &state.policy,
                    &runs,
                    opsclaw::domain::Principal::System,
                    &title,
                    &target,
                    &cli_vars,
                )
                .await?;

                if json {
                    opsclaw::cli::output::print_json(&outcome);
                } else {
                    println!("run {} — {} ({})", outcome.run_id, outcome.runbook, outcome.target);
                    for step in &outcome.steps {
                        println!("{}. [{}] {}", step.index + 1, step.status, step.text.trim());
                        if !step.output.is_empty() {
                            for line in step.output.lines() {
                                println!("     {line}");
                            }
                        }
                    }
                    println!(
                        "{}",
                        if outcome.succeeded {
                            "OK — run succeeded"
                        } else {
                            "FAIL — run did not succeed"
                        }
                    );
                }
                if !outcome.succeeded {
                    std::process::exit(1);
                }
            }
        },

        Command::Memory { command } => match command {
            MemoryCommand::Recall { query, limit, json } => {
                let outcome = opsclaw::cli::memory_cmd::recall(cfg_path, &query, limit).await?;
                if json {
                    opsclaw::cli::output::print_json(&outcome);
                } else if !outcome.enabled {
                    println!("{}", opsclaw::cli::memory_cmd::DISABLED_MESSAGE);
                } else if outcome.records.is_empty() {
                    println!("(nothing recalled for {query:?})");
                } else {
                    for r in &outcome.records {
                        println!("• {}  [{}]", r.fact, r.id);
                    }
                }
            }
            MemoryCommand::Store { text, speaker, json } => {
                let outcome = opsclaw::cli::memory_cmd::store(cfg_path, &speaker, &text).await?;
                if json {
                    opsclaw::cli::output::print_json(&outcome);
                } else if outcome.stored {
                    println!("stored.");
                } else {
                    println!("{}", opsclaw::cli::memory_cmd::DISABLED_MESSAGE);
                }
            }
            MemoryCommand::Forget { target, reason, json } => {
                let outcome = opsclaw::cli::memory_cmd::forget(cfg_path, &target, &reason).await?;
                if json {
                    opsclaw::cli::output::print_json(&outcome);
                } else if !outcome.enabled {
                    println!("{}", opsclaw::cli::memory_cmd::DISABLED_MESSAGE);
                } else if outcome.forgotten.is_empty() {
                    println!("nothing matched {target:?} — nothing forgotten");
                } else {
                    println!(
                        "forgot {} fact(s): {}",
                        outcome.forgotten.len(),
                        outcome.forgotten.join(", ")
                    );
                }
            }
        },

        // `chat` picks local-vs-remote per invocation: `--remote` forces
        // the gateway path (erroring clearly if nothing is logged in);
        // otherwise it's always local (module doc: local is the default
        // for commands that support both, so a fresh install with no
        // `login` ever run still gets a working `chat`).
        Command::Chat { message, remote } if remote => {
            let session = remote_session()?;
            match message {
                Some(m) => {
                    opsclaw::cli::remote::chat::one_shot(&session, &m).await?;
                }
                None => opsclaw::cli::remote::chat::repl(&session).await?,
            }
        }
        Command::Chat { message, remote: _ } => match message {
            Some(m) => {
                let config = Config::load(Some(cfg_path))?;
                config.validate()?;
                let state =
                    opsclaw::boot::daemon_state(config, cfg_path.to_path_buf(), home).await?;
                let reply = state
                    .chat
                    .chat(
                        opsclaw::domain::Principal::System,
                        opsclaw::cli::chat_repl::LOCAL_SPEAKER,
                        &m,
                    )
                    .await?;
                println!("{reply}");
                state.chat.drain(std::time::Duration::from_secs(20)).await;
            }
            None => opsclaw::cli::chat_repl::run(cfg_path, home).await?,
        },

        // `status` is remote-only (see `Command::Status`'s doc).
        Command::Status { json } => {
            let session = remote_session()?;
            opsclaw::cli::remote::status::status(&session, json).await?;
        }

        Command::Approve { id, json } => {
            let session = remote_session()?;
            opsclaw::cli::remote::approvals::approve(&session, id, json).await?;
        }
        Command::Deny { id, json } => {
            let session = remote_session()?;
            opsclaw::cli::remote::approvals::deny(&session, id, json).await?;
        }

        Command::Login { remote } => {
            let mut io = opsclaw::cli::remote::auth::RealLoginIo;
            opsclaw::cli::remote::auth::login(&remote, &mut io).await?;
        }
        Command::Logout => {
            let outcome = opsclaw::cli::remote::auth::logout().await?;
            if !outcome.had_session {
                println!("no saved session.");
            } else if outcome.server_revoked {
                println!("token revoked on the server; local session deleted.");
            } else {
                println!(
                    "could not revoke on the server (already revoked, or unreachable) — local session deleted."
                );
            }
        }
        Command::Whoami { json } => {
            let session = remote_session()?;
            opsclaw::cli::remote::status::whoami(&session, json).await?;
        }

        Command::Secret { command } => match command {
            SecretCommand::Set { name, from_env, from_file } => {
                let value = read_secret_value(&name, from_env.as_deref(), from_file.as_deref())?;
                let outcome = opsclaw::cli::secret_cmd::set(home, &name, &value)?;
                println!(
                    "{} store:{n} — reference it from config as \"store:{n}\" (restart the \
                     daemon to pick up the change)",
                    if outcome.replaced { "replaced" } else { "stored" },
                    n = outcome.name,
                );
            }
            SecretCommand::List { json } => {
                let names = opsclaw::cli::secret_cmd::list(home)?;
                if json {
                    opsclaw::cli::output::print_json(&names);
                } else if names.is_empty() {
                    println!("(no stored secrets)");
                } else {
                    for n in names {
                        println!("store:{n}");
                    }
                }
            }
            SecretCommand::Rm { name } => {
                if opsclaw::cli::secret_cmd::rm(home, &name)? {
                    println!("removed store:{name}");
                } else {
                    eprintln!("no stored secret named {name:?}");
                    std::process::exit(1);
                }
            }
        },

        Command::Scan { target, json } => {
            let config = Config::load(Some(cfg_path))?;
            config.validate()?;
            // Full daemon wiring (no HTTP bind) — a scan drives the same
            // composer/policy path the scheduler does (see `Chat`'s local
            // arm for the same reasoning).
            let state = opsclaw::boot::daemon_state(config, cfg_path.to_path_buf(), home).await?;
            let outcome = opsclaw::cli::scan_cmd::run(&state, &target).await?;
            if json {
                opsclaw::cli::output::print_json(&outcome);
            } else {
                match &outcome.report {
                    Some(report) => println!("{report}"),
                    None => println!("(scan completed; the agent had nothing to report)"),
                }
            }
            state.chat.drain(std::time::Duration::from_secs(20)).await;
        }

        Command::DryRunLog { limit, json } => {
            let db = open_db(cfg_path).await?;
            let entries = opsclaw::cli::audit_cmd::dry_run_log(&db, limit).await?;
            if json {
                opsclaw::cli::output::print_json(&entries);
            } else if entries.is_empty() {
                println!("(dry-run log is empty — no autonomy-blocked commands recorded)");
            } else {
                for e in &entries {
                    println!(
                        "{}  {}  {}  [{}] {}: {}",
                        e.ts.format("%Y-%m-%d %H:%M:%S"),
                        e.principal,
                        e.target,
                        e.risk,
                        e.tool,
                        e.command
                    );
                }
            }
        }

        Command::Ui { tunnel } => {
            let outcome = opsclaw::cli::ui_cmd::run(cfg_path, tunnel.as_deref()).await?;
            println!("opened {}", outcome.url);
        }
    }
    Ok(())
}

/// Acquire a secret VALUE without it ever appearing in argv: an env var, a
/// file, piped stdin, or (interactive) a hidden prompt — in that order of
/// explicitness. Trailing newlines are trimmed (every source here appends
/// one mechanically; a real credential ending in '\n' is vanishingly rare
/// next to the certainty of `echo`/heredoc/file trailing newlines).
fn read_secret_value(
    name: &str,
    from_env: Option<&str>,
    from_file: Option<&std::path::Path>,
) -> opsclaw::Result<String> {
    use std::io::IsTerminal;
    if let Some(var) = from_env {
        return std::env::var(var).map_err(|_| {
            opsclaw::Error::Config(format!("environment variable {var} is not set"))
        });
    }
    if let Some(path) = from_file {
        let raw = std::fs::read_to_string(path)?;
        return Ok(raw.trim_end_matches(['\n', '\r']).to_string());
    }
    if std::io::stdin().is_terminal() {
        let value = rpassword::prompt_password(format!("value for store:{name} (hidden): "))
            .map_err(|e| opsclaw::Error::other(format!("could not read hidden input: {e}")))?;
        Ok(value)
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        Ok(buf.trim_end_matches(['\n', '\r']).to_string())
    }
}

/// Load the saved remote session or fail with the standard "please log in"
/// message — the one place every `--remote`-capable arm below goes through,
/// so that message (and its wording) never drifts between commands.
fn remote_session() -> opsclaw::Result<Session> {
    opsclaw::cli::remote::client::require_session()
}

async fn open_db(cfg_path: &std::path::Path) -> opsclaw::Result<opsclaw::db::Db> {
    match resolve_db_path(cfg_path) {
        Some(path) => opsclaw::db::Db::connect(&path).await,
        None => Err(opsclaw::Error::Config(
            "no daemon.db_path configured — nothing has run the daemon here yet, so there is no \
             database to read"
                .into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_subcommand_shape_parses() {
        let cases: &[&[&str]] = &[
            &["opsclaw-cli", "onboard", "--yes"],
            &["opsclaw-cli", "onboard"],
            &["opsclaw-cli", "doctor"],
            &["opsclaw-cli", "doctor", "--json"],
            &["opsclaw-cli", "daemon"],
            &["opsclaw-cli", "estop"],
            &["opsclaw-cli", "estop", "--resume"],
            &["opsclaw-cli", "estop", "--reason", "testing"],
            &["opsclaw-cli", "config", "project", "add"],
            &["opsclaw-cli", "config", "resource", "add"],
            &["opsclaw-cli", "config", "validate"],
            &["opsclaw-cli", "incidents", "list"],
            &["opsclaw-cli", "incidents", "list", "--include-closed", "--limit", "10"],
            &["opsclaw-cli", "incidents", "list", "--remote"],
            &["opsclaw-cli", "incidents", "show", "00000000-0000-0000-0000-000000000000"],
            &[
                "opsclaw-cli",
                "incidents",
                "show",
                "00000000-0000-0000-0000-000000000000",
                "--remote",
            ],
            &["opsclaw-cli", "audit", "verify"],
            &["opsclaw-cli", "postmortem", "00000000-0000-0000-0000-000000000000"],
            &["opsclaw-cli", "runbook", "init", "dlq-backlog"],
            &["opsclaw-cli", "runbook", "list"],
            &["opsclaw-cli", "runbook", "show", "dlq-backlog"],
            &["opsclaw-cli", "runbook", "run", "DLQ backlog", "--target", "p::e::t"],
            &[
                "opsclaw-cli",
                "runbook",
                "run",
                "DLQ backlog",
                "--target",
                "p::e::t",
                "--var",
                "queue=orders-dlq",
                "--var",
                "strategy=requeue",
                "--json",
            ],
            &["opsclaw-cli", "--config", "/tmp/x.toml", "doctor"],
            &["opsclaw-cli", "memory", "recall", "payments pod"],
            &["opsclaw-cli", "memory", "recall", "payments pod", "--limit", "5", "--json"],
            &["opsclaw-cli", "memory", "store", "the payments pod OOMs above 400 req/s"],
            &["opsclaw-cli", "memory", "store", "some fact", "--speaker", "dcp"],
            &["opsclaw-cli", "memory", "forget", "some-id"],
            &["opsclaw-cli", "memory", "forget", "some free text query", "--reason", "wrong"],
            &["opsclaw-cli", "chat"],
            &["opsclaw-cli", "chat", "is prod healthy?"],
            &["opsclaw-cli", "chat", "is prod healthy?", "--remote"],
            &["opsclaw-cli", "status"],
            &["opsclaw-cli", "status", "--json"],
            &["opsclaw-cli", "approve", "00000000-0000-0000-0000-000000000000"],
            &["opsclaw-cli", "deny", "00000000-0000-0000-0000-000000000000", "--json"],
            &["opsclaw-cli", "login", "--remote", "https://gw.example.com"],
            &["opsclaw-cli", "logout"],
            &["opsclaw-cli", "whoami"],
            &["opsclaw-cli", "ui"],
            &["opsclaw-cli", "ui", "--tunnel", "op@bastion.example.com"],
            &["opsclaw-cli", "secret", "set", "es-password"],
            &["opsclaw-cli", "secret", "set", "es-password", "--from-env", "ES_PASSWORD"],
            &["opsclaw-cli", "secret", "set", "ca-bundle", "--from-file", "/tmp/ca.crt"],
            &["opsclaw-cli", "secret", "list", "--json"],
            &["opsclaw-cli", "secret", "rm", "es-password"],
            &["opsclaw-cli", "scan", "remundo::sandbox::cluster"],
            &["opsclaw-cli", "scan", "remundo::sandbox::cluster", "--json"],
            &["opsclaw-cli", "dry-run-log"],
            &["opsclaw-cli", "dry-run-log", "--limit", "10", "--json"],
            &["opsclaw-cli", "estop", "--remote"],
            &["opsclaw-cli", "estop", "--resume", "--remote"],
        ];
        for argv in cases {
            let result = Cli::try_parse_from(*argv);
            assert!(result.is_ok(), "failed to parse {argv:?}: {:?}", result.err());
        }
    }

    #[test]
    fn postmortem_requires_a_uuid_argument() {
        assert!(Cli::try_parse_from(["opsclaw-cli", "postmortem"]).is_err());
        assert!(Cli::try_parse_from(["opsclaw-cli", "postmortem", "not-a-uuid"]).is_err());
    }

    #[test]
    fn runbook_run_requires_a_target() {
        assert!(Cli::try_parse_from(["opsclaw-cli", "runbook", "run", "some-title"]).is_err());
    }

    #[test]
    fn runbook_run_rejects_a_malformed_var() {
        let result = Cli::try_parse_from([
            "opsclaw-cli",
            "runbook",
            "run",
            "t",
            "--target",
            "p::e::t",
            "--var",
            "no-equals-sign",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn approve_and_deny_require_a_uuid() {
        assert!(Cli::try_parse_from(["opsclaw-cli", "approve"]).is_err());
        assert!(Cli::try_parse_from(["opsclaw-cli", "approve", "not-a-uuid"]).is_err());
        assert!(Cli::try_parse_from(["opsclaw-cli", "deny", "not-a-uuid"]).is_err());
    }

    #[test]
    fn login_requires_remote() {
        assert!(Cli::try_parse_from(["opsclaw-cli", "login"]).is_err());
    }

    #[test]
    fn parse_var_splits_on_first_equals() {
        assert_eq!(
            parse_var("queue=orders-dlq").unwrap(),
            ("queue".to_string(), "orders-dlq".to_string())
        );
        // A value containing '=' stays whole (split_once, not split).
        assert_eq!(parse_var("k=a=b").unwrap(), ("k".to_string(), "a=b".to_string()));
        assert!(parse_var("no-equals").is_err());
    }
}
