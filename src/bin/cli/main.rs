//! `opsclaw-cli` — operator/developer CLI. Links the library crate and
//! drives the same orchestrator path as every channel (gianna pattern).
//! **Local mode only** — every command here either has no daemon
//! counterpart (onboard, config wizards) or opens the same SQLite file the
//! daemon would (doctor, estop, incidents, audit, postmortem, runbook).
//! Remote mode (talking to a live daemon's gateway over the token-auth API)
//! is a later wave; this binary never opens an HTTP client to a daemon.
//!
//! Argument parsing lives here (clap types); all actual logic is in
//! `opsclaw::cli::*`, kept free of clap so it's callable from tests without
//! going through argv (see `src/cli/mod.rs`'s doc comment).

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use opsclaw::audit::AuditWriter;
use opsclaw::cli::prompt::StdioPrompter;
use opsclaw::config::{Config, SecretStore};
use opsclaw::db::Db;
use opsclaw::http::{AppState, server};
use opsclaw::policy::{EStop, Policy, Scrubber};
use opsclaw::scheduler::SchedulerHandle;
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
    /// Freeze all agent action across all targets instantly.
    Estop {
        /// Resume normal operation.
        #[arg(long)]
        resume: bool,
        #[arg(long, default_value = "operator requested via CLI")]
        reason: String,
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
    /// Runbook authoring.
    Runbook {
        #[command(subcommand)]
        command: RunbookCommand,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Chaining project → env → target wizard.
    Project {
        #[command(subcommand)]
        command: ConfigProjectCommand,
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
enum IncidentsCommand {
    List {
        #[arg(long)]
        include_closed: bool,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long)]
        json: bool,
    },
    Show {
        id: Uuid,
        #[arg(long)]
        json: bool,
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
        // `opsclaw-cli daemon` is identical to the `opsclaw` binary
        // (src/main.rs) — same wiring, duplicated here rather than shared
        // because src/main.rs is a `fn main` returning `()`, not `Result`,
        // and isn't itself a library entry point to call into. Keep this in
        // sync with src/main.rs if that wiring changes; it is NOT
        // reimplemented independently (no separate executor-registration
        // logic, no separate policy construction) — every piece here is the
        // same library call src/main.rs makes, in the same order.
        Command::Daemon => {
            let config = Config::load(None)?;
            config.validate()?;

            let secret_store = SecretStore::open(home)?;

            let db_path = config
                .daemon
                .db_path
                .clone()
                .unwrap_or_else(|| home.join("opsclaw.sqlite3"))
                .to_string_lossy()
                .into_owned();
            let db = Db::connect(&db_path).await?;
            let repos = db.repos();

            // Same fail-closed placeholder as src/main.rs: an empty executor
            // map means Policy::execute treats every target as unreachable
            // (no executor => no command can run) until target wiring from
            // config lands — not something to invent independently here.
            let executors = std::collections::HashMap::new();

            let estop_handle =
                Arc::new(EStop::new(home.join(opsclaw::policy::estop::SENTINEL_FILE), repos.clone()));
            let audit = Arc::new(AuditWriter::new(repos.clone()));
            let scrubber = Arc::new(Scrubber::new());
            let policy = Arc::new(Policy::new(
                Arc::new(config.clone()),
                executors,
                audit,
                estop_handle.clone(),
                repos.clone(),
                scrubber,
            ));

            let scheduler_handle = SchedulerHandle::new(config.daemon.tick_seconds.max(1) * 1000);

            let state = AppState::new(
                config,
                &secret_store,
                repos,
                policy.clone(),
                policy,
                estop_handle,
                scheduler_handle,
            )?;

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

        Command::Estop { resume, reason } => {
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
            IncidentsCommand::List { include_closed, limit, json } => {
                let db = open_db(cfg_path).await?;
                opsclaw::cli::incidents_cmd::list(&db, include_closed, limit, json).await?;
            }
            IncidentsCommand::Show { id, json } => {
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
        },
    }
    Ok(())
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
            &["opsclaw-cli", "config", "validate"],
            &["opsclaw-cli", "incidents", "list"],
            &["opsclaw-cli", "incidents", "list", "--include-closed", "--limit", "10"],
            &["opsclaw-cli", "incidents", "show", "00000000-0000-0000-0000-000000000000"],
            &["opsclaw-cli", "audit", "verify"],
            &["opsclaw-cli", "postmortem", "00000000-0000-0000-0000-000000000000"],
            &["opsclaw-cli", "runbook", "init", "dlq-backlog"],
            &["opsclaw-cli", "runbook", "list"],
            &["opsclaw-cli", "runbook", "show", "dlq-backlog"],
            &["opsclaw-cli", "--config", "/tmp/x.toml", "doctor"],
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
}
