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

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{ArgValueCandidates, CompletionCandidate};
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

fn completion_config_path() -> PathBuf {
    let args: Vec<_> = std::env::args_os().collect();
    args.windows(2)
        .find(|pair| pair[0] == "--config")
        .map(|pair| PathBuf::from(&pair[1]))
        .unwrap_or_else(|| opsclaw_home().join("config.toml"))
}

fn configured_paths(targets_only: bool) -> Vec<CompletionCandidate> {
    let Ok(config) = Config::load(Some(&completion_config_path())) else {
        return Vec::new();
    };
    path_candidates_for(&config, targets_only)
}

fn path_candidates_for(config: &Config, targets_only: bool) -> Vec<CompletionCandidate> {
    let mut paths = Vec::new();
    for project in &config.projects {
        if !targets_only {
            paths.push(project.name.clone());
        }
        for environment in &project.envs {
            let env_path = format!("{}::{}", project.name, environment.name);
            if !targets_only {
                paths.push(env_path.clone());
            }
            paths.extend(
                environment.targets.iter().map(|target| format!("{env_path}::{}", target.name)),
            );
        }
    }
    paths.sort();
    paths.into_iter().map(CompletionCandidate::new).collect()
}

fn target_candidates() -> Vec<CompletionCandidate> {
    configured_paths(true)
}

fn config_path_candidates() -> Vec<CompletionCandidate> {
    configured_paths(false)
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

/// Parse `onboard --auth-provider`. A `value_parser` (like [`parse_var`])
/// rather than a string field the wizard interprets later: a typo must be
/// refused at argv-parse time, because "loclal" silently becoming `local`
/// would leave a scripted install accepting passwords the operator meant to
/// turn off.
fn parse_auth_provider(s: &str) -> Result<opsclaw::config::AuthProvider, String> {
    match s {
        "local" => Ok(opsclaw::config::AuthProvider::Local),
        "hanko" => Ok(opsclaw::config::AuthProvider::Hanko),
        other => Err(format!("expected \"local\" or \"hanko\", got {other:?}")),
    }
}

#[derive(Subcommand)]
enum Command {
    /// [local] First-run wizard: provider key, channels, memory, gateway.
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
        /// Which identity provider fronts sign-in: `local` (this daemon's
        /// own password) or `hanko`. Unset leaves the existing config alone.
        #[arg(long, value_parser = parse_auth_provider)]
        auth_provider: Option<opsclaw::config::AuthProvider>,
        /// Hanko API base URL — required with `--auth-provider hanko`.
        #[arg(long)]
        hanko_api_url: Option<String>,
        /// Comma-separated `aud` values a Hanko session token must carry —
        /// required with `--auth-provider hanko`.
        #[arg(long, value_delimiter = ',')]
        hanko_audience: Vec<String>,
    },
    /// [local] Config + dependency health check.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// [local] Run the daemon (identical to the `opsclaw` binary).
    Daemon,
    /// [local|remote] Freeze all agent action across all targets instantly. LOCAL by
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
    /// [local] Config management: project/env/target wizards, validation.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// [local|remote] List, acknowledge, and resolve incidents.
    Incidents {
        #[command(subcommand)]
        command: IncidentsCommand,
    },
    /// [local] Audit chain inspection.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// [local] Render a structured postmortem for an incident.
    Postmortem { id: Uuid },
    /// [local] Runbook authoring + execution.
    #[command(name = "runbooks", alias = "runbook")]
    Runbook {
        #[command(subcommand)]
        command: RunbookCommand,
    },
    /// [local] Team memory: recall/add/remove (honest no-op when
    /// memory.hindsight_url isn't configured).
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    /// [local|remote] Talk to the agent or read chat history. LOCAL by
    /// default (drives the daemon's own library wiring, no HTTP); `--remote`
    /// forces the saved gateway session instead — see module doc.
    Chat {
        /// Send once and print the reply, instead of an interactive REPL.
        message: Option<String>,
        #[arg(long)]
        remote: bool,
        /// Read the durable shared transcript instead of starting a turn.
        #[arg(long)]
        history: bool,
        #[arg(long)]
        before: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: i64,
        #[arg(long)]
        json: bool,
        /// Shared room: `operations` or `project::environment`.
        #[arg(long, default_value = "operations")]
        conversation: String,
    },
    /// [remote] Daemon status. LOCAL mode has no analogue for this (there is no
    /// running-daemon introspection without a daemon to ask) — this
    /// command is REMOTE-ONLY, over the saved gateway session.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// [local|remote] Show today's OpsClaw + Hindsight LLM spend and cap headroom.
    Usage {
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        json: bool,
    },
    /// [local] The approval queue: list what is waiting, see the exact command, and
    /// decide. LOCAL by default, so it works with no gateway session.
    Approvals {
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    /// [remote] Approve a pending approval. Kept as a top-level alias for
    /// `approvals approve`; REMOTE-only, over the saved gateway session.
    Approve {
        id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// [remote] Deny a pending approval. Alias for `approvals deny`.
    Deny {
        id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// [remote] Sign in to a gateway's CLI surface (browser hand-off); saves
    /// a revocable token under ~/.opsclaw/cli.toml.
    Login {
        /// The gateway to sign in to.
        #[arg(long)]
        remote: String,
    },
    /// [remote] Revoke the saved session server-side and delete it locally.
    Logout,
    /// [remote] Show which account the saved remote session belongs to.
    Whoami {
        #[arg(long)]
        json: bool,
    },
    /// [local] Operator accounts: `add` bootstraps the FIRST web-UI login
    /// (local, direct to the daemon's DB); later teammates join via the
    /// web invite flow.
    #[command(name = "accounts", alias = "account")]
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// [local] `ops_` CLI sessions: list them, revoke one. These never expire, so
    /// revoking is what actually ends someone's CLI access.
    Tokens {
        #[command(subcommand)]
        command: TokensCommand,
    },
    /// [local] Encrypted secret store management. Values NEVER pass through argv
    /// (visible in ps/shell history) — `set` reads from a hidden prompt,
    /// piped stdin, --from-env, or --from-file.
    #[command(name = "secrets", alias = "secret")]
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// [local] Run one diagnose cycle against a configured target NOW and print
    /// the agent's report (same code path as a scheduled scan).
    Scan {
        /// `project::env::target` path.
        #[arg(add = ArgValueCandidates::new(target_candidates))]
        target: String,
        #[arg(long)]
        json: bool,
    },
    /// [local] What the agent WOULD have run: mutations refused by observe-mode
    /// autonomy, from the audit chain. Read this before promoting a
    /// target's autonomy.
    #[command(name = "blocked-actions", alias = "dry-run-log")]
    DryRunLog {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// [local] Inspect and edit the scheduler's job table. Editing a seeded scan
    /// job's prompt converts it to operator-owned free text (kept forever;
    /// re-seeding skips it) — unedited seeded jobs keep resolving their
    /// prompt from code and improve with every release.
    Jobs {
        #[command(subcommand)]
        command: JobsCommand,
    },
    /// [local|remote] Create, list, and revoke teammate invites.
    Invites {
        #[command(subcommand)]
        command: InvitesCommand,
    },
    /// [local] Generate shell completion definitions to stdout.
    Completions { shell: clap_complete::Shell },
    /// [local] Open the web UI in a browser ($BROWSER or the platform default);
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
enum AccountCommand {
    /// Create an operator account (password via hidden prompt or piped
    /// stdin — never argv). Under `auth.provider = "hanko"`, pass
    /// `--hanko-subject` instead: no password is prompted or stored.
    #[command(name = "add", alias = "create")]
    Create {
        email: String,
        #[arg(long)]
        name: Option<String>,
        /// The operator's Hanko user id (`claims.subject`, shown in the
        /// Hanko console). Required under the hanko provider.
        #[arg(long)]
        hanko_subject: Option<String>,
    },
    /// List operator accounts.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Link an existing operator account to a Hanko user id, dropping its
    /// password. Run this for every operator BEFORE switching
    /// `auth.provider` to hanko, or the switch locks them all out.
    Link {
        email: String,
        #[arg(long)]
        hanko_subject: String,
        /// Also clear the account's password. Off by default: linking runs
        /// while the daemon is still on `local`, where the hanko route
        /// refuses everything, so dropping the password here would leave
        /// the operator unable to sign in by either method until the flip.
        #[arg(long)]
        drop_password: bool,
    },
    /// Set an operator's password (hidden prompt or piped stdin, never
    /// argv). The way back off an external provider, and the recovery path
    /// for an account linked with --drop-password.
    SetPassword { email: String },
    /// Revoke every outstanding session for an operator: all web session
    /// cookies and all `ops_` CLI tokens. Use when offboarding — removing
    /// someone at the identity provider does not reach this daemon.
    RevokeSessions {
        email: String,
        /// Skip the confirmation (needed where there is no terminal).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum JobsCommand {
    /// List every scheduled job with its cadence and payload kind.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Edit a job by NAME. --prompt converts a seeded scan job to free
    /// text; --every-minutes changes the cadence (next run recomputed from
    /// now); --enabled true|false pauses/resumes it.
    Edit {
        name: String,
        #[arg(long)]
        prompt: Option<String>,
        #[arg(long)]
        every_minutes: Option<i64>,
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Permanently delete a job by name, including its failure history.
    #[command(name = "remove", alias = "delete")]
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum TokensCommand {
    /// List CLI sessions — all operators', or one with --as.
    List {
        /// Only this operator's tokens.
        #[arg(long = "as")]
        as_email: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Revoke one CLI token by id.
    Revoke {
        id: Uuid,
        /// The token's owner.
        #[arg(long = "as")]
        as_email: String,
        /// Skip the confirmation (needed where there is no terminal).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Store a secret under NAME. Value source (in order): --from-env,
    /// --from-file, piped stdin, else a hidden interactive prompt.
    #[command(name = "add", alias = "set")]
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
    /// Remove one stored secret. Unrecoverable — the store holds the only
    /// copy — so it asks first.
    #[command(name = "remove", aliases = ["rm", "delete"])]
    Rm {
        name: String,
        /// Skip the confirmation (needed where there is no terminal).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Chaining project → env → target wizard.
    #[command(name = "projects", alias = "project")]
    Project {
        #[command(subcommand)]
        command: ConfigProjectCommand,
    },
    /// Type-aware resource wizard: attach an elasticsearch/prometheus/
    /// argocd/service-bus/eventstore endpoint to an existing target.
    #[command(name = "resources", alias = "resource")]
    Resource {
        #[command(subcommand)]
        command: ConfigResourceCommand,
    },
    /// Validate the config and print every failure.
    Validate {
        #[arg(long)]
        json: bool,
    },
    /// Every project, environment and target, with autonomy and expected
    /// state RESOLVED through the inheritance chain — the effective values
    /// the daemon uses, which `show` would make you work out from the TOML.
    List {
        /// Limit to these subtrees: `project`, `project::env`, or
        /// `project::env::target`. Repeatable, and they union — e.g.
        /// `config list example::dev example::prod`. Omit for everything.
        #[arg(add = ArgValueCandidates::new(config_path_candidates))]
        paths: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print config.toml exactly as it is on disk. Safe to pipe or paste:
    /// config holds secret REFERENCES (env:VAR / store:KEY), never values.
    Show,
    /// Replace config.toml from stdin or --file, after checking the daemon
    /// would still boot on it. A refused config is never written.
    Apply {
        /// Read from this file instead of stdin.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Open $EDITOR on the config, then apply it. There is no editor in the
    /// standard container image — use `show`/`apply` there.
    Edit,
    /// Remove a project, environment, or target by its
    /// `project[::env[::target]]` path. Prints the whole subtree it would
    /// delete and asks first.
    #[command(name = "remove", aliases = ["rm", "delete"])]
    Rm {
        #[arg(add = ArgValueCandidates::new(config_path_candidates))]
        path: String,
        /// Skip the confirmation. Required where there is no terminal to ask
        /// on, e.g. under `docker compose exec -T`.
        #[arg(long)]
        yes: bool,
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
enum ApprovalsCommand {
    /// Every request awaiting a decision, with the verbatim command each
    /// one would run.
    List {
        #[arg(long)]
        json: bool,
    },
    /// One request by id, pending or already decided.
    Show {
        id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// Approve a request and RUN its stored command, verbatim.
    Approve {
        id: Uuid,
        /// Which operator the decision is recorded as. Inferred when the
        /// deployment has exactly one operator account.
        #[arg(long = "as")]
        as_email: Option<String>,
        /// Skip the confirmation (needed where there is no terminal).
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Deny a request. The command never runs.
    Deny {
        id: Uuid,
        #[arg(long = "as")]
        as_email: Option<String>,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
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
    Ack {
        id: Uuid,
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        json: bool,
    },
    Resolve {
        id: Uuid,
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum InvitesCommand {
    List {
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        json: bool,
    },
    Add {
        #[arg(long = "as")]
        as_email: Option<String>,
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        json: bool,
    },
    Remove {
        code: String,
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Read the chain: what the agent actually did. Defaults to the most
    /// recent records, since "what just happened?" is the usual question.
    List {
        /// Start at this sequence number instead of the tail.
        #[arg(long)]
        from: Option<i64>,
        #[arg(long, default_value = "20")]
        limit: i64,
        #[arg(long)]
        json: bool,
    },
    /// One record by its sequence number.
    Show {
        seq: i64,
        #[arg(long)]
        json: bool,
    },
    /// Re-walk the whole hash chain and report the first tamper/break found, if any.
    Verify {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RunbookCommand {
    /// Write a starter runbook file.
    #[command(name = "add", alias = "init")]
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
        #[arg(long, add = ArgValueCandidates::new(target_candidates))]
        target: String,
        /// `key=value`, repeatable — overrides the runbook's `[default_vars]`.
        #[arg(long = "var", value_parser = parse_var)]
        vars: Vec<(String, String)>,
        #[arg(long)]
        json: bool,
        /// Render every command without executing or recording the run.
        #[arg(long)]
        dry_run: bool,
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
    #[command(name = "add", alias = "store")]
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
    /// Forget one fact by id, or every fact matching a query. A query can
    /// match many facts, so it prints them and asks before forgetting.
    #[command(name = "remove", aliases = ["forget", "delete"])]
    Forget {
        /// An opaque memory id (no spaces), or a free-text query.
        target: String,
        #[arg(long, default_value = "operator requested via CLI")]
        reason: String,
        /// Skip the confirmation (needed where there is no terminal).
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Dump the team's memory bank to stdout — markdown by default (one
    /// section per fact with timestamp/context), --json for the machine
    /// form. A complete enumeration of every stored fact (raw and
    /// consolidated layers) up to --limit, via the backend's list endpoint —
    /// this is also the ARCHIVAL path: the backend has no delete-by-age
    /// API, so archiving old facts means exporting here and forgetting
    /// per-fact.
    Export {
        /// Max facts to dump; the output says so loudly if the bank holds
        /// more.
        #[arg(long, default_value_t = 10_000)]
        limit: usize,
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

/// The daemon's own db_path resolution, mirrored here — INCLUDING the
/// fallback: `boot::daemon_state` defaults to `$OPSCLAW_HOME/opsclaw.sqlite3`
/// when `daemon.db_path` is unset, and onboarded deployments never set it
/// explicitly, so a CLI that required the key couldn't read ANY default
/// deployment's DB (found live: `jobs`/`incidents`/`audit` all refused
/// "no daemon.db_path configured" against a running daemon). `None` only
/// when the config file itself is absent/unreadable — then nothing has run
/// here and there is genuinely no DB to guess at.
fn resolve_db_path(config_path: &std::path::Path) -> Option<String> {
    opsclaw::config::Config::load(Some(config_path))
        .ok()
        .map(|c| c.daemon.db_path.unwrap_or_else(|| opsclaw_home().join("opsclaw.sqlite3")))
        .map(|p| p.display().to_string())
}

#[tokio::main]
async fn main() {
    clap_complete::CompleteEnv::with_factory(Cli::command).complete();
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
            // The log sink is part of that sameness: without a subscriber
            // every tracing event is dropped — a silently mute daemon — and
            // DoD #4's scrubbed sink doesn't exist on this path. Installed
            // only for `daemon`: operator commands print human output, not
            // a tracing stream.
            opsclaw::logging::init_daemon();
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
            auth_provider,
            hanko_api_url,
            hanko_audience,
        } => {
            // Built for BOTH paths: under `--yes` these are the answers, and
            // interactively they are the prompt defaults. Previously only the
            // `--yes` branch saw them, so `--hindsight-url` (which the
            // compose file's own documented onboarding command passes) was
            // accepted by clap and then silently ignored.
            let opts = opsclaw::cli::onboard::NonInteractiveOptions {
                openrouter_api_key_env,
                models,
                hindsight_url,
                telegram_bot_token_env,
                deadman_url,
                auth_provider,
                hanko_api_url,
                hanko_audience,
            };
            if yes {
                let outcome =
                    opsclaw::cli::onboard::run_non_interactive(&opts, cfg_path, home).await?;
                for line in &outcome.summary {
                    println!("  {line}");
                }
                // Advisory, and deliberately after the write: a model this
                // catalogue does not list may simply be newer than the
                // catalogue, so it must not block a scripted install.
                if let Some(warning) =
                    opsclaw::cli::onboard::unknown_model_warning(&opts.models).await
                {
                    println!("  {warning}");
                }
                println!("config written to {}", outcome.config_path);
            } else {
                // The interactive wizard narrates its own summary (and the
                // chained follow-on stages) through the prompter — printing
                // the outcome again here would just repeat it.
                let mut prompter = StdioPrompter::new();
                opsclaw::cli::onboard::run(&mut prompter, &opts, cfg_path, home).await?;
            }
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
                let store = opsclaw::config::SecretStore::open(home)?;
                let project =
                    opsclaw::cli::config_cmd::add_project(&mut prompter, cfg_path, &store)?;
                println!("added project {:?} to {}", project.name, cfg_path.display());
                println!("next: `opsclaw-cli doctor` to verify, then `opsclaw-cli daemon`.");
            }
            ConfigCommand::Resource { command: ConfigResourceCommand::Add } => {
                let mut prompter = StdioPrompter::new();
                let store = opsclaw::config::SecretStore::open(home)?;
                let (target, resource) =
                    opsclaw::cli::config_cmd::add_resource(&mut prompter, cfg_path, &store)?;
                println!(
                    "added {}::{} to {target} in {}",
                    resource.rtype(),
                    resource.name(),
                    cfg_path.display()
                );
                println!("{}", opsclaw::cli::config_edit::restart_hint());
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
            ConfigCommand::List { paths, json } => {
                let projects = opsclaw::cli::config_list::list(cfg_path, &paths)?;
                if json {
                    opsclaw::cli::output::print_json(&projects);
                } else {
                    print!("{}", opsclaw::cli::config_list::render(&projects));
                }
            }
            ConfigCommand::Show => {
                // print! not println!: the file's own trailing newline is
                // part of it, and `show > f && apply < f` must round-trip
                // byte-for-byte.
                print!("{}", opsclaw::cli::config_edit::show(cfg_path)?);
            }
            ConfigCommand::Apply { file } => {
                let body = match &file {
                    Some(path) => std::fs::read_to_string(path)?,
                    None => {
                        use std::io::Read;
                        let mut buf = String::new();
                        std::io::stdin().read_to_string(&mut buf)?;
                        buf
                    }
                };
                opsclaw::cli::config_edit::apply(cfg_path, &body)?;
                println!("{} written", cfg_path.display());
                println!("{}", opsclaw::cli::config_edit::restart_hint());
            }
            ConfigCommand::Edit => match opsclaw::cli::config_edit::edit(cfg_path)? {
                opsclaw::cli::config_edit::EditOutcome::Applied => {
                    println!("{} written", cfg_path.display());
                    println!("{}", opsclaw::cli::config_edit::restart_hint());
                }
                opsclaw::cli::config_edit::EditOutcome::Unchanged => {
                    println!("no changes — {} left alone", cfg_path.display());
                }
            },
            ConfigCommand::Rm { path, yes } => {
                let preview = opsclaw::cli::config_edit::describe_removal(cfg_path, &path)?;
                opsclaw::cli::confirm::destructive(&preview, yes)?;
                let removed = opsclaw::cli::config_edit::remove(cfg_path, &path)?;
                println!("removed {removed} from {}", cfg_path.display());
                println!(
                    "note: a structural edit is re-serialized, so comments in config.toml were \
                     not preserved (the previous file is at {}.bak)",
                    cfg_path.display()
                );
                println!("{}", opsclaw::cli::config_edit::restart_hint());
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
            IncidentsCommand::Ack { id, remote: true, json } => {
                let body =
                    opsclaw::cli::remote::incidents::transition(&remote_session()?, id, "ack")
                        .await?;
                if json {
                    opsclaw::cli::output::print_json(&body);
                } else {
                    println!("incident {id}: {}", body["state"].as_str().unwrap_or("acknowledged"));
                }
            }
            IncidentsCommand::Resolve { id, remote: true, json } => {
                let body =
                    opsclaw::cli::remote::incidents::transition(&remote_session()?, id, "resolve")
                        .await?;
                if json {
                    opsclaw::cli::output::print_json(&body);
                } else {
                    println!("incident {id}: {}", body["state"].as_str().unwrap_or("resolved"));
                }
            }
            IncidentsCommand::Ack { id, remote: false, json } => {
                let db = open_db(cfg_path).await?;
                let incident = opsclaw::cli::incidents_cmd::transition(
                    &db,
                    id,
                    opsclaw::domain::IncidentState::Acknowledged,
                )
                .await?;
                if json {
                    opsclaw::cli::output::print_json(&incident);
                } else {
                    println!("incident {id}: {:?}", incident.state);
                }
            }
            IncidentsCommand::Resolve { id, remote: false, json } => {
                let db = open_db(cfg_path).await?;
                let incident = opsclaw::cli::incidents_cmd::transition(
                    &db,
                    id,
                    opsclaw::domain::IncidentState::Resolved,
                )
                .await?;
                if json {
                    opsclaw::cli::output::print_json(&incident);
                } else {
                    println!("incident {id}: {:?}", incident.state);
                }
            }
        },

        Command::Audit { command } => match command {
            AuditCommand::List { from, limit, json } => {
                let db = open_db(cfg_path).await?;
                let views = match from {
                    Some(seq) => opsclaw::cli::audit_cmd::list(&db, seq, limit).await?,
                    None => opsclaw::cli::audit_cmd::tail(&db, limit).await?,
                };
                if json {
                    opsclaw::cli::output::print_json(&views);
                } else {
                    print!("{}", opsclaw::cli::audit_cmd::render(&views));
                }
            }
            AuditCommand::Show { seq, json } => {
                let db = open_db(cfg_path).await?;
                let view = opsclaw::cli::audit_cmd::show(&db, seq).await?;
                if json {
                    opsclaw::cli::output::print_json(&view);
                } else {
                    print!("{}", opsclaw::cli::audit_cmd::render(std::slice::from_ref(&view)));
                }
            }
            AuditCommand::Verify { json } => {
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
        },

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
                // The success-rate join is best-effort (brief §7: "low
                // scorers surfaced for review"): a host that has never run
                // the daemon has no DB, and `runbook list` must keep
                // working there — an unopenable DB just means no rate
                // notes, not a failed listing.
                let summaries = match open_db(cfg_path).await {
                    Ok(db) => {
                        let runs: std::sync::Arc<dyn opsclaw::db::RunbookRunRepo> = db.repos();
                        opsclaw::cli::runbook_cmd::list_with_history(home, &runs).await?
                    }
                    Err(_) => opsclaw::cli::runbook_cmd::list(home)?,
                };
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
                            Ok(s) => {
                                let marker = s
                                    .success
                                    .as_ref()
                                    .and_then(|x| {
                                        opsclaw::runbooks::low_success_marker(x.total_runs, x.rate)
                                    })
                                    .map(|m| format!(" {m}"))
                                    .unwrap_or_default();
                                println!("{}: {:?} ({} step(s)){marker}", s.file, s.title, s.steps);
                            }
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
            RunbookCommand::Run { title, target, vars, json, dry_run } => {
                let config = Config::load(Some(cfg_path))?;
                config.validate()?;
                let target = opsclaw::domain::FqTarget::parse(&target)?;
                let cli_vars: std::collections::BTreeMap<String, String> =
                    vars.into_iter().collect();

                let store = opsclaw::runbooks::RunbookStore::load(
                    opsclaw::cli::runbook_cmd::runbooks_dir(home),
                )?;
                let (outcome, state) = if dry_run {
                    (opsclaw::cli::runbook_cmd::dry_run(&store, &title, &target, &cli_vars)?, None)
                } else {
                    // Full daemon wiring (no HTTP bind) — a real command
                    // needs policy/executors/e-stop/audit.
                    let state =
                        opsclaw::boot::daemon_state(config, cfg_path.to_path_buf(), home).await?;
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
                    (outcome, Some(state))
                };

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
                if let Some(state) = state {
                    state.chat.drain(std::time::Duration::from_secs(20)).await;
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
            MemoryCommand::Forget { target, reason, yes, json } => {
                let preview = opsclaw::cli::memory_cmd::describe_forget(cfg_path, &target).await?;
                opsclaw::cli::confirm::destructive(&preview, yes)?;
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
            MemoryCommand::Export { limit, json } => {
                let outcome = opsclaw::cli::memory_cmd::export(cfg_path, limit).await?;
                if json {
                    opsclaw::cli::output::print_json(&outcome);
                } else if !outcome.enabled {
                    println!("{}", opsclaw::cli::memory_cmd::DISABLED_MESSAGE);
                } else {
                    // The render is timestamped at the moment of export (an
                    // archive without a date is half an archive) and TESTED
                    // in `cli::memory_cmd` — this arm only prints it.
                    let exported_at =
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    print!(
                        "{}",
                        opsclaw::cli::memory_cmd::render_export_markdown(&outcome, &exported_at)
                    );
                }
            }
        },

        // `chat` picks local-vs-remote per invocation: `--remote` forces
        // the gateway path (erroring clearly if nothing is logged in);
        // otherwise it's always local (module doc: local is the default
        // for commands that support both, so a fresh install with no
        // `login` ever run still gets a working `chat`).
        Command::Chat {
            message,
            remote: true,
            history: true,
            before,
            limit,
            json,
            conversation,
        } => {
            if message.is_some() {
                return Err(opsclaw::Error::validation(
                    "--history cannot be combined with a chat message",
                ));
            }
            let body = opsclaw::cli::remote::history::load_scoped(
                &remote_session()?,
                &conversation,
                before,
                limit,
            )
            .await?;
            if json {
                opsclaw::cli::output::print_json(&body);
            } else {
                render_remote_history(&body);
            }
        }
        Command::Chat {
            message,
            remote: false,
            history: true,
            before,
            limit,
            json,
            conversation,
        } => {
            if message.is_some() {
                return Err(opsclaw::Error::validation(
                    "--history cannot be combined with a chat message",
                ));
            }
            let rows = opsclaw::cli::chat_history_cmd::load_scoped(
                &open_db(cfg_path).await?,
                &conversation,
                before,
                limit,
            )
            .await?;
            if json {
                opsclaw::cli::output::print_json(&rows);
            } else {
                for row in rows {
                    println!("{}  {}  {}: {}", row.seq, row.at, row.speaker, row.content);
                }
            }
        }
        Command::Chat { message, remote: true, history: false, conversation, .. } => {
            let session = remote_session()?;
            match message {
                Some(m) => {
                    opsclaw::cli::remote::chat::one_shot_scoped(&session, &conversation, &m)
                        .await?;
                }
                None => opsclaw::cli::remote::chat::repl_scoped(&session, &conversation).await?,
            }
        }
        Command::Chat { message, remote: false, history: false, conversation, .. } => match message
        {
            Some(m) => {
                let config = Config::load(Some(cfg_path))?;
                config.validate()?;
                let state =
                    opsclaw::boot::daemon_state(config, cfg_path.to_path_buf(), home).await?;
                let conversation = opsclaw::domain::ChatConversation::parse(&conversation)?;
                let reply = state
                    .chat
                    .chat_scoped(
                        &conversation,
                        &Uuid::new_v4().to_string(),
                        opsclaw::domain::Principal::System,
                        opsclaw::cli::chat_repl::LOCAL_SPEAKER,
                        &m,
                    )
                    .await?;
                println!("{reply}");
                state.chat.drain(std::time::Duration::from_secs(20)).await;
            }
            None => opsclaw::cli::chat_repl::run_scoped(cfg_path, home, &conversation).await?,
        },

        // `status` is remote-only (see `Command::Status`'s doc).
        Command::Status { json } => {
            let session = remote_session()?;
            opsclaw::cli::remote::status::status(&session, json).await?;
        }

        Command::Usage { remote: true, json } => {
            let body = opsclaw::cli::remote::status::get(&remote_session()?).await?;
            let spend = &body["spend"];
            if json {
                opsclaw::cli::output::print_json(spend);
            } else {
                render_remote_spend(spend);
            }
        }
        Command::Usage { remote: false, json } => {
            let config = Config::load(Some(cfg_path))?;
            let db = open_db(cfg_path).await?;
            let store = opsclaw::config::SecretStore::open(home)?;
            let snapshot = opsclaw::cli::usage_cmd::load(&config, &store, db.repos()).await?;
            if json {
                opsclaw::cli::output::print_json(&snapshot);
            } else {
                print!("{}", opsclaw::cli::usage_cmd::render(&snapshot));
            }
        }

        Command::Approvals { command } => match command {
            ApprovalsCommand::List { json } => {
                let db = open_db(cfg_path).await?;
                let views = opsclaw::cli::approvals_cmd::list(&db.repos()).await?;
                if json {
                    opsclaw::cli::output::print_json(&views);
                } else {
                    print!("{}", opsclaw::cli::approvals_cmd::render(&views));
                }
            }
            ApprovalsCommand::Show { id, json } => {
                let db = open_db(cfg_path).await?;
                let view = opsclaw::cli::approvals_cmd::show(&db.repos(), id).await?;
                if json {
                    opsclaw::cli::output::print_json(&view);
                } else {
                    print!("{}", opsclaw::cli::approvals_cmd::render(std::slice::from_ref(&view)));
                }
            }
            ApprovalsCommand::Approve { id, as_email, yes, json } => {
                // Approving EXECUTES the stored command, so this needs the
                // daemon's own wiring — the same full boot `scan` uses.
                let config = Config::load(Some(cfg_path))?;
                config.validate()?;
                let state =
                    opsclaw::boot::daemon_state(config, cfg_path.to_path_buf(), home).await?;
                let view = opsclaw::cli::approvals_cmd::show(&state.repos, id).await?;
                if !opsclaw::cli::approvals_cmd::is_pending(&view) {
                    return Err(opsclaw::Error::Config(format!(
                        "approval {id} is already {} — nothing to decide",
                        view.state
                    )));
                }
                let operator = opsclaw::cli::approvals_cmd::resolve_operator(
                    &state.repos,
                    as_email.as_deref(),
                )
                .await?;
                opsclaw::cli::confirm::destructive(
                    &opsclaw::cli::approvals_cmd::decision_preview(&view, true),
                    yes,
                )?;
                let outcome = opsclaw::incidents::approvals::approve(
                    &*state.repos,
                    &state.approved,
                    id,
                    operator,
                )
                .await?;
                if json {
                    opsclaw::cli::output::print_json(&format!("{outcome:?}"));
                } else {
                    println!("{outcome:?}");
                }
                state.chat.drain(std::time::Duration::from_secs(20)).await;
            }
            ApprovalsCommand::Deny { id, as_email, yes, json } => {
                // Denying runs nothing, so it needs only the database.
                let db = open_db(cfg_path).await?;
                let repos = db.repos();
                let view = opsclaw::cli::approvals_cmd::show(&repos, id).await?;
                if !opsclaw::cli::approvals_cmd::is_pending(&view) {
                    return Err(opsclaw::Error::Config(format!(
                        "approval {id} is already {} — nothing to decide",
                        view.state
                    )));
                }
                let operator =
                    opsclaw::cli::approvals_cmd::resolve_operator(&repos, as_email.as_deref())
                        .await?;
                opsclaw::cli::confirm::destructive(
                    &opsclaw::cli::approvals_cmd::decision_preview(&view, false),
                    yes,
                )?;
                let outcome = opsclaw::incidents::approvals::deny(&*repos, id, operator).await?;
                if json {
                    opsclaw::cli::output::print_json(&format!("{outcome:?}"));
                } else {
                    println!("{outcome:?}");
                }
            }
        },

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

        Command::Account { command } => match command {
            AccountCommand::Create { email, name, hanko_subject } => {
                // Resolve the configured provider BEFORE prompting. A
                // password prompt under an external provider blocks the
                // operator on a hidden read for a credential the daemon
                // never checks — and on a non-TTY it silently swallows
                // whatever is on stdin.
                let provider = Config::load(Some(cfg_path))?.auth.provider;
                let db = open_or_create_db(cfg_path, home).await?;
                let display_name = name.clone().unwrap_or_else(|| email.clone());
                use opsclaw::cli::account_cmd::Credential;
                use opsclaw::config::AuthProvider;
                let password;
                let credential = match (provider, hanko_subject.as_deref()) {
                    (AuthProvider::Local, None) => {
                        password = read_password_confirmed()?;
                        Credential::Password(&password)
                    }
                    (AuthProvider::Local, Some(_)) => {
                        return Err(opsclaw::Error::validation(
                            "this daemon uses password sign-in — drop --hanko-subject, or set \
                             auth.provider = \"hanko\" in config.toml",
                        ));
                    }
                    (AuthProvider::Hanko, Some(subject)) => Credential::HankoSubject(subject),
                    (AuthProvider::Hanko, None) => {
                        return Err(opsclaw::Error::validation(
                            "this daemon uses hanko sign-in — pass --hanko-subject <id> (the user \
                             id from the Hanko console); no password is stored",
                        ));
                    }
                };
                let out = opsclaw::cli::account_cmd::create(&db, &email, &display_name, credential)
                    .await?;
                println!("created operator {} ({}) — sign in at the web UI", out.email, out.id);
            }
            AccountCommand::Link { email, hanko_subject, drop_password } => {
                let db = open_or_create_db(cfg_path, home).await?;
                let out = opsclaw::cli::account_cmd::link_hanko(
                    &db,
                    &email,
                    &hanko_subject,
                    drop_password,
                )
                .await?;
                println!("linked {} ({}) to hanko subject {hanko_subject}", out.email, out.id);
                if drop_password {
                    println!(
                        "  its password is cleared — until auth.provider is \"hanko\", this \
                         operator cannot sign in at all"
                    );
                } else {
                    println!("  its password still works until auth.provider is \"hanko\"");
                }
            }
            AccountCommand::SetPassword { email } => {
                // The warning below turns on the DAEMON's configured
                // provider, not the account's: an account linked to Hanko on
                // a daemon still running `local` can absolutely use a
                // password, and that combination is the normal mid-migration
                // state. Reading it off the account row would tell the
                // operator their password does not work when it does.
                let provider = Config::load(Some(cfg_path))?.auth.provider;
                let db = open_or_create_db(cfg_path, home).await?;
                let password = read_password_confirmed()?;
                let out = opsclaw::cli::account_cmd::set_password(&db, &email, &password).await?;
                println!("set the password for {} ({})", out.email, out.id);
                if provider != opsclaw::config::AuthProvider::Local {
                    println!(
                        "  note: auth.provider is not \"local\", so password sign-in is refused \
                         until it is set back"
                    );
                }
            }
            AccountCommand::RevokeSessions { email, yes } => {
                opsclaw::cli::confirm::destructive(
                    &format!(
                        "will revoke EVERY session for {email}: all web sign-ins and all `ops_` \
                         CLI tokens. They must sign in again, and any automation using one of \
                         their tokens stops working."
                    ),
                    yes,
                )?;
                let db = open_or_create_db(cfg_path, home).await?;
                let revoked = opsclaw::cli::account_cmd::revoke_sessions(&db, &email).await?;
                println!(
                    "revoked every web session for {email} and {revoked} CLI token(s) — they must \
                     sign in again"
                );
            }
            AccountCommand::List { json } => {
                let db = open_or_create_db(cfg_path, home).await?;
                let accounts = opsclaw::cli::account_cmd::list(&db).await?;
                if json {
                    opsclaw::cli::output::print_json(&accounts);
                } else if accounts.is_empty() {
                    println!("(no operator accounts — run `opsclaw-cli account create <email>`)");
                } else {
                    // Linkage is shown because it is the one thing an
                    // auth.provider flip depends on, and it was otherwise
                    // only inspectable by opening the database by hand.
                    for a in accounts {
                        let link = match (&a.auth_provider, &a.external_subject) {
                            (p, Some(s)) => format!("{p}:{s}"),
                            (p, None) => format!("{p} (not linked)"),
                        };
                        println!("{}  {}  {}  {link}", a.id, a.email, a.display_name);
                    }
                }
            }
        },

        Command::Tokens { command } => match command {
            TokensCommand::List { as_email, json } => {
                let db = open_or_create_db(cfg_path, home).await?;
                let views =
                    opsclaw::cli::tokens_cmd::list(&db.repos(), as_email.as_deref()).await?;
                if json {
                    opsclaw::cli::output::print_json(&views);
                } else {
                    print!("{}", opsclaw::cli::tokens_cmd::render(&views));
                }
            }
            TokensCommand::Revoke { id, as_email, yes } => {
                let db = open_or_create_db(cfg_path, home).await?;
                opsclaw::cli::confirm::destructive(
                    &format!(
                        "will revoke CLI token {id} belonging to {as_email}. Anything using it \
                         stops working immediately, and the token cannot be restored."
                    ),
                    yes,
                )?;
                if opsclaw::cli::tokens_cmd::revoke(&db.repos(), &as_email, id).await? {
                    println!("revoked CLI token {id}");
                } else {
                    eprintln!("no CLI token {id} belonging to {as_email}");
                    std::process::exit(1);
                }
            }
        },

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
            SecretCommand::Rm { name, yes } => {
                opsclaw::cli::confirm::destructive(
                    &format!(
                        "will remove secret store:{name}. Any config field referencing it stops \
                         resolving, and the store holds the only copy."
                    ),
                    yes,
                )?;
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

        Command::Jobs { command } => {
            let db = open_db(cfg_path).await?;
            match command {
                JobsCommand::List { json } => {
                    let rows = opsclaw::cli::jobs_cmd::list(&*db.repos()).await?;
                    if json {
                        opsclaw::cli::output::print_json(&rows);
                    } else if rows.is_empty() {
                        println!("(no jobs — the daemon seeds one scan job per project at boot)");
                    } else {
                        for r in &rows {
                            let flags = match (r.enabled, r.system) {
                                (false, _) => " [disabled]",
                                (true, true) => " [seeded]",
                                (true, false) => "",
                            };
                            println!(
                                "{}{}  {}  next {}\n    {}",
                                r.name,
                                flags,
                                r.schedule,
                                r.next_run_at.as_deref().unwrap_or("(never)"),
                                r.payload
                            );
                        }
                    }
                }
                JobsCommand::Edit { name, prompt, every_minutes, enabled } => {
                    let job = opsclaw::cli::jobs_cmd::edit(
                        &*db.repos(),
                        &name,
                        prompt,
                        every_minutes,
                        enabled,
                    )
                    .await?;
                    println!(
                        "updated {:?} — schedule {:?}, payload {}, next run {}",
                        job.name,
                        job.schedule,
                        match &job.payload {
                            opsclaw::domain::Payload::Prompt { .. } => "free-text prompt",
                            opsclaw::domain::Payload::ScanRoutine { .. } => "code-resolved routine",
                            opsclaw::domain::Payload::Text(_) => "fixed text",
                        },
                        job.next_run_at.map(|t| t.to_rfc3339()).unwrap_or("(never)".into())
                    );
                }
                JobsCommand::Delete { name, yes } => {
                    opsclaw::cli::confirm::destructive(
                        &format!("will permanently delete job {name:?} and its failure history"),
                        yes,
                    )?;
                    if opsclaw::cli::jobs_cmd::delete(&*db.repos(), &name).await? {
                        println!("deleted job {name:?}");
                    } else {
                        return Err(opsclaw::Error::NotFound(format!("job {name:?}")));
                    }
                }
            }
        }
        Command::DryRunLog { limit, json } => {
            let db = open_db(cfg_path).await?;
            let entries = opsclaw::cli::audit_cmd::blocked_actions(&db, limit).await?;
            if json {
                opsclaw::cli::output::print_json(&entries);
            } else if entries.is_empty() {
                println!("(blocked-actions is empty — no autonomy-blocked commands recorded)");
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
        Command::Invites { command } => handle_invites(command, cfg_path).await?,
        Command::Completions { shell } => {
            // Generate clap's dynamic registration so completion requests
            // come back through this binary and can read the current config
            // for project::env::target candidates.
            let output = std::process::Command::new(std::env::current_exe()?)
                .env("COMPLETE", shell.to_string())
                .output()?;
            if !output.status.success() {
                return Err(opsclaw::Error::other(format!(
                    "completion generation failed with {}",
                    output.status
                )));
            }
            use std::io::Write;
            std::io::stdout().write_all(&output.stdout)?;
        }
    }
    Ok(())
}

async fn handle_invites(
    command: InvitesCommand,
    cfg_path: &std::path::Path,
) -> opsclaw::Result<()> {
    match command {
        InvitesCommand::List { remote: true, json } => {
            let body = opsclaw::cli::remote::invites::list(&remote_session()?).await?;
            if json {
                opsclaw::cli::output::print_json(&body["invites"]);
            } else {
                render_invites(body["invites"].as_array().map(Vec::as_slice).unwrap_or(&[]));
            }
        }
        InvitesCommand::List { remote: false, json } => {
            let db = open_db(cfg_path).await?;
            let invites = opsclaw::cli::invites_cmd::list(db.repos().as_ref()).await?;
            if json {
                opsclaw::cli::output::print_json(&invites);
            } else {
                let rows = invites
                    .iter()
                    .map(|invite| {
                        serde_json::json!({
                            "code": invite.code,
                            "issued_by": invite.issued_by,
                            "expires_at": invite.expires_at,
                        })
                    })
                    .collect::<Vec<_>>();
                render_invites(&rows);
            }
        }
        InvitesCommand::Add { remote: true, json, .. } => {
            let body = opsclaw::cli::remote::invites::create(&remote_session()?).await?;
            if json {
                opsclaw::cli::output::print_json(&body);
            } else {
                println!(
                    "invite {} expires {}",
                    body["code"].as_str().unwrap_or("?"),
                    body["expires_at"].as_str().unwrap_or("?")
                );
            }
        }
        InvitesCommand::Add { as_email, remote: false, json } => {
            let db = open_db(cfg_path).await?;
            let invite =
                opsclaw::cli::invites_cmd::create(db.repos().as_ref(), as_email.as_deref()).await?;
            if json {
                opsclaw::cli::output::print_json(&invite);
            } else {
                println!("invite {} expires {}", invite.code, invite.expires_at.to_rfc3339());
            }
        }
        InvitesCommand::Remove { code, remote: true, yes } => {
            opsclaw::cli::confirm::destructive(&format!("will revoke invite {code}"), yes)?;
            opsclaw::cli::remote::invites::revoke(&remote_session()?, &code).await?;
            println!("revoked invite {code}");
        }
        InvitesCommand::Remove { code, remote: false, yes } => {
            opsclaw::cli::confirm::destructive(&format!("will revoke invite {code}"), yes)?;
            let db = open_db(cfg_path).await?;
            if !opsclaw::cli::invites_cmd::revoke(db.repos().as_ref(), &code).await? {
                return Err(opsclaw::Error::NotFound(format!("open invite {code}")));
            }
            println!("revoked invite {code}");
        }
    }
    Ok(())
}

fn render_invites(invites: &[serde_json::Value]) {
    if invites.is_empty() {
        println!("(no open invites)");
        return;
    }
    for invite in invites {
        println!(
            "{}  expires {}  issued by {}",
            invite["code"].as_str().unwrap_or("?"),
            invite["expires_at"].as_str().unwrap_or("?"),
            invite["issued_by"].as_str().unwrap_or("?"),
        );
    }
}

fn render_remote_history(body: &serde_json::Value) {
    for row in body["history"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        println!(
            "{}  {}  {}: {}",
            row["seq"].as_i64().unwrap_or(0),
            row["at"].as_str().unwrap_or("?"),
            row["speaker"].as_str().unwrap_or("?"),
            row["content"].as_str().unwrap_or(""),
        );
    }
}

fn render_remote_spend(spend: &serde_json::Value) {
    println!("UTC day: {}", spend["day_utc"].as_str().unwrap_or("?"));
    println!("OpsClaw: {:.1}¢", spend["opsclaw_cents"].as_f64().unwrap_or(0.0));
    match spend["hindsight_cents"].as_f64() {
        Some(value) => println!("Hindsight: {value:.1}¢"),
        None => println!("Hindsight: unmetered"),
    }
    println!(
        "Total: {:.1}¢ / {:.0}¢",
        spend["total_cents"].as_f64().unwrap_or(0.0),
        spend["cap_cents"].as_f64().unwrap_or(0.0),
    );
    println!(
        "Coverage: {}",
        if spend["complete"].as_bool().unwrap_or(false) { "complete" } else { "OpsClaw only" }
    );
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
        return std::env::var(var)
            .map_err(|_| opsclaw::Error::Config(format!("environment variable {var} is not set")));
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

/// Hidden password prompt with confirmation (interactive), or piped stdin
/// (scripted). Same never-argv rule as `read_secret_value`.
fn read_password_confirmed() -> opsclaw::Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        // The 12-character rule lives in account_cmd::create; stating it in
        // the prompt (and checking before the confirmation read) spares the
        // operator typing a doomed password twice only to have it rejected.
        let first = rpassword::prompt_password("password (min 12 characters; hidden): ")
            .map_err(|e| opsclaw::Error::other(format!("could not read hidden input: {e}")))?;
        if first.len() < 12 {
            return Err(opsclaw::Error::validation("password must be at least 12 characters"));
        }
        let second = rpassword::prompt_password("confirm password: ")
            .map_err(|e| opsclaw::Error::other(format!("could not read hidden input: {e}")))?;
        if first != second {
            return Err(opsclaw::Error::validation("passwords did not match"));
        }
        Ok(first)
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        Ok(buf.trim_end_matches(['\n', '\r']).to_string())
    }
}

/// Like [`open_db`], but for commands that legitimately run BEFORE the
/// daemon's first boot (account bootstrap): falls back to the default
/// `<home>/opsclaw.sqlite3` when config declares no db_path, creating and
/// migrating it — the same file `boot::daemon_state` would then reuse.
async fn open_or_create_db(
    cfg_path: &std::path::Path,
    home: &std::path::Path,
) -> opsclaw::Result<opsclaw::db::Db> {
    let path = resolve_db_path(cfg_path)
        .unwrap_or_else(|| home.join("opsclaw.sqlite3").display().to_string());
    opsclaw::db::Db::connect(&path).await
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
            &["opsclaw-cli", "onboard", "--auth-provider", "local"],
            &[
                "opsclaw-cli",
                "onboard",
                "--yes",
                "--auth-provider",
                "hanko",
                "--hanko-api-url",
                "https://tenant.hanko.io",
                "--hanko-audience",
                "ops.example.com,ops.internal.example.com",
            ],
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
            &["opsclaw-cli", "memory", "export"],
            &["opsclaw-cli", "memory", "export", "--limit", "50", "--json"],
            &["opsclaw-cli", "chat"],
            &["opsclaw-cli", "chat", "is prod healthy?"],
            &["opsclaw-cli", "chat", "is prod healthy?", "--remote"],
            &["opsclaw-cli", "chat", "--history"],
            &["opsclaw-cli", "chat", "--history", "--before", "42", "--json"],
            &["opsclaw-cli", "status"],
            &["opsclaw-cli", "status", "--json"],
            &["opsclaw-cli", "usage"],
            &["opsclaw-cli", "usage", "--remote", "--json"],
            &["opsclaw-cli", "incidents", "ack", "00000000-0000-0000-0000-000000000000"],
            &[
                "opsclaw-cli",
                "incidents",
                "resolve",
                "00000000-0000-0000-0000-000000000000",
                "--remote",
            ],
            &["opsclaw-cli", "approve", "00000000-0000-0000-0000-000000000000"],
            &["opsclaw-cli", "deny", "00000000-0000-0000-0000-000000000000", "--json"],
            &["opsclaw-cli", "login", "--remote", "https://gw.example.com"],
            &["opsclaw-cli", "logout"],
            &["opsclaw-cli", "whoami"],
            &["opsclaw-cli", "ui"],
            &["opsclaw-cli", "ui", "--tunnel", "op@bastion.example.com"],
            &["opsclaw-cli", "account", "create", "ops@example.com"],
            &["opsclaw-cli", "account", "create", "ops@example.com", "--name", "dcp"],
            &[
                "opsclaw-cli",
                "account",
                "create",
                "ops@example.com",
                "--hanko-subject",
                "6f1c0e64-0000-4000-8000-000000000001",
            ],
            &["opsclaw-cli", "account", "revoke-sessions", "ops@example.com"],
            &["opsclaw-cli", "account", "link", "ops@example.com", "--hanko-subject", "sub-1"],
            &[
                "opsclaw-cli",
                "account",
                "link",
                "ops@example.com",
                "--hanko-subject",
                "sub-1",
                "--drop-password",
            ],
            &["opsclaw-cli", "account", "set-password", "ops@example.com"],
            &["opsclaw-cli", "account", "list", "--json"],
            &["opsclaw-cli", "accounts", "add", "ops@example.com"],
            &["opsclaw-cli", "secret", "set", "es-password"],
            &["opsclaw-cli", "secret", "set", "es-password", "--from-env", "ES_PASSWORD"],
            &["opsclaw-cli", "secret", "set", "ca-bundle", "--from-file", "/tmp/ca.crt"],
            &["opsclaw-cli", "secret", "list", "--json"],
            &["opsclaw-cli", "secret", "rm", "es-password"],
            &["opsclaw-cli", "secrets", "add", "es-password"],
            &["opsclaw-cli", "secrets", "remove", "es-password", "--yes"],
            &["opsclaw-cli", "scan", "example::sandbox::cluster"],
            &["opsclaw-cli", "scan", "example::sandbox::cluster", "--json"],
            &["opsclaw-cli", "dry-run-log"],
            &["opsclaw-cli", "dry-run-log", "--limit", "10", "--json"],
            &["opsclaw-cli", "blocked-actions"],
            &["opsclaw-cli", "config", "projects", "add"],
            &["opsclaw-cli", "config", "resources", "add"],
            &["opsclaw-cli", "config", "remove", "p::e::t", "--yes"],
            &["opsclaw-cli", "runbooks", "add", "dlq-backlog"],
            &["opsclaw-cli", "runbooks", "run", "DLQ backlog", "--target", "p::e::t", "--dry-run"],
            &["opsclaw-cli", "memory", "add", "some fact"],
            &["opsclaw-cli", "memory", "remove", "some-id", "--yes"],
            &["opsclaw-cli", "jobs", "remove", "scan:p:e:t", "--yes"],
            &["opsclaw-cli", "invites", "list"],
            &["opsclaw-cli", "invites", "add", "--as", "ops@example.com"],
            &["opsclaw-cli", "invites", "remove", "code", "--yes"],
            &["opsclaw-cli", "completions", "zsh"],
            &["opsclaw-cli", "estop", "--remote"],
            &["opsclaw-cli", "estop", "--resume", "--remote"],
        ];
        for argv in cases {
            let result = Cli::try_parse_from(*argv);
            assert!(result.is_ok(), "failed to parse {argv:?}: {:?}", result.err());
        }
    }

    #[test]
    fn completion_candidates_include_double_colon_config_paths() {
        let config: Config = toml::from_str(
            r#"
            [[project]]
            name = "payments"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "api"
            kind = "local"
            "#,
        )
        .unwrap();
        let values = path_candidates_for(&config, false)
            .into_iter()
            .map(|candidate| candidate.get_value().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(values, ["payments", "payments::prod", "payments::prod::api"]);
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
    fn onboard_refuses_an_unknown_auth_provider_at_parse_time() {
        assert!(
            Cli::try_parse_from(["opsclaw-cli", "onboard", "--yes", "--auth-provider", "oidc"])
                .is_err()
        );
    }

    #[test]
    fn account_revoke_sessions_requires_an_email() {
        assert!(Cli::try_parse_from(["opsclaw-cli", "account", "revoke-sessions"]).is_err());
        assert!(Cli::try_parse_from(["opsclaw-cli", "account", "set-password"]).is_err());
        // --hanko-subject carries the identity; link without it is meaningless.
        assert!(
            Cli::try_parse_from(["opsclaw-cli", "account", "link", "ops@example.com"]).is_err()
        );
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
