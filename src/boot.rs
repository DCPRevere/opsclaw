//! Shared daemon composition: ONE wiring path for both binaries (`opsclaw`
//! and `opsclaw-cli daemon`), so they cannot drift — the drift already
//! happened once (main.rs gained real executor wiring while the CLI's
//! duplicate kept a stale empty map; this module is the consolidation).
//!
//! Ordering in here is load-bearing: `targets::wiring::build_executors` runs
//! BEFORE `DispatchDeps::assemble`, because build_executors is what registers
//! resolved resource credentials with the scrubber — assemble's
//! `registry_from_config` deliberately does not re-register (see its doc).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::Result;
use crate::agent::dispatch::{AgentJobComposer, ChatTurn, DispatchDeps, WebhookIngest};
use crate::audit::AuditWriter;
use crate::channels::push::{PushChannel, WebPushSender};
use crate::channels::telegram::{DbOffsetStore, DbTelegramRoster, TelegramChannel};
use crate::channels::{Channel, MultiChannel};
use crate::config::{Config, SecretStore};
use crate::db::Db;
use crate::http::AppState;
use crate::memory::Memory;
use crate::policy::{EStop, Policy, Scrubber};
use crate::scheduler::SchedulerHandle;

/// Build the fully-wired daemon state from a loaded, validated config.
/// `config_path` is the exact path the config came from (config-management
/// writes go back to it); `home` is the opsclaw dir (secret store, sqlite
/// default, e-stop sentinel).
pub async fn daemon_state(config: Config, config_path: PathBuf, home: &Path) -> Result<AppState> {
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

    // Executors + scrubber FIRST (see module doc: scrubber registration for
    // resource credentials happens in build_executors).
    let scrubber = Arc::new(Scrubber::new());
    let (executors, wiring_warnings) =
        crate::targets::wiring::build_executors(&config, &secret_store, &scrubber)?;
    for w in &wiring_warnings {
        tracing::warn!("{w}");
    }
    tracing::info!("wired {} executor(s)", executors.len());

    let estop = Arc::new(EStop::new(home.join(crate::policy::estop::SENTINEL_FILE), repos.clone()));
    let audit = Arc::new(AuditWriter::new(repos.clone()));
    let config_arc = Arc::new(config.clone());
    let policy = Arc::new(Policy::new(
        config_arc.clone(),
        executors,
        audit,
        estop.clone(),
        repos.clone(),
        scrubber.clone(),
    ));

    // The shipped LLM chain (FallbackLlm over OpenRouter, or the
    // clearly-logged FakeLlm with no key) — the same chain the evals gate on.
    let llm = crate::llm::build_chain(&config.llm, &secret_store)?;

    // Memory: Hindsight when configured, honest no-op otherwise.
    let memory = match &config.memory.hindsight_url {
        Some(url) => {
            let client = Arc::new(crate::memory::hindsight::HindsightClient::new(
                url.clone(),
                None,
                &config.memory.team_id,
            ));
            Arc::new(Memory::disabled().with_hindsight(client))
        }
        None => Arc::new(Memory::disabled()),
    };

    // The agent dispatch deps (runbook store + endpoint registry loaded from
    // config here; scrubber registration already done above).
    let deps = DispatchDeps::assemble(
        config_arc,
        &secret_store,
        policy.clone(),
        repos.clone(),
        repos.clone(),
        repos.clone(),
        memory,
        llm,
    )?;

    let scheduler_handle = SchedulerHandle::new(config.daemon.tick_seconds.max(1) * 1000);
    let mut state = AppState::new(
        config,
        config_path,
        &secret_store,
        repos,
        policy.clone(),
        policy,
        estop,
        scheduler_handle,
    )?;

    // Outbound channel fan-out: the web SSE hub always; Telegram when a bot
    // token is configured. The Telegram roster and poll offset are DB-backed
    // (`DbTelegramRoster`/`DbOffsetStore` over `ChannelStateRepo`) — a
    // restart neither forgets chat bindings nor re-sees already-handled
    // updates. Telegram also LISTENS (inbound chat), so it gets the state's
    // shutdown token at construction (its long-poll stops on cancel — see
    // `TelegramChannel::with_shutdown`) and joins `listen_channels`, which
    // `server::run` spawns the inbound consumer over.
    let mut channels: Vec<Arc<dyn Channel>> = vec![state.web.clone()];
    if let Some(token_ref) = &state.config.telegram.bot_token {
        let token = token_ref.resolve(&secret_store)?;
        scrubber.register("TELEGRAM_BOT_TOKEN", &token);
        let telegram = Arc::new(
            TelegramChannel::new(
                token,
                reqwest::Client::new(),
                Arc::new(DbTelegramRoster::new(state.repos.clone())),
                Arc::new(DbOffsetStore::new(state.repos.clone())),
            )
            .with_shutdown(state.shutdown.clone()),
        );
        channels.push(telegram.clone());
        state.listen_channels.push(telegram);
    }
    // Web push, when the VAPID pair is configured (`Config::validate`
    // already rejects a half-set pair, so `vapid_private_key.is_some()` here
    // implies the public key is set too). Push is best-effort by design
    // (DESIGN §3 decision 5): Telegram/webhook above are the guaranteed
    // escalation paths, so a push wiring/delivery failure never blocks boot
    // or the rest of the fan-out — only a genuinely malformed configured key
    // (caught by `WebPushSender::new`'s `Result`) fails loudly, the same way
    // a malformed Telegram token would.
    if let Some(private_key_ref) = &state.config.push.vapid_private_key {
        let private_key = private_key_ref.resolve(&secret_store)?;
        scrubber.register("VAPID_PRIVATE_KEY", &private_key);
        let sender = Arc::new(WebPushSender::new(&private_key)?);
        channels.push(Arc::new(PushChannel::new(state.repos.clone(), sender)));
    }
    state.channel = Arc::new(MultiChannel::new(channels));

    // The real webhook ingest (verified alert → framed observation → full
    // registry turn), the real scan-job composer, and the real chat handler
    // replace the boot-safe no-ops AppState::new installs.
    state.ingest = Arc::new(WebhookIngest::new(deps.clone(), state.channel.clone()));
    state.composer = Arc::new(AgentJobComposer::new(deps.clone()));
    state.chat = Arc::new(ChatTurn::new(deps));

    Ok(state)
}

/// Seed the per-project scan jobs (first boot; idempotent — existing jobs
/// are left alone). Called by both binaries right before `server::run`.
pub async fn seed_scan_jobs(state: &AppState) -> Result<()> {
    let deps = crate::http::server::scheduler_deps(state);
    crate::scheduler::seed_default_scan_jobs(&deps, 30).await
}
