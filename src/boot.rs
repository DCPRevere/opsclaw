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
    // clearly-logged FakeLlm with no key) — the same chain the evals gate on
    // — wrapped in the daily cost cap (`limits.max_cost_per_day_cents`).
    // The guard's notifier is installed further down, once the channel
    // fan-out exists (wiring order, not an optional feature).
    let base_llm = crate::llm::build_chain(&config.llm, &secret_store)?;
    let cost_guard = Arc::new(crate::llm::CostGuard::new(
        base_llm,
        repos.clone(),
        config.limits.max_cost_per_day_cents,
    ));
    let llm: Arc<dyn crate::llm::LlmProvider> = cost_guard.clone();

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
    // Outbound escalation webhook (decision 5's second guaranteed path).
    // The signing secret is a resolved credential like any other:
    // scrubber-registered before the channel ever holds it.
    if let Some(url) = &state.config.webhook_out.url {
        let secret = match &state.config.webhook_out.secret {
            Some(r) => {
                let s = r.resolve(&secret_store)?;
                scrubber.register("WEBHOOK_OUT_SECRET", &s);
                Some(s)
            }
            None => None,
        };
        channels.push(Arc::new(crate::channels::webhook_out::WebhookOutChannel::new(
            url.clone(),
            secret,
        )));
    }
    state.named_channels = channels.clone();
    state.channel = Arc::new(MultiChannel::new(channels));
    // The cost cap's loud once-per-day notification rides the same fan-out
    // as every other escalation (built just above — this is the earliest
    // point the notifier can exist).
    cost_guard.set_notifier(state.channel.clone());

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
///
/// The interval is normally the fixed operational default (30 minutes) but
/// is overridable via `OPSCLAW_SCAN_INTERVAL_MINUTES` — a real operational
/// knob (some fleets want a tighter or looser default cadence than 30
/// minutes for every seeded job) that also happens to be exactly what the
/// Tier 2 sim/k3d harnesses need: `Job::new` computes `next_run_at` as
/// `now + every_minutes`, so a 30-minute default would make the harness wait
/// up to half an hour for the very first scan tick. Clamped to
/// `JOB_GAP_MINUTES_MIN` (never 0/negative — that would mean "always due",
/// a hot loop) and loudly logged when it diverges from the default, exactly
/// like `llm::build_chain`'s fake-LLM warning: an operator (or harness
/// author) staring at unexpected scan cadence needs this in the log, not
/// buried in a debug flag.
pub async fn seed_scan_jobs(state: &AppState) -> Result<()> {
    const DEFAULT_SCAN_INTERVAL_MINUTES: i64 = 30;
    let every_minutes = std::env::var("OPSCLAW_SCAN_INTERVAL_MINUTES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .map(|v| v.max(crate::domain::JOB_GAP_MINUTES_MIN))
        .unwrap_or(DEFAULT_SCAN_INTERVAL_MINUTES);
    if every_minutes != DEFAULT_SCAN_INTERVAL_MINUTES {
        tracing::warn!(
            every_minutes,
            "OPSCLAW_SCAN_INTERVAL_MINUTES override active — seeded scan jobs will fire every {every_minutes} minute(s) instead of the {DEFAULT_SCAN_INTERVAL_MINUTES}-minute default"
        );
    }
    let deps = crate::http::server::scheduler_deps(state);
    crate::scheduler::seed_default_scan_jobs(&deps, every_minutes).await
}
