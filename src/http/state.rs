//! Shared application state (gianna's `AppState`/`with_repos` pattern,
//! `src/http/state.rs`, collapsed to opsclaw's single-tenant shape — no
//! household-scoped fields).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use uuid::Uuid;

use crate::channels::web::WebHub;
use crate::channels::{Channel, ChatHandler, NoopChat};
use crate::config::{Config, SecretStore};
use crate::db::AllRepos;
use crate::http::cli_auth::CliAuthCodes;
use crate::http::ratelimit::RateLimiter;
use crate::http::webhook::{IngestAlert, NoopIngest};
use crate::policy::{EStop, ExecuteApproved, PolicyExecute};
use crate::scheduler::{JobComposer, NoopComposer, SchedulerHandle};

/// Shared application state. Every handler reaches persistence, policy, and
/// cross-cutting auth/rate-limit state through this one `Clone` struct
/// (`Arc`-backed fields, so cloning is cheap — one instance is built at
/// boot and handed to every request via axum's `State` extractor).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// The path `config` was actually loaded from (or would be written to
    /// if it doesn't exist yet) — what `routes::config_ui::update_config`
    /// writes to. NOT derived from `config::default_dir()` internally by
    /// any handler: it is passed in explicitly by the caller (`main.rs`
    /// passes the exact path `Config::load` resolved; `AppState::fake`/
    /// `fake_with_config` point it at a per-instance, non-existent tempdir
    /// path so a fakes-mode config write can never reach a real machine's
    /// `~/.opsclaw`). This field exists because of a real incident: an
    /// earlier version of the config-write route resolved
    /// `config::default_dir()` itself, and a test run overwrote the
    /// developer's real `~/.opsclaw/config.toml`. Never reintroduce a
    /// direct `default_dir()` call on the write path — always go through
    /// this field.
    pub config_path: PathBuf,
    /// Resolved once at boot (`Config::resolve_jwt_secret`) — never
    /// re-resolved per-request. A `SecretRef::Store` value would otherwise
    /// mean a disk read (through the encrypted store) on every single
    /// authenticated request.
    pub jwt_secret: Arc<str>,
    /// Resolved once at boot, same reasoning as `jwt_secret` — a webhook
    /// delivery is far less frequent than an authenticated request, but
    /// there is no reason to accept the disk-read cost twice when boot is
    /// the natural place to pay it once. `None` when `config.http.
    /// webhook_secret` is unset (fakes mode only; `resolve_webhook_secret`
    /// mirrors `Config::validate`'s refusal to boot unset+live).
    pub webhook_secret: Option<Arc<str>>,
    /// The Hanko session verifier — `Some` exactly when
    /// `config.auth.provider` is `hanko`, so `is_some()` is the runtime
    /// answer to "is an external provider configured". No secret is
    /// involved: Hanko's `/sessions/validate` is unauthenticated, which is
    /// why (unlike `jwt_secret`) nothing here needs a `SecretStore` and
    /// nothing needs scrubbing from logs.
    pub hanko: Option<Arc<crate::http::hanko::HankoClient>>,
    /// The agent's tool wiring, for the MCP server (`http::mcp`). Set at
    /// boot; `None` in fakes (no `/mcp`).
    pub dispatch: Option<crate::agent::dispatch::DispatchDeps>,
    /// The SSO client when `auth.provider = "oidc"`.
    pub oidc: Option<Arc<crate::http::oidc::OidcClient>>,
    pub repos: Arc<dyn AllRepos>,
    /// The configured memory backend, retained on state so deep readiness
    /// probes the same client agent turns use.
    pub memory: Arc<crate::memory::Memory>,
    /// Shared budget reporter/gate for OpsClaw and metered Hindsight calls.
    pub cost_guard: Arc<crate::llm::CostGuard>,
    /// The safety-invariant seam (AGENTS.md): the ONLY way any handler may
    /// reach a `TargetExecutor` is through one of these two traits — never
    /// a concrete `Policy`, never a `TargetExecutor` directly. `policy` is
    /// for chat/tool-triggered commands; `approved` is for the approval
    /// queue's approve endpoint, which must skip the autonomy gate (see
    /// `policy::ExecuteApproved`'s doc comment for why that's a separate,
    /// narrower trait).
    pub policy: Arc<dyn PolicyExecute>,
    pub approved: Arc<dyn ExecuteApproved>,
    pub estop: Arc<EStop>,
    pub scheduler: SchedulerHandle,
    pub web: Arc<WebHub>,
    /// Fan-out over every configured outbound channel (Telegram, web SSE,
    /// …) — what an approve/deny/estop handler's confirmation, or a fired
    /// scan job, actually reaches operators through.
    pub channel: Arc<dyn Channel>,
    /// The same channels INDIVIDUALLY — what the scheduler's escalation
    /// driver resolves a step's named contact ("telegram", "web", …)
    /// against; `channel` above is the fan-out and cannot express "this
    /// channel only". Kept in lock-step with `channel` by `boot::assemble`.
    pub named_channels: Vec<Arc<dyn Channel>>,
    /// The alert-ingestion seam (`http::webhook::IngestAlert`) a verified
    /// webhook hands its parsed payload to. Defaults to a no-op until the
    /// agent-loop/incident-opening integration wires the real one.
    pub ingest: Arc<dyn IngestAlert>,
    /// What a fired scan job composes with. Boot-safe default is the
    /// NoopComposer; `boot::daemon_state` swaps in the real
    /// `AgentJobComposer` once the dispatch deps exist.
    pub composer: Arc<dyn JobComposer>,
    /// The chat seam every conversational surface drives (gateway chat
    /// route, channel inbound loop, CLI REPL). Boot-safe default is
    /// `NoopChat` (errors, mapped to 503 by the route); `boot::daemon_state`
    /// swaps in the real `agent::dispatch::ChatTurn`.
    pub chat: Arc<dyn ChatHandler>,
    /// Channels with a real `listen` loop (Telegram today) —
    /// `http::server::run` spawns `channels::inbound` over exactly this
    /// list. Empty in fakes mode and when no listening channel is
    /// configured.
    pub listen_channels: Vec<Arc<dyn Channel>>,
    /// The daemon-wide shutdown token. Created HERE (not in `server::run`)
    /// so boot-time wiring can hand it to components that need it at
    /// construction (TelegramChannel's long-poll stops on it);
    /// `server::run` cancels it on SIGINT/SIGTERM, and cancelling it
    /// externally drains `server::run` the same way (the SIGTERM-equivalent
    /// the daemon-lifecycle e2e shuts down through).
    pub shutdown: tokio_util::sync::CancellationToken,
    /// Every detached request/background task joins this tracker so graceful
    /// shutdown waits for side effects and their transcript records to settle.
    pub tasks: tokio_util::task::TaskTracker,
    /// Live agent-turn registry used by the status surfaces.
    pub(crate) turn_gate: crate::agent::turn_gate::TurnGate,
    pub auth_limiter: Arc<RateLimiter>,
    /// Single-use replay guard for SSE stream tickets (gianna's
    /// `used_stream_tickets`) — token string -> expiry unix seconds, swept
    /// on insert. In-memory: opsclaw is a single-node daemon (DESIGN §1),
    /// so there is no cross-instance replay concern to persist against,
    /// and a restart simply forces every open tab to fetch a fresh ticket.
    pub used_stream_tickets: Arc<Mutex<std::collections::HashMap<String, i64>>>,
    /// Pending CLI PKCE authorizations (gianna's `cli_auth_codes`) —
    /// in-memory for the same reason as the stream-ticket guard: a restart
    /// mid-login just means re-running `login`.
    pub cli_auth_codes: Arc<Mutex<CliAuthCodes>>,
    /// Supervised `kubectl port-forward`s for in-cluster resources. Held
    /// here so they live exactly as long as the daemon (or CLI scan) does.
    pub port_forwards: Arc<crate::targets::port_forward::PortForwards>,
    /// Who may see what (`crate::access`), shared with the policy layer.
    pub access: Arc<crate::access::Access>,
    /// The policy layer's audit writer (one writer keeps the chain
    /// serialized). `None` in fakes: access decisions are then only traced.
    pub audit: Option<Arc<crate::audit::AuditWriter>>,
}

impl AppState {
    /// Construct state from already-resolved pieces — the seam every wave
    /// integrates through (tests inject fakes for `policy`/`approved`/
    /// `ingest`; `main.rs` wires the real engine once Wave 2/3 modules are
    /// available to depend on). `secret_store` resolves `config.http.
    /// jwt_secret` (or the fakes-mode dev default) exactly once here.
    /// `config_path` must be the EXACT path the caller loaded (or intends
    /// to create) `config` from/at — `main.rs` passes what `Config::load`
    /// resolved; see the field's own doc comment for why this is a
    /// constructor parameter rather than derived internally.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        config_path: PathBuf,
        secret_store: &SecretStore,
        repos: Arc<dyn AllRepos>,
        policy: Arc<dyn PolicyExecute>,
        approved: Arc<dyn ExecuteApproved>,
        estop: Arc<EStop>,
        scheduler: SchedulerHandle,
    ) -> crate::Result<Self> {
        let jwt_secret: Arc<str> = config.resolve_jwt_secret(secret_store)?.into();
        let oidc = match (&config.auth.provider, &config.auth.oidc) {
            (crate::config::AuthProvider::Oidc, Some(o)) => {
                let secret =
                    o.client_secret.as_ref().map(|r| r.resolve(secret_store)).transpose()?;
                if let Some(s) = &secret {
                    crate::policy::Scrubber::global().register("OIDC_CLIENT_SECRET", s);
                }
                Some(Arc::new(crate::http::oidc::OidcClient::new(o, secret)?))
            }
            _ => None,
        };
        let webhook_secret = match &config.http.webhook_secret {
            Some(r) => Some(Arc::<str>::from(r.resolve(secret_store)?)),
            None => None,
        };
        let hanko = build_hanko(&config)?;
        let web = Arc::new(WebHub::new());
        let cost_guard = Arc::new(crate::llm::CostGuard::new(
            Arc::new(crate::llm::FakeLlm::new()),
            Arc::new(crate::llm::SpendMeter::new()),
            repos.clone(),
            config.limits.max_cost_per_day_cents,
        ));
        Ok(AppState {
            config: Arc::new(config),
            config_path,
            jwt_secret,
            webhook_secret,
            hanko,
            oidc,
            dispatch: None,
            repos,
            memory: Arc::new(crate::memory::Memory::disabled()),
            cost_guard,
            policy,
            approved,
            estop,
            scheduler,
            web: web.clone(),
            channel: web.clone(),
            named_channels: vec![web],
            ingest: Arc::new(NoopIngest),
            composer: Arc::new(NoopComposer),
            chat: Arc::new(NoopChat),
            listen_channels: Vec::new(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            tasks: tokio_util::task::TaskTracker::new(),
            turn_gate: crate::agent::turn_gate::TurnGate::new(),
            auth_limiter: Arc::new(RateLimiter::new(10, 60)),
            used_stream_tickets: Arc::new(Mutex::new(std::collections::HashMap::new())),
            cli_auth_codes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            port_forwards: Arc::new(crate::targets::port_forward::PortForwards::none()),
            access: Arc::new(crate::access::Access::solo()),
            audit: None,
        })
    }

    /// The fully-faked test/dev spine: an in-memory DB, a fail-closed
    /// policy stub (`policy::Policy::new` with no executors — every
    /// command blocks), a disengaged e-stop, and a fresh scheduler handle.
    /// Mirrors gianna's `AppState::new(Config::default())` fakes-mode
    /// boot — every external dependency is an in-process fake.
    pub fn fake() -> Self {
        Self::fake_with_config(Config::default())
    }

    /// As [`Self::fake`], with a caller-supplied config (e.g. a live
    /// `http.jwt_secret` under test). Does NOT use [`SecretStore`] at all —
    /// `tempfile` (the usual way tests get a throwaway directory) is a
    /// dev-dependency only, unavailable to this non-test-gated
    /// constructor, and a `Store`-backed secret has no meaning in a fake
    /// state anyway. Any `SecretRef::Env` value in `config` still resolves
    /// normally (env vars need no store); a `SecretRef::Store` value is
    /// unsupported here and falls back to [`crate::config::DEV_JWT_SECRET`]
    /// (fine — nothing in a fake state depends on the secret being real).
    pub fn fake_with_config(config: Config) -> Self {
        // A CONCRETE `InMemoryDb` handle, not the already-erased `Arc<dyn
        // AllRepos>`: `Policy::new`/`EStop::new` each want a narrower trait
        // object (`Arc<dyn ApprovalRepo>`, `Arc<dyn ControlRepo>`, …), and
        // Rust has no supertrait-to-unrelated-trait-object upcast from an
        // already-erased `dyn AllRepos` — only a concrete type unsizes to
        // each of those independently (see `policy::mod`'s own test rig,
        // which does exactly this with its own `Arc<InMemoryDb>`).
        let db = Arc::new(crate::db::memory::InMemoryDb::new());
        // A process-unique throwaway sentinel path (std-only, no tempfile
        // dependency needed): the e-stop file is never actually written
        // unless a test calls `estop.engage`, so collisions are harmless
        // even if two fake states happened to share a path.
        let sentinel =
            std::env::temp_dir().join(format!("opsclaw-fake-estop-{}", uuid::Uuid::new_v4()));
        let policy = Arc::new(crate::policy::Policy::new(
            Arc::new(config.clone()),
            std::collections::HashMap::new(),
            Arc::new(crate::audit::AuditWriter::new(db.clone())),
            Arc::new(EStop::new(sentinel.clone(), db.clone())),
            db.clone(),
            Arc::new(crate::policy::Scrubber::default()),
        ));
        let estop = Arc::new(EStop::new(sentinel, db.clone()));
        let jwt_secret: Arc<str> = resolve_jwt_secret_without_store(&config).into();
        // Infallible here for the same reason it is safe in `new`: building
        // the client is pure construction with no network I/O. A malformed
        // hanko config in a FAKE state degrades to "no provider wired"
        // rather than panicking a test rig.
        let hanko = build_hanko(&config).unwrap_or(None);
        let web = Arc::new(WebHub::new());
        let repos: Arc<dyn AllRepos> = db;
        // A per-instance, GUARANTEED-non-existent path under the system
        // temp dir — never `config::default_dir()`. This is the fix for
        // the incident in `config_path`'s doc comment: a fakes-mode config
        // write must be physically incapable of reaching a real machine's
        // `~/.opsclaw`, not just conventionally discouraged from it.
        let config_path = std::env::temp_dir()
            .join(format!("opsclaw-fake-config-{}", uuid::Uuid::new_v4()))
            .join("config.toml");
        let cost_guard = Arc::new(crate::llm::CostGuard::new(
            Arc::new(crate::llm::FakeLlm::new()),
            Arc::new(crate::llm::SpendMeter::new()),
            repos.clone(),
            config.limits.max_cost_per_day_cents,
        ));
        AppState {
            config: Arc::new(config),
            config_path,
            jwt_secret,
            webhook_secret: None,
            hanko,
            oidc: None,
            dispatch: None,
            repos,
            memory: Arc::new(crate::memory::Memory::disabled()),
            cost_guard,
            policy: policy.clone(),
            approved: policy,
            estop,
            scheduler: SchedulerHandle::new(60_000),
            web: web.clone(),
            channel: web.clone(),
            named_channels: vec![web],
            ingest: Arc::new(NoopIngest),
            composer: Arc::new(NoopComposer),
            chat: Arc::new(NoopChat),
            listen_channels: Vec::new(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            tasks: tokio_util::task::TaskTracker::new(),
            turn_gate: crate::agent::turn_gate::TurnGate::new(),
            auth_limiter: Arc::new(RateLimiter::new(10, 60)),
            used_stream_tickets: Arc::new(Mutex::new(std::collections::HashMap::new())),
            cli_auth_codes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            port_forwards: Arc::new(crate::targets::port_forward::PortForwards::none()),
            access: Arc::new(crate::access::Access::solo()),
            audit: None,
        }
    }

    /// The signed-in operator's display identity for an audit/approval
    /// principal — `Principal::Operator { account }`. A thin wrapper so
    /// call sites don't hand-construct the variant inconsistently.
    pub fn operator_principal(account_id: Uuid) -> crate::domain::Principal {
        crate::domain::Principal::Operator { account: account_id }
    }
}

/// Build the Hanko verifier when — and only when — the config selects that
/// provider. Kept out of both constructors' struct literals so the two can
/// never drift apart on which provider they honour.
fn build_hanko(config: &Config) -> crate::Result<Option<Arc<crate::http::hanko::HankoClient>>> {
    match config.auth.provider {
        crate::config::AuthProvider::Local | crate::config::AuthProvider::Oidc => Ok(None),
        crate::config::AuthProvider::Hanko => {
            Ok(Some(Arc::new(crate::http::hanko::HankoClient::new(&config.auth)?)))
        }
    }
}

/// Resolve `config.http.jwt_secret` for [`AppState::fake_with_config`]
/// without a [`SecretStore`] — env-backed refs still resolve normally;
/// unset or Store-backed refs fall back to the dev default (see that
/// function's doc comment for why this is fine for a fake state).
fn resolve_jwt_secret_without_store(config: &Config) -> String {
    match &config.http.jwt_secret {
        Some(crate::config::SecretRef::Env(name)) => {
            std::env::var(name).unwrap_or_else(|_| crate::config::DEV_JWT_SECRET.to_string())
        }
        _ => crate::config::DEV_JWT_SECRET.to_string(),
    }
}
