//! Configuration: TOML at `~/.opsclaw/config.toml` + env overlay, and the
//! encrypted secret store.
//!
//! Gianna patterns kept: real-when-credential-set (else clearly-logged fake),
//! `validate()` fails hard before bind on dangerous misconfig, and nothing
//! that fails open. Structural improvement over gianna: `Config` holds
//! [`SecretRef`]s (names), never values — a `{:?}` of Config cannot leak a
//! credential because the value was never there. Values are resolved at
//! connect time and registered with the output scrubber (policy layer).

mod secrets;

pub use secrets::{SecretRef, SecretStore};

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::{Autonomy, ExpectedState, ResourceType, TargetKind};
use crate::{Error, Result};

/// Default config directory: `~/.opsclaw`.
pub fn default_dir() -> PathBuf {
    std::env::var_os("OPSCLAW_HOME").map(PathBuf::from).unwrap_or_else(|| {
        let home =
            std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.join(".opsclaw")
    })
}

/// The default config file location (`<default_dir>/config.toml`) — the
/// exact path `Config::load(None)` reads, exposed so boot wiring can hand
/// `AppState.config_path` the same file it loaded.
pub fn default_config_path() -> PathBuf {
    default_dir().join("config.toml")
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub daemon: DaemonCfg,
    pub http: HttpCfg,
    pub llm: LlmCfg,
    pub memory: MemoryCfg,
    pub telegram: TelegramCfg,
    pub push: PushCfg,
    pub webhook_out: WebhookOutCfg,
    pub limits: LimitsCfg,
    pub policy: PolicyCfg,
    pub escalation: EscalationCfg,
    #[serde(rename = "project")]
    pub projects: Vec<ProjectCfg>,
}

/// Escalation contact chain (brief §6, DESIGN §4 Incidents): ordered
/// `[[escalation.step]]` entries — notify step 0, wait `ack_timeout_minutes`
/// for an ack (re-notifying every `repeat_interval_minutes` meanwhile), then
/// escalate to the next step; a chain exhausted unacknowledged expires the
/// incident. With NO steps configured, [`EscalationCfg::chain`] falls back
/// to a single broadcast step (every channel, 60m ack window, 20m
/// re-notify) — a deployment with no chain configured must still page
/// SOMEWHERE rather than sit silent on a corroborated fault.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct EscalationCfg {
    #[serde(rename = "step")]
    pub steps: Vec<EscalationStepCfg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationStepCfg {
    /// Which channel this step pages: a `Channel::name()` string
    /// ("telegram", "web", "webhook", "push"), or "*" to broadcast on every
    /// configured channel. An unknown name falls back to broadcast with a
    /// boot warning rather than paging nobody.
    pub contact: String,
    pub ack_timeout_minutes: i64,
    pub repeat_interval_minutes: i64,
}

/// The broadcast contact name understood by the scheduler's escalation
/// driver: fan out on every configured channel.
pub const ESCALATION_BROADCAST: &str = "*";

impl EscalationCfg {
    /// The runtime chain: configured steps, or the loud single-step
    /// broadcast default when none are declared (see the struct doc).
    pub fn chain(&self) -> crate::incidents::EscalationChain {
        use crate::incidents::{EscalationChain, EscalationStep};
        if self.steps.is_empty() {
            return EscalationChain::new(vec![EscalationStep {
                contact: ESCALATION_BROADCAST.into(),
                ack_timeout: chrono::Duration::minutes(60),
                repeat_interval: chrono::Duration::minutes(20),
            }]);
        }
        EscalationChain::new(
            self.steps
                .iter()
                .map(|s| EscalationStep {
                    contact: s.contact.clone(),
                    ack_timeout: chrono::Duration::minutes(s.ack_timeout_minutes),
                    repeat_interval: chrono::Duration::minutes(s.repeat_interval_minutes),
                })
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonCfg {
    pub listen: String,
    /// SQLite database path; `:memory:`-style ephemeral DBs are test-only.
    pub db_path: Option<PathBuf>,
    /// Base heartbeat tick in seconds; the scheduler tightens it adaptively
    /// while incidents are active.
    pub tick_seconds: u64,
    /// External dead-man receiver pinged every tick (DESIGN §4). Optional in
    /// adjacent placements, mandatory in-cluster.
    pub deadman_url: Option<String>,
    /// Where `runbook init/list/show` and `runbooks::RunbookStore` look for
    /// runbook markdown files. Defaults to `<opsclaw_home>/runbooks` (the
    /// convention `cli::runbook_cmd` already used before this field
    /// existed) — additive field, no migration needed for an existing
    /// config file (absent = the same default it always resolved to).
    pub runbooks_dir: PathBuf,
    /// Workspace root for the daemon-local `file_read`/`file_write` tools
    /// (brief §10 "file read/write (workspace-bounded)", §5's
    /// "workspace-only file ops" policy bound). `None` resolves to
    /// `<opsclaw_home>/workspace` at runtime ([`DaemonCfg::workspace_root`])
    /// — additive field, no migration needed for an existing config file
    /// (absent = the default it would always have resolved to).
    pub workspace_dir: Option<PathBuf>,
}

impl DaemonCfg {
    /// The resolved workspace root: the configured `workspace_dir`, else
    /// `<opsclaw_home>/workspace` — the same `default_dir()`-anchored
    /// defaulting convention as `runbooks_dir`, resolved at call time (not
    /// in `Default`) so the field stays `Option` and an absent config line
    /// round-trips as absent.
    pub fn workspace_root(&self) -> PathBuf {
        self.workspace_dir.clone().unwrap_or_else(|| default_dir().join("workspace"))
    }
}

impl Default for DaemonCfg {
    fn default() -> Self {
        DaemonCfg {
            listen: "127.0.0.1:8484".into(),
            db_path: None,
            tick_seconds: 300,
            deadman_url: None,
            runbooks_dir: default_dir().join("runbooks"),
            workspace_dir: None,
        }
    }
}

/// HTTP gateway config (Wave 4, `src/http/`, DESIGN.md §3 "HTTP gateway"):
/// the operator-auth signing secret and the inbound webhook (Alertmanager/
/// PagerDuty) verification secret. Gianna pattern ported: a placeholder or
/// too-short `jwt_secret` refuses to boot in live mode (`validate()`), never
/// silently signs sessions with a guessable key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpCfg {
    /// HS256 JWT signing secret for operator sessions (cookie) and scoped
    /// tokens (SSE stream tickets, CLI PKCE exchange). `None` resolves to
    /// [`DEV_JWT_SECRET`] at connect time — fine in fakes mode, refused by
    /// `validate()` outside it — never generated randomly per-boot, which
    /// would invalidate every session on every restart.
    pub jwt_secret: Option<SecretRef>,
    /// Shared secret for verifying inbound webhook signatures
    /// (Alertmanager/PagerDuty, DESIGN.md §3: "HMAC/token verification with
    /// constant-time compare"). `None` refuses every webhook in live mode;
    /// in fakes mode an unconfigured secret is accepted (there is no real
    /// sender to spoof in a fully-faked daemon).
    pub webhook_secret: Option<SecretRef>,
    /// Whether the session cookie carries the `Secure` attribute. Gianna
    /// derives this from the app origin being `https://`; opsclaw has no
    /// configured public origin (DESIGN §3: reached via VPN/tunnel, TLS is
    /// the norm but not detectable from config alone), so it is an explicit
    /// flag defaulting to `true` (fail toward MORE secure) — an operator
    /// running plain http in dev sets this false so the browser will still
    /// send the cookie.
    pub cookies_secure: bool,
}

impl Default for HttpCfg {
    fn default() -> Self {
        HttpCfg { jwt_secret: None, webhook_secret: None, cookies_secure: true }
    }
}

/// The insecure placeholder JWT secret used only when fully faked (no real
/// session could matter). `validate()` refuses to boot with this secret
/// outside fakes mode — mirrors gianna's `dev-insecure-secret-change-me`
/// (`config.rs`), same string convention so an operator recognizes the
/// pattern if they've seen gianna's before.
pub const DEV_JWT_SECRET: &str = "dev-insecure-secret-change-me";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct LlmCfg {
    /// API key reference. Shipped default resolves from `env:OPENROUTER_API_KEY`
    /// when that variable is set (see [`Config::load`]). Absent ⇒ FakeLlm.
    pub api_key: Option<SecretRef>,
    /// Ordered model list for OpenRouter's server-side fallback. Required when
    /// `api_key` is set — gianna's lesson: a key with no models silently 400s
    /// every call, so validate() refuses it.
    pub models: Vec<String>,
    /// Base URL override (OpenRouter default; any OpenAI-compatible endpoint).
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MemoryCfg {
    /// Hindsight base URL. Live mode refuses to boot without it (memory is a
    /// core promise); absent in fakes mode ⇒ honest no-op.
    pub hindsight_url: Option<String>,
    /// Identifies this team's Hindsight bank (`opsclaw-{team_id}`). OpsClaw is
    /// single-tenant (DESIGN §1: "no tenancy ids thread through the code"), so
    /// this exists only to namespace the bank when a Hindsight instance is
    /// shared across multiple team daemons; a lone daemon never needs to set
    /// it. Defaults to "default".
    pub team_id: String,
}

impl Default for MemoryCfg {
    fn default() -> Self {
        MemoryCfg { hindsight_url: None, team_id: "default".to_string() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TelegramCfg {
    pub bot_token: Option<SecretRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct PushCfg {
    pub vapid_private_key: Option<SecretRef>,
    pub vapid_public_key: Option<String>,
}

/// Outbound escalation webhook (DESIGN §7 decision 5: with Telegram, one of
/// the two GUARANTEED escalation paths — push is best-effort). Every
/// outbound team message is POSTed to `url`; `secret` optionally signs
/// deliveries with the same `t=<ts>,v1=<hex>` scheme the inbound webhook
/// verifies (`channels::webhook_out`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct WebhookOutCfg {
    pub url: Option<String>,
    pub secret: Option<SecretRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsCfg {
    pub max_actions_per_hour: u32,
    pub max_cost_per_day_cents: u32,
}

impl Default for LimitsCfg {
    fn default() -> Self {
        // Conservative defaults; 0 is NOT "unlimited" anywhere in opsclaw —
        // 0 means "no actions"/"no spend" (failing closed, not open).
        LimitsCfg { max_actions_per_hour: 30, max_cost_per_day_cents: 500 }
    }
}

/// Policy bounds beyond autonomy levels (brief §5: "forbidden paths, command
/// allowlists ... per-tool/per-runbook auto_approve and always_ask lists tune
/// the middle levels"). All lists default EMPTY — an empty list changes
/// nothing (except `command_allowlist`, whose non-empty form is the
/// fail-closed switch: once anything is listed, only listed mutations run).
///
/// `auto_approve`/`always_ask` entries match a command by one of three forms:
/// - `"<tool>"` — every command composed by that tool;
/// - `"<tool>:<needle>"` — that tool's commands containing `<needle>`;
/// - `"runbook:<title>"` — commands the code-side matcher attributed to that
///   runbook (`CommandRequest.runbook`, never model-supplied).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyCfg {
    /// Pre-approvals: a matching MEDIUM-risk command executes at `suggest`/
    /// `act_on_known` without queueing a human. Deliberately capped at
    /// Medium — High/Destructive never ride a config list past a human
    /// (the same "never silently toward more autonomy" direction as the
    /// rest of validate()).
    pub auto_approve: Vec<String>,
    /// The reverse tuning: a matching mutation ALWAYS queues for approval,
    /// even at `auto` or with a runbook match. Wins over `auto_approve`
    /// when both match (deny beats allow).
    pub always_ask: Vec<String>,
    /// When NON-empty: every mutation must match an entry (same three forms)
    /// or it is blocked outright. Empty = no allowlist. Reads are exempt —
    /// an allowlist is about what may CHANGE, not what may be looked at.
    pub command_allowlist: Vec<String>,
    /// Path prefixes no command line may mention, at ANY autonomy level —
    /// hard-blocked like the destructive-pattern list. Plain substring
    /// match on the composed line (blunt on purpose: false-positive on a
    /// path in a grep pattern is a safe failure; a missed rm under a
    /// creative quoting is not).
    pub forbidden_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCfg {
    pub name: String,
    pub autonomy: Option<Autonomy>,
    #[serde(rename = "env", default)]
    pub envs: Vec<EnvCfg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvCfg {
    pub name: String,
    pub autonomy: Option<Autonomy>,
    pub expected_state: Option<ExpectedState>,
    #[serde(rename = "target", default)]
    pub targets: Vec<TargetCfg>,
}

/// Config-file spelling of the target kind: a plain `kind` string with
/// optional `provider`/`region` fields, kept flat because serde's `flatten`
/// is incompatible with `deny_unknown_fields` — and typo protection on
/// target tables matters more than a nested enum in TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKindName {
    Ssh,
    Local,
    Kubernetes,
    Cloud,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCfg {
    pub name: String,
    pub kind: TargetKindName,
    /// Required when `kind = "cloud"`.
    pub provider: Option<crate::domain::CloudProvider>,
    pub region: Option<String>,
    pub autonomy: Option<Autonomy>,
    pub expected_state: Option<ExpectedState>,
    /// Connection credential (ssh key, kubeconfig, cloud credential) by
    /// reference. Required for every kind except `local`. Never inherited.
    pub credential: Option<SecretRef>,
    /// Connection address: host for ssh (`[user@]host` — ssh accepts the
    /// user inline), context hint for kubernetes, etc.
    pub address: Option<String>,
    /// Optional bastion/jump host for ssh targets, `[user@]host[:port]`
    /// form (ssh `-J`). DESIGN §4 targets: remundo's estate sits behind an
    /// Azure Bastion jumpbox — this is how a target declares it.
    pub jump_host: Option<String>,
    /// `kind = "ssh"` only: non-standard port. `None` lets the system `ssh`
    /// binary fall back to its own default (22, or whatever `~/.ssh/config`
    /// says for the host) — most real targets never need this, but a
    /// jumpbox-fronted or containerized target (Tier 2's sim harness maps
    /// sshd to a random host port) does. Ignored for every other kind.
    pub ssh_port: Option<u16>,
    /// `kind = "ssh"` only: remote login user. `None` lets the system `ssh`
    /// binary fall back to its own default (the invoking user, or whatever
    /// `~/.ssh/config` says for the host) — most real targets configure this
    /// via `~/.ssh/config` or an ssh-agent identity that already implies the
    /// right user, but a containerized target whose `authorized_keys` is
    /// installed for a specific account (Tier 2's sim harness: `root`, since
    /// that's the only account in the target image) needs to say so
    /// explicitly rather than silently trying as whatever account is running
    /// the daemon. Ignored for every other kind.
    pub ssh_user: Option<String>,
    /// `kind = "ssh"` only: path to a target-specific known_hosts file
    /// (`targets::ssh::SshParams::known_hosts_path` doc: "per-target, not
    /// the operator's personal file"). `None` uses ssh's own default lookup.
    pub ssh_known_hosts_path: Option<PathBuf>,
    /// `kind = "ssh"` only: overrides `StrictHostKeyChecking`. Defaults to
    /// `None`, which `SshParams`/`SshExecutor` resolve to `"yes"` — the safe
    /// default for every real target. The one legitimate reason to set this
    /// is a throwaway target whose host key is genuinely new on every run
    /// (Tier 2's sim harness: a fresh container, fresh host key, every
    /// invocation) — `"accept-new"` there, never a blanket `"no"` default
    /// baked into code (that would defeat known_hosts pinning for every
    /// target, not just ephemeral ones).
    pub ssh_strict_host_key_checking: Option<String>,
    #[serde(rename = "resource", default)]
    pub resources: Vec<ResourceCfg>,
}

impl TargetCfg {
    /// Assemble the domain [`TargetKind`], failing on a cloud target with no
    /// provider (validated at boot, not at first use).
    pub fn target_kind(&self) -> Result<TargetKind> {
        match self.kind {
            TargetKindName::Ssh => Ok(TargetKind::Ssh),
            TargetKindName::Local => Ok(TargetKind::Local),
            TargetKindName::Kubernetes => Ok(TargetKind::Kubernetes),
            TargetKindName::Cloud => match self.provider {
                Some(provider) => Ok(TargetKind::Cloud { provider, region: self.region.clone() }),
                None => Err(Error::Config(format!(
                    "target {:?} is kind=cloud but has no provider",
                    self.name
                ))),
            },
        }
    }
}

/// One declared resource, typed PER KIND (brief §4): each variant carries
/// exactly the fields that kind of resource can use, so an ArgoCD
/// declaration cannot silently carry an ES-only `username` and a missing
/// required field (`url`, ArgoCD's `credential`) is a parse-time error
/// naming the resource — not a boot-time warning three modules later.
///
/// The TOML shape is unchanged (`type = "..."` is the tag, same field names
/// as ever): parsing goes through the flat [`RawResourceCfg`], which keeps
/// `deny_unknown_fields` — serde's internally-tagged enums silently swallow
/// unknown fields, which is exactly what a config typo must not do — and
/// [`TryFrom`] then enforces the per-kind shape.
#[derive(Debug, Clone)]
pub enum ResourceCfg {
    Elasticsearch(EsResourceCfg),
    Prometheus(PromResourceCfg),
    Argocd(ArgocdResourceCfg),
    Eventstore(EventstoreResourceCfg),
    AzureServiceBus(AsbResourceCfg),
    /// A declared resource whose tool is still a trait stub (postgres,
    /// rabbitmq, cloudflare, github, pagerduty, loki, jaeger, sentry,
    /// posthog — DESIGN §7 decision 7). Declarable ahead of the tool with
    /// the permissive flat shape; each gets its own variant when its tool
    /// is actually built and the real connection shape is known.
    Stub(StubResourceCfg),
}

/// Elasticsearch (brief: remundo ships logs via Filebeat into ES). Auth is
/// either basic (`username` + `credential` as the password — ECK's
/// operator-generated `elastic` user) or bearer/API key (`username` unset).
#[derive(Debug, Clone)]
pub struct EsResourceCfg {
    pub name: String,
    pub url: String,
    /// Set ⇒ HTTP basic auth with `credential` as the password. Unset ⇒
    /// `credential` (if any) is a bearer token / API key.
    pub username: Option<String>,
    pub credential: Option<SecretRef>,
    /// Extra trusted root CA (PEM file path) for this resource only — an
    /// in-cluster ECK Elasticsearch presents a self-signed CA that must not
    /// pollute global trust.
    pub ca_cert_path: Option<PathBuf>,
    /// Disable certificate verification for THIS resource. Loudly warned at
    /// boot; acceptable only for a localhost port-forward hop where the
    /// hostname can never match the cert. Never a default.
    pub insecure_tls: bool,
}

/// Prometheus. The server itself is unauthenticated; a reverse proxy in
/// front adds basic auth (`username` set) or a bearer token (`username`
/// unset) — both optional because plain in-cluster HTTP is the common case.
#[derive(Debug, Clone)]
pub struct PromResourceCfg {
    pub name: String,
    pub url: String,
    pub username: Option<String>,
    pub credential: Option<SecretRef>,
    pub ca_cert_path: Option<PathBuf>,
    pub insecure_tls: bool,
}

/// ArgoCD. Auth is always an API bearer token (`argocd account
/// generate-token`), so `credential` is REQUIRED and there is no username.
#[derive(Debug, Clone)]
pub struct ArgocdResourceCfg {
    pub name: String,
    pub url: String,
    pub credential: SecretRef,
    pub ca_cert_path: Option<PathBuf>,
    pub insecure_tls: bool,
}

/// EventStore/KurrentDB. Basic auth (`admin` + password) is the norm;
/// both optional because a dev-mode `--insecure` node has no auth at all.
#[derive(Debug, Clone)]
pub struct EventstoreResourceCfg {
    pub name: String,
    pub url: String,
    pub username: Option<String>,
    pub credential: Option<SecretRef>,
    pub ca_cert_path: Option<PathBuf>,
    pub insecure_tls: bool,
}

/// Azure Service Bus. `url` is the namespace endpoint
/// (`https://<ns>.servicebus.windows.net`), `credential` a SAS token by
/// reference — REQUIRED, Service Bus has no anonymous access. No TLS knobs:
/// the endpoint always presents a real, publicly-trusted Azure certificate.
#[derive(Debug, Clone)]
pub struct AsbResourceCfg {
    pub name: String,
    pub url: String,
    pub credential: SecretRef,
}

/// The permissive flat shape for stub-tool resource types (see
/// [`ResourceCfg::Stub`]).
#[derive(Debug, Clone)]
pub struct StubResourceCfg {
    pub rtype: ResourceType,
    pub name: String,
    pub url: Option<String>,
    pub credential: Option<SecretRef>,
    pub username: Option<String>,
    pub ca_cert_path: Option<PathBuf>,
    pub insecure_tls: bool,
}

/// Borrowed connection view over any URL-backed resource — what the
/// endpoint registry and executor wiring actually consume, so those loops
/// stay one arm instead of six. `None` when the resource has no URL to
/// speak to (only possible for [`ResourceCfg::Stub`]; every built-out kind
/// requires `url` at parse time).
#[derive(Debug, Clone, Copy)]
pub struct EndpointCfg<'a> {
    pub url: &'a str,
    pub credential: Option<&'a SecretRef>,
    pub username: Option<&'a str>,
    pub ca_cert_path: Option<&'a Path>,
    pub insecure_tls: bool,
}

impl ResourceCfg {
    pub fn rtype(&self) -> ResourceType {
        match self {
            Self::Elasticsearch(_) => ResourceType::Elasticsearch,
            Self::Prometheus(_) => ResourceType::Prometheus,
            Self::Argocd(_) => ResourceType::Argocd,
            Self::Eventstore(_) => ResourceType::Eventstore,
            Self::AzureServiceBus(_) => ResourceType::AzureServiceBus,
            Self::Stub(s) => s.rtype,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Elasticsearch(r) => &r.name,
            Self::Prometheus(r) => &r.name,
            Self::Argocd(r) => &r.name,
            Self::Eventstore(r) => &r.name,
            Self::AzureServiceBus(r) => &r.name,
            Self::Stub(r) => &r.name,
        }
    }

    /// The declared credential reference, if any (doctor resolves these).
    pub fn credential(&self) -> Option<&SecretRef> {
        match self {
            Self::Elasticsearch(r) => r.credential.as_ref(),
            Self::Prometheus(r) => r.credential.as_ref(),
            Self::Argocd(r) => Some(&r.credential),
            Self::Eventstore(r) => r.credential.as_ref(),
            Self::AzureServiceBus(r) => Some(&r.credential),
            Self::Stub(r) => r.credential.as_ref(),
        }
    }

    /// Uniform connection view for wiring/registry code. See [`EndpointCfg`].
    pub fn endpoint(&self) -> Option<EndpointCfg<'_>> {
        match self {
            Self::Elasticsearch(r) => Some(EndpointCfg {
                url: &r.url,
                credential: r.credential.as_ref(),
                username: r.username.as_deref(),
                ca_cert_path: r.ca_cert_path.as_deref(),
                insecure_tls: r.insecure_tls,
            }),
            Self::Prometheus(r) => Some(EndpointCfg {
                url: &r.url,
                credential: r.credential.as_ref(),
                username: r.username.as_deref(),
                ca_cert_path: r.ca_cert_path.as_deref(),
                insecure_tls: r.insecure_tls,
            }),
            Self::Argocd(r) => Some(EndpointCfg {
                url: &r.url,
                credential: Some(&r.credential),
                username: None,
                ca_cert_path: r.ca_cert_path.as_deref(),
                insecure_tls: r.insecure_tls,
            }),
            Self::Eventstore(r) => Some(EndpointCfg {
                url: &r.url,
                credential: r.credential.as_ref(),
                username: r.username.as_deref(),
                ca_cert_path: r.ca_cert_path.as_deref(),
                insecure_tls: r.insecure_tls,
            }),
            Self::AzureServiceBus(r) => Some(EndpointCfg {
                url: &r.url,
                credential: Some(&r.credential),
                username: None,
                ca_cert_path: None,
                insecure_tls: false,
            }),
            Self::Stub(r) => r.url.as_deref().map(|url| EndpointCfg {
                url,
                credential: r.credential.as_ref(),
                username: r.username.as_deref(),
                ca_cert_path: r.ca_cert_path.as_deref(),
                insecure_tls: r.insecure_tls,
            }),
        }
    }

    fn to_raw(&self) -> RawResourceCfg {
        let rtype = self.rtype();
        match self {
            Self::Elasticsearch(EsResourceCfg {
                name,
                url,
                username,
                credential,
                ca_cert_path,
                insecure_tls,
            })
            | Self::Prometheus(PromResourceCfg {
                name,
                url,
                username,
                credential,
                ca_cert_path,
                insecure_tls,
            })
            | Self::Eventstore(EventstoreResourceCfg {
                name,
                url,
                username,
                credential,
                ca_cert_path,
                insecure_tls,
            }) => RawResourceCfg {
                rtype,
                name: name.clone(),
                url: Some(url.clone()),
                credential: credential.clone(),
                username: username.clone(),
                ca_cert_path: ca_cert_path.clone(),
                insecure_tls: *insecure_tls,
            },
            Self::Argocd(r) => RawResourceCfg {
                rtype,
                name: r.name.clone(),
                url: Some(r.url.clone()),
                credential: Some(r.credential.clone()),
                username: None,
                ca_cert_path: r.ca_cert_path.clone(),
                insecure_tls: r.insecure_tls,
            },
            Self::AzureServiceBus(r) => RawResourceCfg {
                rtype,
                name: r.name.clone(),
                url: Some(r.url.clone()),
                credential: Some(r.credential.clone()),
                username: None,
                ca_cert_path: None,
                insecure_tls: false,
            },
            Self::Stub(r) => RawResourceCfg {
                rtype: r.rtype,
                name: r.name.clone(),
                url: r.url.clone(),
                credential: r.credential.clone(),
                username: r.username.clone(),
                ca_cert_path: r.ca_cert_path.clone(),
                insecure_tls: r.insecure_tls,
            },
        }
    }
}

/// The on-disk (TOML) shape of a resource — a superset of every kind's
/// fields, kept PRIVATE so all construction funnels through the per-kind
/// validation in `TryFrom`. `deny_unknown_fields` lives here because it
/// cannot live on an internally-tagged enum (serde buffers the content and
/// ignores strays — a typo'd key would vanish silently).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResourceCfg {
    #[serde(rename = "type")]
    rtype: ResourceType,
    name: String,
    url: Option<String>,
    credential: Option<SecretRef>,
    username: Option<String>,
    ca_cert_path: Option<PathBuf>,
    #[serde(default)]
    insecure_tls: bool,
}

impl TryFrom<RawResourceCfg> for ResourceCfg {
    type Error = String;

    fn try_from(raw: RawResourceCfg) -> std::result::Result<Self, String> {
        let RawResourceCfg { rtype, name, url, credential, username, ca_cert_path, insecure_tls } =
            raw;

        fn required(rtype: ResourceType, name: &str, field: &str, why: &str) -> String {
            format!("{rtype} resource {name:?} has no `{field}` — {why}")
        }
        fn unused(rtype: ResourceType, name: &str, field: &str, why: &str) -> String {
            format!("{rtype} resource {name:?}: `{field}` is not used by {rtype} resources — {why}")
        }
        let need_url = |why: &str| {
            url.clone().ok_or_else(|| required(rtype, &name, "url", why))
        };

        match rtype {
            ResourceType::Elasticsearch => {
                let url = need_url("the base url (e.g. https://localhost:9201) is how the tool reaches it")?;
                Ok(Self::Elasticsearch(EsResourceCfg {
                    name,
                    url,
                    username,
                    credential,
                    ca_cert_path,
                    insecure_tls,
                }))
            }
            ResourceType::Prometheus => {
                let url = need_url("the base url (e.g. http://localhost:9090) is how the tool reaches it")?;
                Ok(Self::Prometheus(PromResourceCfg {
                    name,
                    url,
                    username,
                    credential,
                    ca_cert_path,
                    insecure_tls,
                }))
            }
            ResourceType::Eventstore => {
                let url = need_url("the HTTP API url (e.g. https://esdb.example:2113) is how the tool reaches it")?;
                Ok(Self::Eventstore(EventstoreResourceCfg {
                    name,
                    url,
                    username,
                    credential,
                    ca_cert_path,
                    insecure_tls,
                }))
            }
            ResourceType::Argocd => {
                if username.is_some() {
                    return Err(unused(
                        rtype,
                        &name,
                        "username",
                        "ArgoCD auth is a bearer token; set `credential` only",
                    ));
                }
                let url = need_url("the API url (e.g. https://argocd.example) is how the tool reaches it")?;
                let credential = credential.ok_or_else(|| {
                    required(
                        rtype,
                        &name,
                        "credential",
                        "the ArgoCD API requires a token (`argocd account generate-token`), by reference",
                    )
                })?;
                Ok(Self::Argocd(ArgocdResourceCfg {
                    name,
                    url,
                    credential,
                    ca_cert_path,
                    insecure_tls,
                }))
            }
            ResourceType::AzureServiceBus => {
                if username.is_some() {
                    return Err(unused(
                        rtype,
                        &name,
                        "username",
                        "Service Bus auth is a SAS token; set `credential` only",
                    ));
                }
                if ca_cert_path.is_some() {
                    return Err(unused(
                        rtype,
                        &name,
                        "ca_cert_path",
                        "the namespace endpoint presents a publicly-trusted Azure certificate",
                    ));
                }
                if insecure_tls {
                    return Err(unused(
                        rtype,
                        &name,
                        "insecure_tls",
                        "the namespace endpoint presents a publicly-trusted Azure certificate",
                    ));
                }
                let url = need_url("the namespace endpoint, e.g. https://<ns>.servicebus.windows.net")?;
                let credential = credential.ok_or_else(|| {
                    required(
                        rtype,
                        &name,
                        "credential",
                        "Service Bus has no anonymous access — a SAS token by reference",
                    )
                })?;
                Ok(Self::AzureServiceBus(AsbResourceCfg { name, url, credential }))
            }
            // Everything else is a stub tool: keep the permissive shape.
            _ => Ok(Self::Stub(StubResourceCfg {
                rtype,
                name,
                url,
                credential,
                username,
                ca_cert_path,
                insecure_tls,
            })),
        }
    }
}

impl<'de> Deserialize<'de> for ResourceCfg {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawResourceCfg::deserialize(deserializer)?;
        ResourceCfg::try_from(raw).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ResourceCfg {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_raw().serialize(serializer)
    }
}

impl Config {
    /// Load from a TOML file (if present) then apply the env overlay. With no
    /// file and no env, the result is the fully-faked configuration that
    /// boots the self-validating daemon (gianna's fakes mode).
    pub fn load(path: Option<&Path>) -> Result<Config> {
        let default_path = default_config_path();
        let path = path.unwrap_or(&default_path);
        let mut cfg: Config = if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            toml::from_str(&raw).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?
        } else {
            Config::default()
        };
        cfg.apply_env_overlay();
        Ok(cfg)
    }

    /// Env vars override/fill file config. Only *references* are recorded —
    /// the values stay in the environment until connect-time resolution.
    fn apply_env_overlay(&mut self) {
        if std::env::var_os("OPENROUTER_API_KEY").is_some() && self.llm.api_key.is_none() {
            self.llm.api_key = Some(SecretRef::env("OPENROUTER_API_KEY"));
        }
        if let Ok(models) = std::env::var("OPSCLAW_MODELS") {
            if !models.trim().is_empty() {
                self.llm.models = models.split(',').map(|m| m.trim().to_string()).collect();
            }
        }
        if let Ok(url) = std::env::var("HINDSIGHT_URL") {
            if !url.trim().is_empty() {
                self.memory.hindsight_url = Some(url);
            }
        }
        if std::env::var_os("TELEGRAM_BOT_TOKEN").is_some() && self.telegram.bot_token.is_none() {
            self.telegram.bot_token = Some(SecretRef::env("TELEGRAM_BOT_TOKEN"));
        }
        if let Ok(listen) = std::env::var("OPSCLAW_LISTEN") {
            if !listen.trim().is_empty() {
                self.daemon.listen = listen;
            }
        }
    }

    /// True when every external dependency would be a fake (no credentials at
    /// all). Gates the live-mode validations.
    pub fn fully_faked(&self) -> bool {
        self.llm.api_key.is_none()
            && self.memory.hindsight_url.is_none()
            && self.telegram.bot_token.is_none()
    }

    /// Resolve `http.jwt_secret`, falling back to [`DEV_JWT_SECRET`] when
    /// unset. Callers in live mode must not reach an unset secret at all —
    /// `validate()` refuses to boot before this is ever called — so the
    /// fallback only fires in fakes mode, where no real session matters.
    /// Additionally refuses (even past `validate()`, defence in depth) a
    /// resolved value that is the placeholder or under 32 bytes outside
    /// fakes mode, since a `Store`-backed secret isn't checkable until now.
    pub fn resolve_jwt_secret(&self, store: &SecretStore) -> Result<String> {
        let secret = match &self.http.jwt_secret {
            Some(r) => r.resolve(store)?,
            None => DEV_JWT_SECRET.to_string(),
        };
        if !self.fully_faked() {
            if secret == DEV_JWT_SECRET {
                return Err(Error::Config(
                    "http.jwt_secret resolved to the insecure default — set a strong secret \
                     before deploying"
                        .into(),
                ));
            }
            if secret.len() < 32 {
                return Err(Error::Config(
                    "http.jwt_secret is too short — use at least 32 characters, e.g. \
                     `openssl rand -base64 48`"
                        .into(),
                ));
            }
        }
        Ok(secret)
    }

    /// Effective autonomy for a target, resolved down the tree
    /// (target > env > project); absent everywhere ⇒ `Suggest` (the default
    /// for new targets, brief §5).
    pub fn autonomy_for(&self, project: &str, env: &str, target: &str) -> Autonomy {
        let p = self.projects.iter().find(|p| p.name == project);
        let e = p.and_then(|p| p.envs.iter().find(|e| e.name == env));
        let t = e.and_then(|e| e.targets.iter().find(|t| t.name == target));
        t.and_then(|t| t.autonomy)
            .or(e.and_then(|e| e.autonomy))
            .or(p.and_then(|p| p.autonomy))
            .unwrap_or(Autonomy::Suggest)
    }

    /// Effective expected state for a target (target > env; default
    /// `Running`). DESIGN §3 Config: an intentionally-stopped or ephemeral
    /// target (remundo's sandbox goes NXDOMAIN when stopped, and is wiped
    /// monthly) must be reasoned about as a STATE, not an outage — the
    /// dispatch layer threads this into the agent's team context so an
    /// unreachable expected-stopped target doesn't page.
    pub fn expected_state_for(&self, project: &str, env: &str, target: &str) -> ExpectedState {
        let p = self.projects.iter().find(|p| p.name == project);
        let e = p.and_then(|p| p.envs.iter().find(|e| e.name == env));
        let t = e.and_then(|e| e.targets.iter().find(|t| t.name == target));
        t.and_then(|t| t.expected_state)
            .or(e.and_then(|e| e.expected_state))
            .unwrap_or(ExpectedState::Running)
    }

    /// Resolve an operator-typed target string with unambiguous-prefix
    /// fallbacks (brief §4: "`opsclaw ssh web-1` works if there's only one
    /// project/env"). Accepted forms, `::`- or `/`-separated: the full
    /// `project::env::target`, `env::target`, or a bare `target` name —
    /// each resolves iff it matches EXACTLY one configured target; zero
    /// matches list every valid path, several list the ambiguous
    /// candidates so the operator can type one more segment.
    pub fn resolve_target_str(&self, s: &str) -> Result<crate::domain::FqTarget> {
        let s = s.trim();
        let parts: Vec<&str> = if s.contains("::") {
            s.split("::").collect()
        } else {
            s.split('/').collect()
        };
        let mut matches: Vec<(&str, &str, &str)> = Vec::new();
        let mut all: Vec<String> = Vec::new();
        for p in &self.projects {
            for e in &p.envs {
                for t in &e.targets {
                    all.push(format!("{}::{}::{}", p.name, e.name, t.name));
                    let hit = match parts.as_slice() {
                        [t1] => t.name == *t1,
                        [e1, t1] => e.name == *e1 && t.name == *t1,
                        [p1, e1, t1] => p.name == *p1 && e.name == *e1 && t.name == *t1,
                        _ => false,
                    };
                    if hit {
                        matches.push((&p.name, &e.name, &t.name));
                    }
                }
            }
        }
        match matches.as_slice() {
            [(p, e, t)] => Ok(crate::domain::FqTarget::new(*p, *e, *t)),
            [] => Err(Error::validation(format!(
                "no configured target matches {s:?} — configured targets: {}",
                if all.is_empty() { "(none)".to_string() } else { all.join(", ") }
            ))),
            several => Err(Error::validation(format!(
                "{s:?} is ambiguous — type more of the path: {}",
                several
                    .iter()
                    .map(|(p, e, t)| format!("{p}::{e}::{t}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// Loud refusal to boot on dangerous misconfig. Everything here fails
    /// CLOSED: nothing silently degrades toward more autonomy, more spend, or
    /// less security.
    pub fn validate(&self) -> Result<()> {
        let mut errs: Vec<String> = Vec::new();

        if self.llm.api_key.is_some() && self.llm.models.is_empty() {
            errs.push(
                "llm.api_key is set but llm.models is empty — there is no sensible \
                 cross-vendor default and every call would fail (set llm.models or OPSCLAW_MODELS)"
                    .into(),
            );
        }
        if !self.fully_faked() && self.memory.hindsight_url.is_none() {
            errs.push(
                "live mode requires memory.hindsight_url (memory is a core promise; \
                 the standard docker-compose install provides it)"
                    .into(),
            );
        }
        // The web UI/gateway is reachable whenever the daemon is not fully
        // faked (an operator can always reach a live daemon's HTTP port,
        // regardless of which external providers are wired) — an unset
        // jwt_secret would fall back to DEV_JWT_SECRET, letting anyone forge
        // an operator session. Length/placeholder checks against a Store-
        // backed secret happen at connect time (validate() has no
        // SecretStore to resolve one); an Env-backed secret is checkable
        // here since env vars need no store.
        if !self.fully_faked() {
            match &self.http.jwt_secret {
                None => errs.push(
                    "live mode requires http.jwt_secret — an unset secret would fall back to \
                     the insecure dev default, letting anyone forge an operator session"
                        .into(),
                ),
                Some(SecretRef::Env(name)) => match std::env::var(name) {
                    Ok(v) if v == DEV_JWT_SECRET => errs.push(format!(
                        "http.jwt_secret (env:{name}) is the insecure default — set a strong \
                         secret before deploying"
                    )),
                    Ok(v) if v.len() < 32 => errs.push(format!(
                        "http.jwt_secret (env:{name}) is too short — use at least 32 characters, \
                         e.g. `openssl rand -base64 48`"
                    )),
                    Ok(_) => {}
                    Err(_) => errs
                        .push(format!("http.jwt_secret references env:{name}, which is not set")),
                },
                Some(SecretRef::Store(_)) => {} // resolved + checked at connect time
            }
        }
        // Policy-bounds lists: an empty-string entry would match EVERY
        // command ("" is a substring of everything) — on auto_approve or
        // command_allowlist that's a silent everything-is-pre-approved
        // fail-open. Refuse it everywhere for symmetry.
        for (list, name) in [
            (&self.policy.auto_approve, "policy.auto_approve"),
            (&self.policy.always_ask, "policy.always_ask"),
            (&self.policy.command_allowlist, "policy.command_allowlist"),
            (&self.policy.forbidden_paths, "policy.forbidden_paths"),
        ] {
            for entry in list {
                if entry.trim().is_empty() {
                    errs.push(format!("{name} contains an empty entry — it would match everything"));
                } else if let Some((_, needle)) = entry.split_once(':')
                    && needle.trim().is_empty()
                {
                    errs.push(format!(
                        "{name} entry {entry:?} has an empty pattern after ':' — it would match \
                         every command of that tool; drop the colon to mean that deliberately"
                    ));
                }
            }
        }
        // A declared escalation chain must be structurally sound before
        // boot — a step that could never re-notify or an empty chain is a
        // fail-open (nobody gets paged), the exact class validate() exists
        // to catch. The zero-steps default is exempt: `chain()` substitutes
        // the always-valid broadcast fallback there.
        if !self.escalation.steps.is_empty()
            && let Err(e) = self.escalation.chain().validate()
        {
            errs.push(e.to_string());
        }
        match (&self.push.vapid_private_key, &self.push.vapid_public_key) {
            (Some(_), None) | (None, Some(_)) => {
                errs.push("push: half-set VAPID keypair — set both vapid_private_key and vapid_public_key or neither".into())
            }
            _ => {}
        }
        for p in &self.projects {
            for e in &p.envs {
                for t in &e.targets {
                    if let Err(err) = t.target_kind() {
                        errs.push(err.to_string());
                    }
                    let needs_cred = t.kind != TargetKindName::Local;
                    if needs_cred && t.credential.is_none() {
                        errs.push(format!(
                            "target {}::{}::{} ({:?}) has no credential reference — \
                             credentials are per-target and never inherit",
                            p.name, e.name, t.name, t.kind
                        ));
                    }
                }
            }
        }

        if errs.is_empty() { Ok(()) } else { Err(Error::Config(errs.join("\n"))) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Config {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn empty_config_is_fully_faked_and_valid() {
        let cfg = Config::default();
        assert!(cfg.fully_faked());
        cfg.validate().unwrap();
    }

    #[test]
    fn key_without_models_refuses() {
        let cfg = parse(
            r#"
            [llm]
            api_key = "env:OPENROUTER_API_KEY"
            [memory]
            hindsight_url = "http://localhost:8888"
            "#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("llm.models is empty"), "{err}");
    }

    #[test]
    fn live_mode_requires_hindsight() {
        let cfg = parse(
            r#"
            [llm]
            api_key = "env:OPENROUTER_API_KEY"
            models = ["some/model"]
            "#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("hindsight_url"), "{err}");
    }

    #[test]
    fn half_set_vapid_refuses() {
        let cfg = parse(
            r#"
            [push]
            vapid_public_key = "BAbc"
            "#,
        );
        assert!(cfg.validate().unwrap_err().to_string().contains("VAPID"));
    }

    #[test]
    fn unknown_autonomy_fails_at_parse() {
        let r: std::result::Result<Config, _> = toml::from_str(
            r#"
            [[project]]
            name = "p"
            autonomy = "full"
            "#,
        );
        assert!(r.is_err(), "old vocabulary must not deserialize");
    }

    #[test]
    fn autonomy_inheritance_resolves_down_the_tree() {
        let cfg = parse(
            r#"
            [[project]]
            name = "remundo"
            autonomy = "observe"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "cluster"
            kind = "kubernetes"
            credential = "store:remundo-prod-kubeconfig"
            [[project.env]]
            name = "dev"
            autonomy = "auto"
            [[project.env.target]]
            name = "cluster"
            kind = "kubernetes"
            credential = "store:remundo-dev-kubeconfig"
            autonomy = "act_on_known"
            "#,
        );
        cfg.validate().unwrap();
        assert_eq!(cfg.autonomy_for("remundo", "prod", "cluster"), Autonomy::Observe);
        assert_eq!(cfg.autonomy_for("remundo", "dev", "cluster"), Autonomy::ActOnKnown);
        assert_eq!(cfg.autonomy_for("unknown", "x", "y"), Autonomy::Suggest);
    }

    #[test]
    fn missing_credential_refuses() {
        let cfg = parse(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "web-1"
            kind = "ssh"
            address = "10.0.0.5"
            "#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("no credential reference"), "{err}");
    }

    #[test]
    fn debug_output_contains_no_secret_values() {
        // Config holds SecretRefs (names) by construction; this pins the
        // property so a future field can't regress it silently.
        unsafe { std::env::set_var("OPSCLAW_TEST_SECRET_XYZZY", "s3cr3t-value-xyzzy") };
        let cfg = parse(
            r#"
            [llm]
            api_key = "env:OPSCLAW_TEST_SECRET_XYZZY"
            models = ["m"]
            [memory]
            hindsight_url = "http://localhost:8888"
            "#,
        );
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("s3cr3t-value-xyzzy"));
        assert!(dbg.contains("OPSCLAW_TEST_SECRET_XYZZY")); // the NAME is fine
    }

    #[test]
    fn live_mode_requires_jwt_secret() {
        let cfg = parse(
            r#"
            [llm]
            api_key = "env:OPENROUTER_API_KEY"
            models = ["some/model"]
            [memory]
            hindsight_url = "http://localhost:8888"
            "#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("http.jwt_secret"), "{err}");
    }

    #[test]
    fn live_mode_env_jwt_secret_dev_placeholder_refuses() {
        unsafe { std::env::set_var("OPSCLAW_TEST_JWT_DEV", super::DEV_JWT_SECRET) };
        let cfg = parse(
            r#"
            [llm]
            api_key = "env:OPENROUTER_API_KEY"
            models = ["some/model"]
            [memory]
            hindsight_url = "http://localhost:8888"
            [http]
            jwt_secret = "env:OPSCLAW_TEST_JWT_DEV"
            "#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("insecure default"), "{err}");
    }

    #[test]
    fn live_mode_env_jwt_secret_too_short_refuses() {
        unsafe { std::env::set_var("OPSCLAW_TEST_JWT_SHORT", "too-short") };
        let cfg = parse(
            r#"
            [llm]
            api_key = "env:OPENROUTER_API_KEY"
            models = ["some/model"]
            [memory]
            hindsight_url = "http://localhost:8888"
            [http]
            jwt_secret = "env:OPSCLAW_TEST_JWT_SHORT"
            "#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("too short"), "{err}");
    }

    #[test]
    fn live_mode_env_jwt_secret_strong_enough_passes() {
        unsafe {
            std::env::set_var("OPSCLAW_TEST_JWT_OK", "a-sufficiently-long-and-random-secret-value")
        };
        let cfg = parse(
            r#"
            [llm]
            api_key = "env:OPENROUTER_API_KEY"
            models = ["some/model"]
            [memory]
            hindsight_url = "http://localhost:8888"
            [http]
            jwt_secret = "env:OPSCLAW_TEST_JWT_OK"
            "#,
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn fully_faked_mode_needs_no_jwt_secret() {
        let cfg = Config::default();
        assert!(cfg.fully_faked());
        cfg.validate().unwrap(); // no http.jwt_secret set at all
    }

    #[test]
    fn resolve_jwt_secret_falls_back_to_dev_default_when_fully_faked() {
        let cfg = Config::default();
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        assert_eq!(cfg.resolve_jwt_secret(&store).unwrap(), super::DEV_JWT_SECRET);
    }

    #[test]
    fn resolve_jwt_secret_rejects_dev_default_and_short_secrets_when_live() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        store.set("jwt", super::DEV_JWT_SECRET).unwrap();
        let mut cfg = parse(
            r#"
            [llm]
            api_key = "env:OPENROUTER_API_KEY"
            models = ["some/model"]
            [memory]
            hindsight_url = "http://localhost:8888"
            "#,
        );
        cfg.http.jwt_secret = Some(SecretRef::store("jwt"));
        assert!(
            cfg.resolve_jwt_secret(&store).unwrap_err().to_string().contains("insecure default")
        );

        store.set("jwt", "short").unwrap();
        assert!(cfg.resolve_jwt_secret(&store).unwrap_err().to_string().contains("too short"));

        store.set("jwt", "a-sufficiently-long-and-random-secret-value").unwrap();
        cfg.resolve_jwt_secret(&store).unwrap();
    }

    // --- unambiguous-prefix target addressing (brief §4) ---

    #[test]
    fn resolve_target_str_accepts_every_unambiguous_form() {
        let cfg = parse(
            r#"
            [[project]]
            name = "remundo"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "web-1"
            kind = "local"
            [[project.env.target]]
            name = "db"
            kind = "local"
            [[project.env]]
            name = "staging"
            [[project.env.target]]
            name = "web-1"
            kind = "local"
            "#,
        );
        // Bare name, unique across the whole tree.
        assert_eq!(cfg.resolve_target_str("db").unwrap().to_string(), "remundo::prod::db");
        // env/target and env::target disambiguate a duplicated name.
        assert_eq!(
            cfg.resolve_target_str("prod/web-1").unwrap().to_string(),
            "remundo::prod::web-1"
        );
        assert_eq!(
            cfg.resolve_target_str("staging::web-1").unwrap().to_string(),
            "remundo::staging::web-1"
        );
        // Full path always works.
        assert_eq!(
            cfg.resolve_target_str("remundo::prod::web-1").unwrap().to_string(),
            "remundo::prod::web-1"
        );

        // Ambiguous bare name: refused, candidates listed.
        let err = cfg.resolve_target_str("web-1").unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "{err}");
        assert!(err.contains("remundo::prod::web-1"), "{err}");
        assert!(err.contains("remundo::staging::web-1"), "{err}");

        // Unknown: refused, valid paths listed.
        let err = cfg.resolve_target_str("nope").unwrap_err().to_string();
        assert!(err.contains("no configured target"), "{err}");
        assert!(err.contains("remundo::prod::db"), "{err}");
    }

    // --- ResourceCfg union type: per-kind shapes enforced at parse time ---

    fn parse_resource(toml_fields: &str) -> std::result::Result<ResourceCfg, String> {
        let cfg: std::result::Result<Config, _> = toml::from_str(&format!(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "local"
            [[project.env.target.resource]]
            {toml_fields}
            "#
        ));
        cfg.map(|c| c.projects[0].envs[0].targets[0].resources[0].clone())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn resource_es_parses_into_its_variant_with_basic_auth() {
        let r = parse_resource(
            r#"type = "elasticsearch"
            name = "logs"
            url = "https://localhost:9201"
            username = "elastic"
            credential = "store:es-password"
            insecure_tls = true"#,
        )
        .unwrap();
        assert_eq!(r.rtype(), ResourceType::Elasticsearch);
        assert_eq!(r.name(), "logs");
        let ep = r.endpoint().expect("es always has an endpoint view");
        assert_eq!(ep.url, "https://localhost:9201");
        assert_eq!(ep.username, Some("elastic"));
        assert!(ep.insecure_tls);
    }

    #[test]
    fn resource_url_is_required_for_built_out_kinds() {
        for (fields, kind) in [
            (r#"type = "prometheus"
                name = "metrics""#, "prometheus"),
            (r#"type = "elasticsearch"
                name = "logs""#, "elasticsearch"),
            (r#"type = "eventstore"
                name = "main""#, "eventstore"),
        ] {
            let err = parse_resource(fields).unwrap_err();
            assert!(err.contains("has no `url`"), "{kind}: {err}");
            assert!(err.contains(kind), "error names the kind: {err}");
        }
    }

    #[test]
    fn resource_argocd_requires_credential_and_refuses_username() {
        let err = parse_resource(
            r#"type = "argocd"
            name = "main"
            url = "https://argocd.example""#,
        )
        .unwrap_err();
        assert!(err.contains("has no `credential`"), "{err}");

        let err = parse_resource(
            r#"type = "argocd"
            name = "main"
            url = "https://argocd.example"
            credential = "env:ARGOCD_TOKEN"
            username = "admin""#,
        )
        .unwrap_err();
        assert!(err.contains("`username` is not used"), "{err}");
    }

    #[test]
    fn resource_service_bus_requires_sas_and_refuses_tls_knobs() {
        let ok = parse_resource(
            r#"type = "azure_service_bus"
            name = "bus"
            url = "https://ns.servicebus.windows.net"
            credential = "env:ASB_SAS""#,
        )
        .unwrap();
        assert!(matches!(ok, ResourceCfg::AzureServiceBus(_)));

        let err = parse_resource(
            r#"type = "azure_service_bus"
            name = "bus"
            url = "https://ns.servicebus.windows.net""#,
        )
        .unwrap_err();
        assert!(err.contains("has no `credential`"), "{err}");

        let err = parse_resource(
            r#"type = "azure_service_bus"
            name = "bus"
            url = "https://ns.servicebus.windows.net"
            credential = "env:ASB_SAS"
            insecure_tls = true"#,
        )
        .unwrap_err();
        assert!(err.contains("`insecure_tls` is not used"), "{err}");
    }

    #[test]
    fn resource_stub_kind_keeps_the_permissive_shape() {
        // postgres has no built tool yet — declarable ahead of it, url and
        // credential both optional.
        let r = parse_resource(
            r#"type = "postgres"
            name = "primary""#,
        )
        .unwrap();
        let ResourceCfg::Stub(s) = &r else { panic!("expected Stub, got {r:?}") };
        assert_eq!(s.rtype, ResourceType::Postgres);
        assert!(r.endpoint().is_none(), "no url -> no endpoint view");
    }

    #[test]
    fn resource_unknown_field_is_still_rejected() {
        // deny_unknown_fields must survive the union type (serde's
        // internally-tagged enums would swallow this typo silently).
        let err = parse_resource(
            r#"type = "prometheus"
            name = "metrics"
            url = "http://localhost:9090"
            insecure_tsl = true"#,
        )
        .unwrap_err();
        assert!(err.contains("insecure_tsl"), "{err}");
    }

    #[test]
    fn resource_round_trips_through_toml() {
        let r = parse_resource(
            r#"type = "elasticsearch"
            name = "logs"
            url = "https://localhost:9201"
            username = "elastic"
            credential = "store:es-password""#,
        )
        .unwrap();
        let serialized = toml::to_string(&r.to_raw()).unwrap();
        let reparsed: ResourceCfg =
            ResourceCfg::try_from(toml::from_str::<RawResourceCfg>(&serialized).unwrap()).unwrap();
        assert_eq!(reparsed.name(), r.name());
        assert_eq!(reparsed.rtype(), r.rtype());
        let (a, b) = (r.endpoint().unwrap(), reparsed.endpoint().unwrap());
        assert_eq!(a.url, b.url);
        assert_eq!(a.username, b.username);
    }
}
