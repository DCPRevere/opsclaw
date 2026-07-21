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
    #[serde(rename = "project")]
    pub projects: Vec<ProjectCfg>,
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
}

impl Default for DaemonCfg {
    fn default() -> Self {
        DaemonCfg {
            listen: "127.0.0.1:8484".into(),
            db_path: None,
            tick_seconds: 300,
            deadman_url: None,
            runbooks_dir: default_dir().join("runbooks"),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCfg {
    #[serde(rename = "type")]
    pub rtype: ResourceType,
    pub name: String,
    pub url: Option<String>,
    pub credential: Option<SecretRef>,
    /// Set ⇒ HTTP basic auth: this username + `credential` as the password
    /// (ECK Elasticsearch: `elastic` + the operator-generated password).
    /// Unset ⇒ `credential` is a bearer token (the original behaviour).
    pub username: Option<String>,
    /// Extra trusted root CA (PEM file path) for this resource only — an
    /// in-cluster ECK Elasticsearch presents a self-signed CA that must not
    /// pollute global trust.
    pub ca_cert_path: Option<PathBuf>,
    /// Disable certificate verification for THIS resource. Loudly warned at
    /// boot; acceptable only for a localhost port-forward hop where the
    /// hostname can never match the cert. Never a default.
    #[serde(default)]
    pub insecure_tls: bool,
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
}
