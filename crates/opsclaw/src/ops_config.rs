//! OpsClaw-specific configuration types.
//!
//! These types extend the upstream zeroclawlabs config schema with
//! SRE-specific concepts: projects, probes, autonomy levels, etc.

use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

/// OpsClaw configuration — wraps the upstream zeroclawlabs `Config` with
/// SRE-specific fields (projects, notifications, diagnosis, a2a).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpsConfig {
    /// The upstream zeroclawlabs configuration.
    #[serde(flatten)]
    pub inner: zeroclaw::Config,

    /// SRE targets (monitored endpoints).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<TargetConfig>>,

    /// Notification delivery settings for alerts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<OpsClawNotificationConfig>,

    /// LLM diagnosis configuration.
    #[serde(default)]
    pub diagnosis: DiagnosisConfig,

    /// A2A (Agent-to-Agent) protocol configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a: Option<A2aConfig>,

    /// Prometheus query endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prometheus: Option<Vec<PrometheusEndpointConfig>>,

    /// Loki log-query endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loki: Option<Vec<LokiEndpointConfig>>,

    /// Elasticsearch / OpenSearch endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elk: Option<Vec<ElkEndpointConfig>>,

    /// PagerDuty configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pagerduty: Option<PagerDutyConfig>,

    /// GitHub configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<GithubConfig>,

    /// Cloudflare configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<CloudflareConfig>,

    /// RabbitMQ management API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rabbitmq: Option<RabbitMqConfig>,

    /// Azure Service Bus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_service_bus: Option<AzureServiceBusConfig>,

    /// Jaeger query endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jaeger: Option<Vec<JaegerEndpointConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JaegerEndpointConfig {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GithubConfig {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_repo: Option<String>,
    #[serde(default)]
    pub autonomy: OpsClawAutonomy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CloudflareConfig {
    pub api_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_zone_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_account_id: Option<String>,
    #[serde(default)]
    pub autonomy: OpsClawAutonomy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RabbitMqConfig {
    pub api_base: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_vhost")]
    pub default_vhost: String,
    #[serde(default)]
    pub autonomy: OpsClawAutonomy,
}

fn default_vhost() -> String {
    "/".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AzureServiceBusConfig {
    pub namespace: String,
    pub sas_key_name: String,
    pub sas_key: String,
    #[serde(default)]
    pub autonomy: OpsClawAutonomy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrometheusEndpointConfig {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LokiEndpointConfig {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ElkEndpointConfig {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_index: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PagerDutyConfig {
    pub api_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_from: Option<String>,
    #[serde(default)]
    pub autonomy: OpsClawAutonomy,
}

impl Deref for OpsConfig {
    type Target = zeroclaw::Config;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for OpsConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl OpsConfig {
    /// Decrypt a secret value using the config's `SecretStore`.
    ///
    /// If the value is not encrypted (no `enc2:` prefix) it is returned as-is.
    pub fn decrypt_secret(&self, value: &str) -> Result<String> {
        let config_dir = self
            .inner
            .config_path
            .parent()
            .context("config path has no parent")?;
        let store = zeroclaw::security::SecretStore::new(config_dir, self.inner.secrets.encrypt);
        store.decrypt(value)
    }

    /// Serialize the full `OpsConfig` (including opsclaw-specific fields) to
    /// `self.config_path`. Must be called instead of `Config::save()` whenever
    /// the caller may have modified `projects`, `notifications`, `diagnosis`, or
    /// `a2a`, because `Config::save()` only serializes the inner zeroclaw fields
    /// and would silently drop those fields.
    pub async fn save(&self) -> Result<()> {
        let config_path = &self.inner.config_path;
        if let Some(parent) = config_path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        // Encrypt secret fields on targets before serializing.
        let mut to_save = self.clone();
        if let Some(ref mut targets) = to_save.targets {
            let store = zeroclaw::security::SecretStore::new(
                config_path.parent().context("config path has no parent")?,
                self.inner.secrets.encrypt,
            );
            for target in targets.iter_mut() {
                if let Some(ref val) = target.key_secret {
                    if !zeroclaw::security::SecretStore::is_encrypted(val) {
                        target.key_secret = Some(store.encrypt(val)?);
                    }
                }
                if let Some(ref mut ds) = target.data_sources {
                    if let Some(ref mut seq) = ds.seq {
                        if let Some(ref val) = seq.api_key {
                            if !zeroclaw::security::SecretStore::is_encrypted(val) {
                                seq.api_key = Some(store.encrypt(val)?);
                            }
                        }
                    }
                    if let Some(ref mut github) = ds.github {
                        if let Some(ref val) = github.token {
                            if !zeroclaw::security::SecretStore::is_encrypted(val) {
                                github.token = Some(store.encrypt(val)?);
                            }
                        }
                    }
                    if let Some(ref mut prometheus) = ds.prometheus {
                        if let Some(ref val) = prometheus.token {
                            if !zeroclaw::security::SecretStore::is_encrypted(val) {
                                prometheus.token = Some(store.encrypt(val)?);
                            }
                        }
                    }
                    if let Some(ref mut es) = ds.elasticsearch {
                        if let Some(ref val) = es.api_key {
                            if !zeroclaw::security::SecretStore::is_encrypted(val) {
                                es.api_key = Some(store.encrypt(val)?);
                            }
                        }
                        if let Some(ref val) = es.password {
                            if !zeroclaw::security::SecretStore::is_encrypted(val) {
                                es.password = Some(store.encrypt(val)?);
                            }
                        }
                    }
                }
            }
        }

        // Encrypt notification secret fields.
        if let Some(ref mut notif) = to_save.notifications {
            let store = zeroclaw::security::SecretStore::new(
                config_path.parent().context("config path has no parent")?,
                self.inner.secrets.encrypt,
            );
            if let Some(ref val) = notif.telegram_bot_token {
                if !zeroclaw::security::SecretStore::is_encrypted(val) {
                    notif.telegram_bot_token = Some(store.encrypt(val)?);
                }
            }
            if let Some(ref val) = notif.slack_webhook_url {
                if !zeroclaw::security::SecretStore::is_encrypted(val) {
                    notif.slack_webhook_url = Some(store.encrypt(val)?);
                }
            }
            if let Some(ref val) = notif.webhook_bearer_token {
                if !zeroclaw::security::SecretStore::is_encrypted(val) {
                    notif.webhook_bearer_token = Some(store.encrypt(val)?);
                }
            }
        }

        // Encrypt diagnosis secret fields.
        {
            let store = zeroclaw::security::SecretStore::new(
                config_path.parent().context("config path has no parent")?,
                self.inner.secrets.encrypt,
            );
            if let Some(ref val) = to_save.diagnosis.api_key {
                if !zeroclaw::security::SecretStore::is_encrypted(val) {
                    to_save.diagnosis.api_key = Some(store.encrypt(val)?);
                }
            }
        }

        // Encrypt A2A secret fields.
        if let Some(ref mut a2a) = to_save.a2a {
            let store = zeroclaw::security::SecretStore::new(
                config_path.parent().context("config path has no parent")?,
                self.inner.secrets.encrypt,
            );
            if !a2a.server.token.is_empty()
                && !zeroclaw::security::SecretStore::is_encrypted(&a2a.server.token)
            {
                a2a.server.token = store.encrypt(&a2a.server.token)?;
            }
            for peer in &mut a2a.peers {
                if !peer.token.is_empty()
                    && !zeroclaw::security::SecretStore::is_encrypted(&peer.token)
                {
                    peer.token = store.encrypt(&peer.token)?;
                }
            }
        }

        let toml_str = toml::to_string_pretty(&to_save).context("Failed to serialize OpsConfig")?;
        tokio::fs::write(config_path, toml_str)
            .await
            .with_context(|| format!("Failed to write config to {}", config_path.display()))
    }
}

/// Three user-facing modes: `dry-run`, `approve`, `auto`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpsClawAutonomy {
    /// Log proposed actions without executing. Read-only commands still run.
    DryRun,
    /// Propose actions and wait for user approval before executing.
    #[default]
    Approve,
    /// Execute remediations automatically without asking.
    Auto,
}

/// Connection type for an OpsClaw project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionType {
    /// SSH connection to a remote host.
    Ssh,
    /// The local machine.
    Local,
    /// Kubernetes cluster (via kube-rs API client).
    Kubernetes,
}

/// Configuration for a single OpsClaw SRE project (monitored environment).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetConfig {
    /// Unique name for this project.
    pub name: String,
    /// Connection type: `ssh` or `local`.
    #[serde(rename = "type")]
    pub connection_type: ConnectionType,
    /// Remote hostname or IP (required for SSH projects).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// SSH port (default: 22, only for SSH projects).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SSH username (required for SSH projects).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// SSH private key PEM content (encrypted inline as `enc2:...`, decrypted at config load).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_secret: Option<String>,
    /// Autonomy level for this project.
    #[serde(default)]
    pub autonomy: OpsClawAutonomy,
    /// Path to an optional context file (Markdown) describing this project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_file: Option<String>,
    /// External probes to run against this project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<Vec<ProbeConfig>>,
    /// Optional pull-based data sources (Seq, Jaeger, GitHub, Docker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_sources: Option<crate::ops::data_sources::DataSourcesConfig>,
    /// Optional escalation policy for tiered on-call notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation: Option<EscalationPolicy>,
    /// Optional database instances for diagnostic health queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub databases: Option<Vec<crate::tools::db_diagnostic::DatabaseConfig>>,
    /// Path to a kubeconfig file (Kubernetes projects only; defaults to ~/.kube/config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubeconfig: Option<String>,
    /// Default namespace for Kubernetes operations (defaults to all namespaces).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Tiered on-call policy: who to page first, who to escalate to, and how long
/// to wait between tiers. Consumed by the notifier when an alert or failed
/// action requires human attention.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct EscalationPolicy {
    /// Primary contact (name, channel id, or handle depending on transport).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
    /// Fallback contact if the primary does not respond.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<String>,
    /// Final escalation contact (e.g. a manager or incident commander).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    /// Minutes to wait before escalating from primary to secondary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_after_minutes: Option<u32>,
    /// Minutes to wait before escalating from secondary to manager.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager_after_minutes: Option<u32>,
}

/// Configuration for a single external probe.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProbeConfig {
    /// Human-readable name for this probe.
    pub name: String,
    /// The probe definition.
    #[serde(flatten)]
    pub probe_type: ProbeType,
}

/// The type and parameters of an external probe.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProbeType {
    Http {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_status: Option<u16>,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
    Tcp {
        host: String,
        port: u16,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
    Dns {
        hostname: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_ip: Option<String>,
    },
    TlsCert {
        hostname: String,
        #[serde(default = "default_tls_port")]
        port: u16,
        #[serde(default = "default_warn_days")]
        warn_days: u32,
    },
}

fn default_timeout() -> u64 {
    5
}

fn default_tls_port() -> u16 {
    443
}

fn default_warn_days() -> u32 {
    30
}

/// Notification delivery settings for OpsClaw alerts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct OpsClawNotificationConfig {
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub slack_webhook_url: Option<String>,
    pub webhook_url: Option<String>,
    pub webhook_bearer_token: Option<String>,
    #[serde(default)]
    pub min_severity: AlertSeverity,
}

/// LLM-based diagnosis settings for OpsClaw monitoring alerts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosisConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Alert severity level (shared between config and monitoring).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    #[default]
    Warning,
    Critical,
}

/// A capability advertised by an A2A agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct A2aAgentSkill {
    pub name: String,
    pub description: String,
}

/// Configuration for the A2A server.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct A2aServerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_a2a_server_port")]
    pub port: u16,
    #[serde(default = "default_a2a_server_host")]
    pub bind: String,
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_a2a_agent_name")]
    pub agent_name: String,
    #[serde(default = "default_a2a_agent_description")]
    pub agent_description: String,
    #[serde(default)]
    pub skills: Vec<A2aAgentSkill>,
}

fn default_a2a_server_port() -> u16 {
    42618
}
fn default_a2a_server_host() -> String {
    "127.0.0.1".to_string()
}
fn default_a2a_agent_name() -> String {
    "OpsClaw".to_string()
}
fn default_a2a_agent_description() -> String {
    "OpsClaw autonomous SRE agent".to_string()
}

impl Default for A2aServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_a2a_server_port(),
            bind: default_a2a_server_host(),
            token: String::new(),
            agent_name: default_a2a_agent_name(),
            agent_description: default_a2a_agent_description(),
            skills: Vec::new(),
        }
    }
}

/// A2A protocol configuration — server and known peers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct A2aConfig {
    #[serde(default)]
    pub server: A2aServerConfig,
    #[serde(default)]
    pub peers: Vec<A2aPeerConfig>,
}

/// A known remote A2A peer.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct A2aPeerConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub token: String,
}

#[cfg(test)]
mod golden_tests {
    //! Golden-file tests for `OpsConfig` TOML parsing.
    //!
    //! Lock in the on-disk schema shape. A parse failure against any fixture
    //! means the schema changed — either update the fixture or fix the
    //! regression.

    use super::*;

    fn load(name: &str) -> OpsConfig {
        let path = format!(
            "{}/tests/fixtures/config/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
        toml::from_str(&text)
            .unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
    }

    #[test]
    fn minimal_parses() {
        let cfg = load("minimal.toml");
        let targets = cfg.targets.as_ref().expect("targets present");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "local-box");
        assert!(matches!(targets[0].connection_type, ConnectionType::Local));
        assert!(matches!(targets[0].autonomy, OpsClawAutonomy::Approve));
    }

    #[test]
    fn full_parses_all_sections() {
        let cfg = load("full.toml");

        let targets = cfg.targets.as_ref().expect("targets present");
        assert_eq!(targets.len(), 2);

        let web = &targets[0];
        assert_eq!(web.name, "prod-web-1");
        assert!(matches!(web.connection_type, ConnectionType::Ssh));
        assert_eq!(web.host.as_deref(), Some("10.0.0.1"));
        assert!(matches!(web.autonomy, OpsClawAutonomy::Approve));

        let probes = web.probes.as_ref().expect("probes present");
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].name, "healthcheck");
        assert!(matches!(probes[0].probe_type, ProbeType::Http { .. }));

        let databases = web.databases.as_ref().expect("databases present");
        assert_eq!(databases.len(), 1);
        assert_eq!(databases[0].name, "primary");

        let esc = web.escalation.as_ref().expect("escalation present");
        assert_eq!(esc.primary.as_deref(), Some("oncall-primary"));
        assert_eq!(esc.secondary_after_minutes, Some(10));
        assert_eq!(esc.manager_after_minutes, Some(30));

        let k8s = &targets[1];
        assert_eq!(k8s.name, "k8s-cluster");
        assert!(matches!(k8s.connection_type, ConnectionType::Kubernetes));
        assert_eq!(k8s.kubeconfig.as_deref(), Some("~/.kube/prod-eks"));
        assert_eq!(k8s.namespace.as_deref(), Some("default"));

        let notif = cfg.notifications.as_ref().expect("notifications present");
        assert!(matches!(notif.min_severity, AlertSeverity::Warning));
    }

    #[test]
    fn legacy_autonomy_aliases_rejected() {
        let toml_with_legacy = r#"
workspace_dir = "/tmp/x"

[[targets]]
name = "legacy"
type = "local"
autonomy = "observe"
"#;
        let result: Result<OpsConfig, _> = toml::from_str(toml_with_legacy);
        assert!(
            result.is_err(),
            "legacy autonomy alias 'observe' must not deserialise"
        );
    }

    #[test]
    fn severity_is_typed_not_string() {
        let good = r#"
workspace_dir = "/tmp/x"
[notifications]
min_severity = "critical"
"#;
        let cfg: OpsConfig = toml::from_str(good).expect("critical parses");
        assert!(matches!(
            cfg.notifications.unwrap().min_severity,
            AlertSeverity::Critical
        ));

        let bad = r#"
workspace_dir = "/tmp/x"
[notifications]
min_severity = "bogus"
"#;
        let result: Result<OpsConfig, _> = toml::from_str(bad);
        assert!(
            result.is_err(),
            "invalid severity string must fail to deserialise"
        );
    }
}
