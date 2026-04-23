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
/// Old names (`observe`, `suggest`, `act_on_known`, `full_auto`) are accepted
/// for backward compatibility and mapped to the closest new mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpsClawAutonomy {
    /// Log proposed actions without executing. Read-only commands still run.
    #[serde(alias = "observe", alias = "suggest")]
    DryRun,
    /// Propose actions and wait for user approval before executing.
    #[default]
    Approve,
    /// Execute remediations automatically without asking.
    #[serde(alias = "act_on_known", alias = "full_auto")]
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
    pub escalation: Option<serde_json::Value>,
    /// Optional database instances for diagnostic health queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub databases: Option<serde_json::Value>,
    /// Path to a kubeconfig file (Kubernetes projects only; defaults to ~/.kube/config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubeconfig: Option<String>,
    /// Default namespace for Kubernetes operations (defaults to all namespaces).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpsClawNotificationConfig {
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub slack_webhook_url: Option<String>,
    pub webhook_url: Option<String>,
    pub webhook_bearer_token: Option<String>,
    #[serde(default = "default_min_severity_str")]
    pub min_severity: String,
}

impl Default for OpsClawNotificationConfig {
    fn default() -> Self {
        Self {
            telegram_bot_token: None,
            telegram_chat_id: None,
            slack_webhook_url: None,
            webhook_url: None,
            webhook_bearer_token: None,
            min_severity: "warning".to_string(),
        }
    }
}

fn default_min_severity_str() -> String {
    "warning".to_string()
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Parse a severity string into an `AlertSeverity` value.
pub fn parse_min_severity(s: &str) -> AlertSeverity {
    match s.to_lowercase().as_str() {
        "info" => AlertSeverity::Info,
        "critical" => AlertSeverity::Critical,
        _ => AlertSeverity::Warning,
    }
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
