//! Configuration types for optional pull-based data sources.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Optional data-source configuration block for a target.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DataSourcesConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<SeqConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jaeger: Option<JaegerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<GithubConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_containers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prometheus: Option<PrometheusConfig>,
    /// Paths to git repositories on the target for deployment correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elasticsearch: Option<ElasticsearchConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SeqConfig {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JaegerConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GithubConfig {
    pub repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrometheusConfig {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ElasticsearchConfig {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_pattern: Option<String>,
}
