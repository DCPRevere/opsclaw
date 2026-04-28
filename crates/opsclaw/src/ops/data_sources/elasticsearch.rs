//! Elasticsearch / OpenSearch data source.
//!
//! Queries `POST {url}/{index}/_search` with a time-range filter for recent
//! error-level log entries and returns them as [`LogEntry`] values.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::ops::data_sources::{ElasticsearchConfig, LogEntry, LogLevel};

/// Maximum number of hits to return per query.
const MAX_HITS: u32 = 50;

// ---------------------------------------------------------------------------
// Elasticsearch response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SearchResponse {
    hits: HitsEnvelope,
}

#[derive(Debug, Deserialize)]
struct HitsEnvelope {
    hits: Vec<Hit>,
}

#[derive(Debug, Deserialize)]
struct Hit {
    #[serde(rename = "_source")]
    source: HitSource,
}

#[derive(Debug, Deserialize)]
struct HitSource {
    #[serde(alias = "@timestamp")]
    timestamp: Option<String>,
    #[serde(alias = "log.level")]
    level: Option<String>,
    message: Option<String>,
    #[serde(alias = "error.message")]
    error_message: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch recent error-level log entries from an Elasticsearch or OpenSearch
/// instance.
pub async fn fetch_error_logs(cfg: &ElasticsearchConfig) -> Result<Vec<LogEntry>> {
    let base = cfg.url.trim_end_matches('/');
    let index = cfg.index_pattern.as_deref().unwrap_or("*");
    let url = format!("{base}/{index}/_search");

    let now = Utc::now();
    let since = now - chrono::Duration::minutes(15);

    let body = build_query(&since, MAX_HITS);

    let client = reqwest::Client::new();
    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body);

    req = apply_auth(req, cfg);

    let resp = req
        .send()
        .await
        .context("failed to reach Elasticsearch API")?
        .error_for_status()
        .context("Elasticsearch API returned error status")?;

    let search: SearchResponse = resp
        .json()
        .await
        .context("failed to parse Elasticsearch response")?;

    let entries = search
        .hits
        .hits
        .into_iter()
        .map(|hit| {
            let src = hit.source;

            let timestamp = src
                .timestamp
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            let level = src.level.as_deref().and_then(map_es_level);

            let mut message = src.message.unwrap_or_default();
            if let Some(err_msg) = &src.error_message {
                if !err_msg.is_empty() {
                    message = format!("{message}\n  error: {err_msg}");
                }
            }

            LogEntry {
                timestamp,
                source: "elasticsearch".into(),
                level,
                message: message.clone(),
                raw: message,
            }
        })
        .collect();

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn apply_auth(req: reqwest::RequestBuilder, cfg: &ElasticsearchConfig) -> reqwest::RequestBuilder {
    if let Some(api_key) = &cfg.api_key {
        return req.header("Authorization", format!("ApiKey {api_key}"));
    }
    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        return req.basic_auth(user, Some(pass));
    }
    req
}

fn build_query(since: &DateTime<Utc>, size: u32) -> serde_json::Value {
    serde_json::json!({
        "size": size,
        "sort": [{ "@timestamp": { "order": "desc" } }],
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": since.to_rfc3339(),
                                "lte": "now"
                            }
                        }
                    }
                ],
                "should": [
                    { "term": { "level": "error" } },
                    { "term": { "level": "ERROR" } },
                    { "term": { "log.level": "error" } },
                    { "term": { "log.level": "ERROR" } },
                    { "term": { "severity": "error" } },
                    { "term": { "severity": "ERROR" } }
                ],
                "minimum_should_match": 1
            }
        }
    })
}

fn map_es_level(s: &str) -> Option<LogLevel> {
    match s.to_ascii_lowercase().as_str() {
        "fatal" | "critical" | "emerg" | "alert" => Some(LogLevel::Fatal),
        "error" | "err" => Some(LogLevel::Error),
        "warn" | "warning" => Some(LogLevel::Warn),
        "info" | "information" | "notice" => Some(LogLevel::Info),
        "debug" | "trace" | "verbose" => Some(LogLevel::Debug),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_es_levels() {
        assert_eq!(map_es_level("fatal"), Some(LogLevel::Fatal));
        assert_eq!(map_es_level("CRITICAL"), Some(LogLevel::Fatal));
        assert_eq!(map_es_level("error"), Some(LogLevel::Error));
        assert_eq!(map_es_level("ERROR"), Some(LogLevel::Error));
        assert_eq!(map_es_level("err"), Some(LogLevel::Error));
        assert_eq!(map_es_level("warn"), Some(LogLevel::Warn));
        assert_eq!(map_es_level("WARNING"), Some(LogLevel::Warn));
        assert_eq!(map_es_level("info"), Some(LogLevel::Info));
        assert_eq!(map_es_level("Information"), Some(LogLevel::Info));
        assert_eq!(map_es_level("debug"), Some(LogLevel::Debug));
        assert_eq!(map_es_level("trace"), Some(LogLevel::Debug));
        assert_eq!(map_es_level("unknown"), None);
    }

    #[test]
    fn build_query_structure() {
        let ts = Utc::now();
        let q = build_query(&ts, 25);
        assert_eq!(q["size"], 25);
        assert!(
            q["query"]["bool"]["must"][0]["range"]["@timestamp"]["gte"]
                .as_str()
                .is_some()
        );
        assert_eq!(q["query"]["bool"]["minimum_should_match"], 1);
    }

    #[test]
    fn deserialize_search_response() {
        let json = r#"{
            "hits": {
                "total": { "value": 1 },
                "hits": [{
                    "_index": "logs-2024.03",
                    "_id": "abc",
                    "_source": {
                        "@timestamp": "2024-03-17T12:00:00Z",
                        "level": "error",
                        "message": "connection refused"
                    }
                }]
            }
        }"#;
        let resp: SearchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.hits.hits.len(), 1);
        assert_eq!(
            resp.hits.hits[0].source.message.as_deref(),
            Some("connection refused")
        );
    }

    #[test]
    fn deserialize_hit_with_error_message() {
        let json = r#"{
            "_index": "logs",
            "_id": "x",
            "_source": {
                "@timestamp": "2024-03-17T12:00:00Z",
                "level": "ERROR",
                "message": "request failed",
                "error.message": "timeout after 30s"
            }
        }"#;
        let hit: Hit = serde_json::from_str(json).unwrap();
        assert_eq!(hit.source.level.as_deref(), Some("ERROR"));
        assert_eq!(
            hit.source.error_message.as_deref(),
            Some("timeout after 30s")
        );
    }
}
