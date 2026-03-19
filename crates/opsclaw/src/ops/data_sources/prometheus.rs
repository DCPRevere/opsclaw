//! Prometheus HTTP API data source.
//!
//! Queries `/api/v1/query_range` for target up/down status and
//! `/api/v1/query` for active alerts. Returns structured summaries
//! for LLM diagnosis context.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ops::data_sources::PrometheusConfig;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single metric time-series result from `query_range`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    pub metric_name: String,
    pub labels: String,
    pub values: Vec<(f64, f64)>,
}

/// A currently-firing Prometheus alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveAlert {
    pub name: String,
    pub state: String,
    pub labels: String,
    pub value: String,
}

/// Combined Prometheus snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrometheusSnapshot {
    pub up_samples: Vec<MetricSample>,
    pub active_alerts: Vec<ActiveAlert>,
}

// ---------------------------------------------------------------------------
// Prometheus API response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct QueryResponse {
    data: QueryData,
}

#[derive(Debug, Deserialize)]
struct QueryData {
    result: Vec<ResultEntry>,
}

#[derive(Debug, Deserialize)]
struct ResultEntry {
    metric: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    values: Vec<(f64, serde_json::Value)>,
    #[serde(default)]
    value: Option<(f64, serde_json::Value)>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch up/down status and active alerts from a Prometheus instance.
pub async fn fetch_prometheus_snapshot(
    cfg: &PrometheusConfig,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<PrometheusSnapshot> {
    let base = cfg.url.trim_end_matches('/');
    let client = reqwest::Client::new();

    let mut snap = PrometheusSnapshot::default();

    // 1. Query range for `up` metric
    let range_url = format!(
        "{base}/api/v1/query_range?query=up&start={}&end={}&step=60s",
        start.timestamp(),
        end.timestamp(),
    );

    let mut req = client.get(&range_url);
    if let Some(token) = &cfg.token {
        req = req.bearer_auth(token);
    }

    match req.send().await {
        Ok(resp) => match resp.error_for_status() {
            Ok(r) => match r.json::<QueryResponse>().await {
                Ok(qr) => {
                    snap.up_samples = qr
                        .data
                        .result
                        .into_iter()
                        .map(|entry| {
                            let labels = format_labels(&entry.metric);
                            let metric_name = entry
                                .metric
                                .get("__name__")
                                .and_then(|v| v.as_str())
                                .unwrap_or("up")
                                .to_string();
                            let values = entry
                                .values
                                .into_iter()
                                .map(|(ts, val)| (ts, parse_sample_value(&val)))
                                .collect();
                            MetricSample {
                                metric_name,
                                labels,
                                values,
                            }
                        })
                        .collect();
                }
                Err(e) => tracing::warn!("prometheus: failed to parse query_range: {e:#}"),
            },
            Err(e) => tracing::warn!("prometheus: query_range error status: {e:#}"),
        },
        Err(e) => tracing::warn!("prometheus: could not reach query_range API: {e:#}"),
    }

    // 2. Query instant for active ALERTS
    let alerts_url = format!("{base}/api/v1/query?query=ALERTS");

    let mut req = client.get(&alerts_url);
    if let Some(token) = &cfg.token {
        req = req.bearer_auth(token);
    }

    match req.send().await {
        Ok(resp) => match resp.error_for_status() {
            Ok(r) => match r.json::<QueryResponse>().await {
                Ok(qr) => {
                    snap.active_alerts = qr
                        .data
                        .result
                        .into_iter()
                        .map(|entry| {
                            let name = entry
                                .metric
                                .get("alertname")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let state = entry
                                .metric
                                .get("alertstate")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let labels = format_labels(&entry.metric);
                            let value = entry
                                .value
                                .as_ref()
                                .map(|(_, v)| sample_value_str(v))
                                .unwrap_or_default();
                            ActiveAlert {
                                name,
                                state,
                                labels,
                                value,
                            }
                        })
                        .collect();
                }
                Err(e) => tracing::warn!("prometheus: failed to parse alerts query: {e:#}"),
            },
            Err(e) => tracing::warn!("prometheus: alerts query error status: {e:#}"),
        },
        Err(e) => tracing::warn!("prometheus: could not reach alerts API: {e:#}"),
    }

    Ok(snap)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_labels(metric: &serde_json::Map<String, serde_json::Value>) -> String {
    metric
        .iter()
        .filter(|(k, _)| k.as_str() != "__name__")
        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("?")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_sample_value(v: &serde_json::Value) -> f64 {
    match v {
        serde_json::Value::String(s) => s.parse().unwrap_or(0.0),
        serde_json::Value::Number(n) => n.as_f64().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn sample_value_str(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_labels_filters_name() {
        let mut map = serde_json::Map::new();
        map.insert("__name__".into(), "up".into());
        map.insert("instance".into(), "localhost:9090".into());
        map.insert("job".into(), "node".into());
        let result = format_labels(&map);
        assert!(!result.contains("__name__"));
        assert!(result.contains("instance=localhost:9090"));
        assert!(result.contains("job=node"));
    }

    #[test]
    fn parse_sample_value_string() {
        let v = serde_json::Value::String("1.5".into());
        assert!((parse_sample_value(&v) - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_sample_value_number() {
        let v = serde_json::json!(42.0);
        assert!((parse_sample_value(&v) - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn deserialize_query_response() {
        let json = r#"{"data":{"resultType":"matrix","result":[{"metric":{"__name__":"up","job":"node"},"values":[[1710000000,"1"],[1710000060,"0"]]}]}}"#;
        let resp: QueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.result.len(), 1);
        assert_eq!(resp.data.result[0].values.len(), 2);
    }

    #[test]
    fn deserialize_alerts_response() {
        let json = r#"{"data":{"resultType":"vector","result":[{"metric":{"__name__":"ALERTS","alertname":"HighMemory","alertstate":"firing"},"value":[1710000000,"1"]}]}}"#;
        let resp: QueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.result.len(), 1);
        let alert_name = resp.data.result[0]
            .metric
            .get("alertname")
            .and_then(|v| v.as_str());
        assert_eq!(alert_name, Some("HighMemory"));
    }

    #[test]
    fn sample_value_str_string() {
        let v = serde_json::Value::String("1".into());
        assert_eq!(sample_value_str(&v), "1");
    }

    #[test]
    fn sample_value_str_other() {
        let v = serde_json::json!(42);
        assert_eq!(sample_value_str(&v), "42");
    }
}
