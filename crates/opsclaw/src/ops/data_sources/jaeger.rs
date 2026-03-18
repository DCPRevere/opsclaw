//! Jaeger trace API data source.
//!
//! Queries `/api/services` to list services, then
//! `/api/traces?service={name}&limit=20` for recent traces. Flags traces
//! with `error=true` tags or high latency (>2 s).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::ops::data_sources::JaegerConfig;

/// High-latency threshold in microseconds (2 seconds).
const HIGH_LATENCY_US: u64 = 2_000_000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    pub trace_id: String,
    pub service: String,
    pub span_count: usize,
    pub duration_ms: u64,
    pub has_error: bool,
    pub high_latency: bool,
}

// ---------------------------------------------------------------------------
// Jaeger API response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ServicesResponse {
    data: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TracesResponse {
    data: Vec<TraceData>,
}

#[derive(Debug, Deserialize)]
struct TraceData {
    #[serde(rename = "traceID")]
    trace_id: String,
    spans: Vec<SpanData>,
}

#[derive(Debug, Deserialize)]
struct SpanData {
    #[serde(default)]
    duration: u64,
    #[serde(default)]
    tags: Vec<Tag>,
}

#[derive(Debug, Deserialize)]
struct Tag {
    key: String,
    value: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch all services, then retrieve recent traces and flag problems.
pub async fn fetch_problem_traces(cfg: &JaegerConfig) -> Result<Vec<TraceSummary>> {
    let base = cfg.url.trim_end_matches('/');
    let client = reqwest::Client::new();

    // 1. List services
    let services: ServicesResponse = client
        .get(format!("{base}/api/services"))
        .send()
        .await
        .context("failed to reach Jaeger services API")?
        .error_for_status()
        .context("Jaeger services API error")?
        .json()
        .await
        .context("failed to parse Jaeger services response")?;

    let mut summaries = Vec::new();

    // 2. For each service, fetch recent traces
    for svc in &services.data {
        let traces: TracesResponse = match client
            .get(format!("{base}/api/traces?service={svc}&limit=20"))
            .send()
            .await
        {
            Ok(resp) => match resp.error_for_status() {
                Ok(r) => match r.json().await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!("jaeger: failed to parse traces for {svc}: {e:#}");
                        continue;
                    }
                },
                Err(e) => {
                    tracing::warn!("jaeger: error fetching traces for {svc}: {e:#}");
                    continue;
                }
            },
            Err(e) => {
                tracing::warn!("jaeger: could not reach traces API for {svc}: {e:#}");
                continue;
            }
        };

        for trace in &traces.data {
            let span_count = trace.spans.len();
            let duration_us = trace.spans.iter().map(|s| s.duration).max().unwrap_or(0);
            let has_error = trace.spans.iter().any(|s| {
                s.tags.iter().any(|t| {
                    t.key == "error"
                        && matches!(&t.value, serde_json::Value::Bool(true)
                            | serde_json::Value::String(s) if s == "true")
                })
            });
            let high_latency = duration_us > HIGH_LATENCY_US;

            if has_error || high_latency {
                summaries.push(TraceSummary {
                    trace_id: trace.trace_id.clone(),
                    service: svc.clone(),
                    span_count,
                    duration_ms: duration_us / 1000,
                    has_error,
                    high_latency,
                });
            }
        }
    }

    Ok(summaries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_services_response() {
        let json = r#"{"data":["frontend","backend"]}"#;
        let resp: ServicesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data, vec!["frontend", "backend"]);
    }

    #[test]
    fn deserialize_traces_response() {
        let json = r#"{"data":[{"traceID":"abc123","spans":[{"duration":1500000,"tags":[{"key":"error","value":true}]}]}]}"#;
        let resp: TracesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].trace_id, "abc123");
        assert_eq!(resp.data[0].spans[0].duration, 1_500_000);
    }

    #[test]
    fn error_tag_detected() {
        let tag = Tag {
            key: "error".into(),
            value: serde_json::Value::Bool(true),
        };
        assert!(tag.key == "error" && matches!(&tag.value, serde_json::Value::Bool(true)));
    }

    #[test]
    fn high_latency_threshold() {
        assert!(3_000_000u64 > HIGH_LATENCY_US);
        assert!(1_000_000u64 <= HIGH_LATENCY_US);
    }
}
