//! Seq structured log API data source.
//!
//! Queries `GET /api/events?count=50&filter=@Level='Error'&apiKey={key}` and
//! returns matching entries as [`LogEntry`] values.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::ops::data_sources::SeqConfig;
use crate::ops::log_sources::{LogEntry, LogLevel};

// ---------------------------------------------------------------------------
// Seq API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SeqEvent {
    #[serde(rename = "Timestamp")]
    timestamp: Option<String>,
    #[serde(rename = "Level")]
    level: Option<String>,
    #[serde(rename = "RenderedMessage")]
    rendered_message: Option<String>,
    #[serde(rename = "Exception")]
    exception: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch recent error-level events from a Seq instance.
pub async fn fetch_error_logs(cfg: &SeqConfig) -> Result<Vec<LogEntry>> {
    let url = format!(
        "{}/api/events?count=50&filter=@Level%3D'Error'",
        cfg.url.trim_end_matches('/')
    );

    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if let Some(key) = &cfg.api_key {
        req = req.header("X-Seq-ApiKey", key);
    }

    let resp = req
        .send()
        .await
        .context("failed to reach Seq API")?
        .error_for_status()
        .context("Seq API returned error status")?;

    let events: Vec<SeqEvent> = resp.json().await.context("failed to parse Seq response")?;

    let entries = events
        .into_iter()
        .map(|ev| {
            let timestamp = ev
                .timestamp
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            let level = ev.level.as_deref().and_then(map_seq_level);

            let mut message = ev.rendered_message.unwrap_or_default();
            if let Some(exc) = &ev.exception {
                if !exc.is_empty() {
                    message = format!("{message}\n  exception: {exc}");
                }
            }

            LogEntry {
                timestamp,
                source: "seq".into(),
                level,
                message: message.clone(),
                raw: message,
            }
        })
        .collect();

    Ok(entries)
}

fn map_seq_level(s: &str) -> Option<LogLevel> {
    match s {
        "Fatal" => Some(LogLevel::Fatal),
        "Error" => Some(LogLevel::Error),
        "Warning" => Some(LogLevel::Warn),
        "Information" => Some(LogLevel::Info),
        "Debug" | "Verbose" => Some(LogLevel::Debug),
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
    fn map_seq_levels() {
        assert_eq!(map_seq_level("Fatal"), Some(LogLevel::Fatal));
        assert_eq!(map_seq_level("Error"), Some(LogLevel::Error));
        assert_eq!(map_seq_level("Warning"), Some(LogLevel::Warn));
        assert_eq!(map_seq_level("Information"), Some(LogLevel::Info));
        assert_eq!(map_seq_level("Debug"), Some(LogLevel::Debug));
        assert_eq!(map_seq_level("Verbose"), Some(LogLevel::Debug));
        assert_eq!(map_seq_level("Unknown"), None);
    }

    #[test]
    fn deserialize_seq_event() {
        let json = r#"{"Timestamp":"2024-03-17T12:00:00Z","Level":"Error","RenderedMessage":"boom","Exception":"NullRef"}"#;
        let ev: SeqEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.level.as_deref(), Some("Error"));
        assert_eq!(ev.rendered_message.as_deref(), Some("boom"));
        assert_eq!(ev.exception.as_deref(), Some("NullRef"));
    }
}
