//! GitHub releases API data source.
//!
//! Queries `GET /repos/{owner}/{repo}/releases/latest` and returns the
//! tag name, published timestamp, and release name. Useful for detecting
//! when the most recent deploy happened.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ops::data_sources::GithubConfig;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    pub name: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// GitHub API response (only the fields we care about)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    name: Option<String>,
    published_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch the latest release for the configured repository.
pub async fn fetch_latest_release(cfg: &GithubConfig) -> Result<Option<ReleaseInfo>> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", cfg.repo);

    let client = reqwest::Client::builder()
        .user_agent("opsclaw")
        .build()
        .context("failed to build HTTP client")?;

    let mut req = client.get(&url);
    if let Some(token) = &cfg.token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await.context("failed to reach GitHub API")?;

    // 404 means no releases exist — not an error.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let resp = resp
        .error_for_status()
        .context("GitHub API returned error status")?;

    let gh: GhRelease = resp
        .json()
        .await
        .context("failed to parse GitHub release response")?;

    let published_at = gh
        .published_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    Ok(Some(ReleaseInfo {
        tag_name: gh.tag_name,
        name: gh.name,
        published_at,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_gh_release() {
        let json =
            r#"{"tag_name":"v1.2.3","name":"Release 1.2.3","published_at":"2024-03-17T12:00:00Z"}"#;
        let rel: GhRelease = serde_json::from_str(json).unwrap();
        assert_eq!(rel.tag_name, "v1.2.3");
        assert_eq!(rel.name.as_deref(), Some("Release 1.2.3"));
        assert_eq!(rel.published_at.as_deref(), Some("2024-03-17T12:00:00Z"));
    }

    #[test]
    fn deserialize_gh_release_minimal() {
        let json = r#"{"tag_name":"v0.1.0","name":null,"published_at":null}"#;
        let rel: GhRelease = serde_json::from_str(json).unwrap();
        assert_eq!(rel.tag_name, "v0.1.0");
        assert!(rel.name.is_none());
        assert!(rel.published_at.is_none());
    }
}
