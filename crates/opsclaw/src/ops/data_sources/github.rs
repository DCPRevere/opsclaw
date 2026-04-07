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

/// A single GitHub Actions workflow run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub id: u64,
    pub name: Option<String>,
    pub status: String,
    pub conclusion: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub html_url: String,
}

/// A git tag with its commit SHA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoTag {
    pub name: String,
    pub commit_sha: String,
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

#[derive(Debug, Deserialize)]
struct GhWorkflowRunsResponse {
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(Debug, Deserialize)]
struct GhTagCommit {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GhTag {
    name: String,
    commit: GhTagCommit,
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

/// Fetch the most recent workflow runs for the configured repository.
pub async fn fetch_recent_runs(cfg: &GithubConfig) -> Result<Vec<WorkflowRun>> {
    let url = format!(
        "https://api.github.com/repos/{}/actions/runs?per_page=5",
        cfg.repo
    );

    let client = reqwest::Client::builder()
        .user_agent("opsclaw")
        .build()
        .context("failed to build HTTP client")?;

    let mut req = client.get(&url);
    if let Some(token) = &cfg.token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await.context("failed to reach GitHub API")?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }

    let resp = resp
        .error_for_status()
        .context("GitHub API returned error status")?;

    let body: GhWorkflowRunsResponse = resp
        .json()
        .await
        .context("failed to parse GitHub workflow runs response")?;

    Ok(body.workflow_runs)
}

/// Fetch recent tags for the configured repository.
pub async fn fetch_recent_tags(cfg: &GithubConfig) -> Result<Vec<RepoTag>> {
    let url = format!(
        "https://api.github.com/repos/{}/tags?per_page=10",
        cfg.repo
    );

    let client = reqwest::Client::builder()
        .user_agent("opsclaw")
        .build()
        .context("failed to build HTTP client")?;

    let mut req = client.get(&url);
    if let Some(token) = &cfg.token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await.context("failed to reach GitHub API")?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }

    let resp = resp
        .error_for_status()
        .context("GitHub API returned error status")?;

    let tags: Vec<GhTag> = resp
        .json()
        .await
        .context("failed to parse GitHub tags response")?;

    Ok(tags
        .into_iter()
        .map(|t| RepoTag {
            name: t.name,
            commit_sha: t.commit.sha,
        })
        .collect())
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

    #[test]
    fn deserialize_workflow_runs_response() {
        let json = r#"{
            "total_count": 1,
            "workflow_runs": [{
                "id": 42,
                "name": "CI",
                "status": "completed",
                "conclusion": "success",
                "created_at": "2024-03-17T12:00:00Z",
                "updated_at": "2024-03-17T12:05:00Z",
                "html_url": "https://github.com/owner/repo/actions/runs/42"
            }]
        }"#;
        let resp: GhWorkflowRunsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.workflow_runs.len(), 1);
        assert_eq!(resp.workflow_runs[0].id, 42);
        assert_eq!(resp.workflow_runs[0].status, "completed");
        assert_eq!(resp.workflow_runs[0].conclusion.as_deref(), Some("success"));
    }

    #[test]
    fn deserialize_workflow_run_in_progress() {
        let json = r#"{
            "total_count": 1,
            "workflow_runs": [{
                "id": 99,
                "name": null,
                "status": "in_progress",
                "conclusion": null,
                "created_at": null,
                "updated_at": null,
                "html_url": "https://github.com/owner/repo/actions/runs/99"
            }]
        }"#;
        let resp: GhWorkflowRunsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.workflow_runs[0].status, "in_progress");
        assert!(resp.workflow_runs[0].conclusion.is_none());
    }

    #[test]
    fn deserialize_gh_tags() {
        let json = r#"[
            {"name": "v1.0.0", "commit": {"sha": "abc1234"}},
            {"name": "v0.9.0", "commit": {"sha": "def5678"}}
        ]"#;
        let tags: Vec<GhTag> = serde_json::from_str(json).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].name, "v1.0.0");
        assert_eq!(tags[0].commit.sha, "abc1234");
        assert_eq!(tags[1].name, "v0.9.0");
    }
}
