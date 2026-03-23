//! Scout — skill discovery from external sources.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// ScoutSource
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScoutSource {
    GitHub,
    ClawHub,
    HuggingFace,
}

impl std::str::FromStr for ScoutSource {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "github" => Self::GitHub,
            "clawhub" => Self::ClawHub,
            "huggingface" | "hf" => Self::HuggingFace,
            _ => {
                warn!(source = s, "Unknown scout source, defaulting to GitHub");
                Self::GitHub
            }
        })
    }
}

// ---------------------------------------------------------------------------
// ScoutResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoutResult {
    pub name: String,
    pub url: String,
    pub description: String,
    pub stars: u64,
    pub language: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub source: ScoutSource,
    /// Owner / org extracted from the URL or API response.
    pub owner: String,
    /// Whether the repo has a license file.
    pub has_license: bool,
}

// ---------------------------------------------------------------------------
// Scout trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait Scout: Send + Sync {
    /// Discover candidate skills from the source.
    async fn discover(&self) -> Result<Vec<ScoutResult>>;
}

// ---------------------------------------------------------------------------
// GitHubScout
// ---------------------------------------------------------------------------

/// Searches GitHub for repos matching skill-related queries.
pub struct GitHubScout {
    client: reqwest::Client,
    queries: Vec<String>,
}

impl GitHubScout {
    pub fn new(token: Option<&str>) -> Self {
        use std::time::Duration;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            "application/vnd.github+json".parse().expect("valid header"),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            "OpsClaw-SkillForge/0.1".parse().expect("valid header"),
        );
        if let Some(t) = token {
            if let Ok(val) = format!("Bearer {t}").parse() {
                headers.insert(reqwest::header::AUTHORIZATION, val);
            }
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            queries: vec!["opsclaw skill".into(), "ai agent skill".into()],
        }
    }

    /// Parse the GitHub search/repositories JSON response.
    fn parse_items(body: &serde_json::Value) -> Vec<ScoutResult> {
        let items = match body.get("items").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => return vec![],
        };

        items
            .iter()
            .filter_map(|item| {
                let name = item.get("name")?.as_str()?.to_string();
                let url = item.get("html_url")?.as_str()?.to_string();
                let description = item
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let stars = item
                    .get("stargazers_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let language = item
                    .get("language")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let updated_at = item
                    .get("updated_at")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok());
                let owner = item
                    .get("owner")
                    .and_then(|o| o.get("login"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let has_license = item.get("license").map(|v| !v.is_null()).unwrap_or(false);

                Some(ScoutResult {
                    name,
                    url,
                    description,
                    stars,
                    language,
                    updated_at,
                    source: ScoutSource::GitHub,
                    owner,
                    has_license,
                })
            })
            .collect()
    }
}

#[async_trait]
impl Scout for GitHubScout {
    async fn discover(&self) -> Result<Vec<ScoutResult>> {
        let mut all: Vec<ScoutResult> = Vec::new();

        for query in &self.queries {
            let url = format!(
                "https://api.github.com/search/repositories?q={}&sort=stars&order=desc&per_page=30",
                urlencoding(query)
            );
            debug!(query = query.as_str(), "Searching GitHub");

            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        query = query.as_str(),
                        error = %e,
                        "GitHub API request failed, skipping query"
                    );
                    continue;
                }
            };

            if !resp.status().is_success() {
                warn!(
                    status = %resp.status(),
                    query = query.as_str(),
                    "GitHub search returned non-200"
                );
                continue;
            }

            let body: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        query = query.as_str(),
                        error = %e,
                        "Failed to parse GitHub response, skipping query"
                    );
                    continue;
                }
            };

            let mut items = Self::parse_items(&body);
            debug!(count = items.len(), query = query.as_str(), "Parsed items");
            all.append(&mut items);
        }

        dedup(&mut all);
        Ok(all)
    }
}

// ---------------------------------------------------------------------------
// ClawHubScout
// ---------------------------------------------------------------------------

/// Discovers skills from the ClawHub skill registry at clawhub.com.
pub struct ClawHubScout {
    client: reqwest::Client,
}

impl ClawHubScout {
    pub fn new() -> Self {
        use std::time::Duration;

        let client = reqwest::Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    reqwest::header::USER_AGENT,
                    "OpsClaw-SkillForge/0.1".parse().expect("valid header"),
                );
                h.insert(
                    reqwest::header::ACCEPT,
                    "application/json".parse().expect("valid header"),
                );
                h
            })
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Self { client }
    }

    fn parse_items(body: &serde_json::Value) -> Vec<ScoutResult> {
        // Try top-level array or nested "skills" / "items" key.
        let items = body
            .as_array()
            .or_else(|| body.get("skills").and_then(|v| v.as_array()))
            .or_else(|| body.get("items").and_then(|v| v.as_array()));

        let items = match items {
            Some(arr) => arr,
            None => return vec![],
        };

        items
            .iter()
            .filter_map(|item| {
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())?
                    .to_string();
                let url = item
                    .get("url")
                    .or_else(|| item.get("html_url"))
                    .or_else(|| item.get("homepage"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| format!("https://clawhub.com/skills/{name}"));
                let description = item
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let stars = item
                    .get("stars")
                    .or_else(|| item.get("downloads"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let owner = item
                    .get("author")
                    .or_else(|| item.get("owner"))
                    .and_then(|v| v.as_str().or_else(|| v.get("login").and_then(|l| l.as_str())))
                    .unwrap_or("unknown")
                    .to_string();
                let updated_at = item
                    .get("updated_at")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok());
                let has_license = item
                    .get("license")
                    .map(|v| !v.is_null() && v.as_str() != Some(""))
                    .unwrap_or(false);

                Some(ScoutResult {
                    name,
                    url,
                    description,
                    stars,
                    language: None,
                    updated_at,
                    source: ScoutSource::ClawHub,
                    owner,
                    has_license,
                })
            })
            .collect()
    }
}

#[async_trait]
impl Scout for ClawHubScout {
    async fn discover(&self) -> Result<Vec<ScoutResult>> {
        let urls = [
            "https://clawhub.com/api/skills",
            "https://clawhub.com/skills",
        ];

        for url in &urls {
            debug!(url, "Fetching ClawHub skills");
            let resp = match self.client.get(*url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(url, error = %e, "ClawHub request failed, trying next URL");
                    continue;
                }
            };

            if !resp.status().is_success() {
                warn!(url, status = %resp.status(), "ClawHub returned non-200, trying next URL");
                continue;
            }

            let body: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(url, error = %e, "Failed to parse ClawHub response");
                    continue;
                }
            };

            let items = Self::parse_items(&body);
            info!(count = items.len(), "ClawHub scout returned candidates");
            return Ok(items);
        }

        warn!("All ClawHub endpoints failed — returning empty results");
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// HuggingFaceScout
// ---------------------------------------------------------------------------

/// Discovers opsclaw-related models and datasets from the HuggingFace Hub API.
pub struct HuggingFaceScout {
    client: reqwest::Client,
}

impl HuggingFaceScout {
    pub fn new() -> Self {
        use std::time::Duration;

        let client = reqwest::Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    reqwest::header::USER_AGENT,
                    "OpsClaw-SkillForge/0.1".parse().expect("valid header"),
                );
                h
            })
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Self { client }
    }

    fn parse_models(body: &serde_json::Value) -> Vec<ScoutResult> {
        let items = match body.as_array() {
            Some(arr) => arr,
            None => return vec![],
        };

        items
            .iter()
            .filter_map(|item| {
                let model_id = item.get("modelId").or_else(|| item.get("id"));
                let id = model_id?.as_str()?.to_string();
                let (owner, name) = id.split_once('/').unwrap_or(("unknown", &id));
                let url = format!("https://huggingface.co/{id}");
                let description = item
                    .get("description")
                    .or_else(|| item.get("cardData").and_then(|c| c.get("description")))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let stars = item
                    .get("likes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let updated_at = item
                    .get("lastModified")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok());
                let has_license = item
                    .get("cardData")
                    .and_then(|c| c.get("license"))
                    .map(|v| !v.is_null())
                    .unwrap_or(false);

                Some(ScoutResult {
                    name: name.to_string(),
                    url,
                    description,
                    stars,
                    language: None,
                    updated_at,
                    source: ScoutSource::HuggingFace,
                    owner: owner.to_string(),
                    has_license,
                })
            })
            .collect()
    }

    fn parse_datasets(body: &serde_json::Value) -> Vec<ScoutResult> {
        let items = match body.as_array() {
            Some(arr) => arr,
            None => return vec![],
        };

        items
            .iter()
            .filter_map(|item| {
                let id = item.get("id")?.as_str()?.to_string();
                let (owner, name) = id.split_once('/').unwrap_or(("unknown", &id));
                let url = format!("https://huggingface.co/datasets/{id}");
                let description = item
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let stars = item
                    .get("likes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let updated_at = item
                    .get("lastModified")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok());

                Some(ScoutResult {
                    name: name.to_string(),
                    url,
                    description,
                    stars,
                    language: None,
                    updated_at,
                    source: ScoutSource::HuggingFace,
                    owner: owner.to_string(),
                    has_license: false,
                })
            })
            .collect()
    }
}

#[async_trait]
impl Scout for HuggingFaceScout {
    async fn discover(&self) -> Result<Vec<ScoutResult>> {
        let mut all: Vec<ScoutResult> = Vec::new();

        let endpoints = [
            "https://huggingface.co/api/models?search=opsclaw&limit=20",
            "https://huggingface.co/api/datasets?search=opsclaw&limit=20",
        ];

        for (i, url) in endpoints.iter().enumerate() {
            let kind = if i == 0 { "models" } else { "datasets" };
            debug!(kind, "Fetching HuggingFace {kind}");

            let resp = match self.client.get(*url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(kind, error = %e, "HuggingFace {kind} request failed");
                    continue;
                }
            };

            if !resp.status().is_success() {
                warn!(kind, status = %resp.status(), "HuggingFace {kind} returned non-200");
                continue;
            }

            let body: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(kind, error = %e, "Failed to parse HuggingFace {kind} response");
                    continue;
                }
            };

            let mut items = if i == 0 {
                Self::parse_models(&body)
            } else {
                Self::parse_datasets(&body)
            };
            debug!(count = items.len(), kind, "Parsed HuggingFace {kind}");
            all.append(&mut items);
        }

        dedup(&mut all);
        info!(count = all.len(), "HuggingFace scout returned candidates");
        Ok(all)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal percent-encoding for query strings (space → +).
fn urlencoding(s: &str) -> String {
    s.replace(' ', "+").replace('&', "%26").replace('#', "%23")
}

/// Deduplicate scout results by URL (keeps first occurrence).
pub fn dedup(results: &mut Vec<ScoutResult>) {
    let mut seen = std::collections::HashSet::new();
    results.retain(|r| seen.insert(r.url.clone()));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scout_source_from_str() {
        assert_eq!(
            "github".parse::<ScoutSource>().unwrap(),
            ScoutSource::GitHub
        );
        assert_eq!(
            "GitHub".parse::<ScoutSource>().unwrap(),
            ScoutSource::GitHub
        );
        assert_eq!(
            "clawhub".parse::<ScoutSource>().unwrap(),
            ScoutSource::ClawHub
        );
        assert_eq!(
            "huggingface".parse::<ScoutSource>().unwrap(),
            ScoutSource::HuggingFace
        );
        assert_eq!(
            "hf".parse::<ScoutSource>().unwrap(),
            ScoutSource::HuggingFace
        );
        // unknown falls back to GitHub
        assert_eq!(
            "unknown".parse::<ScoutSource>().unwrap(),
            ScoutSource::GitHub
        );
    }

    #[test]
    fn dedup_removes_duplicates() {
        let mut results = vec![
            ScoutResult {
                name: "a".into(),
                url: "https://github.com/x/a".into(),
                description: String::new(),
                stars: 10,
                language: None,
                updated_at: None,
                source: ScoutSource::GitHub,
                owner: "x".into(),
                has_license: true,
            },
            ScoutResult {
                name: "a-dup".into(),
                url: "https://github.com/x/a".into(),
                description: String::new(),
                stars: 10,
                language: None,
                updated_at: None,
                source: ScoutSource::GitHub,
                owner: "x".into(),
                has_license: true,
            },
            ScoutResult {
                name: "b".into(),
                url: "https://github.com/x/b".into(),
                description: String::new(),
                stars: 5,
                language: None,
                updated_at: None,
                source: ScoutSource::GitHub,
                owner: "x".into(),
                has_license: false,
            },
        ];
        dedup(&mut results);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "a");
        assert_eq!(results[1].name, "b");
    }

    #[test]
    fn parse_github_items() {
        let json = serde_json::json!({
            "total_count": 1,
            "items": [
                {
                    "name": "cool-skill",
                    "html_url": "https://github.com/user/cool-skill",
                    "description": "A cool skill",
                    "stargazers_count": 42,
                    "language": "Rust",
                    "updated_at": "2026-01-15T10:00:00Z",
                    "owner": { "login": "user" },
                    "license": { "spdx_id": "MIT" }
                }
            ]
        });
        let items = GitHubScout::parse_items(&json);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "cool-skill");
        assert_eq!(items[0].stars, 42);
        assert!(items[0].has_license);
        assert_eq!(items[0].owner, "user");
    }

    #[test]
    fn urlencoding_works() {
        assert_eq!(urlencoding("hello world"), "hello+world");
        assert_eq!(urlencoding("a&b#c"), "a%26b%23c");
    }

    #[test]
    fn parse_clawhub_items_from_skills_key() {
        let json = serde_json::json!({
            "skills": [
                {
                    "name": "deploy-monitor",
                    "url": "https://clawhub.com/skills/deploy-monitor",
                    "description": "Monitors deployments",
                    "stars": 15,
                    "author": "acme",
                    "license": "MIT"
                }
            ]
        });
        let items = ClawHubScout::parse_items(&json);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "deploy-monitor");
        assert_eq!(items[0].source, ScoutSource::ClawHub);
        assert_eq!(items[0].owner, "acme");
        assert!(items[0].has_license);
    }

    #[test]
    fn parse_clawhub_items_from_top_level_array() {
        let json = serde_json::json!([
            {
                "name": "log-parser",
                "description": "Parses logs",
                "downloads": 100,
                "author": "bob"
            }
        ]);
        let items = ClawHubScout::parse_items(&json);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "log-parser");
        assert_eq!(items[0].stars, 100);
        assert_eq!(items[0].url, "https://clawhub.com/skills/log-parser");
        assert!(!items[0].has_license);
    }

    #[test]
    fn parse_clawhub_empty_object() {
        let json = serde_json::json!({});
        let items = ClawHubScout::parse_items(&json);
        assert!(items.is_empty());
    }

    #[test]
    fn parse_hf_models() {
        let json = serde_json::json!([
            {
                "modelId": "acme/opsclaw-skill-gen",
                "likes": 7,
                "lastModified": "2026-02-01T12:00:00Z",
                "cardData": {
                    "description": "Generates skills",
                    "license": "apache-2.0"
                }
            }
        ]);
        let items = HuggingFaceScout::parse_models(&json);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "opsclaw-skill-gen");
        assert_eq!(items[0].owner, "acme");
        assert_eq!(items[0].stars, 7);
        assert_eq!(items[0].source, ScoutSource::HuggingFace);
        assert!(items[0].has_license);
        assert_eq!(items[0].url, "https://huggingface.co/acme/opsclaw-skill-gen");
    }

    #[test]
    fn parse_hf_models_no_owner_slash() {
        let json = serde_json::json!([
            { "modelId": "standalone-model", "likes": 0 }
        ]);
        let items = HuggingFaceScout::parse_models(&json);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].owner, "unknown");
        assert_eq!(items[0].name, "standalone-model");
    }

    #[test]
    fn parse_hf_datasets() {
        let json = serde_json::json!([
            {
                "id": "org/opsclaw-data",
                "likes": 3,
                "description": "Training data"
            }
        ]);
        let items = HuggingFaceScout::parse_datasets(&json);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "opsclaw-data");
        assert_eq!(items[0].owner, "org");
        assert_eq!(items[0].url, "https://huggingface.co/datasets/org/opsclaw-data");
    }

    #[test]
    fn parse_hf_empty_response() {
        let json = serde_json::json!([]);
        assert!(HuggingFaceScout::parse_models(&json).is_empty());
        assert!(HuggingFaceScout::parse_datasets(&json).is_empty());

        let json = serde_json::json!("not an array");
        assert!(HuggingFaceScout::parse_models(&json).is_empty());
    }
}
