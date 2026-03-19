//! Git log + Docker inspect deployment correlation data source.
//!
//! Runs `git -C {path} log --oneline --since={window} -20` on the target for
//! each configured path, parses the output into recent commits, then
//! cross-references commit timestamps with Docker container creation times to
//! identify deployments that may have caused issues.
//!
//! This is a zero-config source: if `git_paths` is not explicitly configured
//! the source is silently skipped. When configured, it needs only path list —
//! no API keys, tokens, or external services.

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::tools::discovery::CommandRunner;

use super::docker_inspect::ContainerStartTime;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single parsed commit from `git log --oneline`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentCommit {
    pub hash: String,
    pub message: String,
    pub date: DateTime<Utc>,
    pub repo_path: String,
}

/// A commit that happened shortly before a container was (re)created,
/// suggesting it may be part of the deployment that triggered the restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployCorrelation {
    pub commit: RecentCommit,
    pub container: String,
    pub container_started_at: DateTime<Utc>,
    /// How many seconds before the container start the commit was made.
    pub lag_seconds: i64,
}

/// Full result from the git-deploy data source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitDeploySnapshot {
    pub recent_commits: Vec<RecentCommit>,
    pub correlations: Vec<DeployCorrelation>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Default look-back window for `git log --since`.
const DEFAULT_WINDOW_HOURS: u64 = 24;

/// Maximum lag (in seconds) between a commit and a container start to consider
/// them correlated. 30 minutes covers most CI/CD pipelines.
const CORRELATION_WINDOW_SECS: i64 = 1800;

/// Fetch recent commits from git repos on the target and correlate with
/// container start times.
pub async fn fetch_git_deploy_snapshot(
    runner: &dyn CommandRunner,
    paths: &[String],
    docker_deploys: &[ContainerStartTime],
    window_hours: Option<u64>,
) -> Result<GitDeploySnapshot> {
    let window = window_hours.unwrap_or(DEFAULT_WINDOW_HOURS);
    let mut all_commits = Vec::new();

    for path in paths {
        match fetch_recent_commits(runner, path, window).await {
            Ok(commits) => all_commits.extend(commits),
            Err(e) => {
                tracing::warn!("git log for {path} failed: {e:#}");
                continue;
            }
        }
    }

    let correlations = correlate_commits(&all_commits, docker_deploys);

    Ok(GitDeploySnapshot {
        recent_commits: all_commits,
        correlations,
    })
}

/// Format the snapshot as markdown suitable for LLM diagnosis context.
pub fn format_as_markdown(snap: &GitDeploySnapshot, window_hours: u64) -> String {
    if snap.recent_commits.is_empty() && snap.correlations.is_empty() {
        return String::new();
    }

    let mut md = format!("## Deployment Activity (last {window_hours}h)\n\n");

    if !snap.correlations.is_empty() {
        md.push_str("### Commits correlated with container restarts\n\n");
        for c in &snap.correlations {
            md.push_str(&format!(
                "- `{}` {} (repo: {}) — container **{}** started {}s later\n",
                c.commit.hash, c.commit.message, c.commit.repo_path, c.container, c.lag_seconds,
            ));
        }
        md.push('\n');
    }

    if !snap.recent_commits.is_empty() {
        md.push_str("### Recent commits\n\n");
        for c in &snap.recent_commits {
            md.push_str(&format!(
                "- `{}` {} ({}, {})\n",
                c.hash,
                c.message,
                c.repo_path,
                c.date.format("%Y-%m-%dT%H:%M:%SZ"),
            ));
        }
    }

    md
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Run `git log` on a single repo path and parse the output.
async fn fetch_recent_commits(
    runner: &dyn CommandRunner,
    path: &str,
    window_hours: u64,
) -> Result<Vec<RecentCommit>> {
    let cmd =
        format!("git -C {path} log --format='%H %aI %s' --since='{window_hours} hours ago' -20");
    let output = runner
        .run(&cmd)
        .await
        .context(format!("git log failed for {path}"))?;

    if output.exit_code != 0 {
        anyhow::bail!(
            "git log exited with code {} for {path}: {}",
            output.exit_code,
            output.stderr.trim()
        );
    }

    parse_git_log_output(&output.stdout, path)
}

/// Parse lines of `git log --format='%H %aI %s'`.
fn parse_git_log_output(stdout: &str, repo_path: &str) -> Result<Vec<RecentCommit>> {
    let mut commits = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Format: <full-hash> <ISO-8601-date> <subject>
        // The hash is 40 hex chars, then a space, then the date (variable length), then a space, then subject.
        let (hash, rest) = line
            .split_once(' ')
            .context("expected space after commit hash")?;

        let (date_str, message) = rest.split_once(' ').context("expected space after date")?;

        let date = parse_git_date(date_str).unwrap_or_else(|_| Utc::now());

        commits.push(RecentCommit {
            hash: hash.chars().take(12).collect(),
            message: message.to_string(),
            date,
            repo_path: repo_path.to_string(),
        });
    }

    Ok(commits)
}

/// Parse an ISO-8601 date as produced by git's `%aI` format.
fn parse_git_date(s: &str) -> Result<DateTime<Utc>> {
    // Try RFC 3339 first (most common from git %aI).
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    // Fallback: parse as naive datetime and assume UTC.
    let naive = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .context("failed to parse git date")?;
    Ok(naive.and_utc())
}

/// Find commits that occurred shortly before container start times.
fn correlate_commits(
    commits: &[RecentCommit],
    deploys: &[ContainerStartTime],
) -> Vec<DeployCorrelation> {
    let mut correlations = Vec::new();

    for deploy in deploys {
        for commit in commits {
            let lag = (deploy.started_at - commit.date).num_seconds();
            // Commit should be *before* the container start (lag > 0) and
            // within the correlation window.
            if lag > 0 && lag <= CORRELATION_WINDOW_SECS {
                correlations.push(DeployCorrelation {
                    commit: commit.clone(),
                    container: deploy.container.clone(),
                    container_started_at: deploy.started_at,
                    lag_seconds: lag,
                });
            }
        }
    }

    // Sort by lag (closest correlations first).
    correlations.sort_by_key(|c| c.lag_seconds);
    correlations
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::discovery::CommandOutput;
    use async_trait::async_trait;

    struct MockRunner {
        response: String,
        exit_code: i32,
    }

    #[async_trait]
    impl CommandRunner for MockRunner {
        async fn run(&self, _command: &str) -> Result<CommandOutput> {
            Ok(CommandOutput {
                stdout: self.response.clone(),
                stderr: String::new(),
                exit_code: self.exit_code,
            })
        }
    }

    #[test]
    fn parse_git_log_lines() {
        let output = "\
abc123def456789012345678901234567890abcd 2024-03-17T12:00:00+00:00 fix: database connection pool\n\
def456abc789012345678901234567890abcdef 2024-03-17T11:30:00+00:00 feat: add health endpoint\n";

        let commits = parse_git_log_output(output, "/opt/app").unwrap();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].hash, "abc123def456");
        assert_eq!(commits[0].message, "fix: database connection pool");
        assert_eq!(commits[0].repo_path, "/opt/app");
        assert_eq!(commits[1].hash, "def456abc789");
    }

    #[test]
    fn parse_git_date_rfc3339() {
        let dt = parse_git_date("2024-03-17T12:00:00+00:00").unwrap();
        assert_eq!(dt.timestamp(), 1710676800);
    }

    #[test]
    fn parse_git_date_naive() {
        let dt = parse_git_date("2024-03-17T12:00:00").unwrap();
        assert_eq!(dt.timestamp(), 1710676800);
    }

    #[test]
    fn correlate_finds_matches() {
        let commits = vec![RecentCommit {
            hash: "abc123".into(),
            message: "fix: something".into(),
            date: DateTime::parse_from_rfc3339("2024-03-17T11:50:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            repo_path: "/opt/app".into(),
        }];

        let deploys = vec![ContainerStartTime {
            container: "my-app".into(),
            started_at: DateTime::parse_from_rfc3339("2024-03-17T12:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
        }];

        let correlations = correlate_commits(&commits, &deploys);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].container, "my-app");
        assert_eq!(correlations[0].lag_seconds, 600); // 10 minutes
    }

    #[test]
    fn correlate_ignores_commits_after_deploy() {
        let commits = vec![RecentCommit {
            hash: "abc123".into(),
            message: "fix: something".into(),
            date: DateTime::parse_from_rfc3339("2024-03-17T12:10:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            repo_path: "/opt/app".into(),
        }];

        let deploys = vec![ContainerStartTime {
            container: "my-app".into(),
            started_at: DateTime::parse_from_rfc3339("2024-03-17T12:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
        }];

        let correlations = correlate_commits(&commits, &deploys);
        assert!(correlations.is_empty());
    }

    #[test]
    fn correlate_ignores_old_commits() {
        let commits = vec![RecentCommit {
            hash: "abc123".into(),
            message: "fix: something".into(),
            date: DateTime::parse_from_rfc3339("2024-03-17T10:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            repo_path: "/opt/app".into(),
        }];

        let deploys = vec![ContainerStartTime {
            container: "my-app".into(),
            started_at: DateTime::parse_from_rfc3339("2024-03-17T12:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
        }];

        // 2 hours = 7200s > 1800s window
        let correlations = correlate_commits(&commits, &deploys);
        assert!(correlations.is_empty());
    }

    #[tokio::test]
    async fn fetch_recent_commits_success() {
        let runner = MockRunner {
            response:
                "abc123def456789012345678901234567890abcd 2024-03-17T12:00:00+00:00 fix: db pool\n"
                    .into(),
            exit_code: 0,
        };

        let commits = fetch_recent_commits(&runner, "/opt/app", 24).await.unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].message, "fix: db pool");
    }

    #[tokio::test]
    async fn fetch_recent_commits_nonzero_exit() {
        let runner = MockRunner {
            response: String::new(),
            exit_code: 128,
        };

        let result = fetch_recent_commits(&runner, "/opt/app", 24).await;
        assert!(result.is_err());
    }

    #[test]
    fn format_markdown_empty() {
        let snap = GitDeploySnapshot::default();
        assert!(format_as_markdown(&snap, 24).is_empty());
    }

    #[test]
    fn format_markdown_with_data() {
        let snap = GitDeploySnapshot {
            recent_commits: vec![RecentCommit {
                hash: "abc123".into(),
                message: "fix: db pool".into(),
                date: DateTime::parse_from_rfc3339("2024-03-17T12:00:00+00:00")
                    .unwrap()
                    .with_timezone(&Utc),
                repo_path: "/opt/app".into(),
            }],
            correlations: vec![],
        };
        let md = format_as_markdown(&snap, 24);
        assert!(md.contains("## Deployment Activity"));
        assert!(md.contains("abc123"));
    }
}
