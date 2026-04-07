//! Pull-based data sources for OpsClaw.
//!
//! Each source queries an external API (Seq, Jaeger, GitHub, Docker) and
//! returns structured data. Sources are optional — if not configured on a
//! target they are silently skipped.

pub mod docker_inspect;
pub mod elasticsearch;
pub mod git_deploy;
pub mod github;
pub mod jaeger;
pub mod prometheus;
pub mod seq;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ops::log_sources::LogEntry;

// ---------------------------------------------------------------------------
// Shared snapshot type
// ---------------------------------------------------------------------------

/// Aggregated result from all configured data sources for a single target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataSourcesSnapshot {
    pub seq_logs: Vec<LogEntry>,
    pub jaeger_traces: Vec<jaeger::TraceSummary>,
    pub github_release: Option<github::ReleaseInfo>,
    pub github_runs: Vec<github::WorkflowRun>,
    pub github_tags: Vec<github::RepoTag>,
    pub docker_deploys: Vec<docker_inspect::ContainerStartTime>,
    pub prometheus: Option<prometheus::PrometheusSnapshot>,
    pub git_deploy: Option<git_deploy::GitDeploySnapshot>,
    pub elasticsearch_logs: Vec<LogEntry>,
}

// ---------------------------------------------------------------------------
// Per-project data-source configuration (lives inside ProjectConfig)
// ---------------------------------------------------------------------------

/// Optional data-source configuration block for a project.
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

// ---------------------------------------------------------------------------
// Collect all sources for a target
// ---------------------------------------------------------------------------

/// Query every configured data source for `target_name` and return a snapshot.
pub async fn collect_all(
    cfg: &DataSourcesConfig,
    runner: Option<&dyn crate::tools::discovery::CommandRunner>,
) -> DataSourcesSnapshot {
    let mut snap = DataSourcesSnapshot::default();

    if let Some(seq_cfg) = &cfg.seq {
        match seq::fetch_error_logs(seq_cfg).await {
            Ok(logs) => snap.seq_logs = logs,
            Err(e) => tracing::warn!("seq source failed: {e:#}"),
        }
    }

    if let Some(jaeger_cfg) = &cfg.jaeger {
        match jaeger::fetch_problem_traces(jaeger_cfg).await {
            Ok(traces) => snap.jaeger_traces = traces,
            Err(e) => tracing::warn!("jaeger source failed: {e:#}"),
        }
    }

    if let Some(gh_cfg) = &cfg.github {
        match github::fetch_latest_release(gh_cfg).await {
            Ok(release) => snap.github_release = release,
            Err(e) => tracing::warn!("github release source failed: {e:#}"),
        }
        match github::fetch_recent_runs(gh_cfg).await {
            Ok(runs) => snap.github_runs = runs,
            Err(e) => tracing::warn!("github actions source failed: {e:#}"),
        }
        match github::fetch_recent_tags(gh_cfg).await {
            Ok(tags) => snap.github_tags = tags,
            Err(e) => tracing::warn!("github tags source failed: {e:#}"),
        }
    }

    if let Some(prom_cfg) = &cfg.prometheus {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::minutes(15);
        match prometheus::fetch_prometheus_snapshot(prom_cfg, start, end).await {
            Ok(psnap) => snap.prometheus = Some(psnap),
            Err(e) => tracing::warn!("prometheus source failed: {e:#}"),
        }
    }

    if let Some(es_cfg) = &cfg.elasticsearch {
        match elasticsearch::fetch_error_logs(es_cfg).await {
            Ok(logs) => snap.elasticsearch_logs = logs,
            Err(e) => tracing::warn!("elasticsearch source failed: {e:#}"),
        }
    }

    if let (Some(containers), Some(runner)) = (&cfg.docker_containers, runner) {
        match docker_inspect::fetch_start_times(runner, containers).await {
            Ok(times) => snap.docker_deploys = times,
            Err(e) => tracing::warn!("docker inspect source failed: {e:#}"),
        }
    }

    if let (Some(paths), Some(runner)) = (&cfg.git_paths, runner) {
        match git_deploy::fetch_git_deploy_snapshot(runner, paths, &snap.docker_deploys, None).await
        {
            Ok(gs) => snap.git_deploy = Some(gs),
            Err(e) => tracing::warn!("git deploy source failed: {e:#}"),
        }
    }

    snap
}

/// Fetch context from all configured data sources for a project, in parallel.
///
/// Deserializes the project's `data_sources` JSON value into a
/// [`DataSourcesConfig`], then delegates to [`collect_all`].  Missing or
/// malformed config is silently treated as "no data sources configured".
pub async fn fetch_all(
    project: &crate::ops_config::ProjectConfig,
    runner: Option<&dyn crate::tools::discovery::CommandRunner>,
) -> DataSourcesSnapshot {
    let ds_config = project.data_sources.clone().unwrap_or_default();
    collect_all(&ds_config, runner).await
}

/// Format the snapshot as a text block suitable for inclusion in an LLM
/// diagnosis prompt.  Returns an empty string when the snapshot is empty.
pub fn format_for_diagnosis(snap: &DataSourcesSnapshot) -> String {
    use std::fmt::Write;

    let mut sections: Vec<String> = Vec::new();

    if !snap.seq_logs.is_empty() {
        let mut s = format!("=== Seq Error Logs ({}) ===", snap.seq_logs.len());
        for entry in &snap.seq_logs {
            let ts = entry
                .timestamp
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "----".into());
            let lvl = entry
                .level
                .as_ref()
                .map(|l| format!("[{l}]"))
                .unwrap_or_default();
            let _ = write!(s, "\n  {ts} {lvl} {}", entry.message);
        }
        sections.push(s);
    }

    if !snap.jaeger_traces.is_empty() {
        let mut s = format!("=== Jaeger Traces ({}) ===", snap.jaeger_traces.len());
        for t in &snap.jaeger_traces {
            let flags: Vec<&str> = [
                t.has_error.then_some("error"),
                t.high_latency.then_some("slow"),
            ]
            .into_iter()
            .flatten()
            .collect();
            let _ = write!(
                s,
                "\n  {} service={} spans={} duration={}ms [{}]",
                t.trace_id,
                t.service,
                t.span_count,
                t.duration_ms,
                flags.join(", ")
            );
        }
        sections.push(s);
    }

    if let Some(rel) = &snap.github_release {
        let published = rel
            .published_at
            .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| "unknown".into());
        sections.push(format!(
            "=== GitHub ===\n  Latest release: {} ({}) published {}",
            rel.tag_name,
            rel.name.as_deref().unwrap_or("unnamed"),
            published,
        ));
    }

    if !snap.docker_deploys.is_empty() {
        let mut s = format!(
            "=== Docker Container Start Times ({}) ===",
            snap.docker_deploys.len()
        );
        for d in &snap.docker_deploys {
            let _ = write!(
                s,
                "\n  {} started {}",
                d.container,
                d.started_at.format("%Y-%m-%dT%H:%M:%SZ")
            );
        }
        sections.push(s);
    }

    if let Some(psnap) = &snap.prometheus {
        let mut parts = Vec::new();
        for s in &psnap.up_samples {
            let last_val = s
                .values
                .last()
                .map(|(_, v)| if *v >= 1.0 { "UP" } else { "DOWN" })
                .unwrap_or("?");
            parts.push(format!("  {} ({}) = {last_val}", s.metric_name, s.labels));
        }
        for a in &psnap.active_alerts {
            parts.push(format!(
                "  [{}] {} ({}) val={}",
                a.state, a.name, a.labels, a.value
            ));
        }
        if !parts.is_empty() {
            sections.push(format!("=== Prometheus ===\n{}", parts.join("\n")));
        }
    }

    if let Some(gs) = &snap.git_deploy {
        let mut parts = Vec::new();
        for c in &gs.recent_commits {
            parts.push(format!(
                "  {} {} ({})",
                c.hash,
                c.message,
                c.date.format("%Y-%m-%dT%H:%M:%SZ")
            ));
        }
        for c in &gs.correlations {
            parts.push(format!(
                "  {} {} → container {} ({}s before start)",
                c.commit.hash, c.commit.message, c.container, c.lag_seconds
            ));
        }
        if !parts.is_empty() {
            sections.push(format!(
                "=== Git Deploy Correlation ===\n{}",
                parts.join("\n")
            ));
        }
    }

    if !snap.elasticsearch_logs.is_empty() {
        let mut s = format!(
            "=== Elasticsearch Error Logs ({}) ===",
            snap.elasticsearch_logs.len()
        );
        for entry in &snap.elasticsearch_logs {
            let ts = entry
                .timestamp
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "----".into());
            let lvl = entry
                .level
                .as_ref()
                .map(|l| format!("[{l}]"))
                .unwrap_or_default();
            let _ = write!(s, "\n  {ts} {lvl} {}", entry.message);
        }
        sections.push(s);
    }

    if sections.is_empty() {
        return String::new();
    }

    format!(
        "=== External Data Sources ===\n\n{}",
        sections.join("\n\n")
    )
}

/// Print a human-readable summary of the snapshot.
pub fn print_summary(snap: &DataSourcesSnapshot) {
    if !snap.seq_logs.is_empty() {
        println!("\n── Seq error logs ({}) ──", snap.seq_logs.len());
        for entry in &snap.seq_logs {
            let ts = entry
                .timestamp
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "----".into());
            let lvl = entry
                .level
                .as_ref()
                .map(|l| format!("[{l}]"))
                .unwrap_or_default();
            println!("  {ts} {lvl} {}", entry.message);
        }
    }

    if !snap.jaeger_traces.is_empty() {
        println!(
            "\n── Jaeger problem traces ({}) ──",
            snap.jaeger_traces.len()
        );
        for t in &snap.jaeger_traces {
            let flags: Vec<&str> = [
                t.has_error.then_some("error"),
                t.high_latency.then_some("slow"),
            ]
            .into_iter()
            .flatten()
            .collect();
            println!(
                "  {} service={} spans={} duration={}ms [{}]",
                t.trace_id,
                t.service,
                t.span_count,
                t.duration_ms,
                flags.join(", ")
            );
        }
    }

    if let Some(rel) = &snap.github_release {
        println!("\n── GitHub latest release ──");
        println!(
            "  {} ({}) published {}",
            rel.tag_name,
            rel.name.as_deref().unwrap_or("unnamed"),
            rel.published_at
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "unknown".into())
        );
    }

    if !snap.github_runs.is_empty() {
        println!(
            "\n── GitHub workflow runs ({}) ──",
            snap.github_runs.len()
        );
        for run in &snap.github_runs {
            let conclusion = run
                .conclusion
                .as_deref()
                .unwrap_or("-");
            let name = run.name.as_deref().unwrap_or("unnamed");
            let ts = run
                .updated_at
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "unknown".into());
            println!(
                "  {} [{}→{}] {ts}",
                name, run.status, conclusion
            );
        }
    }

    if !snap.github_tags.is_empty() {
        println!("\n── GitHub tags ({}) ──", snap.github_tags.len());
        for tag in &snap.github_tags {
            println!("  {} ({})", tag.name, &tag.commit_sha[..7.min(tag.commit_sha.len())]);
        }
    }

    if !snap.docker_deploys.is_empty() {
        println!(
            "\n── Docker container start times ({}) ──",
            snap.docker_deploys.len()
        );
        for d in &snap.docker_deploys {
            println!(
                "  {} started {}",
                d.container,
                d.started_at.format("%Y-%m-%dT%H:%M:%SZ")
            );
        }
    }

    if let Some(psnap) = &snap.prometheus {
        if !psnap.up_samples.is_empty() {
            println!("\n── Prometheus up/down ({}) ──", psnap.up_samples.len());
            for s in &psnap.up_samples {
                let last_val = s
                    .values
                    .last()
                    .map(|(_, v)| if *v >= 1.0 { "UP" } else { "DOWN" })
                    .unwrap_or("?");
                println!("  {} ({}) = {last_val}", s.metric_name, s.labels);
            }
        }
        if !psnap.active_alerts.is_empty() {
            println!(
                "\n── Prometheus active alerts ({}) ──",
                psnap.active_alerts.len()
            );
            for a in &psnap.active_alerts {
                println!("  [{}] {} ({}) val={}", a.state, a.name, a.labels, a.value);
            }
        }
    }

    if let Some(gs) = &snap.git_deploy {
        if !gs.recent_commits.is_empty() {
            println!("\n── Git recent commits ({}) ──", gs.recent_commits.len());
            for c in &gs.recent_commits {
                println!(
                    "  {} {} ({})",
                    c.hash,
                    c.message,
                    c.date.format("%Y-%m-%dT%H:%M:%SZ")
                );
            }
        }
        if !gs.correlations.is_empty() {
            println!("\n── Deploy correlations ({}) ──", gs.correlations.len());
            for c in &gs.correlations {
                println!(
                    "  {} {} → container {} ({}s before start)",
                    c.commit.hash, c.commit.message, c.container, c.lag_seconds
                );
            }
        }
    }

    if !snap.elasticsearch_logs.is_empty() {
        println!(
            "\n── Elasticsearch error logs ({}) ──",
            snap.elasticsearch_logs.len()
        );
        for entry in &snap.elasticsearch_logs {
            let ts = entry
                .timestamp
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "----".into());
            let lvl = entry
                .level
                .as_ref()
                .map(|l| format!("[{l}]"))
                .unwrap_or_default();
            println!("  {ts} {lvl} {}", entry.message);
        }
    }

    if snap.seq_logs.is_empty()
        && snap.jaeger_traces.is_empty()
        && snap.github_release.is_none()
        && snap.github_runs.is_empty()
        && snap.github_tags.is_empty()
        && snap.docker_deploys.is_empty()
        && snap.prometheus.is_none()
        && snap.git_deploy.is_none()
        && snap.elasticsearch_logs.is_empty()
    {
        println!("  (no data sources configured or returned data)");
    }
}
