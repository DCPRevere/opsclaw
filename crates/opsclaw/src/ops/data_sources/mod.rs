//! Pull-based data sources for OpsClaw.
//!
//! Each source queries an external API (Seq, Jaeger, GitHub, Docker) and
//! returns structured data. Sources are optional — if not configured on a
//! target they are silently skipped.

pub mod docker_inspect;
pub mod github;
pub mod jaeger;
pub mod seq;

use chrono::{DateTime, Utc};
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
    pub docker_deploys: Vec<docker_inspect::ContainerStartTime>,
}

// ---------------------------------------------------------------------------
// Per-target data-source configuration (lives inside TargetConfig)
// ---------------------------------------------------------------------------

/// Optional data-source configuration block for a target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataSourcesConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<SeqConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jaeger: Option<JaegerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<GithubConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_containers: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeqConfig {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaegerConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubConfig {
    pub repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
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
            Err(e) => tracing::warn!("github source failed: {e:#}"),
        }
    }

    if let (Some(containers), Some(runner)) = (&cfg.docker_containers, runner) {
        match docker_inspect::fetch_start_times(runner, containers).await {
            Ok(times) => snap.docker_deploys = times,
            Err(e) => tracing::warn!("docker inspect source failed: {e:#}"),
        }
    }

    snap
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
        println!("\n── Jaeger problem traces ({}) ──", snap.jaeger_traces.len());
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

    if snap.seq_logs.is_empty()
        && snap.jaeger_traces.is_empty()
        && snap.github_release.is_none()
        && snap.docker_deploys.is_empty()
    {
        println!("  (no data sources configured or returned data)");
    }
}
