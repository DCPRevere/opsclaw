//! Pull-based data sources for OpsClaw.
//!
//! Each source queries an external API (Seq, Jaeger, GitHub, Docker) and
//! returns structured data. Sources are optional — if not configured on a
//! target they are silently skipped.

pub mod docker_inspect;
pub mod git_deploy;
pub mod github;
pub mod jaeger;
pub mod prometheus;
pub mod seq;

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
    pub prometheus: Option<prometheus::PrometheusSnapshot>,
    pub git_deploy: Option<git_deploy::GitDeploySnapshot>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prometheus: Option<PrometheusConfig>,
    /// Paths to git repositories on the target for deployment correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_paths: Option<Vec<String>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusConfig {
    pub url: String,
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

    if let Some(prom_cfg) = &cfg.prometheus {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::minutes(15);
        match prometheus::fetch_prometheus_snapshot(prom_cfg, start, end).await {
            Ok(psnap) => snap.prometheus = Some(psnap),
            Err(e) => tracing::warn!("prometheus source failed: {e:#}"),
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

    if snap.seq_logs.is_empty()
        && snap.jaeger_traces.is_empty()
        && snap.github_release.is_none()
        && snap.docker_deploys.is_empty()
        && snap.prometheus.is_none()
        && snap.git_deploy.is_none()
    {
        println!("  (no data sources configured or returned data)");
    }
}
