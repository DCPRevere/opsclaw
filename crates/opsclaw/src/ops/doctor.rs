//! OpsClaw-specific self-diagnostic checks.
//!
//! Produces a [`DoctorReport`] with per-check results covering config validity,
//! SSH target reachability, notification credentials, LLM provider readiness,
//! disk space, and data-directory integrity.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use zeroclaw::config::schema::{Config, TargetType};

use super::data_sources::DataSourcesConfig;

// ── Result types ────────────────────────────────────────────────

/// Severity of a single diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Warn,
    Error,
}

/// A single diagnostic check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub severity: Severity,
    pub category: String,
    pub message: String,
}

/// The full doctor report, JSON-serializable for the web UI API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub results: Vec<CheckResult>,
    pub summary: ReportSummary,
}

/// Aggregate counts from a doctor run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub ok: usize,
    pub warnings: usize,
    pub errors: usize,
}

impl CheckResult {
    fn ok(category: &str, msg: impl Into<String>) -> Self {
        Self {
            severity: Severity::Ok,
            category: category.into(),
            message: msg.into(),
        }
    }
    fn warn(category: &str, msg: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warn,
            category: category.into(),
            message: msg.into(),
        }
    }
    fn error(category: &str, msg: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            category: category.into(),
            message: msg.into(),
        }
    }

    fn icon(&self) -> &'static str {
        match self.severity {
            Severity::Ok => "✅",
            Severity::Warn => "⚠️ ",
            Severity::Error => "❌",
        }
    }
}

// ── Public entry points ─────────────────────────────────────────

/// Run all OpsClaw diagnostics and return a structured report.
pub async fn diagnose(config: &Config) -> DoctorReport {
    let mut results = Vec::new();

    check_config(config, &mut results);
    check_targets(config, &mut results);
    check_ssh_connectivity(config, &mut results).await;
    check_notifications(config, &mut results);
    check_llm_provider(config, &mut results);
    check_disk_space(config, &mut results);
    check_data_directories(config, &mut results);
    check_data_sources(config, &mut results).await;

    let ok = results
        .iter()
        .filter(|r| r.severity == Severity::Ok)
        .count();
    let warnings = results
        .iter()
        .filter(|r| r.severity == Severity::Warn)
        .count();
    let errors = results
        .iter()
        .filter(|r| r.severity == Severity::Error)
        .count();

    DoctorReport {
        results,
        summary: ReportSummary {
            ok,
            warnings,
            errors,
        },
    }
}

/// Run diagnostics and print a human-readable report to stdout.
pub async fn run(config: &Config) -> Result<()> {
    let report = diagnose(config).await;

    println!("🩺 OpsClaw Doctor — self-diagnostic");
    println!();

    let mut current_cat = String::new();
    for item in &report.results {
        if item.category != current_cat {
            current_cat.clone_from(&item.category);
            println!("  [{}]", current_cat);
        }
        println!("    {} {}", item.icon(), item.message);
    }

    println!();
    println!(
        "  Summary: {} ok, {} warnings, {} errors",
        report.summary.ok, report.summary.warnings, report.summary.errors
    );

    if report.summary.errors > 0 {
        println!("  💡 Fix the errors above, then run `opsclaw doctor` again.");
    }

    Ok(())
}

// ── Config validity ─────────────────────────────────────────────

fn check_config(config: &Config, results: &mut Vec<CheckResult>) {
    let cat = "config";

    if config.config_path.exists() {
        results.push(CheckResult::ok(
            cat,
            format!("config file: {}", config.config_path.display()),
        ));
    } else {
        results.push(CheckResult::error(
            cat,
            format!("config file not found: {}", config.config_path.display()),
        ));
    }

    if config.default_provider.is_some() {
        results.push(CheckResult::ok(
            cat,
            format!(
                "default provider: {}",
                config.default_provider.as_deref().unwrap_or("?")
            ),
        ));
    } else {
        results.push(CheckResult::error(cat, "no default_provider configured"));
    }

    if config.default_model.is_some() {
        results.push(CheckResult::ok(
            cat,
            format!(
                "default model: {}",
                config.default_model.as_deref().unwrap_or("?")
            ),
        ));
    } else {
        results.push(CheckResult::warn(cat, "no default_model configured"));
    }

    if config.api_key.is_some() {
        results.push(CheckResult::ok(cat, "API key configured"));
    } else if config.default_provider.as_deref() != Some("ollama") {
        results.push(CheckResult::warn(
            cat,
            "no api_key set (may rely on env vars)",
        ));
    }
}

// ── Target validation ───────────────────────────────────────────

fn check_targets(config: &Config, results: &mut Vec<CheckResult>) {
    let cat = "targets";

    let targets = match config.targets.as_ref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            results.push(CheckResult::warn(
                cat,
                "no targets configured — run `opsclaw setup` to add one",
            ));
            return;
        }
    };

    results.push(CheckResult::ok(
        cat,
        format!("{} target(s) configured", targets.len()),
    ));

    for target in targets {
        match target.target_type {
            TargetType::Ssh => {
                let mut missing = Vec::new();
                if target.host.is_none() {
                    missing.push("host");
                }
                if target.user.is_none() {
                    missing.push("user");
                }
                if target.key_secret.is_none() {
                    missing.push("key_secret");
                }
                if missing.is_empty() {
                    results.push(CheckResult::ok(
                        cat,
                        format!(
                            "target \"{}\" (ssh://{}@{}:{})",
                            target.name,
                            target.user.as_deref().unwrap_or("?"),
                            target.host.as_deref().unwrap_or("?"),
                            target.port.unwrap_or(22),
                        ),
                    ));
                } else {
                    results.push(CheckResult::error(
                        cat,
                        format!(
                            "target \"{}\" missing required SSH fields: {}",
                            target.name,
                            missing.join(", ")
                        ),
                    ));
                }
            }
            TargetType::Local => {
                results.push(CheckResult::ok(
                    cat,
                    format!("target \"{}\" (local)", target.name),
                ));
            }
            TargetType::Kubernetes => {
                results.push(CheckResult::ok(
                    cat,
                    format!(
                        "target \"{}\" (kubernetes, ns={})",
                        target.name,
                        target.namespace.as_deref().unwrap_or("default"),
                    ),
                ));
            }
        }
    }
}

// ── SSH connectivity ────────────────────────────────────────────

async fn check_ssh_connectivity(config: &Config, results: &mut Vec<CheckResult>) {
    let cat = "ssh";

    let targets = match config.targets.as_ref() {
        Some(t) => t,
        None => return,
    };

    let ssh_targets: Vec<_> = targets
        .iter()
        .filter(|t| t.target_type == TargetType::Ssh)
        .collect();

    if ssh_targets.is_empty() {
        return;
    }

    for target in &ssh_targets {
        let host = match target.host.as_deref() {
            Some(h) => h,
            None => {
                results.push(CheckResult::error(
                    cat,
                    format!(
                        "target \"{}\": no host configured, cannot test SSH",
                        target.name
                    ),
                ));
                continue;
            }
        };
        let port = target.port.unwrap_or(22);

        // TCP connectivity check — can we reach the SSH port at all?
        let addr = format!("{host}:{port}");
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(_)) => {
                results.push(CheckResult::ok(
                    cat,
                    format!(
                        "target \"{}\": TCP connect to {addr} succeeded",
                        target.name
                    ),
                ));
            }
            Ok(Err(e)) => {
                results.push(CheckResult::error(
                    cat,
                    format!(
                        "target \"{}\": TCP connect to {addr} failed: {e}",
                        target.name
                    ),
                ));
            }
            Err(_) => {
                results.push(CheckResult::error(
                    cat,
                    format!(
                        "target \"{}\": TCP connect to {addr} timed out (5s)",
                        target.name
                    ),
                ));
            }
        }
    }
}

// ── Notification channels ───────────────────────────────────────

fn check_notifications(config: &Config, results: &mut Vec<CheckResult>) {
    let cat = "notifications";

    match config.notifications.as_ref() {
        None => {
            results.push(CheckResult::warn(
                cat,
                "no notification config — alerts won't be delivered",
            ));
        }
        Some(notif) => {
            if let Some(ref token) = notif.telegram_bot_token {
                if token.is_empty() {
                    results.push(CheckResult::error(
                        cat,
                        "telegram_bot_token is set but empty",
                    ));
                } else {
                    results.push(CheckResult::ok(cat, "Telegram bot token present"));
                }
            } else {
                results.push(CheckResult::warn(cat, "no telegram_bot_token configured"));
            }

            if let Some(ref chat_id) = notif.telegram_chat_id {
                if chat_id.is_empty() {
                    results.push(CheckResult::error(cat, "telegram_chat_id is set but empty"));
                } else {
                    results.push(CheckResult::ok(cat, "Telegram chat ID present"));
                }
            } else {
                results.push(CheckResult::warn(cat, "no telegram_chat_id configured"));
            }
        }
    }
}

// ── LLM provider ────────────────────────────────────────────────

fn check_llm_provider(config: &Config, results: &mut Vec<CheckResult>) {
    let cat = "llm";

    // Diagnosis-specific config
    let diag = &config.diagnosis;
    let has_diag_key = diag.api_key.is_some()
        || std::env::var("ANTHROPIC_API_KEY").is_ok()
        || config.api_key.is_some();

    if has_diag_key {
        results.push(CheckResult::ok(
            cat,
            "diagnosis API key available (config or ANTHROPIC_API_KEY)",
        ));
    } else {
        results.push(CheckResult::warn(
            cat,
            "no diagnosis API key — set diagnosis.api_key or ANTHROPIC_API_KEY",
        ));
    }

    let diag_model = diag
        .model
        .clone()
        .or_else(|| std::env::var("OPSCLAW_DIAGNOSIS_MODEL").ok());
    if let Some(ref model) = diag_model {
        results.push(CheckResult::ok(cat, format!("diagnosis model: {model}")));
    } else if config.default_model.is_some() {
        results.push(CheckResult::ok(
            cat,
            "no explicit diagnosis model — will use default_model",
        ));
    } else {
        results.push(CheckResult::warn(cat, "no diagnosis model configured"));
    }
}

// ── Disk space ──────────────────────────────────────────────────

fn check_disk_space(config: &Config, results: &mut Vec<CheckResult>) {
    let cat = "disk";
    let ws = &config.workspace_dir;

    if !ws.exists() {
        results.push(CheckResult::error(
            cat,
            format!("workspace directory missing: {}", ws.display()),
        ));
        return;
    }

    if let Some(avail_mb) = disk_available_mb(ws) {
        if avail_mb >= 500 {
            results.push(CheckResult::ok(
                cat,
                format!("{avail_mb} MB available in workspace"),
            ));
        } else if avail_mb >= 100 {
            results.push(CheckResult::warn(
                cat,
                format!("low disk space: {avail_mb} MB available"),
            ));
        } else {
            results.push(CheckResult::error(
                cat,
                format!("critically low disk space: {avail_mb} MB available"),
            ));
        }
    } else {
        results.push(CheckResult::warn(
            cat,
            "could not determine disk space (df failed)",
        ));
    }
}

fn disk_available_mb(path: &std::path::Path) -> Option<u64> {
    let output = std::process::Command::new("df")
        .arg("-m")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // df output: header line then data line; Available is column 4.
    let line = stdout.lines().rev().find(|l| !l.trim().is_empty())?;
    line.split_whitespace().nth(3)?.parse::<u64>().ok()
}

// ── Data directories ────────────────────────────────────────────

fn check_data_directories(config: &Config, results: &mut Vec<CheckResult>) {
    let cat = "directories";

    let home = match directories::UserDirs::new() {
        Some(u) => u.home_dir().to_path_buf(),
        None => {
            results.push(CheckResult::error(cat, "cannot determine home directory"));
            return;
        }
    };

    let opsclaw_dir = home.join(".opsclaw");
    if !opsclaw_dir.exists() {
        results.push(CheckResult::error(
            cat,
            format!("{} does not exist", opsclaw_dir.display()),
        ));
        return;
    }

    results.push(CheckResult::ok(
        cat,
        format!("{} exists", opsclaw_dir.display()),
    ));

    let subdirs = ["snapshots", "incidents", "baselines"];
    for name in &subdirs {
        let path = opsclaw_dir.join(name);
        if path.is_dir() {
            results.push(CheckResult::ok(cat, format!("{name}/ exists")));
        } else {
            results.push(CheckResult::warn(
                cat,
                format!("{name}/ missing — will be created on first use"),
            ));
        }
    }

    // Config file
    let config_path = &config.config_path;
    if config_path.exists() {
        results.push(CheckResult::ok(
            cat,
            format!("config.toml: {}", config_path.display()),
        ));
    }

    // Secrets file
    let secrets_path = opsclaw_dir.join("secrets.enc");
    if secrets_path.exists() {
        results.push(CheckResult::ok(cat, "secrets.enc present"));
    } else {
        results.push(CheckResult::warn(
            cat,
            "secrets.enc not found — run `opsclaw secret` to set up secrets",
        ));
    }
}

// ── Data source connectivity ─────────────────────────────────

async fn check_data_sources(config: &Config, results: &mut Vec<CheckResult>) {
    let cat = "data_sources";

    let targets = match config.targets.as_ref() {
        Some(t) => t,
        None => return,
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            results.push(CheckResult::error(
                cat,
                format!("could not create HTTP client: {e}"),
            ));
            return;
        }
    };

    for target in targets {
        let ds_config: DataSourcesConfig = target
            .data_sources
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        if let Some(ref seq) = ds_config.seq {
            let mut url = format!("{}/api/events?count=1", seq.url.trim_end_matches('/'));
            if let Some(ref key) = seq.api_key {
                if !key.is_empty() {
                    let _ = std::fmt::Write::write_fmt(
                        &mut url,
                        format_args!("&apiKey={key}"),
                    );
                }
            }
            check_http_endpoint(&client, cat, "Seq", &seq.url, &url, &target.name, results)
                .await;
        }

        if let Some(ref jaeger) = ds_config.jaeger {
            let url = format!("{}/api/services", jaeger.url.trim_end_matches('/'));
            check_http_endpoint(
                &client,
                cat,
                "Jaeger",
                &jaeger.url,
                &url,
                &target.name,
                results,
            )
            .await;
        }

        if let Some(ref prom) = ds_config.prometheus {
            let url = format!(
                "{}/api/v1/query?query=up",
                prom.url.trim_end_matches('/')
            );
            check_http_endpoint(
                &client,
                cat,
                "Prometheus",
                &prom.url,
                &url,
                &target.name,
                results,
            )
            .await;
        }

        if let Some(ref es) = ds_config.elasticsearch {
            let url = format!("{}/_cluster/health", es.url.trim_end_matches('/'));
            check_http_endpoint(
                &client,
                cat,
                "Elasticsearch",
                &es.url,
                &url,
                &target.name,
                results,
            )
            .await;
        }
    }
}

async fn check_http_endpoint(
    client: &reqwest::Client,
    cat: &str,
    source_name: &str,
    base_url: &str,
    check_url: &str,
    target_name: &str,
    results: &mut Vec<CheckResult>,
) {
    match client.get(check_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            results.push(CheckResult::ok(
                cat,
                format!(
                    "{source_name} at {base_url} is reachable (target \"{}\")",
                    target_name
                ),
            ));
        }
        Ok(resp) => {
            results.push(CheckResult::warn(
                cat,
                format!(
                    "{source_name} at {base_url} returned {} (target \"{}\")",
                    resp.status(),
                    target_name
                ),
            ));
        }
        Err(e) => {
            let reason = if e.is_timeout() {
                "timed out (5s)".to_string()
            } else if e.is_connect() {
                "connection refused".to_string()
            } else {
                format!("{e}")
            };
            results.push(CheckResult::error(
                cat,
                format!(
                    "{source_name} at {base_url} — {reason} (target \"{}\")",
                    target_name
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_icons() {
        assert_eq!(CheckResult::ok("t", "m").icon(), "✅");
        assert_eq!(CheckResult::warn("t", "m").icon(), "⚠️ ");
        assert_eq!(CheckResult::error("t", "m").icon(), "❌");
    }

    #[test]
    fn severity_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Severity::Ok).unwrap(), r#""ok""#);
        assert_eq!(serde_json::to_string(&Severity::Warn).unwrap(), r#""warn""#);
        assert_eq!(
            serde_json::to_string(&Severity::Error).unwrap(),
            r#""error""#
        );
    }

    #[test]
    fn doctor_report_serializes_for_api() {
        let report = DoctorReport {
            results: vec![
                CheckResult::ok("config", "looks good"),
                CheckResult::error("ssh", "unreachable"),
            ],
            summary: ReportSummary {
                ok: 1,
                warnings: 0,
                errors: 1,
            },
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["summary"]["ok"], 1);
        assert_eq!(json["summary"]["errors"], 1);
        assert_eq!(json["results"].as_array().unwrap().len(), 2);
        assert_eq!(json["results"][0]["severity"], "ok");
        assert_eq!(json["results"][1]["severity"], "error");
    }

    #[test]
    fn check_config_reports_missing_provider() {
        let config = Config {
            default_provider: None,
            ..Config::default()
        };
        let mut results = Vec::new();
        check_config(&config, &mut results);
        let provider_item = results
            .iter()
            .find(|r| r.message.contains("default_provider"));
        assert!(provider_item.is_some());
        assert_eq!(provider_item.unwrap().severity, Severity::Error);
    }

    #[test]
    fn check_targets_warns_when_none() {
        let config = Config::default();
        let mut results = Vec::new();
        check_targets(&config, &mut results);
        let item = results.iter().find(|r| r.message.contains("no targets"));
        assert!(item.is_some());
        assert_eq!(item.unwrap().severity, Severity::Warn);
    }

    #[test]
    fn check_notifications_warns_when_missing() {
        let config = Config::default();
        let mut results = Vec::new();
        check_notifications(&config, &mut results);
        let item = results
            .iter()
            .find(|r| r.message.contains("no notification config"));
        assert!(item.is_some());
        assert_eq!(item.unwrap().severity, Severity::Warn);
    }

    #[tokio::test]
    async fn check_data_sources_skips_when_no_targets() {
        let config = Config::default();
        let mut results = Vec::new();
        check_data_sources(&config, &mut results).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn check_data_sources_reports_unreachable() {
        use zeroclaw::config::schema::{OpsClawAutonomy, TargetConfig};

        let ds_json = serde_json::json!({
            "seq": { "url": "http://127.0.0.1:19876" },
            "jaeger": { "url": "http://127.0.0.1:19877" },
        });

        let config = Config {
            targets: Some(vec![TargetConfig {
                name: "test-target".into(),
                target_type: TargetType::Local,
                host: None,
                port: None,
                user: None,
                key_secret: None,
                autonomy: OpsClawAutonomy::default(),
                context_file: None,
                probes: None,
                data_sources: Some(ds_json),
                escalation: None,
                databases: None,
                kubeconfig: None,
                namespace: None,
            }]),
            ..Config::default()
        };

        let mut results = Vec::new();
        check_data_sources(&config, &mut results).await;

        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.category, "data_sources");
            assert_eq!(r.severity, Severity::Error);
        }
        assert!(results[0].message.contains("Seq"));
        assert!(results[1].message.contains("Jaeger"));
    }
}
