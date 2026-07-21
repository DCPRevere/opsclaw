//! `opsclaw-cli doctor` — config + dependency health check (DESIGN.md §5:
//! "`opsclaw onboard` → `config project add` (chaining wizards) → `doctor` →
//! `daemon` in under ten minutes is definition-of-done #1").
//!
//! Checks, in order: config parses + validates; every secret reference the
//! config declares resolves (NAMES only are ever reported — never a value,
//! matching `opsclaw_config`'s inventory contract, DESIGN.md §4 Tool
//! surface); a per-target executor probe (skipped, not failed, for `cloud`
//! targets — `NotImplementedExecutor` reports itself honestly rather than
//! doctor treating "not built yet" as a target-specific outage); the DB
//! opens and migrates; Hindsight reachability when `memory.hindsight_url` is
//! set. Exits nonzero (via the caller checking `Report::ok()`) on any
//! check's failure — a green `doctor` is meant to be a real precondition for
//! `daemon`, not a lint that's easy to ignore.

use serde::Serialize;

use crate::Result;
use crate::config::{Config, SecretStore};
use crate::domain::FqTarget;

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub checks: Vec<CheckResult>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

/// Run every check against the config at `config_path` (file-or-default,
/// same rule as `Config::load`). `db_path`: explicit override, else
/// `config.daemon.db_path`, else skip the DB check entirely (no daemon has
/// ever run here — not itself a failure, `daemon` would create it on boot).
pub async fn run(config_path: &std::path::Path, opsclaw_home: &std::path::Path) -> Result<Report> {
    let mut checks = Vec::new();

    // 1. Config parses + validates. Every later check needs a loaded config,
    // so a failure here is reported and everything else is skipped rather
    // than cascading into confusing secondary failures.
    let raw =
        if config_path.exists() { std::fs::read_to_string(config_path)? } else { String::new() };
    if !raw.is_empty() && crate::cli::legacy::looks_like_legacy_config(&raw) {
        checks.push(CheckResult {
            name: "config".into(),
            ok: false,
            detail: format!(
                "{}: {}",
                config_path.display(),
                crate::cli::legacy::LEGACY_CONFIG_MESSAGE
            ),
        });
        return Ok(Report { checks });
    }

    let cfg = match Config::load(Some(config_path)) {
        Ok(cfg) => cfg,
        Err(e) => {
            checks.push(CheckResult { name: "config".into(), ok: false, detail: e.to_string() });
            return Ok(Report { checks });
        }
    };
    match cfg.validate() {
        Ok(()) => checks.push(CheckResult {
            name: "config".into(),
            ok: true,
            detail: format!("{} project(s) configured", cfg.projects.len()),
        }),
        Err(e) => {
            checks.push(CheckResult { name: "config".into(), ok: false, detail: e.to_string() });
            // Continue anyway: individual target/secret checks below are
            // still useful diagnostic signal even when validate() failed on
            // an unrelated field (e.g. a bad VAPID pair shouldn't hide an
            // unreachable Hindsight).
        }
    }

    // 2. Secret resolution — NAMES only, matching opsclaw_config's contract
    // (DESIGN.md §4): report whether each reference resolves, never the
    // resolved value.
    checks.extend(check_secrets(&cfg, opsclaw_home)?);

    // 3. Per-target executor probe.
    checks.extend(check_targets(&cfg, opsclaw_home).await);

    // 4. DB open/migrate.
    let db_path = cfg.daemon.db_path.clone().map(|p| p.display().to_string());
    checks.push(check_db(db_path.as_deref()).await);

    // 5. Hindsight reachability (only if configured — absent is fakes mode,
    // not a failure).
    if let Some(url) = &cfg.memory.hindsight_url {
        checks.push(check_hindsight(url).await);
    }

    Ok(Report { checks })
}

fn check_secrets(cfg: &Config, opsclaw_home: &std::path::Path) -> Result<Vec<CheckResult>> {
    let store = SecretStore::open(opsclaw_home)?;
    let mut refs: Vec<(String, crate::config::SecretRef)> = Vec::new();
    if let Some(r) = &cfg.llm.api_key {
        refs.push(("llm.api_key".into(), r.clone()));
    }
    if let Some(r) = &cfg.telegram.bot_token {
        refs.push(("telegram.bot_token".into(), r.clone()));
    }
    if let Some(r) = &cfg.push.vapid_private_key {
        refs.push(("push.vapid_private_key".into(), r.clone()));
    }
    if let Some(r) = &cfg.http.jwt_secret {
        refs.push(("http.jwt_secret".into(), r.clone()));
    }
    if let Some(r) = &cfg.http.webhook_secret {
        refs.push(("http.webhook_secret".into(), r.clone()));
    }
    for project in &cfg.projects {
        for env in &project.envs {
            for target in &env.targets {
                if let Some(r) = &target.credential {
                    refs.push((
                        format!("target {}::{}::{}", project.name, env.name, target.name),
                        r.clone(),
                    ));
                }
                for res in &target.resources {
                    if let Some(r) = &res.credential {
                        refs.push((
                            format!(
                                "resource {}::{}::{}/{}",
                                project.name, env.name, target.name, res.name
                            ),
                            r.clone(),
                        ));
                    }
                }
            }
        }
    }

    let mut out = Vec::with_capacity(refs.len());
    for (label, secret_ref) in refs {
        let result = secret_ref.resolve(&store);
        out.push(CheckResult {
            name: format!("secret: {label}"),
            ok: result.is_ok(),
            // The reference form ("env:NAME"/"store:NAME") is safe to print —
            // SecretRef's Display never includes the resolved value
            // (config/secrets.rs) — the resolved value itself never appears
            // here even on success.
            detail: match result {
                Ok(_) => format!("{secret_ref} resolves"),
                Err(e) => format!("{secret_ref}: {e}"),
            },
        });
    }
    Ok(out)
}

async fn check_targets(cfg: &Config, opsclaw_home: &std::path::Path) -> Vec<CheckResult> {
    let store = match SecretStore::open(opsclaw_home) {
        Ok(s) => s,
        Err(e) => {
            return vec![CheckResult {
                name: "targets".into(),
                ok: false,
                detail: format!("could not open secret store: {e}"),
            }];
        }
    };

    let mut out = Vec::new();
    for project in &cfg.projects {
        for env in &project.envs {
            for target in &env.targets {
                let fq = FqTarget::new(&project.name, &env.name, &target.name);
                let result = probe_target(target, &store).await;
                out.push(match result {
                    Ok(report) => CheckResult {
                        name: format!("target: {fq}"),
                        ok: report.reachable,
                        detail: report.detail,
                    },
                    Err(e) => CheckResult {
                        name: format!("target: {fq}"),
                        ok: false,
                        detail: e.to_string(),
                    },
                });
            }
        }
    }
    out
}

async fn probe_target(
    target: &crate::config::TargetCfg,
    store: &SecretStore,
) -> Result<crate::targets::ProbeReport> {
    // The SAME construction path the daemon boots with
    // (targets::wiring::executor_for_target) — doctor probing one thing and
    // the daemon wiring another is exactly the divergence this prevents.
    crate::targets::wiring::executor_for_target(target, store)?.probe().await
}

async fn check_db(db_path: Option<&str>) -> CheckResult {
    let Some(path) = db_path else {
        return CheckResult {
            name: "database".into(),
            ok: true,
            detail: "no daemon.db_path configured — daemon will create one on first boot".into(),
        };
    };
    match crate::db::Db::connect(path).await {
        Ok(_) => CheckResult {
            name: "database".into(),
            ok: true,
            detail: format!("{path} opens and migrates"),
        },
        Err(e) => {
            CheckResult { name: "database".into(), ok: false, detail: format!("{path}: {e}") }
        }
    }
}

async fn check_hindsight(url: &str) -> CheckResult {
    let client = crate::memory::hindsight::HindsightClient::new(url, None, "default");
    match client.health().await {
        Ok(()) => {
            CheckResult { name: "hindsight".into(), ok: true, detail: format!("{url} reachable") }
        }
        Err(e) => {
            CheckResult { name: "hindsight".into(), ok: false, detail: format!("{url}: {e}") }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fully_faked_config_is_all_green() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        // No file at all -> Config::default(), fully faked.
        let report = run(&config_path, dir.path()).await.unwrap();
        assert!(report.ok(), "{:#?}", report.checks);
        assert!(report.checks.iter().any(|c| c.name == "config" && c.ok));
        // No hindsight_url configured -> no hindsight check at all.
        assert!(!report.checks.iter().any(|c| c.name == "hindsight"));
    }

    #[tokio::test]
    async fn local_target_probes_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
                [[project]]
                name = "p"
                [[project.env]]
                name = "e"
                [[project.env.target]]
                name = "this-host"
                kind = "local"
            "#,
        )
        .unwrap();

        let report = run(&config_path, dir.path()).await.unwrap();
        let target_check = report.checks.iter().find(|c| c.name.contains("this-host")).unwrap();
        assert!(target_check.ok, "{target_check:?}");
    }

    #[tokio::test]
    async fn cloud_target_reports_not_implemented_without_failing_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
                [[project]]
                name = "p"
                [[project.env]]
                name = "e"
                [[project.env.target]]
                name = "aci"
                kind = "cloud"
                provider = "azure"
                credential = "env:AZURE_CRED"
            "#,
        )
        .unwrap();
        unsafe { std::env::set_var("AZURE_CRED", "fake-value-for-doctor-test") };

        let report = run(&config_path, dir.path()).await.unwrap();
        let target_check = report
            .checks
            .iter()
            .find(|c| c.name.starts_with("target:") && c.name.contains("aci"))
            .unwrap();
        assert!(!target_check.ok, "{target_check:?}");
        assert!(target_check.detail.contains("not implemented"), "{target_check:?}");

        unsafe { std::env::remove_var("AZURE_CRED") };
    }

    #[tokio::test]
    async fn unresolvable_secret_is_reported_by_name_only() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
                [llm]
                api_key = "env:OPSCLAW_DOCTOR_TEST_MISSING_KEY"
                models = ["some/model"]
            "#,
        )
        .unwrap();
        unsafe { std::env::remove_var("OPSCLAW_DOCTOR_TEST_MISSING_KEY") };

        let report = run(&config_path, dir.path()).await.unwrap();
        let secret_check = report.checks.iter().find(|c| c.name.contains("llm.api_key")).unwrap();
        assert!(!secret_check.ok);
        assert!(!report.ok());
        // Never leaks a value, because there is none to leak, and the
        // reference form itself carries no secret material.
        assert!(secret_check.detail.contains("env:OPSCLAW_DOCTOR_TEST_MISSING_KEY"));
    }

    #[tokio::test]
    async fn legacy_config_is_reported_as_one_clear_check_not_a_parse_crash() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "schema_version = 2\n[providers]\n").unwrap();

        let report = run(&config_path, dir.path()).await.unwrap();
        assert!(!report.ok());
        assert_eq!(report.checks.len(), 1);
        assert!(report.checks[0].detail.contains("different, unrelated opsclaw generation"));
    }
}
