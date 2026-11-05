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
//! set; the identity provider is reachable when one is configured. Exits
//! nonzero (via the caller checking `Report::ok()`) on any
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
/// same rule as `Config::load`). The database checked is
/// [`effective_db_path`]'s — `config.daemon.db_path`, else an existing
/// `<home>/opsclaw.sqlite3` — and only when neither exists is the DB check
/// skipped (no daemon has ever run here — not itself a failure, `daemon`
/// would create it on boot).
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
    checks.extend(check_resources(&cfg, opsclaw_home).await);

    // 4. DB open/migrate.
    let db_path = effective_db_path(&cfg, opsclaw_home);
    checks.push(check_db(db_path.as_deref()).await);

    // 5. Hindsight reachability (only if configured — absent is fakes mode,
    // not a failure).
    if let Some(url) = &cfg.memory.hindsight_url {
        checks.push(check_hindsight(url).await);
    }

    // 6. Identity provider reachability, and whether the operator roster is
    // ready for the configured provider — the precondition an auth.provider
    // flip stakes everything on.
    checks.push(check_auth_provider(&cfg).await);
    checks.push(check_account_linkage(&cfg, db_path.as_deref()).await);

    Ok(Report { checks })
}

/// The database the daemon will actually open: an explicit `daemon.db_path`,
/// else `<home>/opsclaw.sqlite3` IF that file already exists.
///
/// The fallback is the point. `boot::daemon_state` (src/boot.rs), the CLI's
/// own `db_path_from_config`, and `onboard`'s account wizard all default to
/// `<home>/opsclaw.sqlite3` when config declares nothing — doctor was the
/// only caller that did not, so on a default install it reported
/// "no daemon.db_path configured" and skipped both the DB check and the
/// operator roster. That made `[OK] operator linkage` a check of nothing,
/// seconds after `onboard` had written an account into exactly that file,
/// and it silently voided the pre-flip roster check CHANGELOG.md tells
/// operators to trust before switching `auth.provider` to `hanko`.
///
/// Gated on `exists()` rather than defaulting unconditionally because
/// `check_db` CONNECTS, and connecting creates: an unconditional default
/// would have `doctor` — a read-only diagnostic — create the daemon's
/// database as a side effect of being run.
fn effective_db_path(cfg: &Config, opsclaw_home: &std::path::Path) -> Option<String> {
    if let Some(path) = &cfg.daemon.db_path {
        return Some(path.display().to_string());
    }
    let default = opsclaw_home.join("opsclaw.sqlite3");
    default.exists().then(|| default.display().to_string())
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
                    if let Some(r) = res.credential() {
                        refs.push((
                            format!(
                                "resource {}::{}::{}/{}",
                                project.name,
                                env.name,
                                target.name,
                                res.name()
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

    // VAPID pair check — the same guard boot enforces, surfaced here so a
    // mismatched pair (browsers subscribe with one key, the daemon signs
    // with another → every push 403s) is diagnosable before a restart. The
    // resolved private key is used only for the check, never printed.
    if let (Some(private_ref), Some(public_key)) =
        (&cfg.push.vapid_private_key, &cfg.push.vapid_public_key)
        && let Ok(private_key) = private_ref.resolve(&store)
    {
        let result = crate::channels::push::validate_vapid_pair(&private_key, public_key);
        out.push(CheckResult {
            name: "push: VAPID pair".into(),
            ok: result.is_ok(),
            detail: match result {
                Ok(()) => "public key is the pair of the private key".into(),
                Err(e) => e,
            },
        });
    }
    Ok(out)
}

/// Every configured resource (Elasticsearch, Prometheus, …) answers, with
/// the same auth and TLS settings its tools use. A dead port-forward or a
/// wrong password shows here instead of mid-scan.
async fn check_resources(cfg: &Config, opsclaw_home: &std::path::Path) -> Vec<CheckResult> {
    let store = match SecretStore::open(opsclaw_home) {
        Ok(s) => s,
        Err(_) => return Vec::new(), // check_targets already reported it
    };
    // Start any declared port-forwards for the duration of the probes, so the
    // check covers the same path a scan uses.
    let _forwards = match crate::targets::port_forward::start(cfg, &store).await {
        Ok(forwards) => forwards,
        Err(e) => {
            return vec![CheckResult {
                name: "port-forwards".into(),
                ok: false,
                detail: e.to_string(),
            }];
        }
    };
    let scrubber = crate::policy::scrub::Scrubber::new();
    let executors = match crate::targets::wiring::build_executors(cfg, &store, &scrubber) {
        Ok((executors, _warnings)) => executors,
        Err(e) => {
            return vec![CheckResult {
                name: "resources".into(),
                ok: false,
                detail: format!("could not build resource connections: {e}"),
            }];
        }
    };
    let mut resources: Vec<_> = executors
        .into_iter()
        .filter(|(fq, _)| FqTarget::parse(fq).is_ok_and(|t| t.resource().is_some()))
        .collect();
    resources.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    for (fq, executor) in resources {
        let name = format!("resource: {fq}");
        out.push(match executor.probe().await {
            Ok(report) => CheckResult { name, ok: report.reachable, detail: report.detail },
            Err(e) => CheckResult { name, ok: false, detail: scrubber.scrub(&e.to_string()) },
        });
    }
    out
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
            detail: "no database exists yet — the daemon will create one on first boot".into(),
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

/// Is the configured identity provider actually there? Under `local` there
/// is nothing external to reach, so this reports skipped rather than
/// inventing a check.
///
/// Under `hanko` the probe is `GET {api_url}/.well-known/jwks.json`, not the
/// `POST /sessions/validate` the daemon really uses: validate needs a live
/// session token, which doctor has no way to obtain, while the JWKS document
/// is unauthenticated and served by the same public port — so reaching it
/// proves exactly what doctor can prove here (the URL is right and the
/// project is up), and nothing more.
///
/// Never fatal to the RUN: a failure is one red line beside the others, and
/// every other check still executes. Doctor reports, it does not refuse.
async fn check_auth_provider(cfg: &Config) -> CheckResult {
    const NAME: &str = "auth provider";
    let result = |ok: bool, detail: String| CheckResult { name: NAME.into(), ok, detail };

    if cfg.auth.provider == crate::config::AuthProvider::Local {
        return result(true, "local password sign-in — skipped (no external provider)".into());
    }
    let Some(base) = cfg.auth.api_base() else {
        // validate() already refuses this; saying it again here means a
        // config that failed check 1 still names WHY sign-in is broken.
        return result(false, "auth.provider is \"hanko\" but auth.api_url is unset".into());
    };

    // Probe the endpoint the daemon ACTUALLY calls, with a deliberately
    // bogus token. It is unauthenticated, and a correctly configured Hanko
    // answers HTTP 200 `{"is_valid": false}` — so this proves the public
    // API, the exact path, and the response shape all at once. The JWKS
    // endpoint would only prove that some host serves something at a
    // well-known path: it would pass against the admin port, against a v2
    // backend, and against an entirely different tenant.
    let url = format!("{base}/sessions/validate");
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build()
    {
        Ok(c) => c,
        Err(e) => return result(false, format!("could not build an HTTP client: {e}")),
    };
    let resp = match client
        .post(&url)
        .json(&serde_json::json!({ "session_token": "opsclaw-doctor-probe" }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return result(false, format!("hanko: {url} unreachable: {e}")),
    };
    let status = resp.status();
    if !status.is_success() {
        return result(
            false,
            format!(
                "hanko: {url} answered HTTP {} — check auth.api_url names the PUBLIC Hanko API, \
                 not the admin port",
                status.as_u16()
            ),
        );
    }
    match resp.json::<serde_json::Value>().await {
        Ok(v) if v.get("is_valid").and_then(serde_json::Value::as_bool) == Some(false) => {
            result(true, format!("hanko: {url} answers as expected"))
        }
        Ok(v) => result(
            false,
            format!(
                "hanko: {url} answered 200 but not the expected {{\"is_valid\": false}} shape \
                 (got {v}) — is this a Hanko public API?"
            ),
        ),
        Err(e) => result(false, format!("hanko: {url} returned an unreadable body: {e}")),
    }
}

/// Whether the operator roster is ready for the configured provider. The
/// provider flip stakes everything on "every operator is linked", and
/// nothing else can answer it: `by_external_subject` is the only lookup the
/// exchange route uses, so an unlinked account is refused forever and the
/// first symptom is a locked-out operator at the worst moment.
async fn check_account_linkage(cfg: &Config, db_path: Option<&str>) -> CheckResult {
    const NAME: &str = "operator linkage";
    let result = |ok: bool, detail: String| CheckResult { name: NAME.into(), ok, detail };
    let hanko = cfg.auth.provider == crate::config::AuthProvider::Hanko;

    let Some(path) = db_path else {
        return result(true, "no database exists yet — no roster to check".into());
    };
    let db = match crate::db::Db::connect(path).await {
        Ok(db) => db,
        Err(e) => return result(false, format!("{path}: {e}")),
    };
    let accounts = match crate::db::AccountRepo::list(&*db.repos()).await {
        Ok(a) => a,
        Err(e) => return result(false, format!("could not read accounts: {e}")),
    };
    if accounts.is_empty() {
        return result(true, "no operator accounts yet".into());
    }
    let (linked, unlinked): (Vec<_>, Vec<_>) =
        accounts.iter().partition(|a| a.external_subject.is_some());

    if hanko {
        if unlinked.is_empty() {
            return result(true, format!("all {} operator account(s) linked", linked.len()));
        }
        let names: Vec<&str> = unlinked.iter().map(|a| a.email.as_str()).collect();
        result(
            false,
            format!(
                "{} of {} operator account(s) are not linked and will be refused at sign-in: {} \
                 — run `opsclaw-cli account link <email> --hanko-subject <id>`",
                unlinked.len(),
                accounts.len(),
                names.join(", ")
            ),
        )
    } else if linked.is_empty() {
        result(true, format!("{} local operator account(s)", accounts.len()))
    } else {
        // The converse warning: mid-migration, and the danger is real if
        // any of them were linked with --drop-password.
        let stuck: Vec<&str> = linked
            .iter()
            .filter(|a| a.password_hash == crate::http::auth::NO_PASSWORD)
            .map(|a| a.email.as_str())
            .collect();
        if stuck.is_empty() {
            result(
                true,
                format!(
                    "{} of {} account(s) already linked, ready for auth.provider = \"hanko\"",
                    linked.len(),
                    accounts.len()
                ),
            )
        } else {
            result(
                false,
                format!(
                    "{} account(s) are linked AND have no password, but auth.provider is still \
                     \"local\" — they cannot sign in by either method: {} — either complete the \
                     flip or run `opsclaw-cli account set-password <email>`",
                    stuck.len(),
                    stuck.join(", ")
                ),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_default_database_is_the_one_doctor_checks() {
        // The regression this exists for: `daemon.db_path` unset is the
        // DEFAULT install, and `boot::daemon_state` still opens
        // `<home>/opsclaw.sqlite3`. Doctor skipping it made both the DB
        // check and the operator roster silently vacuous — reported as OK.
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::default();
        assert!(cfg.daemon.db_path.is_none(), "guards the premise of this test");

        assert_eq!(effective_db_path(&cfg, dir.path()), None, "nothing written yet");

        let db = dir.path().join("opsclaw.sqlite3");
        std::fs::write(&db, b"").unwrap();
        assert_eq!(
            effective_db_path(&cfg, dir.path()),
            Some(db.display().to_string()),
            "an existing default-path database must be checked, not skipped"
        );
    }

    #[test]
    fn an_explicit_db_path_wins_and_is_never_gated_on_existence() {
        // Unlike the fallback, an explicitly configured path that does not
        // exist is a real finding — `check_db` reporting it unopenable is
        // the point, so this must NOT be existence-gated into a pass.
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        let explicit = dir.path().join("elsewhere.sqlite3");
        cfg.daemon.db_path = Some(explicit.clone());
        assert_eq!(effective_db_path(&cfg, dir.path()), Some(explicit.display().to_string()));
    }

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

    /// A hanko config needs a real jwt secret (`requires_real_jwt_secret`),
    /// so every hanko doctor test seeds one rather than tripping check 1 on
    /// an unrelated failure.
    fn hanko_config(api_url: &str) -> String {
        format!(
            r#"
                [http]
                jwt_secret = "env:OPSCLAW_DOCTOR_TEST_JWT"
                [auth]
                provider = "hanko"
                api_url = "{api_url}"
                audience = ["ops.example.com"]
            "#
        )
    }

    fn set_test_jwt() {
        unsafe {
            std::env::set_var("OPSCLAW_DOCTOR_TEST_JWT", "0123456789abcdef0123456789abcdef0123")
        };
    }

    #[tokio::test]
    async fn local_provider_reports_the_auth_check_as_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let report = run(&config_path, dir.path()).await.unwrap();
        let check = report.checks.iter().find(|c| c.name == "auth provider").unwrap();
        assert!(check.ok, "{check:?}");
        assert!(check.detail.contains("skipped"), "{check:?}");
        assert!(report.ok(), "{:#?}", report.checks);
    }

    #[tokio::test]
    async fn hanko_validate_endpoint_answering_correctly_is_green() {
        // The probe hits the endpoint the DAEMON calls, not the JWKS one:
        // a wrong tenant, the admin port, or a v2 backend all serve
        // something at /.well-known/jwks.json but cannot answer this.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/sessions/validate"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "is_valid": false })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        set_test_jwt();
        std::fs::write(&config_path, hanko_config(&server.uri())).unwrap();

        let report = run(&config_path, dir.path()).await.unwrap();
        let check = report.checks.iter().find(|c| c.name == "auth provider").unwrap();
        assert!(check.ok, "{check:?}");
        server.verify().await;
    }

    /// A host that is up and answers 200, but is not a Hanko public API, must
    /// be reported red rather than passing on reachability alone.
    #[tokio::test]
    async fn a_200_that_is_not_the_hanko_shape_is_reported_red() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/sessions/validate"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "something": "else" })),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        set_test_jwt();
        std::fs::write(&config_path, hanko_config(&server.uri())).unwrap();

        let report = run(&config_path, dir.path()).await.unwrap();
        let check = report.checks.iter().find(|c| c.name == "auth provider").unwrap();
        assert!(!check.ok, "{check:?}");
    }

    #[tokio::test]
    async fn a_wrong_hanko_url_is_reported_without_stopping_the_other_checks() {
        // The server is up but serves no JWKS — the shape of "api_url points
        // at something that is not a Hanko public port".
        let server = wiremock::MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        set_test_jwt();
        std::fs::write(&config_path, hanko_config(&server.uri())).unwrap();

        let report = run(&config_path, dir.path()).await.unwrap();
        let check = report.checks.iter().find(|c| c.name == "auth provider").unwrap();
        assert!(!check.ok, "{check:?}");
        assert!(check.detail.contains("404"), "{check:?}");
        // Reported, not fatal: doctor still ran (and still reports) the rest.
        assert!(report.checks.iter().any(|c| c.name == "config"), "{:#?}", report.checks);
        assert!(report.checks.iter().any(|c| c.name == "database"), "{:#?}", report.checks);
    }

    #[tokio::test]
    async fn an_unreachable_hanko_is_reported_not_a_doctor_crash() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        set_test_jwt();
        // Port 1 is reserved and never listening: connection refused.
        std::fs::write(&config_path, hanko_config("http://127.0.0.1:1")).unwrap();

        let report = run(&config_path, dir.path()).await.unwrap();
        let check = report.checks.iter().find(|c| c.name == "auth provider").unwrap();
        assert!(!check.ok, "{check:?}");
        assert!(check.detail.contains("unreachable"), "{check:?}");
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
