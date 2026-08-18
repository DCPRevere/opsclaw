//! Tier-3 daemon lifecycle e2e (DESIGN §6: "e2e in-process daemon...
//! lifecycle"): the REAL boot path (`boot::daemon_state` — the exact wiring
//! `main.rs` and `opsclaw-cli daemon` share) over a REAL SQLite file, served
//! by the REAL `server::run`, shut down through the SIGTERM-equivalent seam
//! (cancelling the state's daemon-wide `CancellationToken` — the same token
//! a process signal cancels; a raw signal would hit every parallel test in
//! this process, so the token IS the honest in-process stand-in), and booted
//! a SECOND time over the SAME database file to prove state survives a
//! restart.
//!
//! What this deliberately does NOT fake: the config is a fully-faked one
//! (no llm key → the clearly-logged FakeLlm; no Hindsight; no channels), but
//! everything on the lifecycle path itself — sqlite migrate-on-connect, the
//! scheduler loop, the HTTP listener, graceful drain — is the shipped code.

use std::time::Duration;

use opsclaw::config::Config;
use opsclaw::db::{Account, AccountRepo, IncidentRepo};
use opsclaw::domain::{FqTarget, Incident, IncidentState, Severity};
use opsclaw::http::AppState;
use uuid::Uuid;

/// Reserve a concrete `127.0.0.1:<port>` for the daemon to bind. `server::run`
/// binds whatever `daemon.listen` says and never reports the resolved port,
/// so an ephemeral `:0` would leave the test unable to reach it — reserve a
/// real port, release it, and hand that address to the config. (The tiny
/// reuse race this leaves open is the standard test trade-off; the bind
/// happens milliseconds later.)
async fn reserve_addr() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("reserve port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr.to_string()
}

/// Full production boot over `home`: the same `Config` shape the sim
/// harness generates (fully faked, explicit `db_path`), through
/// `boot::daemon_state` — never a hand-rolled `AppState`.
async fn boot(home: &std::path::Path, listen: &str) -> AppState {
    let mut config = Config::default();
    config.daemon.listen = listen.to_string();
    config.daemon.db_path = Some(home.join("opsclaw.sqlite3"));
    config.daemon.runbooks_dir = home.join("runbooks");
    opsclaw::boot::daemon_state(config, home.join("config.toml"), home)
        .await
        .expect("daemon_state boots on a fresh home")
}

/// Poll until the freshly-spawned server actually answers (the app shell is
/// public, so a 200 means the listener + router are live).
async fn wait_until_serving(base: &str) {
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if let Ok(resp) = client.get(format!("{base}/app")).send().await
            && resp.status() == reqwest::StatusCode::OK
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server at {base} did not start serving within 5s");
}

async fn login(base: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({ "email": "op@example.com", "password": "some-password-123" }))
        .send()
        .await
        .expect("login request reaches the server")
}

fn session_cookie(resp: &reqwest::Response) -> String {
    let set_cookie = resp.headers().get(reqwest::header::SET_COOKIE).expect("session cookie set");
    set_cookie.to_str().unwrap().split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn daemon_boots_serves_drains_on_the_shutdown_token_and_persists_across_restart() {
    let home = tempfile::tempdir().expect("tempdir home");

    // ---- first boot: real wiring over a fresh sqlite file ----
    let addr = reserve_addr().await;
    let base = format!("http://{addr}");
    let state = boot(home.path(), &addr).await;

    // Seed the operator through the repos (the `opsclaw onboard` bootstrap
    // seam) — INTO SQLITE, which is exactly what the restart must preserve.
    let account = Account {
        id: Uuid::new_v4(),
        email: "op@example.com".into(),
        display_name: "Test Operator".into(),
        password_hash: opsclaw::http::auth::hash_password("some-password-123").unwrap(),
        token_version: 0,
        created_at: chrono::Utc::now(),
        auth_provider: "local".into(),
        external_subject: None,
    };
    AccountRepo::insert(&*state.repos, &account).await.unwrap();

    let server = tokio::spawn(opsclaw::http::server::run(state.clone()));
    wait_until_serving(&base).await;

    // Authenticated round trip against the live daemon.
    let logged_in = login(&base).await;
    assert_eq!(logged_in.status(), reqwest::StatusCode::OK);
    let cookie = session_cookie(&logged_in);

    // An incident opened before shutdown (via the daemon's own sqlite-backed
    // repos — the same store `opsclaw_notify` writes through)...
    let incident_id = Uuid::new_v4();
    let incident = Incident {
        id: incident_id,
        fingerprint: "lifecycle-e2e-fingerprint".into(),
        fault_class: String::new(),
        target: FqTarget::try_new("example", "prod", "web-1").unwrap(),
        severity: Severity::Critical,
        state: IncidentState::Active,
        signals: "disk 98% full on /data".into(),
        hypothesis: "log rotation stopped".into(),
        recommended_action: None,
        opened_at: chrono::Utc::now(),
        reopened_at: None,
        acked_at: None,
        acked_by: None,
        resolved_at: None,
        last_notified_at: None,
        notify_count: 0,
        escalation_step: 0,
        step_started_at: None,
    };
    IncidentRepo::insert(&*state.repos, &incident).await.unwrap();

    // ...is visible over HTTP while the first daemon is still up.
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/api/incidents"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed["incidents"][0]["id"], incident_id.to_string());

    // ---- SIGTERM-equivalent shutdown: cancel the daemon-wide token ----
    state.shutdown.cancel();
    // The server task must complete GRACEFULLY within the drain budget
    // (server::run's own bound is 20s): no hang, no panic, no error.
    let drained = tokio::time::timeout(Duration::from_secs(25), server)
        .await
        .expect("server did not drain within the 25s budget (20s drain bound + margin)")
        .expect("server task panicked during shutdown");
    drained.expect("server::run returned an error on graceful shutdown");

    // The listener is actually gone — this is a stopped daemon, not a
    // wedged one still accepting connections.
    assert!(
        reqwest::Client::new().get(format!("{base}/app")).send().await.is_err(),
        "the drained server must no longer accept connections"
    );
    drop(state);

    // ---- second boot over the SAME sqlite file ----
    let addr2 = reserve_addr().await;
    let base2 = format!("http://{addr2}");
    let state2 = boot(home.path(), &addr2).await;
    let server2 = tokio::spawn(opsclaw::http::server::run(state2.clone()));
    wait_until_serving(&base2).await;

    // The operator account persisted: the SAME credentials sign in against
    // the rebooted daemon, over HTTP, with no re-seeding.
    let relogin = login(&base2).await;
    assert_eq!(relogin.status(), reqwest::StatusCode::OK, "account must survive the restart");
    let cookie2 = session_cookie(&relogin);

    // And the incident persisted, with its content intact.
    let relisted: serde_json::Value = reqwest::Client::new()
        .get(format!("{base2}/api/incidents"))
        .header(reqwest::header::COOKIE, &cookie2)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let survived = relisted["incidents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == incident_id.to_string())
        .unwrap_or_else(|| panic!("incident must survive the restart: {relisted}"));
    assert_eq!(survived["hypothesis"], "log rotation stopped");
    assert_eq!(survived["severity"], "critical");
    assert_eq!(survived["state"], "active");

    // Second daemon drains the same way (the lifecycle is repeatable, not a
    // one-boot fluke).
    state2.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(25), server2)
        .await
        .expect("second server did not drain within the budget")
        .expect("second server task panicked")
        .expect("second server::run returned an error");
}
