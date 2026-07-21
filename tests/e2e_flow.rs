//! End-to-end HTTP tests: a real bound server, real HTTP requests (via
//! `reqwest`), running against the fakes spine (`AppState::fake`). Ported
//! in spirit from gianna's `tests/e2e_flow.rs` (real server, real client,
//! no mocking of the router itself) — the journeys here are opsclaw's own:
//! bootstrap an account, invite a teammate, sign in, hit the auth matrix,
//! e-stop, audit verify, and the webhook HMAC gate.
//!
//! `reqwest`'s `cookies` feature isn't declared in Cargo.toml (frozen for
//! this port), so [`SessionClient`] manually captures and replays the
//! `Set-Cookie` header — a browser's cookie jar collapsed to exactly the
//! one cookie these tests need.
//!
//! Each test binds its OWN server on an ephemeral port (`127.0.0.1:0`) so
//! the suite can run fully parallel with no shared state between tests.

use opsclaw::config::Config;
use opsclaw::db::{Account, AccountRepo};
use opsclaw::http::AppState;
use uuid::Uuid;

/// Bind `state`'s router on an ephemeral port and serve it on a background
/// task for the life of the test. Returns the base URL to hit.
async fn spawn_server(state: AppState) -> String {
    let router = opsclaw::http::routes::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

/// A minimal single-cookie jar over `reqwest`: captures `Set-Cookie` from
/// every response and replays it as `Cookie` on every subsequent request —
/// exactly what the auth flow needs (`opsclaw_session=...`), with none of
/// the surface area a general cookie jar would need `reqwest`'s `cookies`
/// feature for.
struct SessionClient {
    client: reqwest::Client,
    cookie: std::sync::Mutex<Option<String>>,
}

impl SessionClient {
    fn new() -> Self {
        SessionClient { client: reqwest::Client::new(), cookie: std::sync::Mutex::new(None) }
    }

    fn capture(&self, resp: &reqwest::Response) {
        if let Some(v) = resp.headers().get(reqwest::header::SET_COOKIE)
            && let Ok(s) = v.to_str()
        {
            // "name=value; HttpOnly; ..." — keep only the "name=value" part,
            // which is exactly what a `Cookie:` request header carries.
            let kv = s.split(';').next().unwrap_or(s).to_string();
            *self.cookie.lock().unwrap() = Some(kv);
        }
    }

    fn attach(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(c) = self.cookie.lock().unwrap().clone() {
            req = req.header(reqwest::header::COOKIE, c);
        }
        req
    }

    async fn get(&self, url: &str) -> reqwest::Response {
        let resp = self.attach(self.client.get(url)).send().await.unwrap();
        self.capture(&resp);
        resp
    }

    async fn post_json(&self, url: &str, body: &serde_json::Value) -> reqwest::Response {
        let resp = self.attach(self.client.post(url).json(body)).send().await.unwrap();
        self.capture(&resp);
        resp
    }

    async fn post(&self, url: &str) -> reqwest::Response {
        let resp = self.attach(self.client.post(url)).send().await.unwrap();
        self.capture(&resp);
        resp
    }
}

/// Seed one operator account directly via the repo (bypassing HTTP — the
/// same seam `opsclaw onboard` uses for the very first account; see
/// `http::routes::invites`'s module doc for why bootstrap has no HTTP path).
async fn seed_account(state: &AppState, email: &str, password: &str) -> Uuid {
    let id = Uuid::new_v4();
    let account = Account {
        id,
        email: email.into(),
        display_name: "Test Operator".into(),
        password_hash: opsclaw::http::auth::hash_password(password).unwrap(),
        token_version: 0,
        created_at: chrono::Utc::now(),
    };
    AccountRepo::insert(&*state.repos, &account).await.unwrap();
    id
}

// ---- auth matrix ----

#[tokio::test]
async fn no_cookie_is_rejected_with_401() {
    let state = AppState::fake();
    let base = spawn_server(state).await;
    let resp = reqwest::get(format!("{base}/api/status")).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_garbage_cookie_is_rejected_with_401() {
    let state = AppState::fake();
    let base = spawn_server(state).await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/status"))
        .header(reqwest::header::COOKIE, "opsclaw_session=not-a-real-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_then_authenticated_route_succeeds() {
    let state = AppState::fake();
    seed_account(&state, "op@example.com", "correct horse battery staple").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();

    let login = client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "op@example.com", "password": "correct horse battery staple" }))
        .await;
    assert_eq!(login.status(), reqwest::StatusCode::OK);

    let status = client.get(&format!("{base}/api/status")).await;
    assert_eq!(status.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = status.json().await.unwrap();
    assert!(body.get("heartbeat").is_some());
}

#[tokio::test]
async fn wrong_password_is_rejected_with_the_same_message_as_unknown_email() {
    let state = AppState::fake();
    seed_account(&state, "known@example.com", "the-real-password").await;
    let base = spawn_server(state).await;
    let client = reqwest::Client::new();

    let wrong_password = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({ "email": "known@example.com", "password": "nope" }))
        .send()
        .await
        .unwrap();
    let unknown_email = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({ "email": "nobody@example.com", "password": "nope" }))
        .send()
        .await
        .unwrap();

    assert_eq!(wrong_password.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_email.status(), reqwest::StatusCode::UNAUTHORIZED);
    let a: serde_json::Value = wrong_password.json().await.unwrap();
    let b: serde_json::Value = unknown_email.json().await.unwrap();
    assert_eq!(a["error"], b["error"], "must not leak which emails are registered");
}

#[tokio::test]
async fn revoked_token_version_invalidates_an_outstanding_session() {
    let state = AppState::fake();
    let account_id = seed_account(&state, "revokeme@example.com", "some-password-123").await;
    let base = spawn_server(state.clone()).await;
    let client = SessionClient::new();

    client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "revokeme@example.com", "password": "some-password-123" }))
        .await;
    let before = client.get(&format!("{base}/api/status")).await;
    assert_eq!(before.status(), reqwest::StatusCode::OK);

    // Bump token_version directly (what a password reset / "sign out
    // everywhere" would trigger) — the already-issued cookie's `ver` claim
    // is now stale.
    state.repos.bump_token_version(account_id).await.unwrap();

    let after = client.get(&format!("{base}/api/status")).await;
    assert_eq!(after.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_clears_the_session() {
    let state = AppState::fake();
    seed_account(&state, "logout@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();

    client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "logout@example.com", "password": "some-password-123" }))
        .await;
    assert_eq!(client.get(&format!("{base}/api/status")).await.status(), reqwest::StatusCode::OK);

    client.post(&format!("{base}/api/logout")).await;
    assert_eq!(client.get(&format!("{base}/api/status")).await.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ---- invite / join ----

#[tokio::test]
async fn invite_then_join_creates_a_signed_in_account() {
    let state = AppState::fake();
    seed_account(&state, "inviter@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();

    client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "inviter@example.com", "password": "some-password-123" }))
        .await;
    let invite: serde_json::Value = client.post(&format!("{base}/api/invites")).await.json().await.unwrap();
    let code = invite["code"].as_str().unwrap().to_string();

    let join_client = SessionClient::new();
    let joined = join_client
        .post_json(
            &format!("{base}/api/join"),
            &serde_json::json!({
                "code": code,
                "email": "teammate@example.com",
                "password": "another-strong-password",
                "display_name": "Teammate",
            }),
        )
        .await;
    assert_eq!(joined.status(), reqwest::StatusCode::OK);

    // The joined session works immediately (join sets the session cookie).
    let status = join_client.get(&format!("{base}/api/status")).await;
    assert_eq!(status.status(), reqwest::StatusCode::OK);

    // The SAME code cannot be used twice (the double-join TOCTOU guard).
    let replay = reqwest::Client::new()
        .post(format!("{base}/api/join"))
        .json(&serde_json::json!({
            "code": code,
            "email": "someone-else@example.com",
            "password": "yet-another-password",
            "display_name": "Someone Else",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ---- e-stop ----

#[tokio::test]
async fn estop_engage_and_resume_round_trip_over_http() {
    let state = AppState::fake();
    seed_account(&state, "estop@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "estop@example.com", "password": "some-password-123" }))
        .await;

    let engaged: serde_json::Value =
        client.post_json(&format!("{base}/api/estop/engage"), &serde_json::json!({ "reason": "test" })).await.json().await.unwrap();
    assert_eq!(engaged["estop_engaged"], true);

    let status: serde_json::Value = client.get(&format!("{base}/api/status")).await.json().await.unwrap();
    assert_eq!(status["estop_engaged"], true);

    let resumed: serde_json::Value = client.post(&format!("{base}/api/estop/resume")).await.json().await.unwrap();
    assert_eq!(resumed["estop_engaged"], false);
}

// ---- audit ----

#[tokio::test]
async fn audit_verify_on_an_empty_chain_is_ok() {
    let state = AppState::fake();
    seed_account(&state, "audit@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "audit@example.com", "password": "some-password-123" }))
        .await;

    let verify: serde_json::Value = client.get(&format!("{base}/api/audit/verify")).await.json().await.unwrap();
    assert_eq!(verify["ok"], true);
    assert_eq!(verify["records_verified"], 0);
}

/// A chain long enough to span multiple `AuditRepo::range` pages (the
/// handler pages at 1000) must still verify — proving the handler carries
/// the previous page's tail into `chain::verify_from` rather than calling
/// `chain::verify` fresh per page (which would fail page 2's first record
/// against the genesis check). Regression test for exactly the trap
/// `audit::chain::verify_from`'s own doc comment names.
#[tokio::test]
async fn audit_verify_spans_multiple_pages_of_an_intact_chain() {
    let state = AppState::fake();
    seed_account(&state, "bigaudit@example.com", "some-password-123").await;

    let writer = opsclaw::audit::AuditWriter::new(state.repos.clone());
    for i in 0..1500 {
        writer
            .append(
                &opsclaw::domain::Principal::System,
                "remundo::prod::web-1",
                "ssh",
                &format!("uptime # {i}"),
                opsclaw::domain::RiskClass::Read,
                opsclaw::audit::AuditOutcome::Executed,
                Some(0),
            )
            .await
            .unwrap();
    }

    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "bigaudit@example.com", "password": "some-password-123" }))
        .await;

    let verify: serde_json::Value = client.get(&format!("{base}/api/audit/verify")).await.json().await.unwrap();
    assert_eq!(verify["ok"], true, "{verify:?}");
    assert_eq!(verify["records_verified"], 1500);
}

// ---- webhook HMAC gate ----

#[tokio::test]
async fn webhook_without_a_secret_configured_and_not_fully_faked_is_rejected() {
    // A LIVE config (llm configured) with no webhook secret must refuse —
    // unlike the plain fakes spine, which accepts an unsigned payload.
    let mut cfg = Config::default();
    cfg.llm.api_key = Some(opsclaw::config::SecretRef::env("OPSCLAW_TEST_NEVER_SET_XYZ"));
    cfg.llm.models = vec!["some/model".into()];
    cfg.memory.hindsight_url = Some("http://localhost:1".into());
    let state = AppState::fake_with_config(cfg);
    assert!(!state.config.fully_faked());
    let base = spawn_server(state).await;

    let resp = reqwest::Client::new().post(format!("{base}/webhooks/alertmanager")).body("{}").send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_on_the_fully_faked_spine_is_accepted_with_no_secret() {
    let state = AppState::fake();
    assert!(state.config.fully_faked());
    let base = spawn_server(state).await;

    let resp = reqwest::Client::new().post(format!("{base}/webhooks/alertmanager")).body("{}").send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

// ---- secret-never-in-response ----

#[tokio::test]
async fn jwt_secret_never_appears_in_any_response_body() {
    let mut cfg = Config::default();
    // A distinctive live secret, checked against every response body below.
    cfg.http.jwt_secret = Some(opsclaw::config::SecretRef::env("OPSCLAW_E2E_JWT_SECRET_XYZZY"));
    // SAFETY: test-only env var, unique name, no cross-test interference
    // beyond the usual env-var caveats already accepted elsewhere in this
    // crate's test suite (see config::secrets::tests).
    unsafe { std::env::set_var("OPSCLAW_E2E_JWT_SECRET_XYZZY", "sekrit-marker-value-do-not-leak-12345") };
    let state = AppState::fake_with_config(cfg);
    let base = spawn_server(state).await;
    let client = SessionClient::new();

    let login =
        client.post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "nobody@example.com", "password": "x" })).await;
    let body = login.text().await.unwrap();
    assert!(!body.contains("sekrit-marker-value-do-not-leak"), "{body}");

    let status = client.get(&format!("{base}/api/status")).await;
    let body = status.text().await.unwrap();
    assert!(!body.contains("sekrit-marker-value-do-not-leak"), "{body}");
}
