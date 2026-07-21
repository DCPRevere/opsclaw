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
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "logout@example.com", "password": "some-password-123" }),
        )
        .await;
    assert_eq!(client.get(&format!("{base}/api/status")).await.status(), reqwest::StatusCode::OK);

    client.post(&format!("{base}/api/logout")).await;
    assert_eq!(
        client.get(&format!("{base}/api/status")).await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
}

// ---- invite / join ----

#[tokio::test]
async fn invite_then_join_creates_a_signed_in_account() {
    let state = AppState::fake();
    seed_account(&state, "inviter@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();

    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "inviter@example.com", "password": "some-password-123" }),
        )
        .await;
    let invite: serde_json::Value =
        client.post(&format!("{base}/api/invites")).await.json().await.unwrap();
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

// ---- remote CLI (PKCE login, then the minted `ops_` bearer reaches
// `Authed`-gated operator-action routes — DESIGN §7 decision 14) ----

/// Full PKCE round trip against the real router: a signed-in web session
/// authorizes a CLI login (`POST /api/cli/authorize`), then the CLI
/// exchanges its code+verifier for a token (`POST /cli/v1/auth/token`) with
/// NO cookie attached — proving the exchange endpoint is reachable
/// unauthenticated, as a fresh CLI process would call it.
#[tokio::test]
async fn cli_pkce_login_mints_a_bearer_token() {
    let state = AppState::fake();
    seed_account(&state, "cliop@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let web = SessionClient::new();
    web.post_json(
        &format!("{base}/api/login"),
        &serde_json::json!({ "email": "cliop@example.com", "password": "some-password-123" }),
    )
    .await;

    let verifier = "a".repeat(43);
    let challenge = opsclaw::http::cli_auth::challenge_for(&verifier);
    let authorize: serde_json::Value = web
        .post_json(
            &format!("{base}/api/cli/authorize"),
            &serde_json::json!({ "challenge": challenge, "name": "test-host" }),
        )
        .await
        .json()
        .await
        .unwrap();
    let code = authorize["code"].as_str().unwrap().to_string();

    // Unauthenticated on purpose — a bare reqwest client, no cookie jar.
    let exchange: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/cli/v1/auth/token"))
        .json(&serde_json::json!({ "code": code, "verifier": verifier }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = exchange["token"].as_str().unwrap();
    assert!(token.starts_with("ops_"));
    assert_eq!(exchange["email"], "cliop@example.com");

    // /cli/v1/me confirms the bearer resolves to the right account.
    let me: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/cli/v1/me"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["email"], "cliop@example.com");
}

/// The minted `ops_` token, with NO session cookie, is accepted by an
/// `Authed`-gated route that lives outside `/cli/v1/*` (e-stop) — the
/// gateway-side change this wave made so the remote CLI's approve/deny/
/// estop commands don't need a second, duplicate route family.
#[tokio::test]
async fn cli_bearer_token_reaches_authed_gated_routes() {
    let state = AppState::fake();
    seed_account(&state, "cliestop@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let web = SessionClient::new();
    web.post_json(
        &format!("{base}/api/login"),
        &serde_json::json!({ "email": "cliestop@example.com", "password": "some-password-123" }),
    )
    .await;

    let verifier = "b".repeat(43);
    let challenge = opsclaw::http::cli_auth::challenge_for(&verifier);
    let authorize: serde_json::Value = web
        .post_json(
            &format!("{base}/api/cli/authorize"),
            &serde_json::json!({ "challenge": challenge }),
        )
        .await
        .json()
        .await
        .unwrap();
    let code = authorize["code"].as_str().unwrap().to_string();
    let exchange: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/cli/v1/auth/token"))
        .json(&serde_json::json!({ "code": code, "verifier": verifier }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = exchange["token"].as_str().unwrap();

    // No cookie anywhere in this client — bearer only.
    let cli_client = reqwest::Client::new();
    let engaged: serde_json::Value = cli_client
        .post(format!("{base}/api/estop/engage"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "reason": "cli e2e test" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(engaged["estop_engaged"], true);

    // Revoke (logout) then confirm the same token is rejected everywhere.
    let revoked =
        cli_client.delete(format!("{base}/cli/v1/token")).bearer_auth(token).send().await.unwrap();
    assert_eq!(revoked.status(), reqwest::StatusCode::OK);

    let after_revoke = cli_client
        .post(format!("{base}/api/estop/resume"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(after_revoke.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ---- e-stop ----

#[tokio::test]
async fn estop_engage_and_resume_round_trip_over_http() {
    let state = AppState::fake();
    seed_account(&state, "estop@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "estop@example.com", "password": "some-password-123" }),
        )
        .await;

    let engaged: serde_json::Value = client
        .post_json(&format!("{base}/api/estop/engage"), &serde_json::json!({ "reason": "test" }))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(engaged["estop_engaged"], true);

    let status: serde_json::Value =
        client.get(&format!("{base}/api/status")).await.json().await.unwrap();
    assert_eq!(status["estop_engaged"], true);

    let resumed: serde_json::Value =
        client.post(&format!("{base}/api/estop/resume")).await.json().await.unwrap();
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
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "audit@example.com", "password": "some-password-123" }),
        )
        .await;

    let verify: serde_json::Value =
        client.get(&format!("{base}/api/audit/verify")).await.json().await.unwrap();
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

    let verify: serde_json::Value =
        client.get(&format!("{base}/api/audit/verify")).await.json().await.unwrap();
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

    let resp = reqwest::Client::new()
        .post(format!("{base}/webhooks/alertmanager"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_on_the_fully_faked_spine_is_accepted_with_no_secret() {
    let state = AppState::fake();
    assert!(state.config.fully_faked());
    let base = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/webhooks/alertmanager"))
        .body("{}")
        .send()
        .await
        .unwrap();
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
    unsafe {
        std::env::set_var("OPSCLAW_E2E_JWT_SECRET_XYZZY", "sekrit-marker-value-do-not-leak-12345")
    };
    let state = AppState::fake_with_config(cfg);
    let base = spawn_server(state).await;
    let client = SessionClient::new();

    let login = client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "nobody@example.com", "password": "x" }),
        )
        .await;
    let body = login.text().await.unwrap();
    assert!(!body.contains("sekrit-marker-value-do-not-leak"), "{body}");

    let status = client.get(&format!("{base}/api/status")).await;
    let body = status.text().await.unwrap();
    assert!(!body.contains("sekrit-marker-value-do-not-leak"), "{body}");
}

// ---- embedded web UI ----
//
// The UI's own JS is not testable here (no browser in this test process —
// `pages.rs`'s unit tests already cover the served bytes/headers
// structurally). What IS tested: the app shell serves publicly with the
// no-cache header this whole mechanism exists for, and every JSON route
// the four surfaces' JS consumes round-trips correctly on the fakes spine
// — the exact contract the UI is built against.

#[tokio::test]
async fn app_shell_serves_with_no_cache_and_no_auth_required() {
    let state = AppState::fake();
    let base = spawn_server(state).await;
    // No cookie at all — the shell itself is a PUBLIC route (DESIGN §3:
    // login lives inside it, so "the login page is public" holds without
    // a separate server-side redirect; see routes/mod.rs's module doc).
    let resp = reqwest::get(format!("{base}/app")).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.headers().get(reqwest::header::CACHE_CONTROL).unwrap(), "no-cache");
    let body = resp.text().await.unwrap();
    assert!(body.contains("login-form"), "shell must contain the login form");
}

#[tokio::test]
async fn unauthed_api_request_against_a_ui_backed_route_is_401_not_the_shell() {
    // The four surfaces' JS all call JSON routes under /api — an unauthed
    // request to one of them must 401 (never silently serve HTML or an
    // empty 200 the JS would misinterpret as "no data").
    let state = AppState::fake();
    let base = spawn_server(state).await;
    for path in [
        "/api/me",
        "/api/incidents",
        "/api/approvals",
        "/api/status",
        "/api/invites",
        "/api/cli-tokens",
        "/api/config",
    ] {
        let resp = reqwest::get(format!("{base}{path}")).await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn app_modules_manifest_and_service_worker_serve_publicly() {
    let state = AppState::fake();
    let base = spawn_server(state).await;
    for path in [
        "/app/main.js",
        "/app/api.js",
        "/app/state.js",
        "/app/auth.js",
        "/app/chat.js",
        "/app/incidents.js",
        "/app/approvals.js",
        "/app/status.js",
        "/app/settings.js",
        "/sw.js",
        "/static/manifest.json",
        "/static/img/icon.svg",
    ] {
        let resp = reqwest::get(format!("{base}{path}")).await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn incidents_and_approvals_backing_routes_round_trip_for_an_authed_operator() {
    let state = AppState::fake();
    seed_account(&state, "ui@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "ui@example.com", "password": "some-password-123" }),
        )
        .await;

    let incidents: serde_json::Value =
        client.get(&format!("{base}/api/incidents")).await.json().await.unwrap();
    assert!(incidents["incidents"].as_array().unwrap().is_empty());

    let approvals: serde_json::Value =
        client.get(&format!("{base}/api/approvals")).await.json().await.unwrap();
    assert!(approvals["approvals"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn settings_surface_backing_routes_round_trip_invites_and_cli_tokens() {
    let state = AppState::fake();
    seed_account(&state, "settings@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "settings@example.com", "password": "some-password-123" }))
        .await;

    let invite: serde_json::Value =
        client.post(&format!("{base}/api/invites")).await.json().await.unwrap();
    assert!(invite["code"].as_str().is_some());

    let invites: serde_json::Value =
        client.get(&format!("{base}/api/invites")).await.json().await.unwrap();
    assert_eq!(invites["invites"].as_array().unwrap().len(), 1);

    let tokens: serde_json::Value =
        client.get(&format!("{base}/api/cli-tokens")).await.json().await.unwrap();
    assert!(tokens["tokens"].as_array().unwrap().is_empty());
}

/// `POST /api/config` writes to `config::default_dir()` (honours
/// `$OPSCLAW_HOME`) — there is no `AppState`-level seam to redirect it
/// (see `routes::config_ui::update_config`'s doc comment for why, and the
/// contract gap flagged in this task's report). `$OPSCLAW_HOME` is a
/// process-global env var, so any test that sets it to actually exercise
/// the write path MUST serialize against every other such test — this
/// mutex is that guard. Found the hard way: an earlier version of this
/// test suite exercised the write path against the REAL, UNGUARDED
/// `~/.opsclaw/config.toml` on the dev machine running the suite, which
/// turned out to hold a legacy zeroclaw-fork config containing unencrypted
/// SSH private keys — this guard plus an isolated tempdir is what stops
/// that from ever happening again, in this suite or a future one that
/// copies this pattern.
static CONFIG_WRITE_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Point `$OPSCLAW_HOME` at a fresh, isolated tempdir for the duration of
/// the returned guard (which also holds `CONFIG_WRITE_TEST_GUARD` so no
/// other config-writing test can interleave). Restores the previous value
/// (or removes the var if it was unset) on drop.
struct IsolatedOpsclawHome {
    _lock: std::sync::MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
    previous: Option<std::ffi::OsString>,
}

impl IsolatedOpsclawHome {
    fn set() -> Self {
        let lock = CONFIG_WRITE_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var_os("OPSCLAW_HOME");
        let dir = tempfile::tempdir().expect("tempdir for isolated OPSCLAW_HOME");
        unsafe { std::env::set_var("OPSCLAW_HOME", dir.path()) };
        IsolatedOpsclawHome { _lock: lock, _dir: dir, previous }
    }
}

impl Drop for IsolatedOpsclawHome {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(v) => unsafe { std::env::set_var("OPSCLAW_HOME", v) },
            None => unsafe { std::env::remove_var("OPSCLAW_HOME") },
        }
    }
}

#[tokio::test]
async fn config_surface_round_trips_read_then_validated_write() {
    let _home = IsolatedOpsclawHome::set();
    let state = AppState::fake();
    seed_account(&state, "config@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "config@example.com", "password": "some-password-123" }),
        )
        .await;

    let got: serde_json::Value =
        client.get(&format!("{base}/api/config")).await.json().await.unwrap();
    let toml_text = got["toml"].as_str().expect("toml field").to_string();
    // The read-back text must itself parse as valid opsclaw config — the
    // settings tab's textarea is seeded with exactly this.
    let _: opsclaw::config::Config =
        toml::from_str(&toml_text).expect("round-tripped config must parse");

    let saved = client
        .post_json(&format!("{base}/api/config"), &serde_json::json!({ "toml": toml_text }))
        .await;
    assert_eq!(saved.status(), reqwest::StatusCode::OK);
    let saved_body: serde_json::Value = saved.json().await.unwrap();
    assert_eq!(saved_body["ok"], true);

    // The write actually landed at the isolated path — never the real
    // machine's ~/.opsclaw regardless of what this assertion finds.
    let written =
        std::fs::read_to_string(opsclaw::config::default_dir().join("config.toml")).unwrap();
    assert_eq!(written, toml_text);
}

#[tokio::test]
async fn config_surface_rejects_invalid_toml_and_invalid_config() {
    let state = AppState::fake();
    seed_account(&state, "badconfig@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(&format!("{base}/api/login"), &serde_json::json!({ "email": "badconfig@example.com", "password": "some-password-123" }))
        .await;

    let garbage = client
        .post_json(
            &format!("{base}/api/config"),
            &serde_json::json!({ "toml": "not valid toml {{{" }),
        )
        .await;
    assert_eq!(garbage.status(), reqwest::StatusCode::BAD_REQUEST);

    // Valid TOML, but a config `Config::validate()` itself would refuse
    // (an unset http.jwt_secret while llm.api_key is set — see
    // config::tests::live_mode_requires_jwt_secret) must be rejected too,
    // not just a parse failure — the API route runs the SAME validation
    // the daemon boots with.
    let invalid_but_parseable = r#"
[llm]
api_key = "env:OPSCLAW_E2E_NEVER_SET"
models = ["some/model"]
[memory]
hindsight_url = "http://localhost:1"
"#;
    let rejected = client
        .post_json(
            &format!("{base}/api/config"),
            &serde_json::json!({ "toml": invalid_but_parseable }),
        )
        .await;
    assert_eq!(rejected.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ---- web push ----

#[tokio::test]
async fn vapid_public_key_is_unauthenticated_and_404s_when_unconfigured() {
    // No push config: the route must 404 (not error, not an empty 200) so
    // the app shell can feature-detect and skip offering "enable
    // notifications" — see routes::push's module doc.
    let state = AppState::fake();
    let base = spawn_server(state).await;
    let resp = reqwest::get(format!("{base}/api/push/vapid-public-key")).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    // With push configured, the SAME route is reachable with no cookie at
    // all (deliberately unauthenticated — a VAPID public key is not a
    // secret; see the route's doc comment for why).
    let mut cfg = Config::default();
    cfg.push.vapid_public_key = Some("test-vapid-public-key".into());
    let state = AppState::fake_with_config(cfg);
    let base = spawn_server(state).await;
    let resp = reqwest::get(format!("{base}/api/push/vapid-public-key")).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["vapid_public_key"], "test-vapid-public-key");
}

#[tokio::test]
async fn push_subscribe_requires_auth_then_roundtrips_to_unsubscribe() {
    let mut cfg = Config::default();
    cfg.push.vapid_public_key = Some("test-vapid-public-key".into());
    let state = AppState::fake_with_config(cfg);
    seed_account(&state, "push@example.com", "some-password-123").await;
    let base = spawn_server(state).await;

    // No session: both routes reject with 401.
    let anon = reqwest::Client::new();
    let sub_body = serde_json::json!({
        "endpoint": "https://push.example/ep-1",
        "keys": { "p256dh": "p256dh-value", "auth": "auth-value" }
    });
    let resp =
        anon.post(format!("{base}/api/push/subscribe")).json(&sub_body).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let resp = anon
        .post(format!("{base}/api/push/unsubscribe"))
        .json(&serde_json::json!({ "endpoint": "https://push.example/ep-1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Signed in: subscribe succeeds, then unsubscribe succeeds.
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "push@example.com", "password": "some-password-123" }),
        )
        .await;

    let subscribed = client.post_json(&format!("{base}/api/push/subscribe"), &sub_body).await;
    assert_eq!(subscribed.status(), reqwest::StatusCode::OK);

    let unsubscribed = client
        .post_json(
            &format!("{base}/api/push/unsubscribe"),
            &serde_json::json!({ "endpoint": "https://push.example/ep-1" }),
        )
        .await;
    assert_eq!(unsubscribed.status(), reqwest::StatusCode::OK);
}
