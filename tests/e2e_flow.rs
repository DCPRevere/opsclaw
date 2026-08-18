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

use opsclaw::channels::ChatHandler;
use opsclaw::config::Config;
use opsclaw::db::{Account, AccountRepo};
use opsclaw::domain::Principal;
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
        auth_provider: "local".into(),
        external_subject: None,
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

/// A bearer-authenticated request must carry the OPERATOR's identity, not
/// the token row's. `CliTokenRepo::find_cli_token` returns
/// `(token_id, account_id)`; `handlers::authenticate` bound that tuple the
/// other way round, so every `Authed` route outside `/cli/v1/*` saw the
/// TOKEN's uuid as the account. `/api/me` is the cheapest place to see it:
/// it looks the id up and reports the row, so the bug showed as a 401
/// ("unknown account") rather than as a wrong-but-plausible answer.
///
/// Asserting the status alone would NOT catch a future re-swap that happens
/// to resolve — the account id in the body is the actual claim.
#[tokio::test]
async fn cli_bearer_token_reaches_api_me_as_the_right_account() {
    let state = AppState::fake();
    let account_id = seed_account(&state, "clime@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let web = SessionClient::new();
    web.post_json(
        &format!("{base}/api/login"),
        &serde_json::json!({ "email": "clime@example.com", "password": "some-password-123" }),
    )
    .await;

    let verifier = "c".repeat(43);
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

    // Bearer only, no cookie — and `/api/me` is an `Authed` route OUTSIDE
    // the `/cli/v1/*` family, so it goes through `handlers::authenticate`.
    let me = reqwest::Client::new()
        .get(format!("{base}/api/me"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = me.json().await.unwrap();
    assert_eq!(
        body["account_id"],
        account_id.to_string(),
        "the bearer must resolve to the operator's account, never the token row's id: {body}"
    );
    assert_eq!(body["email"], "clime@example.com");
}

// ---- auth provider: local vs hanko (DESIGN §7 decision 16) ----
//
// The whole claim of the design is that the provider chooses the FRONT DOOR
// only: past the `opsclaw_session` cookie the two are indistinguishable, and
// every downstream gate (`Authed`, the `ops_` bearer, `token_version`) is
// untouched. These tests drive that through the real router, with a
// wiremock standing in for the Hanko API — same idiom as `http::hanko`'s own
// unit tests, one level up.

/// The `aud` a Hanko token must carry to be accepted by these test apps.
const HANKO_AUDIENCE: &str = "ops.example.com";

/// A hanko-provider config pointed at `api_url`.
///
/// `http.jwt_secret` is set because `Config::validate()` now demands a real
/// one whenever the provider is not local — a fakes-mode daemon whose only
/// configured integration is Hanko still signs REAL operator sessions. A
/// `store:` ref satisfies validate() without touching process env (it is
/// resolved at connect time), and `AppState::fake_with_config` falls back to
/// the dev secret internally, which is self-consistent within one app.
///
/// `validate()` is asserted here, not just assumed: these tests are only
/// worth anything if the config under test is one the daemon would boot.
/// Note it permits the wiremock's `http://` URL solely because a test config
/// is `fully_faked()`.
fn hanko_config(api_url: &str) -> Config {
    let mut cfg = Config::default();
    cfg.auth.provider = opsclaw::config::AuthProvider::Hanko;
    cfg.auth.api_url = Some(api_url.to_string());
    cfg.auth.audience = vec![HANKO_AUDIENCE.into()];
    cfg.http.jwt_secret = Some(opsclaw::config::SecretRef::store("opsclaw-e2e-jwt"));
    cfg.validate().expect("the hanko test config must be one the daemon would boot with");
    cfg
}

/// A stand-in for the Hanko API that validates exactly one subject.
///
/// The body is shaped like Hanko backend 3.0.4's `ValidateSessionResponse`:
/// `claims.subject`/`claims.audience`, NOT the JWT's `sub`/`aud`. Held by
/// the caller for the life of the test — dropping the server unbinds it.
async fn hanko_server(subject: &str) -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/sessions/validate"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "is_valid": true,
            "claims": {
                "subject": subject,
                "expiration": "2026-07-28T21:00:00Z",
                "session_id": "6f1c0e64-0000-4000-8000-00000000ffff",
                "audience": [HANKO_AUDIENCE],
                "amr": ["passkey"],
                "email": { "address": "passkey@example.com", "is_primary": true, "is_verified": true }
            }
        })))
        .mount(&server)
        .await;
    server
}

/// Seed an operator linked to a Hanko identity — the row
/// `opsclaw-cli account create --hanko-subject` writes. No password: the
/// column is NOT NULL, so the `NO_PASSWORD` sentinel stands in for one.
async fn seed_hanko_account(state: &AppState, email: &str, subject: &str) -> Uuid {
    let id = Uuid::new_v4();
    let account = Account {
        id,
        email: email.into(),
        display_name: "Passkey Operator".into(),
        password_hash: opsclaw::http::auth::NO_PASSWORD.into(),
        token_version: 0,
        created_at: chrono::Utc::now(),
        auth_provider: "hanko".into(),
        external_subject: Some(subject.into()),
    };
    AccountRepo::insert(&*state.repos, &account).await.unwrap();
    id
}

/// Mint an open invite directly through the repo — the same bypass
/// `seed_account` uses, for the cases where minting it over HTTP would need
/// a signed-in session the test isn't about.
async fn seed_invite(state: &AppState, issued_by: Uuid) -> String {
    use opsclaw::db::Invite;
    let code = format!("e2e{}", Uuid::new_v4().simple());
    let now = chrono::Utc::now();
    let invite = Invite {
        code: code.clone(),
        issued_by,
        created_at: now,
        expires_at: now + chrono::Duration::days(1),
    };
    state.repos.create_invite(&invite).await.unwrap();
    code
}

/// The login screen cannot render at all until it knows which provider is
/// in front of it, so this route is public by construction — asserted with
/// no cookie anywhere.
#[tokio::test]
async fn auth_config_is_public_and_reports_the_provider() {
    let base = spawn_server(AppState::fake()).await;
    let resp = reqwest::get(format!("{base}/api/auth/config")).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["provider"], "local");
    assert!(body.get("api_url").is_none(), "a local daemon names no identity provider: {body}");

    // Under hanko the browser also learns WHERE to authenticate. The
    // trailing slash is deliberate: `api_base()` trims it, so the widget
    // never builds a `//sessions/...` URL.
    let base =
        spawn_server(AppState::fake_with_config(hanko_config("https://tenant.hanko.io/"))).await;
    let resp = reqwest::get(format!("{base}/api/auth/config")).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["provider"], "hanko");
    assert_eq!(body["api_url"], "https://tenant.hanko.io");
}

/// The provider setting is authoritative, not advisory: an account created
/// before the switch keeps its argon2 hash, and leaving `/api/login` live
/// would leave that password working as a parallel front door. The refusal
/// names hanko on purpose — the downstream symptom of a mis-set provider is
/// a wall of 401s, which needs a legible cause.
#[tokio::test]
async fn password_login_is_refused_under_the_hanko_provider() {
    let state = AppState::fake_with_config(hanko_config("https://tenant.hanko.io"));
    // A REAL, correct password: the refusal must be about the provider, not
    // about the credential.
    seed_account(&state, "legacy@example.com", "some-password-123").await;
    let base = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/api/login"))
        .json(
            &serde_json::json!({ "email": "legacy@example.com", "password": "some-password-123" }),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("hanko"),
        "the refusal must name the provider so the cause is legible: {body}"
    );
}

/// The core claim of the design: after the exchange, a hanko sign-in holds
/// exactly the cookie a password sign-in holds, and the ordinary `Authed`
/// routes serve it without knowing anything about Hanko.
#[tokio::test]
async fn hanko_exchange_mints_the_standard_session_cookie() {
    let subject = "6f1c0e64-0000-4000-8000-000000000001";
    let hanko = hanko_server(subject).await;
    let state = AppState::fake_with_config(hanko_config(&hanko.uri()));
    assert!(state.hanko.is_some(), "the hanko provider must wire a client");
    let account_id = seed_hanko_account(&state, "passkey@example.com", subject).await;
    let base = spawn_server(state).await;

    let client = SessionClient::new();
    let exchanged = client
        .post_json(
            &format!("{base}/api/auth/hanko/exchange"),
            &serde_json::json!({ "session_token": "a-hanko-session-token" }),
        )
        .await;
    assert_eq!(exchanged.status(), reqwest::StatusCode::OK);

    // The SAME cookie the password path sets — HttpOnly (an XSS cannot read
    // it) and SameSite=Strict (no cross-site ride-along).
    let set_cookie = exchanged
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("the exchange must set a session cookie")
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("opsclaw_session="), "{set_cookie}");
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("SameSite=Strict"), "{set_cookie}");
    let body: serde_json::Value = exchanged.json().await.unwrap();
    assert_eq!(body["account_id"], account_id.to_string());

    // …and from here on nothing is hanko-aware: an ordinary `Authed` route
    // resolves the operator from that cookie alone.
    let me = client.get(&format!("{base}/api/me")).await;
    assert_eq!(me.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = me.json().await.unwrap();
    assert_eq!(body["account_id"], account_id.to_string());
    assert_eq!(body["email"], "passkey@example.com");
}

/// No auto-provisioning. A Hanko project can be open to self-registration
/// and this daemon holds cluster credentials, so an identity Hanko
/// authenticates but no `accounts` row claims gets a 401 — and, critically,
/// no new row.
#[tokio::test]
async fn hanko_exchange_with_an_unlinked_subject_is_401() {
    let hanko = hanko_server("6f1c0e64-0000-4000-8000-00000000dead").await;
    let state = AppState::fake_with_config(hanko_config(&hanko.uri()));
    // One EXISTING operator, linked to a different subject: the count below
    // is then a real "nothing was created", not "the table stayed empty".
    seed_hanko_account(&state, "incumbent@example.com", "6f1c0e64-0000-4000-8000-000000000001")
        .await;
    let before = AccountRepo::list(&*state.repos).await.unwrap().len();
    let base = spawn_server(state.clone()).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/api/auth/hanko/exchange"))
        .json(&serde_json::json!({ "session_token": "a-hanko-session-token" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers().get(reqwest::header::SET_COOKIE).is_none(),
        "a refused exchange must not set a session cookie"
    );

    let after = AccountRepo::list(&*state.repos).await.unwrap();
    assert_eq!(after.len(), before, "a verified-but-unlinked identity must not self-provision");
}

/// The remote-CLI hand-off is untouched by the provider change: the web leg
/// is authorized by whatever cookie the front door minted, and the CLI leg
/// never sees the provider at all.
#[tokio::test]
async fn the_cli_pkce_flow_works_under_the_hanko_provider() {
    let subject = "6f1c0e64-0000-4000-8000-000000000042";
    let hanko = hanko_server(subject).await;
    let state = AppState::fake_with_config(hanko_config(&hanko.uri()));
    seed_hanko_account(&state, "hankocli@example.com", subject).await;
    let base = spawn_server(state).await;

    // Sign in through hanko instead of /api/login…
    let web = SessionClient::new();
    let exchanged = web
        .post_json(
            &format!("{base}/api/auth/hanko/exchange"),
            &serde_json::json!({ "session_token": "a-hanko-session-token" }),
        )
        .await;
    assert_eq!(exchanged.status(), reqwest::StatusCode::OK);

    // …and the PKCE round trip runs exactly as it does under local.
    let verifier = "d".repeat(43);
    let challenge = opsclaw::http::cli_auth::challenge_for(&verifier);
    let authorize = web
        .post_json(
            &format!("{base}/api/cli/authorize"),
            &serde_json::json!({ "challenge": challenge, "name": "hanko-host" }),
        )
        .await;
    assert_eq!(authorize.status(), reqwest::StatusCode::OK);
    let authorize: serde_json::Value = authorize.json().await.unwrap();
    let code = authorize["code"].as_str().unwrap().to_string();

    // No cookie: a fresh CLI process, which has never talked to Hanko.
    let exchange: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/cli/v1/auth/token"))
        .json(&serde_json::json!({ "code": code, "verifier": verifier }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = exchange["token"].as_str().expect("a minted CLI token");
    assert!(token.starts_with("ops_"));
    assert_eq!(exchange["email"], "hankocli@example.com");

    let me: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/cli/v1/me"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["email"], "hankocli@example.com");
}

/// `take_invite` is a one-time consume, so anything that can fail AFTER it
/// burns the code and leaves the teammate locked out with nothing to retry.
/// The hanko path added several late failure modes (provider timeout,
/// audience mismatch, an already-linked subject), which is what moved every
/// identity check ahead of the consume. A too-short password is the
/// cheapest way to prove the ordering under the local provider.
#[tokio::test]
async fn a_failed_join_does_not_consume_the_invite() {
    let state = AppState::fake();
    seed_account(&state, "invite-order@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let inviter = login(&base, "invite-order@example.com").await;
    let invite: serde_json::Value =
        inviter.post(&format!("{base}/api/invites")).await.json().await.unwrap();
    let code = invite["code"].as_str().unwrap().to_string();

    let failed = reqwest::Client::new()
        .post(format!("{base}/api/join"))
        .json(&serde_json::json!({
            "code": code,
            "email": "newbie@example.com",
            "password": "short",
            "display_name": "Newbie",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), reqwest::StatusCode::BAD_REQUEST);

    // The SAME code, second attempt, valid this time: it must still work.
    let retry = SessionClient::new();
    let joined = retry
        .post_json(
            &format!("{base}/api/join"),
            &serde_json::json!({
                "code": code,
                "email": "newbie@example.com",
                "password": "a-long-enough-password",
                "display_name": "Newbie",
            }),
        )
        .await;
    assert_eq!(joined.status(), reqwest::StatusCode::OK, "a failed join must not burn the code");
    assert_eq!(
        retry.get(&format!("{base}/api/status")).await.status(),
        reqwest::StatusCode::OK,
        "the retried join signs the teammate in"
    );
}

/// A password sent to a hanko daemon is refused with a message that says
/// what to do instead — never quietly accepted and stored, which would
/// create an account with a working password the provider setting claims is
/// impossible.
#[tokio::test]
async fn join_with_a_password_is_refused_under_hanko() {
    let hanko = hanko_server("6f1c0e64-0000-4000-8000-000000000007").await;
    let state = AppState::fake_with_config(hanko_config(&hanko.uri()));
    let inviter = seed_hanko_account(
        &state,
        "hankoinviter@example.com",
        "6f1c0e64-0000-4000-8000-00000000000a",
    )
    .await;
    let code = seed_invite(&state, inviter).await;
    let base = spawn_server(state.clone()).await;
    let before = AccountRepo::list(&*state.repos).await.unwrap().len();

    let resp = reqwest::Client::new()
        .post(format!("{base}/api/join"))
        .json(&serde_json::json!({
            "code": code,
            "email": "pwjoin@example.com",
            "password": "a-long-enough-password",
            "display_name": "Password Joiner",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap_or("").contains("hanko"), "{body}");
    assert_eq!(AccountRepo::list(&*state.repos).await.unwrap().len(), before);
}

/// The mirror image: a local daemon refuses a session token, and refuses a
/// join carrying no credential at all.
#[tokio::test]
async fn join_without_a_password_is_refused_under_local() {
    let state = AppState::fake();
    seed_account(&state, "localinviter@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let inviter = login(&base, "localinviter@example.com").await;
    let invite: serde_json::Value =
        inviter.post(&format!("{base}/api/invites")).await.json().await.unwrap();
    let code = invite["code"].as_str().unwrap().to_string();

    let with_token = reqwest::Client::new()
        .post(format!("{base}/api/join"))
        .json(&serde_json::json!({
            "code": code,
            "email": "tokenjoin@example.com",
            "display_name": "Token Joiner",
            "session_token": "a-hanko-session-token",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(with_token.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = with_token.json().await.unwrap();
    assert!(body["error"].as_str().unwrap_or("").contains("password"), "{body}");

    // Neither credential: refused too (the field is Option only so the
    // hanko path can deserialize, never so a join can skip the password).
    let with_nothing = reqwest::Client::new()
        .post(format!("{base}/api/join"))
        .json(&serde_json::json!({
            "code": code,
            "email": "nothingjoin@example.com",
            "display_name": "Nothing Joiner",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(with_nothing.status(), reqwest::StatusCode::BAD_REQUEST);

    // Both refusals ran before the consume, so the code is still open.
    let survivor = SessionClient::new();
    let joined = survivor
        .post_json(
            &format!("{base}/api/join"),
            &serde_json::json!({
                "code": code,
                "email": "properjoin@example.com",
                "password": "a-long-enough-password",
                "display_name": "Proper Joiner",
            }),
        )
        .await;
    assert_eq!(joined.status(), reqwest::StatusCode::OK);
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

// ---- status surface (DESIGN §3: heartbeat liveness, per-target scan
// state, e-stop) ----

#[tokio::test]
async fn status_reports_last_tick_and_per_target_scan_state() {
    use opsclaw::db::JobRepo;
    use opsclaw::domain::{Job, Payload, Schedule};

    let state = AppState::fake();
    seed_account(&state, "status@example.com", "some-password-123").await;

    // One seeded-style per-target scan job plus one operator-authored job.
    let scan = Job::new(
        "example::prod::web-1-scan",
        Schedule::Interval { every_minutes: 5 },
        Payload::ScanRoutine {
            routine: "record_scan".into(),
            target: Some(opsclaw::domain::FqTarget::try_new("example", "prod", "web-1").unwrap()),
        },
    )
    .system();
    JobRepo::insert(&*state.repos, &scan).await.unwrap();
    let manual = Job::new(
        "disk-report",
        Schedule::Interval { every_minutes: 60 },
        Payload::Prompt { body: "a possibly sensitive prompt body".into() },
    );
    JobRepo::insert(&*state.repos, &manual).await.unwrap();

    let base = spawn_server(state.clone()).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "status@example.com", "password": "some-password-123" }),
        )
        .await;

    // Before the first tick: booting, last tick unknown.
    let body: serde_json::Value =
        client.get(&format!("{base}/api/status")).await.json().await.unwrap();
    assert_eq!(body["heartbeat"], "booting");
    assert!(body["last_tick_ms"].is_null(), "no tick recorded yet: {body}");
    assert_eq!(body["estop_engaged"], false);

    // The scan-state listing: sorted by name, cadence position per job,
    // payload KIND only — never the prompt body.
    let jobs = body["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0]["name"], "disk-report");
    assert_eq!(jobs[0]["kind"], "prompt");
    assert_eq!(jobs[1]["name"], "example::prod::web-1-scan");
    assert_eq!(jobs[1]["kind"], "scan_routine");
    assert_eq!(jobs[1]["enabled"], true);
    assert_eq!(jobs[1]["system"], true);
    assert!(jobs[1]["next_run_at"].is_string(), "a due schedule has a next run: {body}");
    assert!(jobs[1]["last_run_at"].is_null(), "never fired yet");
    assert!(
        !body.to_string().contains("a possibly sensitive prompt body"),
        "the status surface must never dump a payload body: {body}"
    );

    // After a tick is recorded (the handle's atomics are shared with the
    // served state), last tick surfaces and the heartbeat goes healthy.
    let now = chrono::Utc::now();
    state.scheduler.mark_tick_start(now);
    let body: serde_json::Value =
        client.get(&format!("{base}/api/status")).await.json().await.unwrap();
    assert_eq!(body["heartbeat"], "healthy");
    assert_eq!(body["last_tick_ms"], now.timestamp_millis());
    assert!(body["tick_interval_ms"].is_u64());
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
                "example::prod::web-1",
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

// ---- PagerDuty v3 webhook (signature gate + event-type routing) ----

/// Records every `(source, payload)` the webhook routes hand to the ingest
/// seam — the test double for `http::webhook::IngestAlert`.
struct RecordingIngest {
    calls: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
}

impl RecordingIngest {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(RecordingIngest { calls: std::sync::Mutex::new(Vec::new()) })
    }
    fn calls(&self) -> Vec<(String, serde_json::Value)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl opsclaw::http::webhook::IngestAlert for RecordingIngest {
    async fn ingest(&self, source: &str, payload: &serde_json::Value) -> opsclaw::Result<()> {
        self.calls.lock().unwrap().push((source.to_string(), payload.clone()));
        Ok(())
    }
}

/// A minimal-but-valid PagerDuty v3 webhook envelope for `event_type`.
fn pagerduty_fixture(event_type: &str) -> String {
    serde_json::json!({
        "event": {
            "id": "01BRB6ZP4M6T8ZG4X6BP63ZB9O",
            "event_type": event_type,
            "resource_type": "incident",
            "occurred_at": "2026-07-22T09:00:00.000Z",
            "agent": { "type": "user_reference", "id": "PUSER01" },
            "data": {
                "id": "PINC123",
                "type": "incident",
                "title": "High error rate on web-1",
                "status": "triggered",
                "urgency": "high",
                "service": { "id": "PSVC01", "summary": "example prod" }
            }
        }
    })
    .to_string()
}

/// A fake state with a live webhook secret and a recording ingest sink.
fn pagerduty_state(secret: &str) -> (AppState, std::sync::Arc<RecordingIngest>) {
    let mut state = AppState::fake();
    state.webhook_secret = Some(std::sync::Arc::from(secret));
    let ingest = RecordingIngest::new();
    state.ingest = ingest.clone();
    (state, ingest)
}

#[tokio::test]
async fn pagerduty_triggered_event_with_a_valid_signature_reaches_ingest() {
    let (state, ingest) = pagerduty_state("pd-secret");
    let base = spawn_server(state).await;

    let body = pagerduty_fixture("incident.triggered");
    let sig = opsclaw::http::webhook::pagerduty_sign(b"pd-secret", body.as_bytes());
    let resp = reqwest::Client::new()
        .post(format!("{base}/webhooks/pagerduty"))
        .header("x-pagerduty-signature", sig)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let calls = ingest.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "pagerduty");
    assert_eq!(calls[0].1["event"]["event_type"], "incident.triggered");
    assert_eq!(calls[0].1["event"]["data"]["title"], "High error rate on web-1");
}

#[tokio::test]
async fn pagerduty_resolved_event_with_a_valid_signature_reaches_ingest() {
    let (state, ingest) = pagerduty_state("pd-secret");
    let base = spawn_server(state).await;

    let body = pagerduty_fixture("incident.resolved");
    let sig = opsclaw::http::webhook::pagerduty_sign(b"pd-secret", body.as_bytes());
    let resp = reqwest::Client::new()
        .post(format!("{base}/webhooks/pagerduty"))
        .header("x-pagerduty-signature", sig)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(ingest.calls().len(), 1);
}

#[tokio::test]
async fn pagerduty_bad_signature_is_rejected_and_nothing_is_ingested() {
    let (state, ingest) = pagerduty_state("pd-secret");
    let base = spawn_server(state).await;

    let body = pagerduty_fixture("incident.triggered");
    // Signed with the WRONG secret — a valid-shaped but unverifiable header.
    let sig = opsclaw::http::webhook::pagerduty_sign(b"not-the-secret", body.as_bytes());
    let resp = reqwest::Client::new()
        .post(format!("{base}/webhooks/pagerduty"))
        .header("x-pagerduty-signature", sig)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(ingest.calls().is_empty(), "a rejected delivery must never reach ingest");
}

#[tokio::test]
async fn pagerduty_missing_signature_header_is_rejected() {
    let (state, ingest) = pagerduty_state("pd-secret");
    let base = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/webhooks/pagerduty"))
        .body(pagerduty_fixture("incident.triggered"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(ingest.calls().is_empty());
}

#[tokio::test]
async fn pagerduty_unknown_event_type_is_ignored_with_204() {
    let (state, ingest) = pagerduty_state("pd-secret");
    let base = spawn_server(state).await;

    // `pagey.ping` is PagerDuty's own subscription test event — verified,
    // then dropped, never an error on PagerDuty's side.
    for event_type in ["pagey.ping", "incident.annotated"] {
        let body = pagerduty_fixture(event_type);
        let sig = opsclaw::http::webhook::pagerduty_sign(b"pd-secret", body.as_bytes());
        let resp = reqwest::Client::new()
            .post(format!("{base}/webhooks/pagerduty"))
            .header("x-pagerduty-signature", sig)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT, "{event_type}");
    }
    assert!(ingest.calls().is_empty(), "ignored event types must never reach ingest");
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

/// A fake state whose `config_path` points inside a caller-held tempdir —
/// the seam every config-writing route goes through (`AppState.config_path`,
/// injected at boot; see that field's doc for the incident that made it a
/// hard rule: an earlier version of the write route resolved
/// `config::default_dir()` itself and a test run overwrote the developer's
/// real `~/.opsclaw/config.toml`, which held unencrypted SSH keys). With
/// the path injected per-test there is no process-global `$OPSCLAW_HOME`
/// to serialize on, so these tests run fully parallel like the rest of the
/// suite.
fn state_with_config_dir(config: Config) -> (AppState, tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir for config writes");
    let path = dir.path().join("config.toml");
    let mut state = AppState::fake_with_config(config);
    state.config_path = path.clone();
    (state, dir, path)
}

async fn login(base: &str, email: &str) -> SessionClient {
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": email, "password": "some-password-123" }),
        )
        .await;
    client
}

#[tokio::test]
async fn config_surface_round_trips_read_then_validated_write() {
    let (state, _dir, path) = state_with_config_dir(Config::default());
    seed_account(&state, "config@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = login(&base, "config@example.com").await;

    let got: serde_json::Value =
        client.get(&format!("{base}/api/config")).await.json().await.unwrap();
    let toml_text = got["toml"].as_str().expect("toml field").to_string();
    // The read-back text must itself parse as valid opsclaw config — the
    // settings tab's textarea is seeded with exactly this. The structured
    // JSON view rides alongside for the escalation/policy/autonomy editors.
    let _: opsclaw::config::Config =
        toml::from_str(&toml_text).expect("round-tripped config must parse");
    assert!(got["config"].is_object(), "structured JSON view present");

    let saved = client
        .post_json(&format!("{base}/api/config"), &serde_json::json!({ "toml": toml_text }))
        .await;
    assert_eq!(saved.status(), reqwest::StatusCode::OK);
    let saved_body: serde_json::Value = saved.json().await.unwrap();
    assert_eq!(saved_body["ok"], true);

    // The write landed at the INJECTED path (never a real ~/.opsclaw)…
    assert_eq!(std::fs::read_to_string(&path).unwrap(), toml_text);

    // …and a second save keeps a .bak of what it replaced — the recovery
    // path for a valid-but-wrong save.
    let edited = format!("{toml_text}\n# an operator comment\n");
    let resaved = client
        .post_json(&format!("{base}/api/config"), &serde_json::json!({ "toml": edited }))
        .await;
    assert_eq!(resaved.status(), reqwest::StatusCode::OK);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    assert_eq!(
        std::fs::read_to_string(path.with_extension("toml.bak")).unwrap(),
        toml_text,
        "the previous contents survive as config.toml.bak"
    );
}

#[tokio::test]
async fn config_surface_rejects_invalid_toml_and_invalid_config() {
    let (state, _dir, path) = state_with_config_dir(Config::default());
    seed_account(&state, "badconfig@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = login(&base, "badconfig@example.com").await;

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
    // Refusal means untouched: neither rejected body ever reached disk.
    assert!(!path.exists(), "no config file may appear from a refused write");
}

#[tokio::test]
async fn config_read_never_contains_secret_values() {
    // The config holds SecretRefs (names) by construction, so no resolved
    // value can appear in either the TOML or JSON view — this pins that
    // property at the HTTP boundary, where a regression would actually
    // leak to a browser.
    let sentinel = "s3cr3t-value-e2e-xyzzy";
    unsafe { std::env::set_var("OPSCLAW_E2E_SECRET_XYZZY", sentinel) };
    let mut cfg = Config::default();
    cfg.llm.api_key = Some(opsclaw::config::SecretRef::env("OPSCLAW_E2E_SECRET_XYZZY"));
    cfg.llm.models = vec!["some/model".into()];
    cfg.telegram.bot_token = Some(opsclaw::config::SecretRef::store("tg-bot-token"));
    let (state, _dir, _path) = state_with_config_dir(cfg);
    seed_account(&state, "redact@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = login(&base, "redact@example.com").await;

    let resp = client.get(&format!("{base}/api/config")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(!body.contains(sentinel), "secret VALUE must never appear in a config response");
    // The reference NAMES are the point of the surface — they must appear.
    assert!(body.contains("OPSCLAW_E2E_SECRET_XYZZY"), "env ref name shown");
    assert!(body.contains("store:tg-bot-token"), "store ref shown in reference form");
}

/// Seed an on-disk config the structured-edit routes can mutate: one
/// project with one env and one local target (local needs no credential,
/// so the whole thing passes `validate()`).
const EDITABLE_SEED: &str = r#"
[[project]]
name = "example"
[[project.env]]
name = "prod"
[[project.env.target]]
name = "web-1"
kind = "local"
"#;

#[tokio::test]
async fn config_edit_rejects_invalid_and_leaves_the_file_untouched() {
    let (state, _dir, path) = state_with_config_dir(Config::default());
    std::fs::write(&path, EDITABLE_SEED).unwrap();
    seed_account(&state, "editreject@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = login(&base, "editreject@example.com").await;
    let cookie = client.cookie.lock().unwrap().clone().unwrap();

    // An empty policy entry matches EVERYTHING — `Config::validate()`
    // refuses it, and the refusal must carry the message and leave the
    // file byte-identical.
    let resp = client
        .client
        .put(format!("{base}/api/config/policy"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({ "auto_approve": [""] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("empty entry"),
        "the validation message reaches the caller: {body}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), EDITABLE_SEED, "file untouched");

    // A structurally-bad escalation chain is refused the same way.
    let resp = client
        .client
        .put(format!("{base}/api/config/escalation"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "project": "example",
            "steps": [{ "contact": "web", "ack_timeout_minutes": 10, "repeat_interval_minutes": 10 }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), EDITABLE_SEED, "file untouched");
}

#[tokio::test]
async fn config_edit_autonomy_requires_confirm_auto() {
    let (state, _dir, path) = state_with_config_dir(Config::default());
    std::fs::write(&path, EDITABLE_SEED).unwrap();
    seed_account(&state, "autonomy@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = login(&base, "autonomy@example.com").await;
    let cookie = client.cookie.lock().unwrap().clone().unwrap();

    // Promotion to "auto" without the explicit confirmation: refused, file
    // untouched — the fat-finger guard.
    let resp = client
        .client
        .put(format!("{base}/api/config/autonomy"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({ "project": "example", "env": "prod", "autonomy": "auto" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("confirm_auto"), "{body}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), EDITABLE_SEED);

    // With confirm_auto: true the same edit lands.
    let resp = client
        .client
        .put(format!("{base}/api/config/autonomy"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "project": "example", "env": "prod", "autonomy": "auto", "confirm_auto": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let written: opsclaw::config::Config =
        toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(written.autonomy_for("example", "prod", "web-1"), opsclaw::domain::Autonomy::Auto);

    // A NON-auto edit needs no confirmation; an unknown node is a 400.
    let resp = client
        .client
        .put(format!("{base}/api/config/autonomy"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({ "project": "example", "autonomy": "observe" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp = client
        .client
        .put(format!("{base}/api/config/autonomy"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({ "project": "nope", "autonomy": "observe" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn config_edit_escalation_chain_round_trips() {
    let (state, _dir, path) = state_with_config_dir(Config::default());
    std::fs::write(&path, EDITABLE_SEED).unwrap();
    seed_account(&state, "escedit@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = login(&base, "escedit@example.com").await;
    let cookie = client.cookie.lock().unwrap().clone().unwrap();

    // Set the GLOBAL chain (project absent)…
    let resp = client
        .client
        .put(format!("{base}/api/config/escalation"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "steps": [{ "contact": "telegram", "ack_timeout_minutes": 30, "repeat_interval_minutes": 10 }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // …then a per-project override for "example".
    let resp = client
        .client
        .put(format!("{base}/api/config/escalation"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "project": "example",
            "steps": [{ "contact": "web", "ack_timeout_minutes": 15, "repeat_interval_minutes": 5 }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // The file round-trips both, and the resolver honours the inheritance:
    // example pages its own chain, an undeclared project the global one.
    let written: opsclaw::config::Config =
        toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    written.validate().unwrap();
    assert_eq!(written.escalation_chain_for("example").steps[0].contact, "web");
    assert_eq!(written.escalation_chain_for("other").steps[0].contact, "telegram");

    // An empty steps list for a project REMOVES the override (back to
    // inheriting) — never persists the declared-empty shape validate()
    // refuses.
    let resp = client
        .client
        .put(format!("{base}/api/config/escalation"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({ "project": "example", "steps": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let written: opsclaw::config::Config =
        toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(written.projects[0].escalation.is_none());
    assert_eq!(written.escalation_chain_for("example").steps[0].contact, "telegram");

    // Editing an unknown project's chain is a 400, not a silent create —
    // project intake stays wizard-only.
    let resp = client
        .client
        .put(format!("{base}/api/config/escalation"))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "project": "ghost",
            "steps": [{ "contact": "web", "ack_timeout_minutes": 15, "repeat_interval_minutes": 5 }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
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

// ---- web chat ----

/// A canned [`ChatHandler`] for the success-path test: echoes back a fixed
/// reply and records the last `(principal, speaker, message)` it was
/// called with, so the test can assert what the route actually handed the
/// chat seam — never trusting an inner `Ok(())`/200 alone to prove the
/// right thing happened.
struct FakeChat {
    reply: String,
    calls: std::sync::Mutex<Vec<(Principal, String, String)>>,
}

impl FakeChat {
    fn new(reply: &str) -> Self {
        FakeChat { reply: reply.to_string(), calls: std::sync::Mutex::new(Vec::new()) }
    }
}

#[async_trait::async_trait]
impl ChatHandler for FakeChat {
    async fn chat(
        &self,
        principal: Principal,
        speaker: &str,
        message: &str,
    ) -> opsclaw::Result<String> {
        self.calls.lock().unwrap().push((principal, speaker.to_string(), message.to_string()));
        Ok(self.reply.clone())
    }
}

#[tokio::test]
async fn chat_without_a_session_is_rejected_with_401() {
    let state = AppState::fake();
    let base = spawn_server(state).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/chat"))
        .json(&serde_json::json!({ "message": "hello" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let resp = reqwest::get(format!("{base}/api/chat/history")).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn chat_on_the_fakes_spine_503s_with_a_clear_body_not_a_500() {
    // AppState::fake()'s `chat` field is the boot-safe NoopChat default
    // (never a real agent loop in fakes mode) — the route must surface
    // that as 503 with an explanatory body, not a masked 500.
    let state = AppState::fake();
    seed_account(&state, "chat-noop@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "chat-noop@example.com", "password": "some-password-123" }),
        )
        .await;

    let request = serde_json::json!({
        "message": "hi",
        "idempotency_key": "failed-request",
    });
    let resp = client.post_json(&format!("{base}/api/chat"), &request).await;
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("chat is not wired"),
        "expected a clear 'not wired' message, got: {body}"
    );

    let replay = client.post_json(&format!("{base}/api/chat"), &request).await;
    assert_eq!(replay.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = replay.json().await.unwrap();
    assert!(body["error"].as_str().unwrap_or("").contains("cannot be replayed safely"));
}

#[tokio::test]
async fn chat_history_on_the_fakes_spine_is_empty_not_an_error() {
    let state = AppState::fake();
    seed_account(&state, "chat-hist-noop@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "chat-hist-noop@example.com", "password": "some-password-123" }),
        )
        .await;

    let resp = client.get(&format!("{base}/api/chat/history")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["history"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_successful_chat_turn_returns_the_reply_through_the_authed_seam() {
    let mut state = AppState::fake();
    let fake = std::sync::Arc::new(FakeChat::new("42 is the answer"));
    state.chat = fake.clone();
    let account_id = seed_account(&state, "chatter@example.com", "some-password-123").await;

    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "chatter@example.com", "password": "some-password-123" }),
        )
        .await;

    let resp = client
        .post_json(&format!("{base}/api/chat"), &serde_json::json!({ "message": "what is 6*7?" }))
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["reply"], "42 is the answer");

    // The chat seam saw the authed operator's principal, display name, and
    // exact message — not some placeholder.
    {
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (principal, speaker, message) = &calls[0];
        assert!(matches!(principal, Principal::Operator { account } if *account == account_id));
        assert_eq!(speaker, "Test Operator"); // seed_account's display_name
        assert_eq!(message, "what is 6*7?");
    }

    // NOT asserted here: the SSE broadcast. Publishing both sides of the
    // exchange (plus live tool events) is `ChatTurn`'s own responsibility
    // now — moved INTO the handler so a Telegram/CLI-originated turn
    // reaches web tabs identically — so a fake handler publishes nothing,
    // and asserting it here would mean teaching the fake to imitate the
    // real broadcast (a test of the fixture, not the product). The real
    // path is pinned by `agent::dispatch`'s
    // `chat_turn_persists_the_durable_log_streams_tools_and_hydrates`,
    // which drives a real ChatTurn against a real hub.
}

#[tokio::test]
async fn repeated_chat_idempotency_key_runs_the_turn_once() {
    let mut state = AppState::fake();
    let fake = std::sync::Arc::new(FakeChat::new("done"));
    state.chat = fake.clone();
    seed_account(&state, "dedupe@example.com", "some-password-123").await;
    let base = spawn_server(state).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "dedupe@example.com", "password": "some-password-123" }),
        )
        .await;
    let request = serde_json::json!({ "message": "run once", "idempotency_key": "same-request" });
    let first: serde_json::Value =
        client.post_json(&format!("{base}/api/chat"), &request).await.json().await.unwrap();
    let second: serde_json::Value =
        client.post_json(&format!("{base}/api/chat"), &request).await.json().await.unwrap();
    assert_eq!(first["duplicate"], false);
    assert_eq!(second["duplicate"], true);
    assert_eq!(second["reply"], "done");
    assert_eq!(fake.calls.lock().unwrap().len(), 1);
}
