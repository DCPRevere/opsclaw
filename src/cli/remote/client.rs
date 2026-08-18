//! Shared HTTP plumbing for every remote-CLI command: attach the saved
//! bearer token, surface the gateway's own `{"error": "..."}` body on a
//! non-2xx response (gianna's `remote/mod.rs::api_get` pattern, generalised
//! to GET/POST/DELETE since opsclaw's remote command set needs all three —
//! gianna's remote surface was read-only).
//!
//! Every function here takes a `&Session` rather than loading one itself,
//! so callers (`bin/cli/main.rs`'s dispatch) load it once, decide "not
//! logged in" themselves with a consistent message, and every command
//! function in this module is testable against a `wiremock::MockServer`
//! without touching `~/.opsclaw/cli.toml` at all.

use serde_json::Value;

use crate::Result;
use crate::cli::remote::session::Session;

fn no_session_error() -> crate::Error {
    crate::Error::validation(
        "remote mode needs gateway credentials — sign in from a workstation with browser \
         access using `opsclaw-cli login --remote <gateway-url>`, or set \
         OPSCLAW_TOKEN/OPSCLAW_SERVER; omit --remote when this command supports local mode",
    )
}

/// Load the saved session or fail with the standard "please log in first"
/// message every remote command wants — kept here (not duplicated at every
/// call site) so that message never drifts.
pub fn require_session() -> Result<Session> {
    crate::cli::remote::session::load().ok_or_else(no_session_error)
}

async fn handle_response(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        Ok(body)
    } else if status == reqwest::StatusCode::UNAUTHORIZED {
        Err(crate::Error::unauthorized(format!(
            "{} — run `opsclaw-cli login --remote <gateway-url>` again",
            body["error"].as_str().unwrap_or("session rejected")
        )))
    } else {
        Err(crate::Error::other(format!(
            "request failed ({status}): {}",
            body["error"].as_str().unwrap_or("unexpected response")
        )))
    }
}

pub async fn get(session: &Session, path: &str) -> Result<Value> {
    let resp = reqwest::Client::new()
        .get(format!("{}{path}", session.server))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| crate::Error::other(format!("could not reach {}: {e}", session.server)))?;
    handle_response(resp).await
}

pub async fn post_json(session: &Session, path: &str, body: &Value) -> Result<Value> {
    let resp = reqwest::Client::new()
        .post(format!("{}{path}", session.server))
        .bearer_auth(&session.token)
        .json(body)
        .send()
        .await
        .map_err(|e| crate::Error::other(format!("could not reach {}: {e}", session.server)))?;
    handle_response(resp).await
}

pub async fn post(session: &Session, path: &str) -> Result<Value> {
    post_json(session, path, &Value::Null).await
}

pub async fn delete(session: &Session, path: &str) -> Result<Value> {
    let resp = reqwest::Client::new()
        .delete(format!("{}{path}", session.server))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| crate::Error::other(format!("could not reach {}: {e}", session.server)))?;
    handle_response(resp).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(server: String) -> Session {
        Session { server, token: "ops_test".into() }
    }

    #[tokio::test]
    async fn get_returns_the_json_body_on_success() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/cli/v1/status"))
            .and(wiremock::matchers::header("authorization", "Bearer ops_test"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "heartbeat": "ok" })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        let body = get(&session, "/cli/v1/status").await.unwrap();
        assert_eq!(body["heartbeat"], "ok");
    }

    #[tokio::test]
    async fn a_401_surfaces_a_relogin_hint() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/cli/v1/status"))
            .respond_with(
                wiremock::ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({ "error": "token revoked" })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        let err = get(&session, "/cli/v1/status").await.unwrap_err();
        assert!(err.to_string().contains("token revoked"), "{err}");
        assert!(err.to_string().contains("login"), "{err}");
    }

    #[tokio::test]
    async fn post_json_sends_the_body_and_bearer() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/chat"))
            .and(wiremock::matchers::body_json(serde_json::json!({ "message": "status?" })))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "reply": "all green" })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        let body = post_json(&session, "/api/chat", &serde_json::json!({ "message": "status?" }))
            .await
            .unwrap();
        assert_eq!(body["reply"], "all green");
    }

    #[tokio::test]
    async fn a_500_surfaces_the_status_and_error_body() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/approvals/00000000-0000-0000-0000-000000000000/approve",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(500)
                    .set_body_json(serde_json::json!({ "error": "boom" })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        let err = post(&session, "/api/approvals/00000000-0000-0000-0000-000000000000/approve")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"), "{err}");
        assert!(err.to_string().contains("boom"), "{err}");
    }

    #[test]
    fn require_session_errors_clearly_with_no_env_and_no_file() {
        // See `session::ENV_LOCK`'s doc: this test both reads and CLEARS
        // `OPSCLAW_TOKEN` (process-global), so it must be serialized against
        // every other test touching that same env var, not just the ones
        // touching `OPSCLAW_CLI_HOME`.
        // `#[test]`, not `#[tokio::test]` — no runtime, so the blocking
        // variant is required (and safe: nothing else on this thread is
        // driving async work that a blocking lock could starve).
        let _g = crate::cli::remote::session::ENV_LOCK.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("OPSCLAW_CLI_HOME", dir.path()) };
        unsafe { std::env::remove_var("OPSCLAW_TOKEN") };
        let err = require_session().unwrap_err();
        assert!(err.to_string().contains("login"), "{err}");
        unsafe { std::env::remove_var("OPSCLAW_CLI_HOME") };
    }
}
