//! `opsclaw-cli login` / `logout` — the PKCE browser hand-off against a
//! gateway's `/api/cli/authorize` + `/cli/v1/auth/token` (`http::routes::cli`,
//! itself ported from gianna's `src/cli_auth.rs`/`http/cli_api.rs`).
//!
//! Flow (mirrors `http::cli_auth`'s own doc comment exactly — this is the
//! CLI-side other half of it):
//! 1. Generate a random `verifier`, derive `challenge = sha256(verifier)`.
//! 2. Print (and try to open) `{server}/cli-auth?challenge=...` — a page
//!    the WEB UI serves, where the operator is (or becomes) signed in and
//!    approves, minting a one-time code.
//! 3. The operator pastes that code back into this terminal.
//! 4. Exchange `code + verifier` at `POST /cli/v1/auth/token`; the gateway
//!    re-derives the challenge, so a code intercepted in flight is useless
//!    without the verifier, which never left this process.
//!
//! Deliberately the PASTE flow only (gianna's `--no-browser` path), not a
//! loopback-listener redirect: `DESIGN.md`'s brief for this wave asks for
//! "small and honest", and a operator-facing paste is one code path instead
//! of two (loopback + paste) with identical security properties — the
//! loopback listener is a convenience gianna's web-facing product justifies
//! for its consumer users; opsclaw's audience is operators already
//! comfortable pasting a code from a browser tab into a terminal (the same
//! motion `gh auth login`/`doctl auth init` use). If a smoother hand-off is
//! wanted later, that is a deliberate follow-up, not something to grow here
//! silently.
//!
//! `/cli-auth` itself (the browser-side page that calls `/api/cli/authorize`
//! and shows the resulting code) is a WEB UI concern, not built by this
//! wave — if it doesn't exist yet in a given gateway build, `login --paste`
//! (below) lets an operator drive the same exchange by hand from `curl`/the
//! browser devtools, so `login` is never the ONLY way in.

use std::io::Write;

use serde_json::Value;

use crate::Result;
use crate::cli::remote::session::{self, Session};
use crate::http::cli_auth;

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "opsclaw-cli".to_string())
}

/// Best-effort `xdg-open`/`open`/`start` — mirrors `cli::ui_cmd::open_url`
/// (same three-OS dispatch; kept as a separate copy here rather than a
/// shared helper because the two callers want different failure handling:
/// `ui` treats "couldn't open" as the whole command's result, `login` treats
/// it as a footnote next to a URL it prints regardless).
fn try_open_browser(url: &str) -> bool {
    crate::cli::ui_cmd::open_url(url).is_ok()
}

fn prompt(text: &str) -> Result<String> {
    print!("{text}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| crate::Error::other(e.to_string()))?;
    let line = line.trim().to_string();
    if line.is_empty() {
        return Err(crate::Error::validation("no code entered"));
    }
    Ok(line)
}

/// Everything `login` needs from the outside world besides the HTTP calls
/// themselves — swappable in tests so the paste step doesn't need a real
/// TTY and the browser step doesn't need a real display.
pub trait LoginIo {
    fn say(&mut self, line: &str);
    fn open_browser(&mut self, url: &str) -> bool;
    fn read_code(&mut self) -> Result<String>;
}

pub struct RealLoginIo;

impl LoginIo for RealLoginIo {
    fn say(&mut self, line: &str) {
        println!("{line}");
    }
    fn open_browser(&mut self, url: &str) -> bool {
        try_open_browser(url)
    }
    fn read_code(&mut self) -> Result<String> {
        prompt("Paste the code shown after authorizing: ")
    }
}

/// `opsclaw-cli login --remote <server>`: run the PKCE hand-off and save
/// the resulting session. `server` is normalised (trailing slash trimmed)
/// before use and before being persisted, so every later remote call can
/// blindly concatenate a path onto it.
pub async fn login(server: &str, io: &mut dyn LoginIo) -> Result<Session> {
    let server = server.trim_end_matches('/').to_string();
    let verifier = cli_auth::generate_verifier();
    let challenge = cli_auth::challenge_for(&verifier);
    let name: String = hostname()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(80)
        .collect();

    let url = format!("{server}/cli-auth?challenge={challenge}&name={name}");
    if io.open_browser(&url) {
        io.say("Authorize this terminal in the browser tab that just opened.");
    }
    io.say(&format!("(If nothing opened, or you're signed out there, use this URL:\n  {url})\n"));
    let code = io.read_code()?;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{server}/cli/v1/auth/token"))
        .json(&serde_json::json!({ "code": code.trim(), "verifier": verifier }))
        .send()
        .await
        .map_err(|e| crate::Error::other(format!("could not reach {server}: {e}")))?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(crate::Error::other(format!(
            "login failed ({status}): {}",
            body["error"].as_str().unwrap_or("unexpected response")
        )));
    }
    let token = body["token"]
        .as_str()
        .ok_or_else(|| crate::Error::other("malformed exchange response (no token)"))?;

    let session = Session { server: server.clone(), token: token.to_string() };
    let path = session::save(&session)?;
    io.say(&format!("\nSigned in as {}.", body["email"].as_str().unwrap_or("?")));
    io.say(&format!(
        "Session saved to {} — revoke it any time with `opsclaw-cli logout`.",
        path.display()
    ));
    Ok(session)
}

#[derive(Debug, Default)]
pub struct LogoutOutcome {
    pub had_session: bool,
    pub server_revoked: bool,
}

/// `opsclaw-cli logout`: best-effort server-side revocation (`DELETE
/// /cli/v1/token`) first, then delete the local file regardless — a token
/// the server has already forgotten (network down, gateway restarted with a
/// fresh DB) must not leave a stale, un-revocable file sitting around
/// looking valid.
pub async fn logout() -> Result<LogoutOutcome> {
    let Some(session) = session::load() else {
        return Ok(LogoutOutcome { had_session: false, server_revoked: false });
    };
    let server_revoked = reqwest::Client::new()
        .delete(format!("{}/cli/v1/token", session.server))
        .bearer_auth(&session.token)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    session::clear()?;
    Ok(LogoutOutcome { had_session: true, server_revoked })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ScriptedIo {
        codes: VecDeque<String>,
        said: Vec<String>,
        opened: Vec<String>,
    }

    impl ScriptedIo {
        fn new(codes: impl IntoIterator<Item = &'static str>) -> Self {
            ScriptedIo {
                codes: codes.into_iter().map(String::from).collect(),
                said: Vec::new(),
                opened: Vec::new(),
            }
        }
    }

    impl LoginIo for ScriptedIo {
        fn say(&mut self, line: &str) {
            self.said.push(line.to_string());
        }
        fn open_browser(&mut self, url: &str) -> bool {
            self.opened.push(url.to_string());
            false // pretend headless: exercises the "nothing opened" narration too
        }
        fn read_code(&mut self) -> Result<String> {
            self.codes.pop_front().ok_or_else(|| crate::Error::validation("no code scripted"))
        }
    }

    #[tokio::test]
    async fn login_exchanges_the_pasted_code_and_saves_the_session() {
        let _g = session::ENV_LOCK.lock().await;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/cli/v1/auth/token"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "ops_test_token_123",
                "email": "op@example.com",
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("OPSCLAW_CLI_HOME", dir.path()) };

        let mut io = ScriptedIo::new(["the-pasted-code"]);
        let session = login(&server.uri(), &mut io).await.unwrap();
        assert_eq!(session.token, "ops_test_token_123");
        assert_eq!(session.server, server.uri());

        let loaded = session::load().unwrap();
        assert_eq!(loaded, session);
        assert!(io.said.iter().any(|l| l.contains("Signed in as op@example.com")));
        assert_eq!(io.opened.len(), 1, "the authorize URL must have been offered to open_browser");

        unsafe { std::env::remove_var("OPSCLAW_CLI_HOME") };
    }

    #[tokio::test]
    async fn login_surfaces_the_gateways_error_message() {
        let _g = session::ENV_LOCK.lock().await;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/cli/v1/auth/token"))
            .respond_with(wiremock::ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid or expired authorization code",
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("OPSCLAW_CLI_HOME", dir.path()) };

        let mut io = ScriptedIo::new(["a-bad-code"]);
        let err = login(&server.uri(), &mut io).await.unwrap_err();
        assert!(err.to_string().contains("invalid or expired authorization code"), "{err}");

        unsafe { std::env::remove_var("OPSCLAW_CLI_HOME") };
    }

    #[tokio::test]
    async fn logout_with_no_session_is_a_clean_noop() {
        let _g = session::ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("OPSCLAW_CLI_HOME", dir.path()) };
        let outcome = logout().await.unwrap();
        assert!(!outcome.had_session);
        unsafe { std::env::remove_var("OPSCLAW_CLI_HOME") };
    }

    #[tokio::test]
    async fn logout_revokes_on_the_server_then_deletes_the_local_file() {
        let _g = session::ENV_LOCK.lock().await;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("DELETE"))
            .and(wiremock::matchers::path("/cli/v1/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "ok": true })),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("OPSCLAW_CLI_HOME", dir.path()) };
        session::save(&Session { server: server.uri(), token: "ops_whatever".into() }).unwrap();

        let outcome = logout().await.unwrap();
        assert!(outcome.had_session);
        assert!(outcome.server_revoked);
        assert!(session::load().is_none());

        unsafe { std::env::remove_var("OPSCLAW_CLI_HOME") };
    }
}
