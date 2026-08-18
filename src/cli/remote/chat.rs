//! `opsclaw-cli chat` in REMOTE mode: one-shot (`chat <message>`) or a REPL
//! (`chat` with no message) against the gateway's chat route.
//!
//! Built against the CONTRACT stated for this wave (the route lands from a
//! gateway): `POST /cli/v1/chat`, bearer-authed, body
//! `{"message": "...", "idempotency_key": "..."}`, response
//! `{"reply": "..."}`. If the deployed
//! gateway's route differs, every call here fails with the gateway's own
//! error body surfaced verbatim (`remote::client::post_json`), never a
//! silent misparse.
//!
//! The REPL loop itself is intentionally NOT shared code with
//! `cli::chat_repl` (the local REPL): the two have different failure modes
//! (local: an in-process `Result`; remote: an HTTP round-trip that can also
//! fail on the network itself) and different exit-drain needs (local drains
//! an in-process `Memory`; remote has nothing to drain — the gateway's own
//! process owns that). Sharing a loop abstraction over both would need a
//! trait boundary that buys nothing here — two ~15-line loops are more
//! honest than one indirected one.

use std::io::Write;

use crate::Result;
use crate::cli::remote::client;
use crate::cli::remote::session::Session;

async fn send(session: &Session, message: &str) -> Result<String> {
    let body = client::post_json(
        session,
        "/cli/v1/chat",
        &serde_json::json!({
            "message": message,
            "idempotency_key": uuid::Uuid::new_v4().to_string(),
        }),
    )
    .await?;
    body["reply"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| crate::Error::other("malformed chat response (no `reply` field)"))
}

/// `opsclaw-cli chat <message>` — one-shot: send, print the reply, exit.
pub async fn one_shot(session: &Session, message: &str) -> Result<String> {
    let reply = send(session, message).await?;
    println!("{reply}");
    Ok(reply)
}

/// `opsclaw-cli chat` (no message) — a REPL over the same route. Ctrl-D or
/// `exit`/`quit` ends it; each line is its own independent `/api/chat`
/// call (the gateway's `ChatTurn` owns conversational history server-side —
/// see `agent::dispatch::ChatTurn`'s shared transcript — so the REPL itself
/// carries no client-side history to replay).
pub async fn repl(session: &Session) -> Result<()> {
    println!("opsclaw remote chat ({}) — Ctrl-D or 'exit' to quit", session.server);
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        print!("> ");
        std::io::stdout().flush().ok();
        line.clear();
        let n = stdin.read_line(&mut line).map_err(|e| crate::Error::other(e.to_string()))?;
        if n == 0 {
            println!();
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "exit" | "quit") {
            break;
        }
        match send(session, trimmed).await {
            Ok(reply) => println!("{reply}"),
            Err(e) => println!("error: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(server: String) -> Session {
        Session { server, token: "ops_test".into() }
    }

    #[tokio::test]
    async fn one_shot_sends_the_message_and_returns_the_reply() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/cli/v1/chat"))
            .and(wiremock::matchers::header("authorization", "Bearer ops_test"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "reply": "yes, all green" })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        let reply = one_shot(&session, "is prod healthy?").await.unwrap();
        assert_eq!(reply, "yes, all green");
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["message"], "is prod healthy?");
        assert!(uuid::Uuid::parse_str(body["idempotency_key"].as_str().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn a_malformed_response_is_a_clear_error_not_a_panic() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/cli/v1/chat"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "unexpected": "shape" })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        let err = one_shot(&session, "hi").await.unwrap_err();
        assert!(err.to_string().contains("reply"), "{err}");
    }

    #[tokio::test]
    async fn gateway_error_is_surfaced() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/cli/v1/chat"))
            .respond_with(
                wiremock::ResponseTemplate::new(503).set_body_json(
                    serde_json::json!({ "error": "chat is not wired on this state" }),
                ),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        let err = one_shot(&session, "hi").await.unwrap_err();
        assert!(err.to_string().contains("chat is not wired"), "{err}");
    }
}
