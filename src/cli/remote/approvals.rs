//! `opsclaw-cli approve <id>` / `deny <id>` — over `POST
//! /api/approvals/{id}/approve|deny` (`http::routes::approvals`). These
//! routes are `Authed`-gated (session cookie, historically) rather than
//! `/cli/v1/*` bearer-gated; reaching them from the remote CLI required the
//! gateway-side change this wave made to `http::handlers::authenticate` —
//! see that function's doc comment — so an `ops_` token now satisfies
//! `Authed` exactly like a signed-in web session does.

use uuid::Uuid;

use crate::Result;
use crate::cli::output::print_json;
use crate::cli::remote::client;
use crate::cli::remote::session::Session;

fn print_decision(body: &serde_json::Value, json: bool) {
    if json {
        print_json(body);
        return;
    }
    match body["decision"].as_str() {
        Some("denied") => println!("denied"),
        Some("approved") => {
            let status = body["status"].as_str().unwrap_or("?");
            println!("approved — {status}");
            if status == "executed" {
                let detail = &body["detail"];
                if let Some(exit) = detail["exit_code"].as_i64() {
                    println!("exit_code: {exit}");
                }
                if let Some(stdout) = detail["stdout"].as_str().filter(|s| !s.is_empty()) {
                    println!("stdout:\n{stdout}");
                }
                if let Some(stderr) = detail["stderr"].as_str().filter(|s| !s.is_empty()) {
                    println!("stderr:\n{stderr}");
                }
            } else if let Some(reason) = body["detail"]["reason"].as_str() {
                println!("reason: {reason}");
            }
        }
        other => println!("{other:?}: {body}"),
    }
}

pub async fn approve(session: &Session, id: Uuid, json: bool) -> Result<()> {
    let body = client::post(session, &format!("/api/approvals/{id}/approve")).await?;
    print_decision(&body, json);
    Ok(())
}

pub async fn deny(session: &Session, id: Uuid, json: bool) -> Result<()> {
    let body = client::post(session, &format!("/api/approvals/{id}/deny")).await?;
    print_decision(&body, json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(server: String) -> Session {
        Session { server, token: "ops_test".into() }
    }

    #[tokio::test]
    async fn approve_posts_to_the_right_route() {
        let server = wiremock::MockServer::start().await;
        let id = Uuid::new_v4();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(format!("/api/approvals/{id}/approve")))
            .and(wiremock::matchers::header("authorization", "Bearer ops_test"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "decision": "approved",
                "status": "executed",
                "detail": { "exit_code": 0, "stdout": "ok", "stderr": "", "duration_ms": 12 },
            })))
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        approve(&session, id, true).await.unwrap();
    }

    #[tokio::test]
    async fn deny_posts_to_the_right_route() {
        let server = wiremock::MockServer::start().await;
        let id = Uuid::new_v4();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(format!("/api/approvals/{id}/deny")))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "decision": "denied" })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        deny(&session, id, false).await.unwrap();
    }
}
