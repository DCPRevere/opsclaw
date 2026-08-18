//! `opsclaw-cli status` in REMOTE mode — `GET /cli/v1/status`
//! (`http::routes::cli::status`, the bearer-native twin of `/api/status`
//! documented right there: "DESIGN §7 decision 14: 'Remote CLI v1: small
//! set — chat, incidents, approve/deny, estop, status'"). Uses the
//! `/cli/v1/*` route rather than `/api/status` even though `/api/status`
//! would also now accept the bearer (`handlers::authenticate`'s extension)
//! — no reason to reach for the cookie-first route when a bearer-native
//! twin already exists for exactly this.
//!
//! Also carries `whoami` (`GET /cli/v1/me`) — not in decision 14's named
//! list, but a natural, tiny addition alongside `login`/`logout`: knowing
//! which account a saved session belongs to is the same category of
//! question as "is this session even valid", and the route already exists
//! for `login` to have used implicitly.

use crate::Result;
use crate::cli::output::print_json;
use crate::cli::remote::client;
use crate::cli::remote::session::Session;

pub async fn status(session: &Session, json: bool) -> Result<()> {
    let body = get(session).await?;
    if json {
        print_json(&body);
    } else {
        println!("heartbeat:      {}", body["heartbeat"].as_str().unwrap_or("?"));
        println!("estop_engaged:  {}", body["estop_engaged"].as_bool().unwrap_or(false));
    }
    Ok(())
}

pub async fn get(session: &Session) -> Result<serde_json::Value> {
    client::get(session, "/cli/v1/status").await
}

pub async fn whoami(session: &Session, json: bool) -> Result<()> {
    let body = client::get(session, "/cli/v1/me").await?;
    if json {
        print_json(&body);
    } else {
        println!(
            "{} (account {}) — {}",
            body["email"].as_str().unwrap_or("?"),
            body["account_id"].as_str().unwrap_or("?"),
            session.server
        );
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
    async fn status_reports_heartbeat_and_estop() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/cli/v1/status"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "heartbeat": "healthy",
                "estop_engaged": false,
            })))
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        status(&session, true).await.unwrap();
    }

    #[tokio::test]
    async fn whoami_reports_the_account() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/cli/v1/me"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "account_id": "00000000-0000-0000-0000-000000000000",
                "email": "op@example.com",
            })))
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        whoami(&session, false).await.unwrap();
    }
}
