//! `opsclaw-cli estop engage|resume` in REMOTE mode — over `POST
//! /api/estop/engage` / `POST /api/estop/resume` (`http::routes::estop`,
//! `Authed`-gated; see `cli::remote::approvals`'s doc for why an `ops_`
//! token satisfies that gate now). Distinct from the LOCAL `estop` command
//! (`cli::estop`), which writes the sentinel file directly and needs no
//! network round-trip at all — the remote command exists for exactly the
//! case the local one can't cover: an operator away from the box who needs
//! to pull the lever from a phone (DESIGN §7 decision 14).

use crate::Result;
use crate::cli::remote::client;
use crate::cli::remote::session::Session;

pub async fn engage(session: &Session, reason: &str) -> Result<bool> {
    let body = if reason.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::json!({ "reason": reason })
    };
    let resp = client::post_json(session, "/api/estop/engage", &body).await?;
    Ok(resp["estop_engaged"].as_bool().unwrap_or(false))
}

pub async fn resume(session: &Session) -> Result<bool> {
    let resp = client::post(session, "/api/estop/resume").await?;
    Ok(resp["estop_engaged"].as_bool().unwrap_or(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(server: String) -> Session {
        Session { server, token: "ops_test".into() }
    }

    #[tokio::test]
    async fn engage_reports_the_gateways_confirmation() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/estop/engage"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "estop_engaged": true })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        assert!(engage(&session, "remote e2e test").await.unwrap());
    }

    #[tokio::test]
    async fn resume_reports_the_gateways_confirmation() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/estop/resume"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "estop_engaged": false })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        assert!(!resume(&session).await.unwrap());
    }
}
