use crate::Result;
use crate::cli::remote::{client, session::Session};

pub async fn list(session: &Session) -> Result<serde_json::Value> {
    client::get(session, "/api/invites").await
}

pub async fn create(session: &Session) -> Result<serde_json::Value> {
    client::post(session, "/api/invites").await
}

pub async fn revoke(session: &Session, code: &str) -> Result<serde_json::Value> {
    client::delete(session, &format!("/api/invites/{code}")).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn revoke_uses_the_invite_delete_route() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("DELETE"))
            .and(wiremock::matchers::path("/api/invites/ABC123"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"revoked": "ABC123"})),
            )
            .mount(&server)
            .await;
        let session = Session { server: server.uri(), token: "ops_test".into() };
        revoke(&session, "ABC123").await.unwrap();
    }
}
