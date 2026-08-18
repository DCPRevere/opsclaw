use crate::Result;
use crate::cli::remote::{client, session::Session};

pub async fn load(session: &Session, before: Option<i64>, limit: i64) -> Result<serde_json::Value> {
    let path = match before {
        Some(seq) => format!("/api/chat/history?before={seq}&limit={limit}"),
        None => format!("/api/chat/history?limit={limit}"),
    };
    client::get(session, &path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn history_sends_paging_arguments() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/chat/history"))
            .and(wiremock::matchers::query_param("before", "42"))
            .and(wiremock::matchers::query_param("limit", "25"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"history": [], "has_more": false})),
            )
            .mount(&server)
            .await;
        let session = Session { server: server.uri(), token: "ops_test".into() };
        load(&session, Some(42), 25).await.unwrap();
    }
}
