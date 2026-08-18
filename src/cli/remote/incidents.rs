//! `opsclaw-cli incidents [list|show]` in REMOTE mode — over `GET
//! /api/incidents` / `GET /api/incidents/{id}` (`http::routes::incidents`).
//! Same `--json`-or-table convention as the local command
//! (`cli::incidents_cmd`), just sourced from the gateway's JSON instead of
//! `db::IncidentRepo` directly — this module owns no incident logic, only
//! the HTTP round-trip and formatting.

use uuid::Uuid;

use crate::Result;
use crate::cli::output::{print_json, print_table};
use crate::cli::remote::client;
use crate::cli::remote::session::Session;

pub async fn list(session: &Session, include_closed: bool, limit: i64, json: bool) -> Result<()> {
    let path = format!("/api/incidents?include_closed={include_closed}&limit={limit}");
    let body = client::get(session, &path).await?;
    let incidents = body["incidents"].as_array().cloned().unwrap_or_default();
    if json {
        print_json(&incidents);
    } else {
        let rows: Vec<Vec<String>> = incidents
            .iter()
            .map(|i| {
                vec![
                    i["id"].as_str().unwrap_or("?").to_string(),
                    i["target"].as_str().unwrap_or("?").to_string(),
                    i["severity"].as_str().unwrap_or("?").to_string(),
                    i["state"].as_str().unwrap_or("?").to_string(),
                    i["opened_at"].as_str().unwrap_or("?").to_string(),
                    i["hypothesis"].as_str().unwrap_or("").chars().take(60).collect(),
                ]
            })
            .collect();
        print_table(&["id", "target", "severity", "state", "opened_at", "hypothesis"], &rows);
    }
    Ok(())
}

pub async fn show(session: &Session, id: Uuid, json: bool) -> Result<()> {
    let body = client::get(session, &format!("/api/incidents/{id}")).await?;
    if json {
        print_json(&body);
    } else {
        println!("id:            {}", body["id"].as_str().unwrap_or("?"));
        println!("fingerprint:   {}", body["fingerprint"].as_str().unwrap_or("?"));
        println!("target:        {}", body["target"].as_str().unwrap_or("?"));
        println!("severity:      {}", body["severity"].as_str().unwrap_or("?"));
        println!("state:         {}", body["state"].as_str().unwrap_or("?"));
        println!("opened_at:     {}", body["opened_at"].as_str().unwrap_or("?"));
        if let Some(acked) = body["acked_at"].as_str() {
            println!("acked_at:      {acked}");
        }
        if let Some(resolved) = body["resolved_at"].as_str() {
            println!("resolved_at:   {resolved}");
        }
        println!("notify_count:  {}", body["notify_count"].as_i64().unwrap_or(0));
        println!("hypothesis:    {}", body["hypothesis"].as_str().unwrap_or(""));
        println!("signals:       {}", body["signals"].as_str().unwrap_or(""));
        if let Some(action) = body["recommended_action"].as_str() {
            println!("recommended:   {action}");
        }
    }
    Ok(())
}

pub async fn transition(session: &Session, id: Uuid, action: &str) -> Result<serde_json::Value> {
    client::post(session, &format!("/api/incidents/{id}/{action}")).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(server: String) -> Session {
        Session { server, token: "ops_test".into() }
    }

    #[tokio::test]
    async fn list_requests_the_right_query_params() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/incidents"))
            .and(wiremock::matchers::query_param("include_closed", "true"))
            .and(wiremock::matchers::query_param("limit", "10"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "incidents": [] })),
            )
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        list(&session, true, 10, true).await.unwrap();
    }

    #[tokio::test]
    async fn show_reaches_the_by_id_route() {
        let server = wiremock::MockServer::start().await;
        let id = Uuid::new_v4();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!("/api/incidents/{id}")))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": id.to_string(),
                "target": "example::prod::sb-worker",
                "severity": "critical",
                "state": "active",
                "opened_at": "2026-01-01T00:00:00Z",
                "hypothesis": "dlq backlog",
                "signals": "queue_depth=500",
                "notify_count": 1,
            })))
            .mount(&server)
            .await;

        let session = test_session(server.uri());
        show(&session, id, true).await.unwrap();
    }
}
