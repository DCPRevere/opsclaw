//! The HTTP gateway (DESIGN.md §3 "HTTP gateway", Wave 4): operator auth
//! (argon2 + HS256 JWT + HttpOnly SameSite=Strict cookie), typed auth
//! extractors, the incident/approval/status/e-stop/audit API, teammate
//! invites, the remote-CLI token-auth surface, webhook ingestion, and the
//! SSE push channel. Ported from gianna's `src/http/` — see each
//! submodule's doc comment for its specific donor file.
//!
//! The embedded web UI's HTML/JS (four surfaces: chat, incidents, approval
//! queue, status/config) is a SEPARATE later task — this module is the
//! API + auth layer it will sit on, matching DESIGN §3's split between the
//! gateway and the frontend it serves.

pub mod auth;
pub mod cli_auth;
pub mod handlers;
pub mod ratelimit;
pub mod routes;
pub mod server;
pub mod sse;
pub mod state;
pub mod webhook;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub use state::AppState;

use crate::Error;

/// Map domain errors to HTTP status codes + a JSON body. Ported from
/// gianna's `src/http/mod.rs::impl IntoResponse for Error` — the status
/// mapping for the variants opsclaw shares with gianna (`NotFound`,
/// `Validation`/`validation()`, `Unauthorized`, `Conflict`, `RateLimited`)
/// is identical; opsclaw's other variants (`Config`, `Policy`, `Llm*`,
/// `Database`, `Io`, `Other`) have no gianna analog and all fall through to
/// 500 — none of them should ever reach a handler in ordinary operation
/// (a `Config`/`Policy` error reaching HTTP is itself a bug worth the loud
/// 500, not a 400 that would suggest the CLIENT did something wrong).
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match &self {
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::Validation(_) => StatusCode::BAD_REQUEST,
            Error::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let retry_after = match &self {
            Error::RateLimited { retry_after_secs, .. } => Some(*retry_after_secs),
            _ => None,
        };
        // 500-class details (raw sqlx/internal text) never reach the body —
        // they can leak schema/queries. Log server-side; serve a generic
        // message.
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "internal error (masked in response)");
            "something went wrong on our side — please try again".to_string()
        } else {
            user_message(&self)
        };
        let mut resp = (status, Json(json!({ "error": message }))).into_response();
        if let Some(secs) = retry_after
            && let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string())
        {
            resp.headers_mut().insert(axum::http::header::RETRY_AFTER, v);
        }
        resp
    }
}

/// The message as shown to the CLIENT for a non-500 error: the inner text
/// without the technical variant prefix (`Display` on `Error::Validation`
/// renders as `"validation: msg"` — the status code already carries the
/// kind, so the prefix is redundant noise in the body).
fn user_message(err: &Error) -> String {
    match err {
        Error::NotFound(m) => format!("{m} not found"),
        Error::Validation(m) | Error::Unauthorized(m) | Error::Conflict(m) => m.clone(),
        Error::RateLimited { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_maps_to_404_with_a_sentence_body() {
        let resp = Error::NotFound("incident".into()).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn unauthorized_maps_to_401() {
        assert_eq!(Error::unauthorized("nope").into_response().status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn validation_maps_to_400() {
        assert_eq!(Error::validation("bad").into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn conflict_maps_to_409() {
        assert_eq!(Error::Conflict("x".into()).into_response().status(), StatusCode::CONFLICT);
    }

    #[test]
    fn rate_limited_maps_to_429_with_retry_after_header() {
        let resp = Error::rate_limited("slow down", 42).into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(axum::http::header::RETRY_AFTER).unwrap(), "42");
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn internal_errors_map_to_500_and_never_leak_their_message() {
        let resp = Error::Config("secret-looking internal detail".into()).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_string(resp).await;
        assert!(!body.contains("secret-looking internal detail"), "{body}");
        assert!(body.contains("something went wrong"), "{body}");
    }

    #[tokio::test]
    async fn database_error_text_never_reaches_the_response_body() {
        let resp = Error::Database(sqlx::Error::RowNotFound).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_string(resp).await;
        assert!(!body.to_lowercase().contains("rowid"), "{body}");
        assert!(!body.to_lowercase().contains("sqlx"), "{body}");
    }

    #[tokio::test]
    async fn user_facing_errors_show_their_own_message_verbatim() {
        let resp = Error::validation("that field is required").into_response();
        let body = body_string(resp).await;
        assert!(body.contains("that field is required"), "{body}");
        // And the technical variant prefix ("validation: ") must NOT leak
        // into the body — the status code already carries the kind.
        assert!(!body.contains("validation:"), "{body}");
    }
}
