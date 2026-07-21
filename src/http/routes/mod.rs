//! Route assembly + the layer stack (DESIGN §3: "same layer-ordering
//! discipline" as gianna's `src/http/routes.rs`). Security headers, request-
//! id, tracing, compression, body limit, and CORS wrap every route below in
//! the same order gianna uses; sliding-session refresh is the one gianna
//! layer NOT ported as a separate middleware — session refresh happens
//! inline in `handlers::authenticate`'s caller instead (see that module),
//! since opsclaw has far fewer session-bearing routes to intercept.

pub mod approvals;
pub mod audit;
pub mod cli;
pub mod estop;
pub mod incidents;
pub mod invites;
pub mod status;
pub mod webhooks;

use axum::Router;
use axum::routing::get;
use tower_http::cors::CorsLayer;

use super::handlers;
use super::sse;
use super::state::AppState;

/// Build the application router from already-constructed state.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ready", get(ready))
        .route("/api/login", axum::routing::post(handlers::login))
        .route("/api/logout", axum::routing::post(handlers::logout))
        .route("/api/me", get(handlers::me))
        .route("/api/stream", get(sse::stream))
        .route("/api/stream-ticket", get(sse::stream_ticket))
        .merge(incidents::router())
        .merge(approvals::router())
        .merge(status::router())
        .merge(estop::router())
        .merge(audit::router())
        .merge(invites::router())
        .merge(cli::router())
        .merge(webhooks::router())
        .layer(cors_layer())
        // Operability: every request runs inside a `trace_id`-bearing span
        // so downstream logs for one turn share an id an operator can grep
        // on. Identity fields start Empty and are filled by `authenticate`
        // once the token resolves.
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(|req: &axum::http::Request<axum::body::Body>| {
                    let trace_id = trace_id_for(req.headers());
                    tracing::info_span!(
                        "http_request",
                        trace_id = %trace_id,
                        method = %req.method(),
                        path = %req.uri().path(),
                        account = tracing::field::Empty,
                        session = tracing::field::Empty,
                    )
                })
                .on_response(
                    |res: &axum::http::Response<_>, latency: std::time::Duration, _: &tracing::Span| {
                        let status = res.status().as_u16();
                        let latency_ms = latency.as_millis() as u64;
                        const SLOW_MS: u64 = 3000;
                        if status >= 500 {
                            tracing::warn!(status, latency_ms, "request failed (5xx)");
                        } else if latency_ms >= SLOW_MS {
                            tracing::warn!(status, latency_ms, "request slow");
                        } else {
                            tracing::info!(status, latency_ms, "request");
                        }
                    },
                ),
        )
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        // Security headers on every response. The web UI is never publicly
        // reachable (DESIGN §3: VPN/tunnel-only), but that's a network
        // property, not a browser one — a compromised operator laptop still
        // benefits from CSP/frame-deny/nosniff the same way any web app does.
        .layer(security_header(axum::http::header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY))
        .layer(security_header(axum::http::header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains"))
        .layer(security_header(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(security_header(axum::http::header::X_FRAME_OPTIONS, "DENY"))
        .layer(security_header(axum::http::header::REFERRER_POLICY, "strict-origin-when-cross-origin"))
        // Outermost: stamp `x-request-id` before the TraceLayer's span mints
        // its trace_id from it.
        .layer(axum::middleware::map_request(ensure_request_id))
        .with_state(state)
}

async fn ready(axum::extract::State(state): axum::extract::State<AppState>) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "ok": true,
        "version": crate::version(),
        "fakes_mode": state.config.fully_faked(),
    }))
}

/// CORS: the operational web UI is embedded and same-origin (DESIGN §3 —
/// never a split frontend talking cross-origin to this daemon), so a
/// permissive policy costs nothing extra in practice; kept explicit (not
/// `Any`) so a future split frontend doesn't silently inherit an
/// unreviewed policy.
fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
        .allow_credentials(true)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
        ])
        .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE])
}

/// The web UI is embedded in the binary and self-contained (no third-party
/// scripts/fonts/analytics — DESIGN §3: a departure from gianna's
/// marketing-site CSP, which allows PostHog/Stripe/Google hosts opsclaw has
/// no analog for). `connect-src 'self'` covers the SSE stream and every
/// `/api` call; no inline script exception is granted here (unlike
/// gianna's `'unsafe-inline'`) — the embedded UI's `<script>` should use a
/// nonce or external file once it's built, not inline handlers.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
script-src 'self'; style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; connect-src 'self'; \
object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

fn security_header(name: axum::http::HeaderName, value: &'static str) -> tower_http::set_header::SetResponseHeaderLayer<axum::http::HeaderValue> {
    tower_http::set_header::SetResponseHeaderLayer::overriding(name, axum::http::HeaderValue::from_static(value))
}

/// The correlation id for a request: honour an inbound `x-request-id`
/// (an upstream proxy's id flows through), else mint a fresh uuid v4.
pub(crate) fn trace_id_for(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Guarantee `x-request-id` on the request BEFORE the TraceLayer runs.
async fn ensure_request_id(mut req: axum::http::Request<axum::body::Body>) -> axum::http::Request<axum::body::Body> {
    let missing = req.headers().get("x-request-id").and_then(|v| v.to_str().ok()).filter(|s| !s.is_empty()).is_none();
    if missing {
        let id = uuid::Uuid::new_v4().to_string();
        if let Ok(v) = axum::http::HeaderValue::from_str(&id) {
            req.headers_mut().insert("x-request-id", v);
        }
    }
    req
}

#[cfg(test)]
mod tests {
    #[test]
    fn trace_id_honours_request_header_else_mints() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-request-id", "upstream-42".parse().unwrap());
        assert_eq!(super::trace_id_for(&h), "upstream-42");

        let minted = super::trace_id_for(&axum::http::HeaderMap::new());
        assert!(uuid::Uuid::parse_str(&minted).is_ok(), "minted id must be a uuid: {minted}");

        let mut empty = axum::http::HeaderMap::new();
        empty.insert("x-request-id", "".parse().unwrap());
        assert!(uuid::Uuid::parse_str(&super::trace_id_for(&empty)).is_ok());
    }
}
