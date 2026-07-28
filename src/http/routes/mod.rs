//! Route assembly + the layer stack (DESIGN §3: "same layer-ordering
//! discipline" as gianna's `src/http/routes.rs`). Security headers, request-
//! id, tracing, compression, body limit, and CORS wrap every route below in
//! the same order gianna uses; sliding-session refresh is the one gianna
//! layer NOT ported as a separate middleware — session refresh happens
//! inline in `handlers::authenticate`'s caller instead (see that module),
//! since opsclaw has far fewer session-bearing routes to intercept.

pub mod approvals;
pub mod audit;
pub mod auth_provider;
pub mod chat;
pub mod cli;
pub mod config_ui;
pub mod estop;
pub mod incidents;
pub mod invites;
pub mod push;
pub mod status;
pub mod webhooks;

use axum::Router;
use axum::routing::get;
use tower_http::cors::CorsLayer;

use super::handlers;
use super::pages;
use super::sse;
use super::state::AppState;

/// Build the application router from already-constructed state.
///
/// The embedded UI (DESIGN §3 + decision 9): the app shell (`/app`), its ES
/// modules (`/app/{name}`), the service worker (`/sw.js`, root-scoped —
/// see `pages::service_worker`'s doc comment), and the PWA manifest/icons
/// (`/static/*`, `include_str!`'d — see `pages`, NOT `ServeDir`: a
/// deployed daemon must be one self-contained binary with no `static/`
/// directory to ship or mount alongside it) are all PUBLIC routes — same
/// as gianna's `app_spa`. The shell contains no secrets; it renders a
/// login form client-side when `GET /api/me` 401s, and every actual
/// surface (chat/incidents/approvals/status/settings) is backed by
/// `Authed`-gated JSON routes underneath it, so "login page public,
/// everything else authed" holds at the API layer where it's enforced,
/// not by gating the static shell itself.
pub fn router(state: AppState) -> Router {
    Router::new()
        // Bare root goes to the app shell — every first-run operator types
        // `localhost:8484` and a 404 there reads as "daemon broken".
        // Temporary (not 308): browsers cache permanent redirects, which
        // would pin `/` to `/app` even if a future version serves something
        // else at the root.
        .route("/", get(|| async { axum::response::Redirect::temporary("/app") }))
        .route("/ready", get(ready))
        .route("/app", get(pages::app_shell))
        .route("/app/{name}", get(pages::app_module))
        .route("/sw.js", get(pages::service_worker))
        .route("/static/manifest.json", get(pages::manifest))
        .route("/static/img/{name}", get(pages::icon))
        .route("/api/login", axum::routing::post(handlers::login))
        .route("/api/logout", axum::routing::post(handlers::logout))
        .route("/api/me", get(handlers::me))
        .route("/api/stream", get(sse::stream))
        .route("/api/stream-ticket", get(sse::stream_ticket))
        .merge(auth_provider::router())
        .merge(chat::router())
        .merge(incidents::router())
        .merge(approvals::router())
        .merge(status::router())
        .merge(estop::router())
        .merge(audit::router())
        .merge(invites::router())
        .merge(push::router())
        .merge(cli::router())
        .merge(webhooks::router())
        .merge(config_ui::router())
        .layer(cors_layer())
        // Response logging lives in a from_fn (inside the TraceLayer span, so
        // it carries trace_id/account) rather than TraceLayer's on_response,
        // because on_response cannot see the request path — and the path is
        // what decides the level: the web tab polls /api/status every 15s,
        // and at INFO that poll was >95% of the journal, burying real
        // warnings (this is how live retain failures went unnoticed for
        // hours). Health-poll success logs at DEBUG; everything else keeps
        // its level.
        .layer(axum::middleware::from_fn(log_response))
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
                .on_response(()),
        )
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        // Security headers on every response. The web UI is never publicly
        // reachable (DESIGN §3: VPN/tunnel-only), but that's a network
        // property, not a browser one — a compromised operator laptop still
        // benefits from CSP/frame-deny/nosniff the same way any web app does.
        .layer(security_header(
            axum::http::header::CONTENT_SECURITY_POLICY,
            csp_header_value(&state.config),
        ))
        .layer(static_security_header(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        ))
        .layer(static_security_header(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(static_security_header(axum::http::header::X_FRAME_OPTIONS, "DENY"))
        .layer(static_security_header(
            axum::http::header::REFERRER_POLICY,
            "strict-origin-when-cross-origin",
        ))
        // Outermost: stamp `x-request-id` before the TraceLayer's span mints
        // its trace_id from it.
        .layer(axum::middleware::map_request(ensure_request_id))
        .with_state(state)
}

async fn ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<serde_json::Value> {
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
/// gianna's `'unsafe-inline'`) — the shell (`src/http/index.html`) has no
/// inline `<script>` bodies for exactly this reason (see `pages`'s test
/// `app_shell_forbids_no_inline_script`). `worker-src`/`manifest-src` are
/// explicit rather than left to fall back to `default-src`, since the PWA
/// shell depends on both (the service worker and the installable
/// manifest) and a browser that doesn't fall back silently would
/// otherwise break install with no visible error.
/// Under `auth.provider = "hanko"` ONE directive changes: `connect-src`
/// gains the Hanko API's origin, because the login widget talks to it
/// directly from the browser. `script-src` never widens — the widget is
/// vendored and served from this daemon (`static/vendor/`), so it is
/// same-origin like every other module. There is no `frame-src` exception
/// either; nothing is framed.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
script-src 'self'; style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; connect-src 'self'; \
worker-src 'self'; manifest-src 'self'; \
object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

/// The policy for a given config. Byte-identical to
/// [`CONTENT_SECURITY_POLICY`] under the local provider — a deployment that
/// does not use an external identity provider gets exactly the policy it got
/// before this setting existed.
///
/// Only the ORIGIN of `auth.api_url` is added, never the full URL: a CSP
/// source expression matches on origin, and a path there is at best ignored.
pub(crate) fn content_security_policy(config: &crate::config::Config) -> String {
    match (config.auth.provider, config.auth.api_origin()) {
        (crate::config::AuthProvider::Hanko, Some(origin)) => CONTENT_SECURITY_POLICY
            .replace("connect-src 'self'", &format!("connect-src 'self' {origin}")),
        _ => CONTENT_SECURITY_POLICY.to_string(),
    }
}

fn csp_header_value(config: &crate::config::Config) -> axum::http::HeaderValue {
    let policy = content_security_policy(config);
    axum::http::HeaderValue::from_str(&policy).unwrap_or_else(|_| {
        // Unreachable in practice: `validate()` has already refused an
        // api_url that is not a plain https URL. Falling back to the
        // stricter static policy beats serving no CSP at all.
        tracing::error!("auth.api_url is not header-safe — serving the base CSP");
        axum::http::HeaderValue::from_static(CONTENT_SECURITY_POLICY)
    })
}

fn security_header(
    name: axum::http::HeaderName,
    value: axum::http::HeaderValue,
) -> tower_http::set_header::SetResponseHeaderLayer<axum::http::HeaderValue> {
    tower_http::set_header::SetResponseHeaderLayer::overriding(name, value)
}

fn static_security_header(
    name: axum::http::HeaderName,
    value: &'static str,
) -> tower_http::set_header::SetResponseHeaderLayer<axum::http::HeaderValue> {
    security_header(name, axum::http::HeaderValue::from_static(value))
}

/// Per-request outcome log. Runs INSIDE the TraceLayer span (layer order:
/// TraceLayer wraps this middleware), so every line carries trace_id and the
/// identity fields. Successful `/api/status` polls log at DEBUG — the web tab
/// fires one every 15s, and at INFO that heartbeat was effectively the whole
/// journal; failures and slow responses stay loud regardless of path.
async fn log_response(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_health_poll =
        req.method() == axum::http::Method::GET && req.uri().path() == "/api/status";
    let started = std::time::Instant::now();
    let res = next.run(req).await;
    let status = res.status().as_u16();
    let latency_ms = started.elapsed().as_millis() as u64;
    const SLOW_MS: u64 = 3000;
    if status >= 500 {
        tracing::warn!(status, latency_ms, "request failed (5xx)");
    } else if latency_ms >= SLOW_MS {
        tracing::warn!(status, latency_ms, "request slow");
    } else if is_health_poll && status < 400 {
        tracing::debug!(status, latency_ms, "request");
    } else {
        tracing::info!(status, latency_ms, "request");
    }
    res
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
async fn ensure_request_id(
    mut req: axum::http::Request<axum::body::Body>,
) -> axum::http::Request<axum::body::Body> {
    let missing = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .is_none();
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
    use super::{CONTENT_SECURITY_POLICY, content_security_policy};
    use crate::config::Config;

    /// House style for config-under-test (see `config::tests::parse`): build
    /// from TOML so the test states the operator-visible setting, not the
    /// struct shape.
    fn parse(s: &str) -> Config {
        toml::from_str(s).unwrap()
    }

    /// One directive out of a policy string, without its trailing `;`.
    /// Panics if the directive is absent — an assertion that names a
    /// directive the policy does not carry is itself the failure.
    fn directive<'a>(policy: &'a str, name: &str) -> &'a str {
        policy
            .split("; ")
            .find(|d| d.split_whitespace().next() == Some(name))
            .unwrap_or_else(|| panic!("no `{name}` directive in: {policy}"))
    }

    /// The five security headers `router` sets on every response. Kept as
    /// one list so the regression guard below and any future header change
    /// disagree loudly rather than silently.
    const SECURITY_HEADERS: [&str; 5] = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    ];

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

    /// The promise made when the CSP stopped being a constant: a deployment
    /// with no external identity provider gets byte-identical headers to the
    /// ones it got before `[auth]` existed. Exact equality, not `contains` —
    /// a stray space or a reordered directive is a behaviour change to a
    /// browser and must fail here.
    #[test]
    fn csp_is_unchanged_under_the_local_provider() {
        assert_eq!(content_security_policy(&Config::default()), CONTENT_SECURITY_POLICY);
    }

    #[test]
    fn csp_names_the_hanko_origin_in_connect_src_only() {
        let cfg = parse(
            r#"
            [auth]
            provider = "hanko"
            api_url = "https://tenant.hanko.io"
            audience = ["ops.example.com"]
            "#,
        );
        let policy = content_security_policy(&cfg);
        const ORIGIN: &str = "https://tenant.hanko.io";

        // The browser talks to the Hanko API directly from the login widget,
        // so exactly one directive has to allow it.
        assert_eq!(directive(&policy, "connect-src"), format!("connect-src 'self' {ORIGIN}"));

        // `script-src` never widens: the widget is vendored and served from
        // this daemon, so it stays same-origin like every other module.
        assert!(policy.contains("script-src 'self';"), "{policy}");
        assert_eq!(directive(&policy, "script-src"), "script-src 'self'");

        // No other directive picked the origin up.
        assert_eq!(
            policy.matches(ORIGIN).count(),
            1,
            "the origin must appear in connect-src and nowhere else: {policy}"
        );

        assert!(policy.contains("default-src 'self';"), "{policy}");
        assert_eq!(directive(&policy, "default-src"), "default-src 'self'");
    }

    #[test]
    fn csp_adds_the_origin_not_the_path() {
        // A CSP source expression matches on origin; a path there is at best
        // ignored and at worst reads as a different host token.
        let with_path = parse(
            r#"
            [auth]
            provider = "hanko"
            api_url = "https://tenant.hanko.io/some/path"
            audience = ["ops.example.com"]
            "#,
        );
        let policy = content_security_policy(&with_path);
        assert_eq!(directive(&policy, "connect-src"), "connect-src 'self' https://tenant.hanko.io");
        assert!(!policy.contains("/some/path"), "{policy}");

        // A non-default port is part of the origin and must survive — a
        // self-hosted Hanko on :8000 is otherwise blocked by its own CSP.
        let with_port = parse(
            r#"
            [auth]
            provider = "hanko"
            api_url = "https://hanko.internal:8000/base/path"
            audience = ["ops.example.com"]
            "#,
        );
        let policy = content_security_policy(&with_port);
        assert_eq!(
            directive(&policy, "connect-src"),
            "connect-src 'self' https://hanko.internal:8000"
        );
        assert!(!policy.contains("/base/path"), "{policy}");
    }

    /// Regression guard for the refactor that made the CSP header dynamic:
    /// it rewrote all five `SetResponseHeaderLayer` call sites, and a
    /// dropped layer is invisible until a browser complains. Real server on
    /// an ephemeral port + a real request, the same rig `tests/e2e_flow.rs`
    /// uses (`tower::ServiceExt::oneshot` is not available — `tower` is not
    /// a declared dependency of this crate).
    #[tokio::test]
    async fn every_security_header_is_present_on_a_response() {
        let app = super::router(super::AppState::fake());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let resp =
            reqwest::Client::new().get(format!("http://{addr}/ready")).send().await.expect("GET");
        assert_eq!(resp.status().as_u16(), 200);

        for name in SECURITY_HEADERS {
            assert!(
                resp.headers().contains_key(name),
                "missing {name} on the response: {:?}",
                resp.headers()
            );
        }
        // A fake state is the local provider, so the served policy is the
        // constant — the layer carries the real value, not an empty header.
        assert_eq!(
            resp.headers().get("content-security-policy").unwrap().to_str().unwrap(),
            CONTENT_SECURITY_POLICY
        );
    }
}
