//! The embedded web UI (DESIGN.md §3 "HTTP gateway" + decision 9): the app
//! shell, its ES modules, the PWA manifest, and the service worker — every
//! byte compiled into the binary via `include_str!`, so a running daemon
//! is fully self-contained (no `static/` directory needs to ship or be
//! mounted at runtime; AGENTS.md: "embedded frontend... needs a release to
//! show" — edits here only take effect on rebuild).
//!
//! Ported from gianna's `src/http/pages.rs`: the `Cache-Control: no-cache`
//! wrapper and the `OnceLock`-memoized template-substitution pattern are
//! near-verbatim (see [`html_no_cache`] and [`app_shell`]'s doc comments
//! for the exact incident that motivated both). Adapted: gianna's shell is
//! one big HTML file with Stripe/PostHog/Google placeholders; opsclaw's
//! placeholders are just `__VERSION__` (shown in a `<meta>` tag, not
//! substituted into any script — the CSP here forbids inline scripts
//! entirely, a deliberate tightening over gianna's `'unsafe-inline'`, so
//! there is nothing else to template into the shell). `/app/{name}` module
//! serving and the `/sw.js` root-scoped route are the same shape.

use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

/// Wrap an HTML document with `Cache-Control: no-cache`. Every navigable
/// page is embedded in the binary and served with no validators, so with
/// no header browsers cache it HEURISTICALLY — after a deploy an operator
/// could keep a stale app shell talking to a newer API (gianna's own
/// stale-app-shell incident, `src/http/pages.rs`). `no-cache` forces
/// revalidation on every navigation; `/static/*` assets are plain files
/// with their own validators (ETags via `ServeDir`) and don't need this.
fn html_no_cache(body: &str) -> Response {
    ([(header::CACHE_CONTROL, "no-cache")], Html(body.to_string())).into_response()
}

fn js_no_cache(body: impl Into<String>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript"), (header::CACHE_CONTROL, "no-cache")],
        body.into(),
    )
        .into_response()
}

const SHELL_TEMPLATE: &str = include_str!("index.html");

/// GET /app — the SPA shell. Templated exactly ONCE per process via a
/// function-local `OnceLock<String>` (gianna's pattern: the substitution
/// is cheap but pointless to redo on every request when the result never
/// changes for the life of the process), then served with `no-cache` so a
/// stale-shell deploy can't linger in a browser's heuristic cache.
pub async fn app_shell() -> Response {
    static HTML: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    html_no_cache(
        HTML.get_or_init(|| SHELL_TEMPLATE.replace("__VERSION__", crate::build_version())),
    )
}

const APP_STATE_JS: &str = include_str!("../../static/app/state.js");
const APP_FORMAT_JS: &str = include_str!("../../static/app/format.js");
const APP_API_JS: &str = include_str!("../../static/app/api.js");
const APP_AUTH_JS: &str = include_str!("../../static/app/auth.js");
const APP_CHAT_JS: &str = include_str!("../../static/app/chat.js");
const APP_INCIDENTS_JS: &str = include_str!("../../static/app/incidents.js");
const APP_APPROVALS_JS: &str = include_str!("../../static/app/approvals.js");
const APP_STATUS_JS: &str = include_str!("../../static/app/status.js");
const APP_SETTINGS_JS: &str = include_str!("../../static/app/settings.js");
const APP_MAIN_JS: &str = include_str!("../../static/app/main.js");
const APP_HANKO_JS: &str = include_str!("../../static/app/hanko.js");
/// The vendored Hanko widget (`static/vendor/`, MIT, pinned + hashed in its
/// own header). Served from this registry like any other module so the
/// page's `script-src 'self'` never has to widen to a CDN.
const APP_HANKO_ELEMENTS_JS: &str = include_str!("../../static/vendor/hanko-elements.js");

/// GET /app/{name} — the shell's ES modules. Each is `include_str!`'d
/// (never read from disk at runtime — see this module's doc comment), so
/// the binary can never serve a module that doesn't match the shell it
/// shipped with. Modules import each other via relative `./name.js` paths
/// resolved under `/app/`, exactly as gianna's do.
pub async fn app_module(Path(name): Path<String>) -> Response {
    let body = match name.as_str() {
        "state.js" => Some(APP_STATE_JS),
        "format.js" => Some(APP_FORMAT_JS),
        "api.js" => Some(APP_API_JS),
        "auth.js" => Some(APP_AUTH_JS),
        "chat.js" => Some(APP_CHAT_JS),
        "incidents.js" => Some(APP_INCIDENTS_JS),
        "approvals.js" => Some(APP_APPROVALS_JS),
        "status.js" => Some(APP_STATUS_JS),
        "settings.js" => Some(APP_SETTINGS_JS),
        "main.js" => Some(APP_MAIN_JS),
        "hanko.js" => Some(APP_HANKO_JS),
        "hanko-elements.js" => Some(APP_HANKO_ELEMENTS_JS),
        _ => None,
    };
    match body {
        Some(js) => js_no_cache(js),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

const SW_TEMPLATE: &str = include_str!("../../static/sw.js");

/// GET /sw.js — the service worker, served at ROOT (not under `/static` or
/// `/app`) because a service worker's scope is capped at its own path; a
/// worker served from `/static/sw.js` could only ever control `/static/*`,
/// never `/app`. Templated once per process (same `OnceLock` pattern as
/// [`app_shell`] — `crate::version()` is fixed for the process lifetime,
/// so there is nothing to gain from re-substituting per request, and
/// unlike a naive `Box::leak` this costs no unbounded per-request memory)
/// so `__SW_VERSION__` reflects the CURRENT build: a new release produces
/// a byte-different file, which is the entire cache-busting mechanism
/// (see `static/sw.js`'s own doc comment).
pub async fn service_worker() -> Response {
    static SW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    js_no_cache(
        SW.get_or_init(|| SW_TEMPLATE.replace("__SW_VERSION__", crate::build_version())).as_str(),
    )
}

const MANIFEST_JSON: &str = include_str!("../../static/manifest.json");

/// GET /static/manifest.json — the PWA manifest. Not templated (no
/// placeholders — unlike gianna, opsclaw's manifest has no VAPID key or
/// other per-deployment value to substitute; that lands with the push
/// task). Cacheable normally (unlike the shell/modules/worker, a stale
/// manifest is harmless — its only effect is "install" metadata, and a
/// fresh one is picked up the next time the PWA is (re)installed), so no
/// `no-cache` override here — plain `application/json`.
pub async fn manifest() -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], MANIFEST_JSON).into_response()
}

const ICON: &str = include_str!("../../static/img/icon.svg");
const ICON_192: &str = include_str!("../../static/img/icon-192.svg");
const ICON_512: &str = include_str!("../../static/img/icon-512.svg");
const ICON_MASKABLE: &str = include_str!("../../static/img/icon-maskable.svg");

/// GET /static/img/{name} — the PWA icon set (DESIGN §3 decision 9:
/// "icons placeholder"). SVG rather than raster: scales to every size the
/// manifest declares from one small text asset with nothing to generate
/// or ship as binary — swap in real artwork (raster or otherwise) later
/// without changing this route's shape.
pub async fn icon(Path(name): Path<String>) -> Response {
    let body = match name.as_str() {
        "icon.svg" => Some(ICON),
        "icon-192.svg" => Some(ICON_192),
        "icon-512.svg" => Some(ICON_512),
        "icon-maskable.svg" => Some(ICON_MASKABLE),
        _ => None,
    };
    match body {
        Some(svg) => {
            (StatusCode::OK, [(header::CONTENT_TYPE, "image/svg+xml")], svg).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn app_shell_serves_no_cache_and_embeds_the_version() {
        let resp = app_shell().await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CACHE_CONTROL).unwrap(), "no-cache");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains(crate::version()), "{text}");
        assert!(!text.contains("__VERSION__"), "placeholder must be substituted");
    }

    #[tokio::test]
    async fn app_shell_forbids_no_inline_script() {
        // Structural check that the shell has no inline `<script>` body (a
        // CSP with no 'unsafe-inline' would silently no-op any that
        // existed) — the shell must load everything via external files.
        let resp = app_shell().await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        // Every <script> tag in the shell must be external (have a src=)
        // — a bare `<script>` with a body would be dead code under this
        // CSP and worth catching here rather than in production.
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("<script") && !trimmed.contains("src=") {
                panic!(
                    "shell has an inline <script> with no src= — dead under the no-inline CSP: {trimmed}"
                );
            }
        }
    }

    #[tokio::test]
    async fn known_modules_serve_as_javascript_with_no_cache() {
        // Every registered module. A name missing here 404s at runtime with
        // no compile error, so this list is the only thing that catches a
        // registry gap — `format.js` was registered and precached but absent
        // from this list until the auth-provider work added to it.
        for name in [
            "state.js",
            "format.js",
            "api.js",
            "auth.js",
            "chat.js",
            "incidents.js",
            "approvals.js",
            "status.js",
            "settings.js",
            "main.js",
            "hanko.js",
            "hanko-elements.js",
        ] {
            let resp = app_module(Path(name.to_string())).await;
            assert_eq!(resp.status(), StatusCode::OK, "{name}");
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/javascript",
                "{name}"
            );
            assert_eq!(resp.headers().get(header::CACHE_CONTROL).unwrap(), "no-cache", "{name}");
        }
    }

    #[tokio::test]
    async fn unknown_module_is_404() {
        let resp = app_module(Path("does-not-exist.js".to_string())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn service_worker_embeds_the_version_and_has_no_leftover_placeholder() {
        let resp = service_worker().await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CACHE_CONTROL).unwrap(), "no-cache");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains(crate::version()), "{text}");
        assert!(!text.contains("__SW_VERSION__"));
    }

    #[tokio::test]
    async fn service_worker_declares_push_and_notificationclick_handlers() {
        // Push task landed: the worker actually shows notifications and
        // deep-links on tap now, not the earlier TODO stub.
        let resp = service_worker().await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("addEventListener('push'"), "{text}");
        assert!(text.contains("showNotification"), "{text}");
        assert!(text.contains("addEventListener('notificationclick'"), "{text}");
        assert!(!text.contains("TODO"), "push handler should no longer be a stub, {text}");
    }

    #[tokio::test]
    async fn manifest_serves_as_valid_json_naming_every_declared_icon() {
        let resp = manifest().await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("manifest must be valid JSON");
        let icons = parsed["icons"].as_array().expect("icons array");
        assert!(!icons.is_empty());
        for entry in icons {
            let src = entry["src"].as_str().expect("icon src");
            let name = src.rsplit('/').next().unwrap();
            let resp = icon(Path(name.to_string())).await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "manifest names {src} but icon() 404s for it"
            );
        }
    }

    #[tokio::test]
    async fn known_icons_serve_as_svg() {
        for name in ["icon.svg", "icon-192.svg", "icon-512.svg", "icon-maskable.svg"] {
            let resp = icon(Path(name.to_string())).await;
            assert_eq!(resp.status(), StatusCode::OK, "{name}");
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "image/svg+xml",
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_icon_is_404() {
        let resp = icon(Path("does-not-exist.svg".to_string())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
