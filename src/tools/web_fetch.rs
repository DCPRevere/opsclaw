//! `web_fetch` — daemon-local GET of a public http(s) URL (brief §10
//! "Generic: ... web search/fetch"). For pulling a provider status page,
//! an upstream incident feed, or a runbook-referenced doc into the loop as
//! evidence. Deliberately narrow v1:
//!
//! - http(s) only, GET only, NO auth headers or URL credentials ever —
//!   this tool must never become a side door to an authenticated API; the
//!   endpoint-backed tools with declared, scrub-registered credentials
//!   exist for that.
//! - SSRF guard: the URL's host is resolved FIRST and every resolved
//!   address must be public — loopback, RFC 1918/4193, link-local
//!   (including cloud metadata at 169.254.169.254), and CGNAT ranges are
//!   refused — and the checked addresses are PINNED for the actual request
//!   (`resolve_to_addrs`) so a rebinding resolver can't swap in a private
//!   address between check and GET. Best-effort v1: it refuses the ranges
//!   that matter for a daemon sitting next to production, not every exotic
//!   block — tighten here, never loosen.
//! - redirects are NOT followed: a 3xx is reported with its Location so
//!   the model can re-fetch explicitly — re-applying this guard — rather
//!   than the client silently following a 302 into a private range.
//! - 10s timeout; body streamed and capped at 40KB with an honest
//!   truncation marker (never a silent cut, and never buffering an
//!   unbounded body).
//!
//! Web SEARCH (also brief §10) is deliberately deferred: search needs a
//! provider choice and an API key — a config surface of its own — where
//! fetch is self-contained. Left out until asked for.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

/// Body cap — enough for any status page or feed head the model can
/// actually use as evidence.
const MAX_BODY_BYTES: usize = 40 * 1024;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

pub struct WebFetchTool;

/// Is this an address `web_fetch` must refuse? Loopback, private,
/// link-local (cloud metadata lives there), unspecified/broadcast/
/// documentation, CGNAT (100.64/10), IPv6 unique-local (fc00::/7) and
/// link-local (fe80::/10); IPv4-mapped IPv6 unwraps to the IPv4 rules so
/// `::ffff:10.0.0.5` can't dodge them.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // CGNAT 100.64.0.0/10 (`Ipv4Addr::is_shared` isn't stable yet)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private(IpAddr::V4(mapped));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Validate + resolve + GET. `allow_private` exists ONLY so tests can point
/// at a mock server on loopback; the tool's `call` always passes `false` —
/// there is no runtime path that sets it.
async fn fetch(url_str: &str, allow_private: bool) -> Result<ToolResult, ToolError> {
    let url = reqwest::Url::parse(url_str)
        .map_err(|e| ToolError::UserFacing(format!("invalid URL {url_str:?}: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ToolError::UserFacing(format!(
            "refusing {:?} URL — only http and https are allowed",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ToolError::UserFacing(
            "refusing URL with embedded credentials — web_fetch never authenticates; use the \
             configured endpoint tools for authenticated APIs"
                .to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ToolError::UserFacing(format!("URL {url_str:?} has no host")))?;
    let port = url.port_or_known_default().unwrap_or(443);

    // Resolve up front (an IPv6 literal arrives bracketed from `host_str`,
    // so strip before the literal parse) and gate every address.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = if let Ok(ip) = bare.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((bare, port))
            .await
            .map_err(|e| ToolError::UserFacing(format!("could not resolve host {host:?}: {e}")))?
            .collect()
    };
    if addrs.is_empty() {
        return Err(ToolError::UserFacing(format!("host {host:?} resolved to no addresses")));
    }
    if !allow_private {
        if let Some(bad) = addrs.iter().find(|a| is_private(a.ip())) {
            return Err(ToolError::UserFacing(format!(
                "refusing to fetch {host:?}: it resolves to a private/loopback/link-local \
                 address ({}) — web_fetch reaches PUBLIC URLs only",
                bad.ip()
            )));
        }
    }

    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // Pin the request to the addresses just checked — see module doc.
        .resolve_to_addrs(bare, &addrs)
        .build()
        .map_err(|e| ToolError::Internal(format!("http client: {e}")))?;
    let mut resp = client
        .get(url.clone())
        .send()
        .await
        .map_err(|e| ToolError::UserFacing(format!("GET {url} failed: {e}")))?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Stream the body up to the cap — never buffer an unbounded response.
    let mut body: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ToolError::UserFacing(format!("reading body of {url} failed: {e}")))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            body.extend_from_slice(&chunk[..MAX_BODY_BYTES - body.len()]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    let mut out = format!("HTTP {status}");
    if let Some(ct) = content_type {
        out.push_str(&format!(" ({ct})"));
    }
    if status.is_redirection() {
        match location {
            Some(loc) => out.push_str(&format!(
                "\nredirect to {loc} — NOT followed; fetch that URL explicitly if it's public."
            )),
            None => out.push_str("\nredirect with no Location header — not followed."),
        }
    }
    let text = String::from_utf8_lossy(&body);
    if text.trim().is_empty() {
        out.push_str("\n\n(empty body)");
    } else {
        out.push_str(&format!("\n\n{text}"));
    }
    if truncated {
        out.push_str(&format!("\n[truncated: showing the first {MAX_BODY_BYTES} bytes]"));
    }
    Ok(ToolResult { output: out })
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &'static str {
        "web_fetch"
    }

    fn description(&self) -> &str {
        "GET a public http(s) URL and return the status plus the first 40KB of the body — \
         for provider status pages, upstream incident feeds, or docs a runbook references. \
         It sends no credentials, does not follow redirects (a redirect is reported back to \
         you), and refuses hosts that resolve to private/internal addresses — it cannot \
         reach internal services; use the configured endpoint tools for those."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "the full public URL, e.g. https://status.example.com/api/v2/status.json"}
            },
            "required": ["url"]
        })
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        false
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, _ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let url = args["url"].as_str().ok_or_else(|| {
            ToolError::UserFacing("web_fetch requires a \"url\" argument".to_string())
        })?;
        fetch(url, false).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Principal;
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct NoopPolicy;
    #[async_trait]
    impl PolicyExecute for NoopPolicy {
        async fn execute(&self, _req: CommandRequest) -> crate::Result<PolicyOutcome> {
            Ok(PolicyOutcome::EStopped)
        }
    }

    fn ctx() -> ToolCtx {
        ToolCtx::for_tests(Principal::Agent { job: None }, Arc::new(NoopPolicy))
    }

    #[test]
    fn private_range_classification() {
        for bad in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.3.4",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:10.0.0.5", // IPv4-mapped must unwrap to the v4 rules
        ] {
            assert!(is_private(bad.parse().unwrap()), "{bad} must be refused");
        }
        for good in ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(!is_private(good.parse().unwrap()), "{good} must be allowed");
        }
    }

    #[tokio::test]
    async fn non_http_schemes_are_refused() {
        for url in ["ftp://example.com/x", "file:///etc/passwd", "gopher://example.com"] {
            let err = WebFetchTool.call(&ctx(), json!({"url": url})).await.unwrap_err();
            assert!(matches!(err, ToolError::UserFacing(_)), "{url}");
        }
    }

    #[tokio::test]
    async fn urls_with_embedded_credentials_are_refused() {
        let err = WebFetchTool
            .call(&ctx(), json!({"url": "https://user:pass@example.com/"}))
            .await
            .unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("credentials"), "{msg}"),
            other => panic!("expected UserFacing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn private_and_loopback_hosts_are_refused() {
        for url in [
            "http://127.0.0.1/secrets",
            "http://[::1]:8484/",
            "http://10.0.0.5/",
            "http://192.168.1.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/",
        ] {
            let err = WebFetchTool.call(&ctx(), json!({"url": url})).await.unwrap_err();
            match err {
                ToolError::UserFacing(msg) => {
                    assert!(msg.contains("PUBLIC"), "{url}: {msg}")
                }
                other => panic!("{url}: expected UserFacing, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn localhost_domain_resolving_to_loopback_is_refused() {
        // Exercises the DOMAIN-resolution path of the guard (the literals
        // above never hit DNS): `localhost` resolves to loopback on any
        // sane host.
        let err =
            WebFetchTool.call(&ctx(), json!({"url": "http://localhost:9/"})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    // The happy-path tests drive `fetch` with `allow_private: true` — the
    // mock server necessarily lives on loopback, which the registered
    // tool's own path (always `allow_private: false`) refuses by design.

    #[tokio::test]
    async fn fetch_returns_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/status.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(r#"{"status":"degraded"}"#, "application/json"),
            )
            .mount(&server)
            .await;

        let r = fetch(&format!("{}/status.json", server.uri()), true).await.unwrap();
        assert!(r.output.starts_with("HTTP 200"), "{}", r.output);
        assert!(r.output.contains("application/json"));
        assert!(r.output.contains(r#"{"status":"degraded"}"#));
    }

    #[tokio::test]
    async fn oversized_body_is_truncated_with_an_honest_marker() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("y".repeat(MAX_BODY_BYTES * 2)))
            .mount(&server)
            .await;

        let r = fetch(&server.uri(), true).await.unwrap();
        assert!(r.output.contains("[truncated: showing the first"), "no marker");
        assert!(r.output.len() < MAX_BODY_BYTES + 200, "output must be capped");
    }

    #[tokio::test]
    async fn redirects_are_reported_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/old"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "https://example.com/new"),
            )
            .mount(&server)
            .await;

        let r = fetch(&format!("{}/old", server.uri()), true).await.unwrap();
        assert!(r.output.starts_with("HTTP 302"), "{}", r.output);
        assert!(r.output.contains("NOT followed"));
        assert!(r.output.contains("https://example.com/new"));
    }

    #[test]
    fn is_read_only_and_heartbeat_allowed() {
        assert!(!WebFetchTool.is_action());
        assert_eq!(WebFetchTool.risk(), RiskClass::Read);
        assert!(WebFetchTool.allowed_in_heartbeat());
    }
}
