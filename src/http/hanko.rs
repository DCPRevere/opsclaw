//! Hanko (hanko.io) session verification — the server side of
//! `auth.provider = "hanko"` (DESIGN §7 decision 16).
//!
//! Hanko authenticates the operator in the browser (passkeys, email OTP, …)
//! and hands the page a session token. This module is the ONLY thing that
//! decides whether such a token is real. It verifies by calling Hanko's own
//! `POST /sessions/validate` rather than fetching the JWKS and checking the
//! signature locally, because:
//!
//! - There is no key handling, so no JWKS cache, no `kid` rotation, and no
//!   algorithm-confusion foot-gun. Nothing here can be tricked into treating
//!   a public key as an HMAC secret. This is the load-bearing reason.
//! - It sees Hanko's server-side session state (revocation, idle timeout,
//!   `session.limit`), which a signature check cannot. Do NOT overstate this:
//!   verification happens ONCE, at login, and the daemon then issues its own
//!   7-day sliding cookie, so revoking at Hanko closes a window about one
//!   round trip wide. Ending a signed-in operator's access here is
//!   `opsclaw-cli account revoke-sessions`, not anything Hanko does.
//!
//! The cost is a hard dependency on Hanko being reachable FROM THE DAEMON on
//! the login path — not merely from the operator's browser. In a cluster
//! with no egress that is a real new requirement; `opsclaw-cli doctor`
//! probes it, but doctor runs where the CLI runs, which may not be where the
//! daemon runs.
//!
//! Everything downstream — `Authed`, the `ops_` CLI bearer, SSE stream
//! tickets, `token_version` revocation — runs on opsclaw's own HS256 cookie
//! exactly as it does under the local provider, so there is no per-request
//! round trip to Hanko.
//!
//! Two traps this module encodes, both verified against Hanko backend v3.0.4:
//!
//! 1. **An invalid token is HTTP 200.** `/sessions/validate` answers `200
//!    {"is_valid":false}` for a forged, expired, or revoked token; only a
//!    malformed request (400) or an internal fault (500) is an error status.
//!    Branching on the status code alone would authenticate every forgery.
//! 2. **The response renames the claims.** It is `subject`/`expiration`/
//!    `audience`, NOT the JWT's `sub`/`exp`/`aud`, and the timestamps are
//!    RFC3339 strings where the JWT carries numeric epochs. A struct written
//!    against the JWT's shape silently fails to deserialise here.
//!
//! `POST` (rather than `GET`) is deliberate: `GET /sessions/validate` needs
//! the Hanko session cookie, which belongs to Hanko's origin and never
//! reaches this daemon. `POST` also slides Hanko's idle-timeout window, which
//! is correct — an operator signing in here HAS just used their session.
//!
//! Note on egress: `reqwest` is built without `system-proxy`, so this call
//! ignores `HTTP_PROXY`/`HTTPS_PROXY`. TLS trust comes from the OS store, so
//! a self-hosted Hanko behind a private CA needs that CA in the daemon image.

use std::time::Duration;

use serde::Deserialize;

use crate::config::AuthCfg;
use crate::{Error, Result};

/// What a verified Hanko sign-in tells us about the operator. Only `subject`
/// is guaranteed by Hanko: `email` is absent for a user with no primary
/// email, and a passkey-only identity may carry neither email nor username.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// Hanko's immutable user id (`claims.subject`) — the ONLY stable
    /// identity, and what an `accounts` row links to.
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub username: Option<String>,
}

/// Verifies Hanko session tokens against one Hanko project.
pub struct HankoClient {
    http: reqwest::Client,
    /// Base URL, trailing slash already trimmed by `AuthCfg::api_base`.
    api_url: String,
    /// Accepted `aud` values. Never empty — `Config::validate` refuses a
    /// hanko config without one, because an unchecked audience would accept
    /// a token minted by any Hanko project this daemon can reach.
    audience: Vec<String>,
}

impl HankoClient {
    /// Build the client. Synchronous and does no network I/O, so it is safe
    /// in `AppState::new` and in the fakes-mode constructor — a boot that
    /// probed the identity provider would make every CLI subcommand
    /// unrunnable whenever Hanko is down.
    pub fn new(cfg: &AuthCfg) -> Result<Self> {
        let api_url = cfg
            .api_base()
            .ok_or_else(|| Error::Config("auth.api_url is required for the hanko provider".into()))?
            .to_string();
        if cfg.audience.is_empty() {
            return Err(Error::Config("auth.audience is required for the hanko provider".into()));
        }
        Ok(HankoClient {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| Error::other(format!("hanko client: {e}")))?,
            api_url,
            audience: cfg.audience.clone(),
        })
    }

    /// Verify a session token and return the identity it proves.
    ///
    /// Every rejection is the SAME `Unauthorized` message: the distinguishing
    /// reason is logged (never returned), so this endpoint cannot be used to
    /// probe which identities exist. A transport failure is
    /// `Unavailable` (503) instead, so a Hanko outage does not read to the
    /// operator as "your passkey was rejected".
    pub async fn verify(&self, session_token: &str) -> Result<VerifiedIdentity> {
        let rejected = || Error::unauthorized("could not verify that sign-in — please try again");

        let resp = self
            .http
            .post(format!("{}/sessions/validate", self.api_url))
            .json(&serde_json::json!({ "session_token": session_token }))
            .send()
            .await
            .map_err(|e| {
                // The token is never logged, at any level.
                tracing::warn!(error = %e, api_url = %self.api_url, "hanko unreachable");
                Error::unavailable("the identity provider is unreachable — try again shortly")
            })?;

        let status = resp.status();
        if !status.is_success() {
            tracing::warn!(%status, "hanko rejected the validation request");
            return Err(Error::unavailable(
                "the identity provider rejected the validation request",
            ));
        }

        let body: ValidateResponse = resp.json().await.map_err(|e| {
            tracing::warn!(error = %e, "hanko validate response did not parse");
            Error::unavailable("the identity provider returned an unreadable response")
        })?;

        // HTTP 200 says the QUESTION was answered, not that the answer was
        // yes. This is the check that actually authenticates.
        if !body.is_valid {
            tracing::debug!("hanko reports the session token is not valid");
            return Err(rejected());
        }
        let Some(claims) = body.claims else {
            tracing::debug!("hanko reported a valid session with no claims");
            return Err(rejected());
        };

        // `aud` is an array, and Hanko OMITS the key entirely when empty
        // rather than sending `[]`.
        let audience = claims.audience.unwrap_or_default();
        if !audience.iter().any(|a| self.audience.contains(a)) {
            // WARN, not debug: this is the single easiest thing to get
            // wrong in a Hanko deployment (its `session.audience` defaults
            // to `webauthn.relying_party.id`), the values are not
            // sensitive, and at 3am an operator otherwise sees the same
            // opaque rejection for a misconfiguration as for a forgery.
            tracing::warn!(
                got = ?audience, expected = ?self.audience,
                "hanko token audience does not match auth.audience — check Hanko's \
                 session.audience against auth.audience"
            );
            return Err(rejected());
        }

        let (email, email_verified) = match claims.email {
            Some(e) => (Some(e.address), e.is_verified),
            None => (None, false),
        };
        Ok(VerifiedIdentity {
            subject: claims.subject,
            email,
            email_verified,
            username: claims.username,
        })
    }
}

/// `dto.ValidateSessionResponse`. Deliberately NOT `deny_unknown_fields`:
/// Hanko flattens `amr` and every `session.jwt_template` claim into this
/// object, and a future release may add more.
#[derive(Debug, Deserialize)]
struct ValidateResponse {
    is_valid: bool,
    #[serde(default)]
    claims: Option<ValidateClaims>,
}

/// `dto.Claims` — the RESPONSE shape, not the JWT payload shape. `subject`
/// (not `sub`), `audience` (not `aud`). Absent fields are missing keys, never
/// nulls.
#[derive(Debug, Deserialize)]
struct ValidateClaims {
    subject: String,
    #[serde(default)]
    audience: Option<Vec<String>>,
    #[serde(default)]
    email: Option<EmailClaim>,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EmailClaim {
    address: String,
    #[serde(default)]
    is_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(url: &str) -> AuthCfg {
        AuthCfg {
            provider: crate::config::AuthProvider::Hanko,
            api_url: Some(url.to_string()),
            audience: vec!["ops.example.com".into()],
        }
    }

    fn valid_body() -> serde_json::Value {
        json!({
            "is_valid": true,
            "expiration_time": "2026-07-28T21:00:00Z",
            "user_id": "6f1c0e64-0000-4000-8000-000000000001",
            "claims": {
                "subject": "6f1c0e64-0000-4000-8000-000000000001",
                "expiration": "2026-07-28T21:00:00Z",
                "session_id": "6f1c0e64-0000-4000-8000-000000000002",
                "issued_at": "2026-07-28T09:00:00Z",
                "audience": ["ops.example.com"],
                "amr": ["passkey"],
                "email": { "address": "sre@example.com", "is_primary": true, "is_verified": true }
            }
        })
    }

    async fn mount(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/sessions/validate"))
            .and(body_json(json!({ "session_token": "tok" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_valid_session_yields_the_subject_and_email() {
        let server = MockServer::start().await;
        mount(&server, valid_body()).await;
        let id = HankoClient::new(&cfg(&server.uri())).unwrap().verify("tok").await.unwrap();
        assert_eq!(id.subject, "6f1c0e64-0000-4000-8000-000000000001");
        assert_eq!(id.email.as_deref(), Some("sre@example.com"));
        assert!(id.email_verified);
        server.verify().await;
    }

    #[tokio::test]
    async fn a_passkey_only_identity_with_no_email_still_verifies() {
        let server = MockServer::start().await;
        mount(
            &server,
            json!({
                "is_valid": true,
                "claims": {
                    "subject": "sub-1",
                    "expiration": "2026-07-28T21:00:00Z",
                    "session_id": "sess-1",
                    "audience": ["ops.example.com"],
                    "amr": ["passkey"]
                }
            }),
        )
        .await;
        let id = HankoClient::new(&cfg(&server.uri())).unwrap().verify("tok").await.unwrap();
        assert_eq!(id.subject, "sub-1");
        assert_eq!(id.email, None);
        assert!(!id.email_verified);
        server.verify().await;
    }

    #[tokio::test]
    async fn is_valid_false_is_unauthorized_despite_the_200() {
        // The trap: Hanko answers 200 for a forged token.
        let server = MockServer::start().await;
        mount(&server, json!({ "is_valid": false })).await;
        let err = HankoClient::new(&cfg(&server.uri())).unwrap().verify("tok").await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)), "{err:?}");
        server.verify().await;
    }

    #[tokio::test]
    async fn an_audience_from_another_hanko_project_is_refused() {
        let server = MockServer::start().await;
        let mut body = valid_body();
        body["claims"]["audience"] = json!(["someone-elses-app.example.net"]);
        mount(&server, body).await;
        let err = HankoClient::new(&cfg(&server.uri())).unwrap().verify("tok").await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)), "{err:?}");
        server.verify().await;
    }

    #[tokio::test]
    async fn a_missing_audience_is_refused_rather_than_defaulted() {
        let server = MockServer::start().await;
        let mut body = valid_body();
        body["claims"].as_object_mut().unwrap().remove("audience");
        mount(&server, body).await;
        let err = HankoClient::new(&cfg(&server.uri())).unwrap().verify("tok").await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)), "{err:?}");
        server.verify().await;
    }

    #[tokio::test]
    async fn valid_with_no_claims_is_refused() {
        let server = MockServer::start().await;
        mount(&server, json!({ "is_valid": true })).await;
        let err = HankoClient::new(&cfg(&server.uri())).unwrap().verify("tok").await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)), "{err:?}");
        server.verify().await;
    }

    #[tokio::test]
    async fn a_jwt_shaped_payload_does_not_deserialise_as_the_validate_response() {
        // Pins the rename trap: the JWT says sub/aud, the validate response
        // says subject/audience. If this ever starts passing, the response
        // struct has drifted onto the wrong shape.
        let server = MockServer::start().await;
        mount(
            &server,
            json!({
                "is_valid": true,
                "claims": { "sub": "sub-1", "aud": ["ops.example.com"], "exp": 1785000000 }
            }),
        )
        .await;
        let err = HankoClient::new(&cfg(&server.uri())).unwrap().verify("tok").await.unwrap_err();
        assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
        server.verify().await;
    }

    #[tokio::test]
    async fn a_hanko_outage_is_unavailable_not_unauthorized() {
        // A 503 must not read to the operator as "bad passkey".
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sessions/validate"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        let err = HankoClient::new(&cfg(&server.uri())).unwrap().verify("tok").await.unwrap_err();
        assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
        server.verify().await;
    }

    #[test]
    fn a_client_needs_a_url_and_an_audience() {
        let mut c = cfg("https://tenant.hanko.io");
        c.audience.clear();
        assert!(HankoClient::new(&c).is_err());
        let mut c = cfg("https://tenant.hanko.io");
        c.api_url = None;
        assert!(HankoClient::new(&c).is_err());
    }
}
