//! Outbound webhook — the send-only channel from DESIGN §2's channel list
//! and §7 decision 5: "Telegram and the outbound webhook (→ PagerDuty) are
//! the guaranteed escalation paths; push is the convenient one". Every
//! outbound team message (incident alerts, approval requests, scheduler
//! escalations — whatever reaches the `MultiChannel` fan-out) is POSTed as
//! JSON to one configured receiver outside the daemon: a PagerDuty events
//! endpoint behind a relay, a healthchecks-style collector, an internal
//! automation — anything that speaks HTTP.
//!
//! Deliveries are optionally SIGNED with the same `t=<ts>,v1=<hmac_hex>`
//! convention `http::webhook::verify_signature` checks on the inbound side
//! (`http::webhook::sign_payload` — one scheme, one module, both
//! directions), so a receiver holding the shared secret can authenticate
//! the daemon and reject replays.
//!
//! Delivery is one POST with a bounded timeout; a non-2xx or transport
//! failure is an `Err`, which `MultiChannel::send` logs and survives — the
//! GUARANTEE in "guaranteed escalation path" is that this channel has no
//! best-effort filtering of its own (unlike push, which prunes and
//! infers): every message goes out, and a failed delivery is loudly
//! visible in the log. Retry belongs to the caller's machinery (the
//! scheduler's escalation re-notify cadence re-sends on its own clock),
//! not hidden here.

use async_trait::async_trait;
use serde_json::json;

use super::{Channel, OutboundMessage};
use crate::Result;

/// Bounded delivery timeout — long enough for a slow receiver, short
/// enough that a dead one can't stall the fan-out loop noticeably.
const DELIVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct WebhookOutChannel {
    client: reqwest::Client,
    url: String,
    /// Already-resolved signing secret (boot registers it with the
    /// scrubber, same discipline as every resolved credential). `None`
    /// sends unsigned — valid for receivers that authenticate by URL
    /// secrecy or network position.
    secret: Option<String>,
}

impl WebhookOutChannel {
    pub fn new(url: impl Into<String>, secret: Option<String>) -> Self {
        WebhookOutChannel { client: reqwest::Client::new(), url: url.into(), secret }
    }
}

#[async_trait]
impl Channel for WebhookOutChannel {
    fn name(&self) -> &str {
        "webhook-out"
    }

    async fn send(&self, msg: OutboundMessage) -> Result<()> {
        let now = chrono::Utc::now();
        // The body a receiver sees: enough to route and render, nothing
        // secret (the Scrubber has already cleaned `body` before any
        // channel sees it — policy choke-point discipline).
        let payload = json!({
            "source": "opsclaw",
            "body": msg.body,
            "operator": msg.operator,
            "ts": now.timestamp(),
        });
        let raw = serde_json::to_vec(&payload)
            .map_err(|e| crate::Error::other(format!("webhook-out payload encode: {e}")))?;

        let mut req = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(DELIVERY_TIMEOUT)
            .body(raw.clone());
        if let Some(secret) = &self.secret {
            req = req.header(
                "X-Opsclaw-Signature",
                crate::http::webhook::sign_payload(secret.as_bytes(), &raw, now),
            );
        }

        let resp = req.send().await.map_err(|e| {
            crate::Error::other(format!("webhook-out {} unreachable: {e}", self.url))
        })?;
        if !resp.status().is_success() {
            return Err(crate::Error::other(format!(
                "webhook-out {} rejected delivery: HTTP {}",
                self.url,
                resp.status()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    #[tokio::test]
    async fn delivers_the_message_as_json() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let ch = WebhookOutChannel::new(format!("{}/hook", server.uri()), None);
        ch.send(OutboundMessage { operator: None, body: "disk full on web-1".into(), meta: None })
            .await
            .unwrap();

        let received = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(body["source"], "opsclaw");
        assert_eq!(body["body"], "disk full on web-1");
    }

    #[tokio::test]
    async fn signature_verifies_with_the_inbound_side_of_the_same_scheme() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header_exists("X-Opsclaw-Signature"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let ch = WebhookOutChannel::new(server.uri(), Some("shared-secret".into()));
        ch.send(OutboundMessage { operator: None, body: "escalating".into(), meta: None })
            .await
            .unwrap();

        let received: Vec<Request> = server.received_requests().await.unwrap();
        let sig = received[0].headers.get("X-Opsclaw-Signature").unwrap().to_str().unwrap();
        // The OUTBOUND signature must satisfy the INBOUND verifier — the
        // whole point of sharing one scheme in one module.
        crate::http::webhook::verify_signature(
            b"shared-secret",
            sig,
            &received[0].body,
            chrono::Utc::now(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn a_rejected_delivery_is_an_error_not_a_shrug() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(500)).mount(&server).await;

        let ch = WebhookOutChannel::new(server.uri(), None);
        let err = ch
            .send(OutboundMessage { operator: None, body: "x".into(), meta: None })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rejected delivery"), "{err}");
    }

    #[tokio::test]
    async fn no_secret_means_no_signature_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let ch = WebhookOutChannel::new(server.uri(), None);
        ch.send(OutboundMessage { operator: None, body: "x".into(), meta: None }).await.unwrap();

        let received = server.received_requests().await.unwrap();
        assert!(received[0].headers.get("X-Opsclaw-Signature").is_none());
    }
}
