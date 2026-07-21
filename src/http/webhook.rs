//! Inbound webhook ingestion (DESIGN §3: "Webhook ingestion (Alertmanager,
//! PagerDuty) → same orchestrator path as chat; HMAC/token verification
//! with constant-time compare"). HMAC-SHA256 + constant-time-compare are
//! hand-rolled over `sha2` — ported verbatim from gianna's
//! `src/http/stripe.rs` (`hmac_sha256_hex`/`constant_time_eq`) — because
//! neither `hmac` nor `subtle` is a declared dependency (Cargo.toml is
//! frozen for this port) and gianna solved exactly this problem the same
//! way for its Stripe webhook.
//!
//! The alert payload is DATA, never instructions (brief invariant, DESIGN
//! §3 "agent loop": "everything arriving from the outside world mid-
//! diagnosis... is data, not instructions"). This module's only job is
//! verify + parse + hand off; it never decides what happens next — that is
//! [`IngestAlert::ingest`]'s job, seamed behind a trait for the same reason
//! `scheduler::JobComposer` was seamed: the agent loop/incident-opening
//! path this hands off to is built concurrently by another module and not
//! yet available to depend on directly.

use async_trait::async_trait;
use serde_json::Value;

use crate::{Error, Result};

/// What a verified webhook hands off to. A minimal seam — parsed alert
/// text plus the raw payload for a caller that wants more structure than
/// this module extracts. Mirrors the shape `scheduler::JobComposer` uses:
/// a trait with a single async method, a recording/noop fake for tests,
/// and the real implementation (agent-loop-backed incident opening) wired
/// in by main-session integration once that module lands.
#[async_trait]
pub trait IngestAlert: Send + Sync {
    /// `source` identifies the webhook route (`"alertmanager"`,
    /// `"pagerduty"`, …) so a downstream consumer can apply source-specific
    /// parsing without this module needing to know their shapes.
    async fn ingest(&self, source: &str, payload: &Value) -> Result<()>;
}

/// The fail-open-to-nothing default: every ingested alert is accepted
/// (200) and silently dropped. Never a failure — proves the HMAC/parse
/// scaffolding works with no incident engine wired in, not a real sink.
pub struct NoopIngest;

#[async_trait]
impl IngestAlert for NoopIngest {
    async fn ingest(&self, _source: &str, _payload: &Value) -> Result<()> {
        Ok(())
    }
}

/// HMAC-SHA256 (RFC 2104) implemented over `sha2` to avoid an extra
/// dependency — verbatim port of gianna's `stripe.rs::hmac_sha256_hex`.
fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = Sha256::digest(key);
        k[..h.len()].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let out = outer.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time byte comparison — verbatim port of gianna's
/// `stripe.rs::constant_time_eq`. Prevents a timing side-channel from
/// leaking how many leading bytes of a guessed signature matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// How stale a signed timestamp may be before a signature is rejected as a
/// replay, even with a valid HMAC (a captured webhook must not be
/// replayable forever). Mirrors gianna's Stripe replay tolerance.
const REPLAY_WINDOW_SECS: i64 = 300;

/// Verify a `t=<unix_ts>,v1=<hmac_hex>` style signature (Alertmanager has
/// no native HMAC signature of its own — this is the convention a
/// reverse-proxy/relay in front of it, or a custom receiver, is expected
/// to add; documented at the call site). `body` is the exact raw request
/// bytes the signature was computed over. Returns `Ok(())` when the
/// signature is valid AND its timestamp is within [`REPLAY_WINDOW_SECS`]
/// of `now`.
pub fn verify_signature(secret: &[u8], header: &str, body: &[u8], now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    let (t, v1) = parse_sig(header).ok_or_else(|| Error::unauthorized("unparseable webhook signature"))?;
    let signed_payload = [t.as_bytes(), b".", body].concat();
    let expected = hmac_sha256_hex(secret, &signed_payload);
    if !constant_time_eq(expected.as_bytes(), v1.as_bytes()) {
        return Err(Error::unauthorized("webhook signature mismatch"));
    }
    let ts: i64 = t.parse().map_err(|_| Error::unauthorized("bad signature timestamp"))?;
    if (now.timestamp() - ts).abs() > REPLAY_WINDOW_SECS {
        return Err(Error::unauthorized("stale webhook signature (replay window exceeded)"));
    }
    Ok(())
}

fn parse_sig(sig: &str) -> Option<(String, String)> {
    let (mut t, mut v1) = (None, None);
    for part in sig.split(',') {
        if let Some(v) = part.strip_prefix("t=") {
            t = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("v1=") {
            v1 = Some(v.to_string());
        }
    }
    Some((t?, v1?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sign(secret: &[u8], ts: i64, body: &[u8]) -> String {
        let signed = [ts.to_string().as_bytes(), b".", body].concat();
        format!("t={ts},v1={}", hmac_sha256_hex(secret, &signed))
    }

    #[test]
    fn valid_signature_within_window_is_accepted() {
        let now = Utc::now();
        let body = br#"{"alerts":[]}"#;
        let header = sign(b"shhh", now.timestamp(), body);
        verify_signature(b"shhh", &header, body, now).unwrap();
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let now = Utc::now();
        let body = b"payload";
        let header = sign(b"real-secret", now.timestamp(), body);
        let err = verify_signature(b"wrong-secret", &header, body, now).unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn tampered_body_is_rejected() {
        let now = Utc::now();
        let header = sign(b"shhh", now.timestamp(), b"original body");
        let err = verify_signature(b"shhh", &header, b"tampered body", now).unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn stale_timestamp_outside_replay_window_is_rejected_even_with_valid_hmac() {
        let now = Utc::now();
        let body = b"payload";
        let stale = now - chrono::Duration::seconds(REPLAY_WINDOW_SECS + 1);
        let header = sign(b"shhh", stale.timestamp(), body);
        let err = verify_signature(b"shhh", &header, body, now).unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn timestamp_just_inside_the_window_is_accepted() {
        let now = Utc::now();
        let body = b"payload";
        let almost_stale = now - chrono::Duration::seconds(REPLAY_WINDOW_SECS - 1);
        let header = sign(b"shhh", almost_stale.timestamp(), body);
        verify_signature(b"shhh", &header, body, now).unwrap();
    }

    #[test]
    fn unparseable_header_is_rejected() {
        let now = Utc::now();
        let err = verify_signature(b"shhh", "garbage", b"body", now).unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));

        let err = verify_signature(b"shhh", "t=123", b"body", now).unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)), "missing v1 must be rejected");
    }

    #[test]
    fn constant_time_eq_matches_naive_equality_but_short_circuits_on_length() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[tokio::test]
    async fn noop_ingest_accepts_and_drops() {
        let sink = NoopIngest;
        sink.ingest("alertmanager", &serde_json::json!({"alerts": []})).await.unwrap();
    }
}
