//! Web push — the lock-screen path for incident alerts and approval requests
//! (DESIGN §3 channels + §4 HTTP gateway PWA/push paragraphs: "Web push
//! (gianna's `push.rs` ported) is a send-only channel behind the same
//! trait... deep-linking into the installed PWA's approval screen").
//!
//! Ported from gianna's `src/push.rs`. Kept: the `PushSender` trait seam
//! (VAPID + RFC 8291 encryption hidden behind it so `PushChannel` itself is
//! testable with a fake), the 404/410-prunes-the-subscription rule, and
//! 401/403 being treated as a loud CONFIGURATION error rather than a dead
//! endpoint (gianna's comment: almost always a VAPID public/private key
//! mismatch — pruning would hide a fleet-wide outage instead of surfacing
//! it). Changed for opsclaw's single-tenant shape (DESIGN §1: no household/
//! member scoping — one team, one shared subscription set):
//!   - `can_reach`/`send` iterate every stored [`crate::db::PushSubscription`]
//!     rather than household-scoped rows; there is no per-device
//!     alerts-enabled toggle (gianna's `sub.alerts_enabled`) — opsclaw has no
//!     analog yet, so every stored subscription is live.
//!   - The notification payload carries `title`/`body`/`url` (not just
//!     `body`) so the service worker can deep-link into the right PWA screen
//!     (`/approvals`, `/incidents`, …) rather than always opening `/app`.
//!     The target url comes from the structured `OutboundMessage.meta`
//!     `"kind"` when the sender attached one ([`deep_link`]), with
//!     [`infer_deep_link`]'s body heuristic as the meta-less fallback.
//!   - Push is BEST-EFFORT by design (DESIGN §3 decision 5: "Telegram/webhook
//!     are the guaranteed escalation paths; push is the convenient one") —
//!     `send` never returns an error for an individual subscription's
//!     failure; only a fatal repo-read error surfaces (matching
//!     `Channel::send`'s Ok(()) contract that `MultiChannel::send` already
//!     relies on to keep fanning out to the other channels).

use async_trait::async_trait;
use std::sync::Arc;

use crate::channels::{Channel, OutboundMessage};
use crate::db::{PushSubscription, PushSubscriptionRepo};
use crate::{Error, Result};

/// Delivery outcome the channel cares about: delivered, or the subscription
/// is dead and should be pruned (endpoint Gone/expired at the push service).
pub enum PushOutcome {
    Delivered,
    SubscriptionGone,
}

#[async_trait]
pub trait PushSender: Send + Sync {
    async fn send(&self, sub: &PushSubscription, payload: &str) -> Result<PushOutcome>;
}

/// Records pushes for tests; never actually calls out over the network.
#[derive(Clone, Default)]
pub struct FakePushSender {
    sent: Arc<std::sync::Mutex<Vec<(String, String)>>>, // (endpoint, payload)
}

impl FakePushSender {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn sent(&self) -> Vec<(String, String)> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl PushSender for FakePushSender {
    async fn send(&self, sub: &PushSubscription, payload: &str) -> Result<PushOutcome> {
        tracing::info!(endpoint = %sub.endpoint, "PUSH (fake): {payload}");
        self.sent.lock().unwrap().push((sub.endpoint.clone(), payload.to_string()));
        // Endpoints containing "gone" simulate an expired subscription so the
        // pruning path is testable without a real push service.
        if sub.endpoint.contains("gone") {
            return Ok(PushOutcome::SubscriptionGone);
        }
        Ok(PushOutcome::Delivered)
    }
}

/// Verify the configured VAPID public key is the genuine pair of the private
/// key. The browser subscribes with the public key (`applicationServerKey`)
/// and the server signs the VAPID JWT with the private key; if they don't
/// match, the push service rejects every send with 403 — silently, from the
/// operator's side. Catching it at boot turns a slow, invisible outage into a
/// loud startup error. Both inputs are URL-safe base64: the private key is
/// the 32-byte P-256 scalar, the public key the 65-byte uncompressed SEC1
/// point (`0x04`-prefixed) — the same encoding `cli::vapid::generate`
/// produces.
pub fn validate_vapid_pair(
    private_key_b64: &str,
    public_key_b64: &str,
) -> std::result::Result<(), String> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use web_push_native::p256::elliptic_curve::sec1::ToEncodedPoint;
    let priv_bytes = URL_SAFE_NO_PAD
        .decode(private_key_b64)
        .map_err(|e| format!("vapid_private_key is not valid URL-safe base64: {e}"))?;
    let secret = web_push_native::p256::SecretKey::from_slice(&priv_bytes)
        .map_err(|e| format!("vapid_private_key is not a valid P-256 private key: {e}"))?;
    let configured = URL_SAFE_NO_PAD
        .decode(public_key_b64)
        .map_err(|e| format!("vapid_public_key is not valid URL-safe base64: {e}"))?;
    let derived = secret.public_key().to_encoded_point(false); // false = uncompressed
    if derived.as_bytes() != configured.as_slice() {
        return Err("vapid_public_key is not the pair of vapid_private_key — browsers would \
             subscribe with a key the server can't sign for, so every push is rejected. \
             Re-derive the public key from the private key, or regenerate the pair."
            .to_string());
    }
    Ok(())
}

/// The real sender: VAPID-signed, RFC 8291-encrypted Web Push, sent over the
/// same rustls reqwest stack as everything else (no openssl —
/// `web-push-native` is RustCrypto-based).
pub struct WebPushSender {
    client: reqwest::Client,
    key_pair: web_push_native::jwt_simple::algorithms::ES256KeyPair,
}

impl WebPushSender {
    /// `private_key_b64`: the raw P-256 scalar, URL-safe base64 (the standard
    /// VAPID private-key format; already resolved from the secret store by
    /// the caller — this type never touches `SecretStore` itself,
    /// constructor discipline matching `TelegramChannel::new`). Errors
    /// (rather than panics — unlike gianna, this is a boot-path `Result`,
    /// not a lazily-constructed global) if the key is malformed.
    pub fn new(private_key_b64: &str) -> Result<Self> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let bytes = URL_SAFE_NO_PAD
            .decode(private_key_b64)
            .map_err(|e| Error::Config(format!("vapid_private_key: invalid base64: {e}")))?;
        let key_pair = web_push_native::jwt_simple::algorithms::ES256KeyPair::from_bytes(&bytes)
            .map_err(|e| Error::Config(format!("vapid_private_key: not a valid P-256 key: {e}")))?;
        Ok(Self { client: reqwest::Client::new(), key_pair })
    }
}

#[async_trait]
impl PushSender for WebPushSender {
    async fn send(&self, sub: &PushSubscription, payload: &str) -> Result<PushOutcome> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let p256dh = URL_SAFE_NO_PAD
            .decode(&sub.p256dh)
            .map_err(|e| Error::other(format!("push p256dh: {e}")))?;
        let auth = URL_SAFE_NO_PAD
            .decode(&sub.auth)
            .map_err(|e| Error::other(format!("push auth: {e}")))?;
        let builder = web_push_native::WebPushBuilder::new(
            sub.endpoint.parse().map_err(|e| Error::other(format!("push endpoint: {e}")))?,
            web_push_native::p256::PublicKey::from_sec1_bytes(&p256dh)
                .map_err(|e| Error::other(format!("push key: {e}")))?,
            web_push_native::Auth::clone_from_slice(&auth),
        )
        .with_vapid(&self.key_pair, "mailto:ops@opsclaw.io");
        let request = builder
            .build(payload.as_bytes().to_vec())
            .map_err(|e| Error::other(format!("push build: {e}")))?;
        let request = reqwest::Request::try_from(request)
            .map_err(|e| Error::other(format!("push request: {e}")))?;
        let resp = self
            .client
            .execute(request)
            .await
            .map_err(|e| Error::other(format!("push send: {e}")))?;
        match resp.status().as_u16() {
            200..=299 => Ok(PushOutcome::Delivered),
            404 | 410 => Ok(PushOutcome::SubscriptionGone),
            // 401/403 is an AUTH failure, not a dead endpoint — almost always
            // a VAPID public/private mismatch. Don't prune the subscription
            // (it's fine; our signing is wrong); surface it loudly so a
            // fleet-wide "no notifications" outage is diagnosable at a
            // glance instead of silently eating every subscription.
            code @ (401 | 403) => {
                let body = resp.text().await.unwrap_or_default();
                tracing::error!(
                    "push: {code} from the push service — usually a VAPID key mismatch \
                     (public served to clients != private used to sign). Body: {body}"
                );
                Err(Error::other(format!("push auth rejected ({code})")))
            }
            code => Err(Error::other(format!(
                "push service returned {code}: {}",
                resp.text().await.unwrap_or_default()
            ))),
        }
    }
}

/// The outbound channel: fans a proactive message out to every stored
/// subscription and prunes dead subscriptions as the push services report
/// them. Send-only (DESIGN §3: the `Channel` trait's `send_reply` default
/// no-op is exactly right here — a push notification is never a reply
/// surface, replies render in the open app via the web/SSE channel).
pub struct PushChannel {
    repo: Arc<dyn PushSubscriptionRepo>,
    sender: Arc<dyn PushSender>,
}

impl PushChannel {
    pub fn new(repo: Arc<dyn PushSubscriptionRepo>, sender: Arc<dyn PushSender>) -> Self {
        Self { repo, sender }
    }
}

/// Notification payload character budget: notification payloads are small
/// (the full text lives in the app once opened); mirrors gianna's 360-char
/// truncation with an ellipsis + pointer.
const BODY_CHAR_BUDGET: usize = 360;
const BODY_CHAR_CUT: usize = 340;

/// Which PWA screen a push should deep-link into (brief: "approvals →
/// /approvals etc."). The escalation driver and approval announcer both
/// attach a structured twin (`OutboundMessage.meta` with `"kind":
/// "incident"` / `"kind": "approval"` — `scheduler::escalations::drive_one`,
/// `policy::announce_approval`), which is authoritative when present;
/// meta-less senders fall back to [`infer_deep_link`]'s body heuristic.
fn deep_link(meta: Option<&serde_json::Value>, body: &str) -> &'static str {
    match meta.and_then(|m| m.get("kind")).and_then(|k| k.as_str()) {
        Some("incident") => "/app#incidents",
        Some("approval") => "/app#approvals",
        _ => infer_deep_link(body),
    }
}

/// Best-effort fallback for messages with no structured `meta.kind`: keys
/// off a case-insensitive substring of the body, which is how the agent's
/// own composed messages are worded (see `incidents::` / `policy::` message
/// templates). Falls back to the app shell itself when nothing matches —
/// always a safe landing spot.
fn infer_deep_link(body: &str) -> &'static str {
    let lower = body.to_ascii_lowercase();
    if lower.contains("approval") {
        "/app#approvals"
    } else if lower.contains("incident") {
        "/app#incidents"
    } else {
        "/app"
    }
}

#[async_trait]
impl Channel for PushChannel {
    fn name(&self) -> &str {
        "push"
    }

    /// Reachable iff at least one subscription is stored — opsclaw has no
    /// per-operator/per-device addressing yet (see module doc), so every
    /// stored device is a candidate for every message.
    async fn can_reach(&self, _operator: Option<uuid::Uuid>) -> bool {
        match self.repo.list_push_subscriptions().await {
            Ok(subs) => !subs.is_empty(),
            Err(e) => {
                tracing::warn!("push reachability read failed: {e}");
                false
            }
        }
    }

    async fn send(&self, msg: OutboundMessage) -> Result<()> {
        let subs = self.repo.list_push_subscriptions().await?;
        if subs.is_empty() {
            return Ok(());
        }
        let body: String = if msg.body.chars().count() > BODY_CHAR_BUDGET {
            let cut: String = msg.body.chars().take(BODY_CHAR_CUT).collect();
            format!("{cut}… (open OpsClaw for the rest)")
        } else {
            msg.body.clone()
        };
        let url = deep_link(msg.meta.as_ref(), &msg.body);
        let payload =
            serde_json::json!({ "title": "OpsClaw", "body": body, "url": url }).to_string();
        for sub in subs {
            // Push is BEST-EFFORT by design (DESIGN §3 decision 5) — a
            // single subscription's failure is logged and skipped, never
            // propagated to abort the rest of the fan-out or the caller
            // (Telegram/webhook are the guaranteed paths; this one never
            // gets to hold up or fail the whole `send`).
            //
            // NB: never log sub.endpoint — a Web Push endpoint is a
            // delivery capability token (anyone holding it can push to that
            // device).
            match self.sender.send(&sub, &payload).await {
                Ok(PushOutcome::Delivered) => {}
                Ok(PushOutcome::SubscriptionGone) => {
                    tracing::info!("pruning a dead push subscription");
                    if let Err(e) = self.repo.delete_push_subscription(&sub.endpoint).await {
                        tracing::warn!("failed to prune dead push subscription: {e}");
                    }
                }
                Err(e) => {
                    tracing::warn!("push send failed: {e}");
                }
            }
        }
        Ok(())
    }

    async fn send_reply(&self, _sender: &str, _text: &str) -> Result<()> {
        // Replies render in the open app; push is for proactive sends only.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory::InMemoryDb;
    use uuid::Uuid;

    #[test]
    fn vapid_pair_validation_accepts_a_real_pair_and_rejects_a_mismatch() {
        let kp1 = crate::cli::vapid::generate();
        let kp2 = crate::cli::vapid::generate();

        assert!(
            validate_vapid_pair(&kp1.private_key, &kp1.public_key).is_ok(),
            "a real pair must validate"
        );
        assert!(
            validate_vapid_pair(&kp1.private_key, &kp2.public_key).is_err(),
            "a mismatched public key must fail"
        );
        assert!(validate_vapid_pair("not-base64!!", &kp1.public_key).is_err());
        assert!(validate_vapid_pair(&kp1.private_key, "not-base64!!").is_err());
    }

    #[test]
    fn deep_link_inference_matches_message_wording() {
        assert_eq!(infer_deep_link("New approval requested: restart web-1"), "/app#approvals");
        assert_eq!(infer_deep_link("Incident opened: cpu 98% on cluster"), "/app#incidents");
        assert_eq!(infer_deep_link("hello from the agent"), "/app");
    }

    #[test]
    fn structured_meta_kind_is_authoritative_over_the_body_heuristic() {
        // The escalation driver / approval announcer attach meta.kind; it
        // wins even when the body wording would infer differently.
        let incident = serde_json::json!({ "kind": "incident" });
        let approval = serde_json::json!({ "kind": "approval" });
        assert_eq!(deep_link(Some(&incident), "needs approval soon"), "/app#incidents");
        assert_eq!(deep_link(Some(&approval), "incident context here"), "/app#approvals");
        // Unknown kinds and absent meta fall back to the body heuristic.
        let other = serde_json::json!({ "kind": "digest" });
        assert_eq!(deep_link(Some(&other), "Incident opened"), "/app#incidents");
        assert_eq!(deep_link(None, "hello"), "/app");
    }

    fn sub(endpoint: &str) -> PushSubscription {
        PushSubscription {
            endpoint: endpoint.into(),
            account_id: Uuid::new_v4(),
            p256dh: "k".into(),
            auth: "a".into(),
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn fans_out_and_prunes_dead_endpoints() {
        let db = Arc::new(InMemoryDb::new());
        let repo: Arc<dyn PushSubscriptionRepo> = db.clone();
        let fake = Arc::new(FakePushSender::new());
        let ch = PushChannel::new(repo.clone(), fake.clone());

        repo.upsert_push_subscription(&sub("https://push.example/alive-1")).await.unwrap();
        repo.upsert_push_subscription(&sub("https://push.example/alive-2")).await.unwrap();
        repo.upsert_push_subscription(&sub("https://push.example/gone")).await.unwrap();

        ch.send(OutboundMessage {
            operator: None,
            body: "New approval requested".into(),
            meta: None,
        })
        .await
        .unwrap();

        let eps: Vec<_> = fake.sent().iter().map(|(e, _)| e.clone()).collect();
        assert!(eps.iter().any(|e| e.contains("alive-1")));
        assert!(eps.iter().any(|e| e.contains("alive-2")));
        assert!(eps.iter().any(|e| e.contains("gone")));
        // The dead one was pruned after being attempted.
        assert_eq!(repo.list_push_subscriptions().await.unwrap().len(), 2, "dead endpoint pruned");

        let payload = &fake.sent()[0].1;
        assert!(payload.contains("\"title\":\"OpsClaw\""));
        assert!(payload.contains("/app#approvals"));
    }

    #[tokio::test]
    async fn long_bodies_are_truncated_into_notification_sized_payloads() {
        let db = Arc::new(InMemoryDb::new());
        let repo: Arc<dyn PushSubscriptionRepo> = db.clone();
        let fake = Arc::new(FakePushSender::new());
        let ch = PushChannel::new(repo.clone(), fake.clone());
        repo.upsert_push_subscription(&sub("https://push.example/one")).await.unwrap();

        ch.send(OutboundMessage { operator: None, body: "x".repeat(1000), meta: None })
            .await
            .unwrap();
        assert!(fake.sent().last().unwrap().1.contains("open OpsClaw for the rest"));
    }

    #[tokio::test]
    async fn send_is_a_noop_with_no_subscriptions() {
        let db = Arc::new(InMemoryDb::new());
        let repo: Arc<dyn PushSubscriptionRepo> = db.clone();
        let fake = Arc::new(FakePushSender::new());
        let ch = PushChannel::new(repo, fake.clone());

        let r = ch.send(OutboundMessage { operator: None, body: "hi".into(), meta: None }).await;
        assert!(r.is_ok());
        assert!(fake.sent().is_empty());
    }

    #[tokio::test]
    async fn can_reach_reflects_subscription_presence() {
        let db = Arc::new(InMemoryDb::new());
        let repo: Arc<dyn PushSubscriptionRepo> = db.clone();
        let fake = Arc::new(FakePushSender::new());
        let ch = PushChannel::new(repo.clone(), fake);

        assert!(!ch.can_reach(None).await);
        repo.upsert_push_subscription(&sub("https://push.example/one")).await.unwrap();
        assert!(ch.can_reach(None).await);
        assert!(ch.can_reach(Some(Uuid::new_v4())).await, "no per-operator addressing yet");
    }

    #[tokio::test]
    async fn one_failing_subscription_does_not_abort_the_rest_of_the_fanout() {
        struct FlakySender;
        #[async_trait]
        impl PushSender for FlakySender {
            async fn send(&self, sub: &PushSubscription, _payload: &str) -> Result<PushOutcome> {
                if sub.endpoint.contains("bad") {
                    return Err(Error::other("simulated push failure"));
                }
                Ok(PushOutcome::Delivered)
            }
        }

        let db = Arc::new(InMemoryDb::new());
        let repo: Arc<dyn PushSubscriptionRepo> = db.clone();
        let ch = PushChannel::new(repo.clone(), Arc::new(FlakySender));
        repo.upsert_push_subscription(&sub("https://push.example/bad")).await.unwrap();
        repo.upsert_push_subscription(&sub("https://push.example/ok")).await.unwrap();

        // A hard sender error for one subscription must not fail `send` as a
        // whole (best-effort by design) — the good subscription is still
        // stored (its own send succeeded; nothing was pruned since the
        // failure wasn't a SubscriptionGone outcome).
        let r = ch.send(OutboundMessage { operator: None, body: "hi".into(), meta: None }).await;
        assert!(r.is_ok());
        assert_eq!(repo.list_push_subscriptions().await.unwrap().len(), 2);
    }
}
