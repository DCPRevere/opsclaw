//! The web SSE channel (DESIGN §3: "the web SSE hub... land with the web UI
//! (Wave 4)"). A broadcast hub any number of connected browser tabs
//! subscribe to; `Channel::send` publishes one [`WebEvent`] per outbound
//! message. Ported in spirit from gianna's `state.web`/`subscribe_as`
//! (`src/http/state.rs`, `chat_api.rs`) — simplified because opsclaw has no
//! per-member scoping (single-tenant, every operator sees the same team-
//! wide stream) where gianna's hub filtered by household+member.
//!
//! The actual auth (short-lived signed stream tickets) lives in
//! `http::sse` — this module is transport only: a `tokio::sync::broadcast`
//! channel plus the `Channel` trait adapter.

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::Result;
use crate::channels::{Channel, OutboundMessage};

/// One event pushed down the SSE stream. `kind` is a stable, low-cardinality
/// tag (`"message"`, `"incident"`, `"approval"`, `"status"`) so the client's
/// `EventSource` listener can dispatch without parsing the body first.
#[derive(Debug, Clone, Serialize)]
pub struct WebEvent {
    pub kind: &'static str,
    pub body: serde_json::Value,
}

impl WebEvent {
    pub fn message(text: &str) -> Self {
        WebEvent { kind: "message", body: serde_json::json!({ "text": text }) }
    }

    /// A chat-turn event (`http::routes::chat`'s broadcast after a turn
    /// completes) — kind `"chat"`, distinct from the generic `"message"`
    /// kind so the client can render it in the shared chat log specifically
    /// rather than lumping it in with any other proactive push notice.
    /// `role` is `"user"` or `"assistant"` (matches `ChatHandler::
    /// transcript`'s pairs, so a client's render function is the same
    /// whether the text came from history or from this live event);
    /// `speaker` is the attribution label (`"assistant"` for the reply, the
    /// operator's display name for their own message).
    pub fn chat(role: &str, speaker: &str, text: &str) -> Self {
        WebEvent {
            kind: "chat",
            body: serde_json::json!({ "role": role, "speaker": speaker, "text": text }),
        }
    }
}

/// Bounded broadcast hub. `capacity` is generous (a slow/disconnected
/// subscriber lags rather than blocking a sender — `RecvError::Lagged` is
/// handled at the SSE handler, which logs and continues) — matching
/// gianna's stance that a dropped proactive event is recoverable (the
/// client re-syncs via a REST read) where a blocked publisher is not.
pub struct WebHub {
    tx: broadcast::Sender<WebEvent>,
}

impl WebHub {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(256);
        WebHub { tx }
    }

    /// A fresh receiver for a newly connected SSE stream. Every subscriber
    /// gets every event (no per-operator scoping — DESIGN §1: single-tenant,
    /// team-shared state) — the client filters by `kind` if it only cares
    /// about some events.
    pub fn subscribe(&self) -> broadcast::Receiver<WebEvent> {
        self.tx.subscribe()
    }

    pub fn publish(&self, event: WebEvent) {
        // No subscribers is not an error (nobody has a tab open) — `send`
        // returning Err just means the channel is momentarily empty.
        let _ = self.tx.send(event);
    }
}

impl Default for WebHub {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Channel for WebHub {
    fn name(&self) -> &str {
        "web"
    }

    async fn send(&self, msg: OutboundMessage) -> Result<()> {
        // Structured announcements (OutboundMessage.meta with a known
        // "kind") become their own SSE event kind so the client can render
        // an ACTIONABLE card (inline approve/deny, acknowledge) instead of
        // plain text. `kind` must map to one of the static strings below —
        // an unknown kind degrades to a plain message, never an error (the
        // body always stands alone by OutboundMessage's contract). The text
        // body rides along in the payload so the card can fall back to it.
        if let Some(meta) = &msg.meta
            && let Some(kind) = meta.get("kind").and_then(|k| k.as_str())
        {
            let stable: Option<&'static str> = match kind {
                "approval" => Some("approval"),
                "incident" => Some("incident"),
                _ => None,
            };
            if let Some(kind) = stable {
                let mut body = meta.clone();
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("text".into(), serde_json::json!(msg.body));
                }
                self.publish(WebEvent { kind, body });
                return Ok(());
            }
        }
        self.publish(WebEvent::message(&msg.body));
        Ok(())
    }

    /// A tab is open iff at least one subscriber is attached — best-effort
    /// (a subscriber that's open but the tab is backgrounded still counts,
    /// matching gianna's "a spouse's tab must not count" caution the other
    /// direction: this errs toward "reachable" rather than silently
    /// dropping alerts a human might still see).
    async fn can_reach(&self, _operator: Option<Uuid>) -> bool {
        self.tx.receiver_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_reaches_every_subscriber() {
        let hub = WebHub::new();
        let mut a = hub.subscribe();
        let mut b = hub.subscribe();

        hub.send(OutboundMessage { operator: None, body: "hello".into(), meta: None })
            .await
            .unwrap();

        let ev_a = a.recv().await.unwrap();
        let ev_b = b.recv().await.unwrap();
        assert_eq!(ev_a.kind, "message");
        assert_eq!(ev_b.kind, "message");
    }

    #[tokio::test]
    async fn can_reach_reflects_subscriber_count() {
        let hub = WebHub::new();
        assert!(!hub.can_reach(None).await, "no subscribers yet");
        let _rx = hub.subscribe();
        assert!(hub.can_reach(None).await);
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_does_not_error() {
        let hub = WebHub::new();
        hub.send(OutboundMessage { operator: None, body: "into the void".into(), meta: None })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn structured_meta_becomes_its_own_event_kind_with_text_fallback() {
        let hub = WebHub::new();
        let mut rx = hub.subscribe();
        hub.send(OutboundMessage {
            operator: None,
            body: "APPROVAL NEEDED …".into(),
            meta: Some(serde_json::json!({"kind": "approval", "id": "abc"})),
        })
        .await
        .unwrap();
        // An UNKNOWN kind must degrade to a plain message (the body always
        // stands alone), never error or emit a kind the client won't know.
        hub.send(OutboundMessage {
            operator: None,
            body: "plain".into(),
            meta: Some(serde_json::json!({"kind": "mystery"})),
        })
        .await
        .unwrap();

        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.kind, "approval");
        assert_eq!(ev.body["id"], "abc");
        assert_eq!(ev.body["text"], "APPROVAL NEEDED …", "body rides along for fallback render");
        let ev2 = rx.recv().await.unwrap();
        assert_eq!(ev2.kind, "message");
        assert_eq!(ev2.body["text"], "plain");
    }
}
