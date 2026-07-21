//! Message delivery abstraction. The trait is gianna's `Channel`, near
//! verbatim: only `name` and `send` are mandatory so adding a channel is a
//! small diff. Wave 1 ports Telegram (long-polling; offset persisted only
//! after genuine hand-off), the CLI capture channel, and `RecordingChannel`;
//! the web SSE hub and web push land with the web UI (Wave 4).
//!
//! Trait-surface additions over the frozen shape (all DEFAULTED, no existing
//! signature touched): `send_typing`, `self_handle`, `drop_self_messages`.
//! Ported verbatim from gianna's `Channel` — Telegram's self-message guard
//! and typing indicator need them, and every other channel gets a free
//! no-op default.

pub mod cli;
pub mod recording;
pub mod telegram;

use async_trait::async_trait;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::Result;

/// A message leaving the daemon toward operators.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// Specific operator, or None for the whole team channel.
    pub operator: Option<Uuid>,
    pub body: String,
}

/// A message arriving from an operator on some channel.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// Channel-local sender handle (telegram chat id, account id, "cli").
    pub sender: String,
    pub body: String,
    /// Channel identity = `Channel::name()` string; no enum (gianna pattern).
    pub channel: String,
}

#[async_trait]
pub trait Channel: Send + Sync {
    fn name(&self) -> &str;

    async fn send(&self, msg: OutboundMessage) -> Result<()>;

    /// Reply to a specific sender handle on this channel.
    async fn send_reply(&self, _sender: &str, _text: &str) -> Result<()> {
        Ok(())
    }

    /// Whether this channel can currently reach the given operator.
    async fn can_reach(&self, _operator: Option<Uuid>) -> bool {
        true
    }

    /// Long-running listener pushing inbound messages; default no-op for
    /// send-only channels (webhook-out, push).
    async fn listen(&self, _tx: mpsc::Sender<InboundMessage>) -> Result<()> {
        Ok(())
    }

    /// Best-effort "typing…" presence hint while a reply is being composed.
    /// Default no-op; channels with a native indicator (Telegram) implement
    /// it. DEFAULTED addition (gianna parity) — not on the original frozen
    /// signature list.
    async fn send_typing(&self, _sender: &str) {}

    /// The bot's own identity on this channel, if known — so callers can drop
    /// inbound events the bot itself authored (self-loop guard). DEFAULTED
    /// addition (gianna parity).
    fn self_handle(&self) -> Option<String> {
        None
    }

    /// Whether an inbound message is self-authored (default compares
    /// `sender` against `self_handle`, case-insensitively, ignoring a
    /// leading `@`). DEFAULTED addition (gianna parity).
    fn drop_self_messages(&self, msg: &InboundMessage) -> bool {
        let Some(handle) = self.self_handle() else {
            return false;
        };
        let h = handle.trim_start_matches('@').to_ascii_lowercase();
        let s = msg.sender.trim_start_matches('@').to_ascii_lowercase();
        !h.is_empty() && h == s
    }
}

/// Fan-out over every configured channel (gianna's `MultiChannel`).
pub struct MultiChannel {
    channels: Vec<std::sync::Arc<dyn Channel>>,
}

impl MultiChannel {
    pub fn new(channels: Vec<std::sync::Arc<dyn Channel>>) -> Self {
        MultiChannel { channels }
    }
}

#[async_trait]
impl Channel for MultiChannel {
    fn name(&self) -> &str {
        "multi"
    }

    async fn send(&self, msg: OutboundMessage) -> Result<()> {
        for ch in &self.channels {
            if let Err(e) = ch.send(msg.clone()).await {
                tracing::warn!(channel = ch.name(), error = %e, "channel send failed");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::recording::RecordingChannel;

    /// A channel whose `send` always fails, to prove one bad channel doesn't
    /// stop fan-out to the others.
    struct FailingChannel;

    #[async_trait]
    impl Channel for FailingChannel {
        fn name(&self) -> &str {
            "failing"
        }
        async fn send(&self, _msg: OutboundMessage) -> Result<()> {
            Err(crate::Error::other("boom"))
        }
    }

    #[tokio::test]
    async fn multi_channel_fanout_survives_one_failing_channel() {
        let recording = std::sync::Arc::new(RecordingChannel::new());
        let multi = MultiChannel::new(vec![std::sync::Arc::new(FailingChannel), recording.clone()]);

        let msg = OutboundMessage { operator: None, body: "hello".into() };
        let r = multi.send(msg).await;

        // MultiChannel::send is best-effort fan-out: it must still return Ok
        // even though one underlying channel failed...
        assert!(r.is_ok());
        // ...and the other channel must still have received the message.
        assert_eq!(recording.sent().len(), 1);
        assert_eq!(recording.last().unwrap().body, "hello");
    }
}
