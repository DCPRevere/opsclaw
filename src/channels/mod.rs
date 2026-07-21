//! Message delivery abstraction. The trait is gianna's `Channel`, near
//! verbatim: only `name` and `send` are mandatory so adding a channel is a
//! small diff. Wave 1 ports Telegram (long-polling; offset persisted only
//! after genuine hand-off), the CLI capture channel, and `RecordingChannel`;
//! the web SSE hub and web push land with the web UI (Wave 4).

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
