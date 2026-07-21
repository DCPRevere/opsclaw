//! Message delivery abstraction. The trait is gianna's `Channel`, near
//! verbatim: only `name` and `send` are mandatory so adding a channel is a
//! small diff. Wave 1 ports Telegram (long-polling; offset persisted only
//! after genuine hand-off), the CLI capture channel, and `RecordingChannel`.
//! [`web::WebHub`] (Wave 4) is the SSE-backed channel; its ticket-based auth
//! lives in `http::sse`. Web push is a later addition, not yet landed.
//!
//! Trait-surface additions over the frozen shape (all DEFAULTED, no existing
//! signature touched): `send_typing`, `self_handle`, `drop_self_messages`.
//! Ported verbatim from gianna's `Channel` — Telegram's self-message guard
//! and typing indicator need them, and every other channel gets a free
//! no-op default.

pub mod cli;
pub mod inbound;
pub mod recording;
pub mod telegram;
pub mod web;

use async_trait::async_trait;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::Result;
use crate::domain::Principal;

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

    /// Resolve an inbound sender handle to a bound OPERATOR ACCOUNT —
    /// the channel-side half of the trust boundary for channel-originated
    /// chat: an inbound message may only drive a chat turn under a
    /// `Principal::Operator` this method vouches for (Telegram resolves
    /// through its roster allowlist). Default `None` = this channel cannot
    /// vouch for senders, so [`inbound`]'s consumer loop refuses the
    /// message (fail closed) — correct for send-only channels and for the
    /// web channel, whose inbound path is the authenticated HTTP chat
    /// route, never this loop. DEFAULTED addition.
    async fn resolve_operator(&self, _sender: &str) -> Option<Uuid> {
        None
    }
}

/// The chat seam: one conversational turn against the team's agent, from
/// any surface — a channel's inbound loop ([`inbound`]), the gateway's
/// chat route, or the CLI REPL. Same shape as `scheduler::JobComposer` and
/// `http::webhook::IngestAlert`: consumers hold the trait, the real
/// agent-backed impl (`agent::dispatch`'s chat entry) is swapped in by
/// `boot::daemon_state`, and the boot-safe default is [`NoopChat`].
///
/// `principal` is TRUSTED POSITIONAL context resolved by the caller (an
/// authenticated account on the HTTP path, a roster-vouched binding via
/// [`Channel::resolve_operator`] on the channel path) — never derived from
/// the message. `speaker` is a display label for attribution only
/// (memory framing "`{operator}` said: …", DESIGN §3 memory).
#[async_trait]
pub trait ChatHandler: Send + Sync {
    async fn chat(&self, principal: Principal, speaker: &str, message: &str) -> Result<String>;
}

/// Boot-safe default: chat is not wired (fakes-mode state before
/// `boot::daemon_state` swaps in the real handler). Errors rather than
/// pretending — the HTTP route maps this to a 503, the inbound loop logs
/// and apologizes, and neither silently swallows an operator's message.
pub struct NoopChat;

#[async_trait]
impl ChatHandler for NoopChat {
    async fn chat(&self, _principal: Principal, _speaker: &str, _message: &str) -> Result<String> {
        Err(crate::Error::Config(
            "chat is not wired on this state (boot-safe NoopChat — daemon_state installs the real handler)"
                .into(),
        ))
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

    /// The wrapped channels — what [`inbound`]'s consumer loop routes
    /// replies through (a reply must go back to the ORIGIN channel only,
    /// which `send`'s fan-out deliberately cannot express).
    pub fn channels(&self) -> &[std::sync::Arc<dyn Channel>] {
        &self.channels
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
