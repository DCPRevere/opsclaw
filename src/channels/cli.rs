//! CLI channel — implements `Channel` for a local terminal.
//!
//! This is what lets `opsclaw-cli chat` drive the *exact* inbound path every
//! other channel uses rather than a parallel copy: the REPL feeds an
//! `InboundMessage`, the orchestrator handles it, and the reply is printed.
//! `send` captures every reply (the trait's default `send_reply` forwards to
//! it) so the caller can both print them inline and observe proactive
//! (scheduler) sends in tests.

use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use crate::Result;
use crate::channels::{Channel, OutboundMessage};

/// A terminal-backed channel. Replies are pushed to an in-process queue the
/// REPL drains and prints, so the same `Channel` works for interactive chat
/// and for observing proactive sends in tests.
#[derive(Clone, Default)]
pub struct CliChannel {
    sent: Arc<Mutex<Vec<OutboundMessage>>>,
}

impl CliChannel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain and return every message sent since the last drain, in order.
    pub fn drain(&self) -> Vec<OutboundMessage> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }

    /// Every reply text sent since the last drain (convenience for the REPL).
    pub fn drain_text(&self) -> Vec<String> {
        self.drain().into_iter().map(|m| m.body).collect()
    }
}

#[async_trait]
impl Channel for CliChannel {
    fn name(&self) -> &str {
        "cli"
    }

    async fn send(&self, msg: OutboundMessage) -> Result<()> {
        self.sent.lock().unwrap().push(msg);
        Ok(())
    }

    // ADAPTATION: opsclaw's `Channel::send_reply` default is a no-op (unlike
    // gianna's, which forwards to `send`), so the CLI channel — which relies
    // on every reply landing in the same capture queue the REPL drains —
    // must override it explicitly rather than inherit the default.
    async fn send_reply(&self, _sender: &str, text: &str) -> Result<()> {
        self.sent.lock().unwrap().push(OutboundMessage { operator: None, body: text.to_string() });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_and_drains_in_order() {
        let ch = CliChannel::new();
        ch.send_reply("cli:local", "first").await.unwrap();
        ch.send(OutboundMessage { operator: None, body: "second".into() }).await.unwrap();

        assert_eq!(ch.drain_text(), vec!["first", "second"]);
        // Drained queue is empty afterwards.
        assert!(ch.drain().is_empty());
    }
}
