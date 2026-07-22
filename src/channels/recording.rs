//! In-memory channel that records every sent message. The scheduler/agent
//! test workhorse: assertions read `sent()`/`last()` instead of standing up a
//! real transport.

use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use crate::Result;
use crate::channels::{Channel, OutboundMessage};

#[derive(Clone, Default)]
pub struct RecordingChannel {
    sent: Arc<Mutex<Vec<OutboundMessage>>>,
    self_handle: Option<String>,
}

impl RecordingChannel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_self_handle(mut self, handle: impl Into<String>) -> Self {
        self.self_handle = Some(handle.into());
        self
    }

    pub fn sent(&self) -> Vec<OutboundMessage> {
        self.sent.lock().unwrap().clone()
    }

    pub fn last(&self) -> Option<OutboundMessage> {
        self.sent.lock().unwrap().last().cloned()
    }
}

#[async_trait]
impl Channel for RecordingChannel {
    fn name(&self) -> &str {
        "recording"
    }

    async fn send(&self, msg: OutboundMessage) -> Result<()> {
        tracing::info!(target: "opsclaw::channel", operator = ?msg.operator, "OUT: {}", msg.body);
        self.sent.lock().unwrap().push(msg);
        Ok(())
    }

    fn self_handle(&self) -> Option<String> {
        self.self_handle.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::InboundMessage;

    #[tokio::test]
    async fn records_sent_messages() {
        let ch = RecordingChannel::new();
        ch.send(OutboundMessage { operator: None, body: "hello".into(), meta: None })
            .await
            .unwrap();
        assert_eq!(ch.sent().len(), 1);
        assert_eq!(ch.last().unwrap().body, "hello");
    }

    #[test]
    fn self_loop_guard() {
        let ch = RecordingChannel::new().with_self_handle("@opsclaw_bot");
        assert!(ch.drop_self_messages(&InboundMessage {
            sender: "opsclaw_bot".into(),
            body: "hi".into(),
            channel: "telegram".into(),
        }));
        assert!(!ch.drop_self_messages(&InboundMessage {
            sender: "alice".into(),
            body: "hi".into(),
            channel: "telegram".into(),
        }));
        // No handle -> never drops.
        let ch2 = RecordingChannel::new();
        assert!(!ch2.drop_self_messages(&InboundMessage {
            sender: "anyone".into(),
            body: "hi".into(),
            channel: "x".into(),
        }));
    }
}
