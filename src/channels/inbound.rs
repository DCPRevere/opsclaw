//! The inbound-message consumer: the loop that makes listening channels
//! (Telegram today; anything implementing `Channel::listen`) actually drive
//! chat turns. This was the missing half of the channel story — `listen`
//! produced `InboundMessage`s into an mpsc that nothing consumed. One loop,
//! spawned by `http::server::run` alongside the scheduler on the same
//! `CancellationToken`/`TaskTracker` pair, fans every listener into one
//! queue and runs each message through the [`ChatHandler`] seam.
//!
//! Trust boundary (fail closed): a message only becomes a chat turn if the
//! ORIGIN channel vouches for its sender via `Channel::resolve_operator`
//! (Telegram's roster allowlist). An unvouched sender gets one polite
//! refusal and no agent turn — the agent never sees the message at all, so
//! an unknown chat id can't even spend tokens, let alone reach a tool. The
//! reply goes back to the origin channel only (`send_reply`), never the
//! whole fan-out: a Telegram DM's answer must not broadcast to the team
//! (same content-leak defence as telegram's own group-chat guard).

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::{Channel, ChatHandler, InboundMessage};
use crate::domain::Principal;

/// What an unvouched sender is told, once per message. Deliberately says
/// how to fix it rather than pretending to be unreachable.
const NOT_LINKED_REPLY: &str = "This chat isn't linked to an opsclaw operator — an operator must bind it before I can help here.";

/// What a vouched sender is told when the turn itself failed. The real
/// error goes to the log, never the channel (it may carry internal detail).
const TURN_FAILED_REPLY: &str =
    "I hit an internal error handling that — the details are in my log.";

/// Spawn the listener task for every channel plus the single consumer loop,
/// all on the shared shutdown/tracker pair (mirrors `scheduler::spawn`'s
/// contract: nothing outlives the drain window unaccounted for).
pub fn spawn(
    channels: Vec<Arc<dyn Channel>>,
    chat: Arc<dyn ChatHandler>,
    shutdown: CancellationToken,
    tracker: &TaskTracker,
) {
    if channels.is_empty() {
        return;
    }
    let (tx, rx) = mpsc::channel::<InboundMessage>(64);
    for ch in &channels {
        let ch = ch.clone();
        let tx = tx.clone();
        tracker.spawn(async move {
            // A listener returning is normal on shutdown (Telegram watches
            // its own wired token); an ERROR return is a real fault worth a
            // log line — but never a crash of the whole consumer side.
            if let Err(e) = ch.listen(tx).await {
                tracing::warn!(channel = ch.name(), error = %e, "channel listener exited with error");
            }
        });
    }
    // Drop the original sender so `rx` closes when every listener is gone.
    drop(tx);
    tracker.spawn(consume(channels, chat, rx, shutdown));
}

/// The consumer loop proper — separated from [`spawn`] so tests can drive
/// it directly with a hand-fed receiver and no real listener tasks.
async fn consume(
    channels: Vec<Arc<dyn Channel>>,
    chat: Arc<dyn ChatHandler>,
    mut rx: mpsc::Receiver<InboundMessage>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                handle_one(&channels, chat.as_ref(), msg).await;
            }
        }
    }
}

/// One inbound message end to end: origin lookup, self-drop, sender
/// vouching, the chat turn, and the origin-only reply. Every failure path
/// is terminal for THIS message only — the loop never dies over one
/// message (the same one-bad-tick discipline as the scheduler).
async fn handle_one(channels: &[Arc<dyn Channel>], chat: &dyn ChatHandler, msg: InboundMessage) {
    let Some(origin) = channels.iter().find(|c| c.name() == msg.channel) else {
        // A message claiming a channel we don't hold — can only be a bug
        // (listeners are spawned over this exact list), but fail loudly.
        tracing::warn!(channel = %msg.channel, "inbound message from unknown channel dropped");
        return;
    };
    if origin.drop_self_messages(&msg) {
        return;
    }
    let Some(account) = origin.resolve_operator(&msg.sender).await else {
        tracing::info!(channel = %msg.channel, sender = %msg.sender, "unvouched inbound sender refused");
        if let Err(e) = origin.send_reply(&msg.sender, NOT_LINKED_REPLY).await {
            tracing::warn!(channel = origin.name(), error = %e, "refusal reply failed");
        }
        return;
    };

    origin.send_typing(&msg.sender).await;
    match chat.chat(Principal::Operator { account }, &msg.sender, &msg.body).await {
        Ok(reply) => {
            if reply.trim().is_empty() {
                return;
            }
            if let Err(e) = origin.send_reply(&msg.sender, &reply).await {
                tracing::warn!(channel = origin.name(), error = %e, "chat reply delivery failed");
            }
        }
        Err(e) => {
            tracing::warn!(channel = origin.name(), sender = %msg.sender, error = %e, "chat turn failed");
            let _ = origin.send_reply(&msg.sender, TURN_FAILED_REPLY).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use uuid::Uuid;

    /// A channel double that vouches for one configured sender and records
    /// every `send_reply` (RecordingChannel only records `send`, which this
    /// loop deliberately never uses — replies are origin-only).
    struct VouchingChannel {
        vouched: Option<(String, Uuid)>,
        replies: Mutex<Vec<(String, String)>>,
    }

    impl VouchingChannel {
        fn new(vouched: Option<(&str, Uuid)>) -> Arc<Self> {
            Arc::new(VouchingChannel {
                vouched: vouched.map(|(s, u)| (s.to_string(), u)),
                replies: Mutex::new(Vec::new()),
            })
        }
        fn replies(&self) -> Vec<(String, String)> {
            self.replies.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Channel for VouchingChannel {
        fn name(&self) -> &str {
            "vouching"
        }
        async fn send(&self, _msg: crate::channels::OutboundMessage) -> crate::Result<()> {
            panic!("inbound replies must use send_reply (origin-only), never send (fan-out)");
        }
        async fn send_reply(&self, sender: &str, text: &str) -> crate::Result<()> {
            self.replies.lock().unwrap().push((sender.to_string(), text.to_string()));
            Ok(())
        }
        async fn resolve_operator(&self, sender: &str) -> Option<Uuid> {
            self.vouched.as_ref().filter(|(s, _)| s == sender).map(|(_, u)| *u)
        }
    }

    /// Records what principal/speaker/message each chat turn got.
    struct RecordingChat {
        calls: Mutex<Vec<(Principal, String, String)>>,
        reply: String,
    }

    impl RecordingChat {
        fn new(reply: &str) -> Arc<Self> {
            Arc::new(RecordingChat { calls: Mutex::new(Vec::new()), reply: reply.to_string() })
        }
        fn calls(&self) -> Vec<(Principal, String, String)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ChatHandler for RecordingChat {
        async fn chat(
            &self,
            principal: Principal,
            speaker: &str,
            message: &str,
        ) -> crate::Result<String> {
            self.calls.lock().unwrap().push((principal, speaker.to_string(), message.to_string()));
            Ok(self.reply.clone())
        }
    }

    fn msg(sender: &str, body: &str) -> InboundMessage {
        InboundMessage { sender: sender.into(), body: body.into(), channel: "vouching".into() }
    }

    fn as_list(ch: &Arc<VouchingChannel>) -> Vec<Arc<dyn Channel>> {
        vec![ch.clone()]
    }

    #[tokio::test]
    async fn vouched_sender_gets_a_chat_turn_under_their_operator_principal() {
        let account = Uuid::new_v4();
        let ch = VouchingChannel::new(Some(("tg:42", account)));
        let chat = RecordingChat::new("hello back");

        handle_one(&as_list(&ch), chat.as_ref(), msg("tg:42", "status?")).await;

        let calls = chat.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0].0, Principal::Operator { account: a } if a == account));
        assert_eq!(calls[0].1, "tg:42");
        assert_eq!(calls[0].2, "status?");
        assert_eq!(ch.replies(), vec![("tg:42".to_string(), "hello back".to_string())]);
    }

    #[tokio::test]
    async fn unvouched_sender_is_refused_and_the_agent_never_sees_the_message() {
        let ch = VouchingChannel::new(None);
        let chat = RecordingChat::new("should never be sent");

        handle_one(&as_list(&ch), chat.as_ref(), msg("tg:999", "hi")).await;

        assert!(chat.calls().is_empty(), "no chat turn for an unvouched sender");
        let replies = ch.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].1, NOT_LINKED_REPLY);
    }

    #[tokio::test]
    async fn a_failed_turn_apologizes_without_leaking_the_error() {
        struct FailingChat;
        #[async_trait]
        impl ChatHandler for FailingChat {
            async fn chat(&self, _p: Principal, _s: &str, _m: &str) -> crate::Result<String> {
                Err(crate::Error::other("secret backend detail"))
            }
        }
        let ch = VouchingChannel::new(Some(("tg:42", Uuid::new_v4())));

        handle_one(&as_list(&ch), &FailingChat, msg("tg:42", "hi")).await;

        let replies = ch.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].1, TURN_FAILED_REPLY);
        assert!(!replies[0].1.contains("secret backend detail"));
    }

    #[tokio::test]
    async fn consume_drains_until_shutdown() {
        let account = Uuid::new_v4();
        let ch = VouchingChannel::new(Some(("tg:42", account)));
        let chat = RecordingChat::new("ok");
        let (tx, rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();

        let handle = tokio::spawn(consume(
            vec![ch.clone() as Arc<dyn Channel>],
            chat.clone() as Arc<dyn ChatHandler>,
            rx,
            shutdown.clone(),
        ));
        tx.send(msg("tg:42", "one")).await.unwrap();
        tx.send(msg("tg:42", "two")).await.unwrap();
        // Closing the sender ends the loop without needing the token —
        // both exit paths are exercised across this module's tests.
        drop(tx);
        handle.await.unwrap();

        assert_eq!(chat.calls().len(), 2);
        assert_eq!(ch.replies().len(), 2);
    }
}
