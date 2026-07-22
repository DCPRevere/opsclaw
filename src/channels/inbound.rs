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
use uuid::Uuid;

use super::{Channel, ChatHandler, InboundMessage};
use crate::domain::Principal;
use crate::policy::EStop;

/// What an unvouched sender is told, once per message. Deliberately says
/// how to fix it rather than pretending to be unreachable.
const NOT_LINKED_REPLY: &str = "This chat isn't linked to an opsclaw operator — an operator must bind it before I can help here.";

/// What a vouched sender is told when the turn itself failed. The real
/// error goes to the log, never the channel (it may carry internal detail).
const TURN_FAILED_REPLY: &str =
    "I hit an internal error handling that — the details are in my log.";

/// The chat e-stop lever (DESIGN §4: "Remote `estop` (PWA / remote CLI /
/// chat)"). Exact, case-sensitive match after trim — "what is !estop" is a
/// question for the agent, not a command.
const ESTOP_COMMAND: &str = "!estop";
const ESTOP_RESUME_COMMAND: &str = "!estop resume";

const ESTOP_ENGAGED_REPLY: &str =
    "E-stop engaged — nothing will execute. Send `!estop resume` (or use the UI/CLI) to resume.";
const ESTOP_RESUMED_REPLY: &str = "E-stop resumed — command execution is unblocked.";
/// A chat resume never touches the sentinel file (see
/// `EStop::resume_db_only`) — the reply says so, and says how to clear it
/// where it CAN be cleared: on the daemon host.
const ESTOP_SENTINEL_HOLDS_REPLY: &str = "Remote e-stop flag cleared, but a LOCAL sentinel file still holds the stop engaged on the daemon host. Run `opsclaw-cli estop --resume` there (or delete the sentinel file) to resume.";
const ESTOP_FAILED_REPLY: &str =
    "I could not update the e-stop — the details are in my log. The UI and CLI levers still work.";

/// Spawn the listener task for every channel plus the single consumer loop,
/// all on the shared shutdown/tracker pair (mirrors `scheduler::spawn`'s
/// contract: nothing outlives the drain window unaccounted for).
pub fn spawn(
    channels: Vec<Arc<dyn Channel>>,
    chat: Arc<dyn ChatHandler>,
    estop: Arc<EStop>,
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
    tracker.spawn(consume(channels, chat, estop, rx, shutdown));
}

/// The consumer loop proper — separated from [`spawn`] so tests can drive
/// it directly with a hand-fed receiver and no real listener tasks.
async fn consume(
    channels: Vec<Arc<dyn Channel>>,
    chat: Arc<dyn ChatHandler>,
    estop: Arc<EStop>,
    mut rx: mpsc::Receiver<InboundMessage>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                handle_one(&channels, chat.as_ref(), &estop, msg).await;
            }
        }
    }
}

/// One inbound message end to end: origin lookup, self-drop, sender
/// vouching, the e-stop command intercept, the chat turn, and the
/// origin-only reply. Every failure path is terminal for THIS message only
/// — the loop never dies over one message (the same one-bad-tick
/// discipline as the scheduler).
async fn handle_one(
    channels: &[Arc<dyn Channel>],
    chat: &dyn ChatHandler,
    estop: &EStop,
    msg: InboundMessage,
) {
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

    // Remote e-stop via chat (DESIGN §4: "Remote `estop` (PWA / remote CLI /
    // chat) is a gateway endpoint") — intercepted HERE, before the message
    // can reach the LLM: a stop lever must not depend on the agent loop
    // being healthy enough to interpret it, and it must never burn a token
    // or a turn. Deliberately AFTER the resolve_operator gate above, so
    // only a roster-vouched operator can pull it — an unvouched sender got
    // the refusal reply and never reaches this line.
    let trimmed = msg.body.trim();
    if trimmed == ESTOP_COMMAND || trimmed == ESTOP_RESUME_COMMAND {
        let reply =
            run_estop_command(estop, trimmed == ESTOP_RESUME_COMMAND, account, &msg.sender).await;
        if let Err(e) = origin.send_reply(&msg.sender, reply).await {
            tracing::warn!(channel = origin.name(), error = %e, "e-stop reply delivery failed");
        }
        return;
    }

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

/// Execute a vouched operator's e-stop chat command against the DB flag
/// ONLY (`EStop::engage_db_only`/`resume_db_only` — see those methods for
/// why the sentinel file is never touched from here) and pick the reply.
/// Errors are logged, never surfaced verbatim (same stance as
/// [`TURN_FAILED_REPLY`]).
async fn run_estop_command(
    estop: &EStop,
    resume: bool,
    account: Uuid,
    sender: &str,
) -> &'static str {
    if resume {
        match estop.resume_db_only().await {
            Ok(sentinel_holds) => {
                tracing::warn!(operator = %account, sender = %sender, sentinel_holds, "e-stop resumed via chat (DB flag only)");
                if sentinel_holds { ESTOP_SENTINEL_HOLDS_REPLY } else { ESTOP_RESUMED_REPLY }
            }
            Err(e) => {
                tracing::error!(operator = %account, error = %e, "chat e-stop resume failed");
                ESTOP_FAILED_REPLY
            }
        }
    } else {
        match estop.engage_db_only().await {
            Ok(()) => {
                tracing::warn!(operator = %account, sender = %sender, "e-stop engaged via chat");
                ESTOP_ENGAGED_REPLY
            }
            Err(e) => {
                tracing::error!(operator = %account, error = %e, "chat e-stop engage failed");
                ESTOP_FAILED_REPLY
            }
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

    /// An e-stop over a throwaway sentinel path and an in-memory control
    /// repo — returned separately so tests can assert on the DB flag alone.
    fn test_estop(dir: &tempfile::TempDir) -> (Arc<EStop>, Arc<crate::db::memory::InMemoryDb>) {
        let db = Arc::new(crate::db::memory::InMemoryDb::new());
        (Arc::new(EStop::new(dir.path().join("ESTOP"), db.clone())), db)
    }

    #[tokio::test]
    async fn vouched_sender_gets_a_chat_turn_under_their_operator_principal() {
        let account = Uuid::new_v4();
        let ch = VouchingChannel::new(Some(("tg:42", account)));
        let chat = RecordingChat::new("hello back");
        let dir = tempfile::tempdir().unwrap();
        let (estop, _) = test_estop(&dir);

        handle_one(&as_list(&ch), chat.as_ref(), &estop, msg("tg:42", "status?")).await;

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
        let dir = tempfile::tempdir().unwrap();
        let (estop, _) = test_estop(&dir);

        handle_one(&as_list(&ch), chat.as_ref(), &estop, msg("tg:999", "hi")).await;

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
        let dir = tempfile::tempdir().unwrap();
        let (estop, _) = test_estop(&dir);

        handle_one(&as_list(&ch), &FailingChat, &estop, msg("tg:42", "hi")).await;

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
        let dir = tempfile::tempdir().unwrap();
        let (estop, _) = test_estop(&dir);
        let (tx, rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();

        let handle = tokio::spawn(consume(
            vec![ch.clone() as Arc<dyn Channel>],
            chat.clone() as Arc<dyn ChatHandler>,
            estop,
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

    // ---- chat e-stop (DESIGN §4: remote e-stop via chat) ----

    #[tokio::test]
    async fn exact_estop_message_engages_the_db_flag_and_confirms() {
        use crate::db::ControlRepo;
        let ch = VouchingChannel::new(Some(("tg:42", Uuid::new_v4())));
        let chat = RecordingChat::new("must never run");
        let dir = tempfile::tempdir().unwrap();
        let (estop, db) = test_estop(&dir);

        handle_one(&as_list(&ch), chat.as_ref(), &estop, msg("tg:42", "!estop")).await;

        assert!(db.estop_engaged().await.unwrap(), "the DB flag must be set");
        assert!(!estop.sentinel_path().exists(), "the chat path must not write the sentinel");
        assert!(chat.calls().is_empty(), "the command must never reach the LLM");
        assert_eq!(ch.replies(), vec![("tg:42".to_string(), ESTOP_ENGAGED_REPLY.to_string())]);
    }

    #[tokio::test]
    async fn estop_resume_clears_the_db_flag_and_confirms() {
        use crate::db::ControlRepo;
        let ch = VouchingChannel::new(Some(("tg:42", Uuid::new_v4())));
        let chat = RecordingChat::new("must never run");
        let dir = tempfile::tempdir().unwrap();
        let (estop, db) = test_estop(&dir);
        db.set_estop(true).await.unwrap();

        // Leading/trailing whitespace still matches — exact match AFTER trim.
        handle_one(&as_list(&ch), chat.as_ref(), &estop, msg("tg:42", "  !estop resume  ")).await;

        assert!(!db.estop_engaged().await.unwrap(), "the DB flag must be cleared");
        assert!(chat.calls().is_empty());
        assert_eq!(ch.replies(), vec![("tg:42".to_string(), ESTOP_RESUMED_REPLY.to_string())]);
    }

    #[tokio::test]
    async fn estop_resume_never_clears_a_local_sentinel() {
        use crate::db::ControlRepo;
        let ch = VouchingChannel::new(Some(("tg:42", Uuid::new_v4())));
        let chat = RecordingChat::new("must never run");
        let dir = tempfile::tempdir().unwrap();
        let (estop, db) = test_estop(&dir);
        db.set_estop(true).await.unwrap();
        crate::policy::estop::write_sentinel(estop.sentinel_path(), "local operator").unwrap();

        handle_one(&as_list(&ch), chat.as_ref(), &estop, msg("tg:42", "!estop resume")).await;

        assert!(!db.estop_engaged().await.unwrap(), "the DB flag alone is cleared");
        assert!(estop.sentinel_path().exists(), "a remote resume must never delete the sentinel");
        assert!(estop.engaged().await.unwrap(), "the stop still holds via the sentinel");
        assert_eq!(
            ch.replies(),
            vec![("tg:42".to_string(), ESTOP_SENTINEL_HOLDS_REPLY.to_string())]
        );
    }

    #[tokio::test]
    async fn unvouched_sender_cannot_pull_the_estop() {
        use crate::db::ControlRepo;
        let ch = VouchingChannel::new(None);
        let chat = RecordingChat::new("must never run");
        let dir = tempfile::tempdir().unwrap();
        let (estop, db) = test_estop(&dir);

        handle_one(&as_list(&ch), chat.as_ref(), &estop, msg("tg:999", "!estop")).await;

        assert!(!db.estop_engaged().await.unwrap(), "an unvouched sender must not engage");
        assert!(chat.calls().is_empty());
        let replies = ch.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].1, NOT_LINKED_REPLY);
    }

    #[tokio::test]
    async fn near_miss_estop_text_goes_to_the_agent_as_a_normal_turn() {
        use crate::db::ControlRepo;
        let ch = VouchingChannel::new(Some(("tg:42", Uuid::new_v4())));
        let chat = RecordingChat::new("it's the emergency stop");
        let dir = tempfile::tempdir().unwrap();
        let (estop, db) = test_estop(&dir);

        // Not exact matches: a question, and a case variant (case-sensitive).
        handle_one(&as_list(&ch), chat.as_ref(), &estop, msg("tg:42", "what is !estop")).await;
        handle_one(&as_list(&ch), chat.as_ref(), &estop, msg("tg:42", "!ESTOP")).await;

        assert_eq!(chat.calls().len(), 2, "near-misses are ordinary chat turns");
        assert!(!db.estop_engaged().await.unwrap(), "no near-miss may engage the stop");
    }
}
