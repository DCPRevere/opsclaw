//! Telegram channel — implements the `Channel` trait.
//!
//! `listen` long-polls `getUpdates`, `send`/`send_reply` post to
//! `sendMessage`. The sender identity is the Telegram chat id, prefixed
//! `"tg:"` to disambiguate across channels.
//!
//! ADAPTATION from gianna: gianna resolves a chat id to a household via a
//! stored member channel handle (`db::HouseholdRepo`). OpsClaw has no
//! household concept — a chat id instead maps to an operator handle via the
//! local [`TelegramRoster`] trait (allowlist), and the getUpdates offset is
//! persisted via the local [`OffsetStore`] trait. In-memory implementations
//! ([`InMemoryRoster`], [`InMemoryOffsetStore`]) live here for tests;
//! [`DbTelegramRoster`] and [`DbOffsetStore`] below are the DB-backed
//! production implementations (persistent roster + poll offset task),
//! thin adapters over `db::ChannelStateRepo` — both traits here are already
//! `#[async_trait]`, so the adapter is a direct async delegation with no
//! `block_on`/runtime-blocking bridge needed. `boot::daemon_state` wires
//! these instead of the in-memory pair (gianna lesson preserved: the offset
//! is persisted only after genuine hand-off — see `listen`'s `advance_offset!`
//! macro below, unchanged by this adapter).

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::channels::{Channel, InboundMessage, OutboundMessage};
use crate::{Error, Result};

/// The control-store key holding the Telegram getUpdates offset.
const TELEGRAM_OFFSET_KEY: &str = "telegram:getUpdates:offset";

/// The prefix marking an operator channel-handle as a Telegram chat id.
pub const TELEGRAM_HANDLE_PREFIX: &str = "tg:";

/// Telegram's hard message limit.
const TELEGRAM_MAX_CHARS: usize = 4096;

/// Maps Telegram chat ids to operator handles (an allowlist — the
/// household/member linking gianna did via `HouseholdRepo` becomes a simple
/// operator-handle model here). `find_operator` resolves an inbound chat id
/// to a known operator; `chat_ids_for` resolves an outbound operator target
/// to the chat ids that should receive it (None = every allowlisted chat, matching
/// `OutboundMessage.operator: None` meaning "whole team channel").
#[async_trait]
pub trait TelegramRoster: Send + Sync {
    /// The operator bound to this chat id, if the chat is allowlisted.
    async fn find_operator(&self, chat_id: &str) -> Option<Uuid>;

    /// Chat ids that should receive a message addressed to `operator`
    /// (`None` = broadcast to every roster entry).
    async fn chat_ids_for(&self, operator: Option<Uuid>) -> Vec<String>;
}

/// In-memory allowlist: chat id <-> operator handle. The SQLite-backed impl
/// (persisted roster, admin-managed) wires in at integration.
#[derive(Default)]
pub struct InMemoryRoster {
    by_chat: std::sync::Mutex<HashMap<String, Uuid>>,
}

impl InMemoryRoster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a chat id to an operator handle (test/bootstrap helper).
    pub fn bind(&self, chat_id: impl Into<String>, operator: Uuid) {
        self.by_chat.lock().unwrap().insert(chat_id.into(), operator);
    }
}

#[async_trait]
impl TelegramRoster for InMemoryRoster {
    async fn find_operator(&self, chat_id: &str) -> Option<Uuid> {
        self.by_chat.lock().unwrap().get(chat_id).copied()
    }

    async fn chat_ids_for(&self, operator: Option<Uuid>) -> Vec<String> {
        let map = self.by_chat.lock().unwrap();
        match operator {
            None => map.keys().cloned().collect(),
            Some(op) => map.iter().filter(|(_, v)| **v == op).map(|(k, _)| k.clone()).collect(),
        }
    }
}

/// Durable cursor store for the getUpdates offset, so a restart doesn't
/// re-process updates that were handled but never confirmed. The
/// SQLite-backed impl wires in at integration; this module only provides an
/// in-memory implementation.
#[async_trait]
pub trait OffsetStore: Send + Sync {
    async fn load(&self, key: &str) -> Result<Option<i64>>;
    async fn store(&self, key: &str, offset: i64) -> Result<()>;
}

/// In-memory offset store (process-lifetime only — a restart starts from 0).
#[derive(Default)]
pub struct InMemoryOffsetStore {
    offsets: std::sync::Mutex<HashMap<String, i64>>,
}

impl InMemoryOffsetStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl OffsetStore for InMemoryOffsetStore {
    async fn load(&self, key: &str) -> Result<Option<i64>> {
        Ok(self.offsets.lock().unwrap().get(key).copied())
    }

    async fn store(&self, key: &str, offset: i64) -> Result<()> {
        self.offsets.lock().unwrap().insert(key.to_string(), offset);
        Ok(())
    }
}

/// DB-backed [`TelegramRoster`]: a thin adapter over `db::ChannelStateRepo`
/// (persistent roster + poll offset task). Production wiring — replaces
/// [`InMemoryRoster`] in `boot::daemon_state`, so an operator's chat binding
/// survives a restart/deploy instead of needing to be re-established.
pub struct DbTelegramRoster {
    repo: Arc<dyn crate::db::ChannelStateRepo>,
}

impl DbTelegramRoster {
    pub fn new(repo: Arc<dyn crate::db::ChannelStateRepo>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl TelegramRoster for DbTelegramRoster {
    async fn find_operator(&self, chat_id: &str) -> Option<Uuid> {
        match self.repo.find_telegram_operator(chat_id).await {
            Ok(op) => op,
            Err(e) => {
                tracing::warn!("telegram roster lookup failed: {e}");
                None
            }
        }
    }

    async fn chat_ids_for(&self, operator: Option<Uuid>) -> Vec<String> {
        match self.repo.telegram_chat_ids_for(operator).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!("telegram roster chat_ids_for failed: {e}");
                Vec::new()
            }
        }
    }
}

/// DB-backed [`OffsetStore`]: a thin adapter over `db::ChannelStateRepo`'s
/// generic key/value cursor store. Production wiring — replaces
/// [`InMemoryOffsetStore`] in `boot::daemon_state`. The crash-window
/// message-loss rule (persist only after genuine hand-off) is enforced by
/// `TelegramChannel::listen`'s caller-side ordering, unchanged here — this
/// type is just where the value lands durably.
pub struct DbOffsetStore {
    repo: Arc<dyn crate::db::ChannelStateRepo>,
}

impl DbOffsetStore {
    pub fn new(repo: Arc<dyn crate::db::ChannelStateRepo>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl OffsetStore for DbOffsetStore {
    async fn load(&self, key: &str) -> Result<Option<i64>> {
        match self.repo.get_channel_state(key).await? {
            Some(raw) => raw
                .parse::<i64>()
                .map(Some)
                .map_err(|e| Error::other(format!("telegram offset {raw:?} not an i64: {e}"))),
            None => Ok(None),
        }
    }

    async fn store(&self, key: &str, offset: i64) -> Result<()> {
        self.repo.set_channel_state(key, &offset.to_string()).await
    }
}

pub struct TelegramChannel {
    client: reqwest::Client,
    token: String,
    self_username: Option<String>,
    /// getUpdates offset (last processed update id + 1).
    offset: AtomicI64,
    roster: Arc<dyn TelegramRoster>,
    offsets: Arc<dyn OffsetStore>,
    /// Cancelled on shutdown. `listen` stops pulling new updates once set, so
    /// an update that arrives during the drain window is left un-acked on
    /// Telegram's side and redelivered to the NEXT process — never enqueued
    /// onto a `tx` whose consumer is about to die. Without it, the long-poll
    /// would keep fetching (and advancing the durable offset) straight into
    /// shutdown.
    shutdown: Option<tokio_util::sync::CancellationToken>,
    /// Telegram API base URL, overridable so tests can point at a wiremock
    /// server instead of `https://api.telegram.org`. Not part of the
    /// production constructor surface — production always uses the default.
    base_url: String,
}

impl TelegramChannel {
    /// `token` is an already-resolved bot token String — secret resolution
    /// happens outside, at wiring time (constructor discipline: this type
    /// never touches the secret store).
    pub fn new(
        token: String,
        client: reqwest::Client,
        roster: Arc<dyn TelegramRoster>,
        offsets: Arc<dyn OffsetStore>,
    ) -> Self {
        Self {
            client,
            token,
            self_username: None,
            offset: AtomicI64::new(0),
            roster,
            offsets,
            shutdown: None,
            base_url: "https://api.telegram.org".to_string(),
        }
    }

    /// Wire the shutdown token so `listen` stops long-polling on shutdown,
    /// leaving any not-yet-fetched update for the next process to receive.
    pub fn with_shutdown(mut self, token: tokio_util::sync::CancellationToken) -> Self {
        self.shutdown = Some(token);
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.self_username = Some(username.into());
        self
    }

    /// Override the API base URL (test-only hook for pointing at a wiremock
    /// server). Not called in production wiring.
    #[cfg(test)]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn api(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.base_url, self.token, method)
    }
}

#[async_trait]
impl Channel for TelegramChannel {
    fn name(&self) -> &str {
        "telegram"
    }

    async fn send_typing(&self, sender: &str) {
        // sender is "tg:<chat_id>".
        if let Some(chat_id) = sender.strip_prefix(TELEGRAM_HANDLE_PREFIX) {
            self.send_chat_action(chat_id).await;
        }
    }

    async fn send(&self, msg: OutboundMessage) -> Result<()> {
        let chat_ids = self.roster.chat_ids_for(msg.operator).await;
        tracing::info!(
            channel = "telegram",
            operator = ?msg.operator,
            recipients = chat_ids.len(),
            body_len = msg.body.len(),
            "outbound"
        );
        for chat_id in chat_ids {
            if let Err(e) = self.send_to_chat(&chat_id, &msg.body).await {
                tracing::warn!(chat_id, "telegram proactive send failed: {e}");
            }
        }
        Ok(())
    }

    /// Reachable iff the operator (or, when `None`, ANY operator) has an
    /// allowlisted chat id — the same set `send` resolves via
    /// `roster.chat_ids_for`.
    async fn can_reach(&self, operator: Option<Uuid>) -> bool {
        !self.roster.chat_ids_for(operator).await.is_empty()
    }

    async fn send_reply(&self, sender: &str, text: &str) -> Result<()> {
        // `sender` is the operator handle ("tg:<chat_id>"); strip the prefix
        // to the raw chat id Telegram expects.
        let chat_id = sender.strip_prefix(TELEGRAM_HANDLE_PREFIX).unwrap_or(sender);
        tracing::info!(channel = "telegram", chat = %chat_id, body_len = text.len(), "reply sent");
        self.send_to_chat(chat_id, text).await
    }

    async fn listen(&self, tx: mpsc::Sender<InboundMessage>) -> Result<()> {
        // Resume from the durable cursor so a restart doesn't re-process
        // updates that were handled but never confirmed to Telegram.
        match self.offsets.load(TELEGRAM_OFFSET_KEY).await {
            Ok(Some(saved)) => self.offset.store(saved, Ordering::SeqCst),
            Ok(None) => {}
            Err(e) => tracing::warn!("telegram offset load failed (starting from 0): {e}"),
        }
        loop {
            // Deploy safety: once shutdown has cancelled the token, stop
            // pulling. A getUpdates call only ADVANCES the durable offset for
            // updates it both fetches AND hands off; by not fetching during
            // the drain window we leave any pending update un-acked, so
            // Telegram redelivers it to the next process rather than us
            // losing it when this one exits.
            if self.shutdown.as_ref().is_some_and(|s| s.is_cancelled()) {
                tracing::info!("telegram listen stopping (shutdown)");
                return Ok(());
            }
            let offset = self.offset.load(Ordering::SeqCst);
            let url = format!("{}?timeout=60&offset={offset}", self.api("getUpdates"));
            // Race the (up to 60s) long-poll against shutdown so a deploy
            // isn't held for a full poll cycle. On cancellation we abandon
            // THIS fetch without touching the offset — its updates stay
            // un-acked on Telegram and come back next boot.
            let resp = match &self.shutdown {
                Some(token) => tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        tracing::info!("telegram listen stopping (shutdown mid-poll)");
                        return Ok(());
                    }
                    r = self.client.get(&url).send() => r,
                },
                None => self.client.get(&url).send().await,
            };
            let body: serde_json::Value = match resp {
                Ok(r) => match r.json().await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("telegram getUpdates json: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        continue;
                    }
                },
                Err(e) => {
                    tracing::warn!("telegram getUpdates: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    continue;
                }
            };
            let mut processed_any = false;
            if let Some(updates) = body["result"].as_array() {
                for u in updates {
                    processed_any = true;
                    // The durable offset must NOT advance past an update
                    // until that update is fully handled — either enqueued
                    // onto `tx`, or intentionally dropped (group chat,
                    // non-text, etc.). Advancing it up front would open a
                    // silent-loss window: a crash after the batch's cursor
                    // persist but before the consumer drained the in-memory
                    // `tx` would skip those updates on restart. So we advance
                    // only at the genuine end-of-handling points below.
                    let update_id = u["update_id"].as_i64();
                    macro_rules! advance_offset {
                        () => {
                            if let Some(id) = update_id {
                                self.offset.store(id + 1, Ordering::SeqCst);
                            }
                        };
                    }
                    let msg = &u["message"];
                    let Some(chat_id) = msg["chat"]["id"].as_i64() else {
                        advance_offset!(); // unhandleable update: still consumed
                        continue;
                    };
                    // Group-chat guard (content-leak defence): this channel
                    // only ever works in a 1:1 DM. In a group/supergroup/
                    // channel the chat id is the GROUP's id, and processing
                    // it would bind that group as an operator handle —
                    // leaking one operator's private content to everyone in
                    // the room, and letting any group member drive it. So
                    // for anything other than a "private" chat we send one
                    // plain reply and drop the update without processing or
                    // linking. Telegram always sets chat.type; a MISSING
                    // type is treated as non-private (fail closed).
                    if !is_private_chat(msg) {
                        let _ = self
                            .send_to_chat(&chat_id.to_string(), "I only work in a direct chat.")
                            .await;
                        advance_offset!(); // rejected, but consumed
                        continue;
                    }
                    // Prefix the chat id so the operator handle is
                    // unambiguous across channels ("tg:<chat_id>").
                    let handle = format!("{TELEGRAM_HANDLE_PREFIX}{chat_id}");

                    // Self-message guard: drop updates the bot itself
                    // authored before they ever reach the orchestrator.
                    let text: String = match msg["text"].as_str() {
                        Some(t) => t.to_string(),
                        None => {
                            advance_offset!(); // non-text (sticker, photo, etc.)
                            continue;
                        }
                    };

                    tracing::info!(
                        channel = "telegram",
                        chat = chat_id,
                        text_len = text.chars().count(),
                        "inbound"
                    );
                    let inbound =
                        InboundMessage { sender: handle, body: text, channel: "telegram".into() };
                    if self.drop_self_messages(&inbound) {
                        advance_offset!(); // self-authored: consumed, not enqueued
                        continue;
                    }
                    if tx.send(inbound).await.is_err() {
                        // Receiver gone: do NOT advance the offset — this
                        // update was not handed off, so a restart should
                        // re-fetch it.
                        return Ok(());
                    }
                    // Enqueued onto the consumer's channel: now safe to advance.
                    advance_offset!();
                }
            }
            // Persist the advanced cursor once per batch (cheap; restart-safe).
            // The offset now only covers updates already enqueued onto `tx`
            // (or intentionally dropped), so persisting it can't skip an
            // un-handed-off message.
            if processed_any {
                let current = self.offset.load(Ordering::SeqCst);
                if let Err(e) = self.offsets.store(TELEGRAM_OFFSET_KEY, current).await {
                    tracing::warn!("telegram offset persist failed (restart may re-process): {e}");
                }
            }
        }
    }

    fn self_handle(&self) -> Option<String> {
        self.self_username.clone()
    }
}

impl TelegramChannel {
    /// Telegram-native typing indicator (lasts ~5s; cheap, fire-and-forget).
    pub async fn send_chat_action(&self, chat_id: &str) {
        let _ = self
            .client
            .post(self.api("sendChatAction"))
            .json(&serde_json::json!({ "chat_id": chat_id, "action": "typing" }))
            .send()
            .await;
    }

    /// Send a message directly to a Telegram chat id (used by the reply
    /// path, which knows the originating chat from the inbound message).
    /// Telegram caps a message at 4096 chars — a long message is split at
    /// line/char boundaries rather than failing with a 400 (and the operator
    /// getting nothing).
    pub async fn send_to_chat(&self, chat_id: &str, text: &str) -> Result<()> {
        // Chunk the raw text (so a 4096-char split never lands inside an
        // HTML tag), then render each chunk's Markdown to Telegram HTML for
        // sending.
        for chunk in split_for_telegram(text) {
            self.send_chunk(chat_id, &chunk).await?;
        }
        Ok(())
    }

    /// One sendMessage call with bounded retry: 429 (honouring Telegram's
    /// `retry_after`) and 5xx are transient — an alert shouldn't vanish over
    /// one rate-limit blip. Other 4xx fail immediately (won't improve).
    ///
    /// The agent emits standard Markdown (`**bold**`, `# headings`, `-
    /// lists`), which Telegram shows literally as plain text. We render it
    /// to Telegram HTML and send with `parse_mode: HTML` so it formats; if
    /// Telegram rejects our HTML (a 400 we can't fix by retrying), we resend
    /// the chunk as plain text so the operator still gets the message rather
    /// than nothing.
    async fn send_chunk(&self, chat_id: &str, chunk: &str) -> Result<()> {
        let html = markdown_to_telegram_html(chunk);
        let mut last_err = String::new();
        for attempt in 0..3u64 {
            match self
                .client
                .post(self.api("sendMessage"))
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "text": html,
                    "parse_mode": "HTML",
                }))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(r) => {
                    let status = r.status();
                    if status.as_u16() != 429 && !status.is_server_error() {
                        // A 400 here is almost always a parse_mode complaint
                        // about our HTML. Don't lose the message: resend it
                        // as plain text.
                        if status.as_u16() == 400 {
                            tracing::warn!("telegram HTML rejected, resending as plain text");
                            return self.send_plain(chat_id, chunk).await;
                        }
                        return Err(Error::other(format!("telegram send {status}")));
                    }
                    // Telegram says how long to back off on 429.
                    let wait = r
                        .json::<serde_json::Value>()
                        .await
                        .ok()
                        .and_then(|b| b["parameters"]["retry_after"].as_u64())
                        .unwrap_or(2 * (attempt + 1))
                        .min(30);
                    last_err = format!("telegram send {status}");
                    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                }
                Err(e) => {
                    last_err = format!("telegram send: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(2 * (attempt + 1))).await;
                }
            }
        }
        Err(Error::other(format!("{last_err} (after 3 attempts)")))
    }

    /// Fallback path: send a chunk with no parse_mode (raw text). Used when
    /// our HTML rendering is rejected, so a formatting glitch never eats a
    /// message.
    async fn send_plain(&self, chat_id: &str, chunk: &str) -> Result<()> {
        let r = self
            .client
            .post(self.api("sendMessage"))
            .json(&serde_json::json!({ "chat_id": chat_id, "text": chunk }))
            .send()
            .await
            .map_err(|e| Error::other(format!("telegram plain send: {e}")))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(Error::other(format!("telegram plain send {}", r.status())))
        }
    }
}

/// Render the agent's standard Markdown to the small HTML subset Telegram's
/// `parse_mode: HTML` accepts (`<b> <i> <u> <s> <code> <pre> <a>`). Telegram
/// does NOT support `<h1>`, `<ul>`, `<br>` etc., so headings become bold
/// lines and bullets keep their `•` marker as plain text. Only `< > &` are
/// special in HTML mode, so escaping is simple and robust (unlike
/// MarkdownV2, which needs many characters escaped and breaks on the agent's
/// `**double-star**` bold — this is why we render to the HTML subset instead
/// of using Telegram's MarkdownV2 parse mode).
fn markdown_to_telegram_html(md: &str) -> String {
    /// HTML-escape the three characters Telegram's HTML mode treats specially.
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    let mut out = String::with_capacity(md.len() + md.len() / 8);
    // Process fenced code blocks first so their contents are never treated
    // as markup. Split on ``` and alternate outside/inside.
    let mut in_fence = false;
    for (i, segment) in md.split("```").enumerate() {
        if i > 0 {
            in_fence = !in_fence;
        }
        if in_fence {
            // The opening fence's own line (the text between ``` and the
            // first newline) is either empty or a language label (`rust`,
            // `json`) — in both cases it is not code, so drop it and keep
            // the rest as the body.
            let body = match segment.split_once('\n') {
                Some((first, rest)) if !first.contains(char::is_whitespace) => rest,
                _ => segment,
            };
            out.push_str("<pre>");
            out.push_str(&esc(body));
            out.push_str("</pre>");
        } else {
            out.push_str(&render_inline_lines(segment, &esc));
        }
    }
    out
}

/// Render the non-code-block portion: per-line heading/bullet handling, then
/// inline spans (`**bold**`, `*italic*`/`_italic_`, `` `code` ``, links).
fn render_inline_lines(text: &str, esc: &dyn Fn(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let lines: Vec<&str> = text.split('\n').collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        // `#`/`##`/`###` heading -> a bold line.
        if let Some(rest) = trimmed.strip_prefix('#') {
            let heading = rest.trim_start_matches('#').trim_start();
            out.push_str(indent);
            out.push_str("<b>");
            out.push_str(&render_inline(heading, esc));
            out.push_str("</b>");
        } else if let Some(rest) = trimmed.strip_prefix("- ").or_else(|| trimmed.strip_prefix("* "))
        {
            // `-`/`*` bullet -> a `•` marker (Telegram has no list markup).
            out.push_str(indent);
            out.push_str("• ");
            out.push_str(&render_inline(rest, esc));
        } else {
            out.push_str(indent);
            out.push_str(&render_inline(trimmed, esc));
        }
        if i + 1 < lines.len() {
            out.push('\n');
        }
    }
    out
}

/// Render inline Markdown spans within a single run of text to Telegram
/// HTML. Handles `**bold**`, `__bold__`, `*italic*`, `_italic_`, `` `code`
/// ``, and `[text](url)` links. Everything else is HTML-escaped verbatim.
fn render_inline(s: &str, esc: &dyn Fn(&str) -> String) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    // Buffer of plain text pending escape — flushed before each emitted tag.
    let mut plain = String::new();
    macro_rules! flush {
        () => {
            if !plain.is_empty() {
                out.push_str(&esc(&plain));
                plain.clear();
            }
        };
    }
    while i < chars.len() {
        let c = chars[i];
        // `code` — verbatim, no nested markup.
        if c == '`'
            && let Some(end) = find_char(&chars, i + 1, '`')
        {
            flush!();
            let code: String = chars[i + 1..end].iter().collect();
            out.push_str("<code>");
            out.push_str(&esc(&code));
            out.push_str("</code>");
            i = end + 1;
            continue;
        }
        // `**bold**` or `__bold__`.
        if (c == '*' || c == '_') && i + 1 < chars.len() && chars[i + 1] == c {
            let marker = [c, c];
            if let Some(end) = find_seq(&chars, i + 2, &marker) {
                flush!();
                let inner: String = chars[i + 2..end].iter().collect();
                out.push_str("<b>");
                out.push_str(&render_inline(&inner, esc));
                out.push_str("</b>");
                i = end + 2;
                continue;
            }
        }
        // `*italic*` or `_italic_` (single marker).
        if (c == '*' || c == '_')
            && let Some(end) = find_char(&chars, i + 1, c)
        {
            // Avoid treating `a_b_c` mid-word underscores as italic noise:
            // require the span to be non-empty.
            if end > i + 1 {
                flush!();
                let inner: String = chars[i + 1..end].iter().collect();
                out.push_str("<i>");
                out.push_str(&render_inline(&inner, esc));
                out.push_str("</i>");
                i = end + 1;
                continue;
            }
        }
        // `[text](url)` link.
        if c == '['
            && let Some(close) = find_char(&chars, i + 1, ']')
            && close + 1 < chars.len()
            && chars[close + 1] == '('
            && let Some(paren) = find_char(&chars, close + 2, ')')
        {
            let label: String = chars[i + 1..close].iter().collect();
            let url: String = chars[close + 2..paren].iter().collect();
            flush!();
            out.push_str("<a href=\"");
            out.push_str(&esc(&url));
            out.push_str("\">");
            out.push_str(&render_inline(&label, esc));
            out.push_str("</a>");
            i = paren + 1;
            continue;
        }
        plain.push(c);
        i += 1;
    }
    flush!();
    out
}

/// Index of the next `target` char at or after `from`, if any.
fn find_char(chars: &[char], from: usize, target: char) -> Option<usize> {
    (from..chars.len()).find(|&j| chars[j] == target)
}

/// Index where the two-char `seq` next starts at or after `from`, if any.
fn find_seq(chars: &[char], from: usize, seq: &[char; 2]) -> Option<usize> {
    (from..chars.len().saturating_sub(1)).find(|&j| chars[j] == seq[0] && chars[j + 1] == seq[1])
}

/// Split a message into <=4096-char chunks, preferring newline boundaries (a
/// report is line-structured) and falling back to a hard char split.
fn split_for_telegram(text: &str) -> Vec<String> {
    if text.chars().count() <= TELEGRAM_MAX_CHARS {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;
    for line in text.split_inclusive('\n') {
        let line_len = line.chars().count();
        if current_len + line_len > TELEGRAM_MAX_CHARS {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
                current_len = 0;
            }
            // A single line longer than the cap: hard-split it.
            if line_len > TELEGRAM_MAX_CHARS {
                let mut buf = String::new();
                let mut n = 0;
                for ch in line.chars() {
                    buf.push(ch);
                    n += 1;
                    if n == TELEGRAM_MAX_CHARS {
                        chunks.push(std::mem::take(&mut buf));
                        n = 0;
                    }
                }
                current = buf;
                current_len = current.chars().count();
                continue;
            }
        }
        current.push_str(line);
        current_len += line_len;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Whether an inbound Telegram update is a 1:1 direct message (chat.type ==
/// "private"). This channel binds the chat id as an operator handle, so it
/// must only ever act in a private chat: in a group/supergroup/channel the
/// id is the GROUP's, and treating it as an operator would leak that
/// operator's content to the whole room and let anyone there drive it. A
/// missing/unknown type fails CLOSED (not private) so a malformed update can
/// never slip through the guard.
fn is_private_chat(msg: &serde_json::Value) -> bool {
    msg["chat"]["type"].as_str() == Some("private")
}

#[cfg(test)]
mod chat_type_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_private_chats_are_processed() {
        // A 1:1 DM is the only chat this channel acts in.
        assert!(is_private_chat(&json!({ "chat": { "id": 42, "type": "private" } })));

        // Group / supergroup / channel updates are rejected — processing one
        // would bind the GROUP id as an operator handle and leak content.
        for kind in ["group", "supergroup", "channel"] {
            let msg = json!({ "chat": { "id": -100, "type": kind } });
            assert!(!is_private_chat(&msg), "chat.type={kind} must not be treated as private");
        }

        // A missing or non-string type fails closed (not private).
        assert!(!is_private_chat(&json!({ "chat": { "id": 42 } })));
        assert!(!is_private_chat(&json!({ "chat": { "id": 42, "type": 7 } })));
        assert!(!is_private_chat(&json!({})));
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;

    #[test]
    fn short_messages_pass_through() {
        assert_eq!(split_for_telegram("hello"), vec!["hello"]);
    }

    #[test]
    fn long_messages_split_under_the_cap_without_loss() {
        let lines: Vec<String> =
            (0..200).map(|i| format!("line {i}: {}", "x".repeat(40))).collect();
        let text = lines.join("\n");
        let chunks = split_for_telegram(&text);
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|c| c.chars().count() <= TELEGRAM_MAX_CHARS));
        assert_eq!(chunks.concat(), text, "no content lost");
    }

    #[test]
    fn one_giant_line_is_hard_split() {
        let text = "y".repeat(TELEGRAM_MAX_CHARS * 2 + 10);
        let chunks = split_for_telegram(&text);
        assert!(chunks.iter().all(|c| c.chars().count() <= TELEGRAM_MAX_CHARS));
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn splits_prefer_newline_boundaries() {
        // Two lines that individually fit but together exceed the cap must
        // split BETWEEN them, not mid-line.
        let a = "a".repeat(3000);
        let b = "b".repeat(3000);
        let text = format!("{a}\n{b}");
        let chunks = split_for_telegram(&text);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].trim_end_matches('\n').chars().all(|c| c == 'a'));
        assert!(chunks[1].chars().all(|c| c == 'b'));
    }
}

#[cfg(test)]
mod html_tests {
    use super::*;

    fn html(md: &str) -> String {
        markdown_to_telegram_html(md)
    }

    #[test]
    fn the_reported_bold_case_renders() {
        // The exact string from gianna's bug report.
        assert_eq!(html("**3. Review.** Gently,"), "<b>3. Review.</b> Gently,");
    }

    #[test]
    fn bold_italic_and_code_spans() {
        assert_eq!(html("**bold**"), "<b>bold</b>");
        assert_eq!(html("__also bold__"), "<b>also bold</b>");
        assert_eq!(html("*italic*"), "<i>italic</i>");
        assert_eq!(html("_italic_"), "<i>italic</i>");
        assert_eq!(html("`code`"), "<code>code</code>");
    }

    #[test]
    fn html_special_chars_are_escaped() {
        assert_eq!(html("a < b & c > d"), "a &lt; b &amp; c &gt; d");
        assert_eq!(html("**x & y**"), "<b>x &amp; y</b>");
    }

    #[test]
    fn headings_become_bold_lines() {
        assert_eq!(html("# Title"), "<b>Title</b>");
        assert_eq!(html("### Sub"), "<b>Sub</b>");
    }

    #[test]
    fn bullets_get_a_dot_marker() {
        assert_eq!(html("- one\n- two"), "• one\n• two");
        assert_eq!(html("* star bullet"), "• star bullet");
    }

    #[test]
    fn links_render_as_anchors() {
        assert_eq!(
            html("[OpsClaw](https://opsclaw.test)"),
            "<a href=\"https://opsclaw.test\">OpsClaw</a>"
        );
    }

    #[test]
    fn fenced_code_block_is_preformatted_and_escaped() {
        let md = "before\n```\nlet x = a < b;\n```\nafter";
        let out = html(md);
        assert!(out.contains("<pre>let x = a &lt; b;\n</pre>"), "got: {out}");
        assert!(out.starts_with("before\n"));
        assert!(out.ends_with("\nafter"));
    }

    #[test]
    fn code_block_with_language_label_drops_the_label() {
        let out = html("```rust\nfn main() {}\n```");
        assert_eq!(out, "<pre>fn main() {}\n</pre>");
    }

    #[test]
    fn inline_code_is_not_treated_as_markup() {
        assert_eq!(html("`a * b`"), "<code>a * b</code>");
    }

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(html("just a normal sentence."), "just a normal sentence.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    #[test]
    fn self_handle_set_from_username() {
        let t = TelegramChannel::new(
            "123:abc".into(),
            client(),
            Arc::new(InMemoryRoster::new()),
            Arc::new(InMemoryOffsetStore::new()),
        )
        .with_username("@opsclaw_bot");
        assert_eq!(t.self_handle().as_deref(), Some("@opsclaw_bot"));
        assert!(t.drop_self_messages(&InboundMessage {
            sender: "opsclaw_bot".into(),
            body: "hi".into(),
            channel: "telegram".into(),
        }));
        assert!(!t.drop_self_messages(&InboundMessage {
            sender: "4242".into(),
            body: "hi".into(),
            channel: "telegram".into(),
        }));
    }

    #[test]
    fn api_url_construction() {
        let t = TelegramChannel::new(
            "TOK".into(),
            client(),
            Arc::new(InMemoryRoster::new()),
            Arc::new(InMemoryOffsetStore::new()),
        );
        assert_eq!(t.api("getUpdates"), "https://api.telegram.org/botTOK/getUpdates");
    }

    #[tokio::test]
    async fn proactive_send_is_noop_without_a_linked_operator() {
        let t = TelegramChannel::new(
            "TOK".into(),
            client(),
            Arc::new(InMemoryRoster::new()),
            Arc::new(InMemoryOffsetStore::new()),
        );
        // No roster entries -> send resolves to nothing and returns Ok (the
        // operator is reachable on another channel).
        let r = t.send(OutboundMessage { operator: None, body: "hi".into() }).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn can_reach_reflects_roster_membership() {
        let roster = Arc::new(InMemoryRoster::new());
        let op = Uuid::new_v4();
        roster.bind("111", op);
        let t = TelegramChannel::new(
            "TOK".into(),
            client(),
            roster.clone(),
            Arc::new(InMemoryOffsetStore::new()),
        );
        assert!(t.can_reach(Some(op)).await);
        assert!(!t.can_reach(Some(Uuid::new_v4())).await);
        // None (broadcast) is reachable whenever the roster is non-empty.
        assert!(t.can_reach(None).await);
    }

    #[test]
    fn inbound_sender_is_prefixed() {
        // The listen loop emits "tg:<chat_id>" handles; send_reply strips it.
        assert_eq!(TELEGRAM_HANDLE_PREFIX, "tg:");
    }

    #[tokio::test]
    async fn roster_chat_ids_for_broadcast_and_targeted() {
        let roster = InMemoryRoster::new();
        let anna = Uuid::new_v4();
        let tom = Uuid::new_v4();
        roster.bind("111", anna);
        roster.bind("222", tom);

        let mut all = roster.chat_ids_for(None).await;
        all.sort();
        assert_eq!(all, vec!["111", "222"]);

        assert_eq!(roster.chat_ids_for(Some(tom)).await, vec!["222"]);
    }
}

#[cfg(test)]
mod db_adapter_tests {
    use super::*;
    use crate::db::ChannelStateRepo;
    use crate::db::memory::InMemoryDb;

    fn repo() -> Arc<dyn ChannelStateRepo> {
        Arc::new(InMemoryDb::new())
    }

    #[tokio::test]
    async fn db_roster_reflects_repo_bindings_and_survives_a_fresh_handle() {
        let repo = repo();
        let anna = Uuid::new_v4();
        repo.bind_telegram_chat("111", anna).await.unwrap();

        // A FRESH DbTelegramRoster over the SAME repo sees the binding —
        // this is the whole point (a restart constructs a new roster
        // instance, but the underlying store is durable).
        let roster = DbTelegramRoster::new(repo.clone());
        assert_eq!(roster.find_operator("111").await, Some(anna));
        assert_eq!(roster.chat_ids_for(None).await, vec!["111"]);
        assert_eq!(roster.chat_ids_for(Some(anna)).await, vec!["111"]);
        assert!(roster.find_operator("unknown").await.is_none());
    }

    #[tokio::test]
    async fn db_offset_store_roundtrips_and_survives_a_fresh_handle() {
        let repo = repo();
        let store = DbOffsetStore::new(repo.clone());
        assert_eq!(store.load(TELEGRAM_OFFSET_KEY).await.unwrap(), None);

        store.store(TELEGRAM_OFFSET_KEY, 101).await.unwrap();

        // A fresh handle over the same repo reads back the persisted value —
        // the exact property InMemoryOffsetStore could never offer (its
        // module doc: "process-lifetime only — a restart starts from 0").
        let reloaded = DbOffsetStore::new(repo.clone());
        assert_eq!(reloaded.load(TELEGRAM_OFFSET_KEY).await.unwrap(), Some(101));

        reloaded.store(TELEGRAM_OFFSET_KEY, 202).await.unwrap();
        assert_eq!(store.load(TELEGRAM_OFFSET_KEY).await.unwrap(), Some(202));
    }
}

/// Wiremock-backed tests: exercise the real HTTP paths (offset advance,
/// 429 retry_after, HTML-reject fallback, chunking, group rejection)
/// against a mock Telegram API rather than unit-testing the pure helpers.
#[cfg(test)]
mod wiremock_tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn channel(server: &MockServer) -> TelegramChannel {
        TelegramChannel::new(
            "TESTTOKEN".into(),
            reqwest::Client::new(),
            Arc::new(InMemoryRoster::new()),
            Arc::new(InMemoryOffsetStore::new()),
        )
        .with_base_url(server.uri())
    }

    #[tokio::test]
    async fn offset_advances_only_after_handoff_and_persists() {
        let server = MockServer::start().await;
        let offsets = Arc::new(InMemoryOffsetStore::new());
        let roster: Arc<dyn TelegramRoster> = Arc::new(InMemoryRoster::new());

        // First getUpdates call returns one private-chat text update; the
        // second call (after the offset has advanced) returns an empty
        // result so the poll loop has nothing left to do — we then cancel
        // via shutdown to end the test.
        Mock::given(method("GET"))
            .and(path("/botTESTTOKEN/getUpdates"))
            .and(wiremock::matchers::query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "result": [{
                    "update_id": 100,
                    "message": {
                        "chat": { "id": 555, "type": "private" },
                        "text": "hello"
                    }
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Once handed off, the offset must be 101 (update_id + 1): the next
        // poll requests offset=101.
        Mock::given(method("GET"))
            .and(path("/botTESTTOKEN/getUpdates"))
            .and(wiremock::matchers::query_param("offset", "101"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "ok": true, "result": [] })),
            )
            .mount(&server)
            .await;

        let shutdown = tokio_util::sync::CancellationToken::new();
        let t = TelegramChannel::new(
            "TESTTOKEN".into(),
            reqwest::Client::new(),
            roster,
            offsets.clone(),
        )
        .with_base_url(server.uri())
        .with_shutdown(shutdown.clone());

        let (tx, mut rx) = mpsc::channel(8);
        let listen = tokio::spawn(async move { t.listen(tx).await });

        // Drain the one inbound message the fixture produces.
        let inbound = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("listen produced a message before timing out")
            .expect("channel open");
        assert_eq!(inbound.sender, "tg:555");
        assert_eq!(inbound.body, "hello");

        // Give the loop a moment to persist the advanced cursor, then verify
        // it, then shut the loop down.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(offsets.load(TELEGRAM_OFFSET_KEY).await.unwrap(), Some(101));

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), listen).await;
    }

    #[tokio::test]
    async fn group_chat_updates_are_rejected_and_offset_still_advances() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/botTESTTOKEN/getUpdates"))
            .and(wiremock::matchers::query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "result": [{
                    "update_id": 7,
                    "message": {
                        "chat": { "id": -999, "type": "group" },
                        "text": "hi everyone"
                    }
                }]
            })))
            .mount(&server)
            .await;
        // The channel must send the "direct chat only" rejection reply.
        Mock::given(method("POST"))
            .and(path("/botTESTTOKEN/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/botTESTTOKEN/getUpdates"))
            .and(wiremock::matchers::query_param("offset", "8"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "ok": true, "result": [] })),
            )
            .mount(&server)
            .await;

        let offsets = Arc::new(InMemoryOffsetStore::new());
        let shutdown = tokio_util::sync::CancellationToken::new();
        let t = TelegramChannel::new(
            "TESTTOKEN".into(),
            reqwest::Client::new(),
            Arc::new(InMemoryRoster::new()),
            offsets.clone(),
        )
        .with_base_url(server.uri())
        .with_shutdown(shutdown.clone());

        let (tx, mut rx) = mpsc::channel(8);
        let listen = tokio::spawn(async move { t.listen(tx).await });

        // No inbound message should ever be enqueued for the group chat.
        let got = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        assert!(got.is_err(), "group chat update must not be handed to the orchestrator");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(offsets.load(TELEGRAM_OFFSET_KEY).await.unwrap(), Some(8));

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), listen).await;
    }

    #[tokio::test]
    async fn honours_retry_after_on_429_then_succeeds() {
        let server = MockServer::start().await;

        // First attempt: 429 with retry_after=1. Second attempt: success.
        Mock::given(method("POST"))
            .and(path("/botTESTTOKEN/sendMessage"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(json!({ "ok": false, "parameters": { "retry_after": 1 } })),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/botTESTTOKEN/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
            .mount(&server)
            .await;

        let t = channel(&server).await;
        let start = std::time::Instant::now();
        let r = t.send_to_chat("555", "hello").await;
        assert!(r.is_ok(), "{r:?}");
        // The retry must have honoured the server's retry_after (>= ~1s),
        // not just the exponential backoff default.
        assert!(start.elapsed() >= std::time::Duration::from_millis(900));
    }

    #[tokio::test]
    async fn html_rejection_falls_back_to_plain_text() {
        let server = MockServer::start().await;

        // HTML send: Telegram rejects our markup with a 400.
        Mock::given(method("POST"))
            .and(path("/botTESTTOKEN/sendMessage"))
            .and(wiremock::matchers::body_string_contains("\"parse_mode\":\"HTML\""))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "ok": false,
                "description": "Bad Request: can't parse entities"
            })))
            .mount(&server)
            .await;
        // Plain-text fallback (no parse_mode field) must succeed.
        Mock::given(method("POST"))
            .and(path("/botTESTTOKEN/sendMessage"))
            .and(wiremock::matchers::body_json(json!({ "chat_id": "555", "text": "**broken" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
            .mount(&server)
            .await;

        let t = channel(&server).await;
        let r = t.send_to_chat("555", "**broken").await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn long_message_is_chunked_into_multiple_send_calls() {
        let server = MockServer::start().await;
        // Two lines that individually fit under the cap but together exceed
        // it must be split into exactly two `sendMessage` calls.
        let expected_chunks =
            split_for_telegram(&format!("{}\n{}", "a".repeat(3000), "b".repeat(3000)));
        assert_eq!(expected_chunks.len(), 2, "test fixture must actually need chunking");

        Mock::given(method("POST"))
            .and(path("/botTESTTOKEN/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
            .expect(2)
            .mount(&server)
            .await;

        let t = channel(&server).await;
        let text = format!("{}\n{}", "a".repeat(3000), "b".repeat(3000));
        let r = t.send_to_chat("555", &text).await;
        assert!(r.is_ok(), "{r:?}");
        // `expect(2)` above is verified when the MockServer drops.
    }
}
