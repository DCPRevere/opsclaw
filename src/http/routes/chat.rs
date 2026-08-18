//! The web chat surface (DESIGN §3: "Day-one surfaces: agent chat (same
//! orchestrator path as every channel, SSE for proactive push)"). Two
//! routes: `POST /api/chat` runs one turn against the SHARED TEAM
//! transcript `state.chat` already holds (`channels::ChatHandler`,
//! `agent::dispatch::ChatTurn` — see that module's doc for why one
//! transcript, not per-operator); `GET /api/chat/history` renders it on
//! load. Both are cookie-authed (`Authed`) for the web UI; `routes::cli`
//! wires a bearer-authed twin (`POST /cli/v1/chat`) onto the SAME turn
//! logic below (`run_chat_turn`), for the remote CLI's `chat --remote`
//! (DESIGN §7 decision 14: "Remote CLI v1: small set — chat, incidents,
//! approve/deny, estop, status").
//!
//! A chat turn is agent-loop-backed and can genuinely take many seconds
//! (tool calls, LLM round-trips) — there is no router-level request
//! timeout in `routes::mod`'s layer stack to worry about here (checked:
//! only the graceful-shutdown drain budget in `http::server` bounds
//! anything, and that's an orthogonal shutdown concern, not a per-request
//! cap), so a slow turn is never cut off in flight.
//!
//! Broadcast design call: the SSE `"chat"`-kind events (the operator's
//! message before the turn, the agent's live tool calls DURING it, the
//! reply after) are published by `ChatTurn` itself, not here — so a turn
//! entering via Telegram or the CLI reaches web tabs identically to a
//! web-originated one (DESIGN: "web chat is a team surface, one shared
//! conversation"). The HTTP response still carries the reply directly for
//! the CLI twin; the web client renders exclusively from the SSE stream
//! (see `static/app/chat.js`'s module comment).

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Result;
use crate::domain::Principal;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/chat", post(send)).route("/api/chat/history", get(history))
}

#[derive(Deserialize)]
pub struct ChatReq {
    pub message: String,
    /// Optional client-generated replay key. Reusing it for the same account
    /// returns a duplicate response without running another agent turn.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// The shared turn logic both the cookie-authed web route and the
/// bearer-authed `/cli/v1/chat` twin (`routes::cli`) call: run one chat
/// turn as `speaker` under `Principal::Operator { account }`, then
/// broadcast both sides of the exchange to every connected web tab.
/// `state.chat`'s `NoopChat` boot-safe default (fakes mode, or a daemon
/// that hasn't finished wiring the real agent loop) surfaces here as
/// `Error::Unavailable` — propagated through `?` unchanged, so both
/// callers get the same 503 rather than either one masking it as a 500.
pub(crate) async fn run_chat_turn(
    state: &AppState,
    account: uuid::Uuid,
    speaker: &str,
    message: &str,
    idempotency_key: Option<&str>,
) -> Result<(String, bool)> {
    if !state.chat_idempotency.accept(account, idempotency_key) {
        tracing::info!(%account, "dropping duplicate chat send (idempotency key seen)");
        return Ok((String::new(), true));
    }

    // Own the turn in a tracked task. If a browser refresh or network drop
    // cancels this handler future, the agent finishes its tool side effects
    // and transcript writes; graceful shutdown also drains the same tracker.
    let state = state.clone();
    let speaker = speaker.to_string();
    let message = message.to_string();
    use tracing::Instrument;
    let span = tracing::Span::current();
    let turn = state.tasks.spawn(
        async move { state.chat.chat(Principal::Operator { account }, &speaker, &message).await }
            .instrument(span),
    );
    match turn.await {
        Ok(result) => result.map(|reply| (reply, false)),
        Err(error) => {
            tracing::error!(%account, %error, "chat turn task failed");
            Err(crate::Error::other("chat turn failed"))
        }
    }
}

/// POST /api/chat — `{"message": "..."}` -> `{"reply": "..."}`. Cookie-authed
/// (`Authed`); `speaker` is the signed-in operator's `display_name` (same
/// identity `GET /api/me` returns), matching `ChatHandler::chat`'s
/// attribution framing (`"{speaker} said: …"`, DESIGN §3 memory).
async fn send(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Json(req): Json<ChatReq>,
) -> Result<Json<Value>> {
    let account = state
        .repos
        .by_id(ctx.account_id)
        .await?
        .ok_or_else(|| crate::Error::unauthorized("unknown account"))?;
    let (reply, duplicate) = run_chat_turn(
        &state,
        ctx.account_id,
        &account.display_name,
        &req.message,
        req.idempotency_key.as_deref(),
    )
    .await?;
    Ok(Json(json!({ "reply": reply, "duplicate": duplicate })))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    /// When present, page BACKWARD: the newest `PAGE` rows strictly before
    /// this seq (the client hands back the oldest seq it has rendered).
    pub before: Option<i64>,
    /// Optional CLI page size. The web UI omits it and keeps the default.
    pub limit: Option<i64>,
}

/// GET /api/chat/history[?before=<seq>] — the shared transcript for
/// render-on-load, as `{"history": [{"seq", "role", "speaker", "content",
/// "at"}, ...], "has_more": bool}` in render order. Reads the DURABLE log
/// (migration 0007) rather than the in-memory replay transcript, so
/// history survives a daemon restart and includes the agent's tool-call
/// rows (`role: "tool"`) the replay transcript never holds. `has_more` is
/// gianna's full-page heuristic (`msgs.len() == PAGE`): a full page means
/// there is plausibly an earlier one, so the client offers "Show earlier";
/// the one false positive (an archive of exactly a page multiple) costs a
/// single empty fetch, never a wrong render. Empty is "nothing said yet",
/// not a failure.
async fn history(
    State(state): State<AppState>,
    Authed(_ctx): Authed,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Value>> {
    const PAGE: i64 = 100;
    let limit = q.limit.unwrap_or(PAGE).clamp(1, 500);
    let rows = match q.before {
        Some(before) => state.repos.before_chat(before, limit).await?,
        None => state.repos.recent_chat(limit).await?,
    };
    let has_more = rows.len() as i64 == limit;
    Ok(Json(json!({
        "history": rows.into_iter().map(|m| json!({
            "seq": m.seq,
            "role": m.role,
            "speaker": m.speaker,
            "content": m.content,
            "at": m.at.to_rfc3339(),
        })).collect::<Vec<_>>(),
        "has_more": has_more,
    })))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::channels::ChatHandler;

    struct BlockingChat {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        finished: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl ChatHandler for BlockingChat {
        async fn chat(
            &self,
            _principal: Principal,
            _speaker: &str,
            _message: &str,
        ) -> Result<String> {
            self.started.notify_one();
            self.release.notified().await;
            self.finished.notify_one();
            Ok("done".into())
        }
    }

    #[tokio::test]
    async fn detached_turn_finishes_after_request_future_is_cancelled() {
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let finished = Arc::new(tokio::sync::Notify::new());
        let mut state = AppState::fake();
        state.chat = Arc::new(BlockingChat {
            started: started.clone(),
            release: release.clone(),
            finished: finished.clone(),
        });
        let account = uuid::Uuid::new_v4();
        let state2 = state.clone();
        let request = tokio::spawn(async move {
            run_chat_turn(&state2, account, "operator", "check it", Some("request-1")).await
        });
        started.notified().await;
        request.abort();
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), finished.notified())
            .await
            .expect("detached turn must finish after the request disappears");
    }

    #[test]
    fn idempotency_is_scoped_to_the_account_and_bounded() {
        let state = AppState::fake();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        assert!(state.chat_idempotency.accept(a, Some("same")));
        assert!(!state.chat_idempotency.accept(a, Some("same")));
        assert!(state.chat_idempotency.accept(b, Some("same")));
        assert!(state.chat_idempotency.accept(a, None));

        for index in 0..crate::http::state::CHAT_IDEMPOTENCY_MAX {
            assert!(state.chat_idempotency.accept(a, Some(&format!("request-{index}"))));
        }
        assert!(state.chat_idempotency.accept(a, Some("same")), "oldest entry was evicted");
        assert!(
            !state.chat_idempotency.accept(a, Some("request-511")),
            "newest entry remains protected"
        );
    }
}
