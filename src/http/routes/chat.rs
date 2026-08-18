//! The web chat surface (DESIGN §3: "Day-one surfaces: agent chat (same
//! orchestrator path as every channel, SSE for proactive push)"). Two
//! routes: `POST /api/chat` runs one turn in a team-visible conversation:
//! global `Operations` or one configured project environment. History and
//! live events carry the same stable conversation identity; environment
//! selection also narrows the agent's target allow-list. Both routes are
//! cookie-authed (`Authed`) for the web UI; `routes::cli`
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
//! web-originated one. The HTTP response still carries the reply directly for
//! the CLI twin; the web client renders exclusively from the SSE stream
//! (see `static/app/chat.js`'s module comment).

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Result;
use crate::db::{ChatRepo, ChatRequestClaim};
use crate::domain::{ChatConversation, Principal};
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/chat", post(send))
        .route("/api/chat/history", get(history))
        .route("/api/chat/conversations", get(conversations))
}

#[derive(Deserialize)]
pub struct ChatReq {
    pub message: String,
    #[serde(default)]
    pub conversation: Option<String>,
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
    conversation: &ChatConversation,
    idempotency_key: Option<&str>,
) -> Result<(String, bool, String)> {
    let key = idempotency_key.map(str::trim).filter(|key| !key.is_empty());
    if key.is_some_and(|key| key.len() > 128) {
        return Err(crate::Error::validation("idempotency_key must be at most 128 bytes"));
    }
    if let Some(key) = key {
        match ChatRepo::claim_chat_request(
            &*state.repos,
            account,
            &conversation.id(),
            key,
            chrono::Utc::now(),
        )
        .await?
        {
            ChatRequestClaim::Claimed => {}
            ChatRequestClaim::Complete(reply) => {
                tracing::info!(%account, "returning completed chat request replay");
                return Ok((reply, true, key.to_string()));
            }
            ChatRequestClaim::Pending => {
                return Err(crate::Error::Conflict(
                    "this chat request is already in progress".into(),
                ));
            }
            ChatRequestClaim::Failed => {
                return Err(crate::Error::Conflict(
                    "this chat request previously failed and cannot be replayed safely; send it again as a new request after checking the transcript and audit log".into(),
                ));
            }
        }
    }

    // Own the turn in a tracked task. If a browser refresh or network drop
    // cancels this handler future, the agent finishes its tool side effects
    // and transcript writes; graceful shutdown also drains the same tracker.
    let state = state.clone();
    let speaker = speaker.to_string();
    let message = message.to_string();
    let key = key.map(str::to_string);
    let turn_id = key.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let conversation = conversation.clone();
    let task_turn_id = turn_id.clone();
    use tracing::Instrument;
    let span = tracing::Span::current();
    let turn = state.tasks.spawn(async move {
        let result = state
            .chat
            .chat_scoped(
                &conversation,
                &task_turn_id,
                Principal::Operator { account },
                &speaker,
                &message,
            )
            .await;
        match result {
            Ok(reply) => {
                if let Some(key) = &key {
                    ChatRepo::complete_chat_request(
                        &*state.repos,
                        account,
                        key,
                        &reply,
                        chrono::Utc::now(),
                    )
                    .await?;
                }
                Ok(reply)
            }
            Err(error) => {
                if let Some(key) = &key
                    && let Err(store_error) = ChatRepo::fail_chat_request(
                        &*state.repos,
                        account,
                        key,
                        chrono::Utc::now(),
                    )
                    .await
                {
                    tracing::error!(%account, %store_error, "could not mark failed chat request");
                }
                Err(error)
            }
        }
    }.instrument(span));
    match turn.await {
        Ok(result) => result.map(|reply| (reply, false, turn_id)),
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
    let conversation = resolve_conversation(&state, req.conversation.as_deref())?;
    let (reply, duplicate, turn_id) = run_chat_turn(
        &state,
        ctx.account_id,
        &account.display_name,
        &req.message,
        &conversation,
        req.idempotency_key.as_deref(),
    )
    .await?;
    Ok(Json(json!({ "reply": reply, "duplicate": duplicate, "turn_id": turn_id })))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub conversation: Option<String>,
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
    let conversation = resolve_conversation(&state, q.conversation.as_deref())?.id();
    let rows = match q.before {
        Some(before) => state.repos.before_chat(&conversation, before, limit).await?,
        None => state.repos.recent_chat(&conversation, limit).await?,
    };
    let has_more = rows.len() as i64 == limit;
    Ok(Json(json!({
        "history": rows.into_iter().map(|m| json!({
            "seq": m.seq,
            "conversation": m.conversation,
            "turn_id": m.turn_id,
            "role": m.role,
            "speaker": m.speaker,
            "content": m.content,
            "at": m.at.to_rfc3339(),
        })).collect::<Vec<_>>(),
        "has_more": has_more,
    })))
}

pub(crate) fn resolve_conversation(
    state: &AppState,
    raw: Option<&str>,
) -> Result<ChatConversation> {
    let conversation = ChatConversation::parse(raw.unwrap_or(ChatConversation::OPERATIONS_ID))?;
    if let ChatConversation::Environment { project, environment } = &conversation {
        let exists = state.config.projects.iter().any(|configured_project| {
            configured_project.name == *project
                && configured_project.envs.iter().any(|env| env.name == *environment)
        });
        if !exists {
            return Err(crate::Error::NotFound(format!("chat conversation {}", conversation.id())));
        }
    }
    Ok(conversation)
}

async fn conversations(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let mut values = vec![json!({
        "id": ChatConversation::OPERATIONS_ID,
        "kind": "operations",
        "label": "Operations",
    })];
    for project in &state.config.projects {
        for environment in &project.envs {
            let conversation = ChatConversation::environment(&project.name, &environment.name);
            values.push(json!({
                "id": conversation.id(),
                "kind": "environment",
                "label": format!("{} / {}", project.name, environment.name),
                "project": project.name,
                "environment": environment.name,
            }));
        }
    }
    Ok(Json(json!({ "conversations": values })))
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
            run_chat_turn(
                &state2,
                account,
                "operator",
                "check it",
                &ChatConversation::Operations,
                Some("request-1"),
            )
            .await
        });
        started.notified().await;
        request.abort();
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), finished.notified())
            .await
            .expect("detached turn must finish after the request disappears");
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let outcome = ChatRepo::claim_chat_request(
                    &*state.repos,
                    account,
                    "operations",
                    "request-1",
                    chrono::Utc::now(),
                )
                .await
                .unwrap();
                if outcome != ChatRequestClaim::Pending {
                    break outcome;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached turn must persist its terminal outcome");
        assert_eq!(outcome, ChatRequestClaim::Complete("done".into()));
    }
}
