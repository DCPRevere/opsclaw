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
//! Broadcast design call: after a successful turn, BOTH the operator's own
//! message and the agent's reply are published to `state.web` (the SSE
//! hub) as `"chat"`-kind events, so every OTHER connected tab sees the
//! live exchange too (DESIGN: "web chat is a team surface, one shared
//! conversation" — the same reasoning `ChatTurn`'s single shared
//! transcript already encodes). The HTTP response to the CALLER also
//! carries the reply directly (`{"reply": "..."}`) — the caller's own tab
//! does NOT wait on its own SSE echo to render the reply (a `POST` that
//! succeeded should show its result immediately, not depend on a second
//! channel), it renders from the POST response, and treats the SSE `chat`
//! event as how OTHER tabs catch up. See `static/app/chat.js`'s own
//! comment for how the client reconciles the two so nothing double-renders
//! for the tab that sent the message.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Result;
use crate::channels::web::WebEvent;
use crate::domain::Principal;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/chat", post(send)).route("/api/chat/history", get(history))
}

#[derive(Deserialize)]
pub struct ChatReq {
    pub message: String,
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
) -> Result<String> {
    let reply = state.chat.chat(Principal::Operator { account }, speaker, message).await?;
    // Team-surface broadcast (module doc above): both sides of the
    // exchange, in order, so every OTHER open tab's chat log matches what
    // the sender's own tab already rendered from this call's return value.
    state.web.publish(WebEvent::chat("user", speaker, message));
    state.web.publish(WebEvent::chat("assistant", "assistant", &reply));
    Ok(reply)
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
    let reply = run_chat_turn(&state, ctx.account_id, &account.display_name, &req.message).await?;
    Ok(Json(json!({ "reply": reply })))
}

/// GET /api/chat/history — the shared transcript for render-on-load, as
/// `{"history": [{"role": ..., "content": ...}, ...]}`. Empty (not an
/// error) when `state.chat` has no transcript to offer (`ChatHandler::
/// transcript`'s defaulted empty `Vec` — a boot-safe `NoopChat` state, or a
/// real `ChatTurn` that hasn't seen a turn yet, look identical here: both
/// are "nothing to show", not a failure).
async fn history(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let history = state.chat.transcript().await;
    Ok(Json(json!({
        "history": history.into_iter().map(|(role, content)| json!({
            "role": role,
            "content": content,
        })).collect::<Vec<_>>()
    })))
}
