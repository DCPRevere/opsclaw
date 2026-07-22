//! SSE stream auth: short-lived signed stream tickets (DESIGN §3: "SSE auth
//! uses short-lived signed stream tickets (never a long-lived token in a
//! query string)"). Ported from gianna's `chat_api::stream_ticket`/`stream`
//! (`src/http/chat_api.rs`) — simplified for opsclaw's single-tenant shape
//! (no household|member binding; the `bind` claim is unused here but kept
//! on the wire via `auth::issue_scoped`'s general shape for parity with the
//! CLI PKCE code, which DOES use it).
//!
//! Why a ticket at all, rather than the session cookie: `EventSource`
//! cannot set custom headers, so the only way to authenticate the stream
//! request is a query parameter — but a query string lands in proxy/access
//! logs, so it must never carry the real session token. The ticket is a
//! separate, purpose-scoped ("sse"), 60-second, single-use credential:
//! worthless seconds after mint, and worthless a second time even within
//! that window.

use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::Duration;
use futures::Stream;
use serde_json::{Value, json};
use std::collections::HashMap;

use super::auth;
use super::state::AppState;
use crate::http::handlers::Authed;
use crate::{Error, Result};

const TICKET_PURPOSE: &str = "sse";
const TICKET_TTL_SECS: i64 = 60;
/// How long a used ticket's entry lingers in the replay guard after it
/// would have expired anyway — a small margin over the ticket TTL so a
/// borderline-timed replay attempt is still caught rather than falling
/// through a sweep race.
const REPLAY_GUARD_MARGIN_SECS: i64 = 30;

/// GET /api/stream-ticket — mint a 60-second single-purpose ticket for the
/// SSE stream. Cookie-authed like any other operator action; the returned
/// ticket is what the browser's `EventSource` then uses instead.
pub async fn stream_ticket(
    State(state): State<AppState>,
    Authed(ctx): Authed,
) -> Result<axum::Json<Value>> {
    let ticket = auth::issue_scoped(
        &state.jwt_secret,
        ctx.account_id,
        TICKET_PURPOSE,
        Duration::seconds(TICKET_TTL_SECS),
        "",
    )?;
    Ok(axum::Json(json!({ "ticket": ticket })))
}

/// GET /api/stream — the SSE connection itself. Only the short-lived stream
/// ticket is accepted here (`?token=`) — never the session cookie/token
/// (it would end up in access logs via the query string).
pub async fn stream(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, std::convert::Infallible>>>> {
    let token = q.get("token").ok_or_else(|| Error::unauthorized("missing token"))?;
    let (_account, _bind) = auth::verify_scoped_claims(&state.jwt_secret, token, TICKET_PURPOSE)?;

    // SINGLE-USE: a leaked ticket (URL in a log, referrer header) is
    // worthless after the first connect.
    {
        let now = chrono::Utc::now().timestamp();
        let mut used = state.used_stream_tickets.lock().unwrap();
        used.retain(|_, exp| *exp > now);
        if used.insert(token.clone(), now + TICKET_TTL_SECS + REPLAY_GUARD_MARGIN_SECS).is_some() {
            return Err(Error::unauthorized("ticket already used"));
        }
    }

    Ok(Sse::new(event_stream(&state)).keep_alive(KeepAlive::default()))
}

/// The event stream itself, separated from the auth handler so termination
/// is testable without a bound socket. The stream must END on daemon
/// shutdown: axum's graceful drain waits for every open connection, and a
/// stream blocked on `rx.recv()` never closes on its own (the hub's sender
/// lives in AppState, so `Closed` can't fire) — one open browser tab held
/// Ctrl+C hostage forever until the shutdown select was added.
fn event_stream(
    state: &AppState,
) -> impl Stream<Item = std::result::Result<Event, std::convert::Infallible>> + use<> {
    let mut rx = state.web.subscribe();
    let shutdown = state.shutdown.clone();
    async_stream::stream! {
        yield Ok(Event::default().event("ready").data("connected"));
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                recv = rx.recv() => match recv {
                    Ok(ev) => {
                        let data = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".into());
                        yield Ok(Event::default().event(ev.kind).data(data));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(dropped = n, "SSE receiver lagged; events dropped");
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::state::AppState;

    #[tokio::test]
    async fn stream_rejects_a_missing_token() {
        let state = AppState::fake();
        let err = stream(State(state), Query(HashMap::new())).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[tokio::test]
    async fn stream_rejects_a_token_of_the_wrong_purpose() {
        let state = AppState::fake();
        // A CLI-purposed token must not authenticate the SSE stream.
        let tok = auth::issue_scoped(
            &state.jwt_secret,
            uuid::Uuid::new_v4(),
            "cli",
            Duration::seconds(60),
            "",
        )
        .unwrap();
        let mut q = HashMap::new();
        q.insert("token".to_string(), tok);
        let err = stream(State(state), Query(q)).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[tokio::test]
    async fn a_valid_ticket_is_single_use() {
        let state = AppState::fake();
        let tok = auth::issue_scoped(
            &state.jwt_secret,
            uuid::Uuid::new_v4(),
            TICKET_PURPOSE,
            Duration::seconds(60),
            "",
        )
        .unwrap();
        let mut q = HashMap::new();
        q.insert("token".to_string(), tok.clone());

        // First connect succeeds (constructing the Sse response doesn't
        // poll the stream, so this just proves the auth+replay-guard path).
        let _ = stream(State(state.clone()), Query(q.clone())).await.unwrap();

        // Same ticket again: rejected as already used.
        let err = stream(State(state), Query(q)).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[tokio::test]
    async fn stream_terminates_when_the_shutdown_token_fires() {
        use futures::StreamExt;
        let state = AppState::fake();
        let mut s = Box::pin(event_stream(&state));

        // The greeting arrives; the stream is then parked on the hub.
        let first = s.next().await.expect("ready event");
        assert!(first.is_ok());

        // Cancelling the daemon's token must END the stream — not leave it
        // blocked (the exact hang: graceful shutdown waiting on an open
        // tab's SSE connection forever).
        state.shutdown.cancel();
        let end = tokio::time::timeout(std::time::Duration::from_secs(2), s.next()).await;
        assert!(
            matches!(end, Ok(None)),
            "stream must terminate on shutdown, got a timeout or another event"
        );
    }
}
