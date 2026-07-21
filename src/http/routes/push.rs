//! Web-push subscribe/unsubscribe + the VAPID public-key lookup (DESIGN §4
//! HTTP gateway, PWA/push paragraphs). The app-side flow this backs lives in
//! `static/app/settings.js`; the service-worker side in `static/sw.js`.
//!
//! `subscribe`/`unsubscribe` are `Authed`-gated (a device binds to the
//! signed-in operator's account — `db::PushSubscription::account_id`, kept
//! even though `PushChannel::send` currently fans out to every stored
//! subscription regardless of owner, since DESIGN §1 is single-tenant/
//! team-shared; the column is there for the day per-operator addressing
//! lands, and it makes "whose device is this" inspectable in the meantime).
//!
//! `vapid_public_key` is deliberately left UNAUTHENTICATED: it is not a
//! secret (a VAPID public key is handed to every subscribing browser as
//! `applicationServerKey` — the whole point of a public/private keypair is
//! that this half is safe to expose), and the app shell needs it to call
//! `pushManager.subscribe()` before a first login can complete a round trip
//! in the general case (the shell itself is already an unauthenticated
//! static asset — see `routes::router`'s doc comment). Gating it behind
//! `Authed` would cost real functionality (no way to prime the
//! subscription prompt on the login screen) for no confidentiality benefit.
//! 404s when push isn't configured, so the app can feature-detect.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Error;
use crate::Result;
use crate::db::PushSubscription;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/push/subscribe", post(subscribe))
        .route("/api/push/unsubscribe", post(unsubscribe))
        .route("/api/push/vapid-public-key", get(vapid_public_key))
}

/// The standard browser `PushSubscription.toJSON()` shape:
/// `{ endpoint, keys: { p256dh, auth } }`.
#[derive(Deserialize)]
pub struct SubscribeReq {
    pub endpoint: String,
    pub keys: SubscribeKeys,
}

#[derive(Deserialize)]
pub struct SubscribeKeys {
    pub p256dh: String,
    pub auth: String,
}

#[derive(Deserialize)]
pub struct UnsubscribeReq {
    pub endpoint: String,
}

/// POST /api/push/subscribe — store (or, for a device re-subscribing under
/// the same endpoint, overwrite — `upsert_push_subscription`'s contract) one
/// device's push credentials.
async fn subscribe(
    State(state): State<AppState>,
    Authed(ctx): Authed,
    Json(req): Json<SubscribeReq>,
) -> Result<Json<Value>> {
    if req.endpoint.trim().is_empty() {
        return Err(Error::validation("push subscription missing endpoint"));
    }
    if req.keys.p256dh.trim().is_empty() || req.keys.auth.trim().is_empty() {
        return Err(Error::validation("push subscription missing p256dh/auth keys"));
    }
    let sub = PushSubscription {
        endpoint: req.endpoint,
        account_id: ctx.account_id,
        p256dh: req.keys.p256dh,
        auth: req.keys.auth,
        created_at: Utc::now(),
    };
    state.repos.upsert_push_subscription(&sub).await?;
    Ok(Json(json!({ "subscribed": true })))
}

/// POST /api/push/unsubscribe — drop one device's subscription (the browser
/// calls this after `pushManager.getSubscription().unsubscribe()` locally,
/// so the daemon stops attempting delivery to a client that no longer wants
/// it — otherwise every future push would harmlessly 404/410 and self-prune,
/// but there is no reason to wait for that when the browser already knows).
async fn unsubscribe(
    State(state): State<AppState>,
    Authed(_ctx): Authed,
    Json(req): Json<UnsubscribeReq>,
) -> Result<Json<Value>> {
    state.repos.delete_push_subscription(&req.endpoint).await?;
    Ok(Json(json!({ "unsubscribed": true })))
}

/// GET /api/push/vapid-public-key — the `applicationServerKey` the app-side
/// subscribe flow needs. 404 (not an empty/null 200) when push isn't
/// configured, so the client can cleanly skip offering the "enable
/// notifications" affordance rather than trying and failing.
async fn vapid_public_key(State(state): State<AppState>) -> Result<Json<Value>> {
    let key = state
        .config
        .push
        .vapid_public_key
        .as_deref()
        .ok_or_else(|| Error::NotFound("push is not configured on this daemon".into()))?;
    Ok(Json(json!({ "vapid_public_key": key })))
}

// HTTP-level coverage (real bound server + reqwest — this repo's e2e
// convention, `tests/e2e_flow.rs`'s module doc) lives there, not here: an
// auth round trip needs a seeded account + login, which that file's fixtures
// already provide. See `push_subscribe_requires_auth_then_roundtrips` and
// `vapid_public_key_is_unauthenticated_and_404s_when_unconfigured`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_req_deserializes_the_standard_browser_shape() {
        let raw = serde_json::json!({
            "endpoint": "https://push.example/ep",
            "keys": { "p256dh": "k", "auth": "a" },
            "expirationTime": null
        });
        let req: SubscribeReq = serde_json::from_value(raw).expect("standard shape parses");
        assert_eq!(req.endpoint, "https://push.example/ep");
        assert_eq!(req.keys.p256dh, "k");
        assert_eq!(req.keys.auth, "a");
    }
}
