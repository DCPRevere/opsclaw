//! Inbound webhook ingestion (DESIGN §3: "Webhook ingestion (Alertmanager,
//! PagerDuty) → same orchestrator path as chat; HMAC/token verification
//! with constant-time compare"). Two sibling routes sharing the same
//! verification discipline and the same [`IngestAlert`] hand-off seam:
//!
//! - `/webhooks/alertmanager` — Alertmanager-shaped JSON. The signature
//!   scheme (`t=<ts>,v1=<hmac>` over `sha256(secret, "{t}.{body}")`) is NOT
//!   Alertmanager's own — it has none — so this is the convention opsclaw's
//!   install docs specify for whatever sits in front of it (a relay, or
//!   Alertmanager's own `webhook_configs` behind a thin signing shim).
//! - `/webhooks/pagerduty` — PagerDuty v3 webhook subscriptions, verified
//!   against PagerDuty's OWN published scheme (`x-pagerduty-signature:
//!   v1=<hmac_sha256_hex>` over the raw body). Only the incident lifecycle
//!   events reach the ingest seam; everything else (pagey.ping, service.*)
//!   is verified then dropped with a 204.
//!
//! See `http::webhook` for the verification primitives (constant-time
//! compare, both signing schemes).
//!
//! [`IngestAlert`]: crate::http::webhook::IngestAlert

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::Error;
use crate::Result;
use crate::http::state::AppState;
use crate::http::webhook;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/webhooks/alertmanager", post(alertmanager))
        .route("/webhooks/pagerduty", post(pagerduty))
}

const SIGNATURE_HEADER: &str = "x-opsclaw-signature";

/// The header PagerDuty v3 webhook subscriptions sign deliveries with.
const PAGERDUTY_SIGNATURE_HEADER: &str = "x-pagerduty-signature";

/// The PagerDuty v3 event types that reach the ingest seam — the incident
/// lifecycle DESIGN §3's reactive path cares about. Anything else
/// (`pagey.ping`, `incident.annotated`, `service.*`, …) is
/// signature-verified, then deliberately dropped with a 204 so PagerDuty
/// records a success and never retries a delivery we chose to ignore.
const PAGERDUTY_INGESTED_EVENTS: [&str; 3] =
    ["incident.triggered", "incident.acknowledged", "incident.resolved"];

/// The shared no-secret stance for every inbound webhook route: `None`
/// (skip verification) only on the fully-faked spine, where there is no
/// real sender to spoof — matching gianna's stripe_webhook stance on an
/// unconfigured secret. A LIVE daemon with no secret configured refuses
/// outright rather than silently accepting unsigned payloads.
fn required_secret(state: &AppState, source: &str) -> Result<Option<std::sync::Arc<str>>> {
    match &state.webhook_secret {
        Some(secret) => Ok(Some(secret.clone())),
        None if state.config.fully_faked() => Ok(None),
        None => {
            tracing::warn!("{source} webhook rejected: secret not configured");
            Err(Error::unauthorized("webhook secret not configured"))
        }
    }
}

/// POST /webhooks/alertmanager — verify the HMAC, frame the payload as DATA
/// (never instructions — brief invariant, see `http::webhook`'s module
/// doc), and hand off to the ingestion seam.
async fn alertmanager(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>> {
    if let Some(secret) = required_secret(&state, "alertmanager")? {
        let sig = headers.get(SIGNATURE_HEADER).and_then(|v| v.to_str().ok()).ok_or_else(|| {
            tracing::warn!("alertmanager webhook rejected: missing signature header");
            Error::unauthorized("missing webhook signature")
        })?;
        if let Err(e) = webhook::verify_signature(secret.as_bytes(), sig, &body, chrono::Utc::now())
        {
            tracing::warn!("alertmanager webhook rejected: {e}");
            return Err(e);
        }
    }

    let payload: Value = serde_json::from_slice(&body)
        .map_err(|e| Error::validation(format!("malformed JSON body: {e}")))?;
    state.ingest.ingest("alertmanager", &payload).await?;
    Ok(Json(json!({ "ok": true })))
}

/// POST /webhooks/pagerduty — verify PagerDuty's v3 signature over the RAW
/// body, then hand incident lifecycle events to the ingestion seam (same
/// DATA-never-instructions framing as `alertmanager`). Unknown event types
/// return 204 AFTER verification: the drop decision is ours, but only a
/// caller holding the secret gets to learn even that much.
async fn pagerduty(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response> {
    if let Some(secret) = required_secret(&state, "pagerduty")? {
        let sig = headers
            .get(PAGERDUTY_SIGNATURE_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                tracing::warn!("pagerduty webhook rejected: missing signature header");
                Error::unauthorized("missing webhook signature")
            })?;
        if let Err(e) = webhook::verify_pagerduty_signature(secret.as_bytes(), sig, &body) {
            tracing::warn!("pagerduty webhook rejected: {e}");
            return Err(e);
        }
    }

    let payload: Value = serde_json::from_slice(&body)
        .map_err(|e| Error::validation(format!("malformed JSON body: {e}")))?;
    // PagerDuty v3 envelope: `{"event": {"event_type": "incident.triggered",
    // "data": {...}}}`. A missing/non-string event_type is treated as an
    // unknown type (204), not a 400 — PagerDuty's own test pings and future
    // event shapes must never surface as delivery failures on their side.
    let event_type = payload
        .get("event")
        .and_then(|e| e.get("event_type"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !PAGERDUTY_INGESTED_EVENTS.contains(&event_type) {
        tracing::debug!(event_type, "pagerduty webhook event type ignored");
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    state.ingest.ingest("pagerduty", &payload).await?;
    Ok(Json(json!({ "ok": true })).into_response())
}
