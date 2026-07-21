//! Inbound webhook ingestion (DESIGN §3: "Webhook ingestion (Alertmanager,
//! PagerDuty) → same orchestrator path as chat; HMAC/token verification
//! with constant-time compare"). Alertmanager-shaped first (its `POST
//! /api/v2/alerts`-style JSON body), since that's the receiver DESIGN.md
//! names first; PagerDuty's shape can be added as a sibling route sharing
//! the same HMAC verification once its exact payload contract is needed.
//!
//! The signature scheme itself (`t=<ts>,v1=<hmac>` over `sha256(secret,
//! "{t}.{body}")`) is NOT Alertmanager's own — it has none — so this is the
//! convention opsclaw's install docs specify for whatever sits in front of
//! it (a relay, or Alertmanager's own `webhook_configs` behind a thin
//! signing shim). See `http::webhook` for the verification primitives.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::Error;
use crate::Result;
use crate::http::state::AppState;
use crate::http::webhook;

pub fn router() -> Router<AppState> {
    Router::new().route("/webhooks/alertmanager", post(alertmanager))
}

const SIGNATURE_HEADER: &str = "x-opsclaw-signature";

/// POST /webhooks/alertmanager — verify the HMAC, frame the payload as DATA
/// (never instructions — brief invariant, see `http::webhook`'s module
/// doc), and hand off to the ingestion seam.
async fn alertmanager(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>> {
    match &state.webhook_secret {
        None => {
            // No secret configured: accept only in fakes mode (no real
            // sender to spoof in a fully-faked daemon) — matching gianna's
            // stripe_webhook stance on an unconfigured secret.
            if !state.config.fully_faked() {
                tracing::warn!("alertmanager webhook rejected: secret not configured");
                return Err(Error::unauthorized("webhook secret not configured"));
            }
        }
        Some(secret) => {
            let sig =
                headers.get(SIGNATURE_HEADER).and_then(|v| v.to_str().ok()).ok_or_else(|| {
                    tracing::warn!("alertmanager webhook rejected: missing signature header");
                    Error::unauthorized("missing webhook signature")
                })?;
            if let Err(e) =
                webhook::verify_signature(secret.as_bytes(), sig, &body, chrono::Utc::now())
            {
                tracing::warn!("alertmanager webhook rejected: {e}");
                return Err(e);
            }
        }
    }

    let payload: Value = serde_json::from_slice(&body)
        .map_err(|e| Error::validation(format!("malformed JSON body: {e}")))?;
    state.ingest.ingest("alertmanager", &payload).await?;
    Ok(Json(json!({ "ok": true })))
}
