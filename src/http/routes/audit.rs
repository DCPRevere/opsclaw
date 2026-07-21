//! Audit range + verify (DESIGN §5: "`opsclaw audit verify`"; DESIGN §3's
//! HTTP gateway carries the same surface for the web UI/remote CLI). Reads
//! `db::AuditRepo::range` and re-derives the hash chain via
//! `audit::chain::verify` — the SAME verification the CLI command runs, so
//! the HTTP and CLI paths can never disagree about whether the chain is
//! intact.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Result;
use crate::audit::chain;
use crate::http::handlers::Authed;
use crate::http::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/audit", get(range)).route("/api/audit/verify", get(verify))
}

#[derive(Deserialize)]
pub struct RangeQuery {
    #[serde(default = "default_from_seq")]
    from_seq: i64,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_from_seq() -> i64 {
    1
}

fn default_limit() -> i64 {
    100
}

fn record_json(r: &crate::audit::AuditRecord) -> Value {
    json!({
        "id": r.id,
        "seq": r.seq,
        "ts": r.ts,
        "principal": r.principal,
        "fq_target": r.fq_target,
        "tool": r.tool,
        "command": r.command,
        "risk": r.risk,
        "outcome": r.outcome,
        "exit_code": r.exit_code,
        "prev_hash": r.prev_hash,
        "hash": r.hash,
    })
}

/// GET /api/audit?from_seq=&limit= — page through the chain in seq order.
async fn range(
    State(state): State<AppState>,
    Authed(_ctx): Authed,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Value>> {
    let records = state.repos.range(q.from_seq, q.limit).await?;
    Ok(Json(json!({ "records": records.iter().map(record_json).collect::<Vec<_>>() })))
}

/// GET /api/audit/verify — walk the WHOLE chain (paged internally) and
/// re-derive every hash/link. `ok: false` names the exact break (bad seq,
/// broken link, or a tampered hash) rather than a bare failure — an
/// operator investigating tampering needs to know WHERE the chain broke.
///
/// Verifies PAGE BY PAGE via `chain::verify_from`, carrying the previous
/// page's last record forward as the next page's trusted `tail` — NOT by
/// accumulating every page into one `Vec` and calling `chain::verify` once
/// at the end. `chain::verify`/`verify_from(None, ..)` requires its FIRST
/// record to be the genesis record (seq 1, zero prev-hash); calling it
/// fresh on each page independently would make page 2 of an intact chain
/// fail with `BadSeq` (its first record has seq 1001, not 1). This is the
/// exact trap `audit::chain::verify_from`'s own doc comment calls out.
async fn verify(State(state): State<AppState>, Authed(_ctx): Authed) -> Result<Json<Value>> {
    let mut tail: Option<crate::audit::AuditRecord> = None;
    let mut total = 0u64;
    let mut from_seq = 1i64;
    loop {
        let page = state.repos.range(from_seq, 1000).await?;
        if page.is_empty() {
            break;
        }
        from_seq = page.last().map(|r| r.seq + 1).unwrap_or(from_seq);
        match chain::verify_from(tail.as_ref(), page.iter()) {
            Ok(count) => total += count,
            Err(e) => return Ok(Json(json!({ "ok": false, "error": format!("{e:?}") }))),
        }
        tail = page.into_iter().next_back();
    }
    Ok(Json(json!({ "ok": true, "records_verified": total })))
}
