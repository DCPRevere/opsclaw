//! Hindsight memory backend (the real vectorize-io/hindsight service, 0.7.2).
//!
//! Hindsight is a knowledge-graph agent memory: we hand it RAW content and its
//! own LLM decomposes it into typed facts (world / experience / observation),
//! then a background worker CONSOLIDATES the raw facts into deduplicated
//! `observation` beliefs. Idiomatic use (learned the hard way in gianna's prod,
//! carried over unchanged):
//!
//! - **Retain raw, never pre-summarise** — a hand-written summary is kept whole
//!   as one fact; raw text gets atomised. Frame "<speaker> said: …" (or, for
//!   passive observations, "scan of <target> observed: …") so the shared team
//!   bank anchors first-person statements and scan findings to their source.
//! - **`document_id` makes a re-retain an UPSERT** (replace the prior facts), so
//!   a correction supersedes instead of duplicating. `timestamp`/`context`
//!   enable temporal retrieval and better extraction.
//! - **`list` ≠ `recall`**: `list` is the complete, deterministic enumeration
//!   (use for "show everything" — filter `type=observation` for the deduplicated
//!   layer); `recall` is a semantic ranking for the agent's topical lookups.
//! - **Configure the bank** (`PATCH /config`, fields wrapped in `updates`) so
//!   extraction/reflection are steered for an SRE domain instead of stock
//!   defaults.
//!
//! Tenancy: OpsClaw is single-tenant (DESIGN §1 — "no tenancy ids thread
//! through the code"), so there is exactly ONE Hindsight bank per daemon,
//! `opsclaw-{team_id}` (`team_id` from `MemoryCfg`, default `"default"`), baked
//! in at construction instead of threaded through every call as gianna's
//! per-household `bank(household_id)` did. This is the adapt-commit tenancy
//! change from the verbatim port.
//!
//! Hindsight is the sole memory backend, selected when `HINDSIGHT_URL` is set.
//! Without it, memory is a no-op (there is no in-process fallback). See `Memory`.

use crate::{Error, Result};

/// Per-request deadline for INTERACTIVE reads (recall / reflect / list), which
/// run inside the agent tool loop where a hung backend would otherwise burn up
/// to 30s per loop step. Writes keep the client's generous default (see `new`)
/// — they run detached and retried, so a slow write costs no user-visible
/// latency.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A thin REST client for a self-hosted Hindsight instance, scoped to this
/// team's single bank.
pub struct HindsightClient {
    http: reqwest::Client,
    base_url: String,
    /// Optional bearer token for the Hindsight API (local instances may omit it).
    auth: Option<String>,
    /// This team's bank id (`opsclaw-{team_id}`), fixed for the client's
    /// lifetime — single-tenant, so there is nothing to key per call.
    bank: String,
}

impl HindsightClient {
    /// `team_id` is `MemoryCfg::team_id` (default `"default"`); the bank id is
    /// `opsclaw-{team_id}`.
    pub fn new(base_url: impl Into<String>, auth: Option<String>, team_id: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest builds"),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth,
            bank: format!("opsclaw-{team_id}"),
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut b = self.http.request(method, format!("{}{path}", self.base_url));
        if let Some(token) = &self.auth {
            b = b.header("authorization", format!("Bearer {token}"));
        }
        b
    }

    /// Cheap liveness probe for readiness checks: `GET /health` (Hindsight's own
    /// "API + database connection" check — no bank, no LLM, no extraction). Used
    /// by `/ready?deep=1` so a monitor sees Hindsight is reachable, since every
    /// tool-loop recall blocks on it and the process REFUSES to boot without it
    /// in live mode (config.rs). A short timeout keeps the probe from hanging
    /// the healthcheck.
    pub async fn health(&self) -> Result<()> {
        let resp = self
            .req(reqwest::Method::GET, "/health")
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
            .map_err(|e| Error::other(format!("hindsight health: {e}")))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::other(format!("hindsight health: HTTP {}", resp.status().as_u16())))
        }
    }

    /// Delete the team's entire memory bank — an operator-triggered wipe. A 404
    /// counts as success (nothing was ever stored).
    pub async fn delete_bank(&self) -> Result<()> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/v1/default/banks/{}", self.bank))
            .send()
            .await
            .map_err(|e| Error::other(format!("hindsight delete: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::info!(bank = %self.bank, "memory.erase: no bank to erase");
            return Ok(()); // no bank = nothing to erase
        }
        let status = resp.status().as_u16();
        let r = ensure_ok(resp, "delete").await;
        match &r {
            Ok(()) => tracing::info!(bank = %self.bank, status, "memory.erase ok (bank deleted)"),
            Err(e) => {
                tracing::warn!(bank = %self.bank, status, "memory.erase FAILED — bank may survive: {e}")
            }
        }
        r
    }

    /// retain: hand Hindsight a piece of RAW content to decompose into facts —
    /// we never pre-summarise (that loses the entity/temporal/structural signal
    /// its extractor needs). Framed with the SPEAKER so a shared bank anchors
    /// first-person statements ("I restarted the service") to the operator who
    /// said it, and scan observations to the target they came from.
    ///
    /// `opts` carries the idiomatic per-item fields:
    /// - `document_id` — a STABLE id makes a re-retain UPSERT (replace the prior
    ///   facts) instead of duplicating, so a correction supersedes rather than
    ///   piles up (verified against 0.7.2).
    /// - `timestamp` — when the content occurred; without it temporal retrieval
    ///   is disabled.
    /// - `context` — a short situational note ("operator chat", "scan finding");
    ///   omitting it measurably hurts extraction quality.
    pub async fn retain(&self, framed_content: &str, opts: &RetainOpts) -> Result<()> {
        let body = retain_body(framed_content, opts);
        // Shape + ids at info (no fact text — may carry operational detail); full
        // content at debug.
        tracing::info!(
            bank = %self.bank,
            content_len = framed_content.chars().count(),
            has_doc_id = opts.document_id.is_some(),
            has_timestamp = opts.timestamp.is_some(),
            "memory.retain → Hindsight"
        );
        tracing::debug!(bank = %self.bank, doc_id = ?opts.document_id, content = framed_content, "memory.retain content");
        let started = std::time::Instant::now();
        let resp = self
            .req(reqwest::Method::POST, &format!("/v1/default/banks/{}/memories", self.bank))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(bank = %self.bank, "memory.retain request failed: {e}");
                Error::other(format!("hindsight retain: {e}"))
            })?;
        let status = resp.status().as_u16();
        let r = ensure_ok(resp, "retain").await;
        match &r {
            Ok(()) => {
                tracing::info!(bank = %self.bank, status, latency_ms = started.elapsed().as_millis() as u64, "memory.retain ok")
            }
            Err(e) => tracing::warn!(bank = %self.bank, status, "memory.retain failed: {e}"),
        }
        r
    }

    /// list: the bank's full set of stored facts, paginated and complete — the
    /// DETERMINISTIC enumeration (`GET /memories/list`), as distinct from the
    /// semantic ranking of `recall`. This is the right source for "show me
    /// everything you remember" (the operator-facing memory panel): it returns
    /// every fact, not just those that happen to rank for a canned query. Loops
    /// `offset` until the reported `total` is covered (bounded by `cap`).
    /// `kind` filters by epistemic type (e.g. `Some("observation")` for the
    /// consolidated, deduplicated belief layer — what a user-facing panel wants;
    /// `None` for every stored fact incl. raw world/experience).
    pub async fn list(&self, kind: Option<&str>, cap: usize) -> Result<Vec<MemoryItem>> {
        Ok(self.list_with_total(kind, cap).await?.0)
    }

    /// As `list`, but also reports the bank's TOTAL count for this `kind` (the
    /// backend's `total`, i.e. the full size even when we return only `cap` of
    /// it). Callers that must show a truncation marker ("showing 25 of 212")
    /// need the total; `list` keeps the plain items-only shape for the rest.
    pub async fn list_with_total(
        &self,
        kind: Option<&str>,
        cap: usize,
    ) -> Result<(Vec<MemoryItem>, usize)> {
        let started = std::time::Instant::now();
        let mut out: Vec<MemoryItem> = Vec::new();
        let page = 100usize;
        let mut offset = 0usize;
        let mut reported_total = 0usize;
        let type_q = kind.map(|k| format!("&type={k}")).unwrap_or_default();
        loop {
            let path = format!(
                "/v1/default/banks/{}/memories/list?limit={page}&offset={offset}{type_q}",
                self.bank
            );
            let resp =
                self.req(reqwest::Method::GET, &path).timeout(READ_TIMEOUT).send().await.map_err(
                    |e| {
                        tracing::warn!(bank = %self.bank, "memory.list request failed: {e}");
                        Error::other(format!("hindsight list: {e}"))
                    },
                )?;
            // A bank that doesn't exist yet (no retain has happened) is "empty".
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                tracing::debug!(bank = %self.bank, "memory.list: bank not created yet (empty)");
                break;
            }
            let v = json_ok(resp, "list").await?;
            let total = v["total"].as_u64().unwrap_or(0) as usize;
            reported_total = total;
            let items = match v["items"].as_array() {
                Some(items) => items.clone(),
                None => {
                    // No `items` key but the bank reports facts → shape drift.
                    if total > 0 {
                        tracing::warn!(
                            bank = %self.bank,
                            total,
                            "memory.list response has no `items` array but total>0 — API shape \
                             may have drifted; stopping pagination"
                        );
                    }
                    Vec::new()
                }
            };
            let got = items.len();
            for it in items {
                out.push(MemoryItem::from_json(&it));
                if out.len() >= cap {
                    // Capped before exhausting the bank — record what we dropped.
                    tracing::info!(
                        bank = %self.bank, returned = out.len(), total, cap,
                        latency_ms = started.elapsed().as_millis() as u64,
                        "memory.list capped (bank has more than we returned)"
                    );
                    // Report the FULL total so the caller can mark truncation,
                    // not just what fit under the cap.
                    return Ok((out, total.max(reported_total)));
                }
            }
            offset += got;
            if got == 0 || offset >= total {
                break;
            }
        }
        tracing::info!(
            bank = %self.bank, kind = ?kind, returned = out.len(), total = reported_total,
            latency_ms = started.elapsed().as_millis() as u64,
            "memory.list ok (full enumeration)"
        );
        // Fully enumerated: total is whatever the backend reported, falling back
        // to the count we actually gathered if it never gave one.
        let total = reported_total.max(out.len());
        Ok((out, total))
    }

    /// Configure the team's bank once, so extraction/reflection are steered for
    /// SRE operations instead of running on stock defaults. Safe to call
    /// repeatedly (PATCH is idempotent for our fixed config); the daemon calls
    /// it once at boot (`boot::daemon_state`), not on every retain.
    ///
    /// Short timeout (READ_TIMEOUT, not the client's 30s write default): this
    /// sits on the boot path, and a down/hung Hindsight must delay daemon
    /// start by seconds, not half a minute — the PATCH is tiny, and a missed
    /// configure only means stock defaults until the next boot (loudly
    /// warned, never fatal).
    pub async fn ensure_configured(&self) -> Result<()> {
        let resp = self
            .req(reqwest::Method::PATCH, &format!("/v1/default/banks/{}/config", self.bank))
            .timeout(READ_TIMEOUT)
            .json(&bank_config())
            .send()
            .await
            .map_err(|e| Error::other(format!("hindsight config: {e}")))?;
        // A not-yet-created bank 404s on PATCH; the first retain creates it, after
        // which a later ensure_configured succeeds. Treat 404 as "try again later".
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::info!(bank = %self.bank, "memory.configure skipped (bank not created yet)");
            return Ok(());
        }
        let status = resp.status().as_u16();
        let r = ensure_ok(resp, "config").await;
        match &r {
            Ok(()) => {
                tracing::info!(bank = %self.bank, status, "memory.configure applied (retain/reflect mission, literalism)")
            }
            Err(e) => {
                tracing::warn!(bank = %self.bank, status, "memory.configure failed (bank uses defaults): {e}")
            }
        }
        r
    }

    /// recall: the facts most RELEVANT to `query` (token-budgeted ranking) —
    /// the agent's topical lookup, as distinct from `list`'s full enumeration.
    ///
    /// Retrieval is HYBRID by the backend's own design (brief §8 requires
    /// "hybrid keyword + semantic search"): Hindsight's `/memories/recall`
    /// runs four strategies in parallel — semantic similarity, BM25 keyword,
    /// graph traversal, and temporal — and fuses them with Reciprocal Rank
    /// Fusion before reranking. There is no retrieval-mode parameter to pass
    /// (the query alone drives all four), so the plain `{query, max_tokens}`
    /// body below already gets keyword AND semantic matching on every call.
    pub async fn recall(&self, query: &str, max_tokens: u32) -> Result<Vec<MemoryItem>> {
        let body = recall_body(query, max_tokens);
        tracing::debug!(bank = %self.bank, query, max_tokens, "memory.recall query");
        let started = std::time::Instant::now();
        let resp = self
            .req(reqwest::Method::POST, &format!("/v1/default/banks/{}/memories/recall", self.bank))
            .timeout(READ_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(bank = %self.bank, "memory.recall request failed: {e}");
                Error::other(format!("hindsight recall: {e}"))
            })?;
        let v = json_ok(resp, "recall").await?;
        // Distinguish "no matches" (results: []) from "unexpected shape" (no
        // results key at all) — the latter is silent data loss on API drift.
        let items: Vec<MemoryItem> = match v["results"].as_array() {
            Some(rs) => rs.iter().map(MemoryItem::from_json).collect(),
            None => {
                tracing::warn!(
                    bank = %self.bank,
                    "memory.recall response has no `results` array — API shape may have drifted; \
                     treating as no hits"
                );
                Vec::new()
            }
        };
        tracing::info!(
            bank = %self.bank, hits = items.len(),
            latency_ms = started.elapsed().as_millis() as u64,
            "memory.recall ok"
        );
        Ok(items)
    }

    /// invalidate (curate): soft-retire ONE memory unit by its id — Hindsight's
    /// per-fact "forget". `PATCH …/memories/{id}` with `{"state":"invalidated"}`
    /// excludes the fact from recall, consolidation, and graph maintenance, and
    /// recomputes derived observations without it; it is kept in the archive for
    /// audit and is reversible (`{"state":"valid"}`). It is NOT a hard delete —
    /// the whole-bank `delete_bank` is the wipe path. A missing backend never
    /// reaches here (the facade gates it). `reason` is recorded on the memory
    /// for the audit trail.
    ///
    /// A 404 means the id no longer exists (already gone / consolidated away):
    /// treated as success, since the fact is not recallable either way.
    pub async fn invalidate(&self, memory_id: &str, reason: &str) -> Result<()> {
        let body = serde_json::json!({ "state": "invalidated", "reason": reason });
        tracing::info!(bank = %self.bank, memory_id, "memory.forget → Hindsight (invalidate)");
        let resp = self
            .req(
                reqwest::Method::PATCH,
                &format!("/v1/default/banks/{}/memories/{memory_id}", self.bank),
            )
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(bank = %self.bank, "memory.forget request failed: {e}");
                Error::other(format!("hindsight invalidate: {e}"))
            })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::info!(bank = %self.bank, memory_id, "memory.forget: fact already gone (404) — treating as done");
            return Ok(());
        }
        let status = resp.status().as_u16();
        let r = ensure_ok(resp, "invalidate").await;
        match &r {
            Ok(()) => {
                tracing::info!(bank = %self.bank, memory_id, status, "memory.forget ok (fact invalidated)")
            }
            Err(e) => {
                tracing::warn!(bank = %self.bank, memory_id, status, "memory.forget failed: {e}")
            }
        }
        r
    }

    /// reflect: Hindsight synthesises a single answer from the team's shared
    /// memory.
    pub async fn reflect(&self, query: &str) -> Result<String> {
        let body = reflect_body(query);
        tracing::debug!(bank = %self.bank, query, "memory.reflect query");
        let started = std::time::Instant::now();
        let resp = self
            .req(reqwest::Method::POST, &format!("/v1/default/banks/{}/reflect", self.bank))
            .timeout(READ_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(bank = %self.bank, "memory.reflect request failed: {e}");
                Error::other(format!("hindsight reflect: {e}"))
            })?;
        let v = json_ok(resp, "reflect").await?;
        let text = v["text"].as_str().unwrap_or("").to_string();
        tracing::info!(
            bank = %self.bank, answer_len = text.chars().count(),
            latency_ms = started.elapsed().as_millis() as u64,
            "memory.reflect ok"
        );
        Ok(text)
    }
}

/// The idiomatic per-item retain fields (besides the framed content + tag).
/// All optional: a caller with none falls back to old behaviour (no upsert, no
/// temporal anchor) but still works.
#[derive(Debug, Default, Clone)]
pub struct RetainOpts {
    /// Stable id → re-retaining the same id REPLACES the prior facts (upsert),
    /// so a correction supersedes rather than duplicates.
    pub document_id: Option<String>,
    /// When the content occurred (RFC3339). Enables temporal retrieval.
    pub timestamp: Option<String>,
    /// Short situational note ("operator chat", "scan finding").
    pub context: Option<String>,
}

/// Retain body. The bank is shared team-wide, so a bare first-person statement
/// ("I restarted it") is ambiguous once several operators' facts are pooled —
/// callers must pre-frame `content` with attribution ("<speaker> said: …" or
/// "scan of <target> observed: …") before calling `retain`; this function just
/// wraps the already-framed text with the item envelope. The `shared` tag is
/// the only one we carry; recall is unfiltered, so a per-operator tag would be
/// dead weight.
fn retain_body(framed_content: &str, opts: &RetainOpts) -> serde_json::Value {
    let mut item = serde_json::Map::new();
    item.insert("content".into(), serde_json::Value::String(framed_content.to_string()));
    item.insert("tags".into(), serde_json::json!(["shared"]));
    if let Some(id) = &opts.document_id {
        item.insert("document_id".into(), serde_json::Value::String(id.clone()));
    }
    if let Some(ts) = &opts.timestamp {
        item.insert("timestamp".into(), serde_json::Value::String(ts.clone()));
    }
    if let Some(ctx) = &opts.context {
        item.insert("context".into(), serde_json::Value::String(ctx.clone()));
    }
    serde_json::json!({ "items": [serde_json::Value::Object(item)] })
}

/// Bank configuration (PATCH /config): steer extraction + reflection for an SRE
/// operations domain rather than running on stock defaults (gianna's household
/// mission, re-tuned). 0.7.2 requires the fields wrapped in an `updates` object
/// (verified live — a bare top-level body 422s). `disposition_literalism` kept
/// high (0.8, unchanged from gianna) so the extractor records what was
/// observed/said and doesn't over-infer root cause from a thin signal.
fn bank_config() -> serde_json::Value {
    serde_json::json!({
        "updates": {
            "retain_mission":
                "Capture durable operational facts about this team's infrastructure \
                 and incidents: target quirks and known-bad behaviours, recurring \
                 failure patterns and their root causes, incident resolutions and \
                 what fixed them, runbook effectiveness, and operator preferences \
                 (approval thresholds, escalation habits, notification routing). \
                 Record literal facts as stated or observed; do not infer a root \
                 cause or a fix beyond what was actually said or confirmed.",
            "reflect_mission":
                "Answer as OpsClaw, an SRE agent, using only what the team has \
                 actually recorded about its infrastructure, incidents, and \
                 operator preferences.",
            "disposition_literalism": 0.8,
        }
    })
}

fn recall_body(query: &str, max_tokens: u32) -> serde_json::Value {
    serde_json::json!({ "query": query, "max_tokens": max_tokens })
}

/// One memory as Hindsight returns it from `list`/`recall`: the fact text (may
/// carry a trailing `| When:/Involving:` annotation) and its stable `id` — the
/// handle the curation endpoints (`invalidate`) address a single fact by. The
/// id is empty when the response omitted it (older shapes / recall payloads that
/// don't carry it); a caller wanting to forget a fact must have a non-empty id.
///
/// `kind`/`context`/`mentioned_at` are the per-item annotations Hindsight
/// carries alongside the text (epistemic type, the situational note the
/// retain supplied, and the retention timestamp) — optional because older
/// shapes / partial payloads may omit any of them. They exist for the
/// human-readable export (brief §8), which wants a timestamped, contextual
/// dump, not just bare fact strings.
#[derive(Debug, Clone)]
pub struct MemoryItem {
    pub id: String,
    pub fact: String,
    /// Epistemic type (`world` / `experience` / `observation`), when reported.
    pub kind: Option<String>,
    /// The situational note supplied at retain time ("operator chat with
    /// OpsClaw", "scan finding"), when reported.
    pub context: Option<String>,
    /// Retention timestamp (RFC3339), when reported.
    pub mentioned_at: Option<String>,
}

impl MemoryItem {
    fn from_json(r: &serde_json::Value) -> Self {
        let opt = |key: &str| r[key].as_str().map(str::to_string);
        MemoryItem {
            id: r["id"].as_str().unwrap_or_default().to_string(),
            fact: r["text"].as_str().unwrap_or_default().to_string(),
            kind: opt("type"),
            context: opt("context"),
            mentioned_at: opt("mentioned_at"),
        }
    }
}

fn reflect_body(query: &str) -> serde_json::Value {
    serde_json::json!({ "query": query })
}

async fn ensure_ok(resp: reqwest::Response, op: &str) -> Result<()> {
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(Error::other(format!("hindsight {op} {status}: {body}")))
    }
}

async fn json_ok(resp: reqwest::Response, op: &str) -> Result<serde_json::Value> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::other(format!("hindsight {op} {status}: {body}")));
    }
    resp.json().await.map_err(|e| Error::other(format!("hindsight {op} bad json: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bank_id_is_opsclaw_prefixed_per_team() {
        let a = HindsightClient::new("http://x", None, "acme");
        let b = HindsightClient::new("http://x", None, "other");
        assert_eq!(a.bank, "opsclaw-acme");
        assert_eq!(b.bank, "opsclaw-other");
        assert_ne!(a.bank, b.bank);
    }

    #[test]
    fn default_team_id_yields_default_bank() {
        let c = HindsightClient::new("http://x", None, "default");
        assert_eq!(c.bank, "opsclaw-default");
    }

    #[test]
    fn retain_body_carries_preframed_content_and_shared_tag() {
        // Callers pre-frame attribution ("<speaker> said: …" / "scan of <target>
        // observed: …") before calling retain; retain_body just wraps it.
        let body = retain_body("dcp said: restarted the payments pod", &RetainOpts::default());
        assert_eq!(
            body["items"][0]["content"].as_str().unwrap(),
            "dcp said: restarted the payments pod"
        );
        // Recall is unfiltered, so the only tag is "shared" — no per-operator tag.
        let tags = body["items"][0]["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0], "shared");

        let obs = retain_body(
            "scan of remundo::prod::cluster observed: pod payments-7 in CrashLoopBackOff",
            &RetainOpts::default(),
        );
        assert!(obs["items"][0]["content"].as_str().unwrap().starts_with("scan of"));
    }

    #[test]
    fn retain_opts_become_item_fields() {
        // document_id (upsert), timestamp (temporal), context (extraction quality)
        // ride along as per-item fields when provided.
        let opts = RetainOpts {
            document_id: Some("scan-42".into()),
            timestamp: Some("2026-01-10T09:00:00Z".into()),
            context: Some("scan finding".into()),
        };
        let body = retain_body("scan of remundo::prod observed: disk at 92%", &opts);
        let item = &body["items"][0];
        assert_eq!(item["document_id"], "scan-42");
        assert_eq!(item["timestamp"], "2026-01-10T09:00:00Z");
        assert_eq!(item["context"], "scan finding");
        // No opts → none of those keys are present (back-compat).
        let bare = retain_body("x", &RetainOpts::default());
        assert!(bare["items"][0].get("document_id").is_none());
        assert!(bare["items"][0].get("timestamp").is_none());
    }

    #[test]
    fn bank_config_carries_sre_missions_and_kept_literalism() {
        let cfg = bank_config();
        let updates = &cfg["updates"];
        let retain_mission = updates["retain_mission"].as_str().unwrap();
        assert!(retain_mission.contains("infrastructure"));
        assert!(retain_mission.contains("operator preferences"));
        assert!(updates["reflect_mission"].as_str().unwrap().contains("OpsClaw"));
        // Literalism kept high, unchanged from gianna — don't over-infer.
        assert_eq!(updates["disposition_literalism"].as_f64().unwrap(), 0.8);
    }

    #[test]
    fn memory_item_parses_fact_text() {
        let r = serde_json::json!({
            "id": "mem-1",
            "text": "remundo::prod::cluster's payments pod OOMs above 400 req/s.",
            "type": "observation",
            "entities": ["remundo::prod::cluster"],
            "mentioned_at": "2026-06-18T17:57:17Z"
        });
        let it = MemoryItem::from_json(&r);
        assert_eq!(it.id, "mem-1", "the id is the handle curation addresses a fact by");
        assert_eq!(it.fact, "remundo::prod::cluster's payments pod OOMs above 400 req/s.");
        // The per-item annotations the export renders ride along when present.
        assert_eq!(it.kind.as_deref(), Some("observation"));
        assert_eq!(it.mentioned_at.as_deref(), Some("2026-06-18T17:57:17Z"));
        // A response missing the id yields an empty id, not a panic — callers that
        // want to forget a fact check for a non-empty id first; the optional
        // annotations are None, never a panic or an empty-string masquerade.
        let no_id = MemoryItem::from_json(&serde_json::json!({ "text": "x" }));
        assert_eq!(no_id.id, "");
        assert!(no_id.kind.is_none() && no_id.context.is_none() && no_id.mentioned_at.is_none());
    }

    #[tokio::test]
    async fn invalidate_patches_the_memory_as_invalidated() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/v1/default/banks/opsclaw-acme/memories/mem-9"))
            .and(body_json(serde_json::json!({
                "state": "invalidated",
                "reason": "operator asked to forget this",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(null)))
            .expect(1)
            .mount(&server)
            .await;
        let client = HindsightClient::new(server.uri(), None, "acme");
        client.invalidate("mem-9", "operator asked to forget this").await.unwrap();
        // The mounted `.expect(1)` is verified on drop — the PATCH with the exact
        // invalidate body must have fired exactly once.
    }

    #[tokio::test]
    async fn invalidate_treats_404_as_already_gone() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("PATCH")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
        let client = HindsightClient::new(server.uri(), None, "acme");
        // A fact that no longer exists is not recallable either way — forgetting
        // it is already done, so a 404 is success, not an error.
        client.invalidate("gone", "reason").await.unwrap();
    }

    #[tokio::test]
    async fn invalidate_surfaces_a_server_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let client = HindsightClient::new(server.uri(), None, "acme");
        // A genuine backend failure must propagate — never claim a fact was
        // forgotten when the PATCH failed.
        assert!(client.invalidate("mem-1", "reason").await.is_err());
    }

    #[tokio::test]
    async fn ensure_configured_wraps_body_in_updates_and_targets_config_path() {
        // 0.7.2 422s on a bare top-level body — the fields must be wrapped in
        // `updates` (bank_config() already does this; pin the wire shape here).
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/v1/default/banks/opsclaw-acme/config"))
            .and(body_partial_json(serde_json::json!({
                "updates": { "disposition_literalism": 0.8 }
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let client = HindsightClient::new(server.uri(), None, "acme");
        client.ensure_configured().await.unwrap();
    }

    #[tokio::test]
    async fn ensure_configured_treats_404_as_not_yet_created() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("PATCH")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
        let client = HindsightClient::new(server.uri(), None, "acme");
        client.ensure_configured().await.unwrap();
    }

    #[test]
    fn recall_is_unfiltered_team_wide() {
        // Memory is shared across the team — no per-operator tag scoping.
        let body = recall_body("what's flaky in prod", 256);
        assert!(body.get("tags").is_none());
        assert!(body.get("tags_match").is_none());
        let body = reflect_body("what's flaky in prod");
        assert!(body.get("tags").is_none());
    }
}
