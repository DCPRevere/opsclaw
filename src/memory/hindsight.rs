//! Hindsight memory backend (the real vectorize-io/hindsight service, 0.7.2).
//!
//! Hindsight is a knowledge-graph agent memory: we hand it RAW content and its
//! own LLM decomposes it into typed facts (world / experience / observation),
//! then a background worker CONSOLIDATES the raw facts into deduplicated
//! `observation` beliefs. Idiomatic use (learned the hard way, see the research
//! in docs/int):
//!
//! - **Retain raw, never pre-summarise** — a hand-written summary is kept whole
//!   as one fact; raw text gets atomised. Frame "<Name> said: …" so a shared
//!   bank anchors first-person statements to the right person.
//! - **`document_id` makes a re-retain an UPSERT** (replace the prior facts), so
//!   a correction supersedes instead of duplicating. `timestamp`/`context`
//!   enable temporal retrieval and better extraction.
//! - **`list` ≠ `recall`**: `list` is the complete, deterministic enumeration
//!   (use for "show everything" — filter `type=observation` for the deduplicated
//!   layer); `recall` is a semantic ranking for the agent's topical lookups.
//! - **Configure the bank** (`PATCH /config`, fields wrapped in `updates`) so
//!   extraction/reflection are steered for a Catholic-household assistant.
//!
//! Tenancy: each household maps to a Hindsight **bank** (`bank_id`), so one
//! household can never recall another's memories.
//!
//! Hindsight is the sole memory backend, selected when `HINDSIGHT_URL` is set.
//! Without it, memory is a no-op (there is no in-process fallback). See `Memory`.

use uuid::Uuid;

use crate::{Error, Result};

/// Per-request deadline for INTERACTIVE reads (recall / reflect / list), which
/// run inside the chat tool loop where a hung backend would otherwise burn up to
/// 30s per loop step. Writes keep the client's generous default (see `new`) —
/// they run detached and retried, so a slow write costs no user-visible latency.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A thin REST client for a self-hosted Hindsight instance.
pub struct HindsightClient {
    http: reqwest::Client,
    base_url: String,
    /// Optional bearer token for the Hindsight API (local instances may omit it).
    auth: Option<String>,
}

impl HindsightClient {
    pub fn new(base_url: impl Into<String>, auth: Option<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest builds"),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth,
        }
    }

    /// A household's Hindsight bank id (stable, opaque, per-tenant).
    fn bank(household_id: Uuid) -> String {
        format!("gianna-{household_id}")
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
    /// chat turn blocks on it and the process REFUSES to boot without it
    /// (config.rs). A short timeout keeps the probe from hanging the healthcheck.
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

    /// delete the household's entire memory bank — the GDPR-erasure path
    /// (PRIVACY.md §6). A 404 counts as success (nothing was ever stored).
    pub async fn delete_bank(&self, household_id: Uuid) -> Result<()> {
        let bank = Self::bank(household_id);
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/v1/default/banks/{bank}"))
            .send()
            .await
            .map_err(|e| Error::other(format!("hindsight delete: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::info!(household = %household_id, "memory.erase: no bank to erase");
            return Ok(()); // no bank = nothing to erase
        }
        let status = resp.status().as_u16();
        let r = ensure_ok(resp, "delete").await;
        match &r {
            Ok(()) => {
                tracing::info!(household = %household_id, status, "memory.erase ok (bank deleted)")
            }
            Err(e) => {
                tracing::warn!(household = %household_id, status, "memory.erase FAILED — bank may survive: {e}")
            }
        }
        r
    }

    /// retain: hand Hindsight a piece of RAW content to decompose into facts —
    /// we never pre-summarise (that loses the entity/temporal/structural signal
    /// its extractor needs). Framed with the NAME of the member who said it so a
    /// shared bank can anchor first-person statements to the right person.
    ///
    /// `opts` carries the idiomatic per-item fields:
    /// - `document_id` — a STABLE id makes a re-retain UPSERT (replace the prior
    ///   facts) instead of duplicating, so a correction supersedes rather than
    ///   piles up (verified against 0.7.2).
    /// - `timestamp` — when the content occurred; without it temporal retrieval
    ///   is disabled.
    /// - `context` — a short situational note ("household chat", "onboarding");
    ///   omitting it measurably hurts extraction quality.
    pub async fn retain(
        &self,
        household_id: Uuid,
        speaker: Option<&str>,
        content: &str,
        opts: &RetainOpts,
    ) -> Result<()> {
        let bank = Self::bank(household_id);
        let body = retain_body(content, speaker, opts);
        // Shape + ids at info (no fact text — PII); full content at debug.
        tracing::info!(
            household = %household_id,
            content_len = content.chars().count(),
            has_doc_id = opts.document_id.is_some(),
            has_timestamp = opts.timestamp.is_some(),
            "memory.retain → Hindsight"
        );
        tracing::debug!(household = %household_id, doc_id = ?opts.document_id, speaker = ?speaker, content, "memory.retain content");
        let started = std::time::Instant::now();
        let resp = self
            .req(reqwest::Method::POST, &format!("/v1/default/banks/{bank}/memories"))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(household = %household_id, "memory.retain request failed: {e}");
                Error::other(format!("hindsight retain: {e}"))
            })?;
        let status = resp.status().as_u16();
        let r = ensure_ok(resp, "retain").await;
        match &r {
            Ok(()) => {
                tracing::info!(household = %household_id, status, latency_ms = started.elapsed().as_millis() as u64, "memory.retain ok")
            }
            Err(e) => {
                tracing::warn!(household = %household_id, status, "memory.retain failed: {e}")
            }
        }
        r
    }

    /// list: the bank's full set of stored facts, paginated and complete — the
    /// DETERMINISTIC enumeration (`GET /memories/list`), as distinct from the
    /// semantic ranking of `recall`. This is the right source for "show me
    /// everything you remember" (the settings panel / GDPR audit): it returns
    /// every fact, not just those that happen to rank for a canned query. Loops
    /// `offset` until the reported `total` is covered (bounded by `cap`).
    /// `kind` filters by epistemic type (e.g. `Some("observation")` for the
    /// consolidated, deduplicated belief layer — what a user-facing panel wants;
    /// `None` for every stored fact incl. raw world/experience).
    pub async fn list(
        &self,
        household_id: Uuid,
        kind: Option<&str>,
        cap: usize,
    ) -> Result<Vec<MemoryItem>> {
        Ok(self.list_with_total(household_id, kind, cap).await?.0)
    }

    /// As `list`, but also reports the bank's TOTAL count for this `kind` (the
    /// backend's `total`, i.e. the full size even when we return only `cap` of
    /// it). Callers that must show a truncation marker ("showing 25 of 212")
    /// need the total; `list` keeps the plain items-only shape for the rest.
    pub async fn list_with_total(
        &self,
        household_id: Uuid,
        kind: Option<&str>,
        cap: usize,
    ) -> Result<(Vec<MemoryItem>, usize)> {
        let bank = Self::bank(household_id);
        let started = std::time::Instant::now();
        let mut out: Vec<MemoryItem> = Vec::new();
        let page = 100usize;
        let mut offset = 0usize;
        let mut reported_total = 0usize;
        let type_q = kind.map(|k| format!("&type={k}")).unwrap_or_default();
        loop {
            let path = format!(
                "/v1/default/banks/{bank}/memories/list?limit={page}&offset={offset}{type_q}"
            );
            let resp = self
                .req(reqwest::Method::GET, &path)
                .timeout(READ_TIMEOUT)
                .send()
                .await
                .map_err(|e| {
                    tracing::warn!(household = %household_id, "memory.list request failed: {e}");
                    Error::other(format!("hindsight list: {e}"))
                })?;
            // A bank that doesn't exist yet (no retain has happened) is "empty".
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                tracing::debug!(household = %household_id, "memory.list: bank not created yet (empty)");
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
                            household = %household_id,
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
                        household = %household_id, returned = out.len(), total, cap,
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
            household = %household_id, kind = ?kind, returned = out.len(), total = reported_total,
            latency_ms = started.elapsed().as_millis() as u64,
            "memory.list ok (full enumeration)"
        );
        // Fully enumerated: total is whatever the backend reported, falling back
        // to the count we actually gathered if it never gave one.
        let total = reported_total.max(out.len());
        Ok((out, total))
    }

    /// Configure a household's bank once, so extraction/reflection are steered for
    /// a Catholic-household assistant instead of running on stock defaults. Safe to
    /// call repeatedly (PATCH is idempotent for our fixed config); callers gate it
    /// to first-use to avoid a PATCH on every retain.
    pub async fn ensure_configured(&self, household_id: Uuid) -> Result<()> {
        let bank = Self::bank(household_id);
        let resp = self
            .req(reqwest::Method::PATCH, &format!("/v1/default/banks/{bank}/config"))
            .json(&bank_config())
            .send()
            .await
            .map_err(|e| Error::other(format!("hindsight config: {e}")))?;
        // A not-yet-created bank 404s on PATCH; the first retain creates it, after
        // which a later ensure_configured succeeds. Treat 404 as "try again later".
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::info!(household = %household_id, "memory.configure skipped (bank not created yet)");
            return Ok(());
        }
        let status = resp.status().as_u16();
        let r = ensure_ok(resp, "config").await;
        match &r {
            Ok(()) => {
                tracing::info!(household = %household_id, status, "memory.configure applied (retain/reflect mission, literalism)")
            }
            Err(e) => {
                tracing::warn!(household = %household_id, status, "memory.configure failed (bank uses defaults): {e}")
            }
        }
        r
    }

    /// recall: the facts most RELEVANT to `query` (semantic ranking, token-
    /// budgeted) — the agent's topical lookup, as distinct from `list`'s full
    /// enumeration.
    pub async fn recall(
        &self,
        household_id: Uuid,
        query: &str,
        max_tokens: u32,
    ) -> Result<Vec<MemoryItem>> {
        let bank = Self::bank(household_id);
        let body = recall_body(query, max_tokens);
        tracing::debug!(household = %household_id, query, max_tokens, "memory.recall query");
        let started = std::time::Instant::now();
        let resp = self
            .req(reqwest::Method::POST, &format!("/v1/default/banks/{bank}/memories/recall"))
            .timeout(READ_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(household = %household_id, "memory.recall request failed: {e}");
                Error::other(format!("hindsight recall: {e}"))
            })?;
        let v = json_ok(resp, "recall").await?;
        // Distinguish "no matches" (results: []) from "unexpected shape" (no
        // results key at all) — the latter is silent data loss on API drift.
        let items: Vec<MemoryItem> = match v["results"].as_array() {
            Some(rs) => rs.iter().map(MemoryItem::from_json).collect(),
            None => {
                tracing::warn!(
                    household = %household_id,
                    "memory.recall response has no `results` array — API shape may have drifted; \
                     treating as no hits"
                );
                Vec::new()
            }
        };
        tracing::info!(
            household = %household_id, hits = items.len(),
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
    /// the whole-bank `delete_bank` remains the GDPR-erasure path. A missing
    /// backend never reaches here (the facade gates it). `reason` is recorded on
    /// the memory for the audit trail.
    ///
    /// A 404 means the id no longer exists (already gone / consolidated away):
    /// treated as success, since the fact is not recallable either way.
    pub async fn invalidate(
        &self,
        household_id: Uuid,
        memory_id: &str,
        reason: &str,
    ) -> Result<()> {
        let bank = Self::bank(household_id);
        let body = serde_json::json!({ "state": "invalidated", "reason": reason });
        tracing::info!(household = %household_id, memory_id, "memory.forget → Hindsight (invalidate)");
        let resp = self
            .req(reqwest::Method::PATCH, &format!("/v1/default/banks/{bank}/memories/{memory_id}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(household = %household_id, "memory.forget request failed: {e}");
                Error::other(format!("hindsight invalidate: {e}"))
            })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::info!(household = %household_id, memory_id, "memory.forget: fact already gone (404) — treating as done");
            return Ok(());
        }
        let status = resp.status().as_u16();
        let r = ensure_ok(resp, "invalidate").await;
        match &r {
            Ok(()) => {
                tracing::info!(household = %household_id, memory_id, status, "memory.forget ok (fact invalidated)")
            }
            Err(e) => {
                tracing::warn!(household = %household_id, memory_id, status, "memory.forget failed: {e}")
            }
        }
        r
    }

    /// reflect: Hindsight synthesises a single answer from the household's
    /// shared memory.
    pub async fn reflect(&self, household_id: Uuid, query: &str) -> Result<String> {
        let bank = Self::bank(household_id);
        let body = reflect_body(query);
        tracing::debug!(household = %household_id, query, "memory.reflect query");
        let started = std::time::Instant::now();
        let resp = self
            .req(reqwest::Method::POST, &format!("/v1/default/banks/{bank}/reflect"))
            .timeout(READ_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(household = %household_id, "memory.reflect request failed: {e}");
                Error::other(format!("hindsight reflect: {e}"))
            })?;
        let v = json_ok(resp, "reflect").await?;
        let text = v["text"].as_str().unwrap_or("").to_string();
        tracing::info!(
            household = %household_id, answer_len = text.chars().count(),
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
    /// Short situational note ("household chat", "onboarding answer").
    pub context: Option<String>,
}

/// Retain body. Memory is shared across the whole household, so a bare
/// first-person statement ("I was born in Liverpool") is ambiguous once two
/// people's facts are pooled. We frame the content with the SPEAKER'S NAME
/// ("David said: …") so Hindsight's extractor anchors the "I" to the right
/// person. The `shared` tag is the only one we carry; recall is unfiltered, so a
/// per-member `user:<id>` tag would be dead weight.
fn retain_body(content: &str, speaker: Option<&str>, opts: &RetainOpts) -> serde_json::Value {
    let framed = match speaker {
        Some(name) if !name.trim().is_empty() => format!("{name} said: {content}"),
        _ => format!("The user said: {content}"),
    };
    let mut item = serde_json::Map::new();
    item.insert("content".into(), serde_json::Value::String(framed));
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

/// Bank configuration (PATCH /config): steer extraction + reflection for a
/// Catholic-household assistant rather than running on stock defaults. 0.7.2
/// requires the fields wrapped in an `updates` object (verified live — a bare
/// top-level body 422s). `disposition_literalism` high so the extractor records
/// what was said and doesn't over-infer about a family.
fn bank_config() -> serde_json::Value {
    serde_json::json!({
        "updates": {
            "retain_mission":
                "Capture durable facts about a Catholic household and its members: \
                 names and relationships, birthdays and anniversaries, parish and \
                 Mass times, prayer intentions and devotions, health needs and \
                 allergies, work and school. Record literal facts; do not infer \
                 beyond what was said.",
            "reflect_mission":
                "Answer as Gianna, a warm personal assistant for Catholic family \
                 life, using only what the household has actually shared.",
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
#[derive(Debug, Clone)]
pub struct MemoryItem {
    pub id: String,
    pub fact: String,
}

impl MemoryItem {
    fn from_json(r: &serde_json::Value) -> Self {
        MemoryItem {
            id: r["id"].as_str().unwrap_or_default().to_string(),
            fact: r["text"].as_str().unwrap_or_default().to_string(),
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
    fn bank_id_is_per_household() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(HindsightClient::bank(a), HindsightClient::bank(b));
        assert!(HindsightClient::bank(a).starts_with("gianna-"));
    }

    #[test]
    fn retained_facts_are_name_framed() {
        let body = retain_body("I was born in Liverpool", Some("David"), &RetainOpts::default());
        // The speaker's name is in the text so Hindsight anchors "I" to David.
        assert_eq!(
            body["items"][0]["content"].as_str().unwrap(),
            "David said: I was born in Liverpool"
        );
        // Recall is unfiltered, so the only tag is "shared" — no per-member tag.
        let tags = body["items"][0]["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0], "shared");
        // Unknown speaker: generic frame, still shared only.
        let body = retain_body("x", None, &RetainOpts::default());
        assert_eq!(body["items"][0]["content"].as_str().unwrap(), "The user said: x");
        assert_eq!(body["items"][0]["tags"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn retain_opts_become_item_fields() {
        // document_id (upsert), timestamp (temporal), context (extraction quality)
        // ride along as per-item fields when provided.
        let opts = RetainOpts {
            document_id: Some("chat-42".into()),
            timestamp: Some("2026-01-10T09:00:00Z".into()),
            context: Some("household chat".into()),
        };
        let body = retain_body("we got married", Some("Daniel"), &opts);
        let item = &body["items"][0];
        assert_eq!(item["document_id"], "chat-42");
        assert_eq!(item["timestamp"], "2026-01-10T09:00:00Z");
        assert_eq!(item["context"], "household chat");
        // No opts → none of those keys are present (back-compat).
        let bare = retain_body("x", None, &RetainOpts::default());
        assert!(bare["items"][0].get("document_id").is_none());
        assert!(bare["items"][0].get("timestamp").is_none());
    }

    #[test]
    fn memory_item_parses_fact_text() {
        let r = serde_json::json!({
            "id": "mem-1",
            "text": "Catherine Revere was born on October 28, 1999.",
            "type": "observation",
            "entities": ["Catherine Revere"],
            "mentioned_at": "2026-06-18T17:57:17Z"
        });
        let it = MemoryItem::from_json(&r);
        assert_eq!(it.id, "mem-1", "the id is the handle curation addresses a fact by");
        assert_eq!(it.fact, "Catherine Revere was born on October 28, 1999.");
        // A response missing the id yields an empty id, not a panic — callers that
        // want to forget a fact check for a non-empty id first.
        let no_id = MemoryItem::from_json(&serde_json::json!({ "text": "x" }));
        assert_eq!(no_id.id, "");
    }

    #[tokio::test]
    async fn invalidate_patches_the_memory_as_invalidated() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let hid = Uuid::new_v4();
        let bank = HindsightClient::bank(hid);
        Mock::given(method("PATCH"))
            .and(path(format!("/v1/default/banks/{bank}/memories/mem-9")))
            .and(body_json(serde_json::json!({
                "state": "invalidated",
                "reason": "user asked to forget this",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(null)))
            .expect(1)
            .mount(&server)
            .await;
        let client = HindsightClient::new(server.uri(), None);
        client.invalidate(hid, "mem-9", "user asked to forget this").await.unwrap();
        // The mounted `.expect(1)` is verified on drop — the PATCH with the exact
        // invalidate body must have fired exactly once.
    }

    #[tokio::test]
    async fn invalidate_treats_404_as_already_gone() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("PATCH")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
        let client = HindsightClient::new(server.uri(), None);
        // A fact that no longer exists is not recallable either way — forgetting
        // it is already done, so a 404 is success, not an error.
        client.invalidate(Uuid::new_v4(), "gone", "reason").await.unwrap();
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
        let client = HindsightClient::new(server.uri(), None);
        // A genuine backend failure must propagate — never claim a fact was
        // forgotten when the PATCH failed.
        assert!(client.invalidate(Uuid::new_v4(), "mem-1", "reason").await.is_err());
    }

    #[test]
    fn recall_is_unfiltered_household_wide() {
        // Memory is shared across the household — no per-member tag scoping.
        let body = recall_body("what's on", 256);
        assert!(body.get("tags").is_none());
        assert!(body.get("tags_match").is_none());
        let body = reflect_body("what's on");
        assert!(body.get("tags").is_none());
    }
}
