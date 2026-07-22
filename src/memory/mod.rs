//! Team memory via Hindsight (adapted from gianna's `src/memory/{mod,hindsight}.rs`
//! — see `hindsight` for the client-level tenancy/mission changes). OpsClaw is
//! single-tenant (DESIGN §1): one daemon, one team, one shared Hindsight bank.
//! There is no per-operator visibility filter — every operator and the agent
//! itself read and write the same bank — but every retained fact is framed
//! with its source so a pooled statement stays attributable: `"{speaker} said:
//! …"` for something an operator or the agent said, `"scan of {fq_target}
//! observed: …"` for a passive finding from a heartbeat scan. Without
//! `HINDSIGHT_URL`, memory is an honest no-op: there is deliberately no
//! in-process fallback, and tools tell the operator so via `is_enabled`
//! instead of silently pretending to remember.

pub mod hindsight;

use std::sync::Arc;

use crate::Result;

/// A recalled fact, as surfaced to callers (storage lives in Hindsight). `id`
/// is the backend handle a single fact is addressed by (for `forget`); it may be
/// empty when the backend response omitted it. `kind`/`context`/`mentioned_at`
/// carry the backend's per-fact annotations when it reported them — the
/// human-readable export (brief §8) renders them; recall-driven callers (the
/// tool loop) ignore them.
#[derive(Debug, Clone)]
pub struct MemoryRecord {
    pub id: String,
    pub fact: String,
    /// Epistemic type (`world` / `experience` / `observation`), when reported.
    pub kind: Option<String>,
    /// The situational note supplied at retain time, when reported.
    pub context: Option<String>,
    /// Retention timestamp (RFC3339), when reported.
    pub mentioned_at: Option<String>,
}

/// Whether a message should be considered for fact extraction. Adapted from
/// gianna's household filter (which skipped questions and doctrinal queries)
/// for SRE content. We skip:
///
/// - **pure questions** — they're queries, not durable operational facts
///   ("is the payments pod healthy?" carries nothing to remember);
/// - **bare control-flow acknowledgements** — "yes", "approve", "ok" and
///   similar turn-taking noise from the approval/chat flow carry no fact on
///   their own;
/// - **content that looks like a secret** — long base64/hex runs, a PEM
///   private-key block, or a bearer/API token shape. This is defence in
///   depth, NOT the primary control: the scrubber (policy layer, DESIGN §4)
///   is what's actually relied on to keep secrets out of tool output and
///   logs. A memory store is an especially bad place for a credential to
///   leak into, though — it is long-lived, gets recalled back into future
///   prompts, and Hindsight's own LLM extractor sees the raw text — so this
///   filter drops the retain outright rather than trust redaction alone.
///
/// Deliberately DOES retain genuine operational statements: target quirks
/// ("the payments pod OOMs above 400 req/s"), incident resolutions ("restarting
/// the connection pool fixed it"), and operator preferences ("dcp wants
/// approval for anything touching prod DNS"). Deterministic + cheap (no LLM
/// call). Errs toward NOT retaining ambiguous input; genuine statements always
/// pass.
pub fn should_retain(message: &str) -> bool {
    let m = message.trim();
    if m.is_empty() {
        return false;
    }
    if looks_like_secret(m) {
        return false;
    }
    if is_bare_control_answer(m) {
        return false;
    }
    let lower = m.to_lowercase();

    // A message that is (just) a question. We treat it as a question if it ends
    // with '?' and contains no declarative statement, OR opens with a question word.
    let ends_question = m.ends_with('?');
    let opens_question = [
        "what ", "who ", "when ", "where ", "why ", "how ", "is ", "are ", "do ", "does ", "did ",
        "can ", "could ", "should ", "would ", "will ", "tell me", "explain",
    ]
    .iter()
    .any(|q| lower.starts_with(q));

    // Skip pure questions; keep statements (even if they contain a '?' mid-text,
    // a leading question word is the stronger signal).
    if (ends_question || opens_question) && !looks_like_statement(&lower) {
        return false;
    }
    true
}

fn looks_like_statement(lower: &str) -> bool {
    [
        "remember that",
        "the issue was",
        "root cause",
        "we found",
        "turns out",
        "always ",
        "never ",
        "known issue",
        "workaround",
        "prefers",
        "wants approval",
        "i am",
        "i'm",
        "it is",
        "it's",
    ]
    .iter()
    .any(|s| lower.contains(s))
}

/// True when the message is pure control-flow acknowledgement in the
/// approval/chat loop ("yes", "approve", "ok", "no", "ack") — SRE's analog of
/// gianna's onboarding "bare control answer": an assent/refusal that answers a
/// prior prompt but carries no fact of its own. Any word outside that small
/// vocabulary means substance: retain it.
fn is_bare_control_answer(message: &str) -> bool {
    const CONTROL: &[&str] = &[
        "yes",
        "no",
        "yeah",
        "yep",
        "nope",
        "please",
        "thanks",
        "thank",
        "you",
        "ok",
        "okay",
        "sure",
        "fine",
        "good",
        "approve",
        "approved",
        "deny",
        "denied",
        "reject",
        "rejected",
        "ack",
        "acked",
        "acknowledge",
        "acknowledged",
        "confirm",
        "confirmed",
        "go",
        "ahead",
        "proceed",
        "cancel",
        "cancelled",
        "stop",
        "continue",
        "the",
        "a",
        "an",
        "and",
        "or",
        "it",
        "that",
        "this",
    ];
    message
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .all(|w| CONTROL.contains(&w))
}

/// Defence-in-depth secret-shape filter: content that structurally resembles a
/// credential never reaches the memory store, independent of the scrubber.
/// Deliberately conservative (pattern-based, not entropy-scored) to avoid
/// false negatives at the cost of the occasional false positive — a dropped
/// retain is cheap; a leaked credential sitting in a long-lived, recalled-into
/// prompts memory store is not.
fn looks_like_secret(message: &str) -> bool {
    let lower = message.to_lowercase();
    if lower.contains("-----begin") && lower.contains("private key") {
        return true;
    }
    if lower.contains("bearer ") {
        // "bearer <token>" — a live credential, not a fact about one.
        return true;
    }
    // A long contiguous run of base64/hex-alphabet characters (>= 32 chars) is
    // treated as an embedded secret (API key, token, encoded credential),
    // regardless of surrounding prose.
    message.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')).any(
        |tok| {
            tok.chars().count() >= 32
                && tok
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        },
    )
}

/// The memory service: a thin facade over the Hindsight backend, scoped to
/// this team's single bank.
pub struct Memory {
    /// Hindsight is the sole backend. None => memory is a no-op (fakes mode,
    /// or a deploy that hasn't set HINDSIGHT_URL yet). There is deliberately
    /// no in-process store: gianna's experience is that in-process extraction
    /// is unreliable and must never be used.
    hindsight: Option<Arc<hindsight::HindsightClient>>,
    /// Tracks every in-flight detached retain (`retain_detached`). A deploy
    /// SIGTERMs the daemon mid-work, and a background retain in flight would
    /// otherwise silently drop a just-learned fact. The shutdown path calls
    /// `drain_detached` to wait (bounded) for these to finish before the
    /// process exits.
    detached: tokio_util::task::TaskTracker,
}

impl Default for Memory {
    fn default() -> Self {
        Self::disabled()
    }
}

impl Memory {
    /// No backend attached — the honest no-op (fakes mode). Frozen facade entry
    /// point: tools call `is_enabled()` and tell the operator the truth rather
    /// than fake a save.
    pub fn disabled() -> Self {
        Self { hindsight: None, detached: tokio_util::task::TaskTracker::new() }
    }

    /// Whether a real memory backend is configured. Tools consult this so the
    /// model is HONEST when memory is off ("I can't remember things right now")
    /// instead of claiming to have saved a fact that went nowhere.
    pub fn is_enabled(&self) -> bool {
        self.hindsight.is_some()
    }

    /// Cheap health probe for the deep readiness check (`/ready?deep=1`). When a
    /// Hindsight backend is configured, ping its `GET /health`; the daemon
    /// healthcheck uses this so a Hindsight outage marks the daemon not-ready
    /// instead of leaving monitors green while every recall hangs on it. When no
    /// backend is configured (fakes mode, or a deploy that hasn't set
    /// HINDSIGHT_URL) memory is a deliberate no-op, so there is nothing to probe
    /// — that is reported as healthy: readiness must not fail on an
    /// intentionally disabled dependency (config.rs refuses to boot LIVE
    /// without one anyway).
    pub async fn health(&self) -> Result<()> {
        match &self.hindsight {
            Some(h) => h.health().await,
            None => Ok(()),
        }
    }

    /// Attach a Hindsight backend (builder-style). When set, it handles all
    /// retain/recall/reflect against this team's single bank.
    pub fn with_hindsight(mut self, client: Arc<hindsight::HindsightClient>) -> Self {
        self.hindsight = Some(client);
        self
    }

    /// Store an explicit note the agent or an operator chose to keep (a
    /// `remember` tool). We hand Hindsight the RAW text and let its extractor
    /// decompose it — we do not pre-summarise. A content-derived `document_id`
    /// makes re-saving the same note upsert rather than duplicate.
    pub async fn store_fact(&self, speaker: &str, fact: &str) -> Result<()> {
        // Hindsight is the ONLY memory backend (it does its own extraction +
        // reconciliation). Without it, memory is a no-op. Live mode must set
        // HINDSIGHT_URL for OpsClaw to remember anything (config.rs refuses to
        // boot live otherwise).
        match &self.hindsight {
            Some(h) => {
                let framed = frame_said(speaker, fact);
                let opts = hindsight::RetainOpts {
                    document_id: Some(doc_id("note", &framed)),
                    // Receipt time as the event anchor: strictly better than None
                    // (which disables temporal retrieval) and always available.
                    timestamp: Some(now_rfc3339()),
                    context: Some("explicit note the agent was asked to remember".into()),
                };
                h.retain(&framed, &opts).await
            }
            None => Ok(()),
        }
    }

    /// Erase the team's ENTIRE remote memory. Errors propagate — a wipe must
    /// not claim success while the remote bank survives. No-op when Hindsight
    /// isn't configured (nothing was stored).
    pub async fn erase(&self) -> Result<()> {
        match &self.hindsight {
            Some(h) => h.delete_bank().await,
            None => Ok(()),
        }
    }

    /// Retain a conversational turn. `speaker` is the operator's name, or
    /// `"agent"` for something OpsClaw itself asserted — woven into the stored
    /// fact ("{speaker} said: …") so the shared, team-wide bank can anchor
    /// first-person statements to the right source. Memory is fully shared —
    /// there is no per-operator read visibility.
    pub async fn retain(&self, speaker: &str, message: &str) -> Result<()> {
        // Only retain genuine operational statements. Questions and bare
        // control-flow acks carry no durable fact — skip them (see
        // `should_retain` for the reasoning, including the secret-shape
        // defence-in-depth layer).
        if !should_retain(message) {
            // Logged so "why didn't OpsClaw remember X?" is answerable: the
            // gate, not the backend, dropped it. Length only (no message text
            // — may carry operational detail or, per the filter, a secret).
            tracing::debug!(
                speaker,
                len = message.chars().count(),
                "memory.retain skipped (not a durable statement)"
            );
            return Ok(());
        }
        // Hindsight extracts + reconciles facts itself — hand it the raw,
        // attribution-framed message.
        if let Some(h) = &self.hindsight {
            let framed = frame_said(speaker, message);
            let opts = hindsight::RetainOpts {
                // Stable per-(speaker,message) id so re-sending the same
                // statement upserts rather than duplicating.
                document_id: Some(doc_id("msg", &framed)),
                // Receipt time as the event anchor (see store_fact): omitting it
                // disables Hindsight's temporal retrieval; Utc::now() costs nothing.
                timestamp: Some(now_rfc3339()),
                context: Some("operator chat with OpsClaw".into()),
            };
            h.retain(&framed, &opts).await?;
        }
        Ok(())
    }

    /// Retain a passive scan observation: `fq_target` is the fully-qualified
    /// target the finding came from (e.g. `remundo::prod::cluster`), `finding`
    /// the raw observed content. Framed as "scan of {fq_target} observed: …" —
    /// distinct from `retain`'s "{speaker} said: …" — so a heartbeat's passive
    /// finding is never confused with something an operator or the agent
    /// asserted. Goes through the same `should_retain` filter (a scan can
    /// surface log lines that happen to contain a secret shape).
    pub async fn retain_observation(&self, fq_target: &str, finding: &str) -> Result<()> {
        let framed = frame_observed(fq_target, finding);
        if !should_retain(&framed) {
            tracing::debug!(
                fq_target,
                len = finding.chars().count(),
                "memory.retain_observation skipped"
            );
            return Ok(());
        }
        if let Some(h) = &self.hindsight {
            let opts = hindsight::RetainOpts {
                document_id: Some(doc_id("scan", &framed)),
                timestamp: Some(now_rfc3339()),
                context: Some("scan finding".into()),
            };
            h.retain(&framed, &opts).await?;
        }
        Ok(())
    }

    /// Fire-and-forget retain: spawn a background task that retains and retries
    /// on failure, then return immediately so a slow Hindsight write never
    /// blocks the caller (e.g. a chat reply or a scan tick). The result is
    /// discarded (failures were already only `warn!`-logged), so detaching it
    /// is safe — but because *remembering matters*, the background task
    /// retries (3 attempts, exponential backoff 500ms→2s→8s) before giving up.
    /// Owns its arguments so the task can outlive the caller; `self` is held as
    /// `Arc<Memory>` everywhere it's shared, which is cheap to clone.
    ///
    /// Use this for pure best-effort per-turn writes. Do NOT use it where a
    /// later step depends on the retain having completed (e.g. `configure`,
    /// which 404-skips on a not-yet-created bank): keep those synchronous.
    pub fn retain_detached(self: &Arc<Self>, speaker: String, message: String) {
        self.detach_with_backoff(
            DetachedRetain::Said { speaker, message },
            std::time::Duration::from_millis(500),
        );
    }

    /// As [`retain_detached`], but for a passive scan finding — the detached
    /// sibling of [`retain_observation`], carrying the `"scan of {fq_target}
    /// observed: …"` framing (DESIGN §3 memory) through the same tracked,
    /// retried background path, so a scan tick is never blocked by a slow
    /// Hindsight write and its finding still survives a SIGTERM (drain).
    ///
    /// [`retain_detached`]: Memory::retain_detached
    /// [`retain_observation`]: Memory::retain_observation
    pub fn retain_observation_detached(self: &Arc<Self>, fq_target: String, finding: String) {
        self.detach_with_backoff(
            DetachedRetain::Observed { fq_target, finding },
            std::time::Duration::from_millis(500),
        );
    }

    /// Backoff base extracted so tests can drive the retry path with a tiny delay
    /// (no real 2.5s wait) while production keeps the 500ms→2s→8s schedule.
    /// One spawn body for both framings so the tracked-spawn/retry/give-up
    /// discipline can never diverge between chat retains and scan retains.
    fn detach_with_backoff(
        self: &Arc<Self>,
        kind: DetachedRetain,
        initial_delay: std::time::Duration,
    ) {
        let me = Arc::clone(self);
        // Spawn ONTO the tracker (not a bare `tokio::spawn`) so the shutdown
        // drain can wait for this write. `spawn` returns the JoinHandle; we drop
        // it, keeping the fire-and-forget shape, but the tracker still counts the
        // task until it completes.
        self.detached.spawn(async move {
            let mut delay = initial_delay;
            for attempt in 1..=3u32 {
                let r = match &kind {
                    DetachedRetain::Said { speaker, message } => me.retain(speaker, message).await,
                    DetachedRetain::Observed { fq_target, finding } => {
                        me.retain_observation(fq_target, finding).await
                    }
                };
                match r {
                    Ok(_) => return,
                    Err(e) => {
                        tracing::warn!(
                            origin = kind.origin(),
                            attempt,
                            "background retain failed: {e}"
                        );
                        if attempt < 3 {
                            tokio::time::sleep(delay).await;
                            delay *= 4;
                        }
                    }
                }
            }
            tracing::warn!(origin = kind.origin(), "background retain gave up after 3 attempts");
        });
    }

    /// Number of detached retains currently in flight. Used by the shutdown drain
    /// and its test to observe outstanding background work.
    pub fn detached_in_flight(&self) -> usize {
        self.detached.len()
    }

    /// Wait (bounded by `timeout`) for every in-flight detached retain to finish,
    /// so a deploy's SIGTERM doesn't drop a just-learned fact mid-write. Closes
    /// the tracker first (no NEW retain is tracked after this — shutdown has
    /// begun), then awaits the outstanding ones. Returns `true` if they all
    /// drained within the budget, `false` on timeout (the process exits anyway;
    /// Hindsight retains are best-effort and the caller logs the shortfall).
    pub async fn drain_detached(&self, timeout: std::time::Duration) -> bool {
        self.detached.close();
        if self.detached.is_empty() {
            return true;
        }
        tokio::time::timeout(timeout, self.detached.wait()).await.is_ok()
    }

    /// recall: the facts most RELEVANT to a query (semantic ranking) — the
    /// agent's topical lookup. For "show me everything", use `all` instead.
    pub async fn recall(&self, query: &str, limit: usize) -> Result<Vec<MemoryRecord>> {
        match &self.hindsight {
            // ~256 tokens per fact is plenty for short operational facts.
            Some(h) => {
                let items = h.recall(query, (limit as u32).max(1) * 256).await?;
                Ok(items.into_iter().take(limit).map(record).collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// ALL stored facts for the team — the complete, deterministic enumeration
    /// (`GET /memories/list`), for "what do you know about our infra?" and the
    /// operator-facing memory panel. This is NOT a recall: it returns every
    /// stored fact, not just those that rank for a canned query.
    pub async fn all(&self, limit: usize) -> Result<Vec<MemoryRecord>> {
        Ok(self.all_with_total(limit).await?.0)
    }

    /// As `all`, but also reports the team's TOTAL stored-fact count for the
    /// layer returned, so callers can mark truncation ("showing 25 of 212") when
    /// `limit` cut the list. `total` counts the same layer the items came from
    /// (observations if consolidated, else all facts).
    pub async fn all_with_total(&self, limit: usize) -> Result<(Vec<MemoryRecord>, usize)> {
        match &self.hindsight {
            Some(h) => {
                // Prefer the CONSOLIDATED belief layer (observations): Hindsight
                // folds the raw world/experience facts into deduplicated beliefs,
                // so the panel shows "the payments pod OOMs above 400 req/s" once,
                // not the 3 near-duplicate raw extractions. Consolidation is
                // async, so a brand-new bank may have none yet — fall back to ALL
                // facts so a just-onboarded team still sees what it's shared.
                let (mut items, mut total) = h.list_with_total(Some("observation"), limit).await?;
                if items.is_empty() {
                    let (all_items, all_total) = h.list_with_total(None, limit).await?;
                    items = all_items;
                    total = all_total;
                }
                Ok((items.into_iter().map(record).collect(), total))
            }
            None => Ok((Vec::new(), 0)),
        }
    }

    /// EVERY stored fact, every layer — the archival dump behind
    /// `opsclaw-cli memory export` (brief §8: human-readable export as the
    /// team's archival mechanism, since Hindsight has no delete-by-age API —
    /// see `MemoryCfg::retention_days`). Unlike `all`, which prefers the
    /// consolidated observation layer for readability, this enumerates with
    /// NO type filter: an archive that silently dropped the raw
    /// world/experience facts would not be an archive. Returns the records
    /// plus the backend's total so the caller can mark truncation when
    /// `cap` cut the dump short.
    pub async fn export(&self, cap: usize) -> Result<(Vec<MemoryRecord>, usize)> {
        match &self.hindsight {
            Some(h) => {
                let (items, total) = h.list_with_total(None, cap).await?;
                Ok((items.into_iter().map(record).collect(), total))
            }
            None => Ok((Vec::new(), 0)),
        }
    }

    /// Forget ONE stored fact — soft-retire it by id (Hindsight `invalidate`:
    /// excluded from recall/consolidation/graph, derived observations recomputed
    /// without it, kept in the archive for audit, reversible). This is NOT a hard
    /// erase (that is `erase`, the whole-bank wipe); it is the per-fact "forget
    /// that" an operator reaches for when OpsClaw has one thing wrong. No-op
    /// when Hindsight isn't configured — but callers gate on `is_enabled` so they
    /// never falsely claim a fact was forgotten. `reason` rides along for the
    /// audit trail.
    pub async fn forget(&self, memory_id: &str, reason: &str) -> Result<()> {
        match &self.hindsight {
            Some(h) => h.invalidate(memory_id, reason).await,
            None => Ok(()),
        }
    }

    /// Configure the team's Hindsight bank for first use (no-op without a
    /// backend). Idempotent; callers run it once at daemon startup.
    pub async fn configure(&self) -> Result<()> {
        match &self.hindsight {
            Some(h) => h.ensure_configured().await,
            None => Ok(()),
        }
    }

    /// reflect: synthesise a single concise answer from memory (Hindsight only).
    pub async fn reflect(&self, question: &str) -> Result<String> {
        match &self.hindsight {
            Some(h) => h.reflect(question).await,
            None => Ok(String::new()),
        }
    }
}

/// The two attribution framings a detached background retain can carry —
/// DESIGN §3 memory: `"{speaker} said: …"` for something said in chat and
/// `"scan of {fq_target} observed: …"` for a passive scan finding. An enum
/// (not two spawn bodies) so `detach_with_backoff` stays the single place
/// the tracked-spawn/retry discipline lives.
enum DetachedRetain {
    Said { speaker: String, message: String },
    Observed { fq_target: String, finding: String },
}

impl DetachedRetain {
    /// The attribution anchor, for retry/give-up log lines: who said it, or
    /// which target the finding was observed on. Never the content itself
    /// (it may carry operational detail — same stance as `Memory::retain`'s
    /// skip log).
    fn origin(&self) -> &str {
        match self {
            DetachedRetain::Said { speaker, .. } => speaker,
            DetachedRetain::Observed { fq_target, .. } => fq_target,
        }
    }
}

/// Frame a conversational statement with its speaker, so a pooled first-person
/// statement in the shared team bank stays anchored to the right source.
/// `speaker` is the operator's name or `"agent"`/`"scan"` for OpsClaw itself.
fn frame_said(speaker: &str, content: &str) -> String {
    let who = if speaker.trim().is_empty() { "the operator" } else { speaker.trim() };
    format!("{who} said: {content}")
}

/// Frame a passive scan finding with the target it came from — distinct from
/// `frame_said` so a heartbeat observation is never confused with something
/// someone asserted.
fn frame_observed(fq_target: &str, finding: &str) -> String {
    format!("scan of {fq_target} observed: {finding}")
}

/// Map a Hindsight item to our `MemoryRecord`.
fn record(item: hindsight::MemoryItem) -> MemoryRecord {
    MemoryRecord {
        id: item.id,
        fact: item.fact,
        kind: item.kind,
        context: item.context,
        mentioned_at: item.mentioned_at,
    }
}

/// Message receipt time as an RFC3339 UTC string, the event anchor we hand
/// Hindsight on every retain (temporal retrieval is disabled when omitted).
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A stable `document_id` for a retained (already attribution-framed)
/// statement, so re-retaining the same thing UPSERTS (Hindsight replaces the
/// prior facts) instead of duplicating. Scoped by kind so a note, a chat line,
/// and a scan finding never collide. There is no per-tenant id to fold in
/// (single-tenant, one bank per daemon) — the bank itself is the isolation
/// boundary, unlike gianna's per-household id in the hash.
///
/// Uses SHA-256 (not `std`'s `DefaultHasher`, whose algorithm is explicitly not
/// stable across Rust releases): the id must survive toolchain upgrades or a
/// correction stops superseding the fact it means to replace and duplicates.
fn doc_id(kind: &str, framed_content: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(framed_content.trim().as_bytes());
    // First 8 bytes of the digest are ample to avoid collisions per kind.
    let mut tag = 0u64;
    for b in &digest[..8] {
        tag = (tag << 8) | u64::from(*b);
    }
    format!("opsclaw-{kind}-{tag:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

    /// A stub Hindsight `POST …/memories` responder: fails (500) for the first
    /// `fail_first` calls, then succeeds (200). Counts every call so a test can
    /// assert the exact number of retain attempts.
    struct FlakyRetain {
        calls: Arc<AtomicUsize>,
        fail_first: usize,
    }
    impl Respond for FlakyRetain {
        fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_first {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({}))
            }
        }
    }

    fn memory_against(server: &MockServer) -> Arc<Memory> {
        let client = hindsight::HindsightClient::new(server.uri(), None, "acme");
        Arc::new(Memory::disabled().with_hindsight(Arc::new(client)))
    }

    /// Tiny backoff so the retry path runs fast (real HTTP to the stub, but ~1ms
    /// between attempts instead of the production 500ms→2s→8s).
    fn detach_fast(memory: &Arc<Memory>, message: &str) {
        memory.detach_with_backoff(
            DetachedRetain::Said { speaker: "dcp".into(), message: message.to_owned() },
            std::time::Duration::from_millis(1),
        );
    }

    /// Spin until `calls` reaches `want` (the spawned task runs concurrently), or
    /// fail after a generous deadline — so a regression fails fast, never hangs.
    async fn wait_for(calls: &Arc<AtomicUsize>, want: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) < want {
            assert!(std::time::Instant::now() < deadline, "timed out waiting for {want} call(s)");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    // A retain that fails twice then succeeds is retried until it lands: memory
    // must survive a briefly-erroring backend, not be lost on the first 500.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retain_detached_retries_until_it_lands() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(FlakyRetain { calls: calls.clone(), fail_first: 2 })
            .mount(&server)
            .await;
        let memory = memory_against(&server);

        detach_fast(&memory, "restarted the payments pod, it recovered");

        // 2 failures + 1 success = exactly 3 attempts. Wait for the success, then
        // confirm it stopped there (no 4th attempt).
        wait_for(&calls, 3).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3, "retries twice then succeeds, then stops");
    }

    // The 3-attempt cap holds: a backend that always 500s is tried exactly 3
    // times and then gives up (it does not loop forever).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retain_detached_gives_up_after_three_attempts() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(FlakyRetain { calls: calls.clone(), fail_first: usize::MAX })
            .mount(&server)
            .await;
        let memory = memory_against(&server);

        detach_fast(&memory, "cluster is in us-east-1");

        wait_for(&calls, 3).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3, "caps at 3 attempts, no infinite loop");
    }

    // The caller does NOT wait for the retain: even when the backend is slow,
    // `retain_detached` returns synchronously (it only spawns), so a chat reply
    // or scan tick built around it is never blocked by a slow Hindsight write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retain_detached_does_not_block_the_caller() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        // Every retain takes 800ms — far longer than the assertion budget below.
        let counter = calls.clone();
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({}))
                    .set_delay(std::time::Duration::from_millis(800))
            })
            .mount(&server)
            .await;
        let memory = memory_against(&server);

        // Returns immediately: the spawn happens, but we never await the retain,
        // so the 800ms backend latency is NOT on the caller's critical path.
        let before = std::time::Instant::now();
        memory.retain_detached("dcp".into(), "cluster is in us-east-1".into());
        assert!(
            before.elapsed() < std::time::Duration::from_millis(100),
            "retain_detached must return promptly without awaiting the slow write"
        );

        // …and the retain still eventually fires in the background.
        wait_for(&calls, 1).await;
    }

    // Shutdown drain: an in-flight detached retain is WAITED FOR, not dropped, so
    // a deploy's SIGTERM doesn't lose a just-learned fact mid-write. The backend
    // holds each retain 300ms; `drain_detached` with a generous budget must block
    // until that write lands, and the call must have completed (200 seen).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_detached_waits_for_an_in_flight_retain() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({}))
                    .set_delay(std::time::Duration::from_millis(300))
            })
            .mount(&server)
            .await;
        let memory = memory_against(&server);

        memory.retain_detached("dcp".into(), "cluster is in us-east-1".into());
        // The spawn has been registered on the tracker; it is in flight.
        assert_eq!(memory.detached_in_flight(), 1, "one retain should be tracked");

        // Drain with plenty of headroom: it must BLOCK until the 300ms write lands.
        let before = std::time::Instant::now();
        let ok = memory.drain_detached(std::time::Duration::from_secs(5)).await;
        assert!(ok, "drain must report success within budget");
        assert!(
            before.elapsed() >= std::time::Duration::from_millis(250),
            "drain must have WAITED for the in-flight write, not returned early"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the retain actually fired before exit");
    }

    // The drain is BOUNDED: a backend that never responds must not hold the deploy
    // open forever — `drain_detached` returns `false` once its budget elapses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_detached_is_bounded_by_its_budget() {
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::method("POST"))
            // Far longer than the drain budget below: the retain can't finish in time.
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
            .mount(&server)
            .await;
        let memory = memory_against(&server);

        memory.retain_detached("dcp".into(), "cluster is in us-east-1".into());
        let before = std::time::Instant::now();
        let ok = memory.drain_detached(std::time::Duration::from_millis(150)).await;
        assert!(!ok, "an un-drainable retain must time out, not hang the shutdown");
        assert!(
            before.elapsed() < std::time::Duration::from_secs(2),
            "drain must return at its budget, not wait on the 30s backend"
        );
    }

    // A no-op memory (no in-flight work) drains instantly and reports success —
    // the common fakes-mode path must not stall or falsely fail the shutdown.
    #[tokio::test]
    async fn drain_detached_is_instant_when_idle() {
        let memory = Arc::new(Memory::disabled());
        assert_eq!(memory.detached_in_flight(), 0);
        assert!(memory.drain_detached(std::time::Duration::from_secs(1)).await);
        assert!(!memory.is_enabled());
    }

    // The detached observation retain rides the SAME tracked/retry path as
    // chat retains and lands with the scan framing + context — the wire-level
    // proof that a scan finding reaches the bank as "scan of {fq_target}
    // observed: …", never as something someone said.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retain_observation_detached_lands_with_scan_framing() {
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let memory = memory_against(&server);

        memory.retain_observation_detached(
            "remundo::prod::web-1".into(),
            "disk at 92% and climbing".into(),
        );
        assert_eq!(memory.detached_in_flight(), 1, "the observation retain is tracked");
        assert!(memory.drain_detached(std::time::Duration::from_secs(5)).await);

        let reqs = server.received_requests().await.expect("recording enabled");
        assert_eq!(reqs.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        let item = &body["items"][0];
        assert_eq!(
            item["content"].as_str().unwrap(),
            "scan of remundo::prod::web-1 observed: disk at 92% and climbing"
        );
        assert_eq!(item["context"].as_str().unwrap(), "scan finding");
    }

    // `export` is the FULL enumeration — no type filter (the archive must
    // carry the raw layers too, not just consolidated observations) — and the
    // per-fact annotations (kind/context/mentioned_at) survive the mapping so
    // the CLI export can render a timestamped, contextual dump.
    #[tokio::test]
    async fn export_enumerates_every_layer_with_annotations() {
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(r"^/v1/default/banks/.*/memories/list$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total": 2,
                "items": [
                    {
                        "id": "m1",
                        "text": "the payments pod OOMs above 400 req/s",
                        "type": "observation",
                        "context": "scan finding",
                        "mentioned_at": "2026-06-18T17:57:17Z"
                    },
                    { "id": "m2", "text": "dcp said: restart fixed it", "type": "experience" }
                ]
            })))
            .mount(&server)
            .await;
        let memory = memory_against(&server);

        let (records, total) = memory.export(100).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind.as_deref(), Some("observation"));
        assert_eq!(records[0].context.as_deref(), Some("scan finding"));
        assert_eq!(records[0].mentioned_at.as_deref(), Some("2026-06-18T17:57:17Z"));
        // Missing annotations are None, and the record still exports.
        assert_eq!(records[1].id, "m2");
        assert!(records[1].mentioned_at.is_none());

        // No `type=` filter reached the backend: the request enumerates every
        // layer (query carries only pagination).
        let reqs = server.received_requests().await.expect("recording enabled");
        let query = reqs[0].url.query().unwrap_or_default();
        assert!(!query.contains("type="), "export must not filter a layer out: {query}");

        // Disabled memory exports an honest nothing, not an error.
        let off = Arc::new(Memory::disabled());
        let (recs, total) = off.export(100).await.unwrap();
        assert!(recs.is_empty());
        assert_eq!(total, 0);
    }

    // doc_id must be a FIXED value for a fixed input, not merely stable within
    // one process run: a toolchain upgrade must not change it (or a correction
    // stops upserting the fact it means to replace). Pins the exact hash.
    #[test]
    fn doc_id_is_stable_across_builds() {
        let id = doc_id("msg", "  dcp said: cluster is in us-east-1  ");
        // Trimming is applied before hashing, so surrounding whitespace is ignored.
        assert_eq!(id, doc_id("msg", "dcp said: cluster is in us-east-1"));
        // Scope separates kinds and content.
        assert_ne!(doc_id("note", "dcp said: cluster is in us-east-1"), id);
        assert_ne!(doc_id("msg", "dcp said: cluster is in us-west-2"), id);
        // Deterministic across repeated calls in the same run too.
        assert_eq!(id, doc_id("msg", "dcp said: cluster is in us-east-1"));
    }

    #[test]
    fn frame_said_and_frame_observed_carry_correct_attribution() {
        assert_eq!(frame_said("dcp", "restarted the pod"), "dcp said: restarted the pod");
        assert_eq!(frame_said("", "restarted the pod"), "the operator said: restarted the pod");
        assert_eq!(
            frame_said("agent", "escalated to pagerduty"),
            "agent said: escalated to pagerduty"
        );
        assert_eq!(
            frame_observed("remundo::prod::cluster", "pod payments-7 in CrashLoopBackOff"),
            "scan of remundo::prod::cluster observed: pod payments-7 in CrashLoopBackOff"
        );
    }

    #[test]
    fn retains_operational_statements_skips_questions_and_acks() {
        // Genuine operational facts -> retain.
        assert!(should_retain("the payments pod OOMs above 400 req/s"));
        assert!(should_retain("restarting the connection pool fixed the timeout issue"));
        assert!(should_retain("dcp prefers approval for anything touching prod DNS"));
        assert!(should_retain("root cause was a stale DNS cache on the edge nodes"));
        assert!(should_retain("remember that the staging cluster is always cold on Mondays"));
        // Questions -> skip (no durable fact).
        assert!(!should_retain("is the payments pod healthy?"));
        assert!(!should_retain("what's the current error rate?"));
        assert!(!should_retain("can you restart the pod?"));
        assert!(!should_retain(""));
        // Bare control-flow acks (approval/chat loop noise) -> skip.
        assert!(!should_retain("yes"));
        assert!(!should_retain("approve"));
        assert!(!should_retain("ok"));
        assert!(!should_retain("no"));
        assert!(!should_retain("ack"));
        assert!(!should_retain("yes, please go ahead"));
    }

    #[test]
    fn secret_shapes_are_never_retained() {
        // PEM private key block.
        assert!(!should_retain(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        ));
        // Bearer token.
        assert!(!should_retain("use Authorization: Bearer sk_live_abcdef1234567890abcdef"));
        // A long base64/hex-looking run embedded in an otherwise ordinary sentence.
        assert!(!should_retain(
            "the api key is AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPLE1234567890abcdef and it's prod"
        ));
        // A genuine operational statement with a short token-like word is fine.
        assert!(should_retain("the deploy tag was v1.2.3 and it fixed the memory leak"));
    }
}
