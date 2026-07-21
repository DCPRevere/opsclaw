//! Memory: retain / recall / reflect, delegated to a self-hosted Hindsight
//! service (the SOLE backend — one bank per household, fully SHARED across the
//! household's members with no per-member visibility filter; facts are framed
//! with the speaker's name so a pooled first-person statement stays anchored to
//! the right person; see `hindsight`). Without `HINDSIGHT_URL`, memory is an
//! honest no-op: there is deliberately no in-process fallback, and the tools
//! tell the user so via `is_enabled`.

pub mod hindsight;

use std::sync::Arc;
use uuid::Uuid;

use crate::Result;

/// A recalled fact, as surfaced to callers (storage lives in Hindsight). `id`
/// is the backend handle a single fact is addressed by (for `forget`); it may be
/// empty when the backend response omitted it.
#[derive(Debug, Clone)]
pub struct MemoryRecord {
    pub id: String,
    pub fact: String,
}

/// Whether a message should be considered for fact extraction. We skip:
/// - pure questions (they're queries, not durable facts about the family);
/// - doctrinal/teaching queries (a weak extractor can invent a doctrinal
///   assertion from them, which must never enter memory — cited-only).
///
/// Deterministic + cheap (no LLM call). Errs toward NOT retaining ambiguous
/// queries; genuine statements ("my wife is Catherine") always pass.
pub fn should_retain(message: &str) -> bool {
    let m = message.trim();
    if m.is_empty() {
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

    // Doctrinal / teaching content — never store as a household fact, even if
    // phrased as a statement ("the Church teaches that…").
    let doctrinal = [
        "church teach",
        "the church say",
        "catechism",
        "is it a sin",
        "is it sinful",
        "mortal sin",
        "venial sin",
        "magisterium",
        "doctrine",
        "what does the church",
        "according to the church",
    ]
    .iter()
    .any(|p| lower.contains(p));

    if doctrinal {
        return false;
    }
    // Skip pure questions; keep statements (even if they contain a '?' mid-text,
    // a leading question word is the stronger signal).
    if (ends_question || opens_question) && !looks_like_statement(&lower) {
        return false;
    }
    true
}

/// Gate for ONBOARDING turns. Deliberately LENIENT: a user can volunteer
/// anything mid-setup ("one on the way", "Catherine and I pray for the day's
/// saint") and it should reach memory — the extraction LLM decides what is
/// actually memorable. The only thing filtered out is the pure control answer
/// ("yes please", "7am", "Sunday"): structured data that lands in the
/// household record, where retention would just feed the extractor noise.
pub fn carries_family_fact(message: &str) -> bool {
    should_retain(message) && !is_bare_control_answer(message)
}

fn looks_like_statement(lower: &str) -> bool {
    ["remember ", "my ", "our ", "we are", "we're", "i am", "i'm", "she is", "he is"]
        .iter()
        .any(|s| lower.contains(s))
}

/// True when every word is setup-flow furniture (assent, numbers, clock times,
/// weekdays, dayparts) — an answer that carries nothing beyond the question it
/// answers. Any word outside that vocabulary means substance: retain it.
fn is_bare_control_answer(message: &str) -> bool {
    const CONTROL: &[&str] = &[
        // assent / refusal / politeness
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
        "sounds",
        "good",
        "lovely",
        "grand",
        "perfect",
        "not",
        "now",
        "skip",
        "none",
        "nothing",
        "pick",
        "choose",
        "whatever",
        "whenever",
        "suits",
        "anytime",
        // numbers and time furniture
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "half",
        "quarter",
        "past",
        "to",
        "at",
        "am",
        "pm",
        "oclock",
        "o'clock",
        "around",
        "about",
        "ish",
        "sharp",
        // dayparts and flow words
        "morning",
        "evening",
        "night",
        "afternoon",
        "noon",
        "midday",
        "midnight",
        "today",
        "tomorrow",
        "daily",
        "weekly",
        "review",
        "examen",
        "time",
        "day",
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "us",
        "me",
        "just",
        "that",
        "thats",
        "it",
        "its",
        "is",
        "works",
        "on",
        "in",
        "for",
        // weekdays
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
        "mon",
        "tue",
        "wed",
        "thu",
        "fri",
        "sat",
        "sun",
        "sundays",
        "mondays",
        "tuesdays",
        "wednesdays",
        "thursdays",
        "fridays",
        "saturdays",
    ];
    message
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != ':' && c != '\'')
        .filter(|w| !w.is_empty())
        .all(|w| w.chars().all(|c| c.is_ascii_digit() || c == ':') || CONTROL.contains(&w))
}

/// The memory service: a thin facade over the Hindsight backend.
pub struct Memory {
    /// Hindsight is the sole backend. None => memory is a no-op (CI/fakes, or a
    /// prod deploy that hasn't set HINDSIGHT_URL yet). There is deliberately no
    /// in-process store: its extraction was unreliable and must never be used.
    hindsight: Option<Arc<hindsight::HindsightClient>>,
    /// Tracks every in-flight detached retain (`retain_detached`). On deploy the
    /// app is SIGTERM'd mid-work (Watchtower recreates the container every
    /// release), and a background retain in flight would otherwise silently drop
    /// a just-learned fact. The shutdown path calls `drain_detached` to wait
    /// (bounded) for these to finish before the process exits.
    detached: tokio_util::task::TaskTracker,
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Memory {
    /// Construct with no backend (no-op memory; tests/fakes).
    pub fn new() -> Self {
        Self { hindsight: None, detached: tokio_util::task::TaskTracker::new() }
    }

    /// No backend attached — the honest no-op (fakes mode). Kept as the frozen
    /// facade entry point; equivalent to `new()`.
    pub fn disabled() -> Self {
        Self::new()
    }

    /// Whether a real memory backend is configured. Tools consult this so the
    /// model is HONEST when memory is off ("I can't remember things right now")
    /// instead of claiming to have saved a fact that went nowhere.
    pub fn is_enabled(&self) -> bool {
        self.hindsight.is_some()
    }

    /// Cheap health probe for the deep readiness check (`/ready?deep=1`). When a
    /// Hindsight backend is configured, ping its `GET /health`; the container
    /// healthcheck uses this so a Hindsight outage marks the app not-ready
    /// instead of leaving monitors green while every chat turn hangs on it. When
    /// no backend is configured (fakes/CI, or a deploy that hasn't set
    /// HINDSIGHT_URL) memory is a deliberate no-op, so there is nothing to probe
    /// — that is reported as healthy: readiness must not fail on an intentionally
    /// disabled dependency (config.rs refuses to boot LIVE without one anyway).
    pub async fn health(&self) -> Result<()> {
        match &self.hindsight {
            Some(h) => h.health().await,
            None => Ok(()),
        }
    }

    /// Attach a Hindsight backend (builder-style). When set, it handles all
    /// retain/recall/reflect.
    pub fn with_hindsight(mut self, client: Arc<hindsight::HindsightClient>) -> Self {
        self.hindsight = Some(client);
        self
    }

    /// Store an explicit note the model chose to keep (the `remember` tool). We
    /// hand Hindsight the RAW text and let its extractor decompose it — we do not
    /// pre-summarise. A content-derived `document_id` makes re-saving the same
    /// note upsert rather than duplicate.
    pub async fn store_fact(
        &self,
        household_id: Uuid,
        speaker: Option<&str>,
        _sender: Option<Uuid>,
        fact: &str,
    ) -> Result<()> {
        // Hindsight is the ONLY memory backend (it does its own extraction +
        // reconciliation). Without it, memory is a no-op. Production must set
        // HINDSIGHT_URL for Gianna to remember anything.
        match &self.hindsight {
            Some(h) => {
                let opts = hindsight::RetainOpts {
                    document_id: Some(doc_id(household_id, "note", fact)),
                    // Receipt time as the event anchor: strictly better than None
                    // (which disables temporal retrieval) and always available.
                    timestamp: Some(now_rfc3339()),
                    context: Some("explicit note Gianna was asked to remember".into()),
                };
                h.retain(household_id, speaker, fact, &opts).await
            }
            None => Ok(()),
        }
    }

    /// Erase the household's ENTIRE remote memory (GDPR / PRIVACY.md §6). Errors
    /// propagate — account deletion must not claim success while the remote bank
    /// survives. No-op when Hindsight isn't configured (nothing was stored).
    pub async fn erase(&self, household_id: Uuid) -> Result<()> {
        match &self.hindsight {
            Some(h) => h.delete_bank(household_id).await,
            None => Ok(()),
        }
    }

    /// `speaker` (the member's display name) is woven into the stored fact so a
    /// shared, household-wide bank can anchor first-person statements to the
    /// right person; `sender` is kept as provenance. Memory is fully shared —
    /// there is no per-member read visibility.
    pub async fn retain(
        &self,
        household_id: Uuid,
        speaker: Option<&str>,
        sender: Option<Uuid>,
        message: &str,
    ) -> Result<()> {
        // Only retain genuine user statements. Questions and doctrinal queries
        // carry no durable family fact, and a weak extractor can turn a doctrinal
        // QUESTION into a stored (uncited, possibly wrong) doctrinal ASSERTION —
        // which would back-door the cited-only doctrine guardrail. Skip them.
        if !should_retain(message) {
            // Logged so "why didn't Gianna remember X?" is answerable: the gate,
            // not the backend, dropped it. Length only (no message text → PII).
            tracing::debug!(%household_id, len = message.chars().count(), "memory.retain skipped (not a durable statement)");
            return Ok(());
        }
        // Hindsight extracts + reconciles facts itself — hand it the raw message.
        if let Some(h) = &self.hindsight {
            let _ = sender; // provenance lives in the speaker frame, not a tag
            let opts = hindsight::RetainOpts {
                // Stable per-(member,message) id so re-sending the same statement
                // upserts rather than duplicating.
                document_id: Some(doc_id(household_id, "msg", message)),
                // Receipt time as the event anchor (see store_fact): omitting it
                // disables Hindsight's temporal retrieval; Utc::now() costs nothing.
                timestamp: Some(now_rfc3339()),
                context: Some("household conversation with Gianna".into()),
            };
            h.retain(household_id, speaker, message, &opts).await?;
        }
        Ok(())
    }

    /// Fire-and-forget retain: spawn a background task that retains and retries
    /// on failure, then return immediately so a slow Hindsight write never blocks
    /// the user's reply. The reply does NOT depend on the retain result (it is
    /// discarded; failures were already only `warn!`-logged), so detaching it is
    /// safe — but because *remembering matters*, the background task retries (3
    /// attempts, exponential backoff) before giving up. Owns its arguments so the
    /// task can outlive the caller; `self` is held as `Arc<Memory>` everywhere
    /// (AppState, Agent), which is cheap to clone.
    ///
    /// Use this for pure best-effort per-turn writes. Do NOT use it where a later
    /// step depends on the retain having completed (e.g. `configure`, which
    /// 404-skips on a not-yet-created bank): keep those synchronous.
    pub fn retain_detached(
        self: &Arc<Self>,
        household_id: Uuid,
        speaker: Option<String>,
        sender: Option<Uuid>,
        message: String,
    ) {
        self.retain_detached_with_backoff(
            household_id,
            speaker,
            sender,
            message,
            std::time::Duration::from_millis(500),
        );
    }

    /// Backoff base extracted so tests can drive the retry path with a tiny delay
    /// (no real 2.5s wait) while production keeps the 500ms→2s→… schedule.
    fn retain_detached_with_backoff(
        self: &Arc<Self>,
        household_id: Uuid,
        speaker: Option<String>,
        sender: Option<Uuid>,
        message: String,
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
                match me.retain(household_id, speaker.as_deref(), sender, &message).await {
                    Ok(_) => return,
                    Err(e) => {
                        tracing::warn!(household = %household_id, attempt, "background retain failed: {e}");
                        if attempt < 3 {
                            tokio::time::sleep(delay).await;
                            delay *= 4;
                        }
                    }
                }
            }
            tracing::warn!(household = %household_id, "background retain gave up after 3 attempts");
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
    pub async fn recall(
        &self,
        household_id: Uuid,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemoryRecord>> {
        match &self.hindsight {
            // ~256 tokens per fact is plenty for short household facts.
            Some(h) => {
                let items = h.recall(household_id, query, (limit as u32).max(1) * 256).await?;
                Ok(items.into_iter().take(limit).map(record).collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// ALL stored facts for a household — the complete, deterministic enumeration
    /// (`GET /memories/list`), for "what do you know about us?" and the user-facing
    /// memory/GDPR panel. This is NOT a recall: it returns every stored fact, not
    /// just those that rank for a canned query (the old fake-list-all silently
    /// dropped facts and re-ordered by relevance).
    pub async fn all(&self, household_id: Uuid, limit: usize) -> Result<Vec<MemoryRecord>> {
        Ok(self.all_with_total(household_id, limit).await?.0)
    }

    /// As `all`, but also reports the household's TOTAL stored-fact count for the
    /// layer returned, so callers can mark truncation ("showing 25 of 212") when
    /// `limit` cut the list. `total` counts the same layer the items came from
    /// (observations if consolidated, else all facts).
    pub async fn all_with_total(
        &self,
        household_id: Uuid,
        limit: usize,
    ) -> Result<(Vec<MemoryRecord>, usize)> {
        match &self.hindsight {
            Some(h) => {
                // Prefer the CONSOLIDATED belief layer (observations): Hindsight
                // folds the raw world/experience facts into deduplicated beliefs,
                // so the panel shows "Brigid is a teacher in Galway" once, not the
                // 3 near-duplicate raw extractions. Consolidation is async, so a
                // brand-new bank may have none yet — fall back to ALL facts so a
                // just-onboarded user still sees what they shared.
                let (mut items, mut total) =
                    h.list_with_total(household_id, Some("observation"), limit).await?;
                if items.is_empty() {
                    let (all_items, all_total) =
                        h.list_with_total(household_id, None, limit).await?;
                    items = all_items;
                    total = all_total;
                }
                Ok((items.into_iter().map(record).collect(), total))
            }
            None => Ok((Vec::new(), 0)),
        }
    }

    /// Forget ONE stored fact — soft-retire it by id (Hindsight `invalidate`:
    /// excluded from recall/consolidation/graph, derived observations recomputed
    /// without it, kept in the archive for audit, reversible). This is NOT a hard
    /// erase (that is `erase`, the whole-bank GDPR wipe); it is the per-fact
    /// "forget that" a user reaches for when Gianna has one thing wrong. No-op
    /// when Hindsight isn't configured — but callers gate on `is_enabled` so they
    /// never falsely claim a fact was forgotten. `reason` rides along for the
    /// audit trail.
    pub async fn forget(&self, household_id: Uuid, memory_id: &str, reason: &str) -> Result<()> {
        match &self.hindsight {
            Some(h) => h.invalidate(household_id, memory_id, reason).await,
            None => Ok(()),
        }
    }

    /// Configure the household's Hindsight bank for first use (no-op without a
    /// backend). Idempotent; callers run it once at household creation.
    pub async fn configure(&self, household_id: Uuid) -> Result<()> {
        match &self.hindsight {
            Some(h) => h.ensure_configured(household_id).await,
            None => Ok(()),
        }
    }

    /// reflect: synthesise a single concise answer from memory (Hindsight only).
    pub async fn reflect(&self, household_id: Uuid, question: &str) -> Result<String> {
        match &self.hindsight {
            Some(h) => h.reflect(household_id, question).await,
            None => Ok(String::new()),
        }
    }
}

/// Map a Hindsight item to our `MemoryRecord`.
fn record(item: hindsight::MemoryItem) -> MemoryRecord {
    MemoryRecord { id: item.id, fact: item.fact }
}

/// Message receipt time as an RFC3339 UTC string, the event anchor we hand
/// Hindsight on every retain (temporal retrieval is disabled when omitted).
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A stable `document_id` for a retained statement, so re-retaining the same
/// thing UPSERTS (Hindsight replaces the prior facts) instead of duplicating.
/// Scoped by household + kind so an explicit note and a chat line never collide.
///
/// Uses SHA-256 (not `std`'s `DefaultHasher`, whose algorithm is explicitly not
/// stable across Rust releases): the id must survive toolchain upgrades or a
/// correction stops superseding the fact it means to replace and duplicates.
fn doc_id(household_id: Uuid, kind: &str, content: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(content.trim().as_bytes());
    // First 8 bytes of the digest are ample to avoid collisions per (household,kind).
    let mut tag = 0u64;
    for b in &digest[..8] {
        tag = (tag << 8) | u64::from(*b);
    }
    format!("gianna-{household_id}-{kind}-{tag:016x}")
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
        let client = hindsight::HindsightClient::new(server.uri(), None);
        Arc::new(Memory::new().with_hindsight(Arc::new(client)))
    }

    /// Tiny backoff so the retry path runs fast (real HTTP to the stub, but ~1ms
    /// between attempts instead of the production 500ms→2s).
    fn detach_fast(memory: &Arc<Memory>, message: &str) {
        memory.retain_detached_with_backoff(
            Uuid::new_v4(),
            Some("David".into()),
            None,
            message.to_owned(),
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

        detach_fast(&memory, "My wife Catherine and I live in Galway");

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

        detach_fast(&memory, "We're in London");

        wait_for(&calls, 3).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3, "caps at 3 attempts, no infinite loop");
    }

    // The caller does NOT wait for the retain: even when the backend is slow,
    // `retain_detached` returns synchronously (it only spawns), so a chat reply
    // built around it is never blocked by a slow Hindsight write.
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
        memory.retain_detached(Uuid::new_v4(), None, None, "We're in London".into());
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

        memory.retain_detached(Uuid::new_v4(), None, None, "We live in Galway".into());
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

        memory.retain_detached(Uuid::new_v4(), None, None, "We live in Galway".into());
        let before = std::time::Instant::now();
        let ok = memory.drain_detached(std::time::Duration::from_millis(150)).await;
        assert!(!ok, "an un-drainable retain must time out, not hang the shutdown");
        assert!(
            before.elapsed() < std::time::Duration::from_secs(2),
            "drain must return at its budget, not wait on the 30s backend"
        );
    }

    // A no-op memory (no in-flight work) drains instantly and reports success —
    // the common CI/fakes path must not stall or falsely fail the shutdown.
    #[tokio::test]
    async fn drain_detached_is_instant_when_idle() {
        let memory = Arc::new(Memory::new());
        assert_eq!(memory.detached_in_flight(), 0);
        assert!(memory.drain_detached(std::time::Duration::from_secs(1)).await);
    }

    #[test]
    fn onboarding_gate_keeps_facts_drops_answers() {
        assert!(carries_family_fact("my mother Anne has been quite unwell"));
        assert!(carries_family_fact("My wife and I live in Galway with our baby daughter Maire."));
        assert!(!carries_family_fact("yes please, around 7"));
        assert!(!carries_family_fact("no weekly review thanks"));
        assert!(!carries_family_fact("Sunday"));
        assert!(!carries_family_fact("half six"));
        assert!(!carries_family_fact("ok, you pick"));
        assert!(!carries_family_fact("7:30 works"));
        // Anything beyond the control vocabulary is substance — the user can
        // volunteer ANYTHING mid-setup; the extraction LLM sorts it out.
        assert!(carries_family_fact("One on the way"));
        assert!(carries_family_fact("Me and Catherine"));
        assert!(carries_family_fact(
            "Yes please, I would like to know whose feast day it is, \
             Catherine and I like to pray for their intercession every day"
        ));
    }

    // doc_id must be a FIXED value for a fixed input, not merely stable within
    // one process run: a toolchain upgrade must not change it (or a correction
    // stops upserting the fact it means to replace). Pins the exact hash.
    #[test]
    fn doc_id_is_stable_across_builds() {
        let hh = Uuid::nil();
        let id = doc_id(hh, "msg", "  We live in Galway  ");
        // Trimming is applied before hashing, so surrounding whitespace is ignored.
        assert_eq!(id, doc_id(hh, "msg", "We live in Galway"));
        // The literal value is pinned: if SHA-256 or the framing changes, this
        // fails loudly rather than silently forking upsert identity.
        assert_eq!(id, "gianna-00000000-0000-0000-0000-000000000000-msg-abf539f1a13eef27");
        // Scope separates kinds and content.
        assert_ne!(doc_id(hh, "note", "We live in Galway"), id);
        assert_ne!(doc_id(hh, "msg", "We live in Cork"), id);
    }

    #[test]
    fn retains_statements_skips_questions_and_doctrine() {
        // Genuine family facts -> retain.
        assert!(should_retain("My wife Catherine and I are expecting a child"));
        assert!(should_retain("Thérèse is allergic to peanuts"));
        assert!(should_retain("We're in London"));
        assert!(should_retain("remember that my wife is Catherine?")); // statement w/ '?'
        // Questions -> skip (no durable fact).
        assert!(!should_retain("what's the weather like?"));
        assert!(!should_retain("how do I start a novena?"));
        assert!(!should_retain("when is Easter?"));
        // Doctrinal queries -> NEVER retain (cited-only guardrail).
        assert!(!should_retain("what does the Church teach about contraception?"));
        assert!(!should_retain("is it a sin to miss Mass?"));
        assert!(!should_retain("The Church teaches that life begins at conception")); // even as a statement
        assert!(!should_retain(""));
    }
}
