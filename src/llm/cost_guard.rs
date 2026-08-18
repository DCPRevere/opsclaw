//! Daily LLM cost-cap enforcement — the missing consumer of
//! `limits.max_cost_per_day_cents` (previously priced per call in
//! `pricing.rs` but never accumulated or enforced: a FAIL-OPEN gap).
//!
//! [`CostGuard`] decorates the whole provider chain (it wraps the
//! `FallbackLlm` `build_chain` returns, so every retry/fallback path is
//! inside the guard). Before each step it checks today's accumulated spend
//! against the cap; past the cap it refuses the call with a hard
//! (non-retryable) error and notifies the team channel LOUDLY, exactly once
//! per UTC day (`ControlRepo::claim` — crash-safe exactly-once). The daemon
//! itself keeps ticking: scheduler jobs fail into their normal
//! failure-budget path, the watchdog/dead-man never involves the LLM, and
//! everything resumes at UTC midnight.
//!
//! The ledger is a per-UTC-day running total persisted through
//! `ChannelStateRepo`'s generic durable scalar store (key
//! `llm_spend_cents:<YYYY-MM-DD>`), so a restart cannot forget spend — the
//! same fail-closed direction as every other limit. Per-call detail is not
//! duplicated here; the audit chain already records every turn.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use chrono::Utc;
use serde::Serialize;

use crate::Result;
use crate::channels::{Channel, OutboundMessage};
use crate::db::AllRepos;
use crate::domain::Principal;
use crate::llm::{ChatStep, LlmProvider, ToolSpec, Turn, pricing};

/// KV key prefix for the per-day spend total.
const SPEND_KEY_PREFIX: &str = "llm_spend_cents";
/// `ControlRepo::claim` kind for the once-per-day cap notification.
const CAP_NOTICE_CLAIM_KIND: &str = "llm_cost_cap_notice";

fn spend_key(day: &str) -> String {
    format!("{SPEND_KEY_PREFIX}:{day}")
}

fn today_utc() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

/// The cost-cap decorator. Construct once at boot around the built chain;
/// `set_notifier` is called later in boot (the channel fan-out is composed
/// after the LLM), so the guard is never blocked on wiring order — an unset
/// notifier degrades to an ERROR log, never to silence about the cap itself
/// (the refusal error text reaches whoever triggered the call regardless).
pub struct CostGuard {
    inner: Arc<dyn LlmProvider>,
    repos: Arc<dyn AllRepos>,
    cap_cents: f64,
    notifier: OnceLock<Arc<dyn Channel>>,
    /// (utc day, cents spent) — cache over the KV row, serialized so
    /// concurrent turns can't lose an increment.
    ledger: tokio::sync::Mutex<Option<(String, f64)>>,
    hindsight_meter: Option<ProviderMeter>,
    hindsight_configured: bool,
}

struct ProviderMeter {
    http: reqwest::Client,
    url: String,
    key: String,
    shared_with_opsclaw: bool,
    cache: tokio::sync::Mutex<Option<(std::time::Instant, f64)>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpendSnapshot {
    pub day_utc: String,
    pub opsclaw_cents: f64,
    pub hindsight_cents: Option<f64>,
    pub total_cents: f64,
    pub cap_cents: f64,
    pub remaining_cents: f64,
    pub complete: bool,
}

impl CostGuard {
    pub fn new(inner: Arc<dyn LlmProvider>, repos: Arc<dyn AllRepos>, cap_cents: u32) -> Self {
        CostGuard {
            inner,
            repos,
            cap_cents: f64::from(cap_cents),
            notifier: OnceLock::new(),
            ledger: tokio::sync::Mutex::new(None),
            hindsight_meter: None,
            hindsight_configured: false,
        }
    }

    /// Include Hindsight's OpenRouter key in the same daily budget. The
    /// current-key endpoint reports `usage_daily` in dollars; when both
    /// components share a key that value is already the combined total.
    pub fn with_hindsight_openrouter_meter(
        mut self,
        key: String,
        shared_with_opsclaw: bool,
    ) -> Self {
        self.install_hindsight_meter(
            key,
            shared_with_opsclaw,
            "https://openrouter.ai/api/v1/key".into(),
        );
        self
    }

    fn install_hindsight_meter(&mut self, key: String, shared_with_opsclaw: bool, url: String) {
        self.hindsight_configured = true;
        self.hindsight_meter = Some(ProviderMeter {
            http: reqwest::Client::new(),
            url,
            key,
            shared_with_opsclaw,
            cache: tokio::sync::Mutex::new(None),
        });
    }

    pub fn with_unmetered_hindsight(mut self) -> Self {
        self.hindsight_configured = true;
        self
    }

    /// Install the escalation channel (idempotent; first caller wins).
    pub fn set_notifier(&self, channel: Arc<dyn Channel>) {
        let _ = self.notifier.set(channel);
    }

    /// Today's accumulated spend in cents (loads the durable row on first
    /// use or day rollover). Public so `doctor`/status surfaces can show it.
    pub async fn spent_today_cents(&self) -> f64 {
        let mut guard = self.ledger.lock().await;
        self.loaded_spend(&mut guard, &today_utc()).await
    }

    /// The configured daily cap in cents.
    pub fn cap_cents(&self) -> f64 {
        self.cap_cents
    }

    pub async fn spend_snapshot(&self) -> Result<SpendSnapshot> {
        let day = today_utc();
        let opsclaw = self.spent_today_cents().await;
        let (hindsight, total, complete) = match &self.hindsight_meter {
            Some(meter) => {
                let provider_total = meter.daily_cents().await?;
                if meter.shared_with_opsclaw {
                    (Some((provider_total - opsclaw).max(0.0)), provider_total.max(opsclaw), true)
                } else {
                    (Some(provider_total), opsclaw + provider_total, true)
                }
            }
            None => (None, opsclaw, !self.hindsight_configured),
        };
        Ok(SpendSnapshot {
            day_utc: day,
            opsclaw_cents: opsclaw,
            hindsight_cents: hindsight,
            total_cents: total,
            cap_cents: self.cap_cents,
            remaining_cents: (self.cap_cents - total).max(0.0),
            complete,
        })
    }

    /// Shared preflight for OpsClaw and Hindsight model work.
    pub async fn ensure_under_cap(&self) -> Result<SpendSnapshot> {
        let snapshot = self.spend_snapshot().await?;
        if !snapshot.complete {
            return Err(crate::Error::llm_hard(
                "daily LLM cost cap cannot include Hindsight — set HINDSIGHT_LLM_BASE_URL to \
                 OpenRouter and HINDSIGHT_LLM_API_KEY to its key",
            ));
        }
        if snapshot.total_cents >= self.cap_cents {
            self.notify_cap_reached(&snapshot.day_utc, snapshot.total_cents).await;
            return Err(crate::Error::llm_hard(format!(
                "daily LLM cost cap reached ({:.1}¢ of {:.0}¢) — no further LLM calls until UTC midnight",
                snapshot.total_cents, self.cap_cents
            )));
        }
        Ok(snapshot)
    }

    /// Resolve the cached ledger for `day`, (re)loading from the durable KV
    /// row on first use or when the cached day is stale (UTC rollover).
    async fn loaded_spend(&self, cache: &mut Option<(String, f64)>, day: &str) -> f64 {
        match cache {
            Some((cached_day, cents)) if cached_day == day => *cents,
            _ => {
                let stored = self
                    .repos
                    .get_channel_state(&spend_key(day))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0);
                *cache = Some((day.to_string(), stored));
                stored
            }
        }
    }

    /// Send the once-per-UTC-day cap notification (claim-guarded so a
    /// restart can't re-send it) and always log at ERROR.
    async fn notify_cap_reached(&self, day: &str, spent: f64) {
        tracing::error!(
            spent_cents = spent,
            cap_cents = self.cap_cents,
            "daily LLM cost cap REACHED — refusing further LLM calls until UTC midnight"
        );
        let newly_claimed =
            self.repos.claim(CAP_NOTICE_CLAIM_KIND, day, Utc::now()).await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "cap-notice claim failed; suppressing channel notice");
                false
            });
        if !newly_claimed {
            return;
        }
        let body = format!(
            "Daily LLM cost cap reached: spent {:.1}¢ of the {:.0}¢/day limit \
             (limits.max_cost_per_day_cents). No further LLM calls will be made until UTC \
             midnight. Monitoring ticks, the dead-man ping, and approvals of already-proposed \
             actions continue. Raise the cap in config and restart if this is too tight.",
            spent, self.cap_cents
        );
        match self.notifier.get() {
            Some(channel) => {
                if let Err(e) =
                    channel.send(OutboundMessage { operator: None, body, meta: None }).await
                {
                    tracing::error!(error = %e, "cap-reached notification failed to send");
                }
            }
            None => tracing::error!("no notifier wired on CostGuard — cap notice logged only"),
        }
    }

    /// Add one step's cost to the ledger and persist. Persistence failure is
    /// logged, never fatal to the turn (the in-memory total still advanced,
    /// so enforcement stays correct for this process's lifetime).
    async fn record(&self, day: &str, cost_cents: f64) -> f64 {
        let mut guard = self.ledger.lock().await;
        let spent = self.loaded_spend(&mut guard, day).await + cost_cents;
        *guard = Some((day.to_string(), spent));
        if let Err(e) = self.repos.set_channel_state(&spend_key(day), &spent.to_string()).await {
            tracing::warn!(error = %e, "failed to persist LLM spend ledger");
        }
        spent
    }
}

#[async_trait]
impl LlmProvider for CostGuard {
    async fn chat_step(
        &self,
        principal: &Principal,
        system: &str,
        history: &[Turn],
        tools: &[ToolSpec],
    ) -> Result<ChatStep> {
        let day = today_utc();
        self.ensure_under_cap().await?;

        let mut step = self.inner.chat_step(principal, system, history, tools).await?;

        // Provider-reported cost wins; otherwise price from the table
        // against the chain's primary model id (`FallbackLlm::name`
        // delegates to it). OpenRouter reports truth, so the table path is
        // the Anthropic/fakes fallback.
        pricing::price_usage(&mut step.usage, self.inner.name());
        let cost = step.usage.cost_cents.unwrap_or(0.0);
        if cost > 0.0 {
            let total = self.record(&day, cost).await;
            if total >= self.cap_cents {
                // Crossed the cap ON this step: announce now rather than
                // waiting for the next (refused) call — "notify loudly" is
                // the contract, and the next call could be hours away.
                self.notify_cap_reached(&day, total).await;
            }
        }
        Ok(step)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

impl ProviderMeter {
    async fn daily_cents(&self) -> Result<f64> {
        let mut cache = self.cache.lock().await;
        if let Some((at, cents)) = *cache
            && at.elapsed() < std::time::Duration::from_secs(15)
        {
            return Ok(cents);
        }
        let response = self
            .http
            .get(&self.url)
            .bearer_auth(&self.key)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| crate::Error::other(format!("OpenRouter spend lookup: {e}")))?;
        let status = response.status();
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| crate::Error::other(format!("OpenRouter spend response: {e}")))?;
        if !status.is_success() {
            return Err(crate::Error::other(format!(
                "OpenRouter spend lookup returned HTTP {status}"
            )));
        }
        let dollars = body["data"]["usage_daily"].as_f64().ok_or_else(|| {
            crate::Error::other("OpenRouter spend response omitted data.usage_daily")
        })?;
        let cents = dollars * 100.0;
        *cache = Some((std::time::Instant::now(), cents));
        Ok(cents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::recording::RecordingChannel;
    use crate::db::Db;
    use crate::llm::TokenUsage;

    /// A provider returning a fixed provider-reported cost per step.
    struct FixedCostLlm {
        cost_cents: f64,
    }

    #[async_trait]
    impl LlmProvider for FixedCostLlm {
        async fn chat_step(
            &self,
            _principal: &Principal,
            _system: &str,
            _history: &[Turn],
            _tools: &[ToolSpec],
        ) -> Result<ChatStep> {
            Ok(ChatStep {
                text: Some("ok".into()),
                tool_calls: Vec::new(),
                usage: TokenUsage {
                    input_tokens: 1000,
                    output_tokens: 100,
                    cost_cents: Some(self.cost_cents),
                },
            })
        }
        fn name(&self) -> &str {
            "fixed-cost"
        }
    }

    fn guard_with(cost_per_step: f64, cap: u32) -> (CostGuard, Arc<dyn AllRepos>) {
        let repos = Db::fake().repos();
        let guard = CostGuard::new(
            Arc::new(FixedCostLlm { cost_cents: cost_per_step }),
            repos.clone(),
            cap,
        );
        (guard, repos)
    }

    async fn step(guard: &CostGuard) -> Result<ChatStep> {
        guard.chat_step(&Principal::System, "sys", &[], &[]).await
    }

    #[tokio::test]
    async fn accumulates_and_refuses_past_the_cap() {
        // 200¢/step against a 500¢ cap: steps 1-3 run (0, 200, 400 spent at
        // check time), step 4 refuses (600 >= 500).
        let (guard, _repos) = guard_with(200.0, 500);
        for _ in 0..3 {
            step(&guard).await.unwrap();
        }
        let err = step(&guard).await.unwrap_err();
        assert!(err.to_string().contains("cost cap"), "{err}");
        assert!(!err.is_retryable(), "cap refusal must be hard, not retried");
        assert_eq!(guard.spent_today_cents().await, 600.0);
    }

    #[tokio::test]
    async fn spend_survives_a_restart_via_the_durable_ledger() {
        let (guard, repos) = guard_with(300.0, 500);
        step(&guard).await.unwrap();
        step(&guard).await.unwrap(); // 600¢ recorded

        // A fresh guard over the SAME repos (a daemon restart) must see the
        // stored spend and refuse immediately.
        let restarted = CostGuard::new(Arc::new(FixedCostLlm { cost_cents: 300.0 }), repos, 500);
        let err = step(&restarted).await.unwrap_err();
        assert!(err.to_string().contains("cost cap"), "{err}");
    }

    #[tokio::test]
    async fn cap_notice_is_sent_loudly_and_exactly_once() {
        let (guard, _repos) = guard_with(600.0, 500);
        let channel = Arc::new(RecordingChannel::new());
        guard.set_notifier(channel.clone());

        step(&guard).await.unwrap(); // crosses the cap on this step -> notice
        let _ = step(&guard).await.unwrap_err(); // refused -> claim suppresses a second notice
        let _ = step(&guard).await.unwrap_err();

        let sent = channel.sent();
        assert_eq!(sent.len(), 1, "exactly one cap notice, got {sent:?}");
        assert!(sent[0].body.contains("cost cap"), "{}", sent[0].body);
        assert!(sent[0].operator.is_none(), "cap notice is a team-wide broadcast");
    }

    #[tokio::test]
    async fn under_cap_calls_pass_through_untouched() {
        let (guard, _repos) = guard_with(1.0, 500);
        let s = step(&guard).await.unwrap();
        assert_eq!(s.text.as_deref(), Some("ok"));
        assert_eq!(guard.spent_today_cents().await, 1.0);
    }

    #[tokio::test]
    async fn zero_cap_means_no_spend_not_unlimited() {
        // LimitsCfg's doc: 0 is "no spend", failing closed.
        let (guard, _repos) = guard_with(1.0, 0);
        let err = step(&guard).await.unwrap_err();
        assert!(err.to_string().contains("cost cap"), "{err}");
    }

    /// A provider with NO provider-reported cost: the table prices it. An
    /// unknown model id gets the deliberately-expensive default, so spend
    /// still accrues (never free).
    struct NoCostLlm;

    #[async_trait]
    impl LlmProvider for NoCostLlm {
        async fn chat_step(
            &self,
            _principal: &Principal,
            _system: &str,
            _history: &[Turn],
            _tools: &[ToolSpec],
        ) -> Result<ChatStep> {
            Ok(ChatStep {
                text: Some("ok".into()),
                tool_calls: Vec::new(),
                usage: TokenUsage { input_tokens: 1_000_000, output_tokens: 0, cost_cents: None },
            })
        }
        fn name(&self) -> &str {
            "some/unpriced-model"
        }
    }

    #[tokio::test]
    async fn table_prices_a_step_with_no_provider_cost() {
        let repos = Db::fake().repos();
        let guard = CostGuard::new(Arc::new(NoCostLlm), repos, 50_000);
        step(&guard).await.unwrap();
        // 1M input at the unknown-model default (300¢/Mtok input).
        assert_eq!(guard.spent_today_cents().await, 300.0);
    }

    #[tokio::test]
    async fn separate_hindsight_key_is_reported_and_enforced() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/key"))
            .and(wiremock::matchers::header("authorization", "Bearer hs-key"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": {"usage_daily": 4.25}})),
            )
            .mount(&server)
            .await;

        let (mut guard, _repos) = guard_with(1.0, 400);
        guard.install_hindsight_meter(
            "hs-key".into(),
            false,
            format!("{}/api/v1/key", server.uri()),
        );
        let snapshot = guard.spend_snapshot().await.unwrap();
        assert_eq!(snapshot.hindsight_cents, Some(425.0));
        assert_eq!(snapshot.total_cents, 425.0);
        assert!(step(&guard).await.unwrap_err().to_string().contains("cost cap"));
    }

    #[tokio::test]
    async fn configured_but_unmetered_hindsight_fails_closed() {
        let (guard, _repos) = guard_with(1.0, 500);
        let guard = guard.with_unmetered_hindsight();
        let snapshot = guard.spend_snapshot().await.unwrap();
        assert!(!snapshot.complete);
        let err = step(&guard).await.unwrap_err();
        assert!(err.to_string().contains("cannot include Hindsight"), "{err}");
    }
}
