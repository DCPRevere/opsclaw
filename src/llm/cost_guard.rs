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
}

impl CostGuard {
    pub fn new(inner: Arc<dyn LlmProvider>, repos: Arc<dyn AllRepos>, cap_cents: u32) -> Self {
        CostGuard {
            inner,
            repos,
            cap_cents: f64::from(cap_cents),
            notifier: OnceLock::new(),
            ledger: tokio::sync::Mutex::new(None),
        }
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
            "🛑 Daily LLM cost cap reached: spent {:.1}¢ of the {:.0}¢/day limit \
             (limits.max_cost_per_day_cents). No further LLM calls will be made until UTC \
             midnight. Monitoring ticks, the dead-man ping, and approvals of already-proposed \
             actions continue. Raise the cap in config and restart if this is too tight.",
            spent, self.cap_cents
        );
        match self.notifier.get() {
            Some(channel) => {
                if let Err(e) = channel.send(OutboundMessage { operator: None, body }).await {
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
        let spent = {
            let mut guard = self.ledger.lock().await;
            self.loaded_spend(&mut guard, &day).await
        };
        if spent >= self.cap_cents {
            self.notify_cap_reached(&day, spent).await;
            return Err(crate::Error::llm_hard(format!(
                "daily LLM cost cap reached ({spent:.1}¢ of {:.0}¢) — no further LLM calls \
                 until UTC midnight (limits.max_cost_per_day_cents)",
                self.cap_cents
            )));
        }

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
}
