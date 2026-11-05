//! Daily LLM cost-cap enforcement — the missing consumer of
//! `limits.max_cost_per_day_cents` (previously priced per call in
//! `pricing.rs` but never accumulated or enforced: a FAIL-OPEN gap).
//!
//! [`CostGuard`] decorates the whole model chain (it wraps the `Fallback`
//! `build_chain` returns, so every retry/fallback path is inside the guard).
//! The chain reports each successful call's usage to a [`SpendMeter`]; the
//! guard drains the meter into the ledger after every call. Before each step it checks today's accumulated spend
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
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::channels::{Channel, OutboundMessage};
use crate::db::AllRepos;
use crate::domain::Principal;
use crate::llm::{ChatModel, ChatStep, Llm, SystemPrompt, ToolTurn, Usage, UsageSink, pricing};

/// KV key prefix for the per-day spend total.
const SPEND_KEY_PREFIX: &str = "llm_spend_cents";
/// KV key prefix for Hindsight's per-day spend, metered from its `/metrics`.
const HINDSIGHT_METERED_KEY_PREFIX: &str = "llm_spend_hindsight_metrics";
/// `ControlRepo::claim` kind for the once-per-day cap notification.
const CAP_NOTICE_CLAIM_KIND: &str = "llm_cost_cap_notice";

fn spend_key(day: &str) -> String {
    format!("{SPEND_KEY_PREFIX}:{day}")
}

fn today_utc() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

/// The chain's usage sink: prices each successful model call (the
/// provider's reported cost wins, otherwise the price table for the model
/// that actually ran) and holds the cents until [`CostGuard`] records them
/// in the durable ledger. Calls are not attributed individually — the cap
/// only needs the total, so concurrent turns can share one meter.
#[derive(Debug, Default)]
pub struct SpendMeter {
    pending_cents: std::sync::Mutex<f64>,
}

impl SpendMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take everything metered since the last call.
    fn take(&self) -> f64 {
        std::mem::take(&mut *self.pending_cents.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl UsageSink<Principal> for SpendMeter {
    fn record(&self, _caller: &Principal, model: &str, usage: Usage, reported_cents: Option<f64>) {
        let cents = pricing::call_cost_cents(&usage, model, reported_cents);
        *self.pending_cents.lock().unwrap_or_else(|e| e.into_inner()) += cents;
    }
}

/// The cost-cap decorator. Construct once at boot around the built chain;
/// `set_notifier` is called later in boot (the channel fan-out is composed
/// after the LLM), so the guard is never blocked on wiring order — an unset
/// notifier degrades to an ERROR log, never to silence about the cap itself
/// (the refusal error text reaches whoever triggered the call regardless).
pub struct CostGuard {
    inner: Arc<Llm>,
    meter: Arc<SpendMeter>,
    repos: Arc<dyn AllRepos>,
    cap_cents: f64,
    notifier: OnceLock<Arc<dyn Channel>>,
    /// (utc day, cents spent) — cache over the KV row, serialized so
    /// concurrent turns can't lose an increment.
    ledger: tokio::sync::Mutex<Option<(String, f64)>>,
    hindsight_meter: Option<HindsightMeter>,
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
    /// `meter` must be the usage sink `inner` reports to (see
    /// [`crate::llm::build_chain`]); a model that reports nowhere is never
    /// charged.
    pub fn new(
        inner: Arc<Llm>,
        meter: Arc<SpendMeter>,
        repos: Arc<dyn AllRepos>,
        cap_cents: u32,
    ) -> Self {
        CostGuard {
            inner,
            meter,
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
        self.hindsight_meter = Some(HindsightMeter::OpenRouter(ProviderMeter {
            http: reqwest::Client::new(),
            url,
            key,
            shared_with_opsclaw,
            cache: tokio::sync::Mutex::new(None),
        }));
    }

    /// Meter Hindsight from its own Prometheus token counters
    /// (`metrics_url`, normally `<hindsight_url>/metrics`), priced from the
    /// built-in list prices. For a Hindsight whose LLM isn't on OpenRouter,
    /// such as OpenAI direct, whose spend can't be read with a normal key.
    pub fn with_hindsight_metrics_meter(mut self, metrics_url: String) -> Self {
        self.hindsight_configured = true;
        self.hindsight_meter = Some(HindsightMeter::Metrics(MetricsMeter {
            http: reqwest::Client::new(),
            url: metrics_url,
            table: dcpr_llm::PriceTable::built_in(),
            repos: self.repos.clone(),
            state: tokio::sync::Mutex::new(MetricsState::default()),
        }));
        self
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
            Some(HindsightMeter::Metrics(meter)) => {
                let hindsight = meter.daily_cents().await?;
                (Some(hindsight), opsclaw + hindsight, true)
            }
            Some(HindsightMeter::OpenRouter(meter)) => {
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
                "daily LLM cost cap cannot include Hindsight — set memory.hindsight_url (its \
                 /metrics is metered) or point HINDSIGHT_LLM_BASE_URL at OpenRouter",
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

impl CostGuard {
    /// Refuse past the cap, run `call`, then charge whatever the chain
    /// metered while it ran. The meter is drained after a failure too, so
    /// nothing metered is ever left pending.
    async fn guarded<T>(
        &self,
        call: impl std::future::Future<Output = dcpr_llm::Result<T>>,
    ) -> dcpr_llm::Result<T> {
        let day = today_utc();
        self.ensure_under_cap().await.map_err(into_llm_error)?;
        let result = call.await;
        let cost = self.meter.take();
        if cost > 0.0 {
            let total = self.record(&day, cost).await;
            if total >= self.cap_cents {
                // Crossed the cap ON this call: announce now rather than
                // waiting for the next (refused) call — "notify loudly" is
                // the contract, and the next call could be hours away.
                self.notify_cap_reached(&day, total).await;
            }
        }
        result
    }
}

/// The guard's refusals are hard model errors, so the loop and any retry
/// logic stop instead of retrying into the cap.
fn into_llm_error(e: crate::Error) -> dcpr_llm::Error {
    match e {
        crate::Error::Llm(e) => e,
        other => dcpr_llm::Error::hard(other.to_string()),
    }
}

#[async_trait]
impl ChatModel<Principal> for CostGuard {
    fn model_id(&self) -> &str {
        self.inner.model_id()
    }

    fn supports_tools(&self) -> bool {
        self.inner.supports_tools()
    }

    async fn chat_step(
        &self,
        principal: &Principal,
        system: SystemPrompt<'_>,
        history: &[ToolTurn],
        tools: &[serde_json::Value],
    ) -> dcpr_llm::Result<ChatStep> {
        self.guarded(self.inner.chat_step(principal, system, history, tools)).await
    }

    async fn chat_step_stream(
        &self,
        principal: &Principal,
        system: SystemPrompt<'_>,
        history: &[ToolTurn],
        tools: &[serde_json::Value],
        sink: Arc<dyn dcpr_llm::TextStreamSink>,
    ) -> dcpr_llm::Result<ChatStep> {
        self.guarded(self.inner.chat_step_stream(principal, system, history, tools, sink)).await
    }

    async fn complete(
        &self,
        principal: &Principal,
        request: dcpr_llm::Completion<'_>,
    ) -> dcpr_llm::Result<String> {
        self.guarded(self.inner.complete(principal, request)).await
    }
}

/// Hindsight's Prometheus endpoint, next to its API.
pub fn hindsight_metrics_url(memory: &crate::config::MemoryCfg) -> String {
    let base = memory.hindsight_url.as_deref().unwrap_or_default().trim_end_matches('/');
    format!("{base}/metrics")
}

/// How Hindsight's own LLM spend reaches the daily cap.
enum HindsightMeter {
    /// OpenRouter's per-key daily usage.
    OpenRouter(ProviderMeter),
    /// Hindsight's Prometheus token counters, priced locally.
    Metrics(MetricsMeter),
}

/// Today's Hindsight spend, metered from cumulative counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
struct MeteredDay {
    today_cents: f64,
    /// The counters' priced total at the last reading.
    last_cumulative_cents: f64,
}

#[derive(Default)]
struct MetricsState {
    day: Option<String>,
    metered: MeteredDay,
    fetched: Option<std::time::Instant>,
}

struct MetricsMeter {
    http: reqwest::Client,
    url: String,
    table: dcpr_llm::PriceTable,
    repos: Arc<dyn AllRepos>,
    state: tokio::sync::Mutex<MetricsState>,
}

impl MetricsMeter {
    async fn daily_cents(&self) -> Result<f64> {
        let mut state = self.state.lock().await;
        let day = today_utc();
        if state.day.as_deref() == Some(day.as_str())
            && state.fetched.is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(15))
        {
            return Ok(state.metered.today_cents);
        }
        let response = self
            .http
            .get(&self.url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| crate::Error::other(format!("Hindsight metrics: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(crate::Error::other(format!("Hindsight metrics returned HTTP {status}")));
        }
        let body = response
            .text()
            .await
            .map_err(|e| crate::Error::other(format!("Hindsight metrics body: {e}")))?;
        let cumulative = cumulative_cost_cents(&body, &self.table);
        let key = format!("{HINDSIGHT_METERED_KEY_PREFIX}:{day}");
        if state.day.as_deref() != Some(day.as_str()) {
            // First reading today: carry on from a stored reading (the daemon
            // restarted), or start the day at the counters' current level.
            let stored = self
                .repos
                .get_channel_state(&key)
                .await
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_str::<MeteredDay>(&v).ok());
            state.metered = stored
                .unwrap_or(MeteredDay { today_cents: 0.0, last_cumulative_cents: cumulative });
            state.day = Some(day);
        }
        state.metered = advance(state.metered, cumulative);
        state.fetched = Some(std::time::Instant::now());
        match serde_json::to_string(&state.metered) {
            Ok(value) => {
                if let Err(e) = self.repos.set_channel_state(&key, &value).await {
                    tracing::warn!("could not persist Hindsight's metered spend: {e}");
                }
            }
            Err(e) => tracing::warn!("could not encode Hindsight's metered spend: {e}"),
        }
        Ok(state.metered.today_cents)
    }
}

/// Move today's metered spend on to a new cumulative reading. The counters
/// only grow, so a lower reading means Hindsight restarted and counted from
/// zero again: everything it counted since then is new spend.
fn advance(day: MeteredDay, cumulative_cents: f64) -> MeteredDay {
    let delta = if cumulative_cents + 1e-9 >= day.last_cumulative_cents {
        cumulative_cents - day.last_cumulative_cents
    } else {
        cumulative_cents
    };
    MeteredDay { today_cents: day.today_cents + delta, last_cumulative_cents: cumulative_cents }
}

const HINDSIGHT_INPUT_TOKENS: &str = "hindsight_llm_tokens_input_tokens_total";
const HINDSIGHT_OUTPUT_TOKENS: &str = "hindsight_llm_tokens_output_tokens_total";

/// The priced total of Hindsight's token counters, summed over every label
/// set per model. Cached tokens aren't reported separately, so all input is
/// priced at the full rate: an overcount, the safe direction for a cap. A
/// model with no price gets [`pricing::UNKNOWN_MODEL_PRICE`].
fn cumulative_cost_cents(metrics: &str, table: &dcpr_llm::PriceTable) -> f64 {
    let mut per_model: std::collections::HashMap<String, (f64, f64)> = Default::default();
    for line in metrics.lines() {
        let (input, output) = if line.starts_with(HINDSIGHT_INPUT_TOKENS) {
            (true, false)
        } else if line.starts_with(HINDSIGHT_OUTPUT_TOKENS) {
            (false, true)
        } else {
            continue;
        };
        let Some((model, value)) = counter_sample(line) else { continue };
        let entry = per_model.entry(model).or_default();
        if input {
            entry.0 += value;
        }
        if output {
            entry.1 += value;
        }
    }
    per_model
        .iter()
        .map(|(model, (input, output))| {
            let usage = Usage {
                input_tokens: *input as u64,
                output_tokens: *output as u64,
                ..Default::default()
            };
            table.price(model).unwrap_or(pricing::UNKNOWN_MODEL_PRICE).cost_cents(&usage)
        })
        .sum()
}

/// `(model label, value)` from one Prometheus sample line.
fn counter_sample(line: &str) -> Option<(String, f64)> {
    let (labels, rest) = match (line.find('{'), line.rfind('}')) {
        (Some(open), Some(close)) if close > open => (&line[open + 1..close], &line[close + 1..]),
        _ => ("", line.split_once(' ').map(|(_, r)| r).unwrap_or("")),
    };
    let model = labels
        .split("model=\"")
        .nth(1)
        .and_then(|after| after.split('"').next())
        .unwrap_or("unknown")
        .to_string();
    let value = rest.split_whitespace().next()?.parse::<f64>().ok()?;
    Some((model, value))
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

    /// A model that reports a fixed usage per step to its meter, the way the
    /// shipped client reports to the chain's usage sink.
    struct MeteredLlm {
        meter: Arc<SpendMeter>,
        model: &'static str,
        usage: Usage,
        reported_cents: Option<f64>,
    }

    #[async_trait]
    impl ChatModel<Principal> for MeteredLlm {
        fn model_id(&self) -> &str {
            self.model
        }

        async fn chat_step(
            &self,
            principal: &Principal,
            _system: SystemPrompt<'_>,
            _history: &[ToolTurn],
            _tools: &[serde_json::Value],
        ) -> dcpr_llm::Result<ChatStep> {
            self.meter.record(principal, self.model, self.usage, self.reported_cents);
            Ok(ChatStep::Text("ok".into()))
        }
    }

    fn guard_over(
        repos: Arc<dyn AllRepos>,
        model: &'static str,
        usage: Usage,
        reported_cents: Option<f64>,
        cap: u32,
    ) -> CostGuard {
        let meter = Arc::new(SpendMeter::new());
        let llm = MeteredLlm { meter: meter.clone(), model, usage, reported_cents };
        CostGuard::new(Arc::new(llm), meter, repos, cap)
    }

    fn fixed_cost_guard(repos: Arc<dyn AllRepos>, cost_per_step: f64, cap: u32) -> CostGuard {
        let usage = Usage { input_tokens: 1000, output_tokens: 100, ..Default::default() };
        guard_over(repos, "fixed-cost", usage, Some(cost_per_step), cap)
    }

    fn guard_with(cost_per_step: f64, cap: u32) -> (CostGuard, Arc<dyn AllRepos>) {
        let repos = Db::fake().repos();
        (fixed_cost_guard(repos.clone(), cost_per_step, cap), repos)
    }

    async fn step(guard: &CostGuard) -> crate::Result<ChatStep> {
        Ok(guard.chat_step(&Principal::System, "sys".into(), &[], &[]).await?)
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
        let restarted = fixed_cost_guard(repos, 300.0, 500);
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
        assert!(matches!(s, ChatStep::Text(t) if t == "ok"));
        assert_eq!(guard.spent_today_cents().await, 1.0);
    }

    #[tokio::test]
    async fn zero_cap_means_no_spend_not_unlimited() {
        // LimitsCfg's doc: 0 is "no spend", failing closed.
        let (guard, _repos) = guard_with(1.0, 0);
        let err = step(&guard).await.unwrap_err();
        assert!(err.to_string().contains("cost cap"), "{err}");
    }

    /// A call with NO provider-reported cost: the table prices it. An
    /// unknown model id gets the deliberately-expensive default, so spend
    /// still accrues (never free).
    #[tokio::test]
    async fn table_prices_a_step_with_no_provider_cost() {
        let usage = Usage { input_tokens: 1_000_000, ..Default::default() };
        let guard = guard_over(Db::fake().repos(), "some/unpriced-model", usage, None, 50_000);
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

    /// Hindsight 1.2.0's counters, as scraped on the jumpbox: one series per
    /// token-count bucket, so a model's total is the sum of its series.
    fn hindsight_metrics(input: [u64; 2], output: u64) -> String {
        format!(
            "# HELP hindsight_llm_tokens_input_tokens_total Number of input tokens for LLM calls\n\
             # TYPE hindsight_llm_tokens_input_tokens_total counter\n\
             hindsight_llm_tokens_input_tokens_total{{model=\"gpt-6.1-sol\",provider=\"openai\",scope=\"retain\",token_bucket=\"0-100\"}} {}\n\
             hindsight_llm_tokens_input_tokens_total{{model=\"gpt-6.1-sol\",provider=\"openai\",scope=\"reflect\",token_bucket=\"1000-10000\"}} {}\n\
             hindsight_llm_tokens_output_tokens_total{{model=\"gpt-6.1-sol\",provider=\"openai\",scope=\"retain\",token_bucket=\"0-10\"}} {output}.0\n\
             hindsight_llm_calls_total{{model=\"gpt-6.1-sol\"}} 3.0\n",
            input[0], input[1]
        )
    }

    #[test]
    fn hindsight_token_counters_are_summed_per_model_and_priced() {
        let table = dcpr_llm::PriceTable::built_in();
        // 1M input over two series, 1M output: $2 + $10.
        let cents =
            cumulative_cost_cents(&hindsight_metrics([400_000, 600_000], 1_000_000), &table);
        assert!((cents - 1200.0).abs() < 1e-6, "{cents}");
        // A model without a price is charged the expensive default, never nothing.
        let unknown = "hindsight_llm_tokens_output_tokens_total{model=\"mystery-9\"} 1000000\n";
        assert_eq!(cumulative_cost_cents(unknown, &table), 1500.0);
        assert_eq!(cumulative_cost_cents("hindsight_llm_calls_total 4\n", &table), 0.0);
    }

    #[test]
    fn a_hindsight_restart_resetting_its_counters_is_still_counted() {
        let day = MeteredDay { today_cents: 10.0, last_cumulative_cents: 50.0 };
        assert_eq!(advance(day, 55.0).today_cents, 15.0, "growth since the last reading");
        // Counters dropped: Hindsight restarted and has counted 3¢ since.
        let after = advance(day, 3.0);
        assert_eq!((after.today_cents, after.last_cumulative_cents), (13.0, 3.0));
    }

    #[tokio::test]
    async fn hindsight_metered_from_metrics_reaches_the_cap_and_survives_a_restart() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metrics"))
            .respond_with(ResponseTemplate::new(200).set_body_string(hindsight_metrics([0, 0], 0)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Later readings: 1M input tokens of gpt-6.1-sol = 200¢ since the first.
        Mock::given(method("GET"))
            .and(path("/metrics"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(hindsight_metrics([1_000_000, 0], 0)),
            )
            .mount(&server)
            .await;
        let url = format!("{}/metrics", server.uri());
        let (guard, repos) = guard_with(1.0, 150);
        let guard = guard.with_hindsight_metrics_meter(url.clone());

        let first = guard.spend_snapshot().await.unwrap();
        assert!(first.complete, "metered, so the cap covers Hindsight");
        assert_eq!(first.hindsight_cents, Some(0.0), "the day starts at the counters' level");

        // A restarted daemon (a new guard over the same store) carries on.
        let restarted = fixed_cost_guard(repos, 1.0, 150).with_hindsight_metrics_meter(url);
        let second = restarted.spend_snapshot().await.unwrap();
        assert_eq!(second.hindsight_cents, Some(200.0));
        let err = step(&restarted).await.unwrap_err();
        assert!(err.to_string().contains("cost cap reached"), "{err}");
    }

    #[tokio::test]
    async fn unreachable_hindsight_metrics_fail_closed() {
        let (guard, _repos) = guard_with(1.0, 500);
        let guard = guard.with_hindsight_metrics_meter("http://127.0.0.1:9/metrics".into());
        assert!(step(&guard).await.is_err(), "no reading, no model call");
    }
}
