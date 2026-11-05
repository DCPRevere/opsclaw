//! Local spend/cap status over the durable OpsClaw ledger plus, for the
//! standard OpenRouter-backed Hindsight install, the provider's daily key
//! usage. Values are cents throughout.

use crate::llm::hindsight_metrics_url;
use std::sync::Arc;

use crate::Result;
use crate::config::{Config, SecretStore};
use crate::db::AllRepos;
use crate::llm::{CostGuard, FakeLlm, SpendMeter, SpendSnapshot};

pub async fn load(
    config: &Config,
    store: &SecretStore,
    repos: Arc<dyn AllRepos>,
) -> Result<SpendSnapshot> {
    let opsclaw_key = match &config.llm.api_key {
        Some(reference) => Some(reference.resolve(store)?),
        None => None,
    };
    let mut guard = CostGuard::new(
        Arc::new(FakeLlm::new()),
        Arc::new(SpendMeter::new()),
        repos,
        config.limits.max_cost_per_day_cents,
    );
    if config.memory.hindsight_url.is_some() {
        let key =
            std::env::var("HINDSIGHT_LLM_API_KEY").ok().filter(|value| !value.trim().is_empty());
        let base = std::env::var("HINDSIGHT_LLM_BASE_URL").unwrap_or_default();
        guard = match key {
            Some(key) if base.contains("openrouter.ai") => {
                let shared = opsclaw_key.as_deref() == Some(key.as_str());
                guard.with_hindsight_openrouter_meter(key, shared)
            }
            // Any other Hindsight LLM (OpenAI direct, say): meter it from
            // Hindsight's own token counters.
            _ => guard.with_hindsight_metrics_meter(hindsight_metrics_url(&config.memory)),
        };
    }
    guard.spend_snapshot().await
}

pub fn render(snapshot: &SpendSnapshot) -> String {
    let hindsight = snapshot
        .hindsight_cents
        .map(|value| format!("{value:.1}¢"))
        .unwrap_or_else(|| "unmetered".into());
    format!(
        "UTC day: {}\nOpsClaw: {:.1}¢\nHindsight: {}\nTotal: {:.1}¢ / {:.0}¢\nRemaining: {:.1}¢\nCoverage: {}\n",
        snapshot.day_utc,
        snapshot.opsclaw_cents,
        hindsight,
        snapshot.total_cents,
        snapshot.cap_cents,
        snapshot.remaining_cents,
        if snapshot.complete { "complete" } else { "OpsClaw only" },
    )
}
