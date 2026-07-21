//! Per-model price table and usage recording. Ported from gianna's
//! `src/usage.rs` (pricing table + provider-cost-wins logic only — the
//! household/cap/PostHog accounting machinery is NOT ported; DB wiring for
//! opsclaw's usage sink happens in a later wave).

use crate::llm::TokenUsage;

/// Price per 1M tokens, in USD cents, for a model.
#[derive(Debug, Clone, Copy)]
pub struct ModelPrice {
    pub input_cents_per_mtok: f64,
    pub output_cents_per_mtok: f64,
}

/// The mid-tier default applied to an unrecognised model id (~Sonnet-class).
/// Public so callers/tests can compare against it (an unknown id priced here is
/// ~300x a cheap prod model and would blow through `limits.max_cost_per_day_cents`
/// within a few turns — deliberately expensive so a routing/rename event is
/// loud, not free).
pub const UNKNOWN_MODEL_PRICE: ModelPrice =
    ModelPrice { input_cents_per_mtok: 300.0, output_cents_per_mtok: 1500.0 };

/// True when `price_for(model)` fell through to [`UNKNOWN_MODEL_PRICE`] — i.e.
/// the table has no row for this id, so its cost is a guess.
pub fn is_unknown_model(model: &str) -> bool {
    let p = price_for(model);
    p.input_cents_per_mtok == UNKNOWN_MODEL_PRICE.input_cents_per_mtok
        && p.output_cents_per_mtok == UNKNOWN_MODEL_PRICE.output_cents_per_mtok
}

/// Look up pricing for a model id. Falls back to a conservative default so an
/// unknown model still accrues *some* cost rather than appearing free.
pub fn price_for(model: &str) -> ModelPrice {
    // USD cents per 1M tokens (1 USD = 100 cents). Anthropic public pricing.
    match model {
        m if m.contains("opus") => {
            ModelPrice { input_cents_per_mtok: 500.0, output_cents_per_mtok: 2500.0 }
        }
        m if m.contains("sonnet") => {
            ModelPrice { input_cents_per_mtok: 300.0, output_cents_per_mtok: 1500.0 }
        }
        m if m.contains("haiku") => {
            ModelPrice { input_cents_per_mtok: 100.0, output_cents_per_mtok: 500.0 }
        }
        // OpenAI (approximate public pricing).
        m if m.contains("gpt-4o-mini") => {
            ModelPrice { input_cents_per_mtok: 15.0, output_cents_per_mtok: 60.0 }
        }
        m if m.contains("gpt-4o") => {
            ModelPrice { input_cents_per_mtok: 250.0, output_cents_per_mtok: 1000.0 }
        }
        m if m.contains("gpt-4") => {
            ModelPrice { input_cents_per_mtok: 300.0, output_cents_per_mtok: 1500.0 }
        }
        // OpenRouter cheap models (public pricing, 2026-06; c per 1M tokens).
        m if m.contains("deepseek-v4-flash") => {
            ModelPrice { input_cents_per_mtok: 0.983, output_cents_per_mtok: 1.966 }
        }
        m if m.contains("deepseek-v4-pro") => {
            ModelPrice { input_cents_per_mtok: 4.35, output_cents_per_mtok: 8.7 }
        }
        m if m.contains("minimax-m3") => {
            ModelPrice { input_cents_per_mtok: 30.0, output_cents_per_mtok: 120.0 }
        }
        m if m.contains("qwen3-235b-a22b") => {
            ModelPrice { input_cents_per_mtok: 9.0, output_cents_per_mtok: 10.0 }
        }
        m if m.contains("llama-3.3-70b") => {
            ModelPrice { input_cents_per_mtok: 10.0, output_cents_per_mtok: 32.0 }
        }
        m if m.contains("mistral-small-3.2") => {
            ModelPrice { input_cents_per_mtok: 7.5, output_cents_per_mtok: 20.0 }
        }
        m if m.contains("gemma-3-27b") => {
            ModelPrice { input_cents_per_mtok: 8.0, output_cents_per_mtok: 16.0 }
        }
        m if m.contains("gpt-oss-120b") => {
            ModelPrice { input_cents_per_mtok: 3.9, output_cents_per_mtok: 18.0 }
        }
        // Unknown — assume mid-tier so we don't undercount.
        _ => UNKNOWN_MODEL_PRICE,
    }
}

/// Model ids already WARNed about as unknown, so the log fires once per id (not
/// once per call). A routing/rename event or a model added to the chain
/// without a price row is a real spend hazard — see [`warn_if_unknown_model`].
static WARNED_UNKNOWN_MODELS: std::sync::Mutex<Option<std::collections::HashSet<String>>> =
    std::sync::Mutex::new(None);

/// WARN once per model id when the unknown-model default is about to price a
/// call. The default is ~300x a cheap prod model and feeds `max_cost_per_day_cents`
/// enforcement, so an unrecognised id silently throttling the daemon must be
/// visible in prod immediately.
fn warn_if_unknown_model(model: &str) {
    if !is_unknown_model(model) {
        return;
    }
    let mut guard = WARNED_UNKNOWN_MODELS.lock().unwrap_or_else(|p| p.into_inner());
    let seen = guard.get_or_insert_with(std::collections::HashSet::new);
    if seen.insert(model.to_string()) {
        tracing::warn!(
            model,
            "unknown model id priced at the mid-tier DEFAULT (~300x a cheap prod \
             model) — cost for this id is a guess; add a price row or check for \
             an OpenRouter routing/rename event"
        );
    }
}

/// The cached-read discount vs the full input rate. Anthropic charges cache
/// reads at 0.1x input; OpenAI/DeepSeek land near 0.1-0.25x. 0.1 is the
/// standard (and slightly conservative-high vs some providers).
const CACHE_READ_RATE_FRACTION: f64 = 0.1;

/// Cost of a token usage record in USD cents (fractional), given the model's
/// price table row. `cache_read_tokens` is priced at the discounted rate and
/// is DISJOINT from `input_tokens` (providers report the uncached remainder
/// there).
pub fn cost_cents(
    input_tokens: u64,
    cache_read_tokens: u64,
    output_tokens: u64,
    model: &str,
) -> f64 {
    let p = price_for(model);
    let input = input_tokens as f64 / 1_000_000.0;
    let cached = cache_read_tokens as f64 / 1_000_000.0;
    let output = output_tokens as f64 / 1_000_000.0;
    input * p.input_cents_per_mtok
        + cached * p.input_cents_per_mtok * CACHE_READ_RATE_FRACTION
        + output * p.output_cents_per_mtok
}

/// Fill in `usage.cost_cents` when a provider hasn't already supplied one
/// (OpenRouter's `usage.cost` is provider-truth and wins; see the
/// OpenAiCompatProvider quirks). WARNs once per unknown model id actually
/// priced from the table.
pub fn price_usage(usage: &mut TokenUsage, model: &str) {
    if usage.cost_cents.is_some() {
        return;
    }
    warn_if_unknown_model(model);
    usage.cost_cents = Some(cost_cents(usage.input_tokens, 0, usage.output_tokens, model));
}

/// Fire-and-forget usage recording sink. DB-backed persistence lands in a
/// later wave; for now this is the seam a real recorder plugs into.
pub trait UsageSink: Send + Sync {
    /// Record one costed LLM call. Must not block the caller — implementations
    /// that need IO should spawn it.
    fn record(&self, principal: &crate::domain::Principal, model: &str, usage: TokenUsage);
}

/// No-op sink — the default until DB wiring lands.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopUsageSink;

impl UsageSink for NoopUsageSink {
    fn record(&self, _principal: &crate::domain::Principal, _model: &str, _usage: TokenUsage) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_is_priced_per_model() {
        // Sonnet: 300c in + 1500c out = 1800c for 1M+1M.
        let c = cost_cents(1_000_000, 0, 1_000_000, "claude-sonnet-4-6");
        assert!((c - 1800.0).abs() < 0.01, "got {c}");
        // Opus is pricier.
        assert!(cost_cents(1_000_000, 0, 1_000_000, "claude-opus-4-8") > c);
    }

    #[test]
    fn cache_reads_are_priced_below_input_and_are_disjoint() {
        // 1M uncached input + 1M cached reads on Haiku (input 100c/Mtok).
        let c = cost_cents(1_000_000, 1_000_000, 0, "claude-haiku-4-5");
        let full = 100.0 + 100.0; // if cached were charged at the input rate
        assert!(c < full, "cached reads must be discounted: {c} !< {full}");
        // 100c input + 100c * 0.1 cached = 110c.
        assert!((c - 110.0).abs() < 0.01, "got {c}");
    }

    #[test]
    fn unknown_model_is_detected_and_priced_at_the_default() {
        assert!(is_unknown_model("some/never-seen-model"));
        assert!(!is_unknown_model("deepseek-v4-flash"));
        let p = price_for("some/never-seen-model");
        assert_eq!(p.input_cents_per_mtok, UNKNOWN_MODEL_PRICE.input_cents_per_mtok);
        assert_eq!(p.output_cents_per_mtok, UNKNOWN_MODEL_PRICE.output_cents_per_mtok);
    }

    #[test]
    fn price_usage_fills_cost_from_the_table_when_absent() {
        let mut usage = TokenUsage { input_tokens: 1_000_000, output_tokens: 0, cost_cents: None };
        price_usage(&mut usage, "claude-haiku-4-5");
        assert_eq!(usage.cost_cents, Some(100.0));
    }

    #[test]
    fn price_usage_never_overrides_a_provider_reported_cost() {
        // Table would price Haiku's 1M input at 100c; provider says 3.5c.
        let mut usage =
            TokenUsage { input_tokens: 1_000_000, output_tokens: 0, cost_cents: Some(3.5) };
        price_usage(&mut usage, "claude-haiku-4-5");
        assert_eq!(usage.cost_cents, Some(3.5), "provider cost must win");
    }

    #[test]
    fn noop_sink_does_not_panic() {
        let sink = NoopUsageSink;
        sink.record(
            &crate::domain::Principal::System,
            "claude-haiku-4-5",
            TokenUsage { input_tokens: 1, output_tokens: 1, cost_cents: Some(0.1) },
        );
    }
}
