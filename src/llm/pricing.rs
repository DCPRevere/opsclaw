//! Pricing for the daily spend cap.
//!
//! A provider's reported cost always wins (OpenRouter reports one). For
//! providers that don't report cost, such as OpenAI direct, `dcpr-llm`'s
//! [`PricedUsage`] prices each call from its built-in list prices
//! ([`PriceTable::built_in`]) before it reaches the [`SpendMeter`].
//!
//! OpsClaw adds one rule of its own: a model with no price at all is charged
//! at [`UNKNOWN_MODEL_PRICE`], never treated as free. An unpriced call
//! silently costing nothing would let the daily cap be blown by a routing
//! change or a model added without a price.
//!
//! [`SpendMeter`]: crate::llm::SpendMeter

use std::sync::Arc;

use dcpr_llm::{ModelPrice, PriceTable, PricedUsage, Usage, UsageSink};

use crate::domain::Principal;

/// Sonnet-class list prices, deliberately expensive: an unknown model costs
/// about 300 times a cheap production model, so it reaches the cap loudly
/// instead of passing unmetered.
pub const UNKNOWN_MODEL_PRICE: ModelPrice = ModelPrice::new(300.0, 1500.0);

/// The usage sink the shipped chain reports to: list prices for anything the
/// provider didn't price, then `meter`.
pub fn priced(meter: Arc<dyn UsageSink<Principal>>) -> Arc<dyn UsageSink<Principal>> {
    Arc::new(PricedUsage::new(meter, PriceTable::built_in()))
}

/// The cost of one call in cents: the reported or table price when there is
/// one, otherwise [`UNKNOWN_MODEL_PRICE`].
pub fn call_cost_cents(usage: &Usage, model: &str, priced_cents: Option<f64>) -> f64 {
    priced_cents.unwrap_or_else(|| {
        // PricedUsage has already warned once for this model.
        tracing::debug!(model, "unpriced call charged at the unknown-model default");
        UNKNOWN_MODEL_PRICE.cost_cents(usage)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records what reaches the meter.
    #[derive(Default)]
    struct Seen(Mutex<Vec<(String, Option<f64>)>>);
    impl UsageSink<Principal> for Seen {
        fn record(&self, _: &Principal, model: &str, _: Usage, cents: Option<f64>) {
            self.0.lock().unwrap().push((model.to_string(), cents));
        }
    }

    fn million_in_and_out() -> Usage {
        Usage { input_tokens: 1_000_000, output_tokens: 1_000_000, ..Default::default() }
    }

    #[test]
    fn openai_calls_are_priced_from_the_library_table() {
        let seen = Arc::new(Seen::default());
        let sink = priced(seen.clone());
        let caller = Principal::Agent { job: None };
        sink.record(&caller, "gpt-6.1-sol", million_in_and_out(), None);
        sink.record(&caller, "openai/gpt-6.1-sol", million_in_and_out(), Some(7.0));
        sink.record(&caller, "some/never-seen-model", million_in_and_out(), None);
        let seen = seen.0.lock().unwrap();
        // $2 in + $10 out per million tokens.
        assert_eq!(seen[0].1, Some(1200.0));
        assert_eq!(seen[1].1, Some(7.0), "a reported cost is never overridden");
        assert_eq!(seen[2].1, None, "no price: the meter decides");
    }

    #[test]
    fn an_unpriced_model_is_charged_the_expensive_default_never_nothing() {
        let usage = million_in_and_out();
        assert_eq!(call_cost_cents(&usage, "some/never-seen-model", None), 1800.0);
        assert_eq!(call_cost_cents(&usage, "gpt-6.1-sol", Some(1200.0)), 1200.0);
    }
}
