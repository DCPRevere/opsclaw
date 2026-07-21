//! A fallback chain of LLM providers. Ported from gianna's
//! `src/llm_providers/fallback.rs`.
//!
//! Tries providers in order. For each provider, retries transient failures
//! (429/5xx/timeout) up to `MAX_RETRIES` times on the SAME provider with
//! jittered exponential backoff (honouring `Retry-After` when the provider
//! supplies one, capped at 30s); on a hard failure (401/400/model-not-found)
//! or exhausted retries, falls through to the next provider. A context-window
//! overflow fails FAST — no retry, no fallthrough, since the same oversized
//! prompt would 400 on every provider in the chain. Errors only when every
//! provider is exhausted.
//!
//! Implements [`LlmProvider`], so it's a drop-in replacement for a single
//! provider — including wrapping a single provider, to get the retry/backoff
//! behaviour uniformly.

use async_trait::async_trait;
use rand::RngExt;
use std::sync::Arc;

use crate::domain::Principal;
use crate::llm::{ChatStep, LlmProvider, ToolSpec, Turn};
use crate::{Error, Result};

/// Retry budget for transient failures, applied per provider.
const MAX_RETRIES: u32 = 3;
/// Base backoff between retries; the exponential ceiling is doubled each
/// attempt and the actual sleep is a full-jittered draw within it. Rate
/// limits (429/529) almost never clear sub-second, so the base is
/// seconds-scale.
const BASE_DELAY_MS: u64 = 1000;
/// Cap on any single backoff sleep, so an honest-but-generous `Retry-After`
/// (or a high exponential draw) can't hang a turn for minutes.
const MAX_DELAY_MS: u64 = 30_000;

/// The backoff for one retry: honour the provider's `Retry-After` when
/// present (capped), otherwise an exponentially-growing window with FULL
/// jitter (a uniform draw in `[0, exp_ceiling]`), which de-correlates
/// concurrent retries. `attempt` is 1-based (the delay before the 1st retry).
fn backoff_delay_ms(attempt: u32, retry_after_secs: Option<u64>) -> u64 {
    if let Some(secs) = retry_after_secs {
        return (secs.saturating_mul(1000)).min(MAX_DELAY_MS);
    }
    let ceiling = BASE_DELAY_MS.saturating_mul(1u64 << (attempt - 1)).min(MAX_DELAY_MS);
    rand::rng().random_range(0..=ceiling)
}

pub struct FallbackLlm {
    chain: Vec<Arc<dyn LlmProvider>>,
    /// When true, sleeps between retries; tests disable this for speed.
    sleep_between_retries: bool,
}

impl FallbackLlm {
    /// Wrap a provider chain, in try order. A single-provider chain is a
    /// valid (and the shipped-default) input — wrapping even one provider
    /// still buys the retry/backoff behaviour.
    pub fn new(chain: Vec<Arc<dyn LlmProvider>>) -> Self {
        Self { chain, sleep_between_retries: true }
    }

    #[cfg(test)]
    fn no_sleep(mut self) -> Self {
        self.sleep_between_retries = false;
        self
    }
}

#[async_trait]
impl LlmProvider for FallbackLlm {
    fn name(&self) -> &str {
        self.chain.first().map(|p| p.name()).unwrap_or("fallback-empty")
    }

    async fn chat_step(
        &self,
        principal: &Principal,
        system: &str,
        history: &[Turn],
        tools: &[ToolSpec],
    ) -> Result<ChatStep> {
        let mut last_err: Option<Error> = None;
        for provider in &self.chain {
            let mut attempt = 0;
            loop {
                match provider.chat_step(principal, system, history, tools).await {
                    Ok(v) => return Ok(v),
                    // A context-window overflow is not a provider fault — the
                    // SAME oversized prompt would 400 on every model in the
                    // chain, so burning transient retries or falling through
                    // to the next provider is pure waste. Fail fast to the
                    // caller.
                    Err(e) if e.is_context_overflow() => {
                        tracing::warn!(
                            provider = provider.name(),
                            "LLM context overflow — failing fast (no retry, no fallthrough): {e}"
                        );
                        return Err(e);
                    }
                    Err(e) if e.is_retryable() && attempt < MAX_RETRIES => {
                        attempt += 1;
                        let retry_after = e.llm_retry_after_secs();
                        let delay = backoff_delay_ms(attempt, retry_after);
                        if self.sleep_between_retries {
                            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        }
                        tracing::warn!(
                            provider = provider.name(),
                            attempt,
                            delay_ms = delay,
                            retry_after_secs = retry_after,
                            "LLM transient failure, retrying: {e}"
                        );
                    }
                    Err(e) => {
                        // Hard failure or retries exhausted -> next provider.
                        tracing::warn!(
                            provider = provider.name(),
                            "LLM failure, falling through to next provider: {e}"
                        );
                        last_err = Some(e);
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::llm_hard("no LLM providers configured")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn principal() -> Principal {
        Principal::System
    }

    /// A test provider that fails a configured number of times (transient or
    /// hard) before succeeding, counting every call.
    struct Stub {
        id: String,
        calls: Arc<AtomicU32>,
        fail_times: u32,
        retryable: bool,
        succeeds_eventually: bool,
    }

    #[async_trait]
    impl LlmProvider for Stub {
        async fn chat_step(
            &self,
            _p: &Principal,
            _s: &str,
            _h: &[Turn],
            _t: &[ToolSpec],
        ) -> Result<ChatStep> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                return Err(if self.retryable {
                    Error::llm_transient(format!("{} transient", self.id))
                } else {
                    Error::llm_hard(format!("{} hard", self.id))
                });
            }
            if self.succeeds_eventually {
                Ok(ChatStep {
                    text: Some("ok".into()),
                    tool_calls: Vec::new(),
                    usage: Default::default(),
                })
            } else {
                Err(Error::llm_hard("never succeeds"))
            }
        }
        fn name(&self) -> &str {
            &self.id
        }
    }

    fn counter() -> Arc<AtomicU32> {
        Arc::new(AtomicU32::new(0))
    }

    #[test]
    fn retry_after_wins_over_exponential_backoff_and_is_capped() {
        assert_eq!(backoff_delay_ms(1, Some(3)), 3_000);
        assert_eq!(backoff_delay_ms(1, Some(600)), MAX_DELAY_MS);
    }

    #[test]
    fn jittered_backoff_stays_within_the_exponential_ceiling() {
        for attempt in 1..=6 {
            let ceiling = (BASE_DELAY_MS * (1u64 << (attempt - 1))).min(MAX_DELAY_MS);
            for _ in 0..100 {
                let d = backoff_delay_ms(attempt, None);
                assert!(d <= ceiling, "attempt {attempt}: {d} exceeds ceiling {ceiling}");
                assert!(d <= MAX_DELAY_MS, "attempt {attempt}: {d} exceeds MAX_DELAY_MS");
            }
        }
        const _: () = assert!(BASE_DELAY_MS >= 1000);
    }

    #[tokio::test]
    async fn retries_transient_then_succeeds_on_same_provider() {
        let c = counter();
        let p = Arc::new(Stub {
            id: "p1".into(),
            calls: c.clone(),
            fail_times: 2,
            retryable: true,
            succeeds_eventually: true,
        });
        let f = FallbackLlm::new(vec![p]).no_sleep();
        let r = f.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        assert_eq!(r.text.as_deref(), Some("ok"));
        // 2 transient failures + 1 success = 3 calls (within MAX_RETRIES).
        assert_eq!(c.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn hard_failure_falls_through_immediately() {
        let c1 = counter();
        let c2 = counter();
        let p1 = Arc::new(Stub {
            id: "p1".into(),
            calls: c1.clone(),
            fail_times: 1,
            retryable: false, // hard -> no retry, fall through
            succeeds_eventually: true,
        });
        let p2 = Arc::new(Stub {
            id: "p2".into(),
            calls: c2.clone(),
            fail_times: 0,
            retryable: true,
            succeeds_eventually: true,
        });
        let f = FallbackLlm::new(vec![p1, p2]).no_sleep();
        f.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exhausted_transient_falls_through_to_next() {
        let c1 = counter();
        let c2 = counter();
        let p1 = Arc::new(Stub {
            id: "p1".into(),
            calls: c1.clone(),
            fail_times: 99, // always transient-fails
            retryable: true,
            succeeds_eventually: false,
        });
        let p2 = Arc::new(Stub {
            id: "p2".into(),
            calls: c2.clone(),
            fail_times: 0,
            retryable: true,
            succeeds_eventually: true,
        });
        let f = FallbackLlm::new(vec![p1, p2]).no_sleep();
        f.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        // p1: 1 initial + MAX_RETRIES retries, then fall through to p2.
        assert_eq!(c1.load(Ordering::SeqCst), 1 + MAX_RETRIES);
        assert_eq!(c2.load(Ordering::SeqCst), 1);
    }

    /// A context-overflow error fails FAST: the first provider returns it and
    /// the chain neither retries that provider nor falls through to the next
    /// one (the same oversized prompt would 400 everywhere). The second
    /// provider is never touched, and the caller gets the overflow error.
    #[tokio::test]
    async fn context_overflow_fails_fast_without_fallthrough() {
        struct Overflow {
            id: String,
            calls: Arc<AtomicU32>,
        }
        #[async_trait]
        impl LlmProvider for Overflow {
            async fn chat_step(
                &self,
                _p: &Principal,
                _s: &str,
                _h: &[Turn],
                _t: &[ToolSpec],
            ) -> Result<ChatStep> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(Error::from_llm_status(400, "maximum context length is 8192 tokens", None))
            }
            fn name(&self) -> &str {
                &self.id
            }
        }
        let c1 = counter();
        let c2 = counter();
        let p1 = Arc::new(Overflow { id: "p1".into(), calls: c1.clone() });
        let p2 = Arc::new(Stub {
            id: "p2".into(),
            calls: c2.clone(),
            fail_times: 0,
            retryable: true,
            succeeds_eventually: true,
        });
        let f = FallbackLlm::new(vec![p1, p2]).no_sleep();
        let err = f.chat_step(&principal(), "sys", &[], &[]).await.unwrap_err();
        assert!(err.is_context_overflow(), "caller gets the overflow error: {err}");
        assert_eq!(c1.load(Ordering::SeqCst), 1, "no retries against the same prompt");
        assert_eq!(c2.load(Ordering::SeqCst), 0, "no fallthrough to the next provider");
    }

    #[tokio::test]
    async fn errors_only_when_all_exhausted() {
        let p1 = Arc::new(Stub {
            id: "p1".into(),
            calls: counter(),
            fail_times: 99,
            retryable: false,
            succeeds_eventually: false,
        });
        let p2 = Arc::new(Stub {
            id: "p2".into(),
            calls: counter(),
            fail_times: 99,
            retryable: false,
            succeeds_eventually: false,
        });
        let f = FallbackLlm::new(vec![p1, p2]).no_sleep();
        assert!(f.chat_step(&principal(), "sys", &[], &[]).await.is_err());
    }

    #[tokio::test]
    async fn single_provider_chain_still_gets_retry_wrapping() {
        // "Wrap-even-single-provider" stance: a one-provider chain still
        // retries transient failures rather than surfacing them immediately.
        let c = counter();
        let p = Arc::new(Stub {
            id: "solo".into(),
            calls: c.clone(),
            fail_times: 1,
            retryable: true,
            succeeds_eventually: true,
        });
        let f = FallbackLlm::new(vec![p]).no_sleep();
        f.chat_step(&principal(), "sys", &[], &[]).await.unwrap();
        assert_eq!(c.load(Ordering::SeqCst), 2, "one retry happened on the sole provider");
    }
}
