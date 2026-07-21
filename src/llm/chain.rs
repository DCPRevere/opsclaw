//! Build the shipped [`LlmProvider`] from config (DESIGN §7 #13): OpenRouter
//! only, via [`OpenAiCompatProvider`], with `cfg.models` as its server-side
//! ordered fallback list, wrapped in [`FallbackLlm`] for retry/backoff.
//!
//! Falls back to [`FakeLlm`] (with a loud `tracing::warn!`) when no API key
//! is configured — the fakes-mode daemon must still boot and self-validate.

use std::sync::Arc;

use crate::Result;
use crate::config::{LlmCfg, SecretStore};
use crate::llm::{FakeLlm, FallbackLlm, LlmProvider, OpenAiCompatProvider};

const DEFAULT_OPENROUTER_BASE_URL: &str = "https://openrouter.ai/api/v1";

/// Resolve `cfg` into the provider the daemon actually talks to.
///
/// - No `api_key` configured -> [`FakeLlm`], loudly logged (never a silent
///   fallback — an operator staring at "why is nothing happening" needs this
///   in the log, not just in a debug flag).
/// - `api_key` configured -> [`OpenAiCompatProvider`] pointed at
///   `cfg.base_url` (default: OpenRouter), using `cfg.models[0]` as the
///   primary model and the rest as OpenRouter's server-side fallback list,
///   wrapped in [`FallbackLlm`] for client-side retry/backoff.
///
/// `cfg.models` being non-empty when `api_key` is set is enforced by
/// [`crate::config::Config::validate`] before boot — this function trusts
/// that invariant and would build a provider with an empty model string
/// otherwise (validate() is the gate, not this function).
pub fn build_chain(cfg: &LlmCfg, store: &SecretStore) -> Result<Arc<dyn LlmProvider>> {
    let Some(api_key_ref) = &cfg.api_key else {
        tracing::warn!(
            "no llm.api_key configured — using FakeLlm (a clearly-logged fake, \
             zero network calls, canned no-tool replies only). Set llm.api_key \
             (or OPENROUTER_API_KEY) to use a real model."
        );
        return Ok(Arc::new(FallbackLlm::new(vec![Arc::new(FakeLlm::new())])));
    };
    let api_key = api_key_ref.resolve(store)?;
    let base_url = cfg.base_url.clone().unwrap_or_else(|| DEFAULT_OPENROUTER_BASE_URL.to_string());
    let (primary, fallbacks) = cfg.models.split_first().ok_or_else(|| {
        crate::Error::Config(
            "llm.api_key is set but llm.models is empty (should have been caught by \
             Config::validate)"
                .into(),
        )
    })?;
    let provider = OpenAiCompatProvider::new(base_url, api_key, primary.clone())
        .with_fallback_models(fallbacks.to_vec())
        .with_referer("https://opsclaw.dev");
    Ok(Arc::new(FallbackLlm::new(vec![Arc::new(provider)])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretRef;
    use std::sync::Mutex;

    // Env vars are process-global; serialize the two tests that touch
    // OPENROUTER-adjacent env state so they can't interleave (hermetic per
    // the port brief).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn no_api_key_selects_fake_llm() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        let cfg = LlmCfg::default();
        let provider = build_chain(&cfg, &store).unwrap();
        assert_eq!(provider.name(), "fake");
    }

    #[test]
    fn api_key_with_models_selects_openai_compat_wrapped_in_fallback() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("OPSCLAW_TEST_CHAIN_KEY", "sk-test-123") };
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        let cfg = LlmCfg {
            api_key: Some(SecretRef::env("OPSCLAW_TEST_CHAIN_KEY")),
            models: vec!["vendor/primary".into(), "vendor/backup".into()],
            base_url: None,
        };
        let provider = build_chain(&cfg, &store).unwrap();
        // FallbackLlm::name() delegates to the first (only) chain member,
        // which reports the primary model id.
        assert_eq!(provider.name(), "vendor/primary");
        unsafe { std::env::remove_var("OPSCLAW_TEST_CHAIN_KEY") };
    }

    #[test]
    fn missing_secret_value_is_a_config_error_not_a_panic() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        let cfg = LlmCfg {
            api_key: Some(SecretRef::env("OPSCLAW_TEST_CHAIN_KEY_DEFINITELY_UNSET")),
            models: vec!["vendor/primary".into()],
            base_url: None,
        };
        let err = match build_chain(&cfg, &store) {
            Err(e) => e,
            Ok(_) => panic!("expected a config error for an unresolvable secret"),
        };
        assert!(err.to_string().contains("not set"), "{err}");
    }

    #[test]
    fn custom_base_url_is_honoured() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("OPSCLAW_TEST_CHAIN_KEY2", "sk-test-456") };
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        let cfg = LlmCfg {
            api_key: Some(SecretRef::env("OPSCLAW_TEST_CHAIN_KEY2")),
            models: vec!["local/model".into()],
            base_url: Some("http://localhost:11434/v1".into()),
        };
        // No direct getter for base_url on the built provider; this test
        // exercises the path compiles and selects OpenAiCompatProvider (not
        // FakeLlm) without panicking on the override.
        let provider = build_chain(&cfg, &store).unwrap();
        assert_eq!(provider.name(), "local/model");
        unsafe { std::env::remove_var("OPSCLAW_TEST_CHAIN_KEY2") };
    }
}
