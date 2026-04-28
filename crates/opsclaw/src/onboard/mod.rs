//! Thin adapter from opsclaw's onboard CLI surface to the upstream
//! schema-driven onboarding orchestrator.
//!
//! Upstream replaced the per-step `run_*_wizard` functions with a single
//! `onboard::run(cfg, ui, Section, Flags)` dispatcher (RFC #5951).
//! opsclaw's CLI still exposes the older verbs (`onboard`,
//! `onboard --quick`, `onboard --channels-only`, `models *`); these
//! adapters keep the old surface stable while delegating to the new core.

use anyhow::Result;
use zeroclaw::Config;
use zeroclaw_runtime::doctor;
use zeroclaw_runtime::onboard::ui::{QuickUi, TermUi};
use zeroclaw_runtime::onboard::{Flags, Section, run as run_section};

pub async fn run_wizard(force: bool) -> Result<Config> {
    let mut cfg = Box::pin(Config::load_or_init()).await?;
    cfg.apply_env_overrides();
    let flags = Flags {
        force,
        ..Flags::default()
    };
    let mut ui = TermUi;
    run_section(&mut cfg, &mut ui, Section::All, &flags).await?;
    Ok(cfg)
}

pub async fn run_channels_repair_wizard() -> Result<Config> {
    let mut cfg = Box::pin(Config::load_or_init()).await?;
    cfg.apply_env_overrides();
    let flags = Flags::default();
    let mut ui = TermUi;
    run_section(&mut cfg, &mut ui, Section::Channels, &flags).await?;
    Ok(cfg)
}

pub async fn run_quick_setup(
    credential_override: Option<&str>,
    provider: Option<&str>,
    model_override: Option<&str>,
    memory_backend: Option<&str>,
    force: bool,
) -> Result<Config> {
    let mut cfg = Box::pin(Config::load_or_init()).await?;
    cfg.apply_env_overrides();
    let flags = Flags {
        force,
        api_key: credential_override.map(str::to_string),
        provider: provider.map(str::to_string),
        model: model_override.map(str::to_string),
        memory: memory_backend.map(str::to_string),
        ..Flags::default()
    };
    let mut ui = QuickUi::new();
    run_section(&mut cfg, &mut ui, Section::All, &flags).await?;
    Ok(cfg)
}

pub async fn run_models_refresh(
    config: &Config,
    provider_override: Option<&str>,
    _force: bool,
) -> Result<()> {
    doctor::run_models(config, provider_override, false).await
}

pub async fn run_models_list(config: &Config, provider_override: Option<&str>) -> Result<()> {
    doctor::run_models(config, provider_override, true).await
}

pub async fn run_models_set(_config: &Config, model: &str) -> Result<()> {
    anyhow::bail!(
        "`opsclaw models set` is no longer supported — set the model in your config or via \
         `opsclaw onboard providers`. (requested: {model})"
    )
}

pub async fn run_models_status(config: &Config) -> Result<()> {
    doctor::run_models(config, None, true).await
}

pub async fn run_models_refresh_all(config: &Config, _force: bool) -> Result<()> {
    doctor::run_models(config, None, false).await
}
