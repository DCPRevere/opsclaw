use anyhow::Result;
use zeroclaw::Config;
use zeroclaw_runtime::onboard::wizard::{self as rt_wizard, WizardCallbacks};

pub async fn run_wizard(force: bool) -> Result<Config> {
    Box::pin(rt_wizard::run_wizard(force, WizardCallbacks::default())).await
}

pub async fn run_channels_repair_wizard() -> Result<Config> {
    Box::pin(rt_wizard::run_channels_repair_wizard(
        WizardCallbacks::default(),
    ))
    .await
}

pub async fn run_quick_setup(
    credential_override: Option<&str>,
    provider: Option<&str>,
    model_override: Option<&str>,
    memory_backend: Option<&str>,
    force: bool,
) -> Result<Config> {
    Box::pin(rt_wizard::run_quick_setup(
        credential_override,
        provider,
        model_override,
        memory_backend,
        force,
    ))
    .await
}

pub async fn run_models_refresh(
    config: &Config,
    provider_override: Option<&str>,
    force: bool,
) -> Result<()> {
    rt_wizard::run_models_refresh(config, provider_override, force).await
}

pub async fn run_models_list(config: &Config, provider_override: Option<&str>) -> Result<()> {
    rt_wizard::run_models_list(config, provider_override).await
}

pub async fn run_models_set(config: &Config, model: &str) -> Result<()> {
    Box::pin(rt_wizard::run_models_set(config, model)).await
}

pub async fn run_models_status(config: &Config) -> Result<()> {
    rt_wizard::run_models_status(config).await
}

pub async fn run_models_refresh_all(config: &Config, force: bool) -> Result<()> {
    rt_wizard::run_models_refresh_all(config, force).await
}
