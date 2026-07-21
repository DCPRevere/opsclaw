//! HTTP gateway + embedded web UI (Wave 4 fills routing/auth/UI). Wave 0
//! provides the minimal boot: bind, serve `/ready`, drain on shutdown —
//! enough for the fakes-mode daemon to run end-to-end.

pub mod server;

use std::sync::Arc;

use crate::config::Config;

/// Shared application state. Grows per wave via `with_*` constructors, but is
/// always constructible from bare config (the fakes spine).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        if config.fully_faked() {
            tracing::warn!(
                "fakes mode: no credentials configured — every external dependency is an in-process fake"
            );
        }
        AppState { config: Arc::new(config) }
    }
}
