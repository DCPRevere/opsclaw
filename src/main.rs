//! The opsclaw daemon binary.

use opsclaw::config::Config;
use opsclaw::http::{AppState, server};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "opsclaw=info,info".into()),
        )
        .init();

    let config = match Config::load(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("opsclaw: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = config.validate() {
        eprintln!("opsclaw: refusing to start:\n{e}");
        std::process::exit(2);
    }

    if let Err(e) = server::run(AppState::new(config)).await {
        eprintln!("opsclaw: {e}");
        std::process::exit(1);
    }
}
