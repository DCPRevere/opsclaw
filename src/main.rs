//! The opsclaw daemon binary. All real composition lives in `opsclaw::boot`
//! — shared with `opsclaw-cli daemon` so the two boot paths cannot drift.

use opsclaw::config::{Config, default_config_path, default_dir};
use opsclaw::http::server;

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

    let state =
        match opsclaw::boot::daemon_state(config, default_config_path(), &default_dir()).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("opsclaw: refusing to start (wiring): {e}");
                std::process::exit(2);
            }
        };

    if let Err(e) = opsclaw::boot::seed_scan_jobs(&state).await {
        eprintln!("opsclaw: seeding scan jobs failed: {e}");
        std::process::exit(1);
    }

    if let Err(e) = server::run(state).await {
        eprintln!("opsclaw: {e}");
        std::process::exit(1);
    }
}
