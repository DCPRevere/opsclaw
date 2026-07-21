//! The opsclaw daemon binary.

use std::sync::Arc;

use opsclaw::audit::AuditWriter;
use opsclaw::config::{Config, SecretStore, default_dir};
use opsclaw::db::Db;
use opsclaw::http::{AppState, server};
use opsclaw::policy::{EStop, Policy, Scrubber};
use opsclaw::scheduler::SchedulerHandle;

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

    let secret_dir = default_dir();
    let secret_store = match SecretStore::open(&secret_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("opsclaw: cannot open secret store: {e}");
            std::process::exit(2);
        }
    };

    let db_path = config
        .daemon
        .db_path
        .clone()
        .unwrap_or_else(|| secret_dir.join("opsclaw.sqlite3"))
        .to_string_lossy()
        .into_owned();
    let db = match Db::connect(&db_path).await {
        Ok(db) => db,
        Err(e) => {
            eprintln!("opsclaw: database connect failed: {e}");
            std::process::exit(1);
        }
    };
    let repos = db.repos();

    // TargetExecutor construction from `config.projects[].envs[].targets[]`
    // (resolving each target's credential through the secret store and
    // registering it with the scrubber) is Wave 2/3 integration work with
    // real credential-handling stakes — left for main-session wiring rather
    // than invented here. Until then the daemon boots with an EMPTY
    // executor map, which is the safe direction: `Policy::execute` already
    // treats an unregistered target as unreachable (no executor => no
    // command can run against it), so this is fail-closed, not fail-open.
    let executors = std::collections::HashMap::new();

    let estop = Arc::new(EStop::new(secret_dir.join(opsclaw::policy::estop::SENTINEL_FILE), repos.clone()));
    let audit = Arc::new(AuditWriter::new(repos.clone()));
    let scrubber = Arc::new(Scrubber::new());
    let policy = Arc::new(Policy::new(Arc::new(config.clone()), executors, audit, estop.clone(), repos.clone(), scrubber));

    let scheduler_handle = SchedulerHandle::new(config.daemon.tick_seconds.max(1) * 1000);

    let state = match AppState::new(config, &secret_store, repos, policy.clone(), policy, estop, scheduler_handle) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("opsclaw: state construction failed: {e}");
            std::process::exit(2);
        }
    };

    if let Err(e) = server::run(state).await {
        eprintln!("opsclaw: {e}");
        std::process::exit(1);
    }
}
