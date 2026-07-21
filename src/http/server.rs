//! Minimal Axum server: `/ready` + graceful shutdown. Wave 4 adds the real
//! router (API, webhooks, embedded UI) behind the same entrypoint.

use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use super::AppState;
use crate::Result;

pub fn router(state: AppState) -> Router {
    Router::new().route("/ready", get(ready)).with_state(state)
}

async fn ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
        "version": crate::version(),
        "fakes_mode": state.config.fully_faked(),
    }))
}

/// Bind and serve until SIGINT/SIGTERM; drains in-flight HTTP on shutdown.
pub async fn run(state: AppState) -> Result<()> {
    let listen = state.config.daemon.listen.clone();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| crate::Error::Config(format!("cannot bind {listen}: {e}")))?;
    tracing::info!(%listen, version = crate::version(), "opsclaw listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| crate::Error::other(e.to_string()))?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received; draining");
}
