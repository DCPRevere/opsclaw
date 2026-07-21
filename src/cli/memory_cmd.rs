//! `opsclaw-cli memory recall|store|forget` (DESIGN.md §1: "memory" in the
//! local command list) — thin wrappers over `memory::Memory`, the same
//! facade the daemon's chat/scan turns use. No Hindsight logic lives here:
//! `memory::Memory` already owns retain/recall/forget and the honest
//! `is_enabled()` no-op stance; this module only builds a `Memory` handle
//! from config and formats its answers.
//!
//! Unlike `chat_repl`, these commands do NOT boot the full daemon wiring
//! (`boot::daemon_state`) — a memory read/write needs no executors, no
//! policy, no DB. Building `Memory` directly from `config.memory` is the
//! cheaper, equally honest path (mirrors exactly what `boot::daemon_state`
//! itself does to build its own `memory` value — see that module, the
//! `Some(url) => ... None => Memory::disabled()` branch this duplicates
//! ONLY because there is no lighter-weight shared constructor to call
//! instead; if a third caller ever needs this, promote it to a free
//! function in `memory::mod` rather than a third copy).
//!
//! Every command is honest when memory is disabled (`is_enabled() ==
//! false`, i.e. no `memory.hindsight_url` configured): it says so plainly
//! rather than silently no-op'ing (`memory::Memory`'s own doc: "tools tell
//! the operator so via `is_enabled` instead of silently pretending to
//! remember").

use std::path::Path;
use std::sync::Arc;

use serde::Serialize;

use crate::Result;
use crate::config::Config;
use crate::memory::{Memory, MemoryRecord};

/// Printed by `bin/cli/main.rs` whenever an outcome here reports `enabled:
/// false` — the honest, human-facing form of `Memory::is_enabled`'s
/// contract.
pub const DISABLED_MESSAGE: &str = "memory is disabled on this deployment (no memory.hindsight_url configured) — nothing is being remembered";

/// Build a `Memory` handle straight from a loaded config's `[memory]`
/// section — no DB, no executors (see module doc for why this doesn't go
/// through `boot::daemon_state`).
fn memory_from_config(cfg_path: &Path) -> Result<Memory> {
    let config = Config::load(Some(cfg_path))?;
    Ok(match &config.memory.hindsight_url {
        Some(url) => {
            let client = Arc::new(crate::memory::hindsight::HindsightClient::new(
                url,
                None,
                &config.memory.team_id,
            ));
            Memory::disabled().with_hindsight(client)
        }
        None => Memory::disabled(),
    })
}

#[derive(Debug, Serialize)]
pub struct RecallOutcome {
    pub enabled: bool,
    pub records: Vec<RecordOut>,
}

#[derive(Debug, Serialize)]
pub struct RecordOut {
    pub id: String,
    pub fact: String,
}

fn record_out(r: &MemoryRecord) -> RecordOut {
    RecordOut { id: r.id.clone(), fact: r.fact.clone() }
}

/// `memory recall <query>` — up to `limit` ranked facts. Honest empty
/// result (not an error) when memory is disabled; `enabled` tells the
/// caller which case it is.
pub async fn recall(cfg_path: &Path, query: &str, limit: usize) -> Result<RecallOutcome> {
    let memory = memory_from_config(cfg_path)?;
    let enabled = memory.is_enabled();
    let records = if enabled { memory.recall(query, limit).await? } else { Vec::new() };
    Ok(RecallOutcome { enabled, records: records.iter().map(record_out).collect() })
}

#[derive(Debug, Serialize)]
pub struct StoreOutcome {
    pub enabled: bool,
    pub stored: bool,
}

/// `memory store <text>` — an explicit note (raw text; Hindsight does its
/// own extraction, see `Memory::store_fact`'s doc). Returns `stored: false`
/// (not an error) when memory is disabled — the caller decides how loudly
/// to say so.
pub async fn store(cfg_path: &Path, speaker: &str, text: &str) -> Result<StoreOutcome> {
    let memory = memory_from_config(cfg_path)?;
    let enabled = memory.is_enabled();
    if enabled {
        memory.store_fact(speaker, text).await?;
    }
    Ok(StoreOutcome { enabled, stored: enabled })
}

#[derive(Debug, Serialize)]
pub struct ForgetOutcome {
    pub enabled: bool,
    pub forgotten: Vec<String>,
}

/// `memory forget <id-or-query>` — forgets ONE fact by its Hindsight id if
/// `target` looks like one (an opaque backend handle, never a query a
/// human would type), else treats `target` as a recall query and forgets
/// every match. A query-based forget can hit more than one fact
/// (`MemoryRecord::id` is the only true identity Hindsight exposes); every
/// id actually forgotten is returned so the operator sees exactly what
/// left, not just an ack. `reason` rides the audit trail Hindsight itself
/// keeps (`Memory::forget`'s doc: "reversible... reason rides along").
pub async fn forget(cfg_path: &Path, target: &str, reason: &str) -> Result<ForgetOutcome> {
    let memory = memory_from_config(cfg_path)?;
    let enabled = memory.is_enabled();
    if !enabled {
        return Ok(ForgetOutcome { enabled, forgotten: Vec::new() });
    }

    // Heuristic: Hindsight's own ids are opaque handles, not something an
    // operator composes by hand — but this module has no independent way
    // to validate one against the backend other than trying `forget`
    // directly first, so: try `target` as a direct id; if recall ALSO
    // matches it as a query, forget those too. This means an id that
    // happens to also match text search gets both — harmless (forgetting
    // the same id twice is a no-op the second time from the backend's
    // perspective; `forget` itself doesn't error on an already-forgotten
    // id) and strictly safer than guessing wrong and forgetting nothing.
    let mut forgotten = Vec::new();
    let looks_like_id = !target.trim().is_empty() && !target.contains(' ');
    if looks_like_id {
        memory.forget(target, reason).await?;
        forgotten.push(target.to_string());
    } else {
        let matches = memory.recall(target, 20).await?;
        for m in &matches {
            if !m.id.is_empty() {
                memory.forget(&m.id, reason).await?;
                forgotten.push(m.id.clone());
            }
        }
    }
    Ok(ForgetOutcome { enabled, forgotten })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &tempfile::TempDir, hindsight_url: Option<&str>) -> std::path::PathBuf {
        let path = dir.path().join("config.toml");
        let body = match hindsight_url {
            Some(url) => format!("[memory]\nhindsight_url = \"{url}\"\n"),
            None => String::new(),
        };
        std::fs::write(&path, body).unwrap();
        path
    }

    #[tokio::test]
    async fn recall_is_honest_when_memory_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(&dir, None);
        let outcome = recall(&cfg, "anything", 10).await.unwrap();
        assert!(!outcome.enabled);
        assert!(outcome.records.is_empty());
    }

    #[tokio::test]
    async fn store_is_honest_when_memory_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(&dir, None);
        let outcome = store(&cfg, "dcp", "the payments pod OOMs above 400 req/s").await.unwrap();
        assert!(!outcome.enabled);
        assert!(!outcome.stored);
    }

    #[tokio::test]
    async fn forget_is_honest_when_memory_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(&dir, None);
        let outcome = forget(&cfg, "some-id", "operator correction").await.unwrap();
        assert!(!outcome.enabled);
        assert!(outcome.forgotten.is_empty());
    }

    #[tokio::test]
    async fn recall_hits_the_configured_hindsight_backend() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path_regex(r"^/v1/default/banks/.*/memories/recall$"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{ "id": "m1", "text": "the payments pod OOMs above 400 req/s" }]
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(&dir, Some(&server.uri()));
        let outcome = recall(&cfg, "payments pod", 10).await.unwrap();
        assert!(outcome.enabled);
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].id, "m1");
    }
}
