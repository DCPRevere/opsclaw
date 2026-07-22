//! `opsclaw-cli memory recall|store|forget|export` (DESIGN.md §1: "memory"
//! in the local command list; export is brief §8's human-readable
//! export/archival mechanism) — thin wrappers over `memory::Memory`, the
//! same facade the daemon's chat/scan turns use. No Hindsight logic lives here:
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
pub struct ExportOutcome {
    pub enabled: bool,
    /// The bank's full fact count — greater than `records.len()` when the
    /// `limit` cap truncated the dump (the markdown marks that explicitly;
    /// an archive that silently looked complete would be a lie).
    pub total: usize,
    pub records: Vec<ExportRecordOut>,
}

/// One exported fact with the annotations Hindsight reported for it —
/// richer than `RecordOut` because an archival dump wants the timestamp and
/// context (brief §8: human-readable export), while `recall` output stays a
/// terse fact list.
#[derive(Debug, Serialize)]
pub struct ExportRecordOut {
    pub id: String,
    pub fact: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentioned_at: Option<String>,
}

/// `memory export [--json] [--limit N]` — the team bank's archival dump
/// (brief §8), via Hindsight's `list` endpoint: the COMPLETE deterministic
/// enumeration (every stored fact, raw and consolidated layers alike — see
/// `Memory::export`), not a best-effort broad recall. Honest empty result
/// when memory is disabled, same contract as `recall`.
pub async fn export(cfg_path: &Path, limit: usize) -> Result<ExportOutcome> {
    let memory = memory_from_config(cfg_path)?;
    let enabled = memory.is_enabled();
    let (records, total) = if enabled { memory.export(limit).await? } else { (Vec::new(), 0) };
    Ok(ExportOutcome {
        enabled,
        total,
        records: records
            .into_iter()
            .map(|r| ExportRecordOut {
                id: r.id,
                fact: r.fact,
                kind: r.kind,
                context: r.context,
                mentioned_at: r.mentioned_at,
            })
            .collect(),
    })
}

/// The export's default human-readable form: one markdown section per
/// memory, annotations (timestamp / context / kind / id) as a sub-list.
/// Lives here (not in `bin/cli`) so the format is TESTED — the whole point
/// of the command is that a human or a later import can rely on its shape.
/// `exported_at` is passed in (not read from the clock) for the same
/// reason.
pub fn render_export_markdown(outcome: &ExportOutcome, exported_at: &str) -> String {
    let mut out = String::new();
    out.push_str("# OpsClaw team memory export\n\n");
    out.push_str(&format!(
        "- exported: {exported_at}\n- facts: {} of {} in the bank\n",
        outcome.records.len(),
        outcome.total
    ));
    if outcome.records.len() < outcome.total {
        out.push_str(&format!(
            "- TRUNCATED: the bank holds {} more fact(s) than this dump — re-run with a higher \
             --limit for a complete archive\n",
            outcome.total - outcome.records.len()
        ));
    }
    for (i, r) in outcome.records.iter().enumerate() {
        out.push_str(&format!("\n## {}\n\n{}\n\n", i + 1, r.fact.trim()));
        if let Some(ts) = &r.mentioned_at {
            out.push_str(&format!("- retained: {ts}\n"));
        }
        if let Some(ctx) = &r.context {
            out.push_str(&format!("- context: {ctx}\n"));
        }
        if let Some(kind) = &r.kind {
            out.push_str(&format!("- kind: {kind}\n"));
        }
        if !r.id.is_empty() {
            out.push_str(&format!("- id: {}\n", r.id));
        }
    }
    out
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
    async fn export_is_honest_when_memory_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(&dir, None);
        let outcome = export(&cfg, 100).await.unwrap();
        assert!(!outcome.enabled);
        assert_eq!(outcome.total, 0);
        assert!(outcome.records.is_empty());
    }

    #[tokio::test]
    async fn export_dumps_the_bank_with_annotations_and_marks_truncation() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(r"^/v1/default/banks/.*/memories/list$"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total": 3,
                "items": [
                    {
                        "id": "m1",
                        "text": "the payments pod OOMs above 400 req/s",
                        "type": "observation",
                        "context": "scan finding",
                        "mentioned_at": "2026-06-18T17:57:17Z"
                    },
                    { "id": "m2", "text": "dcp said: restart fixed it" }
                ]
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(&dir, Some(&server.uri()));
        // limit=2 < total=3: the outcome must carry the FULL total so the
        // rendered archive can say it is incomplete.
        let outcome = export(&cfg, 2).await.unwrap();
        assert!(outcome.enabled);
        assert_eq!(outcome.total, 3);
        assert_eq!(outcome.records.len(), 2);
        assert_eq!(outcome.records[0].mentioned_at.as_deref(), Some("2026-06-18T17:57:17Z"));

        let md = render_export_markdown(&outcome, "2026-07-22T00:00:00Z");
        // One section per memory, annotations as a sub-list…
        assert!(md.contains("# OpsClaw team memory export"), "{md}");
        assert!(md.contains("## 1\n\nthe payments pod OOMs above 400 req/s"), "{md}");
        assert!(md.contains("- retained: 2026-06-18T17:57:17Z"), "{md}");
        assert!(md.contains("- context: scan finding"), "{md}");
        assert!(md.contains("- id: m1"), "{md}");
        assert!(md.contains("## 2\n\ndcp said: restart fixed it"), "{md}");
        // …and the truncation is called out, never silent.
        assert!(md.contains("TRUNCATED"), "{md}");
        assert!(md.contains("1 more fact(s)"), "{md}");
        assert!(md.contains("- facts: 2 of 3 in the bank"), "{md}");
    }

    #[test]
    fn complete_export_markdown_has_no_truncation_marker() {
        let outcome = ExportOutcome {
            enabled: true,
            total: 1,
            records: vec![ExportRecordOut {
                id: String::new(), // an id-less fact renders without an id line
                fact: "web-1 lives in us-east-1".into(),
                kind: None,
                context: None,
                mentioned_at: None,
            }],
        };
        let md = render_export_markdown(&outcome, "2026-07-22T00:00:00Z");
        assert!(!md.contains("TRUNCATED"), "{md}");
        assert!(!md.contains("- id:"), "{md}");
        assert!(md.contains("- facts: 1 of 1 in the bank"), "{md}");
        assert!(md.contains("- exported: 2026-07-22T00:00:00Z"), "{md}");
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
