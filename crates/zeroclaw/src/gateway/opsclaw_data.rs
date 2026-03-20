//! Read-only data access for OpsClaw-specific web dashboard API endpoints.
//!
//! Reads targets, incidents, snapshots, and audit entries from the filesystem
//! paths under `~/.opsclaw/`.

use super::AppState;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::api::require_auth;

fn opsclaw_dir() -> Option<PathBuf> {
    directories::UserDirs::new().map(|u| u.home_dir().join(".opsclaw"))
}

// ── Query params ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TargetQuery {
    pub target: Option<String>,
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<usize>,
}

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize)]
struct WebTarget {
    name: String,
    #[serde(rename = "type")]
    target_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    autonomy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_scan: Option<String>,
    health_status: String,
}

#[derive(Serialize)]
struct WebIncident {
    incident_id: String,
    timestamp: String,
    target_name: String,
    severity: String,
    llm_assessment: String,
    suggested_actions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution: Option<String>,
}

#[derive(Serialize)]
struct WebAuditEntry {
    id: String,
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_name: Option<String>,
    action_type: String,
    command: String,
    dry_run: bool,
    result: String,
    hash: String,
    prev_hash: String,
}

// ── Handlers ───────────────────────────────────────────────────

/// GET /api/opsclaw/targets — list configured targets with health status
pub async fn handle_opsclaw_targets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();
    let targets = match &config.targets {
        Some(t) => t,
        None => return Json(serde_json::json!({"targets": []})).into_response(),
    };

    let web_targets: Vec<WebTarget> = targets
        .iter()
        .map(|t| {
            let last_scan = read_snapshot_time(&t.name);
            let health_status = read_health_status(&t.name);

            WebTarget {
                name: t.name.clone(),
                target_type: format!("{:?}", t.target_type).to_lowercase(),
                host: t.host.clone(),
                autonomy: format!("{:?}", t.autonomy).to_lowercase(),
                last_scan,
                health_status,
            }
        })
        .collect();

    Json(serde_json::json!({"targets": web_targets})).into_response()
}

/// GET /api/opsclaw/incidents?target=X — list incidents (optionally filtered)
pub async fn handle_opsclaw_incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<TargetQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let incidents_dir = match opsclaw_dir() {
        Some(d) => d.join("incidents"),
        None => return Json(serde_json::json!({"incidents": []})).into_response(),
    };

    if !incidents_dir.exists() {
        return Json(serde_json::json!({"incidents": []})).into_response();
    }

    let target_dirs: Vec<(String, PathBuf)> = if let Some(ref name) = params.target {
        let d = incidents_dir.join(name);
        if d.exists() {
            vec![(name.clone(), d)]
        } else {
            return Json(serde_json::json!({"incidents": []})).into_response();
        }
    } else {
        std::fs::read_dir(&incidents_dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                (name, e.path())
            })
            .collect()
    };

    let mut all: Vec<WebIncident> = Vec::new();
    for (target_name, dir) in target_dirs {
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
            .collect();

        let mut resolutions = std::collections::HashMap::new();

        for entry in &entries {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                        // Check if it's a resolution record
                        if val.get("resolution").is_some() && val.get("resolved_at").is_some() {
                            if let (Some(id), Some(res)) = (
                                val.get("incident_id").and_then(|v| v.as_str()),
                                val.get("resolution").and_then(|v| v.as_str()),
                            ) {
                                if !res.is_empty() {
                                    resolutions.insert(id.to_string(), res.to_string());
                                }
                            }
                            continue;
                        }

                        // Try as incident/diagnosis record
                        if let Some(incident_id) = val.get("incident_id").and_then(|v| v.as_str()) {
                            let severity = val
                                .get("severity")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let assessment = val
                                .get("llm_assessment")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let actions: Vec<String> = val
                                .get("suggested_actions")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let timestamp = val
                                .get("timestamp")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            // Skip if no assessment (not an incident record)
                            if assessment.is_empty() && actions.is_empty() {
                                continue;
                            }

                            let t_name = val
                                .get("target_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(&target_name)
                                .to_string();

                            all.push(WebIncident {
                                incident_id: incident_id.to_string(),
                                timestamp,
                                target_name: t_name,
                                severity,
                                llm_assessment: assessment,
                                suggested_actions: actions,
                                resolution: None,
                            });
                        }
                    }
                }
            }
        }

        // Apply resolutions
        for inc in &mut all {
            if let Some(res) = resolutions.get(&inc.incident_id) {
                inc.resolution = Some(res.clone());
            }
        }
    }

    // Sort newest first
    all.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Json(serde_json::json!({"incidents": all})).into_response()
}

/// GET /api/opsclaw/status?target=X — latest snapshot + health for a target
pub async fn handle_opsclaw_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<TargetQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let target_name = match params.target {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "target query parameter required"})),
            )
                .into_response();
        }
    };

    let health = read_health_status(&target_name);
    let snapshot = read_snapshot_json(&target_name);

    Json(serde_json::json!({
        "target_name": target_name,
        "health_status": health,
        "snapshot": snapshot,
    }))
    .into_response()
}

/// GET /api/opsclaw/audit — recent audit log entries
pub async fn handle_opsclaw_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuditQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let limit = params.limit.unwrap_or(100).clamp(1, 1000);
    let config = state.config.lock().clone();

    let zeroclaw_dir = config
        .config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let log_path = zeroclaw_dir.join(&config.security.audit.log_path);

    if !log_path.exists() {
        return Json(serde_json::json!({"entries": []})).into_response();
    }

    let content = match std::fs::read_to_string(&log_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to read audit log: {e}")})),
            )
                .into_response();
        }
    };

    let mut entries: Vec<WebAuditEntry> = content
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(limit)
        .filter_map(parse_audit_line)
        .collect();

    entries.reverse();
    Json(serde_json::json!({"entries": entries})).into_response()
}

// ── Helpers ────────────────────────────────────────────────────

fn read_snapshot_time(target_name: &str) -> Option<String> {
    let dir = opsclaw_dir()?.join("snapshots");
    let path = dir.join(format!("{target_name}.json"));
    let content = std::fs::read_to_string(path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&content).ok()?;
    val.get("scanned_at")
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn read_health_status(target_name: &str) -> String {
    let dir = match opsclaw_dir() {
        Some(d) => d.join("monitor_log"),
        None => return "Unknown".to_string(),
    };
    let path = dir.join(format!("{target_name}.jsonl"));
    if !path.exists() {
        return "Unknown".to_string();
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return "Unknown".to_string(),
    };

    content
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|line| {
            let val: serde_json::Value = serde_json::from_str(line).ok()?;
            val.get("status").and_then(|s| s.as_str()).map(|s| {
                match s.to_lowercase().as_str() {
                    "healthy" | "ok" => "Healthy",
                    "warning" | "warn" | "degraded" => "Warning",
                    "critical" | "error" => "Critical",
                    _ => "Unknown",
                }
                .to_string()
            })
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

fn read_snapshot_json(target_name: &str) -> Option<serde_json::Value> {
    let dir = opsclaw_dir()?.join("snapshots");
    let path = dir.join(format!("{target_name}.json"));
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn parse_audit_line(line: &str) -> Option<WebAuditEntry> {
    let val: serde_json::Value = serde_json::from_str(line).ok()?;
    let action = val.get("action")?;

    let success = val
        .get("result")
        .and_then(|r| r.get("success"))
        .and_then(|s| s.as_bool());
    let approved = action
        .get("approved")
        .and_then(|a| a.as_bool())
        .unwrap_or(false);
    let allowed = action
        .get("allowed")
        .and_then(|a| a.as_bool())
        .unwrap_or(true);

    let result_str = match success {
        Some(true) => "success",
        Some(false) => "failure",
        None => {
            if !allowed {
                "denied"
            } else if !approved {
                "dry-run"
            } else {
                "unknown"
            }
        }
    };

    Some(WebAuditEntry {
        id: val
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        timestamp: val
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        target_name: val
            .get("actor")
            .and_then(|a| a.get("channel"))
            .and_then(|c| c.as_str())
            .map(String::from),
        action_type: val
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        command: action
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        dry_run: !approved,
        result: result_str.to_string(),
        hash: val
            .get("entry_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        prev_hash: val
            .get("prev_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}
